/*
Copyright 2019 Adam Reichold

This file is part of b2_backup.

b2_backup is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

b2_backup is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with b2_backup.  If not, see <https://www.gnu.org/licenses/>.
*/
mod backup;
mod client;
mod database;
mod manifest;
mod pack;
mod split;

use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::{metadata, read_to_string, set_permissions, File};
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::os::unix::fs::{FileExt, PermissionsExt};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use clap::{command, value_parser, Arg, ArgMatches, Command};
use nix::{
    errno::Errno,
    fcntl::copy_file_range,
    libc::c_int,
    sys::signal::{signal, SigHandler, Signal},
};
use rayon::{
    iter::{IntoParallelRefIterator, ParallelIterator},
    ThreadPoolBuilder,
};
use serde::Deserialize;
use serde_yaml::from_str;

use self::{backup::backup, client::Client, manifest::Manifest, pack::Key};

type Fallible<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn main() -> Fallible {
    let opts = parse_opts();

    let config = Config::read(get_path(&opts, "config").unwrap())?;

    let client = Client::new(&config)?;

    let mut manifest = Manifest::open(get_path(&opts, "manifest").unwrap())?;

    match opts.subcommand() {
        Some(("backup", args)) => {
            manifest.update(config.keep_deleted_files, &client, |update| {
                install_interrupt_handler()?;

                if let Some(num_threads) = config.num_threads {
                    ThreadPoolBuilder::new()
                        .num_threads(num_threads)
                        .build_global()?;
                }

                config
                    .includes
                    .par_iter()
                    .try_for_each(|path| backup(&config, &client, update, path))
            })?;

            if *args.get_one::<bool>("maybe_collect").unwrap() {
                manifest.maybe_collect_small_archives(&config, &client)?;
                manifest.maybe_collect_small_patchsets(&config, &client)?;
            }

            Ok(())
        }
        Some(("collect-small-archives", _)) => manifest.collect_small_archives(&config, &client),
        Some(("collect-small-patchsets", _)) => manifest.collect_small_patchsets(&config, &client),
        Some(("list-files", args)) => manifest.list_files(get_path(args, "filter")),
        Some(("restore-files", args)) => manifest.restore_files(
            &client,
            get_path(args, "filter"),
            get_path(args, "target_dir"),
        ),
        Some(("restore-manifest", _)) => manifest.restore_manifest(&client),
        Some(("purge-storage", _)) => manifest.purge_storage(&client),
        None | Some(_) => unreachable!(),
    }
}

fn install_interrupt_handler() -> Fallible {
    extern "C" fn handler(_signum: c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }

    unsafe {
        signal(Signal::SIGINT, SigHandler::Handler(handler))?;
    }

    Ok(())
}

fn was_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

fn copy_file_range_full(
    buf: &mut Vec<u8>,
    from: &File,
    from_off: u64,
    to: &File,
    to_off: u64,
    len: u64,
) -> Fallible {
    let mut from_pos = from_off.try_into().unwrap();
    let mut to_pos = to_off.try_into().unwrap();
    let mut len = len.try_into().unwrap();

    while len != 0 {
        match copy_file_range(from, Some(&mut from_pos), to, Some(&mut to_pos), len) {
            Ok(0) => return Err(IoError::from(IoErrorKind::WriteZero).into()),
            Ok(written) => len -= written,
            Err(Errno::EINTR) => (),
            Err(Errno::EXDEV) => {
                buf.resize(len, 0);
                from.read_exact_at(buf, from_off)?;
                to.write_all_at(buf, to_off)?;
                break;
            }
            Err(err) => return Err(err.into()),
        }
    }

    Ok(())
}

fn ensure_restrictive_permissions(path: &Path) -> Fallible {
    const MODE: u32 = 0o600;

    let mut perm = metadata(path)?.permissions();

    if perm.mode() != MODE {
        perm.set_mode(MODE);

        set_permissions(path, perm)?;
    }

    Ok(())
}

fn parse_opts() -> ArgMatches {
    command!()
        .arg(
            Arg::new("config")
                .long("config")
                .default_value("config.yaml")
                .value_parser(value_parser!(PathBuf)),
        )
        .arg(
            Arg::new("manifest")
                .long("manifest")
                .default_value("manifest.db")
                .value_parser(value_parser!(PathBuf)),
        )
        .subcommand_required(true)
        .subcommand(
            Command::new("backup").arg(
                Arg::new("maybe_collect")
                    .long("maybe-collect")
                    .default_value("true")
                    .value_parser(value_parser!(bool)),
            ),
        )
        .subcommand(Command::new("collect-small-archives"))
        .subcommand(Command::new("collect-small-patchsets"))
        .subcommand(
            Command::new("list-files").arg(Arg::new("filter").value_parser(value_parser!(PathBuf))),
        )
        .subcommand(
            Command::new("restore-files")
                .arg(Arg::new("filter").value_parser(value_parser!(PathBuf)))
                .arg(
                    Arg::new("target_dir")
                        .long("target-dir")
                        .value_parser(value_parser!(PathBuf)),
                ),
        )
        .subcommand(Command::new("restore-manifest"))
        .subcommand(Command::new("purge-storage"))
        .get_matches()
}

fn get_path<'a>(opts: &'a ArgMatches, arg: &str) -> Option<&'a Path> {
    opts.get_one::<PathBuf>(arg).map(PathBuf::as_path)
}

#[derive(Debug, Deserialize)]
pub struct Config {
    app_key_id: String,
    app_key: String,
    bucket_id: String,
    bucket_name: String,
    key: String,
    includes: Vec<PathBuf>,
    #[serde(default)]
    excludes: Vec<PathBuf>,
    #[serde(default = "Config::def_keep_deleted_files")]
    keep_deleted_files: bool,
    num_threads: Option<usize>,
    #[serde(default = "Config::def_compression_level")]
    compression_level: i32,
    #[serde(default = "Config::def_min_archive_len")]
    min_archive_len: u64,
    #[serde(default = "Config::def_max_manifest_len")]
    max_manifest_len: u64,
    #[serde(default = "Config::def_small_archives_upper_limit")]
    small_archives_upper_limit: usize,
    #[serde(default = "Config::def_small_archives_lower_limit")]
    small_archives_lower_limit: usize,
    #[serde(default = "Config::def_small_patchsets_limit")]
    small_patchsets_limit: usize,
}

impl Config {
    fn read(path: &Path) -> Fallible<Self> {
        ensure_restrictive_permissions(path)?;

        let config = from_str(&read_to_string(path)?)?;

        Ok(config)
    }

    fn key(&self) -> Fallible<Key> {
        let mut key = Key::default();
        hex::decode_to_slice(&self.key, &mut key)?;
        Ok(key)
    }

    fn def_keep_deleted_files() -> bool {
        false
    }

    fn def_compression_level() -> i32 {
        17
    }

    fn def_min_archive_len() -> u64 {
        50_000_000
    }

    fn def_max_manifest_len() -> u64 {
        10_000_000
    }

    fn def_small_archives_upper_limit() -> usize {
        10
    }

    fn def_small_archives_lower_limit() -> usize {
        5
    }

    fn def_small_patchsets_limit() -> usize {
        25
    }
}

struct Bytes(f64);

impl Display for Bytes {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> FmtResult {
        let mut factor = self.0;
        let mut unit = "B";

        for next_unit in &["kB", "MB", "GB", "TB"] {
            if factor < 1024.0 {
                break;
            }

            factor /= 1024.0;
            unit = next_unit;
        }

        write!(fmt, "{factor:.1} {unit}")
    }
}
