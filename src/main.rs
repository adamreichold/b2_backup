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

use std::convert::TryInto;
use std::env::args;
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::File;
use std::io::{Error as IoError, ErrorKind as IoErrorKind};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use nix::{
    errno::Errno,
    fcntl::copy_file_range,
    libc::c_int,
    sys::signal::{signal, SigHandler, Signal},
    Error as NixError,
};
use rayon::{
    iter::{IntoParallelRefIterator, ParallelIterator},
    ThreadPoolBuilder,
};
use serde::Deserialize;
use serde_yaml::from_reader;

use self::{backup::backup, client::Client, manifest::Manifest, pack::Key};

type Fallible<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn main() -> Fallible {
    let config: Config = from_reader(File::open("config.yaml")?)?;

    if let Some(num_threads) = config.num_threads {
        ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global()?;
    }

    let client = Client::new(&config)?;

    let mut manifest = Manifest::open("manifest.db")?;

    let mut args = args();

    match args.nth(1).as_deref() {
        None | Some("backup") => manifest.update(config.keep_deleted_files, &client, |update| {
            install_interrupt_handler()?;

            config
                .includes
                .par_iter()
                .try_for_each(|path| backup(&config, &client, update, &config.excludes, path))
        }),
        Some("collect-small-archives") => manifest.collect_small_archives(&config, &client),
        Some("collect-small-patchsets") => manifest.collect_small_patchsets(&config, &client),
        Some("restore-manifest") => manifest.restore(&client),
        Some("list-files") => manifest.list_files(args.next().as_deref()),
        Some("restore-files") => manifest.restore_files(
            &client,
            args.next().as_deref(),
            args.next().map(PathBuf::from).as_deref(),
        ),
        Some("purge-storage") => manifest.purge_storage(&client),
        Some(arg) => Err(format!("Unexpected argument {}", arg).into()),
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

fn copy_file_range_full(from: &File, from_off: u64, to: &File, to_off: u64, len: u64) -> Fallible {
    let from = from.as_raw_fd();
    let to = to.as_raw_fd();

    let mut from_off = from_off.try_into().unwrap();
    let mut to_off = to_off.try_into().unwrap();
    let mut len = len.try_into().unwrap();

    while len != 0 {
        match copy_file_range(from, Some(&mut from_off), to, Some(&mut to_off), len) {
            Ok(0) => return Err(IoError::from(IoErrorKind::WriteZero).into()),
            Ok(written) => len -= written,
            Err(NixError::Sys(Errno::EINTR)) => (),
            Err(err) => return Err(err.into()),
        }
    }

    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct Config {
    app_key_id: String,
    app_key: String,
    bucket_id: String,
    bucket_name: String,
    key: String,
    includes: Vec<PathBuf>,
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
}

impl Config {
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

        write!(fmt, "{:.1} {}", factor, unit)
    }
}
