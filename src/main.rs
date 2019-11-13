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

use std::env::{args, current_dir};
use std::error::Error;
use std::fmt::{Display, Formatter, Result as FmtResult};
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use hex::decode_to_slice;
use libc::{c_int, sighandler_t, signal, SIGINT, SIG_ERR};
use rayon::{
    iter::{IntoParallelRefIterator, ParallelIterator},
    ThreadPoolBuilder,
};
use serde::Deserialize;
use serde_yaml::from_reader;
use sodiumoxide::crypto::secretbox::{Key, KEYBYTES};

use self::{backup::backup, client::Client, manifest::Manifest};

type Fallible<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn main() -> Fallible {
    sodiumoxide::init().map_err(|()| "Failed to initialize libsodium")?;

    let mut manifest = Manifest::open("manifest.db")?;

    let config: Config = from_reader(File::open("config.yaml")?)?;

    if let Some(num_threads) = config.num_threads {
        ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .build_global()?;
    }

    let client = Client::new(&config)?;

    let mut args = args();

    match args.nth(1).as_ref().map(String::as_str) {
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
        Some("list-files") => manifest.list_files(args.next().as_ref().map(String::as_str)),
        Some("restore-files") => manifest.restore_files(
            &config,
            &client,
            args.next().as_ref().map(String::as_str),
            &args
                .next()
                .map(|arg| Ok(arg.into()))
                .unwrap_or_else(current_dir)?,
        ),
        Some(arg) => Err(format!("Unexpected argument {}", arg).into()),
    }
}

fn install_interrupt_handler() -> Fallible {
    extern "C" fn interrupt(_signum: c_int) {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }

    unsafe {
        if signal(SIGINT, interrupt as extern "C" fn(c_int) as sighandler_t) == SIG_ERR {
            return Err("Failed to install signal handler".into());
        }
    }

    Ok(())
}

fn was_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

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
    #[serde(default = "Config::def_archive_cache_cap")]
    archive_cache_cap: usize,
}

impl Config {
    fn key(&self) -> Fallible<Key> {
        let mut key = [0; KEYBYTES];
        decode_to_slice(&self.key, &mut key)?;
        Ok(Key(key))
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

    fn def_archive_cache_cap() -> usize {
        20
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
