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
mod manifest;
mod pack;
mod split;

use std::env::args;
use std::error::Error;
use std::fs::File;
use std::path::{Path, PathBuf};

use hex::decode_to_slice;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use serde::Deserialize;
use serde_yaml::from_reader;
use sodiumoxide::crypto::secretbox::{Key, KEYBYTES};

use self::{backup::backup, client::Client, manifest::Manifest};

type Fallible<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

fn main() -> Fallible {
    sodiumoxide::init().map_err(|()| "Failed to initialize libsodium")?;

    let mut manifest = Manifest::open("manifest.db")?;

    let config = Config::read("config.yaml")?;

    let client = Client::new(&config)?;

    match args().nth(1).as_ref().map(|arg| arg.as_str()) {
        None | Some("backup") => manifest.update(false, &client, |update| {
            config
                .includes
                .par_iter()
                .try_for_each(|path| backup(&client, update, &config.excludes, path))
        }),
        Some("collect-small-archives") => manifest.collect_small_archives(&client),
        Some("collect-small-patchsets") => manifest.collect_small_patchsets(&client),
        Some("restore-manifest") => manifest.restore(&client),
        Some(arg) => Err(format!("Unexpected argument {}", arg).into()),
    }
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
}

impl Config {
    fn read<P: AsRef<Path>>(path: P) -> Fallible<Self> {
        Ok(from_reader(File::open(path)?)?)
    }

    fn key(&self) -> Fallible<Key> {
        let mut key = [0; KEYBYTES];
        decode_to_slice(&self.key, &mut key)?;
        Ok(Key(key))
    }
}
