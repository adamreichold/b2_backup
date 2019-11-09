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
use std::convert::TryFrom;
use std::fs::{File, Metadata};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

use super::{
    client::Client,
    manifest::{add_block, add_file, Update},
    split::split,
    Config, Fallible,
};

macro_rules! try_not_found {
    ($res:expr) => {
        match $res {
            Ok(val) => val,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        }
    };
}

pub fn backup(
    config: &Config,
    client: &Client,
    update: &Mutex<Update<'_>>,
    excludes: &[PathBuf],
    path: &Path,
) -> Fallible {
    if let Some(exclude) = excludes.iter().find(|exclude| path.starts_with(exclude)) {
        println!(
            "Skipping {} due to exclude {}",
            path.display(),
            exclude.display(),
        );
        return Ok(());
    }

    let metadata = try_not_found!(path.symlink_metadata());
    let file_type = metadata.file_type();

    if file_type.is_dir() {
        backup_dir(config, client, update, excludes, &path)?;
    } else if file_type.is_file() {
        backup_file(config, client, update, &path, &metadata)?;
    } else if file_type.is_symlink() {
        backup_symlink(update, &path, &metadata)?;
    } else {
        eprintln!(
            "Skipping {} as it does not appear to be a regular file",
            path.display()
        );
    }

    Ok(())
}

fn backup_dir(
    config: &Config,
    client: &Client,
    update: &Mutex<Update<'_>>,
    excludes: &[PathBuf],
    path: &Path,
) -> Fallible {
    let dir = try_not_found!(path.read_dir());

    let paths = dir
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()?;

    paths
        .par_iter()
        .try_for_each(|path| backup(config, client, update, excludes, &path))
}

fn backup_file(
    config: &Config,
    client: &Client,
    update: &Mutex<Update<'_>>,
    path: &Path,
    metadata: &Metadata,
) -> Fallible {
    let file = try_not_found!(File::open(path));

    let file_id = add_file(update, path, &metadata, None)?;

    let mut offset = 0;

    split(file, |block| {
        add_block(update, config, client, file_id, offset, block)?;

        offset += u64::try_from(block.len()).unwrap();

        Ok(())
    })
}

fn backup_symlink(update: &Mutex<Update<'_>>, path: &Path, metadata: &Metadata) -> Fallible {
    let symlink = try_not_found!(path.read_link());

    add_file(update, path, &metadata, Some(&symlink))?;

    Ok(())
}
