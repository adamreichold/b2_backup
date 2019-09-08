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
    Fallible,
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

pub fn backup_path(
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
        backup_dir(client, update, excludes, &path)?;
    } else if file_type.is_file() {
        backup_file(client, update, &path, &metadata)?;
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
    client: &Client,
    update: &Mutex<Update<'_>>,
    excludes: &[PathBuf],
    path: &Path,
) -> Fallible {
    let dir = try_not_found!(path.read_dir());

    let paths = dir
        .filter_map(|entry| match entry {
            Ok(entry) => Some(Ok(entry.path())),
            Err(err) if err.kind() == ErrorKind::NotFound => None,
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<Vec<_>, _>>()?;

    paths
        .par_iter()
        .try_for_each(|path| backup_path(client, update, excludes, &path))
}

fn backup_file(
    client: &Client,
    update: &Mutex<Update<'_>>,
    path: &Path,
    metadata: &Metadata,
) -> Fallible {
    let file = try_not_found!(File::open(path));

    let file_id = add_file(update, path, &metadata, None)?;

    let mut offset = 0;

    split(file, |block| {
        add_block(update, client, file_id, offset, block)?;

        offset += u64::try_from(block.len()).unwrap();

        Ok(())
    })
}

fn backup_symlink(update: &Mutex<Update<'_>>, path: &Path, metadata: &Metadata) -> Fallible {
    let symlink = try_not_found!(path.read_link());

    add_file(update, path, &metadata, Some(&symlink))?;

    Ok(())
}
