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
use std::collections::{BTreeMap, HashSet};
use std::convert::TryInto;
use std::env::set_current_dir;
use std::fs::{create_dir_all, set_permissions, File, Metadata, OpenOptions, Permissions};
use std::io::{copy, Read, Seek, Write};
use std::mem::replace;
use std::os::unix::fs::{symlink as create_symlink, PermissionsExt};
use std::path::Path;
use std::sync::Mutex;

use blake3::hash;
use rusqlite::{
    session::{Changegroup, ConflictAction, ConflictType, Session},
    Connection, TransactionBehavior,
};
use tempfile::tempfile;

use super::{
    client::Client,
    copy_file_range_full,
    database::{
        clear_tables, delete_archive, delete_mappings, delete_new_file, delete_patchset,
        delete_unused_blocks, delete_unvisited_directories, delete_unvisited_files,
        delete_unvisited_symbolic_links, delete_visited_objects, insert_block, insert_def_archive,
        insert_def_patchset, insert_directory, insert_file, insert_mappings, insert_new_file,
        insert_new_mapping, insert_patchset, insert_symbolic_link, insert_visited_directory,
        insert_visited_file, insert_visited_symbolic_link, open_connection, select_archive,
        select_archives_by_path, select_block, select_blocks_by_archive, select_blocks_by_file,
        select_closed_new_files, select_directories_by_path, select_directory, select_file,
        select_files_by_path, select_files_by_path_and_archive, select_patchset,
        select_small_archives, select_small_patchsets, select_storage_used, select_symbolic_link,
        select_symbolic_links_by_path, select_uncompressed_size, select_unused_archives,
        update_archive, update_block, update_directory, update_file, update_new_file,
        update_patchset, update_symbolic_link,
    },
    ensure_restrictive_permissions, was_interrupted, Bytes, Config, Fallible,
};

pub struct Manifest {
    conn: Connection,
}

impl Manifest {
    pub fn open(path: &Path) -> Fallible<Self> {
        ensure_restrictive_permissions(path)?;

        let conn = open_connection(path)?;

        Ok(Self { conn })
    }

    pub fn update(
        &mut self,
        keep_unvisited_files: bool,
        client: &Client,
        producer: impl FnOnce(&Mutex<Update>) -> Fallible,
    ) -> Fallible {
        let trans = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;

        delete_visited_objects(&trans)?;

        let unused_archives;
        let mut patchset;

        {
            let mut session = Session::new(&trans)?;
            session.attach(None)?;

            let archive_id = insert_def_archive(&trans)?;

            let update = Mutex::new(Update {
                conn: &trans,
                archive_id,
                archive_len: 0,
                blocks: tempfile()?,
            });

            producer(&update)?;

            let was_interrupted = was_interrupted();

            let mut update = update.into_inner().unwrap();

            if !was_interrupted && update.archive_len != 0 {
                let name = format!("archive_{}", update.archive_id);
                update.blocks.rewind()?;
                let (b2_file_id, b2_length) = client.upload(&name, &mut update.blocks)?;

                update_archive(
                    &trans,
                    update.archive_id,
                    update.archive_len,
                    &b2_file_id,
                    b2_length,
                )?;
            } else if was_interrupted || update.archive_id == archive_id {
                delete_archive(&trans, update.archive_id)?;
            }

            collect_closed_new_files(&trans)?;

            unused_archives =
                delete_unused_archives(&trans, was_interrupted || keep_unvisited_files)?;

            patchset = Vec::new();
            session.patchset_strm(&mut patchset)?;
        }

        if patchset.is_empty() {
            println!("No changes recorded");
            return Ok(());
        }

        upload_patchset(&trans, client, patchset.as_slice())?;

        let storage_used = select_storage_used(&trans)?;

        let (uncompressed_size_of_archives, uncompressed_size_of_blocks) =
            select_uncompressed_size(&trans)?;

        trans.commit()?;

        for (archive_id, b2_file_id) in unused_archives {
            let name = format!("archive_{}", archive_id);
            client.remove(&name, &b2_file_id)?;
        }

        println!(
            "{} of storage used ({} uncompressed, {} mapped)",
            Bytes(storage_used as _),
            Bytes(uncompressed_size_of_archives as _),
            Bytes(uncompressed_size_of_blocks as _)
        );

        Ok(())
    }

    pub fn maybe_collect_small_archives(&mut self, config: &Config, client: &Client) -> Fallible {
        let mut small_archives = select_small_archives(&self.conn, config.min_archive_len)?.len();

        if small_archives <= config.small_archives_upper_limit
            || config.small_archives_upper_limit == 0
        {
            return Ok(());
        }

        loop {
            println!("There are {small_archives} small archives. Collection triggered...",);

            self.collect_small_archives(config, client)?;

            small_archives = select_small_archives(&self.conn, config.min_archive_len)?.len();

            if small_archives <= config.small_archives_lower_limit {
                return Ok(());
            }
        }
    }

    pub fn collect_small_archives(&mut self, config: &Config, client: &Client) -> Fallible {
        self.update(true, client, |update| {
            let mut update = update.lock().unwrap();

            let small_archives = select_small_archives(update.conn, config.min_archive_len)?;

            if small_archives.len() <= 1 {
                return Err("Not enough small archives".into());
            }

            let mut buffer = Vec::new();

            for archive_id in &small_archives {
                let name = format!("archive_{}", archive_id);
                let mut archive = tempfile()?;
                copy(&mut client.download(&name)?, &mut archive)?;

                let blocks = select_blocks_by_archive(update.conn, *archive_id)?;

                for (block_id, stored_digest, length, archive_off) in blocks {
                    copy_file_range_full(
                        &mut buffer,
                        &archive,
                        archive_off,
                        &mut update.blocks,
                        None,
                        length,
                    )?;

                    let digest = hash(&buffer);
                    if digest != stored_digest {
                        return Err(format!(
                            "Block {} has digest {}, but should have {}.",
                            block_id,
                            digest.to_hex(),
                            hex::encode(stored_digest),
                        )
                        .into());
                    }

                    update_block(update.conn, block_id, update.archive_id, update.archive_len)?;
                    update.archive_len += length;
                }

                if update.archive_len >= config.min_archive_len {
                    break;
                }
            }

            Ok(())
        })
    }

    pub fn maybe_collect_small_patchsets(&mut self, config: &Config, client: &Client) -> Fallible {
        loop {
            let small_patchsets =
                select_small_patchsets(&self.conn, config.max_manifest_len)?.len();

            if small_patchsets <= config.small_patchsets_limit || config.small_patchsets_limit == 0
            {
                return Ok(());
            }

            println!("There are {small_patchsets} small patchsets. Collection triggered...",);

            self.collect_small_patchsets(config, client)?;
        }
    }

    pub fn collect_small_patchsets(&mut self, config: &Config, client: &Client) -> Fallible {
        let trans = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;

        let small_patchsets = select_small_patchsets(&trans, config.max_manifest_len)?;

        if small_patchsets.len() <= 1 {
            return Err("Not enough small patchsets".into());
        }

        let mut changegroup = Changegroup::new()?;

        for (patchset_id, _) in small_patchsets.iter().rev() {
            let name = format!("manifest_{}", patchset_id);
            let mut patchset = client.download(&name)?;

            changegroup.add_stream(&mut patchset)?;
        }

        let mut patchset = Vec::new();
        changegroup.output_strm(&mut patchset)?;

        upload_patchset(&trans, client, patchset.as_slice())?;

        for (patchset_id, _) in &small_patchsets {
            delete_patchset(&trans, *patchset_id)?;
        }

        trans.commit()?;

        for (patchset_id, b2_file_id) in &small_patchsets {
            let name = format!("manifest_{}", patchset_id);
            client.remove(&name, b2_file_id)?;
        }

        Ok(())
    }

    pub fn list_files(&mut self, path_filter: Option<&Path>) -> Fallible {
        let mut archives = HashSet::new();
        let mut blocks = 0;

        let trans = self.conn.transaction()?;

        select_files_by_path(&trans, path_filter, |file_id, path, size, _mode| {
            archives.clear();
            blocks = 0;

            select_blocks_by_file(
                &trans,
                file_id,
                None,
                |_length, archive_id, _archive_off, _offset| {
                    archives.insert(archive_id);
                    blocks += 1;

                    Ok(())
                },
            )?;

            println!(
                "{:>11} {:>8} {:>8} {}",
                Bytes(size as _).to_string(),
                archives.len(),
                blocks,
                path.display()
            );

            Ok(())
        })?;

        select_directories_by_path(&trans, path_filter, |path, _mode| {
            let mut files = 0;

            select_files_by_path(
                &trans,
                Some(&path.join("*")),
                |_file_id, _path, _size, _mode| {
                    files += 1;

                    Ok(())
                },
            )?;

            println!("{:>11} {:>8} {:>8} {}", "dir", files, "", path.display());

            Ok(())
        })?;

        select_symbolic_links_by_path(&trans, path_filter, |path, _target| {
            println!("{:>11} {:>8} {:>8} {}", "symlink", "", "", path.display());

            Ok(())
        })?;

        Ok(())
    }

    pub fn restore_files(
        &mut self,
        client: &Client,
        path_filter: Option<&Path>,
        target_dir: Option<&Path>,
    ) -> Fallible {
        if let Some(dir) = target_dir {
            if let Some(parent) = dir.parent() {
                create_dir_all(parent)?;
            }

            set_current_dir(dir)?;
        }

        let trans = self.conn.transaction()?;

        select_files_by_path(&trans, path_filter, |_file_id, path, size, _mode| {
            let path = path.strip_prefix("/")?;

            if let Some(parent) = path.parent() {
                create_dir_all(parent)?;
            }

            File::create(path)?.set_len(size)?;

            Ok(())
        })?;

        select_directories_by_path(&trans, path_filter, |path, _mode| {
            let path = path.strip_prefix("/")?;

            create_dir_all(path)?;

            Ok(())
        })?;

        let mut buffer = Vec::new();

        select_archives_by_path(&trans, path_filter, |archive_id| {
            let name = format!("archive_{}", archive_id);
            let mut archive = tempfile()?;
            copy(&mut client.download(&name)?, &mut archive)?;

            select_files_by_path_and_archive(&trans, path_filter, archive_id, |file_id, path| {
                println!("Restoring {}...", path.display());

                let path = path.strip_prefix("/")?;
                let mut file = OpenOptions::new().write(true).open(path)?;

                select_blocks_by_file(
                    &trans,
                    file_id,
                    Some(archive_id),
                    |length, _archive_id, archive_off, offset| {
                        copy_file_range_full(
                            &mut buffer,
                            &archive,
                            archive_off,
                            &mut file,
                            Some(offset),
                            length,
                        )
                    },
                )
            })
        })?;

        select_files_by_path(&trans, path_filter, |_file_id, path, _size, mode| {
            let path = path.strip_prefix("/")?;

            set_permissions(path, Permissions::from_mode(mode))?;

            Ok(())
        })?;

        select_directories_by_path(&trans, path_filter, |path, mode| {
            let path = path.strip_prefix("/")?;

            set_permissions(path, Permissions::from_mode(mode))?;

            Ok(())
        })?;

        select_symbolic_links_by_path(&trans, path_filter, |path, target| {
            let path = path.strip_prefix("/")?;

            if let Some(parent) = path.parent() {
                create_dir_all(parent)?;
            }

            create_symlink(path, target)?;

            Ok(())
        })?;

        Ok(())
    }

    pub fn restore_manifest(&mut self, client: &Client) -> Fallible {
        let trans = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;

        clear_tables(&trans)?;

        let patchsets = client
            .list("manifest_")?
            .into_iter()
            .map(|(name, b2_file_id, b2_length)| {
                let patchset_id = name.trim_start_matches("manifest_").parse()?;
                Ok((patchset_id, (name, b2_file_id, b2_length)))
            })
            .collect::<Fallible<BTreeMap<_, _>>>()?;

        for (patchset_id, (name, b2_file_id, b2_length)) in patchsets {
            println!("Applying patchset {}...", patchset_id);
            apply_patchset(
                &trans,
                client.download(&name)?,
                patchset_id,
                &b2_file_id,
                b2_length,
            )?;
        }

        trans.commit()?;

        Ok(())
    }

    pub fn purge_storage(&mut self, client: &Client) -> Fallible {
        let trans = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;

        for (name, b2_file_id, _) in client.list("manifest_")? {
            let patchset_id = name.trim_start_matches("manifest_").parse()?;

            if !select_patchset(&trans, patchset_id)? {
                client.remove(&name, &b2_file_id)?;
            }
        }

        for (name, b2_file_id, _) in client.list("archive_")? {
            let archive_id = name.trim_start_matches("archive_").parse()?;

            if !select_archive(&trans, archive_id)? {
                client.remove(&name, &b2_file_id)?;
            }
        }

        Ok(())
    }
}

pub struct Update<'a> {
    conn: &'a Connection,
    archive_id: i64,
    archive_len: u64,
    blocks: File,
}

unsafe impl Send for Update<'_> {}

impl Update<'_> {
    pub fn open_file(&self, path: &Path, metadata: &Metadata) -> Fallible<i64> {
        insert_new_file(self.conn, path, metadata)
    }

    pub fn close_file(&self, new_file_id: i64) -> Fallible {
        update_new_file(self.conn, new_file_id)
    }

    pub fn directory(&self, path: &Path, metadata: &Metadata) -> Fallible {
        let dir_id = if let Some(dir_id) = select_directory(self.conn, path)? {
            update_directory(self.conn, dir_id, metadata)?;

            dir_id
        } else {
            insert_directory(self.conn, path, metadata)?
        };

        insert_visited_directory(self.conn, dir_id)?;

        Ok(())
    }

    pub fn symlink(&self, path: &Path, target: &Path) -> Fallible {
        let symlink_id = if let Some(symlink_id) = select_symbolic_link(self.conn, path)? {
            update_symbolic_link(self.conn, symlink_id, target)?;

            symlink_id
        } else {
            insert_symbolic_link(self.conn, path, target)?
        };

        insert_visited_symbolic_link(self.conn, symlink_id)?;

        Ok(())
    }
}

fn collect_closed_new_files(conn: &Connection) -> Fallible {
    select_closed_new_files(conn, |new_file_id, path| {
        let file_id = if let Some(file_id) = select_file(conn, path)? {
            update_file(conn, file_id, new_file_id)?;
            delete_mappings(conn, file_id)?;

            file_id
        } else {
            insert_file(conn, new_file_id)?
        };

        insert_mappings(conn, file_id, new_file_id)?;
        insert_visited_file(conn, file_id)?;

        delete_new_file(conn, new_file_id)?;

        Ok(())
    })
}

pub fn store_block(
    update: &Mutex<Update>,
    config: &Config,
    client: &Client,
    new_file_id: i64,
    offset: u64,
    block: &[u8],
) -> Fallible {
    let digest = hash(block);

    let archive_id;
    let archive_len;
    let mut blocks;

    {
        let mut update = update.lock().unwrap();

        let block_id = select_block(update.conn, digest.as_bytes())?;

        if let Some(block_id) = block_id {
            return insert_new_mapping(update.conn, new_file_id, offset, block_id);
        }

        let length = block.len().try_into().unwrap();
        let block_id = insert_block(
            update.conn,
            digest.as_bytes(),
            length,
            update.archive_id,
            update.archive_len,
        )?;

        insert_new_mapping(update.conn, new_file_id, offset, block_id)?;

        update.blocks.write_all(block)?;

        update.archive_len += length;
        if update.archive_len < config.min_archive_len {
            return Ok(());
        }

        let next_archive_id = insert_def_archive(update.conn)?;

        archive_id = replace(&mut update.archive_id, next_archive_id);
        archive_len = replace(&mut update.archive_len, 0);
        blocks = replace(&mut update.blocks, tempfile()?);
    };

    let name = format!("archive_{}", archive_id);
    blocks.rewind()?;
    let (b2_file_id, b2_length) = client.upload(&name, &mut blocks)?;

    let update = update.lock().unwrap();

    update_archive(update.conn, archive_id, archive_len, &b2_file_id, b2_length)?;
    collect_closed_new_files(update.conn)?;

    Ok(())
}

fn upload_patchset(conn: &Connection, client: &Client, patchset: impl Read) -> Fallible {
    let patchset_id = insert_def_patchset(conn)?;

    let name = format!("manifest_{}", patchset_id);
    let (b2_file_id, b2_length) = client.upload(&name, patchset)?;

    update_patchset(conn, patchset_id, &b2_file_id, b2_length)?;

    Ok(())
}

fn apply_patchset(
    conn: &Connection,
    mut patchset: impl Read,
    patchset_id: i64,
    b2_file_id: &str,
    b2_length: u64,
) -> Fallible {
    conn.apply_strm(
        &mut patchset,
        None::<fn(&str) -> bool>,
        |conflict_type, _item| match conflict_type {
            ConflictType::SQLITE_CHANGESET_DATA | ConflictType::SQLITE_CHANGESET_CONFLICT => {
                ConflictAction::SQLITE_CHANGESET_REPLACE
            }
            _ => ConflictAction::SQLITE_CHANGESET_OMIT,
        },
    )?;

    insert_patchset(conn, patchset_id, b2_file_id, b2_length)
}

fn delete_unused_archives(
    conn: &Connection,
    keep_unvisited_files: bool,
) -> Fallible<Vec<(i64, String)>> {
    if !keep_unvisited_files {
        let deleted_files = delete_unvisited_files(conn)?;
        let deleted_dirs = delete_unvisited_directories(conn)?;
        let deleted_symlinks = delete_unvisited_symbolic_links(conn)?;
        println!(
            "Deleted {} unvisited files, {} unvisted directories and {} unvisited symbolic links",
            deleted_files, deleted_dirs, deleted_symlinks
        );
    }

    let deleted_blocks = delete_unused_blocks(conn)?;
    println!("Deleted {} unmapped blocks", deleted_blocks);

    let unused_archives = select_unused_archives(conn)?;

    for (archive_id, _) in &unused_archives {
        delete_archive(conn, *archive_id)?;
    }

    println!("Deleted {} unused archives", unused_archives.len());

    Ok(unused_archives)
}
