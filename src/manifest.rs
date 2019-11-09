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
use std::collections::BTreeMap;
use std::convert::{TryFrom, TryInto};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::mem::replace;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::Path;
use std::sync::Mutex;

use rusqlite::{
    params,
    session::{Changegroup, ConflictAction, ConflictType, Session},
    Connection, OptionalExtension, TransactionBehavior, NO_PARAMS,
};
use sodiumoxide::crypto::hash::sha256::{hash, DIGESTBYTES};
use tempfile::tempfile;

use super::{client::Client, Bytes, Config, Fallible};

pub struct Manifest {
    conn: Connection,
}

impl Manifest {
    pub fn open<P: AsRef<Path>>(path: P) -> Fallible<Self> {
        let conn = Connection::open(path)?;

        conn.execute_batch(
            r#"
BEGIN;

CREATE TABLE IF NOT EXISTS patchsets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    b2_file_id TEXT,
    b2_length INTEGER
);

CREATE TABLE IF NOT EXISTS archives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    length INTEGER,
    b2_file_id TEXT,
    b2_length INTEGER
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY,
    path BLOB NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    uid INTEGER NOT NULL,
    gid INTEGER NOT NULL,
    mode INTEGER NOT NULL,
    symlink BLOB
);

CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY,
    digest BLOB NOT NULL UNIQUE,
    archive_id INTEGER NOT NULL REFERENCES archives (id)
);

CREATE TABLE IF NOT EXISTS mappings (
    file_id INTEGER NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    offset INTEGER NOT NULL,
    block_id INTEGER NOT NULL REFERENCES blocks (id),
    PRIMARY KEY (file_id, offset)
)
WITHOUT ROWID;

CREATE TEMPORARY TABLE visited_files (
    file_id INTEGER PIMARY KEY
);

COMMIT;
"#,
        )?;

        Ok(Self { conn })
    }

    pub fn update<P>(
        &mut self,
        keep_unvisited_files: bool,
        client: &Client,
        producer: P,
    ) -> Fallible
    where
        P: FnOnce(&Mutex<Update>) -> Fallible,
    {
        let trans = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;

        delete_visited_files(&trans)?;

        let unused_archives;
        let mut patchset;

        {
            let mut session = Session::new(&trans)?;
            session.attach(None)?;

            let archive_id = insert_archive(&trans)?;

            let update = Mutex::new(Update {
                conn: &trans,
                archive: Archive::new(archive_id)?,
            });

            producer(&update)?;

            let mut archive = update.into_inner().unwrap().archive;

            let archive_len = archive.len()?;
            if archive_len != 0 {
                let (b2_file_id, b2_length) = archive.upload(client)?;

                update_archive(&trans, archive.id, archive_len, &b2_file_id, b2_length)?;
            } else if archive_id == archive.id {
                delete_archive(&trans, archive_id)?;
            }

            unused_archives = delete_unused_archives(&trans, keep_unvisited_files)?;

            patchset = Vec::new();
            session.patchset_strm(&mut patchset)?;

            if patchset.is_empty() {
                println!("No changes recorded");
                return Ok(());
            }
        }

        upload_patchset(&trans, client, &patchset)?;

        trans.commit()?;

        for (archive_id, b2_file_id) in unused_archives {
            let name = format!("archive_{}", archive_id);
            client.remove(&name, &b2_file_id)?;
        }

        Ok(())
    }

    pub fn collect_small_archives(&mut self, config: &Config, client: &Client) -> Fallible {
        self.update(true, client, |update| {
            update
                .lock()
                .unwrap()
                .collect_small_archives(config, client)
        })
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

        upload_patchset(&trans, client, &patchset)?;

        for (patchset_id, _) in &small_patchsets {
            delete_patchset(&trans, *patchset_id)?;
        }

        trans.commit()?;

        for (patchset_id, b2_file_id) in &small_patchsets {
            let name = format!("manifest_{}", patchset_id);
            client.remove(&name, &b2_file_id)?;
        }

        Ok(())
    }

    pub fn restore(&mut self, client: &Client) -> Fallible {
        let patchsets = client.list("manifest_")?;

        let trans = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Exclusive)?;

        trans.execute_batch(
            r#"
DELETE FROM mappings;
DELETE FROM blocks;
DELETE FROM files;
DELETE FROM archives;
DELETE FROM patchsets;
        "#,
        )?;

        let patchsets = patchsets
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
                patchset_id,
                client.download(&name)?,
                &b2_file_id,
                b2_length,
            )?;
        }

        trans.commit()?;

        Ok(())
    }

    pub fn list_files(&self, path_filter: Option<&str>) -> Fallible {
        let mut stmt = self.conn.prepare(
            r#"
SELECT
    files.size,
    COUNT(DISTINCT blocks.id),
    COUNT(DISTINCT blocks.archive_id),
    files.path
FROM files, mappings, blocks
WHERE files.id = mappings.file_id
AND mappings.block_id = blocks.id
AND IFNULL(files.path GLOB ?, TRUE)
GROUP BY files.id
ORDER BY MAX(blocks.archive_id) DESC
"#,
        )?;

        let mut rows = stmt.query(params![path_filter])?;

        while let Some(row) = rows.next()? {
            let size: i64 = row.get(0)?;
            let blocks: i64 = row.get(1)?;
            let archives: i64 = row.get(2)?;
            let path = Path::new(OsStr::from_bytes(row.get_raw(3).as_blob()?));

            println!(
                "{:>11} {:>8} {:>8} {}",
                Bytes(size as _).to_string(),
                blocks,
                archives,
                path.display()
            );
        }

        Ok(())
    }
}

pub struct Update<'a> {
    conn: &'a Connection,
    archive: Archive,
}

unsafe impl Send for Update<'_> {}

pub fn add_file(
    self_: &Mutex<Update>,
    path: &Path,
    metadata: &Metadata,
    symlink: Option<&Path>,
) -> Fallible<i64> {
    let path = path.as_os_str().as_bytes();
    let symlink = symlink.map(|symlink| symlink.as_os_str().as_bytes());

    let self_ = self_.lock().unwrap();

    let file_id = select_file(self_.conn, path)?;

    if let Some(file_id) = file_id {
        update_file(self_.conn, file_id, metadata, symlink)?;

        return Ok(file_id);
    }

    insert_file(self_.conn, path, metadata, symlink)
}

pub fn add_block(
    self_: &Mutex<Update>,
    config: &Config,
    client: &Client,
    file_id: i64,
    offset: u64,
    block: &[u8],
) -> Fallible {
    let digest = hash(block);

    let archive_len;
    let mut archive;

    {
        let mut self_ = self_.lock().unwrap();

        let block_id = select_block(self_.conn, digest.as_ref())?;

        if let Some(block_id) = block_id {
            return insert_mapping(self_.conn, file_id, offset, block_id);
        }

        let block_id = insert_block(self_.conn, digest.as_ref(), self_.archive.id)?;

        insert_mapping(self_.conn, file_id, offset, block_id)?;

        self_.archive.add_block(digest.as_ref(), block)?;

        archive_len = self_.archive.len()?;
        if archive_len < config.min_archive_len {
            return Ok(());
        }

        let archive_id = insert_archive(self_.conn)?;
        archive = replace(&mut self_.archive, Archive::new(archive_id)?)
    };

    let (b2_file_id, b2_length) = archive.upload(client)?;

    let self_ = self_.lock().unwrap();

    update_archive(self_.conn, archive.id, archive_len, &b2_file_id, b2_length)?;

    Ok(())
}

impl Update<'_> {
    fn collect_small_archives(&mut self, config: &Config, client: &Client) -> Fallible {
        let small_archives = select_small_archives(self.conn, config.min_archive_len)?;

        if small_archives.len() <= 1 {
            return Err("Not enough small archives".into());
        }

        for archive_id in &small_archives {
            let name = format!("archive_{}", archive_id);
            let archive = client.download(&name)?;

            let mut updated_blocks = 0;
            let mut blocks = 0;

            Archive::read(archive, |digest, block| {
                if let Some(block_id) = select_block(self.conn, digest)? {
                    self.archive.add_block(digest, block)?;

                    update_block(self.conn, block_id, self.archive.id)?;

                    updated_blocks += 1;
                }

                blocks += 1;

                Ok(())
            })?;

            println!("Updated {} out of {} blocks", updated_blocks, blocks);

            if self.archive.len()? >= config.min_archive_len {
                break;
            }
        }

        Ok(())
    }
}

fn upload_patchset(conn: &Connection, client: &Client, patchset: &[u8]) -> Fallible {
    let patchset_id = insert_patchset(conn)?;

    let name = format!("manifest_{}", patchset_id);
    let (b2_file_id, b2_length) = client.upload(&name, patchset)?;

    update_patchset(
        conn,
        patchset_id,
        &b2_file_id,
        b2_length.try_into().unwrap(),
    )?;

    Ok(())
}

fn apply_patchset(
    conn: &Connection,
    patchset_id: i64,
    mut patchset: impl Read,
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

    conn.execute(
        "INSERT INTO patchsets (id, b2_file_id, b2_length) VALUES (?, ?, ?)",
        params![patchset_id, b2_file_id, b2_length as i64],
    )?;

    Ok(())
}

struct Archive {
    id: i64,
    blocks: File,
}

impl Archive {
    fn new(id: i64) -> Fallible<Self> {
        Ok(Self {
            id,
            blocks: tempfile()?,
        })
    }

    fn add_block(&mut self, digest: &[u8], block: &[u8]) -> Fallible {
        let block_len = u32::try_from(block.len()).unwrap().to_be_bytes();

        self.blocks.write_all(digest)?;
        self.blocks.write_all(&block_len)?;
        self.blocks.write_all(block)?;

        Ok(())
    }

    fn len(&mut self) -> Fallible<u64> {
        let len = self.blocks.seek(SeekFrom::Current(0))?;

        Ok(len)
    }

    fn upload(&mut self, client: &Client) -> Fallible<(String, u64)> {
        let name = format!("archive_{}", self.id);
        self.blocks.seek(SeekFrom::Start(0))?;
        let (b2_file_id, b2_length) = client.upload(&name, &mut self.blocks)?;

        Ok((b2_file_id, b2_length))
    }

    fn read<R, C>(mut reader: R, mut consumer: C) -> Fallible
    where
        R: Read,
        C: FnMut(&[u8], &[u8]) -> Fallible,
    {
        let mut digest = [0; DIGESTBYTES];
        let mut block_len = [0; 4];
        let mut block = Vec::new();

        loop {
            match reader.read_exact(&mut digest[..]) {
                Ok(()) => (),
                Err(err) if err.kind() == ErrorKind::UnexpectedEof => break,
                Err(err) => return Err(err.into()),
            }

            reader.read_exact(&mut block_len[..])?;

            block.resize(u32::from_be_bytes(block_len).try_into().unwrap(), 0);
            reader.read_exact(&mut block)?;

            consumer(&digest, &block)?;
        }

        Ok(())
    }
}

fn insert_patchset(conn: &Connection) -> Fallible<i64> {
    conn.execute("INSERT INTO patchsets DEFAULT VALUES", NO_PARAMS)?;
    let patchset_id = conn.last_insert_rowid();

    Ok(patchset_id)
}

fn update_patchset(
    conn: &Connection,
    patchset_id: i64,
    b2_file_id: &str,
    b2_length: u64,
) -> Fallible {
    conn.execute(
        "UPDATE patchsets SET b2_file_id = ?, b2_length = ? WHERE id = ?",
        params![b2_file_id, b2_length as i64, patchset_id],
    )?;

    Ok(())
}

fn delete_patchset(conn: &Connection, patchset_id: i64) -> Fallible<()> {
    conn.execute("DELETE FROM patchsets WHERE id = ?", params![patchset_id])?;

    Ok(())
}

fn insert_archive(conn: &Connection) -> Fallible<i64> {
    conn.execute("INSERT INTO archives DEFAULT VALUES", NO_PARAMS)?;
    let archive_id = conn.last_insert_rowid();

    Ok(archive_id)
}

fn update_archive(
    conn: &Connection,
    archive_id: i64,
    length: u64,
    b2_file_id: &str,
    b2_length: u64,
) -> Fallible {
    conn.execute(
        "UPDATE archives SET length = ?, b2_file_id = ?, b2_length = ? WHERE id = ?",
        params![length as i64, b2_file_id, b2_length as i64, archive_id],
    )?;

    Ok(())
}

fn delete_archive(conn: &Connection, archive_id: i64) -> Fallible {
    conn.execute("DELETE FROM archives WHERE id = ?", params![archive_id])?;

    Ok(())
}

fn select_file(conn: &Connection, path: &[u8]) -> Fallible<Option<i64>> {
    let mut stmt = conn.prepare_cached("SELECT id FROM files WHERE path = ?")?;

    let file_id = stmt.query_row(params![path], |row| row.get(0)).optional()?;

    Ok(file_id)
}

fn insert_file(
    conn: &Connection,
    path: &[u8],
    metadata: &Metadata,
    symlink: Option<&[u8]>,
) -> Fallible<i64> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO files (path, size, uid, gid, mode, symlink) VALUES (?, ?, ?, ?, ?, ?)",
    )?;

    stmt.execute(params![
        path,
        metadata.size() as i64,
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        symlink,
    ])?;
    let file_id = conn.last_insert_rowid();

    insert_visited_file(conn, file_id)?;

    Ok(file_id)
}

fn update_file(
    conn: &Connection,
    file_id: i64,
    metadata: &Metadata,
    symlink: Option<&[u8]>,
) -> Fallible {
    let mut stmt = conn.prepare_cached(
        "UPDATE files SET size = ?, uid = ?, gid = ?, mode = ?, symlink = ? WHERE id = ?",
    )?;

    stmt.execute(params![
        metadata.size() as i64,
        metadata.uid(),
        metadata.gid(),
        metadata.mode(),
        symlink,
        file_id
    ])?;

    insert_visited_file(conn, file_id)?;

    delete_mappings(conn, file_id)?;

    Ok(())
}

fn select_block(conn: &Connection, digest: &[u8]) -> Fallible<Option<i64>> {
    let mut stmt = conn.prepare_cached("SELECT id FROM blocks WHERE digest = ?")?;

    let block_id = stmt
        .query_row(params![digest], |row| row.get(0))
        .optional()?;

    Ok(block_id)
}

fn insert_block(conn: &Connection, digest: &[u8], archive_id: i64) -> Fallible<i64> {
    let mut stmt = conn.prepare_cached("INSERT INTO blocks (digest, archive_id) VALUES (?, ?)")?;

    stmt.execute(params![digest, archive_id])?;
    let block_id = conn.last_insert_rowid();

    Ok(block_id)
}

fn update_block(conn: &Connection, block_id: i64, archive_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached("UPDATE blocks SET archive_id = ? WHERE id = ?")?;

    stmt.execute(params![archive_id, block_id])?;

    Ok(())
}

fn insert_mapping(conn: &Connection, file_id: i64, offset: u64, block_id: i64) -> Fallible {
    let mut stmt =
        conn.prepare_cached("INSERT INTO mappings (file_id, offset, block_id) VALUES (?, ?, ?)")?;

    stmt.execute(params![file_id, offset as i64, block_id])?;

    Ok(())
}

fn delete_mappings(conn: &Connection, file_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached("DELETE FROM mappings WHERE file_id = ?")?;

    stmt.execute(params![file_id])?;

    Ok(())
}

fn insert_visited_file(conn: &Connection, file_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached("INSERT INTO visited_files (file_id) VALUES (?)")?;

    stmt.execute(params![file_id])?;

    Ok(())
}

fn delete_visited_files(conn: &Connection) -> Fallible {
    conn.execute("DELETE FROM visited_files", NO_PARAMS)?;

    Ok(())
}

fn delete_unused_archives(
    conn: &Connection,
    keep_unvisited_files: bool,
) -> Fallible<Vec<(i64, String)>> {
    if !keep_unvisited_files {
        let deleted_files = conn.execute(
            "DELETE FROM files WHERE id NOT IN (SELECT file_id FROM visited_files)",
            NO_PARAMS,
        )?;
        println!("Deleted {} unvisited files", deleted_files);
    }

    let deleted_blocks = conn.execute(
        "DELETE FROM blocks WHERE id NOT IN (SELECT block_id FROM mappings)",
        NO_PARAMS,
    )?;
    println!("Deleted {} unmapped blocks", deleted_blocks);

    let mut stmt = conn.prepare(
        "SELECT id, b2_file_id FROM archives WHERE id NOT IN (SELECT archive_id FROM blocks)",
    )?;

    let unused_archives = stmt
        .query_map(NO_PARAMS, |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    let mut stmt = conn.prepare("DELETE FROM archives WHERE id = ?")?;

    for (id, _) in &unused_archives {
        stmt.execute(params![id])?;
    }

    println!("Deleted {} unused archives", unused_archives.len());

    Ok(unused_archives)
}

fn select_small_patchsets(
    conn: &Connection,
    max_manifest_len: u64,
) -> Fallible<Vec<(i64, String)>> {
    let mut stmt = conn.prepare(
        r#"
SELECT
    ids.id,
    ids.b2_file_id
FROM patchsets ids
WHERE (
    SELECT
        SUM(lengths.b2_length)
    FROM patchsets lengths
    WHERE lengths.id >= ids.id
) < ?
ORDER BY ids.id DESC
"#,
    )?;

    let small_patchsets = stmt
        .query_map(params![max_manifest_len as i64], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(small_patchsets)
}

fn select_small_archives(conn: &Connection, min_archive_len: u64) -> Fallible<Vec<i64>> {
    let mut stmt = conn.prepare(
        r#"
SELECT
    archives.id
FROM archives, blocks
WHERE archives.id = blocks.archive_id
AND archives.length < ?
GROUP BY archives.id
ORDER BY COUNT(blocks.id) ASC, archives.length DESC
"#,
    )?;

    let small_archives = stmt
        .query_map(params![min_archive_len as i64], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(small_archives)
}
