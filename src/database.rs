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
use std::ffi::OsStr;
use std::fs::Metadata;
use std::os::unix::{ffi::OsStrExt, fs::MetadataExt};
use std::path::Path;

use blake3::OUT_LEN as DIGEST_LEN;
use rusqlite::{
    params,
    types::{FromSqlError, ValueRef},
    Connection, OptionalExtension, NO_PARAMS,
};

use super::Fallible;

pub fn open_connection(path: impl AsRef<Path>) -> Fallible<Connection> {
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
    mode INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS directories (
    id INTEGER PRIMARY KEY,
    path BLOB NOT NULL UNIQUE,
    mode INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS symbolic_links (
    id INTEGER PRIMARY KEY,
    path BLOB NOT NULL UNIQUE,
    target BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY,
    digest BLOB NOT NULL UNIQUE,
    length INTEGER NOT NULL,
    archive_id INTEGER NOT NULL REFERENCES archives (id) ON DELETE CASCADE,
    archive_off INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS blocks_by_archive ON blocks (archive_id);

CREATE TABLE IF NOT EXISTS mappings (
    file_id INTEGER NOT NULL REFERENCES files (id) ON DELETE CASCADE,
    offset INTEGER NOT NULL,
    block_id INTEGER NOT NULL REFERENCES blocks (id),
    PRIMARY KEY (file_id, offset)
)
WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS mappings_by_block ON mappings (block_id);

CREATE TEMPORARY TABLE visited_files (
    file_id INTEGER PIMARY KEY
);

CREATE TEMPORARY TABLE visited_directories (
    directory_id INTEGER PIMARY KEY
);

CREATE TEMPORARY TABLE visited_symbolic_links (
    symbolic_link_id INTEGER PIMARY KEY
);

CREATE TEMPORARY TABLE new_files (
    id INTEGER PRIMARY KEY,
    path BLOB NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    mode INTEGER NOT NULL,
    closed INTEGER NOT NULL DEFAULT FALSE
);

CREATE TEMPORARY TABLE new_mappings (
    new_file_id INTEGER NOT NULL REFERENCES new_files (id) ON DELETE CASCADE,
    offset INTEGER NOT NULL,
    block_id INTEGER NOT NULL,
    PRIMARY KEY (new_file_id, offset)
)
WITHOUT ROWID;

COMMIT;
"#,
    )?;

    conn.set_prepared_statement_cache_capacity(32);

    Ok(conn)
}

pub fn clear_tables(conn: &Connection) -> Fallible {
    conn.execute_batch(
        r#"
DELETE FROM mappings;
DELETE FROM blocks;
DELETE FROM symbolic_links;
DELETE FROM directories;
DELETE FROM files;
DELETE FROM archives;
DELETE FROM patchsets;
        "#,
    )?;

    Ok(())
}

pub fn select_patchset(conn: &Connection, patchset_id: i64) -> Fallible<bool> {
    let mut stmt = conn.prepare_cached("SELECT TRUE FROM patchsets WHERE id = ?")?;

    let exists: Option<bool> = stmt
        .query_row(params![patchset_id], |row| row.get(0))
        .optional()?;

    Ok(exists.is_some())
}

pub fn insert_def_patchset(conn: &Connection) -> Fallible<i64> {
    conn.execute("INSERT INTO patchsets DEFAULT VALUES", NO_PARAMS)?;
    let patchset_id = conn.last_insert_rowid();

    Ok(patchset_id)
}

pub fn insert_patchset(
    conn: &Connection,
    patchset_id: i64,
    b2_file_id: &str,
    b2_length: u64,
) -> Fallible {
    conn.execute(
        "INSERT INTO patchsets (id, b2_file_id, b2_length) VALUES (?, ?, ?)",
        params![patchset_id, b2_file_id, b2_length as i64],
    )?;

    Ok(())
}

pub fn update_patchset(
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

pub fn delete_patchset(conn: &Connection, patchset_id: i64) -> Fallible {
    conn.execute("DELETE FROM patchsets WHERE id = ?", params![patchset_id])?;

    Ok(())
}

pub fn select_archive(conn: &Connection, archive_id: i64) -> Fallible<bool> {
    let mut stmt = conn.prepare_cached("SELECT TRUE FROM archives WHERE id = ?")?;

    let exists: Option<bool> = stmt
        .query_row(params![archive_id], |row| row.get(0))
        .optional()?;

    Ok(exists.is_some())
}

pub fn insert_def_archive(conn: &Connection) -> Fallible<i64> {
    conn.execute("INSERT INTO archives DEFAULT VALUES", NO_PARAMS)?;
    let archive_id = conn.last_insert_rowid();

    Ok(archive_id)
}

pub fn update_archive(
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

pub fn delete_archive(conn: &Connection, archive_id: i64) -> Fallible {
    conn.execute("DELETE FROM archives WHERE id = ?", params![archive_id])?;

    Ok(())
}

pub fn select_archives_by_path(
    conn: &Connection,
    path_filter: Option<&Path>,
    mut consumer: impl FnMut(i64) -> Fallible,
) -> Fallible {
    let mut stmt = conn.prepare(
        r#"
SELECT DISTINCT blocks.archive_id
FROM files, mappings, blocks
WHERE files.id = mappings.file_id
AND mappings.block_id = blocks.id
AND IFNULL(files.path GLOB ?, TRUE)
"#,
    )?;

    let mut rows = stmt.query(params![path_filter.map(path_as_bytes)])?;
    while let Some(row) = rows.next()? {
        let archive_id = row.get(0)?;

        consumer(archive_id)?;
    }

    Ok(())
}

pub fn select_file(conn: &Connection, path: &Path) -> Fallible<Option<i64>> {
    let mut stmt = conn.prepare_cached("SELECT id FROM files WHERE path = ?")?;

    let file_id = stmt
        .query_row(params![path_as_bytes(path)], |row| row.get(0))
        .optional()?;

    Ok(file_id)
}

pub fn insert_file(conn: &Connection, new_file_id: i64) -> Fallible<i64> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO files (path, size, mode) SELECT path, size, mode FROM new_files WHERE id = ?",
    )?;

    stmt.execute(params![new_file_id])?;
    let file_id = conn.last_insert_rowid();

    Ok(file_id)
}

pub fn update_file(conn: &Connection, file_id: i64, new_file_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached("SELECT size, mode FROM new_files WHERE id = ?")?;

    let mut rows = stmt.query(params![new_file_id])?;
    let row = rows
        .next()?
        .ok_or_else(|| format!("Invalid new file ID {}", new_file_id))?;

    let size = row.get_raw(0).as_i64()?;
    let mode = row.get_raw(1).as_i64()?;

    let mut stmt = conn.prepare_cached("UPDATE files SET size = ?, mode = ? WHERE id = ?")?;

    stmt.execute(params![size, mode, file_id])?;

    Ok(())
}

pub fn select_files_by_path(
    conn: &Connection,
    path_filter: Option<&Path>,
    mut consumer: impl FnMut(i64, &Path, u64, u32) -> Fallible,
) -> Fallible {
    let mut stmt =
        conn.prepare("SELECT id, path, size, mode FROM files WHERE IFNULL(path GLOB ?, TRUE)")?;

    let mut rows = stmt.query(params![path_filter.map(path_as_bytes)])?;
    while let Some(row) = rows.next()? {
        let file_id = row.get(0)?;
        let path = path_from_blob(row.get_raw(1))?;
        let size = row.get_raw(2).as_i64()? as u64;
        let mode = row.get(3)?;

        consumer(file_id, path, size, mode)?;
    }

    Ok(())
}

pub fn select_files_by_path_and_archive(
    conn: &Connection,
    path_filter: Option<&Path>,
    archive_id: i64,
    mut consumer: impl FnMut(i64, &Path) -> Fallible,
) -> Fallible {
    let mut stmt = conn.prepare(
        r#"
SELECT
    id,
    path
FROM files
WHERE IFNULL(path GLOB ?, TRUE)
AND id IN (
    SELECT mappings.file_id
    FROM mappings, blocks
    WHERE mappings.block_id = blocks.id
    AND blocks.archive_id = ?
)
"#,
    )?;

    let mut rows = stmt.query(params![path_filter.map(path_as_bytes), archive_id])?;
    while let Some(row) = rows.next()? {
        let file_id = row.get(0)?;
        let path = path_from_blob(row.get_raw(1))?;

        consumer(file_id, path)?;
    }

    Ok(())
}

pub fn select_directory(conn: &Connection, path: &Path) -> Fallible<Option<i64>> {
    let mut stmt = conn.prepare_cached("SELECT id FROM directories WHERE path = ?")?;

    let directory_id = stmt
        .query_row(params![path_as_bytes(path)], |row| row.get(0))
        .optional()?;

    Ok(directory_id)
}

pub fn insert_directory(conn: &Connection, path: &Path, metadata: &Metadata) -> Fallible<i64> {
    let mut stmt = conn.prepare_cached("INSERT INTO directories (path, mode) VALUES (?, ?)")?;

    stmt.execute(params![path_as_bytes(path), metadata.mode()])?;
    let directory_id = conn.last_insert_rowid();

    Ok(directory_id)
}

pub fn update_directory(conn: &Connection, directory_id: i64, metadata: &Metadata) -> Fallible {
    let mut stmt = conn.prepare_cached("UPDATE directories SET mode = ? WHERE id = ?")?;

    stmt.execute(params![metadata.mode(), directory_id])?;

    Ok(())
}

pub fn select_directories_by_path(
    conn: &Connection,
    path_filter: Option<&Path>,
    mut consumer: impl FnMut(&Path, u32) -> Fallible,
) -> Fallible {
    let mut stmt =
        conn.prepare("SELECT path, mode FROM directories WHERE IFNULL(path GLOB ?, TRUE)")?;

    let mut rows = stmt.query(params![path_filter.map(path_as_bytes)])?;
    while let Some(row) = rows.next()? {
        let path = path_from_blob(row.get_raw(0))?;
        let mode = row.get(1)?;

        consumer(path, mode)?;
    }

    Ok(())
}

pub fn select_symbolic_link(conn: &Connection, path: &Path) -> Fallible<Option<i64>> {
    let mut stmt = conn.prepare_cached("SELECT id FROM symbolic_links WHERE path = ?")?;

    let symbolic_link_id = stmt
        .query_row(params![path_as_bytes(path)], |row| row.get(0))
        .optional()?;

    Ok(symbolic_link_id)
}

pub fn insert_symbolic_link(conn: &Connection, path: &Path, target: &Path) -> Fallible<i64> {
    let mut stmt =
        conn.prepare_cached("INSERT INTO symbolic_links (path, target) VALUES (?, ?)")?;

    stmt.execute(params![path_as_bytes(path), path_as_bytes(target)])?;
    let symbolic_link_id = conn.last_insert_rowid();

    Ok(symbolic_link_id)
}

pub fn update_symbolic_link(conn: &Connection, symbolic_link_id: i64, target: &Path) -> Fallible {
    let mut stmt = conn.prepare_cached("UPDATE symbolic_links SET target = ? WHERE id = ?")?;

    stmt.execute(params![path_as_bytes(target), symbolic_link_id])?;

    Ok(())
}

pub fn select_symbolic_links_by_path(
    conn: &Connection,
    path_filter: Option<&Path>,
    mut consumer: impl FnMut(&Path, &Path) -> Fallible,
) -> Fallible {
    let mut stmt =
        conn.prepare("SELECT path, target FROM symbolic_links WHERE IFNULL(path GLOB ?, TRUE)")?;

    let mut rows = stmt.query(params![path_filter.map(path_as_bytes)])?;
    while let Some(row) = rows.next()? {
        let path = path_from_blob(row.get_raw(0))?;
        let target = path_from_blob(row.get_raw(1))?;

        consumer(path, target)?;
    }

    Ok(())
}

pub fn select_block(conn: &Connection, digest: &[u8]) -> Fallible<Option<i64>> {
    let mut stmt = conn.prepare_cached("SELECT id FROM blocks WHERE digest = ?")?;

    let block_id = stmt
        .query_row(params![digest], |row| row.get(0))
        .optional()?;

    Ok(block_id)
}

pub fn insert_block(
    conn: &Connection,
    digest: &[u8],
    length: u64,
    archive_id: i64,
    archive_off: u64,
) -> Fallible<i64> {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO blocks (digest, length, archive_id, archive_off) VALUES (?, ?, ?, ?)",
    )?;

    stmt.execute(params![
        digest,
        length as i64,
        archive_id,
        archive_off as i64
    ])?;
    let block_id = conn.last_insert_rowid();

    Ok(block_id)
}

pub fn update_block(
    conn: &Connection,
    block_id: i64,
    archive_id: i64,
    archive_off: u64,
) -> Fallible {
    let mut stmt =
        conn.prepare_cached("UPDATE blocks SET archive_id = ?, archive_off = ? WHERE id = ?")?;

    stmt.execute(params![archive_id, archive_off as i64, block_id])?;

    Ok(())
}

#[allow(clippy::type_complexity)]
pub fn select_blocks_by_archive(
    conn: &Connection,
    archive_id: i64,
) -> Fallible<Vec<(i64, [u8; DIGEST_LEN], u64, u64)>> {
    let mut stmt = conn.prepare(
        "SELECT id, digest, length, archive_off FROM blocks WHERE archive_id = ? ORDER BY archive_off ASC",
    )?;

    let blocks = stmt
        .query_map(params![archive_id], |row| {
            Ok((
                row.get_raw(0).as_i64()?,
                <[u8; DIGEST_LEN]>::try_from(row.get_raw(1).as_blob()?).unwrap(),
                row.get_raw(2).as_i64()? as u64,
                row.get_raw(3).as_i64()? as u64,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(blocks)
}

pub fn select_blocks_by_file(
    conn: &Connection,
    file_id: i64,
    archive_id: Option<i64>,
    mut consumer: impl FnMut(u64, i64, u64, u64) -> Fallible,
) -> Fallible {
    let mut stmt = conn.prepare_cached(
        r#"
SELECT
    blocks.length,
    blocks.archive_id,
    blocks.archive_off,
    mappings.offset
FROM mappings, blocks
WHERE mappings.block_id = blocks.id
AND mappings.file_id = ?
AND IFNULL(blocks.archive_id = ?, TRUE)
ORDER BY blocks.archive_id ASC, blocks.archive_off ASC, mappings.offset ASC
"#,
    )?;

    let mut rows = stmt.query(params![file_id, archive_id])?;
    while let Some(row) = rows.next()? {
        let length = row.get_raw(0).as_i64()? as u64;
        let archive_id = row.get(1)?;
        let archive_off = row.get_raw(2).as_i64()? as u64;
        let offset = row.get_raw(3).as_i64()? as u64;

        consumer(length, archive_id, archive_off, offset)?;
    }

    Ok(())
}

pub fn insert_mappings(conn: &Connection, file_id: i64, new_file_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached("INSERT INTO mappings (file_id, offset, block_id) SELECT ?, offset, block_id FROM new_mappings WHERE new_file_id = ?")?;

    stmt.execute(params![file_id, new_file_id])?;

    Ok(())
}

pub fn delete_mappings(conn: &Connection, file_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached("DELETE FROM mappings WHERE file_id = ?")?;

    stmt.execute(params![file_id])?;

    Ok(())
}

pub fn insert_visited_file(conn: &Connection, file_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached("INSERT INTO visited_files (file_id) VALUES (?)")?;

    stmt.execute(params![file_id])?;

    Ok(())
}

pub fn insert_visited_directory(conn: &Connection, directory_id: i64) -> Fallible {
    let mut stmt =
        conn.prepare_cached("INSERT INTO visited_directories (directory_id) VALUES (?)")?;

    stmt.execute(params![directory_id])?;

    Ok(())
}

pub fn insert_visited_symbolic_link(conn: &Connection, symbolic_link_id: i64) -> Fallible {
    let mut stmt =
        conn.prepare_cached("INSERT INTO visited_symbolic_links (symbolic_link_id) VALUES (?)")?;

    stmt.execute(params![symbolic_link_id])?;

    Ok(())
}

pub fn delete_visited_objects(conn: &Connection) -> Fallible {
    conn.execute_batch(
        r#"
DELETE FROM visited_symbolic_links;
DELETE FROM visited_directories;
DELETE FROM visited_files;
DELETE FROM new_mappings;
DELETE FROM new_files;
"#,
    )?;

    Ok(())
}

pub fn insert_new_file(conn: &Connection, path: &Path, metadata: &Metadata) -> Fallible<i64> {
    let mut stmt =
        conn.prepare_cached("INSERT INTO new_files (path, size, mode) VALUES (?, ?, ?)")?;

    stmt.execute(params![
        path_as_bytes(path),
        metadata.size() as i64,
        metadata.mode(),
    ])?;
    let new_file_id = conn.last_insert_rowid();

    Ok(new_file_id)
}

pub fn update_new_file(conn: &Connection, new_file_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached("UPDATE new_files SET closed = TRUE WHERE id = ?")?;

    stmt.execute(params![new_file_id])?;

    Ok(())
}

pub fn delete_new_file(conn: &Connection, new_file_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached("DELETE FROM new_files WHERE id = ?")?;

    stmt.execute(params![new_file_id])?;

    Ok(())
}

pub fn insert_new_mapping(conn: &Connection, file_id: i64, offset: u64, block_id: i64) -> Fallible {
    let mut stmt = conn.prepare_cached(
        "INSERT INTO new_mappings (new_file_id, offset, block_id) VALUES (?, ?, ?)",
    )?;

    stmt.execute(params![file_id, offset as i64, block_id])?;

    Ok(())
}

pub fn select_small_patchsets(
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

    let rows = stmt
        .query_map(params![max_manifest_len as i64], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

pub fn select_unused_archives(conn: &Connection) -> Fallible<Vec<(i64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT id, b2_file_id FROM archives WHERE id NOT IN (SELECT archive_id FROM blocks)",
    )?;

    let rows = stmt
        .query_map(NO_PARAMS, |row| Ok((row.get(0)?, row.get(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

pub fn select_small_archives(conn: &Connection, min_archive_len: u64) -> Fallible<Vec<i64>> {
    let mut stmt = conn.prepare(
        r#"
SELECT
    id
FROM (
    SELECT
        archives.id as id,
        archives.b2_length as b2_length,
        SUM(blocks.length) as blocks_length
    FROM archives, blocks
    WHERE archives.id = blocks.archive_id
    GROUP BY archives.id
)
WHERE blocks_length < ?
ORDER BY blocks_length ASC, b2_length DESC
"#,
    )?;

    let rows = stmt
        .query_map(params![min_archive_len as i64], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(rows)
}

pub fn select_closed_new_files(
    conn: &Connection,
    mut consumer: impl FnMut(i64, &Path) -> Fallible,
) -> Fallible {
    let mut stmt = conn.prepare(
        r#"
SELECT
    new_files.id,
    new_files.path
FROM new_files
WHERE new_files.closed
AND NOT EXISTS (
    SELECT archives.id
    FROM new_mappings, blocks, archives
    WHERE new_files.id = new_mappings.new_file_id
    AND new_mappings.block_id = blocks.id
    AND blocks.archive_id = archives.id
    AND archives.b2_file_id IS NULL
)
"#,
    )?;

    let mut rows = stmt.query(NO_PARAMS)?;
    while let Some(row) = rows.next()? {
        let new_file_id = row.get(0)?;
        let path = path_from_blob(row.get_raw(1))?;

        consumer(new_file_id, path)?;
    }

    Ok(())
}

pub fn delete_unvisited_files(conn: &Connection) -> Fallible<usize> {
    let rows = conn.execute(
        "DELETE FROM files WHERE id NOT IN (SELECT file_id FROM visited_files)",
        NO_PARAMS,
    )?;

    Ok(rows)
}

pub fn delete_unvisited_directories(conn: &Connection) -> Fallible<usize> {
    let rows = conn.execute(
        "DELETE FROM directories WHERE id NOT IN (SELECT directory_id FROM visited_directories)",
        NO_PARAMS,
    )?;

    Ok(rows)
}

pub fn delete_unvisited_symbolic_links(conn: &Connection) -> Fallible<usize> {
    let rows = conn.execute(
        "DELETE FROM symbolic_links WHERE id NOT IN (SELECT symbolic_link_id FROM visited_symbolic_links)",
        NO_PARAMS,
    )?;

    Ok(rows)
}

pub fn delete_unused_blocks(conn: &Connection) -> Fallible<usize> {
    let rows = conn.execute(
        "DELETE FROM blocks WHERE id NOT IN (SELECT block_id FROM mappings)",
        NO_PARAMS,
    )?;

    Ok(rows)
}

pub fn select_storage_used(conn: &Connection) -> Fallible<i64> {
    let storage_used = conn.query_row("SELECT SUM(b2_length) FROM (SELECT b2_length FROM patchsets UNION ALL SELECT b2_length FROM archives)", NO_PARAMS, |row| row.get(0))?;

    Ok(storage_used)
}

fn path_from_blob(value: ValueRef) -> Result<&Path, FromSqlError> {
    value
        .as_blob()
        .map(|blob| Path::new(OsStr::from_bytes(blob)))
}

fn path_as_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}
