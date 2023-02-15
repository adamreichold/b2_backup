# b2_backup

This program can be used to perform incremental backups of a given set of files and directories targeting [Backblaze B2](https://www.backblaze.com/b2/cloud-storage.html) for storage. It uses the [bup](https://bup.github.io) block splitting algorithm and keeps a local manifest in an [SQLite](https://www.sqlite.org) database. It uses [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) for block addressing, [Zstd](https://github.com/facebook/zstd) for compression and the extended nonce variant of [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305) for authenticated encryption.

During normal operation, it will only upload additional block archives and manifest patchsets, but it will not download any objects from the B2 bucket. Sometimes, it will automatically download objects containing stale data and merge those into new archives and patchsets to reduce the remote space usage.

## Configuration

By default, the configuration file `config.yaml` and the manifest databse `manifest.db` are assumed to be found in the current working directory.

A full example configuration including the optional items is:

```yaml
# B2 application key ID
app_key_id: 'aaaaaaaaaaaaaaaaaaaaaaaaa'
# B2 application key
app_key: 'BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB'
# B2 bucket ID
bucket_id: 'cccccccccccccccccccccccc'
# B2 bucket name
bucket_name: 'foo'
# pack file encryption key
key: 'dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd'
# paths which are recursively included
includes:
  - /home/bar
# path which are skipped if encountered (optional)
excludes:
  - /home/bar/.cache
# whether deleted files are removed from backup (optional)
keep_deleted_files: false
# number of threads used to split and hash blocks and compress archives (optional)
num_threads: 4
# compression level used for pack files (optional)
compression_level: 17
# minimum amount of block data before an new archive file is created (optional)
min_archive_len: 50_000_000
# maximum resulting size when merging patchset files (optional)
max_manifest_len: 10_000_000
# threshold above which collecting archives containing stale data starts (zero deactivates mechanism, optional)
small_archives_upper_limit: 10
# threshold below which collecting archives containing stale data stops (optional)
small_archives_lower_limit: 5
# threshold at which patchsets containing stale data are collected (zero deactivates mechanism, optional)
small_patchsets_limit: 25
```

The [B2 application key](https://www.backblaze.com/b2/docs/application_keys.html) and the [B2 bucket](https://www.backblaze.com/b2/docs/buckets.html) need to be created manually.

The [`systemd`](systemd) folder contains a timer and service which can be used to automatically and persistently run this program each day after placing the binary into `$HOME/bin/b2_bacup`, the unit files into `$HOME/.config/systemd/user` and running `systemctl --user enable --now b2_backup.timer`.
