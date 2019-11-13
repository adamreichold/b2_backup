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
use std::cell::RefCell;
use std::io::{copy, Cursor, Read};
use std::mem::swap;
use std::ops::DerefMut;

use openssl::{
    rand::rand_bytes,
    symm::{Cipher, Crypter, Mode},
};
use zstd::{Decoder, Encoder};

use super::Fallible;

pub fn pack(
    key: &[u8; KEY_LEN],
    compression_level: i32,
    mut reader: impl Read,
) -> Fallible<Vec<u8>> {
    BUFFER.with(|buf| {
        let mut buf = buf.borrow_mut();
        buf.clear();

        let mut encoder = Encoder::new(buf.deref_mut(), compression_level)?;
        copy(&mut reader, &mut encoder)?;
        encoder.finish()?;

        let mut iv = [0; IV_LEN];
        rand_bytes(&mut iv)?;
        let mut crypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Encrypt, &key[..], Some(&iv))?;

        let mut out = vec![0; buf.len()];
        let mut cnt = crypter.update(&buf, &mut out)?;
        cnt += crypter.finalize(&mut out[cnt..])?;
        out.truncate(cnt);

        let mut tag = [0; TAG_LEN];
        crypter.get_tag(&mut tag)?;

        out.reserve(IV_LEN + TAG_LEN);
        out.extend_from_slice(&iv);
        out.extend_from_slice(&tag);

        Ok(out)
    })
}

pub fn unpack(key: &[u8; KEY_LEN], mut buf: Vec<u8>) -> Fallible<impl Read> {
    if buf.len() < IV_LEN + TAG_LEN {
        return Err("Buffer too short".into());
    }

    let data_len = buf.len() - IV_LEN - TAG_LEN;
    let iv = &buf[data_len..][..IV_LEN];
    let tag = &buf[data_len..][IV_LEN..][..TAG_LEN];

    let mut decrypter = Crypter::new(Cipher::aes_256_gcm(), Mode::Decrypt, &key[..], Some(iv))?;
    decrypter.set_tag(tag)?;

    BUFFER.with(|out| -> Fallible {
        let mut out = out.borrow_mut();
        out.resize(data_len, 0);

        let mut cnt = decrypter.update(&buf[..data_len], &mut out)?;
        cnt += decrypter.finalize(&mut out[cnt..])?;
        out.truncate(cnt);

        swap(out.deref_mut(), &mut buf);

        Ok(())
    })?;

    Ok(Decoder::with_buffer(Cursor::new(buf))?)
}

thread_local! {
    static BUFFER: RefCell<Vec<u8>> = RefCell::new(Vec::new());
}

pub const KEY_LEN: usize = 32;
const IV_LEN: usize = 12;
const TAG_LEN: usize = 16;
