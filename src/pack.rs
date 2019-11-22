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
use std::io::{Cursor, Read};

use sodiumoxide::crypto::secretbox::{
    gen_nonce, open_detached, seal_detached, Key, Nonce, Tag, MACBYTES, NONCEBYTES,
};
use zstd::{encode_all, Decoder};

use super::Fallible;

pub fn pack(key: &Key, compression_level: i32, reader: impl Read) -> Fallible<Vec<u8>> {
    let mut buf = encode_all(reader, compression_level)?;

    let nonce = gen_nonce();
    let tag = seal_detached(&mut buf, &nonce, key);

    buf.reserve(NONCEBYTES + MACBYTES);
    buf.extend_from_slice(nonce.as_ref());
    buf.extend_from_slice(tag.as_ref());

    Ok(buf)
}

pub fn unpack(key: &Key, mut buf: Vec<u8>) -> Fallible<impl Read> {
    if buf.len() < MACBYTES + NONCEBYTES {
        return Err("Buffer too short".into());
    }

    {
        let buf = buf.as_mut_slice();
        let (buf, tag) = buf.split_at_mut(buf.len() - MACBYTES);
        let (buf, nonce) = buf.split_at_mut(buf.len() - NONCEBYTES);

        open_detached(
            buf,
            &Tag::from_slice(tag).unwrap(),
            &Nonce::from_slice(nonce).unwrap(),
            key,
        )
        .map_err(|()| "Failed to decrypt buffer")?;
    }

    buf.truncate(buf.len() - MACBYTES - NONCEBYTES);

    Ok(Decoder::with_buffer(Cursor::new(buf))?)
}
