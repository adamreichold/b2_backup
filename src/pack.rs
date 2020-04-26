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

use chacha20poly1305::{
    aead::{
        generic_array::{typenum::Unsigned, GenericArray},
        Aead, NewAead,
    },
    XChaCha20Poly1305,
};
use ring::rand::{SecureRandom, SystemRandom};
use zstd::{encode_all, Decoder};

use super::Fallible;

pub type Key = GenericArray<u8, <XChaCha20Poly1305 as NewAead>::KeySize>;

type Nonce = GenericArray<u8, <XChaCha20Poly1305 as Aead>::NonceSize>;
type Tag = GenericArray<u8, <XChaCha20Poly1305 as Aead>::TagSize>;

const NONCE_LEN: usize = <XChaCha20Poly1305 as Aead>::NonceSize::USIZE;
const TAG_LEN: usize = <XChaCha20Poly1305 as Aead>::TagSize::USIZE;

pub fn pack(key: Key, compression_level: i32, reader: impl Read) -> Fallible<Vec<u8>> {
    let mut buf = encode_all(reader, compression_level)?;

    let mut nonce = Nonce::default();
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| "Failed to generate random nonce")?;

    let tag = XChaCha20Poly1305::new(key)
        .encrypt_in_place_detached(&nonce, &[], &mut buf)
        .map_err(|_| "Failed to encrypt buffer")?;

    buf.reserve(NONCE_LEN + TAG_LEN);
    buf.extend_from_slice(&nonce);
    buf.extend_from_slice(&tag);

    Ok(buf)
}

pub fn unpack(key: Key, mut buf: Vec<u8>) -> Fallible<impl Read> {
    if buf.len() < TAG_LEN + NONCE_LEN {
        return Err("Buffer too short".into());
    }

    let tag = Tag::clone_from_slice(&buf[buf.len() - TAG_LEN..]);
    buf.truncate(buf.len() - TAG_LEN);

    let nonce = Nonce::clone_from_slice(&buf[buf.len() - NONCE_LEN..]);
    buf.truncate(buf.len() - NONCE_LEN);

    XChaCha20Poly1305::new(key)
        .decrypt_in_place_detached(&nonce, &[], &mut buf, &tag)
        .map_err(|_| "Failed to decrypt buffer")?;

    let reader = Decoder::with_buffer(Cursor::new(buf))?;

    Ok(reader)
}
