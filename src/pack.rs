use std::io::{Cursor, Read};

use sodiumoxide::crypto::secretbox::{
    gen_nonce, open_detached, seal_detached, Key, Nonce, Tag, MACBYTES, NONCEBYTES,
};
use zstd::{encode_all, Decoder};

use super::Fallible;

pub fn pack(key: &Key, reader: impl Read) -> Fallible<Vec<u8>> {
    let mut buf = encode_all(reader, 17)?;

    let nonce = gen_nonce();
    let tag = seal_detached(&mut buf, &nonce, key);

    buf.reserve(NONCEBYTES + MACBYTES);
    buf.extend_from_slice(&nonce.0);
    buf.extend_from_slice(&tag.0);

    Ok(buf)
}

pub fn unpack(key: &Key, mut buf: Vec<u8>) -> Fallible<impl Read> {
    if buf.len() < MACBYTES + NONCEBYTES {
        return Err("Buffer to short".into());
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
