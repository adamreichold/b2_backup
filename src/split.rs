use std::io::Read;
use std::mem::replace;

use super::Fallible;

pub fn split<R, C>(mut reader: R, mut consumer: C) -> Fallible
where
    R: Read,
    C: FnMut(&[u8]) -> Fallible,
{
    let mut buf = Vec::new();
    let mut sum = RollingSum::new();

    loop {
        let mut len = buf.len();
        buf.resize(len + CHUNK_SIZE as usize, 0);
        let read = reader.read(&mut buf[len..])?;
        buf.truncate(len + read);

        if read == 0 {
            break;
        }

        while let Some(pos) = sum.split(&buf[len..]) {
            len += pos;

            consumer(&buf[..len])?;

            buf.copy_within(len.., 0);
            buf.truncate(buf.len() - len);

            sum = RollingSum::new();
            len = 0;
        }
    }

    if !buf.is_empty() {
        consumer(&buf)?;
    }

    Ok(())
}

struct RollingSum {
    s1: usize,
    s2: usize,
    win: [u8; WINDOW_SIZE],
    pos: usize,
}

impl RollingSum {
    pub fn new() -> Self {
        Self {
            s1: WINDOW_SIZE * CHAR_OFFSET,
            s2: WINDOW_SIZE * (WINDOW_SIZE - 1) * CHAR_OFFSET,
            win: [0; WINDOW_SIZE],
            pos: 0,
        }
    }

    pub fn split(&mut self, buf: &[u8]) -> Option<usize> {
        for (idx, &new_val) in buf.iter().enumerate() {
            let old_val = replace(&mut self.win[self.pos], new_val);
            self.pos = (self.pos + 1) & WINDOW_MASK;

            self.s1 += new_val as usize;
            self.s1 -= old_val as usize;
            self.s2 += self.s1;
            self.s2 -= WINDOW_SIZE * (old_val as usize + CHAR_OFFSET);

            let digest = (((self.s1 & 0xFFFF) as u32) << 16) | ((self.s2 & 0xFFFF) as u32);

            if digest & CHUNK_MASK == CHUNK_MASK {
                return Some(idx + 1);
            }
        }

        None
    }
}

const WINDOW_BITS: usize = 6;
const WINDOW_SIZE: usize = 1 << WINDOW_BITS;
const WINDOW_MASK: usize = WINDOW_SIZE - 1;

const CHUNK_BITS: u32 = 15;
pub const CHUNK_SIZE: u32 = 1 << CHUNK_BITS;
const CHUNK_MASK: u32 = CHUNK_SIZE - 1;

const CHAR_OFFSET: usize = 31;
