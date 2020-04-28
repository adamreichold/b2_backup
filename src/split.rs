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
use std::io::Read;
use std::mem::replace;

use super::Fallible;

pub fn split(mut reader: impl Read, mut consumer: impl FnMut(&[u8]) -> Fallible) -> Fallible {
    let mut buf = Vec::new();
    let mut start = 0;
    let mut sum = RollingSum::new();

    loop {
        let mut end = buf.len() - start;
        buf.copy_within(start.., 0);
        start = 0;

        buf.resize(end + 1536 * 1024, 0);
        let read = reader.read(&mut buf[end..])?;
        buf.truncate(end + read);

        if read == 0 {
            break;
        }

        while let Some(pos) = sum.split(&buf[end..]) {
            end += pos;

            consumer(&buf[start..end])?;

            start = end;
            sum = RollingSum::new();
        }
    }

    if buf.len() > start {
        consumer(&buf[start..])?;
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
const CHUNK_SIZE: u32 = 1 << CHUNK_BITS;
const CHUNK_MASK: u32 = CHUNK_SIZE - 1;

const CHAR_OFFSET: usize = 31;
