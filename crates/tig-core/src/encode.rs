//! Tiny explicit binary encoding: LEB128 varints and length-prefixed bytes.
//! Every object encoding is built from these, so it is easy to audit.

use crate::error::{Error, Result};
use crate::id::{ChangeId, ObjectId};

#[derive(Default)]
pub struct Writer {
    pub buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn varint(&mut self, mut v: u64) {
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(byte);
                return;
            }
            self.buf.push(byte | 0x80);
        }
    }

    /// Zigzag-encoded signed varint (timestamps, timezone offsets).
    pub fn ivarint(&mut self, v: i64) {
        self.varint(((v << 1) ^ (v >> 63)) as u64);
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.varint(b.len() as u64);
        self.buf.extend_from_slice(b);
    }

    pub fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }

    pub fn id(&mut self, id: &ObjectId) {
        self.buf.extend_from_slice(&id.0);
    }

    pub fn change_id(&mut self, id: &ChangeId) {
        self.buf.extend_from_slice(&id.0);
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    what: &'static str,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8], what: &'static str) -> Self {
        Reader { buf, pos: 0, what }
    }

    fn err(&self, reason: &str) -> Error {
        Error::decode(self.what, format!("{reason} at byte {}", self.pos))
    }

    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    pub fn u8(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or_else(|| self.err("unexpected end"))?;
        self.pos += 1;
        Ok(b)
    }

    pub fn varint(&mut self) -> Result<u64> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let b = self.u8()?;
            let part = (b & 0x7f) as u64;
            if shift == 63 && part > 1 {
                return Err(self.err("varint overflow"));
            }
            v |= part << shift;
            if b & 0x80 == 0 {
                // Reject non-minimal encodings so every value has exactly one encoding.
                if b == 0 && shift != 0 {
                    return Err(self.err("non-minimal varint"));
                }
                return Ok(v);
            }
        }
        Err(self.err("varint too long"))
    }

    pub fn ivarint(&mut self) -> Result<i64> {
        let u = self.varint()?;
        Ok(((u >> 1) as i64) ^ -((u & 1) as i64))
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).filter(|&e| e <= self.buf.len()).ok_or_else(|| self.err("unexpected end"))?;
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| self.err("length too large"))?;
        self.take(n)
    }

    pub fn str(&mut self) -> Result<&'a str> {
        let b = self.bytes()?;
        std::str::from_utf8(b).map_err(|_| self.err("invalid utf-8"))
    }

    pub fn id(&mut self) -> Result<ObjectId> {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.take(32)?);
        Ok(ObjectId(out))
    }

    pub fn change_id(&mut self) -> Result<ChangeId> {
        let mut out = [0u8; 16];
        out.copy_from_slice(self.take(16)?);
        Ok(ChangeId(out))
    }

    /// Count prefix for a list. Bounded by remaining bytes so corrupt input
    /// cannot make us allocate a huge Vec.
    pub fn count(&mut self, min_item_size: usize) -> Result<usize> {
        let n = self.varint()?;
        let remaining = (self.buf.len() - self.pos) as u64;
        if n.saturating_mul(min_item_size.max(1) as u64) > remaining {
            return Err(self.err("list longer than input"));
        }
        Ok(n as usize)
    }

    pub fn finish(self) -> Result<()> {
        if self.pos != self.buf.len() {
            return Err(self.err("trailing bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn varint_roundtrip(v: u64, i: i64) {
            let mut w = Writer::new();
            w.varint(v);
            w.ivarint(i);
            let buf = w.finish();
            let mut r = Reader::new(&buf, "test");
            prop_assert_eq!(r.varint().unwrap(), v);
            prop_assert_eq!(r.ivarint().unwrap(), i);
            r.finish().unwrap();
        }
    }

    #[test]
    fn rejects_non_minimal() {
        let mut r = Reader::new(&[0x80, 0x00], "test");
        assert!(r.varint().is_err());
    }
}
