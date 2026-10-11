use std::fmt;
use std::str::FromStr;

use crate::error::{Error, Result};

/// BLAKE3 content address of an object. See `object::Object::id`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ObjectId(pub [u8; 32]);

impl ObjectId {
    pub const LEN: usize = 32;

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// First `n` hex characters, for display.
    pub fn short(&self, n: usize) -> String {
        let mut s = self.to_hex();
        s.truncate(n.min(64));
        s
    }
}

impl fmt::Display for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for ObjectId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectId({})", self.short(12))
    }
}

impl FromStr for ObjectId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let mut out = [0u8; 32];
        hex::decode_to_slice(s, &mut out).map_err(|e| Error::decode("object id", e.to_string()))?;
        Ok(ObjectId(out))
    }
}

/// Stable identity of a change across rewrites. Random, never derived from content.
///
/// Displayed with the letters k..z instead of hex digits (jj's trick), so a change ID
/// can never be confused with an object ID.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChangeId(pub [u8; 16]);

const CHANGE_ALPHABET: &[u8; 16] = b"zyxwvutsrqponmlk";

impl ChangeId {
    pub fn random() -> Result<Self> {
        let mut b = [0u8; 16];
        getrandom::getrandom(&mut b).map_err(|e| Error::Invalid(format!("no randomness: {e}")))?;
        Ok(ChangeId(b))
    }

    pub fn to_text(&self) -> String {
        let mut s = String::with_capacity(32);
        for byte in self.0 {
            s.push(CHANGE_ALPHABET[(byte >> 4) as usize] as char);
            s.push(CHANGE_ALPHABET[(byte & 0xf) as usize] as char);
        }
        s
    }

    pub fn short(&self, n: usize) -> String {
        let mut s = self.to_text();
        s.truncate(n.min(32));
        s
    }

    /// Parses a full 32-character change ID. Prefix lookup is done by the repo.
    pub fn parse(s: &str) -> Result<Self> {
        let bytes = s.as_bytes();
        if bytes.len() != 32 {
            return Err(Error::decode("change id", "expected 32 characters"));
        }
        let mut out = [0u8; 16];
        for (i, pair) in bytes.chunks(2).enumerate() {
            let hi = nibble(pair[0])?;
            let lo = nibble(pair[1])?;
            out[i] = (hi << 4) | lo;
        }
        Ok(ChangeId(out))
    }
}

fn nibble(c: u8) -> Result<u8> {
    CHANGE_ALPHABET
        .iter()
        .position(|&a| a == c)
        .map(|p| p as u8)
        .ok_or_else(|| Error::decode("change id", format!("bad character {:?}", c as char)))
}

impl fmt::Display for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

impl fmt::Debug for ChangeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChangeId({})", self.short(12))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_id_roundtrip() {
        let c = ChangeId::random().unwrap();
        assert_eq!(ChangeId::parse(&c.to_text()).unwrap(), c);
        assert!(c.to_text().bytes().all(|b| (b'k'..=b'z').contains(&b)));
    }

    #[test]
    fn object_id_roundtrip() {
        let id = ObjectId([7; 32]);
        assert_eq!(id.to_hex().parse::<ObjectId>().unwrap(), id);
    }
}
