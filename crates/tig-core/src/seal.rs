//! Sealed entries: what a public view shows in place of a private file or
//! folder.
//!
//! The internal ID of a private entry is a plain, unsalted content hash, so a
//! small file like `.env` could be guessed from it. A sealed entry therefore
//! carries a [`SealedId`], a BLAKE3 keyed hash under a secret [`SealSalt`].
//! `SealedId` is a separate type from `ObjectId`, and a tree only accepts
//! sealed entries through [`crate::TreeEntry::sealed`], so a plain ID cannot
//! end up in a sealed slot by mistake.

use std::fmt;

use crate::domain;
use crate::id::ObjectId;
use crate::object::EntryKind;

/// Secret salt for one sealed entry. Group readers derive it from the group's
/// key (see tig-private); it depends on the entry's path and content, so
/// disclosing one salt (commit-then-reveal) exposes nothing about any other
/// entry or any other version of the same path.
#[derive(Clone)]
pub struct SealSalt([u8; 32]);

impl SealSalt {
    /// Wraps salt bytes: either a fresh derivation by tig-private or a salt
    /// published on disclosure day.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        SealSalt(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for SealSalt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print secret material.
        f.write_str("SealSalt(..)")
    }
}

/// The public stand-in for a private entry. Only constructible by
/// [`SealedId::compute`] or by decoding a tree that already contains one.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SealedId([u8; 32]);

impl SealedId {
    /// Seals the entry `(kind, target)`. `kind` is hashed too, so the public
    /// view does not reveal whether a file or a folder is hidden.
    pub fn compute(salt: &SealSalt, kind: EntryKind, target: &ObjectId) -> Self {
        let mut h = blake3::Hasher::new_keyed(&salt.0);
        h.update(domain::SEALED_ENTRY.as_bytes());
        h.update(&[kind as u8]);
        h.update(target.as_bytes());
        SealedId(*h.finalize().as_bytes())
    }

    /// Checks a revealed `(salt, kind, target)` against this sealed ID, in
    /// constant time.
    pub fn verify(&self, salt: &SealSalt, kind: EntryKind, target: &ObjectId) -> bool {
        blake3::Hash::from(Self::compute(salt, kind, target).0) == blake3::Hash::from(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Only for decoding trees; see `TreeEntry::sealed_id`.
    pub(crate) fn from_stored(bytes: [u8; 32]) -> Self {
        SealedId(bytes)
    }
}

impl fmt::Display for SealedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for SealedId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SealedId({})", &self.to_hex()[..12])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_and_content_both_matter() {
        let target = ObjectId([5; 32]);
        let a = SealedId::compute(&SealSalt::from_bytes([1; 32]), EntryKind::File, &target);
        let b = SealedId::compute(&SealSalt::from_bytes([2; 32]), EntryKind::File, &target);
        let c = SealedId::compute(&SealSalt::from_bytes([1; 32]), EntryKind::Tree, &target);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a.as_bytes(), target.as_bytes());
        assert!(a.verify(&SealSalt::from_bytes([1; 32]), EntryKind::File, &target));
        assert!(!a.verify(&SealSalt::from_bytes([2; 32]), EntryKind::File, &target));
    }

    #[test]
    fn salt_debug_hides_bytes() {
        assert_eq!(format!("{:?}", SealSalt::from_bytes([9; 32])), "SealSalt(..)");
    }
}
