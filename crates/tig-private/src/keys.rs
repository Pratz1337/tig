//! Keys and the cryptographic primitives behind sealing. See DESIGN.md
//! "Crypto and wire rules". Nothing here runs on the hot path: these are
//! called only at publish, fetch, and grant time.
//!
//! - A person has an [`Identity`]: a long-term X25519 key pair.
//! - An access group (the built-in `private`, or a role) has one random
//!   [`EpochKey`] per epoch. Removing a member starts a new epoch.
//! - Granting access = [`wrap`]ping the epoch key to a member's public key
//!   (ephemeral X25519 + XChaCha20-Poly1305, bound to group and epoch).
//! - The epoch key is never used directly. Every purpose derives its own
//!   subkey with `blake3::derive_key` and a label from `tig_core::domain`.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use tig_core::domain;
use tig_core::seal::{SealSalt, SealedId};
use tig_core::{EntryKind, ObjectId, ObjectKind, RepoPath};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("could not decrypt: wrong key, or the data was tampered with")]
    Decrypt,
    #[error("public key is not usable (low-order point)")]
    WeakKey,
    #[error("no randomness available: {0}")]
    Random(String),
}

fn random32() -> Result<[u8; 32], KeyError> {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).map_err(|e| KeyError::Random(e.to_string()))?;
    Ok(b)
}

// ---------------------------------------------------------------------------
// People

/// A member's public key, shared freely.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey(pub [u8; 32]);

impl PublicKey {
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicKey({})", &self.to_hex()[..16])
    }
}

/// A person's long-term secret key. Stored only on their own machine.
pub struct Identity {
    secret: StaticSecret,
}

impl Identity {
    pub fn generate() -> Result<Self, KeyError> {
        Ok(Identity { secret: StaticSecret::from(random32()?) })
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Identity { secret: StaticSecret::from(bytes) }
    }

    /// The secret bytes, for saving to the user's key file. Handle with care.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(XPublic::from(&self.secret).to_bytes())
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({:?})", self.public())
    }
}

// ---------------------------------------------------------------------------
// Groups

/// Which group and epoch a key or ciphertext belongs to. Bound into the
/// associated data of everything encrypted under that group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEpoch {
    pub group: String,
    pub epoch: u64,
}

impl GroupEpoch {
    fn aad(&self, prefix: &[u8], extra: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(prefix.len() + self.group.len() + 16 + extra.len());
        aad.extend_from_slice(prefix);
        aad.extend_from_slice(&(self.group.len() as u64).to_le_bytes());
        aad.extend_from_slice(self.group.as_bytes());
        aad.extend_from_slice(&self.epoch.to_le_bytes());
        aad.extend_from_slice(extra);
        aad
    }
}

/// The random secret of one group in one epoch.
pub struct EpochKey([u8; 32]);

impl fmt::Debug for EpochKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EpochKey(..)")
    }
}

/// The ID a private object travels under in fetch/push negotiation, so the
/// server never sees its plain (guessable) object ID.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct WireId(pub [u8; 32]);

impl EpochKey {
    pub fn generate() -> Result<Self, KeyError> {
        Ok(EpochKey(random32()?))
    }

    fn subkey(&self, label: &str) -> [u8; 32] {
        blake3::derive_key(label, &self.0)
    }

    /// The per-entry salt for a sealed entry. Bound to path, kind and
    /// content, so revealing it (embargo day) exposes only this entry.
    pub fn seal_salt(&self, path: &RepoPath, kind: EntryKind, target: &ObjectId) -> SealSalt {
        let mut h = blake3::Hasher::new_keyed(&self.subkey(domain::SEAL_SALT_KEY));
        h.update(&(path.as_str().len() as u64).to_le_bytes());
        h.update(path.as_str().as_bytes());
        h.update(&[kind as u8]);
        h.update(target.as_bytes());
        SealSalt::from_bytes(*h.finalize().as_bytes())
    }

    /// The sealed ID that stands in for `(kind, target)` at `path`.
    pub fn seal(&self, path: &RepoPath, kind: EntryKind, target: &ObjectId) -> SealedId {
        SealedId::compute(&self.seal_salt(path, kind, target), kind, target)
    }

    pub fn wire_id(&self, id: &ObjectId) -> WireId {
        WireId(*blake3::keyed_hash(&self.subkey(domain::WIRE_ID_KEY), id.as_bytes()).as_bytes())
    }

    /// Encrypts one object for a sealed pack. The nonce is synthetic
    /// (derived from the object ID under a separate subkey), so the same
    /// object encrypts identically within a group and epoch (dedup) and
    /// differently everywhere else.
    ///
    /// Caller invariant: `id` must equal `hash_object(kind, body)`, and this
    /// epoch key must belong to exactly one group and epoch. Neither is
    /// checked here. Reusing an ID for different bodies reuses a keystream;
    /// reusing this key across contexts also reuses the Poly1305 key even
    /// though the associated data differs. This is not misuse-resistant SIV.
    pub fn encrypt_object(&self, group: &GroupEpoch, kind: ObjectKind, id: &ObjectId, body: &[u8]) -> Vec<u8> {
        let cipher = XChaCha20Poly1305::new(&self.subkey(domain::CONTENT_KEY).into());
        let nonce = self.object_nonce(kind, id);
        let aad = group.aad(domain::OBJECT_AAD, &object_aad(kind, id));
        cipher
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: body, aad: &aad })
            // XChaCha20-Poly1305 encryption only fails for messages > 256 GiB.
            .expect("object too large to encrypt")
    }

    pub fn decrypt_object(
        &self,
        group: &GroupEpoch,
        kind: ObjectKind,
        id: &ObjectId,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, KeyError> {
        let cipher = XChaCha20Poly1305::new(&self.subkey(domain::CONTENT_KEY).into());
        let nonce = self.object_nonce(kind, id);
        let aad = group.aad(domain::OBJECT_AAD, &object_aad(kind, id));
        cipher
            .decrypt(XNonce::from_slice(&nonce), Payload { msg: ciphertext, aad: &aad })
            .map_err(|_| KeyError::Decrypt)
    }

    fn object_nonce(&self, kind: ObjectKind, id: &ObjectId) -> [u8; 24] {
        let full = blake3::keyed_hash(&self.subkey(domain::NONCE_KEY), &object_aad(kind, id));
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&full.as_bytes()[..24]);
        nonce
    }
}

fn object_aad(kind: ObjectKind, id: &ObjectId) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = kind as u8;
    out[1..].copy_from_slice(id.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Granting access

/// An epoch key encrypted to one member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    pub ephemeral: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

fn wrap_cipher(shared: &[u8; 32], ephemeral: &[u8; 32], recipient: &PublicKey) -> XChaCha20Poly1305 {
    let mut material = Vec::with_capacity(96);
    material.extend_from_slice(shared);
    material.extend_from_slice(ephemeral);
    material.extend_from_slice(&recipient.0);
    XChaCha20Poly1305::new(&blake3::derive_key(domain::WRAP_KEY, &material).into())
}

/// Encrypts `key` so only `recipient` can open it, for `group`. A fresh
/// ephemeral key and random nonce are used every time.
/// This authenticates the ciphertext's context, not its sender: anyone with
/// the recipient's public key can wrap a key of their own choosing.
pub fn wrap(key: &EpochKey, group: &GroupEpoch, recipient: &PublicKey) -> Result<WrappedKey, KeyError> {
    let ephemeral_secret = StaticSecret::from(random32()?);
    let ephemeral = XPublic::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&XPublic::from(recipient.0));
    if !shared.was_contributory() {
        return Err(KeyError::WeakKey);
    }
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|e| KeyError::Random(e.to_string()))?;
    let aad = group.aad(domain::WRAP_AAD, &recipient.0);
    let ciphertext = wrap_cipher(shared.as_bytes(), &ephemeral, recipient)
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &key.0, aad: &aad })
        .map_err(|_| KeyError::Decrypt)?;
    Ok(WrappedKey { ephemeral, nonce, ciphertext })
}

/// Opens a wrapped epoch key with the member's identity.
pub fn unwrap(wrapped: &WrappedKey, group: &GroupEpoch, identity: &Identity) -> Result<EpochKey, KeyError> {
    let recipient = identity.public();
    let shared = identity.secret.diffie_hellman(&XPublic::from(wrapped.ephemeral));
    if !shared.was_contributory() {
        return Err(KeyError::WeakKey);
    }
    let aad = group.aad(domain::WRAP_AAD, &recipient.0);
    let plain = wrap_cipher(shared.as_bytes(), &wrapped.ephemeral, &recipient)
        .decrypt(XNonce::from_slice(&wrapped.nonce), Payload { msg: &wrapped.ciphertext, aad: &aad })
        .map_err(|_| KeyError::Decrypt)?;
    let bytes: [u8; 32] = plain.try_into().map_err(|_| KeyError::Decrypt)?;
    Ok(EpochKey(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group() -> GroupEpoch {
        GroupEpoch { group: "private".into(), epoch: 1 }
    }

    fn path(s: &str) -> RepoPath {
        RepoPath::new(s).unwrap()
    }

    #[test]
    fn wrap_roundtrip_and_binding() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let key = EpochKey::generate().unwrap();
        let w = wrap(&key, &group(), &alice.public()).unwrap();
        let opened = unwrap(&w, &group(), &alice).unwrap();
        assert_eq!(opened.0, key.0);
        // Wrong person, wrong group, wrong epoch, tampering: all refused.
        assert!(unwrap(&w, &group(), &bob).is_err());
        assert!(unwrap(&w, &GroupEpoch { group: "billing".into(), epoch: 1 }, &alice).is_err());
        assert!(unwrap(&w, &GroupEpoch { group: "private".into(), epoch: 2 }, &alice).is_err());
        let mut bad = w.clone();
        bad.ciphertext[0] ^= 1;
        assert!(unwrap(&bad, &group(), &alice).is_err());
        // Fresh randomness every wrap.
        assert_ne!(wrap(&key, &group(), &alice.public()).unwrap(), w);
    }

    #[test]
    fn low_order_public_key_is_refused() {
        let key = EpochKey::generate().unwrap();
        assert!(matches!(wrap(&key, &group(), &PublicKey([0; 32])), Err(KeyError::WeakKey)));
    }

    #[test]
    fn object_encryption_is_deterministic_and_bound() {
        let key = EpochKey::generate().unwrap();
        let id = ObjectId([4; 32]);
        let a = key.encrypt_object(&group(), ObjectKind::Blob, &id, b"SECRET=1");
        assert_eq!(a, key.encrypt_object(&group(), ObjectKind::Blob, &id, b"SECRET=1"));
        assert_eq!(key.decrypt_object(&group(), ObjectKind::Blob, &id, &a).unwrap(), b"SECRET=1");
        let other_group = GroupEpoch { group: "billing".into(), epoch: 1 };
        assert!(key.decrypt_object(&other_group, ObjectKind::Blob, &id, &a).is_err());
        assert!(key.decrypt_object(&group(), ObjectKind::Tree, &id, &a).is_err());
        assert!(key.decrypt_object(&group(), ObjectKind::Blob, &ObjectId([5; 32]), &a).is_err());
        // A different epoch key never produces the same ciphertext.
        let key2 = EpochKey::generate().unwrap();
        assert_ne!(a, key2.encrypt_object(&group(), ObjectKind::Blob, &id, b"SECRET=1"));
    }

    #[test]
    fn seal_is_stable_bound_and_verifiable() {
        let key = EpochKey::generate().unwrap();
        let id = ObjectId([7; 32]);
        let s = key.seal(&path(".env"), EntryKind::File, &id);
        assert_eq!(s, key.seal(&path(".env"), EntryKind::File, &id), "stable for unchanged content");
        assert_ne!(s, key.seal(&path("other/.env"), EntryKind::File, &id), "same content elsewhere differs");
        assert_ne!(s, key.seal(&path(".env"), EntryKind::File, &ObjectId([8; 32])));
        assert_ne!(s.as_bytes(), id.as_bytes());
        // Disclosing one salt lets anyone verify that one entry.
        let salt = key.seal_salt(&path(".env"), EntryKind::File, &id);
        assert!(s.verify(&salt, EntryKind::File, &id));
        // Subkeys are independent: the wire id is not the sealed id or the plain id.
        assert_ne!(key.wire_id(&id).0, *s.as_bytes());
        assert_ne!(key.wire_id(&id).0, id.0);
    }
}
