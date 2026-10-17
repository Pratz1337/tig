//! Keys and the cryptographic primitives behind sealing. See DESIGN.md
//! "Crypto and wire rules". Nothing here runs on the hot path: these are
//! called only at publish, fetch, and grant time.
//!
//! - A person has an [`Identity`]: independent X25519 encryption and Ed25519
//!   signing key pairs, saved locally as two 32-byte secrets.
//! - An access group (the built-in `private`, or a role) has one random
//!   [`EpochKey`] per epoch. Removing a member starts a new epoch.
//! - Only the owner grants access in phase 1: [`grant`] wraps and signs an
//!   epoch key. Members use [`open_grant`] with the pinned owner signing key.
//!   Owners use their local epoch keys, never keys supplied by the remote.
//! - The epoch key is never used directly. Every purpose derives its own
//!   subkey from the secret AND its remote, group and epoch, with a frozen
//!   label from `tig_core::domain`. Secret buffers are zeroized on drop.

use std::fmt;

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use tig_core::domain;
use tig_core::object::hash_object;
use tig_core::seal::{SealSalt, SealedId};
use tig_core::{EntryKind, ObjectId, ObjectKind, RepoPath};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error("could not decrypt: wrong key, or the data was tampered with")]
    Decrypt,
    #[error("public key is not usable (low-order point)")]
    WeakKey,
    #[error("object body does not match its kind and ID")]
    ObjectMismatch,
    #[error("invalid grant: owner, signature, recipient, or commitment did not match")]
    InvalidGrant,
    #[error("object too large to encrypt")]
    Encrypt,
    #[error("no randomness available: {0}")]
    Random(String),
    #[error("invalid protected identity")]
    Identity,
}

fn random32() -> Result<Zeroizing<[u8; 32]>, KeyError> {
    let mut b = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut *b).map_err(|e| KeyError::Random(e.to_string()))?;
    Ok(b)
}

// ---------------------------------------------------------------------------
// People

/// A member's encryption and signing keys, shared freely.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicIdentity {
    pub encryption: [u8; 32],
    pub signing: [u8; 32],
}

impl PublicIdentity {
    /// Short fingerprint to display when pinning the owner's identity.
    pub fn fingerprint(&self) -> String {
        let mut bytes = [0; 64];
        bytes[..32].copy_from_slice(&self.encryption);
        bytes[32..].copy_from_slice(&self.signing);
        hex::encode(blake3::derive_key(domain::IDENTITY_FINGERPRINT, &bytes))[..32].to_owned()
    }
}

impl fmt::Debug for PublicIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PublicIdentity({})", self.fingerprint())
    }
}

/// A person's long-term encryption and signing secrets, stored only locally.
pub struct Identity {
    secret: StaticSecret,
    signing: SigningKey,
}

impl Identity {
    /// Password-protected storage: fixed Argon2id parameters, random salt,
    /// and XChaCha20-Poly1305. The version fixes the KDF cost and encoding.
    pub fn encrypt(&self, passphrase: &[u8]) -> Result<Vec<u8>, KeyError> {
        if passphrase.is_empty() { return Err(KeyError::Identity); }
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut salt).map_err(|e| KeyError::Random(e.to_string()))?;
        getrandom::getrandom(&mut nonce).map_err(|e| KeyError::Random(e.to_string()))?;
        let mut key = Zeroizing::new([0u8; 32]);
        argon2::Argon2::default().hash_password_into(passphrase, &salt, &mut *key)
            .map_err(|_| KeyError::Identity)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| KeyError::Identity)?;
        let ciphertext = cipher.encrypt(XNonce::from_slice(&nonce),
            Payload { msg: &*self.to_bytes(), aad: domain::IDENTITY_FILE_AAD })
            .map_err(|_| KeyError::Identity)?;
        let mut out = b"TIGI\x01".to_vec();
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Opens only the fixed version-1 envelope; wrong passwords and damage
    /// are errors and never generate replacement identity material.
    pub fn decrypt(bytes: &[u8], passphrase: &[u8]) -> Result<Self, KeyError> {
        if bytes.len() != 125 || !bytes.starts_with(b"TIGI\x01") || passphrase.is_empty() {
            return Err(KeyError::Identity);
        }
        let mut key = Zeroizing::new([0u8; 32]);
        argon2::Argon2::default().hash_password_into(passphrase, &bytes[5..21], &mut *key)
            .map_err(|_| KeyError::Identity)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| KeyError::Identity)?;
        let plaintext = Zeroizing::new(cipher.decrypt(XNonce::from_slice(&bytes[21..45]),
            Payload { msg: &bytes[45..], aad: domain::IDENTITY_FILE_AAD })
            .map_err(|_| KeyError::Identity)?);
        Ok(Self::from_bytes(plaintext.as_slice().try_into().map_err(|_| KeyError::Identity)?))
    }

    pub fn generate() -> Result<Self, KeyError> {
        Ok(Identity {
            secret: StaticSecret::from(*random32()?),
            signing: SigningKey::from_bytes(&*random32()?),
        })
    }

    /// Stored format: X25519 secret followed by an independent Ed25519 seed.
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        let bytes = Zeroizing::new(bytes);
        Identity {
            secret: StaticSecret::from(*<&[u8; 32]>::try_from(&bytes[..32]).unwrap()),
            signing: SigningKey::from_bytes(bytes[32..].try_into().unwrap()),
        }
    }

    /// The secret bytes, for saving to the user's key file. Handle with care.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 64]> {
        let mut bytes = Zeroizing::new([0; 64]);
        bytes[..32].copy_from_slice(self.secret.as_bytes());
        bytes[32..].copy_from_slice(self.signing.as_bytes());
        bytes
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            encryption: XPublic::from(&self.secret).to_bytes(),
            signing: self.signing.verifying_key().to_bytes(),
        }
    }

    /// Signs `message` with this identity's Ed25519 key.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }
}

impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Identity({:?})", self.public())
    }
}

// ---------------------------------------------------------------------------
// Groups

/// Which remote, group and epoch a key or ciphertext belongs to.
///
/// `remote` is the remote's random 16-byte id. It is mixed, length-prefixed,
/// into every subkey, every AEAD associated-data string, the grant signature
/// and the epoch-key commitment. The same secret bytes in two remotes are
/// two unrelated keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupEpoch {
    pub remote: [u8; 16],
    pub group: String,
    pub epoch: u64,
}

impl GroupEpoch {
    /// `remote_len_u64_le || remote || group_len_u64_le || group || epoch_u64_le`.
    ///
    /// Fixed-width lengths sit in front of every variable field, so two
    /// different contexts cannot encode to the same bytes.
    fn encoding(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.remote.len() + 8 + self.group.len() + 8);
        out.extend_from_slice(&(self.remote.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.remote);
        out.extend_from_slice(&(self.group.len() as u64).to_le_bytes());
        out.extend_from_slice(self.group.as_bytes());
        out.extend_from_slice(&self.epoch.to_le_bytes());
        out
    }

    fn aad(&self, prefix: &[u8], extra: &[u8]) -> Vec<u8> {
        let ctx = self.encoding();
        let mut aad = Vec::with_capacity(prefix.len() + ctx.len() + extra.len());
        aad.extend_from_slice(prefix);
        aad.extend_from_slice(&ctx);
        aad.extend_from_slice(extra);
        aad
    }
}

/// The random secret of one group in one epoch.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EpochKey {
    bytes: [u8; 32],
    #[zeroize(skip)]
    context: GroupEpoch,
}

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
    pub fn generate(context: GroupEpoch) -> Result<Self, KeyError> {
        Ok(Self::from_bytes(context, *random32()?))
    }

    /// Restores an owner's locally stored epoch key with its context.
    pub fn from_bytes(context: GroupEpoch, bytes: [u8; 32]) -> Self {
        let bytes = Zeroizing::new(bytes);
        EpochKey {
            bytes: *bytes,
            context,
        }
    }

    /// Secret bytes for the local keystore; save the context alongside them.
    pub fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.bytes)
    }

    pub fn context(&self) -> &GroupEpoch {
        &self.context
    }

    pub(crate) fn matches_commitment(&self, commitment: &[u8; 32]) -> bool {
        blake3::Hash::from(*self.subkey(domain::EPOCH_KEY_COMMITMENT))
            == blake3::Hash::from(*commitment)
    }

    fn subkey(&self, label: &str) -> Zeroizing<[u8; 32]> {
        let ctx = self.context.encoding();
        let mut material = Zeroizing::new(Vec::with_capacity(self.bytes.len() + ctx.len()));
        material.extend_from_slice(&self.bytes);
        material.extend_from_slice(&ctx);
        Zeroizing::new(blake3::derive_key(label, &material))
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
    /// Refuses a mismatched kind/body/ID before using the synthetic nonce.
    /// This is not misuse-resistant SIV; it relies on collision-resistant IDs.
    pub fn encrypt_object(
        &self,
        kind: ObjectKind,
        id: &ObjectId,
        body: &[u8],
    ) -> Result<Vec<u8>, KeyError> {
        if hash_object(kind, body) != *id {
            return Err(KeyError::ObjectMismatch);
        }
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.subkey(domain::CONTENT_KEY)[..]).unwrap();
        let nonce = self.object_nonce(kind, id);
        let aad = self.context.aad(domain::OBJECT_AAD, &object_aad(kind, id));
        cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: body,
                    aad: &aad,
                },
            )
            .map_err(|_| KeyError::Encrypt)
    }

    /// Authenticates and checks the object hash. The plaintext zeroizes on drop.
    pub fn decrypt_object(
        &self,
        kind: ObjectKind,
        id: &ObjectId,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.subkey(domain::CONTENT_KEY)[..]).unwrap();
        let nonce = self.object_nonce(kind, id);
        let aad = self.context.aad(domain::OBJECT_AAD, &object_aad(kind, id));
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: ciphertext,
                        aad: &aad,
                    },
                )
                .map_err(|_| KeyError::Decrypt)?,
        );
        if hash_object(kind, &plain) != *id {
            return Err(KeyError::ObjectMismatch);
        }
        Ok(plain)
    }

    fn object_nonce(&self, kind: ObjectKind, id: &ObjectId) -> [u8; 24] {
        let full = blake3::keyed_hash(&self.subkey(domain::NONCE_KEY), &object_aad(kind, id));
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&full.as_bytes()[..24]);
        nonce
    }

    /// Encrypts a pack index under the content subkey.
    ///
    /// Generates a fresh 24-byte nonce. Associated data is
    /// `PACK_INDEX_AAD || context || header || nonce`. `context` is the
    /// length-unambiguous remote, group and epoch. `header || nonce` is the
    /// pack header stored in front of the index ciphertext; `header` is that
    /// prefix without the nonce, because the nonce is chosen here.
    pub fn encrypt_index(
        &self,
        index: &[u8],
        header: &[u8],
    ) -> Result<([u8; 24], Vec<u8>), KeyError> {
        let mut nonce = [0u8; 24];
        getrandom::getrandom(&mut nonce).map_err(|e| KeyError::Random(e.to_string()))?;
        let ciphertext = self.seal_index(&nonce, index, header)?;
        Ok((nonce, ciphertext))
    }

    /// Decrypts a pack index. `header` is the prefix passed to
    /// [`EpochKey::encrypt_index`]. The plaintext is zeroized on drop.
    pub fn decrypt_index(
        &self,
        nonce: &[u8; 24],
        ciphertext: &[u8],
        header: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        Ok(Zeroizing::new(self.open_index(nonce, ciphertext, header)?))
    }

    fn seal_index(
        &self,
        nonce: &[u8; 24],
        index: &[u8],
        header: &[u8],
    ) -> Result<Vec<u8>, KeyError> {
        // The derived subkey is 32 bytes, the only length this cipher accepts.
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.subkey(domain::CONTENT_KEY)[..]).unwrap();
        let aad = self.index_aad(header, nonce);
        cipher
            .encrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: index,
                    aad: &aad,
                },
            )
            .map_err(|_| KeyError::Encrypt)
    }

    fn open_index(
        &self,
        nonce: &[u8; 24],
        ciphertext: &[u8],
        header: &[u8],
    ) -> Result<Vec<u8>, KeyError> {
        let cipher =
            XChaCha20Poly1305::new_from_slice(&self.subkey(domain::CONTENT_KEY)[..]).unwrap();
        let aad = self.index_aad(header, nonce);
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| KeyError::Decrypt)
    }

    fn index_aad(&self, header: &[u8], nonce: &[u8; 24]) -> Vec<u8> {
        let ctx = self.context.encoding();
        let mut aad = Vec::with_capacity(
            domain::PACK_INDEX_AAD.len() + ctx.len() + header.len() + nonce.len(),
        );
        aad.extend_from_slice(domain::PACK_INDEX_AAD);
        aad.extend_from_slice(&ctx);
        aad.extend_from_slice(header);
        aad.extend_from_slice(nonce);
        aad
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

fn wrap_cipher(
    shared: &[u8; 32],
    ephemeral: &[u8; 32],
    recipient: &PublicIdentity,
) -> XChaCha20Poly1305 {
    let mut material = Zeroizing::new(Vec::with_capacity(96));
    material.extend_from_slice(shared);
    material.extend_from_slice(ephemeral);
    material.extend_from_slice(&recipient.encryption);
    let key = Zeroizing::new(blake3::derive_key(domain::WRAP_KEY, &material));
    XChaCha20Poly1305::new_from_slice(&key[..]).unwrap()
}

/// Encrypts `key` so only `recipient` can open it, for the key's context. A fresh
/// ephemeral key and random nonce are used every time.
/// This authenticates the ciphertext's context, not its sender: anyone with
/// the recipient's public key can wrap a key of their own choosing.
/// Use [`grant`] and [`open_grant`] for remote key exchange.
pub fn wrap(key: &EpochKey, recipient: &PublicIdentity) -> Result<WrappedKey, KeyError> {
    let ephemeral_secret = StaticSecret::from(*random32()?);
    let ephemeral = XPublic::from(&ephemeral_secret).to_bytes();
    let shared = ephemeral_secret.diffie_hellman(&XPublic::from(recipient.encryption));
    if !shared.was_contributory() {
        return Err(KeyError::WeakKey);
    }
    let mut nonce = [0u8; 24];
    getrandom::getrandom(&mut nonce).map_err(|e| KeyError::Random(e.to_string()))?;
    let aad = key.context.aad(domain::WRAP_AAD, &recipient.encryption);
    let ciphertext = wrap_cipher(shared.as_bytes(), &ephemeral, recipient)
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &key.bytes,
                aad: &aad,
            },
        )
        .map_err(|_| KeyError::Decrypt)?;
    Ok(WrappedKey {
        ephemeral,
        nonce,
        ciphertext,
    })
}

/// Opens an anonymous wrap. This does NOT authenticate the sender; remote
/// keyring consumers must use [`open_grant`] instead.
/// Opens a wrapped key WITHOUT checking who granted it. A server can wrap a
/// key it knows to your public key, so never use this to accept keys from a
/// remote: use [`open_grant`], which verifies the owner's signature.
pub fn unwrap_unverified(
    wrapped: &WrappedKey,
    group: &GroupEpoch,
    identity: &Identity,
) -> Result<EpochKey, KeyError> {
    let recipient = identity.public();
    let shared = identity
        .secret
        .diffie_hellman(&XPublic::from(wrapped.ephemeral));
    if !shared.was_contributory() {
        return Err(KeyError::WeakKey);
    }
    let aad = group.aad(domain::WRAP_AAD, &recipient.encryption);
    let plain = Zeroizing::new(
        wrap_cipher(shared.as_bytes(), &wrapped.ephemeral, &recipient)
            .decrypt(
                XNonce::from_slice(&wrapped.nonce),
                Payload {
                    msg: &wrapped.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| KeyError::Decrypt)?,
    );
    let bytes: &[u8; 32] = plain.as_slice().try_into().map_err(|_| KeyError::Decrypt)?;
    Ok(EpochKey::from_bytes(group.clone(), *bytes))
}

/// An owner-authenticated epoch key for one recipient. All fields except
/// `signature` are covered by the signature. The remote id, the group and
/// the ciphertext are length-prefixed, so the encoding has one parse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    pub context: GroupEpoch,
    pub recipient: PublicIdentity,
    pub wrapped: WrappedKey,
    pub commitment: [u8; 32],
    pub granter: [u8; 32],
    pub signature: [u8; 64],
}

impl Grant {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = self.context.aad(domain::GRANT_SIGNATURE.as_bytes(), b"");
        bytes.extend_from_slice(&self.recipient.encryption);
        bytes.extend_from_slice(&self.recipient.signing);
        bytes.extend_from_slice(&self.wrapped.ephemeral);
        bytes.extend_from_slice(&self.wrapped.nonce);
        bytes.extend_from_slice(&(self.wrapped.ciphertext.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&self.wrapped.ciphertext);
        bytes.extend_from_slice(&self.commitment);
        bytes.extend_from_slice(&self.granter);
        bytes
    }

    /// Checks the granter field and the Ed25519 signature. Does not unwrap.
    pub fn verify_signature(&self, owner_signing_key: &[u8; 32]) -> Result<(), KeyError> {
        if self.granter != *owner_signing_key {
            return Err(KeyError::InvalidGrant);
        }
        let owner =
            VerifyingKey::from_bytes(owner_signing_key).map_err(|_| KeyError::InvalidGrant)?;
        owner
            .verify_strict(
                &self.signing_bytes(),
                &ed25519_dalek::Signature::from_bytes(&self.signature),
            )
            .map_err(|_| KeyError::InvalidGrant)
    }
}

/// Wraps and signs a grant. In phase 1 `owner` must be the pinned repo owner.
pub fn grant(
    key: &EpochKey,
    recipient: &PublicIdentity,
    owner: &Identity,
) -> Result<Grant, KeyError> {
    let mut grant = Grant {
        context: key.context.clone(),
        recipient: *recipient,
        wrapped: wrap(key, recipient)?,
        commitment: *key.subkey(domain::EPOCH_KEY_COMMITMENT),
        granter: owner.public().signing,
        signature: [0; 64],
    };
    grant.signature = owner.signing.sign(&grant.signing_bytes()).to_bytes();
    Ok(grant)
}

/// Verifies the pinned owner, signature, recipient, wrap and key commitment.
/// The trust anchor must come from local pinning or out-of-band verification,
/// never from the untrusted grant itself. Owners keep using local epoch keys.
pub fn open_grant(
    grant: &Grant,
    identity: &Identity,
    trusted_owner_signing_key: &[u8; 32],
) -> Result<EpochKey, KeyError> {
    if grant.recipient != identity.public() {
        return Err(KeyError::InvalidGrant);
    }
    grant.verify_signature(trusted_owner_signing_key)?;
    let key = unwrap_unverified(&grant.wrapped, &grant.context, identity)?;
    if blake3::Hash::from(*key.subkey(domain::EPOCH_KEY_COMMITMENT))
        != blake3::Hash::from(grant.commitment)
    {
        return Err(KeyError::InvalidGrant);
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_identity_is_random_authenticated_and_preserves_public_keys() {
        let identity = Identity::from_bytes([37; 64]);
        let protected = identity.encrypt(b"test passphrase").unwrap();
        assert_ne!(protected, identity.encrypt(b"test passphrase").unwrap());
        assert!(!protected.windows(64).any(|b| b == *identity.to_bytes()));
        assert_eq!(Identity::decrypt(&protected, b"test passphrase").unwrap().public(), identity.public());
        assert_eq!(identity.public().fingerprint().len(), 32);
        assert!(Identity::decrypt(&protected, b"wrong passphrase").is_err());
        for offset in [0, 4, 5, 21, 45, protected.len() - 1] {
            let mut damaged = protected.clone(); damaged[offset] ^= 1;
            assert!(Identity::decrypt(&damaged, b"test passphrase").is_err());
        }
        assert!(Identity::decrypt(&protected[..64], b"test passphrase").is_err());
        assert!(identity.encrypt(b"").is_err());
    }


    fn group() -> GroupEpoch {
        // Fixed remote so the golden vectors below stay reproducible.
        GroupEpoch {
            remote: [9; 16],
            group: "private".into(),
            epoch: 1,
        }
    }

    fn path(s: &str) -> RepoPath {
        RepoPath::new(s).unwrap()
    }

    #[test]
    fn wrap_roundtrip_and_binding() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let key = EpochKey::generate(group()).unwrap();
        let w = wrap(&key, &alice.public()).unwrap();
        let opened = unwrap_unverified(&w, &group(), &alice).unwrap();
        assert_eq!(opened.bytes, key.bytes);
        assert_eq!(opened.context(), key.context());
        // Wrong person, wrong remote, wrong group, wrong epoch, tampering: all refused.
        assert!(unwrap_unverified(&w, &group(), &bob).is_err());
        assert!(unwrap_unverified(
            &w,
            &GroupEpoch {
                remote: [9; 16],
                group: "billing".into(),
                epoch: 1
            },
            &alice
        )
        .is_err());
        assert!(unwrap_unverified(
            &w,
            &GroupEpoch {
                remote: [9; 16],
                group: "private".into(),
                epoch: 2
            },
            &alice
        )
        .is_err());
        assert!(unwrap_unverified(
            &w,
            &GroupEpoch {
                remote: [8; 16],
                group: "private".into(),
                epoch: 1
            },
            &alice
        )
        .is_err());
        let mut bad = w.clone();
        bad.ciphertext[0] ^= 1;
        assert!(unwrap_unverified(&bad, &group(), &alice).is_err());
        // Fresh randomness every wrap.
        assert_ne!(wrap(&key, &alice.public()).unwrap(), w);
    }

    #[test]
    fn low_order_public_key_is_refused() {
        let key = EpochKey::generate(group()).unwrap();
        let recipient = PublicIdentity {
            encryption: [0; 32],
            signing: [0; 32],
        };
        assert!(matches!(wrap(&key, &recipient), Err(KeyError::WeakKey)));
    }

    #[test]
    fn object_encryption_is_deterministic_and_bound() {
        let key = EpochKey::generate(group()).unwrap();
        let id = hash_object(ObjectKind::Blob, b"SECRET=1");
        let a = key
            .encrypt_object(ObjectKind::Blob, &id, b"SECRET=1")
            .unwrap();
        assert_eq!(
            a,
            key.encrypt_object(ObjectKind::Blob, &id, b"SECRET=1")
                .unwrap()
        );
        assert_eq!(
            key.decrypt_object(ObjectKind::Blob, &id, &a)
                .unwrap()
                .as_slice(),
            b"SECRET=1"
        );
        let other_group = GroupEpoch {
            remote: [9; 16],
            group: "billing".into(),
            epoch: 1,
        };
        let other = EpochKey::from_bytes(other_group, *key.to_bytes());
        assert!(other.decrypt_object(ObjectKind::Blob, &id, &a).is_err());
        let other_remote = GroupEpoch {
            remote: [8; 16],
            group: "private".into(),
            epoch: 1,
        };
        let shifted = EpochKey::from_bytes(other_remote, *key.to_bytes());
        assert!(shifted.decrypt_object(ObjectKind::Blob, &id, &a).is_err());
        assert_ne!(key.wire_id(&id), shifted.wire_id(&id));
        assert!(key.decrypt_object(ObjectKind::Tree, &id, &a).is_err());
        assert!(key
            .decrypt_object(ObjectKind::Blob, &ObjectId([5; 32]), &a)
            .is_err());
        // A different epoch key never produces the same ciphertext.
        let key2 = EpochKey::generate(group()).unwrap();
        assert_ne!(
            a,
            key2.encrypt_object(ObjectKind::Blob, &id, b"SECRET=1")
                .unwrap()
        );
    }

    #[test]
    fn seal_is_stable_bound_and_verifiable() {
        let key = EpochKey::generate(group()).unwrap();
        let id = ObjectId([7; 32]);
        let s = key.seal(&path(".env"), EntryKind::File, &id);
        assert_eq!(
            s,
            key.seal(&path(".env"), EntryKind::File, &id),
            "stable for unchanged content"
        );
        assert_ne!(
            s,
            key.seal(&path("other/.env"), EntryKind::File, &id),
            "same content elsewhere differs"
        );
        assert_ne!(
            s,
            key.seal(&path(".env"), EntryKind::File, &ObjectId([8; 32]))
        );
        assert_ne!(s.as_bytes(), id.as_bytes());
        // Disclosing one salt lets anyone verify that one entry.
        let salt = key.seal_salt(&path(".env"), EntryKind::File, &id);
        assert!(s.verify(&salt, EntryKind::File, &id));
        // Subkeys are independent: the wire id is not the sealed id or the plain id.
        assert_ne!(key.wire_id(&id).0, *s.as_bytes());
        assert_ne!(key.wire_id(&id).0, id.0);
    }

    #[test]
    fn identity_storage_preserves_both_independent_keys() {
        let identity = Identity::generate().unwrap();
        let bytes = identity.to_bytes();
        assert_ne!(&bytes[..32], &bytes[32..]);
        let restored = Identity::from_bytes(*bytes);
        assert_eq!(restored.public(), identity.public());
        assert_eq!(restored.to_bytes(), bytes);
        let mut different = identity.public();
        different.encryption[0] ^= 1;
        assert_ne!(different.fingerprint(), identity.public().fingerprint());
        different = identity.public();
        different.signing[0] ^= 1;
        assert_ne!(different.fingerprint(), identity.public().fingerprint());
    }

    #[test]
    fn signed_grants_bind_every_field_and_the_trusted_owner() {
        let owner = Identity::generate().unwrap();
        let member = Identity::generate().unwrap();
        let key = EpochKey::generate(group()).unwrap();
        let g = grant(&key, &member.public(), &owner).unwrap();
        let trusted = owner.public().signing;
        let opened = open_grant(&g, &member, &trusted).unwrap();
        assert_eq!(opened.to_bytes(), key.to_bytes());
        assert_eq!(opened.context(), key.context());
        assert!(open_grant(&g, &owner, &trusted).is_err());
        assert!(open_grant(&g, &member, &member.public().signing).is_err());
        for field in 0..11 {
            let mut bad = g.clone();
            match field {
                0 => bad.context.group.push('\0'),
                1 => bad.context.epoch += 1,
                2 => bad.recipient.encryption[0] ^= 1,
                3 => bad.recipient.signing[0] ^= 1,
                4 => bad.wrapped.ephemeral[0] ^= 1,
                5 => bad.wrapped.nonce[0] ^= 1,
                6 => bad.wrapped.ciphertext[0] ^= 1,
                7 => bad.wrapped.ciphertext.push(0),
                8 => bad.commitment[0] ^= 1,
                9 => bad.granter[0] ^= 1,
                _ => bad.signature[0] ^= 1,
            }
            assert!(
                open_grant(&bad, &member, &trusted).is_err(),
                "field {field}"
            );
        }
        let mut bad = g.clone();
        bad.context.remote[0] ^= 1;
        assert!(open_grant(&bad, &member, &trusted).is_err(), "remote");
        // A correct owner signature cannot make a bad commitment or wrap valid.
        let mut bad = g.clone();
        bad.commitment[0] ^= 1;
        bad.signature = owner.signing.sign(&bad.signing_bytes()).to_bytes();
        assert!(matches!(
            open_grant(&bad, &member, &trusted),
            Err(KeyError::InvalidGrant)
        ));
        let mut bad = g;
        bad.wrapped.ciphertext[0] ^= 1;
        bad.signature = owner.signing.sign(&bad.signing_bytes()).to_bytes();
        assert!(matches!(
            open_grant(&bad, &member, &trusted),
            Err(KeyError::Decrypt)
        ));
    }

    #[test]
    fn authenticated_object_with_wrong_hash_is_refused() {
        let key = EpochKey::generate(group()).unwrap();
        let id = hash_object(ObjectKind::Blob, b"SECRET=1");
        let cipher =
            XChaCha20Poly1305::new_from_slice(&key.subkey(domain::CONTENT_KEY)[..]).unwrap();
        let nonce = key.object_nonce(ObjectKind::Blob, &id);
        let aad = key
            .context
            .aad(domain::OBJECT_AAD, &object_aad(ObjectKind::Blob, &id));
        // Deliberately bypass encrypt_object to simulate an authenticated bad pack.
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: b"SECRET=2",
                    aad: &aad,
                },
            )
            .unwrap();
        assert!(matches!(
            key.decrypt_object(ObjectKind::Blob, &id, &ciphertext),
            Err(KeyError::ObjectMismatch)
        ));
    }

    #[test]
    fn authenticated_wrap_with_wrong_plaintext_length_is_refused() {
        let member = Identity::generate().unwrap();
        let key = EpochKey::generate(group()).unwrap();
        let mut wrapped = wrap(&key, &member.public()).unwrap();
        let shared = member
            .secret
            .diffie_hellman(&XPublic::from(wrapped.ephemeral));
        let cipher = wrap_cipher(shared.as_bytes(), &wrapped.ephemeral, &member.public());
        let aad = key
            .context
            .aad(domain::WRAP_AAD, &member.public().encryption);
        wrapped.ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&wrapped.nonce),
                Payload {
                    msg: &[0; 31],
                    aad: &aad,
                },
            )
            .unwrap();
        assert!(matches!(
            unwrap_unverified(&wrapped, &group(), &member),
            Err(KeyError::Decrypt)
        ));
    }

    #[test]
    fn secret_types_zeroize() {
        fn wipes_on_drop<T: ZeroizeOnDrop>() {}
        wipes_on_drop::<EpochKey>();
        wipes_on_drop::<SealSalt>();
        wipes_on_drop::<SigningKey>();
        wipes_on_drop::<Zeroizing<[u8; 64]>>();
        wipes_on_drop::<Zeroizing<Vec<u8>>>();
        // x25519-dalek zeroizes on drop but does not implement the marker trait.
        let mut secret = StaticSecret::from([7; 32]);
        secret.zeroize();
        assert_eq!(secret.as_bytes(), &[0; 32]);
        let mut key = EpochKey::from_bytes(group(), [9; 32]);
        key.zeroize();
        assert_eq!(*key.to_bytes(), [0; 32]);
        let mut salt = SealSalt::from_bytes([8; 32]);
        salt.zeroize();
        assert_eq!(salt.as_bytes(), &[0; 32]);
    }

    #[test]
    fn context_crypto_and_signed_grant_are_frozen() {
        let owner = Identity::from_bytes([1; 64]);
        let member = Identity::from_bytes([2; 64]);
        let key = EpochKey::from_bytes(group(), [3; 32]);
        let body = b"SECRET=1";
        let id = hash_object(ObjectKind::Blob, body);
        // Fixed randomness is only for this golden vector, never production.
        let ephemeral_secret = StaticSecret::from([4; 32]);
        let ephemeral = XPublic::from(&ephemeral_secret).to_bytes();
        let shared = ephemeral_secret.diffie_hellman(&XPublic::from(member.public().encryption));
        let nonce = [5; 24];
        let aad = key
            .context
            .aad(domain::WRAP_AAD, &member.public().encryption);
        let ciphertext = wrap_cipher(shared.as_bytes(), &ephemeral, &member.public())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &key.bytes,
                    aad: &aad,
                },
            )
            .unwrap();
        let mut g = Grant {
            context: group(),
            recipient: member.public(),
            wrapped: WrappedKey {
                ephemeral,
                nonce,
                ciphertext,
            },
            commitment: *key.subkey(domain::EPOCH_KEY_COMMITMENT),
            granter: owner.public().signing,
            signature: [0; 64],
        };
        g.signature = owner.signing.sign(&g.signing_bytes()).to_bytes();
        assert_eq!(
            open_grant(&g, &member, &owner.public().signing)
                .unwrap()
                .to_bytes(),
            key.to_bytes()
        );
        for (label, expected) in [
            (
                domain::SEAL_SALT_KEY,
                "5e25548d21d46249807c55cc36388a0528ea740277faf8758033d25ac6fa7bb1",
            ),
            (
                domain::CONTENT_KEY,
                "b5b33688a8bebb1b1d9e03ae10a9a5f9268a97165cd167e03d47a7a3a608688f",
            ),
            (
                domain::NONCE_KEY,
                "2be7248c4e30837e97dc2edf305143cb9d48115140bbf07e07666de311bf0317",
            ),
            (
                domain::WIRE_ID_KEY,
                "6e1f7546f22f81739e83a637edf7f9625dfadd793bd34e23c50e9b2352d4e744",
            ),
        ] {
            assert_eq!(hex::encode(*key.subkey(label)), expected, "{label}");
        }
        assert_eq!(owner.public().fingerprint(), "11937e1ac7824421bc2010e36e743598");
        assert_eq!(
            hex::encode(
                key.seal_salt(&path(".env"), EntryKind::File, &id)
                    .as_bytes()
            ),
            "89991c15d66841c44452071247c7a9bbdf9d70f81ae324c7dbd35bf25e48d14b"
        );
        assert_eq!(
            key.seal(&path(".env"), EntryKind::File, &id).to_hex(),
            "0f807823e921a12afba88f9bd9fa1bbb1e3ccc6cc97cfa0cb0413e7d124a414b"
        );
        assert_eq!(
            hex::encode(key.wire_id(&id).0),
            "ab1739d9d7a6d3211ba31486665a8c7c54a1b0ce06a588c871a9f63df99fe416"
        );
        assert_eq!(
            hex::encode(key.encrypt_object(ObjectKind::Blob, &id, body).unwrap()),
            "8b740a129acbf5ed0875171feb4b7f5aee80eb122b74fffc"
        );
        assert_eq!(
            hex::encode(&g.wrapped.ciphertext),
            "484c91ead078bc8e4df19bb7b2b696ed7717ea43feb498b2c4df9809805390cf2732d09fb5342a9519a3a14ddf53d55c"
        );
        assert_eq!(
            hex::encode(g.commitment),
            "e0b245ec5f679ceb03d08bf915f421b51e2d1a73061b2e60b6ee5137c09da483"
        );
        assert_eq!(
            blake3::hash(&g.signing_bytes()).to_hex().as_str(),
            "31e1faaf24dce6a9724b04a63c42db476ccdf724570e362d638ab75bed99a24a"
        );
        assert_eq!(
            hex::encode(g.signature),
            "72e9e644dfef41f17f3bda054b0955164fbe0dbdd1c622a47525ce4a2d632b8e912ae0cedd54e6d9b08fef8472eeee5a0fbebe1b7d4f97456c48e5801e60610d"
        );
    }

    #[test]
    fn index_encryption_is_bound_to_header_and_context() {
        let key = EpochKey::generate(group()).unwrap();
        let header = *b"TIGPheader";
        let (nonce, ct) = key.encrypt_index(b"index-bytes", &header).unwrap();
        assert_eq!(
            key.decrypt_index(&nonce, &ct, &header).unwrap().as_slice(),
            b"index-bytes"
        );
        let mut bad_header = header;
        bad_header[0] ^= 1;
        assert!(key.decrypt_index(&nonce, &ct, &bad_header).is_err());
        let mut bad_nonce = nonce;
        bad_nonce[0] ^= 1;
        assert!(key.decrypt_index(&bad_nonce, &ct, &header).is_err());
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 1;
        assert!(key.decrypt_index(&nonce, &bad_ct, &header).is_err());
        let other = EpochKey::from_bytes(
            GroupEpoch {
                remote: [8; 16],
                group: "private".into(),
                epoch: 1,
            },
            *key.to_bytes(),
        );
        assert!(other.decrypt_index(&nonce, &ct, &header).is_err());
        let (nonce2, ct2) = key.encrypt_index(b"index-bytes", &header).unwrap();
        assert_ne!(nonce, nonce2);
        assert_ne!(ct, ct2);
    }
}
