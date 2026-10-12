//! The signed publish manifest: what a remote is supposed to contain.
//!
//! Without it a server could serve old refs (hiding new history) or withhold
//! a sealed pack, and a member could not tell a withheld pack from a seal
//! they were never meant to open. Every publish writes, after objects, the
//! pack and the refs, a manifest signed by the publisher:
//!
//! - `refs`: bookmark → public revision. Fetch trusts refs only from here.
//! - `sequence`: strictly increases with each publish; fetch and publish
//!   refuse a lower one than they have seen (rollback).
//! - `packs`: cumulative, pack id (BLAKE3 of the pack bytes) → group, epoch
//!   and the sealed ids whose records it carries. A member who can open an
//!   epoch must find every listed pack of that epoch, carrying its records.
//!
//! Signers: the keyring owner, or a member holding a grant for the current
//! epoch of the group. The caller passes a keyring it has already verified.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use tig_core::encode::{Reader, Writer};
use tig_core::seal::SealedId;
use tig_core::ObjectId;

use crate::keyring::Keyring;
use crate::keys::Identity;
use crate::project::PRIVATE_GROUP;
use crate::remote::RemoteError;

const VERSION: u8 = 1;
const MAX_REFS: usize = 100_000;
const MAX_PACKS: usize = 1_000_000;
const MAX_SEALED_PER_PACK: usize = 1_000_000;
const MAX_NAME: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("publish manifest is malformed: {0}")]
    Malformed(String),
    #[error("publish manifest signature is invalid or the signer is not allowed to publish")]
    BadSignature,
    #[error("publish manifest is for a different remote")]
    WrongRemote,
    #[error("publish manifest rolled back: sequence {found} is older than {seen} already seen")]
    RolledBack { found: u64, seen: u64 },
    #[error(transparent)]
    Remote(#[from] RemoteError),
}

impl From<tig_core::Error> for ManifestError {
    fn from(e: tig_core::Error) -> Self {
        ManifestError::Malformed(e.to_string())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackEntry {
    pub group: String,
    pub epoch: u64,
    pub sealed: BTreeSet<SealedId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub remote: [u8; 16],
    pub sequence: u64,
    pub publisher: [u8; 32],
    pub refs: BTreeMap<String, ObjectId>,
    pub packs: BTreeMap<[u8; 32], PackEntry>,
    pub signature: [u8; 64],
}

impl Manifest {
    /// Signs a manifest as `publisher`.
    pub fn signed(
        remote: [u8; 16],
        sequence: u64,
        refs: BTreeMap<String, ObjectId>,
        packs: BTreeMap<[u8; 32], PackEntry>,
        publisher: &Identity,
    ) -> Result<Self, ManifestError> {
        let mut manifest = Manifest {
            remote,
            sequence,
            publisher: publisher.public().signing,
            refs,
            packs,
            signature: [0; 64],
        };
        manifest.signature = publisher.sign(&manifest.signing_bytes()?);
        Ok(manifest)
    }

    /// Checks remote binding, rollback, the signer's right to publish, and
    /// the signature. `keyring` must already be verified by the caller.
    pub fn verify(
        &self,
        remote: [u8; 16],
        keyring: &Keyring,
        min_sequence: u64,
    ) -> Result<(), ManifestError> {
        if self.remote != remote {
            return Err(ManifestError::WrongRemote);
        }
        if self.sequence < min_sequence {
            return Err(ManifestError::RolledBack {
                found: self.sequence,
                seen: min_sequence,
            });
        }
        if !allowed_signers(keyring).contains(&self.publisher) {
            return Err(ManifestError::BadSignature);
        }
        let key =
            VerifyingKey::from_bytes(&self.publisher).map_err(|_| ManifestError::BadSignature)?;
        key.verify_strict(
            &self.signing_bytes()?,
            &ed25519_dalek::Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ManifestError::BadSignature)
    }

    fn body(&self) -> Result<Writer, ManifestError> {
        if self.refs.len() > MAX_REFS || self.packs.len() > MAX_PACKS {
            return Err(ManifestError::Malformed("too many refs or packs".into()));
        }
        let mut w = Writer::new();
        w.u8(VERSION);
        w.buf.extend_from_slice(&self.remote);
        w.varint(self.sequence);
        w.buf.extend_from_slice(&self.publisher);
        w.varint(self.refs.len() as u64);
        for (name, id) in &self.refs {
            if name.is_empty() || name.len() > MAX_NAME {
                return Err(ManifestError::Malformed("invalid ref name".into()));
            }
            w.str(name);
            w.id(id);
        }
        w.varint(self.packs.len() as u64);
        for (pack, entry) in &self.packs {
            if entry.group.is_empty()
                || entry.group.len() > MAX_NAME
                || entry.sealed.len() > MAX_SEALED_PER_PACK
            {
                return Err(ManifestError::Malformed("invalid pack entry".into()));
            }
            w.buf.extend_from_slice(pack);
            w.str(&entry.group);
            w.varint(entry.epoch);
            w.varint(entry.sealed.len() as u64);
            for sealed in &entry.sealed {
                w.buf.extend_from_slice(sealed.as_bytes());
            }
        }
        Ok(w)
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        let mut bytes = tig_core::domain::PUBLISH_MANIFEST_SIGNATURE
            .as_bytes()
            .to_vec();
        bytes.extend_from_slice(&self.body()?.finish());
        Ok(bytes)
    }

    pub fn encode(&self) -> Result<Vec<u8>, ManifestError> {
        let mut w = self.body()?;
        w.buf.extend_from_slice(&self.signature);
        Ok(w.finish())
    }

    /// Decodes canonical bytes only (sorted, no duplicates, no trailing data).
    pub fn decode(bytes: &[u8]) -> Result<Self, ManifestError> {
        let mut r = Reader::new(bytes, "publish manifest");
        if r.u8()? != VERSION {
            return Err(ManifestError::Malformed("unsupported version".into()));
        }
        let remote: [u8; 16] = r.take(16)?.try_into().expect("16 bytes");
        let sequence = r.varint()?;
        let publisher: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
        let n = r.count(1 + 32)?;
        if n > MAX_REFS {
            return Err(ManifestError::Malformed("too many refs".into()));
        }
        let mut refs = BTreeMap::new();
        let mut last: Option<String> = None;
        for _ in 0..n {
            let name = r.str()?.to_string();
            if name.is_empty() || name.len() > MAX_NAME || last.as_ref().is_some_and(|l| *l >= name)
            {
                return Err(ManifestError::Malformed("refs are not canonical".into()));
            }
            last = Some(name.clone());
            refs.insert(name, r.id()?);
        }
        let n = r.count(32 + 1 + 1 + 1)?;
        if n > MAX_PACKS {
            return Err(ManifestError::Malformed("too many packs".into()));
        }
        let mut packs = BTreeMap::new();
        let mut last_pack: Option<[u8; 32]> = None;
        for _ in 0..n {
            let pack: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
            if last_pack.is_some_and(|l| l >= pack) {
                return Err(ManifestError::Malformed("packs are not canonical".into()));
            }
            last_pack = Some(pack);
            let group = r.str()?.to_string();
            if group.is_empty() || group.len() > MAX_NAME {
                return Err(ManifestError::Malformed("invalid group".into()));
            }
            let epoch = r.varint()?;
            let m = r.count(32)?;
            if m > MAX_SEALED_PER_PACK {
                return Err(ManifestError::Malformed("too many sealed ids".into()));
            }
            let mut sealed = BTreeSet::new();
            let mut last_sealed: Option<[u8; 32]> = None;
            for _ in 0..m {
                let raw: [u8; 32] = r.take(32)?.try_into().expect("32 bytes");
                if last_sealed.is_some_and(|l| l >= raw) {
                    return Err(ManifestError::Malformed(
                        "sealed ids are not canonical".into(),
                    ));
                }
                last_sealed = Some(raw);
                sealed.insert(SealedId::from_stored(raw));
            }
            packs.insert(
                pack,
                PackEntry {
                    group,
                    epoch,
                    sealed,
                },
            );
        }
        let signature: [u8; 64] = r.take(64)?.try_into().expect("64 bytes");
        r.finish()?;
        Ok(Manifest {
            remote,
            sequence,
            publisher,
            refs,
            packs,
            signature,
        })
    }
}

/// Re-signs `manifest` as the owner, unchanged but for a higher sequence.
/// Returns the new manifest bytes, or `None` when there is no manifest yet.
/// `keyring` is the verified keyring still on the remote (the caller commits
/// the bytes together with the next keyring). The last publisher may lose
/// their right to sign, and the remote must never show a manifest its own
/// keyring rejects.
pub fn resign_as_owner(
    manifest: Option<&[u8]>,
    remote_id: [u8; 16],
    owner: &Identity,
    keyring: &Keyring,
    min_sequence: u64,
) -> Result<Option<Vec<u8>>, ManifestError> {
    let Some(bytes) = manifest else {
        return Ok(None);
    };
    let current = Manifest::decode(bytes)?;
    current.verify(remote_id, keyring, min_sequence)?;
    if owner.public() != keyring.owner {
        return Err(ManifestError::BadSignature);
    }
    let sequence = current
        .sequence
        .checked_add(1)
        .ok_or_else(|| ManifestError::Malformed("sequence overflow".into()))?;
    let resigned = Manifest::signed(current.remote, sequence, current.refs, current.packs, owner)?;
    Ok(Some(resigned.encode()?))
}

/// Who may sign a manifest: the owner, and members with a grant for the
/// current epoch of the private group. `keyring` must already be verified.
pub fn allowed_signers(keyring: &Keyring) -> BTreeSet<[u8; 32]> {
    let mut allowed = BTreeSet::from([keyring.owner.signing]);
    if let Some(&current) = keyring.head.epochs.get(PRIVATE_GROUP) {
        for grant in &keyring.grants {
            if grant.context.group == PRIVATE_GROUP && grant.context.epoch == current {
                allowed.insert(grant.recipient.signing);
            }
        }
    }
    allowed
}

/// The pack id used in manifests: BLAKE3 of the pack bytes.
pub fn pack_id(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_is_canonical_and_signed() {
        let owner = Identity::generate().unwrap();
        let (keyring, _) = Keyring::create([3; 16], &owner).unwrap();
        let refs = BTreeMap::from([
            ("a".to_string(), ObjectId([1; 32])),
            ("b".to_string(), ObjectId([2; 32])),
        ]);
        let packs = BTreeMap::from([(
            [9; 32],
            PackEntry {
                group: PRIVATE_GROUP.into(),
                epoch: 1,
                sealed: BTreeSet::from([
                    SealedId::from_stored([4; 32]),
                    SealedId::from_stored([5; 32]),
                ]),
            },
        )]);
        let manifest = Manifest::signed([3; 16], 7, refs, packs, &owner).unwrap();
        let bytes = manifest.encode().unwrap();
        let decoded = Manifest::decode(&bytes).unwrap();
        assert_eq!(decoded, manifest);
        decoded.verify([3; 16], &keyring, 7).unwrap();
        assert!(matches!(
            decoded.verify([4; 16], &keyring, 0),
            Err(ManifestError::WrongRemote)
        ));
        assert!(matches!(
            decoded.verify([3; 16], &keyring, 8),
            Err(ManifestError::RolledBack { .. })
        ));

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Manifest::decode(&trailing).is_err());
        // Swap the two sealed ids so they are out of order.
        let mut unsorted = bytes.clone();
        let at = unsorted.windows(32).position(|w| w == [4; 32]).unwrap();
        unsorted[at..at + 32].copy_from_slice(&[5; 32]);
        unsorted[at + 32..at + 64].copy_from_slice(&[4; 32]);
        assert!(Manifest::decode(&unsorted).is_err());
    }
}
