//! Request signatures. The signed bytes are
//! `REMOTE_REQUEST_SIGNATURE || remote_id || u64le_len || method || u64le_len || path
//! || blake3(body) || nonce`.
//!
//! `Identity::sign` covers those bytes directly. The server checks them with
//! `ed25519_dalek` (`verify_strict`) against `PublicIdentity.signing`. A helper
//! on `PublicIdentity` would avoid this crate naming dalek, but none is public.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use tig_core::domain::REMOTE_REQUEST_SIGNATURE;
use tig_private::keys::PublicIdentity;

use crate::limits::{MAX_NONCES, NONCE_TTL_SECS};

pub(crate) fn signing_message(
    remote_id: &[u8; 16],
    method: &str,
    path: &str,
    body: &[u8],
    nonce: &[u8; 32],
) -> Vec<u8> {
    let method = method.as_bytes();
    let path = path.as_bytes();
    let mut out = Vec::with_capacity(
        REMOTE_REQUEST_SIGNATURE.len() + 16 + 8 + method.len() + 8 + path.len() + 32 + 32,
    );
    out.extend_from_slice(REMOTE_REQUEST_SIGNATURE.as_bytes());
    out.extend_from_slice(remote_id);
    out.extend_from_slice(&(method.len() as u64).to_le_bytes());
    out.extend_from_slice(method);
    out.extend_from_slice(&(path.len() as u64).to_le_bytes());
    out.extend_from_slice(path);
    out.extend_from_slice(blake3::hash(body).as_bytes());
    out.extend_from_slice(nonce);
    out
}

pub(crate) fn verify_signature(
    signing: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), ()> {
    let key = VerifyingKey::from_bytes(signing).map_err(|_| ())?;
    let signature = Signature::from_bytes(signature);
    key.verify_strict(message, &signature).map_err(|_| ())
}

pub(crate) fn parse_identity(header: &str) -> Option<PublicIdentity> {
    let header = header.trim();
    if header.len() != 128 {
        return None;
    }
    let raw = hex::decode(header).ok()?;
    if raw.len() != 64 {
        return None;
    }
    let mut encryption = [0u8; 32];
    let mut signing = [0u8; 32];
    encryption.copy_from_slice(&raw[..32]);
    signing.copy_from_slice(&raw[32..]);
    Some(PublicIdentity {
        encryption,
        signing,
    })
}

pub(crate) fn format_identity(identity: &PublicIdentity) -> String {
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&identity.encryption);
    raw[32..].copy_from_slice(&identity.signing);
    hex::encode(raw)
}

pub(crate) fn parse_fixed_hex<const N: usize>(header: &str) -> Option<[u8; N]> {
    let header = header.trim();
    if header.len() != N * 2 {
        return None;
    }
    let raw = hex::decode(header).ok()?;
    raw.try_into().ok()
}

/// Outstanding single-use nonces. Only unconsumed nonces are stored.
#[derive(Default)]
pub(crate) struct NonceTable {
    by_time: VecDeque<([u8; 32], Instant)>,
    live: BTreeMap<[u8; 32], Instant>,
}

impl NonceTable {
    pub(crate) fn issue(&mut self, now: Instant) -> Result<[u8; 32], ()> {
        self.sweep(now);
        if self.live.len() >= MAX_NONCES {
            return Err(());
        }
        let mut nonce = [0u8; 32];
        for _ in 0..4 {
            getrandom::getrandom(&mut nonce).map_err(|_| ())?;
            if let std::collections::btree_map::Entry::Vacant(entry) = self.live.entry(nonce) {
                entry.insert(now);
                self.by_time.push_back((nonce, now));
                return Ok(nonce);
            }
        }
        Err(())
    }

    /// Removes `nonce` if it was issued here and is still inside the TTL.
    pub(crate) fn consume(&mut self, nonce: &[u8; 32], now: Instant) -> Result<(), ()> {
        self.sweep(now);
        match self.live.remove(nonce) {
            Some(issued) if now.duration_since(issued) <= Duration::from_secs(NONCE_TTL_SECS) => {
                Ok(())
            }
            Some(_) => Err(()),
            None => Err(()),
        }
    }

    fn sweep(&mut self, now: Instant) {
        let ttl = Duration::from_secs(NONCE_TTL_SECS);
        while let Some(&(nonce, issued)) = self.by_time.front() {
            if now.duration_since(issued) > ttl {
                self.by_time.pop_front();
                if self.live.get(&nonce).is_some_and(|t| *t == issued) {
                    self.live.remove(&nonce);
                }
            } else {
                break;
            }
        }
    }
}
