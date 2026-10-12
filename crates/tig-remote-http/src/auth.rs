//! Request signatures. The signed bytes are
//! `REMOTE_REQUEST_SIGNATURE || remote_id || u64le_len || method || u64le_len || path
//! || blake3(body) || nonce || u64le_len || if_match` (`if_match` is the exact
//! `If-Match` header value, or empty when the request has none).
//!
//! A nonce is 56 bytes: `issued_ms_u64le || random_16 || mac_32`, where
//! `issued_ms` counts milliseconds on the server's monotonic clock since it
//! started and `mac = blake3::keyed_hash(server_secret, issued_ms || random)`
//! under a random per-process secret. Issuing keeps no state, so asking for
//! nonces cannot crowd anyone out. The server accepts a nonce once, within
//! `NONCE_TTL`, and only after the signature verifies and the signer is
//! authorized; it remembers consumed nonces until they expire. A restart
//! invalidates every outstanding nonce.
//!
//! `Identity::sign` covers those bytes directly. The server checks them with
//! `ed25519_dalek` (`verify_strict`) against `PublicIdentity.signing`. A helper
//! on `PublicIdentity` would avoid this crate naming dalek, but none is public.

use std::collections::BTreeSet;
use std::time::Instant;

use ed25519_dalek::{Signature, VerifyingKey};
use tig_core::domain::REMOTE_REQUEST_SIGNATURE;
use tig_private::keys::PublicIdentity;

use crate::limits::{MAX_CONSUMED_NONCES, NONCE_TTL};

pub(crate) const NONCE_LEN: usize = 56;
pub(crate) type Nonce = [u8; NONCE_LEN];

pub(crate) fn signing_message(
    remote_id: &[u8; 16],
    method: &str,
    path: &str,
    body: &[u8],
    nonce: &Nonce,
    if_match: Option<&str>,
) -> Vec<u8> {
    let method = method.as_bytes();
    let path = path.as_bytes();
    let if_match = if_match.unwrap_or("").as_bytes();
    let mut out = Vec::with_capacity(
        REMOTE_REQUEST_SIGNATURE.len()
            + 16
            + 8
            + method.len()
            + 8
            + path.len()
            + 32
            + NONCE_LEN
            + 8
            + if_match.len(),
    );
    out.extend_from_slice(REMOTE_REQUEST_SIGNATURE.as_bytes());
    out.extend_from_slice(remote_id);
    out.extend_from_slice(&(method.len() as u64).to_le_bytes());
    out.extend_from_slice(method);
    out.extend_from_slice(&(path.len() as u64).to_le_bytes());
    out.extend_from_slice(path);
    out.extend_from_slice(blake3::hash(body).as_bytes());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&(if_match.len() as u64).to_le_bytes());
    out.extend_from_slice(if_match);
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
    let raw: [u8; 64] = parse_fixed_hex(header)?;
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

/// Issues and checks nonces. Holds no per-nonce state.
pub(crate) struct NonceKey {
    secret: [u8; 32],
    started: Instant,
}

impl NonceKey {
    pub(crate) fn generate() -> Result<Self, ()> {
        let mut secret = [0u8; 32];
        getrandom::getrandom(&mut secret).map_err(|_| ())?;
        Ok(NonceKey {
            secret,
            started: Instant::now(),
        })
    }

    pub(crate) fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    pub(crate) fn issue(&self) -> Result<Nonce, ()> {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&self.now_ms().to_le_bytes());
        getrandom::getrandom(&mut nonce[8..24]).map_err(|_| ())?;
        let mac = blake3::keyed_hash(&self.secret, &nonce[..24]);
        nonce[24..].copy_from_slice(mac.as_bytes());
        Ok(nonce)
    }

    /// Checks the MAC and the age. Returns the issue time.
    pub(crate) fn check(&self, nonce: &Nonce) -> Result<u64, ()> {
        let mut issued = [0u8; 8];
        issued.copy_from_slice(&nonce[..8]);
        let issued = u64::from_le_bytes(issued);
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&nonce[24..]);
        // `blake3::Hash` equality is constant-time.
        if blake3::keyed_hash(&self.secret, &nonce[..24]) != blake3::Hash::from(mac) {
            return Err(());
        }
        let age = self.now_ms().checked_sub(issued).ok_or(())?;
        if u128::from(age) > NONCE_TTL.as_millis() {
            return Err(());
        }
        Ok(issued)
    }
}

pub(crate) enum ConsumeError {
    Expired,
    Replayed,
    Full,
}

/// Nonces already used, kept until they would have expired anyway.
/// Ordered by issue time so expiry is a prefix.
#[derive(Default)]
pub(crate) struct ConsumedNonces {
    used: BTreeSet<(u64, Nonce)>,
}

impl ConsumedNonces {
    pub(crate) fn contains(&self, issued: u64, nonce: &Nonce) -> bool {
        self.used.contains(&(issued, *nonce))
    }

    /// `issued` comes from a nonce that already passed `NonceKey::check`.
    pub(crate) fn consume(
        &mut self,
        issued: u64,
        nonce: &Nonce,
        now_ms: u64,
    ) -> Result<(), ConsumeError> {
        let ttl = u64::try_from(NONCE_TTL.as_millis()).unwrap_or(u64::MAX);
        // Authorization may outlive the earlier MAC/age check. Reject this
        // request before expiry pruning could make an old replay look new.
        if now_ms.checked_sub(issued).is_none_or(|age| age > ttl) {
            return Err(ConsumeError::Expired);
        }
        while let Some(&(oldest, _)) = self.used.first() {
            if now_ms.saturating_sub(oldest) > ttl {
                self.used.pop_first();
            } else {
                break;
            }
        }
        if self.used.contains(&(issued, *nonce)) {
            return Err(ConsumeError::Replayed);
        }
        if self.used.len() >= MAX_CONSUMED_NONCES {
            return Err(ConsumeError::Full);
        }
        self.used.insert((issued, *nonce));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_mac_and_replay() {
        let key = NonceKey::generate().unwrap();
        let nonce = key.issue().unwrap();
        let issued = key.check(&nonce).unwrap();
        let mut forged = nonce;
        forged[9] ^= 1;
        assert!(key.check(&forged).is_err());
        let mut backdated = nonce;
        backdated[0] ^= 1;
        assert!(key.check(&backdated).is_err());
        let other = NonceKey::generate().unwrap();
        assert!(other.check(&nonce).is_err());

        let mut used = ConsumedNonces::default();
        assert!(used.consume(issued, &nonce, key.now_ms()).is_ok());
        assert!(used.contains(issued, &nonce));
        assert!(matches!(
            used.consume(issued, &nonce, key.now_ms()),
            Err(ConsumeError::Replayed)
        ));
        // Expired entries are dropped; `check` refuses them first anyway.
        let later = issued + NONCE_TTL.as_millis() as u64 + 1;
        assert!(used.consume(issued + 1, &[1; NONCE_LEN], later).is_ok());
        assert!(!used.contains(issued, &nonce));
    }

    #[test]
    fn if_match_is_signed() {
        let nonce = [5u8; NONCE_LEN];
        let a = signing_message(&[1; 16], "PUT", "/v1/head", b"x", &nonce, Some("\"aa\""));
        let b = signing_message(&[1; 16], "PUT", "/v1/head", b"x", &nonce, Some("\"bb\""));
        let c = signing_message(&[1; 16], "PUT", "/v1/head", b"x", &nonce, None);
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn issuance_is_stateless_and_consumed_set_never_evicts_live_nonces() {
        let key = NonceKey::generate().unwrap();
        let mut used = ConsumedNonces::default();
        for index in 0..MAX_CONSUMED_NONCES {
            // Issuing remains possible even after the original table's cap.
            assert!(key.issue().is_ok());
            let mut nonce = [0; NONCE_LEN];
            nonce[8..16].copy_from_slice(&(index as u64).to_le_bytes());
            assert!(used.consume(0, &nonce, 0).is_ok());
        }
        let fresh = key.issue().unwrap();
        assert!(key.check(&fresh).is_ok());
        assert!(matches!(
            used.consume(0, &fresh, 0),
            Err(ConsumeError::Full)
        ));
        assert!(used.contains(0, &[0; NONCE_LEN]));
        let expired = NONCE_TTL.as_millis() as u64 + 1;
        assert!(used.consume(expired, &fresh, expired).is_ok());
        assert_eq!(used.used.len(), 1);
    }

    #[test]
    fn valid_mac_does_not_allow_expired_or_future_nonce() {
        let mut key = NonceKey::generate().unwrap();
        let mut expired = key.issue().unwrap();
        key.started = Instant::now() - NONCE_TTL - std::time::Duration::from_secs(1);
        assert!(key.check(&expired).is_err());
        expired[..8].copy_from_slice(&u64::MAX.to_le_bytes());
        let mac = blake3::keyed_hash(&key.secret, &expired[..24]);
        expired[24..].copy_from_slice(mac.as_bytes());
        assert!(key.check(&expired).is_err());
    }

    #[test]
    fn expiry_during_authentication_cannot_reopen_replay_window() {
        let mut used = ConsumedNonces::default();
        let nonce = [1; NONCE_LEN];
        assert!(used.consume(0, &nonce, 0).is_ok());
        // Two requests can pass their stateless check before slow authorization.
        // If consumption happens after TTL, pruning must not reopen this nonce.
        assert!(used
            .consume(0, &nonce, NONCE_TTL.as_millis() as u64 + 1)
            .is_err());
    }
}
