//! Frozen domain-separation labels.
//!
//! Each label is baked into hashes or derived keys that end up in repos.
//! Changing one changes every ID (or key) in every existing repo, so these are
//! internal protocol constants, not branding: they stay exactly as written
//! even if the product is renamed. `object::tests::object_ids_are_frozen`
//! fails if the object-ID label drifts.
//!
//! New labels are fine; editing an existing one needs a format version bump.

/// Object IDs: `blake3::derive_key(OBJECT_ID, kind || body)`.
pub const OBJECT_ID: &str = "tig object v1";

/// Sealed entries: `blake3::keyed_hash(salt, SEALED_ENTRY || kind || id)`.
pub const SEALED_ENTRY: &str = "tig sealed entry v1";

// Subkeys that tig-private derives from a group's epoch key with
// `blake3::derive_key(label, epoch_key || remote_len_u64_le || remote || group_len_u64_le || group || epoch_u64_le)`.
// Listed here so every label lives in one place. See DESIGN.md "Crypto and wire rules".

/// Derives per-entry seal salts.
pub const SEAL_SALT_KEY: &str = "tig seal salt key v1";
/// Encrypts objects in sealed packs (XChaCha20-Poly1305).
pub const CONTENT_KEY: &str = "tig content key v1";
/// Derives synthetic nonces from object IDs.
pub const NONCE_KEY: &str = "tig nonce key v1";
/// Keys the IDs of private objects in fetch/push negotiation.
pub const WIRE_ID_KEY: &str = "tig wire id key v1";

/// Derives the key that wraps epoch keys to members.
pub const WRAP_KEY: &str = "tig wrap key v1";
/// Associated data for wrapped epoch keys.
pub const WRAP_AAD: &[u8] = b"tig wrapped epoch key v1";
/// Associated data for objects in sealed packs.
pub const OBJECT_AAD: &[u8] = b"tig sealed object v1";

/// Display fingerprint of an encryption key and signing key, in that order.
pub const IDENTITY_FINGERPRINT: &str = "tig identity fingerprint v1";
/// Commits to an epoch key and its length-prefixed group/epoch context.
pub const EPOCH_KEY_COMMITMENT: &str = "tig epoch key commitment v1";
/// Prefix of the canonical encoding signed by an epoch grant's owner.
pub const GRANT_SIGNATURE: &str = "tig epoch grant signature v1";
/// Associated data for a sealed pack's encrypted index.
pub const PACK_INDEX_AAD: &[u8] = b"tig pack index v1";
/// Prefix of the canonical encoding signed by a keyring head.
pub const KEYRING_HEAD_SIGNATURE: &str = "tig keyring head signature v1";

/// Prefix for the filesystem workspace state's BLAKE3 integrity checksum.
pub const WORKSPACE_STATE: &[u8] = b"tig workspace state v2";

/// First line of the unsynced snapshot head record (`op_head.light`).
pub const LIGHT_OP_HEAD: &str = "tig light op head v1";
