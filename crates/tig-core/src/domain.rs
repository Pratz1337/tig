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
// `blake3::derive_key(label, epoch_key)`. Listed here so every label lives in
// one place. See DESIGN.md "Crypto and wire rules".

/// Derives per-entry seal salts.
pub const SEAL_SALT_KEY: &str = "tig seal salt key v1";
/// Encrypts objects in sealed packs (XChaCha20-Poly1305).
pub const CONTENT_KEY: &str = "tig content key v1";
/// Derives synthetic nonces from object IDs.
pub const NONCE_KEY: &str = "tig nonce key v1";
/// Keys the IDs of private objects in fetch/push negotiation.
pub const WIRE_ID_KEY: &str = "tig wire id key v1";
