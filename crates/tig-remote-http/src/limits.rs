//! Size limits. They match the directory remote where that remote has one,
//! and bound every other request so a length prefix cannot force a huge allocation.

/// Same cap as `DirRemote` pack files.
pub(crate) const MAX_PACK_FILE: usize = 512 * 1024 * 1024;
/// Same cap as `DirRemote` keyring files.
pub(crate) const MAX_KEYRING_FILE: u64 = 64 * 1024 * 1024;
/// Same cap as `DirRemote` manifest files.
pub(crate) const MAX_MANIFEST_FILE: u64 = 256 * 1024 * 1024;
/// Same cap as `DirRemote` pack listings.
pub(crate) const MAX_LISTED_PACKS: usize = 100_000;

/// Objects named in one `missing` or `get` call.
pub(crate) const MAX_ID_BATCH: usize = 100_000;
/// Objects in one `put` or `get` body.
pub(crate) const MAX_OBJECT_BATCH: usize = 4_096;
/// One public object body. Matches the loose-object decompress ceiling.
pub(crate) const MAX_OBJECT_BODY: usize = 256 * 1024 * 1024;

pub(crate) const MAX_HEADERS: usize = 16 * 1024;
pub(crate) const MAX_NONCES: usize = 4_096;
pub(crate) const NONCE_TTL_SECS: u64 = 60;

/// Whole HTTP body for an id list (`missing`, `get`).
pub(crate) const MAX_ID_HTTP: usize = 4 * 1024 * 1024;
/// Whole HTTP body for an object batch. One object may fill it.
pub(crate) const MAX_OBJECTS_HTTP: usize = MAX_OBJECT_BODY;
/// Head body: both optional files plus their flags and length prefixes.
pub(crate) const MAX_HEAD_HTTP: usize =
    (MAX_KEYRING_FILE as usize) + (MAX_MANIFEST_FILE as usize) + 64;

pub(crate) const MAX_GROUP_LEN: usize = 1024;
