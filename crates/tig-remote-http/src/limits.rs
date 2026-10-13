//! Size and time limits. They match the directory remote where that remote has one,
//! and bound every other request so a length prefix cannot force a huge allocation.

use std::time::Duration;

/// Same cap as `DirRemote` pack files, and as the bytes of one epoch's packs.
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
/// A `get` response stops adding objects at this size, unless it is still
/// empty: one object of any allowed size always fits (see `MAX_OBJECTS_HTTP`).
pub(crate) const OBJECTS_RESPONSE_TARGET: usize = 32 * 1024 * 1024;
/// A client `put` batch is split into requests of at most this many body bytes.
pub(crate) const OBJECTS_REQUEST_TARGET: usize = 32 * 1024 * 1024;

/// Request line plus headers.
pub(crate) const MAX_HEADERS: usize = 16 * 1024;
pub(crate) const MAX_HEADER_COUNT: usize = 64;

/// Consumed nonces remembered at once. Only authorized writers add entries.
pub(crate) const MAX_CONSUMED_NONCES: usize = 65_536;
pub(crate) const NONCE_TTL: Duration = Duration::from_secs(60);

/// Whole HTTP body for an id list (`missing`, `get`).
pub(crate) const MAX_ID_HTTP: usize = 4 * 1024 * 1024;
/// Whole HTTP body for an object batch: one largest object plus its framing.
pub(crate) const MAX_OBJECTS_HTTP: usize = MAX_OBJECT_BODY + 1024;
/// Head body: both optional files plus their flags and length prefixes.
pub(crate) const MAX_HEAD_HTTP: usize =
    (MAX_KEYRING_FILE as usize) + (MAX_MANIFEST_FILE as usize) + 64;

pub(crate) const MAX_GROUP_LEN: usize = 1024;

/// Connection threads. Beyond this, new connections are closed at once.
pub(crate) const MAX_WORKERS: usize = 64;
/// Request/response working sets across all connections. A request that does
/// not fit gets `503` before its body is read; object downloads stop at the
/// answered prefix when another object cannot fit.
pub(crate) const MAX_BUFFERED_BODIES: usize = 3 * 1024 * 1024 * 1024;
/// No single read or write may stall longer than this.
pub(crate) const IO_TIMEOUT: Duration = Duration::from_secs(5);
/// TLS handshake, request line and headers must all arrive within this.
pub(crate) const HEADER_DEADLINE: Duration = Duration::from_secs(10);
/// A body or response may take this long, plus its size at `MIN_RATE`.
pub(crate) const TRANSFER_GRACE: Duration = Duration::from_secs(10);
/// Slowest sustained transfer accepted, in bytes per second.
pub(crate) const MIN_RATE: u64 = 128 * 1024;
