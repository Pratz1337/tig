//! A directory remote: dumb storage. It never decrypts.
//!
//! ```text
//! <root>/
//!   remote-id
//!   keyring           } the head, updated together (see `commit_head`)
//!   manifest          }
//!   head.pending      crash journal for one head commit
//!   head.lock         OS-locked while the head is read or committed
//!   refs              unsigned copy; only remotes that predate manifests
//!   objects/          public objects only (a DiskStore)
//!   packs/<group>/<epoch>/<pack-id>.pack
//! ```
//!
//! `pack-id` is the lowercase hex of `blake3(pack bytes)`. Group names used
//! as directories must match `[a-z0-9_-]+`, so `..` and `/` cannot escape
//! `packs/`. Writes go to a unique temp file created with `create_new`, then
//! a rename.
//!
//! A pack is renamed into place under the head lock, and only if its epoch is
//! still the group's current epoch in the keyring. A publish that lost a race
//! with a revoke cannot leave new content, under the epoch the removed member
//! holds, readable on the remote (see DESIGN.md "Collaboration", rule 4).

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tig_core::encode::Reader;
#[cfg(test)]
use tig_core::encode::Writer;
use tig_core::object::hash_object;
use tig_core::store::{DiskStore, Store};
use tig_core::{ObjectId, ObjectKind};

use crate::keyring::Keyring;
use crate::pack::Pack;

const MAX_PACK_FILE: usize = 512 * 1024 * 1024;
const MAX_KEYRING_FILE: u64 = 64 * 1024 * 1024;
const MAX_REFS_FILE: u64 = 16 * 1024 * 1024;
const MAX_MANIFEST_FILE: u64 = 256 * 1024 * 1024;
const MAX_LISTED_PACKS: usize = 100_000;
const MAX_REFS: usize = 100_000;
const MAX_BOOKMARK: usize = 1024;
const MAX_GROUP_NAME: usize = 1024;
const MAX_BATCH_OBJECTS: usize = 1000;
const MAX_BATCH_BYTES: usize = 512 * 1024 * 1024;
const REFS_VERSION: u8 = 1;
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const LOCK_NAME: &str = "head.lock";
const PENDING_NAME: &str = "head.pending";

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Pack(#[from] crate::pack::PackError),
    #[error("invalid group name {0:?}")]
    BadGroup(String),
    #[error("pack is for a different remote")]
    RemoteMismatch,
    #[error("remote is busy: {0}")]
    Busy(String),
    #[error("{0}")]
    Denied(String),
    #[error("{0}")]
    Invalid(String),
}

/// Version of a remote head (see DESIGN.md "Collaboration", rule 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HeadVersion(pub [u8; 32]);

impl HeadVersion {
    /// `derive_key(REMOTE_HEAD_VERSION, len || keyring || len || manifest)`,
    /// lengths u64 little-endian, an absent file encoded as length `u64::MAX`.
    pub fn of(keyring: Option<&[u8]>, manifest: Option<&[u8]>) -> Self {
        let mut h = blake3::Hasher::new_derive_key(tig_core::domain::REMOTE_HEAD_VERSION);
        for part in [keyring, manifest] {
            match part {
                None => {
                    h.update(&u64::MAX.to_le_bytes());
                }
                Some(bytes) => {
                    h.update(&(bytes.len() as u64).to_le_bytes());
                    h.update(bytes);
                }
            }
        }
        HeadVersion(*h.finalize().as_bytes())
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// The only mutable remote state: keyring and manifest, read together.
/// Nothing here is trusted until the caller verifies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteHead {
    pub keyring: Option<Vec<u8>>,
    pub manifest: Option<Vec<u8>>,
}

impl RemoteHead {
    pub fn version(&self) -> HeadVersion {
        HeadVersion::of(self.keyring.as_deref(), self.manifest.as_deref())
    }
}

/// Result of a conditional head write.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    Committed(HeadVersion),
    /// Someone else moved the head first. Nothing was written.
    Stale(RemoteHead),
}

/// Storage a repo publishes to and fetches from: a directory or a server.
/// It is dumb: it never decrypts and never decides trust. See DESIGN.md
/// "Collaboration".
pub trait Remote: Send + Sync {
    fn remote_id(&self) -> [u8; 16];

    /// Public objects only. Packs do not go through this store.
    fn public_store(&self) -> &dyn Store;

    /// Of `ids`, the public objects the remote does not have, in input order.
    fn missing(&self, ids: &[ObjectId]) -> Result<Vec<ObjectId>, RemoteError>;

    /// Uploads public objects in one batch. The remote checks every id.
    fn put_batch(&self, objects: &[(ObjectId, ObjectKind, Vec<u8>)]) -> Result<(), RemoteError>;

    /// Downloads public objects in one batch, verified against their ids.
    /// Missing objects are absent from the result.
    fn get_batch(&self, ids: &[ObjectId]) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, RemoteError>;

    /// Stores a pack. Writing the same bytes again is a no-op.
    fn put_pack(&self, bytes: &[u8]) -> Result<(), RemoteError>;

    /// Pack bytes for one group and epoch, ordered by pack id.
    fn list_packs(&self, group: &str, epoch: u64) -> Result<Vec<Vec<u8>>, RemoteError>;

    /// Ordered pack ids, without buffering an epoch's ciphertext.
    fn list_pack_ids(&self, group: &str, epoch: u64) -> Result<Vec<[u8; 32]>, RemoteError> {
        let mut ids: Vec<_> = self.list_packs(group, epoch)?.iter()
            .map(|bytes| *blake3::hash(bytes).as_bytes()).collect();
        ids.sort();
        if ids.len() > MAX_LISTED_PACKS || ids.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(RemoteError::Invalid("invalid pack listing".into()));
        }
        Ok(ids)
    }

    /// One immutable pack; absent packs are reported without reading others.
    fn get_pack(&self, group: &str, epoch: u64, id: &[u8; 32]) -> Result<Option<Vec<u8>>, RemoteError> {
        for bytes in self.list_packs(group, epoch)? {
            if blake3::hash(&bytes).as_bytes() == id {
                verify_pack_request(&bytes, self.remote_id(), group, epoch, id)?;
                return Ok(Some(bytes));
            }
        }
        Ok(None)
    }

    /// Known ciphertext size for reserving a server response before reading it.
    /// Backends without cheap metadata return None; servers reserve the pack cap.
    fn pack_size(&self, _group: &str, _epoch: u64, _id: &[u8; 32]) -> Result<Option<usize>, RemoteError> {
        Ok(None)
    }

    fn read_head(&self) -> Result<RemoteHead, RemoteError>;

    /// Installs the given files (None = leave that file as it is) only if the
    /// head is still at `expected`; otherwise returns `Stale` with the current
    /// head and changes nothing.
    fn commit_head(
        &self,
        expected: &HeadVersion,
        keyring: Option<&[u8]>,
        manifest: Option<&[u8]>,
    ) -> Result<CommitOutcome, RemoteError>;

    /// Unsigned refs of remotes that predate manifests. Never trusted.
    fn read_legacy_refs(&self) -> Result<Option<BTreeMap<String, ObjectId>>, RemoteError> {
        Ok(None)
    }
}

/// A local directory used as a remote.
pub struct DirRemote {
    root: PathBuf,
    remote_id: [u8; 16],
    objects: PublicObjects,
}

/// Only remote reads pay for untrusted-file limits.
struct PublicObjects(DiskStore);

impl Store for PublicObjects {
    fn get_raw(&self, id: &ObjectId) -> tig_core::Result<Option<(ObjectKind, Vec<u8>)>> {
        self.0.get_raw_limited(id)
    }
    fn put_raw(&self, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> tig_core::Result<()> {
        self.0.put_raw(id, kind, body)
    }
    fn has(&self, id: &ObjectId) -> tig_core::Result<bool> {
        self.0.has(id)
    }
}

impl DirRemote {
    /// Creates the directory layout. A second call with the same id reopens
    /// it and leaves an existing keyring and refs alone.
    pub fn create(path: impl Into<PathBuf>, remote_id: [u8; 16]) -> Result<Self, RemoteError> {
        let root = path.into();
        fs::create_dir_all(&root)?;
        fs::create_dir_all(root.join("packs"))?;
        // Part of the layout, so a refused publish does not create a new file.
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(root.join(LOCK_NAME))?;
        let id_path = root.join("remote-id");
        if id_path.try_exists()? {
            let existing = read_remote_id(&id_path)?;
            if existing != remote_id {
                return Err(RemoteError::Invalid(
                    "remote-id already exists and does not match".into(),
                ));
            }
        } else {
            atomic_write(&root, &id_path, &remote_id, true)?;
        }
        let objects = DiskStore::open(root.join("objects"))?;
        Ok(DirRemote {
            root,
            remote_id,
            objects: PublicObjects(objects),
        })
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RemoteError> {
        let root = path.into();
        let remote_id = read_remote_id(&root.join("remote-id"))?;
        let objects = DiskStore::open_existing(root.join("objects"));
        Ok(DirRemote {
            root,
            remote_id,
            objects: PublicObjects(objects),
        })
    }

    pub fn remote_id(&self) -> [u8; 16] {
        self.remote_id
    }

    /// Public objects only. Packs do not go through this store.
    pub fn public_store(&self) -> &dyn Store {
        &self.objects
    }

    /// Stores a pack under `packs/<group>/<epoch>/<blake3>.pack`.
    /// Writing the same bytes again is a no-op. A pack for an epoch older
    /// than the keyring's current epoch for its group is refused.
    pub fn put_pack(&self, bytes: &[u8]) -> Result<(), RemoteError> {
        if bytes.len() > MAX_PACK_FILE {
            return Err(RemoteError::Invalid("pack is too large".into()));
        }
        let header = Pack::peek_header(bytes)?;
        check_group(&header.group)?;
        if header.remote != self.remote_id {
            return Err(RemoteError::RemoteMismatch);
        }
        let digest = blake3::hash(bytes);
        let name = format!("{}.pack", hex::encode(digest.as_bytes()));
        let dir = self
            .root
            .join("packs")
            .join(&header.group)
            .join(header.epoch.to_string());
        let dest = dir.join(name);
        if dest.try_exists()? {
            let existing = read_limited(&dest, MAX_PACK_FILE as u64)?;
            if existing == bytes {
                return Ok(());
            }
            return Err(RemoteError::Invalid(
                "pack path exists with different bytes".into(),
            ));
        }
        // Write and sync outside the lock; only the rename waits for it.
        let tmp = write_temp(&self.root, bytes)?;
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)?;
        }
        self.with_lock(|guard| {
            let head = guard.roll_forward_and_read()?;
            check_pack_epoch(head.keyring.as_deref(), &header.group, header.epoch)?;
            publish(&tmp.0, &dest, bytes, false)
        })
    }

    /// Pack bytes for one group and epoch, ordered by pack id. An unknown
    /// group or epoch that has no directory is an empty list.
    pub fn list_packs(&self, group: &str, epoch: u64) -> Result<Vec<Vec<u8>>, RemoteError> {
        check_group(group)?;
        let dir = self.root.join("packs").join(group).join(epoch.to_string());
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut paths = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !name.ends_with(".pack") {
                continue;
            }
            paths.push(entry.path());
            if paths.len() > MAX_LISTED_PACKS {
                return Err(RemoteError::Invalid("too many packs".into()));
            }
        }
        paths.sort();
        let mut out = Vec::with_capacity(paths.len());
        let mut remaining = MAX_PACK_FILE as u64;
        for path in paths {
            let meta = fs::metadata(&path)?;
            if !meta.is_file() {
                continue;
            }
            let bytes = read_limited(&path, remaining)?;
            remaining -= bytes.len() as u64;
            out.push(bytes);
        }
        Ok(out)
    }

    pub fn list_pack_ids(&self, group: &str, epoch: u64) -> Result<Vec<[u8; 32]>, RemoteError> {
        check_group(group)?;
        let dir = self.root.join("packs").join(group).join(epoch.to_string());
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error.into()),
        };
        let mut ids = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str().and_then(|name| name.strip_suffix(".pack")) else {
                continue;
            };
            if !entry.file_type()?.is_file() {
                continue;
            }
            let id = name
                .parse::<ObjectId>()
                .map_err(|_| RemoteError::Invalid("invalid stored pack id".into()))?;
            if id.to_hex() != name {
                return Err(RemoteError::Invalid("noncanonical stored pack id".into()));
            }
            ids.push(id.0);
            if ids.len() > MAX_LISTED_PACKS {
                return Err(RemoteError::Invalid("too many packs".into()));
            }
        }
        ids.sort();
        Ok(ids)
    }

    pub fn get_pack(&self, group: &str, epoch: u64, id: &[u8; 32]) -> Result<Option<Vec<u8>>, RemoteError> {
        check_group(group)?;
        let path = self.root.join("packs").join(group).join(epoch.to_string())
            .join(format!("{}.pack", hex::encode(id)));
        let meta = match fs::metadata(&path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !meta.is_file() || meta.len() > crate::pack::PACK_BATCH_MAX as u64 {
            return Err(RemoteError::Invalid("pack is too large or not a file".into()));
        }
        let bytes = read_limited(&path, meta.len())?;
        verify_pack_request(&bytes, self.remote_id, group, epoch, id)?;
        Ok(Some(bytes))
    }

    pub fn pack_size(&self, group: &str, epoch: u64, id: &[u8; 32]) -> Result<Option<usize>, RemoteError> {
        check_group(group)?;
        let path = self.root.join("packs").join(group).join(epoch.to_string())
            .join(format!("{}.pack", hex::encode(id)));
        match fs::metadata(path) {
            Ok(meta) if meta.is_file() && meta.len() <= MAX_PACK_FILE as u64 => Ok(Some(meta.len() as usize)),
            Ok(_) => Err(RemoteError::Invalid("pack is too large or not a file".into())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Some(0)),
            Err(error) => Err(error.into()),
        }
    }

    pub fn read_keyring(&self) -> Result<Vec<u8>, RemoteError> {
        match self.read_head()?.keyring {
            Some(bytes) => Ok(bytes),
            None => Err(RemoteError::Invalid("keyring is missing".into())),
        }
    }

    /// Unsigned refs file from remotes that predate manifests. Missing is an
    /// error here; [`Remote::read_legacy_refs`] returns `None` instead.
    pub fn read_refs(&self) -> Result<BTreeMap<String, ObjectId>, RemoteError> {
        self.read_legacy_refs()?
            .ok_or_else(|| RemoteError::Invalid("refs are missing".into()))
    }

    /// The signed publish manifest, or `None` before the first publish.
    pub fn read_manifest(&self) -> Result<Option<Vec<u8>>, RemoteError> {
        Ok(self.read_head()?.manifest)
    }

    pub fn read_head(&self) -> Result<RemoteHead, RemoteError> {
        self.with_lock(|guard| guard.roll_forward_and_read())
    }

    pub fn commit_head(
        &self,
        expected: &HeadVersion,
        keyring: Option<&[u8]>,
        manifest: Option<&[u8]>,
    ) -> Result<CommitOutcome, RemoteError> {
        if keyring.is_some_and(|bytes| bytes.len() as u64 > MAX_KEYRING_FILE) {
            return Err(RemoteError::Invalid("keyring is too large".into()));
        }
        if manifest.is_some_and(|bytes| bytes.len() as u64 > MAX_MANIFEST_FILE) {
            return Err(RemoteError::Invalid("manifest is too large".into()));
        }
        self.with_lock(|guard| {
            let current = guard.roll_forward_and_read()?;
            if &current.version() != expected {
                return Ok(CommitOutcome::Stale(current));
            }
            let new_keyring = match keyring {
                Some(bytes) => Some(bytes.to_vec()),
                None => current.keyring,
            };
            let new_manifest = match manifest {
                Some(bytes) => Some(bytes.to_vec()),
                None => current.manifest,
            };
            let pending = encode_pending(new_keyring.as_deref(), new_manifest.as_deref())?;
            atomic_write(guard.root, &guard.root.join(PENDING_NAME), &pending, true)?;
            install_part(guard.root, &guard.root.join("keyring"), new_keyring.as_deref())?;
            install_part(
                guard.root,
                &guard.root.join("manifest"),
                new_manifest.as_deref(),
            )?;
            match fs::remove_file(guard.root.join(PENDING_NAME)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            Ok(CommitOutcome::Committed(HeadVersion::of(
                new_keyring.as_deref(),
                new_manifest.as_deref(),
            )))
        })
    }

    pub fn missing(&self, ids: &[ObjectId]) -> Result<Vec<ObjectId>, RemoteError> {
        check_batch_count(ids.len())?;
        let mut out = Vec::new();
        for id in ids {
            if !self.objects.has(id)? {
                out.push(*id);
            }
        }
        Ok(out)
    }

    pub fn put_batch(
        &self,
        objects: &[(ObjectId, ObjectKind, Vec<u8>)],
    ) -> Result<(), RemoteError> {
        check_batch_count(objects.len())?;
        let mut bytes = 0usize;
        for (_, _, body) in objects {
            bytes = batch_bytes(bytes, body.len())?;
        }
        for (id, kind, body) in objects {
            if hash_object(*kind, body) != *id {
                return Err(RemoteError::Invalid(
                    "public object does not match its id".into(),
                ));
            }
            self.objects.put_raw(id, *kind, body)?;
        }
        Ok(())
    }

    pub fn get_batch(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, RemoteError> {
        check_batch_count(ids.len())?;
        let mut out = Vec::new();
        let mut bytes = 0usize;
        for id in ids {
            let Some((kind, body)) = self.objects.get_raw(id)? else {
                continue;
            };
            bytes = batch_bytes(bytes, body.len())?;
            if hash_object(kind, &body) != *id {
                return Err(RemoteError::Invalid(
                    "public object does not match its id".into(),
                ));
            }
            out.push((*id, kind, body));
        }
        Ok(out)
    }

    pub fn read_legacy_refs(&self) -> Result<Option<BTreeMap<String, ObjectId>>, RemoteError> {
        let path = self.root.join("refs");
        let bytes = match read_limited(&path, MAX_REFS_FILE) {
            Ok(bytes) => bytes,
            Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(error) => return Err(error),
        };
        Ok(Some(decode_refs(&bytes)?))
    }

    /// Runs `body` holding an OS lock on `head.lock`. The OS releases it when
    /// the process dies, so a crashed publisher or a killed server never
    /// leaves the remote locked. The file is never deleted: a waiter may
    /// already hold it open.
    fn with_lock<T>(
        &self,
        body: impl FnOnce(&HeadLock<'_>) -> Result<T, RemoteError>,
    ) -> Result<T, RemoteError> {
        let lock = self.root.join(LOCK_NAME);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock)?;
        let start = Instant::now();
        let guard = loop {
            match file.try_lock() {
                Ok(()) => break LockGuard(file),
                Err(fs::TryLockError::WouldBlock) => {
                    if start.elapsed() > LOCK_TIMEOUT {
                        return Err(RemoteError::Invalid(format!(
                            "timed out waiting for {}; another tig process is using this remote",
                            lock.display()
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(fs::TryLockError::Error(error)) => return Err(error.into()),
            }
        };
        body(&HeadLock {
            root: &self.root,
            _lock: &guard,
        })
    }
}

struct LockGuard(fs::File);

fn check_batch_count(count: usize) -> Result<(), RemoteError> {
    if count > MAX_BATCH_OBJECTS {
        return Err(RemoteError::Invalid("too many objects in a batch".into()));
    }
    Ok(())
}

fn batch_bytes(used: usize, amount: usize) -> Result<usize, RemoteError> {
    used.checked_add(amount)
        .filter(|bytes| *bytes <= MAX_BATCH_BYTES)
        .ok_or_else(|| RemoteError::Invalid("object batch is too large".into()))
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}

/// A pack may only be added under its group's current epoch. Without a
/// keyring (the first publish) any epoch is accepted. The keyring is not
/// verified here; it only orders this upload against a revoke.
fn check_pack_epoch(keyring: Option<&[u8]>, group: &str, epoch: u64) -> Result<(), RemoteError> {
    let Some(bytes) = keyring else {
        return Ok(());
    };
    let keyring = Keyring::decode(bytes)
        .map_err(|error| RemoteError::Invalid(format!("keyring is invalid: {error}")))?;
    match keyring.head.epochs.get(group) {
        Some(current) if *current == epoch => Ok(()),
        Some(current) => Err(RemoteError::Invalid(format!(
            "pack is for epoch {epoch} of {group}, but the remote is at epoch {current}; publish again"
        ))),
        // Stage a new group's ciphertext before its policy and manifest
        // become visible together. Existing groups still require their
        // current epoch, so revoked epochs remain refused.
        None if epoch == 1 => Ok(()),
        None => Err(RemoteError::Invalid(format!(
            "the remote keyring has no group {group}"
        ))),
    }
}

struct HeadLock<'a> {
    root: &'a Path,
    _lock: &'a LockGuard,
}

impl HeadLock<'_> {
    fn roll_forward_and_read(&self) -> Result<RemoteHead, RemoteError> {
        match read_pending(&self.root.join(PENDING_NAME))? {
            Pending::Absent => {}
            Pending::Torn => {
                remove_pending(&self.root.join(PENDING_NAME))?;
            }
            Pending::Valid { keyring, manifest } => {
                install_part(self.root, &self.root.join("keyring"), keyring.as_deref())?;
                install_part(self.root, &self.root.join("manifest"), manifest.as_deref())?;
                remove_pending(&self.root.join(PENDING_NAME))?;
            }
        }
        Ok(RemoteHead {
            keyring: read_optional(&self.root.join("keyring"), MAX_KEYRING_FILE)?,
            manifest: read_optional(&self.root.join("manifest"), MAX_MANIFEST_FILE)?,
        })
    }
}

enum Pending {
    Absent,
    Torn,
    Valid {
        keyring: Option<Vec<u8>>,
        manifest: Option<Vec<u8>>,
    },
}

fn remove_pending(path: &Path) -> Result<(), RemoteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn install_part(root: &Path, dest: &Path, bytes: Option<&[u8]>) -> Result<(), RemoteError> {
    match bytes {
        Some(bytes) => atomic_write(root, dest, bytes, true),
        None => match fs::remove_file(dest) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        },
    }
}

/// `head.pending`: for keyring then manifest, a u64-le length (`u64::MAX`
/// means that file is absent) and the bytes, then a 32-byte BLAKE3 of
/// everything before the checksum. A short or mismatched record is torn.
fn encode_pending(keyring: Option<&[u8]>, manifest: Option<&[u8]>) -> Result<Vec<u8>, RemoteError> {
    let mut body = Vec::new();
    write_part(&mut body, keyring)?;
    write_part(&mut body, manifest)?;
    let sum = blake3::hash(&body);
    body.extend_from_slice(sum.as_bytes());
    Ok(body)
}

fn write_part(out: &mut Vec<u8>, bytes: Option<&[u8]>) -> Result<(), RemoteError> {
    match bytes {
        None => out.extend_from_slice(&u64::MAX.to_le_bytes()),
        Some(bytes) => {
            let len = u64::try_from(bytes.len())
                .map_err(|_| RemoteError::Invalid("pending record is too large".into()))?;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(bytes);
        }
    }
    Ok(())
}

fn read_pending(path: &Path) -> Result<Pending, RemoteError> {
    let bytes = match read_limited(path, MAX_KEYRING_FILE + MAX_MANIFEST_FILE + 64) {
        Ok(bytes) => bytes,
        Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(Pending::Absent)
        }
        Err(RemoteError::Invalid(_)) => return Ok(Pending::Torn),
        Err(error) => return Err(error),
    };
    Ok(decode_pending(&bytes).unwrap_or(Pending::Torn))
}

fn decode_pending(bytes: &[u8]) -> Option<Pending> {
    if bytes.len() < 32 {
        return None;
    }
    let (body, sum) = bytes.split_at(bytes.len() - 32);
    if blake3::hash(body).as_bytes() != sum {
        return None;
    }
    let mut rest = body;
    let keyring = take_part(&mut rest, MAX_KEYRING_FILE)?;
    let manifest = take_part(&mut rest, MAX_MANIFEST_FILE)?;
    if !rest.is_empty() {
        return None;
    }
    Some(Pending::Valid { keyring, manifest })
}

fn take_part(input: &mut &[u8], max: u64) -> Option<Option<Vec<u8>>> {
    if input.len() < 8 {
        return None;
    }
    let mut len_bytes = [0u8; 8];
    len_bytes.copy_from_slice(&input[..8]);
    *input = &input[8..];
    let len = u64::from_le_bytes(len_bytes);
    if len == u64::MAX {
        return Some(None);
    }
    if len > max || input.len() < len as usize {
        return None;
    }
    let (head, tail) = input.split_at(len as usize);
    *input = tail;
    Some(Some(head.to_vec()))
}

fn read_optional(path: &Path, max: u64) -> Result<Option<Vec<u8>>, RemoteError> {
    match read_limited(path, max) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

impl Remote for DirRemote {
    fn remote_id(&self) -> [u8; 16] {
        DirRemote::remote_id(self)
    }

    fn public_store(&self) -> &dyn Store {
        DirRemote::public_store(self)
    }

    fn missing(&self, ids: &[ObjectId]) -> Result<Vec<ObjectId>, RemoteError> {
        DirRemote::missing(self, ids)
    }

    fn put_batch(&self, objects: &[(ObjectId, ObjectKind, Vec<u8>)]) -> Result<(), RemoteError> {
        DirRemote::put_batch(self, objects)
    }

    fn get_batch(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, RemoteError> {
        DirRemote::get_batch(self, ids)
    }

    fn put_pack(&self, bytes: &[u8]) -> Result<(), RemoteError> {
        DirRemote::put_pack(self, bytes)
    }

    fn list_packs(&self, group: &str, epoch: u64) -> Result<Vec<Vec<u8>>, RemoteError> {
        DirRemote::list_packs(self, group, epoch)
    }

    fn list_pack_ids(&self, group: &str, epoch: u64) -> Result<Vec<[u8; 32]>, RemoteError> {
        DirRemote::list_pack_ids(self, group, epoch)
    }

    fn get_pack(&self, group: &str, epoch: u64, id: &[u8; 32]) -> Result<Option<Vec<u8>>, RemoteError> {
        DirRemote::get_pack(self, group, epoch, id)
    }

    fn pack_size(&self, group: &str, epoch: u64, id: &[u8; 32]) -> Result<Option<usize>, RemoteError> {
        DirRemote::pack_size(self, group, epoch, id)
    }

    fn read_head(&self) -> Result<RemoteHead, RemoteError> {
        DirRemote::read_head(self)
    }

    fn commit_head(
        &self,
        expected: &HeadVersion,
        keyring: Option<&[u8]>,
        manifest: Option<&[u8]>,
    ) -> Result<CommitOutcome, RemoteError> {
        DirRemote::commit_head(self, expected, keyring, manifest)
    }

    fn read_legacy_refs(&self) -> Result<Option<BTreeMap<String, ObjectId>>, RemoteError> {
        DirRemote::read_legacy_refs(self)
    }
}

fn verify_pack_request(bytes: &[u8], remote: [u8; 16], group: &str, epoch: u64, id: &[u8; 32]) -> Result<(), RemoteError> {
    if blake3::hash(bytes).as_bytes() != id {
        return Err(RemoteError::Invalid("pack bytes do not match the pack id".into()));
    }
    let header = Pack::peek_header(bytes)?;
    if header.remote != remote || header.group != group || header.epoch != epoch {
        return Err(RemoteError::Invalid("pack context does not match the request".into()));
    }
    Ok(())
}

fn check_group(group: &str) -> Result<(), RemoteError> {
    let ok = !group.is_empty()
        && group.len() <= MAX_GROUP_NAME
        && group
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-' | b'+'))
        && group.split('+').all(|part| !part.is_empty())
        && group.split('+').zip(group.split('+').skip(1)).all(|(a, b)| a < b);
    if ok {
        Ok(())
    } else {
        Err(RemoteError::BadGroup(group.to_string()))
    }
}

fn read_remote_id(path: &Path) -> Result<[u8; 16], RemoteError> {
    let bytes = match read_limited(path, 16) {
        Ok(bytes) => bytes,
        Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Err(RemoteError::Invalid("remote-id is missing".into()));
        }
        Err(error) => return Err(error),
    };
    if bytes.len() != 16 {
        return Err(RemoteError::Invalid(
            "remote-id must be exactly 16 bytes".into(),
        ));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes);
    Ok(id)
}

fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>, RemoteError> {
    let file = fs::File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(RemoteError::Invalid("expected a file".into()));
    }
    if meta.len() > max {
        return Err(RemoteError::Invalid("file is too large".into()));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(RemoteError::Invalid("file is too large".into()));
    }
    Ok(bytes)
}

#[cfg(test)]
fn encode_refs(refs: &BTreeMap<String, ObjectId>) -> Result<Vec<u8>, RemoteError> {
    if refs.len() > MAX_REFS {
        return Err(RemoteError::Invalid("too many refs".into()));
    }
    for name in refs.keys() {
        if name.is_empty() || name.len() > MAX_BOOKMARK {
            return Err(RemoteError::Invalid("invalid bookmark".into()));
        }
    }
    let mut w = Writer::new();
    w.u8(REFS_VERSION);
    w.varint(refs.len() as u64);
    for (name, id) in refs {
        w.str(name);
        w.id(id);
    }
    Ok(w.finish())
}

fn decode_refs(bytes: &[u8]) -> Result<BTreeMap<String, ObjectId>, RemoteError> {
    let mut r = Reader::new(bytes, "refs");
    let version = r.u8()?;
    if version != REFS_VERSION {
        return Err(RemoteError::Invalid(format!(
            "unsupported refs version {version}"
        )));
    }
    let n = r.count(1 + 32)?;
    if n > MAX_REFS {
        return Err(RemoteError::Invalid("too many refs".into()));
    }
    let mut refs = BTreeMap::new();
    let mut previous: Option<String> = None;
    for _ in 0..n {
        let name = r.str()?;
        if name.is_empty() || name.len() > MAX_BOOKMARK {
            return Err(RemoteError::Invalid("invalid bookmark".into()));
        }
        if previous.as_ref().is_some_and(|prev| name <= prev.as_str()) {
            return Err(RemoteError::Invalid(
                "refs are not in canonical order".into(),
            ));
        }
        let name = name.to_string();
        let id = r.id()?;
        previous = Some(name.clone());
        refs.insert(name, id);
    }
    r.finish()?;
    Ok(refs)
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn atomic_write(root: &Path, dest: &Path, bytes: &[u8], replace: bool) -> Result<(), RemoteError> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = write_temp(root, bytes)?;
    publish(&tmp.0, dest, bytes, replace)
}

/// A synced temp file under `tmp/`, removed on drop unless renamed away.
fn write_temp(root: &Path, bytes: &[u8]) -> Result<RemoveOnDrop, RemoteError> {
    let tmp_dir = root.join("tmp");
    fs::create_dir_all(&tmp_dir)?;
    let mut rnd = [0u8; 16];
    for _ in 0..8 {
        getrandom::getrandom(&mut rnd)
            .map_err(|error| RemoteError::Invalid(format!("no randomness: {error}")))?;
        let path = tmp_dir.join(hex::encode(rnd));
        let file = match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        };
        // Declared before `file` is rebound so the handle closes before the
        // temp file is removed. Windows will not delete a file that is open.
        let tmp = RemoveOnDrop(path);
        let mut file = file;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        return Ok(tmp);
    }
    Err(RemoteError::Invalid("could not create a temp file".into()))
}

fn publish(tmp: &Path, dest: &Path, bytes: &[u8], replace: bool) -> Result<(), RemoteError> {
    if !replace && dest.try_exists()? {
        return same_bytes(dest, bytes);
    }
    let mut wait = Duration::from_millis(1);
    let mut last = None;
    for _ in 0..5 {
        if !replace && dest.try_exists()? {
            return same_bytes(dest, bytes);
        }
        match fs::rename(tmp, dest) {
            Ok(()) => return Ok(()),
            Err(error) => {
                if !replace && dest.try_exists()? {
                    return same_bytes(dest, bytes);
                }
                last = Some(error);
                std::thread::sleep(wait);
                wait = (wait * 2).min(Duration::from_millis(16));
            }
        }
    }
    match last {
        Some(error) => Err(error.into()),
        None => Err(RemoteError::Invalid("rename failed".into())),
    }
}

fn same_bytes(dest: &Path, bytes: &[u8]) -> Result<(), RemoteError> {
    let existing = read_limited(dest, MAX_PACK_FILE as u64)?;
    if existing == bytes {
        Ok(())
    } else {
        Err(RemoteError::Invalid(
            "destination exists with different bytes".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listed_packs_have_an_aggregate_byte_limit() {
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::create(dir.path(), [3; 16]).unwrap();
        let packs = dir.path().join("packs/private/1");
        fs::create_dir_all(&packs).unwrap();
        for name in ["a.pack", "b.pack"] {
            let file = fs::File::create(packs.join(name)).unwrap();
            file.set_len((MAX_PACK_FILE / 2 + 1) as u64).unwrap();
        }
        assert!(remote.list_packs("private", 1).is_err());
    }

    #[test]
    fn oversized_public_objects_are_refused_before_decoding() {
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::create(dir.path(), [4; 16]).unwrap();
        let shard = dir.path().join("objects/01");
        fs::create_dir_all(&shard).unwrap();
        let file = fs::File::create(shard.join("01".repeat(31))).unwrap();
        file.set_len(256 * 1024 * 1024 + 1025).unwrap();
        drop(file);
        let error = remote
            .public_store()
            .get_raw(&ObjectId([1; 32]))
            .unwrap_err();
        assert!(error.to_string().contains("file is too large"), "{error}");
    }

    #[test]
    fn opening_a_remote_does_not_create_directories() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("remote-id"), [1; 16]).unwrap();
        let _remote = DirRemote::open(dir.path()).unwrap();
        assert!(
            !dir.path().join("objects").exists(),
            "fetch must not write to its source"
        );
    }

    #[test]
    fn failed_atomic_replace_preserves_the_destination() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("keyring");
        fs::write(&dest, b"old").unwrap();
        fs::write(dir.path().join("keyring.bak"), b"recovery copy").unwrap();
        // An absent temporary file must not move or delete recovery data.
        assert!(publish(&dir.path().join("missing"), &dest, b"new", true).is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"old");
        assert_eq!(
            fs::read(dir.path().join("keyring.bak")).unwrap(),
            b"recovery copy"
        );
    }

    #[test]
    fn refs_reject_unsorted_trailing_and_noncanonical_bytes() {
        assert!(decode_refs(&[REFS_VERSION, 0x80, 0x00]).is_err());
        let mut refs = BTreeMap::new();
        refs.insert("a".into(), ObjectId([1; 32]));
        refs.insert("b".into(), ObjectId([2; 32]));
        let mut bytes = encode_refs(&refs).unwrap();
        assert_eq!(decode_refs(&bytes).unwrap(), refs);
        bytes.push(0);
        assert!(decode_refs(&bytes).is_err());

        // "b" then "a": not the canonical order.
        let mut unsorted = Writer::new();
        unsorted.u8(REFS_VERSION);
        unsorted.varint(2);
        unsorted.str("b");
        unsorted.id(&ObjectId([2; 32]));
        unsorted.str("a");
        unsorted.id(&ObjectId([1; 32]));
        assert!(matches!(
            decode_refs(&unsorted.finish()),
            Err(RemoteError::Invalid(ref reason)) if reason.contains("canonical")
        ));
    }
}
