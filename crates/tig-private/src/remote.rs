//! A directory remote: dumb storage. It never decrypts.
//!
//! ```text
//! <root>/
//!   remote-id
//!   keyring
//!   refs
//!   objects/          public objects only (a DiskStore)
//!   packs/<group>/<epoch>/<pack-id>.pack
//! ```
//!
//! `pack-id` is the lowercase hex of `blake3(pack bytes)`. Group names used
//! as directories must match `[a-z0-9_-]+`, so `..` and `/` cannot escape
//! `packs/`. Writes go to a unique temp file created with `create_new`, then
//! a rename.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use tig_core::encode::{Reader, Writer};
use tig_core::store::DiskStore;
use tig_core::ObjectId;

use crate::pack::Pack;

const MAX_PACK_FILE: usize = 512 * 1024 * 1024;
const MAX_KEYRING_FILE: u64 = 64 * 1024 * 1024;
const MAX_REFS_FILE: u64 = 16 * 1024 * 1024;
const MAX_LISTED_PACKS: usize = 100_000;
const MAX_REFS: usize = 100_000;
const MAX_BOOKMARK: usize = 1024;
const REFS_VERSION: u8 = 1;

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
    #[error("{0}")]
    Invalid(String),
}

/// A local directory used as a remote.
pub struct DirRemote {
    root: PathBuf,
    remote_id: [u8; 16],
    objects: DiskStore,
}

impl DirRemote {
    /// Creates the directory layout. A second call with the same id reopens
    /// it and leaves an existing keyring and refs alone.
    pub fn create(path: impl Into<PathBuf>, remote_id: [u8; 16]) -> Result<Self, RemoteError> {
        let root = path.into();
        fs::create_dir_all(&root)?;
        fs::create_dir_all(root.join("packs"))?;
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
        let refs = root.join("refs");
        if !refs.try_exists()? {
            atomic_write(&root, &refs, &encode_refs(&BTreeMap::new())?, true)?;
        }
        let objects = DiskStore::open(root.join("objects"))?;
        Ok(DirRemote {
            root,
            remote_id,
            objects,
        })
    }

    pub fn open(path: impl Into<PathBuf>) -> Result<Self, RemoteError> {
        let root = path.into();
        let remote_id = read_remote_id(&root.join("remote-id"))?;
        let objects = DiskStore::open(root.join("objects"))?;
        Ok(DirRemote {
            root,
            remote_id,
            objects,
        })
    }

    pub fn remote_id(&self) -> [u8; 16] {
        self.remote_id
    }

    /// Public objects only. Packs do not go through this store.
    pub fn public_store(&self) -> &DiskStore {
        &self.objects
    }

    /// Stores a pack under `packs/<group>/<epoch>/<blake3>.pack`.
    /// Writing the same bytes again is a no-op.
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
        atomic_write(&self.root, &dest, bytes, false)
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
        for path in paths {
            let meta = fs::metadata(&path)?;
            if !meta.is_file() {
                continue;
            }
            out.push(read_limited(&path, MAX_PACK_FILE as u64)?);
        }
        Ok(out)
    }

    pub fn read_keyring(&self) -> Result<Vec<u8>, RemoteError> {
        let path = self.root.join("keyring");
        match read_limited(&path, MAX_KEYRING_FILE) {
            Ok(bytes) => Ok(bytes),
            Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                Err(RemoteError::Invalid("keyring is missing".into()))
            }
            Err(error) => Err(error),
        }
    }

    pub fn write_keyring(&self, bytes: &[u8]) -> Result<(), RemoteError> {
        if bytes.len() as u64 > MAX_KEYRING_FILE {
            return Err(RemoteError::Invalid("keyring is too large".into()));
        }
        atomic_write(&self.root, &self.root.join("keyring"), bytes, true)
    }

    pub fn read_refs(&self) -> Result<BTreeMap<String, ObjectId>, RemoteError> {
        let path = self.root.join("refs");
        let bytes = match read_limited(&path, MAX_REFS_FILE) {
            Ok(bytes) => bytes,
            Err(RemoteError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Err(RemoteError::Invalid("refs are missing".into()));
            }
            Err(error) => return Err(error),
        };
        decode_refs(&bytes)
    }

    pub fn write_refs(&self, refs: &BTreeMap<String, ObjectId>) -> Result<(), RemoteError> {
        let bytes = encode_refs(refs)?;
        atomic_write(&self.root, &self.root.join("refs"), &bytes, true)
    }
}

fn check_group(group: &str) -> Result<(), RemoteError> {
    let ok = !group.is_empty()
        && group
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(RemoteError::BadGroup(group.to_string()))
    }
}

fn read_remote_id(path: &Path) -> Result<[u8; 16], RemoteError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(RemoteError::Invalid("remote-id is missing".into()));
        }
        Err(error) => return Err(error.into()),
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
    let meta = fs::metadata(path)?;
    if !meta.is_file() {
        return Err(RemoteError::Invalid("expected a file".into()));
    }
    if meta.len() > max {
        return Err(RemoteError::Invalid("file is too large".into()));
    }
    Ok(fs::read(path)?)
}

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
    let tmp_dir = root.join("tmp");
    fs::create_dir_all(&tmp_dir)?;
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
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
        publish(&tmp.0, dest, bytes, replace)?;
        return Ok(());
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
    if replace && dest.try_exists()? {
        return replace_via_backup(tmp, dest);
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

fn replace_via_backup(tmp: &Path, dest: &Path) -> Result<(), RemoteError> {
    let bak_name = format!(
        "{}.bak",
        dest.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("file")
    );
    let bak = dest.with_file_name(bak_name);
    let _ = fs::remove_file(&bak);
    fs::rename(dest, &bak)?;
    match fs::rename(tmp, dest) {
        Ok(()) => {
            let _ = fs::remove_file(&bak);
            Ok(())
        }
        Err(error) => {
            let _ = fs::rename(&bak, dest);
            Err(error.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
