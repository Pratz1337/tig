//! Loose-object store.
//!
//! Files live at `<root>/<first two hex digits>/<the other 62 hex digits>`.
//! Each file is the magic `TIG1`, a kind byte, an encoding flag, and the
//! payload. Flag 0 is the raw body. Flag 1 is lz4 block data with the
//! uncompressed length prepended (`lz4_flex::block::compress_prepend_size`),
//! and only when the body is at least 64 bytes and the compressed payload is
//! actually smaller.
//!
//! A write goes to a random file under `<root>/tmp` and is renamed into
//! place, so readers never see a half-written object.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::{hash_object, ObjectKind};
use crate::store::Store;

const MAGIC: [u8; 4] = *b"TIG1";
const FLAG_RAW: u8 = 0;
const FLAG_LZ4: u8 = 1;
const HEADER_LEN: usize = 6;
/// Bodies shorter than this are stored raw. lz4 cannot help them.
const MIN_COMPRESS_LEN: usize = 64;
/// Hard cap on a claimed uncompressed size. The length prefix is part of
/// the file, so a corrupt object must not be able to force an unbounded
/// allocation.
const MAX_OBJECT_BYTES: usize = 256 * 1024 * 1024;
/// Claimed size may not exceed `compressed_len * MAX_EXPAND`. Real lz4
/// output stays far under this; the check rejects a tiny payload that
/// claims to expand to `MAX_OBJECT_BYTES`.
const MAX_EXPAND: usize = 1024;

/// Filesystem backend. Safe to share across threads: each object is one
/// file, and the rename either publishes it or loses to a file that is
/// already there.
pub struct DiskStore {
    root: PathBuf,
}

impl DiskStore {
    /// Refers to an existing layout without creating anything. Remote reads
    /// must not create `tmp` through an attacker-controlled directory link.
    pub fn open_existing(root: impl Into<PathBuf>) -> Self {
        DiskStore { root: root.into() }
    }

    /// Opens a store at `root`, creating `root` and `root/tmp` when missing.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("tmp"))?;
        Ok(DiskStore { root })
    }

    /// Directory this store reads and writes.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Bounded read for untrusted remote storage. Local hot-path reads retain
    /// their existing behavior; this cap also bounds a concurrently growing file.
    pub fn get_raw_limited(&self, id: &ObjectId) -> Result<Option<(ObjectKind, Vec<u8>)>> {
        const MAX_FILE: u64 = MAX_OBJECT_BYTES as u64 + 1024;
        let file = match File::open(self.object_path(id)) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_FILE {
            return Err(corrupt(*id, "file is too large or is not a regular file"));
        }
        let mut data = Vec::new();
        file.take(MAX_FILE + 1).read_to_end(&mut data)?;
        if data.len() as u64 > MAX_FILE {
            return Err(corrupt(*id, "file is too large"));
        }
        let (kind, body) = decode_loose(id, &data)?;
        if hash_object(kind, &body) != *id {
            return Err(corrupt(*id, "content hash does not match id"));
        }
        Ok(Some((kind, body)))
    }

    fn object_path(&self, id: &ObjectId) -> PathBuf {
        let hex = id.to_hex();
        // ObjectId is 32 bytes, so the hex form is always 64 characters.
        debug_assert_eq!(hex.len(), 64);
        let (shard, rest) = hex.split_at(2);
        self.root.join(shard).join(rest)
    }

    fn temp_file(&self) -> Result<(PathBuf, File)> {
        let mut rnd = [0u8; 16];
        for _ in 0..8 {
            getrandom::getrandom(&mut rnd)
                .map_err(|e| Error::Invalid(format!("no randomness: {e}")))?;
            let path = self.root.join("tmp").join(hex::encode(rnd));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Error::Invalid("could not create a temp file".into()))
    }
}

impl Store for DiskStore {
    fn kind(&self, id: &ObjectId) -> Result<Option<ObjectKind>> {
        let mut file = match File::open(self.object_path(id)) {
            Ok(file) => file,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let mut header = [0u8; 5];
        match file.read_exact(&mut header) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(corrupt(*id, "truncated object header"));
            }
            Err(e) => return Err(e.into()),
        }
        if header[..4] != MAGIC {
            return Err(corrupt(*id, "bad magic"));
        }
        let kind = ObjectKind::from_u8(header[4]).map_err(|e| corrupt(*id, e.to_string()))?;
        Ok(Some(kind))
    }

    fn get_raw(&self, id: &ObjectId) -> Result<Option<(ObjectKind, Vec<u8>)>> {
        let data = match fs::read(self.object_path(id)) {
            Ok(data) => data,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let (kind, body) = decode_loose(id, &data)?;
        if hash_object(kind, &body) != *id {
            return Err(corrupt(*id, "content hash does not match id"));
        }
        Ok(Some((kind, body)))
    }

    fn put_raw(&self, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> Result<()> {
        let dest = self.object_path(id);
        if dest.try_exists()? {
            return Ok(());
        }
        let bytes = encode_loose(kind, body);
        let (path, file) = self.temp_file()?;
        // Declared before `file` is rebound so that, on error, the handle
        // closes first and this remove then runs. Windows will not delete
        // a file that is still open. After a successful rename the path is
        // already gone, so the remove is a no-op.
        let tmp = RemoveOnDrop(path);
        let mut file = file;
        file.write_all(&bytes)?;
        // No per-object fsync: it costs milliseconds per object on Windows
        // and breaks the hot-path rule. Durability comes from the synced op
        // head plus crash recovery (DESIGN.md "Known gaps"), as in git.
        // Windows cannot rename a file that still has an open handle.
        drop(file);
        publish(&tmp.0, &dest)
    }

    fn has(&self, id: &ObjectId) -> Result<bool> {
        Ok(self.object_path(id).try_exists()?)
    }
}

/// Best-effort deletion of a temp path, including when a later write fails.
struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn publish(tmp: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    // Another writer may win the race. Windows also refuses to rename over
    // a file that is already there, and may briefly deny the rename of a
    // just-closed temp file, so a few tries are required.
    let mut wait = Duration::from_millis(1);
    let mut last = None;
    for _ in 0..5 {
        if dest.try_exists()? {
            return Ok(());
        }
        match fs::rename(tmp, dest) {
            Ok(()) => return Ok(()),
            Err(e) => {
                if dest.try_exists()? {
                    return Ok(());
                }
                last = Some(e);
                std::thread::sleep(wait);
                wait = (wait * 2).min(Duration::from_millis(16));
            }
        }
    }
    match last {
        Some(e) => Err(e.into()),
        None => Err(Error::Invalid("rename failed".into())),
    }
}

fn encode_loose(kind: ObjectKind, body: &[u8]) -> Vec<u8> {
    let (flag, payload) = encode_payload(body);
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.extend_from_slice(&MAGIC);
    out.push(kind as u8);
    out.push(flag);
    out.extend_from_slice(&payload);
    out
}

fn encode_payload(body: &[u8]) -> (u8, Vec<u8>) {
    // Bodies above the read-side cap are stored raw, or they could never be
    // decompressed again.
    if body.len() < MIN_COMPRESS_LEN || body.len() > MAX_OBJECT_BYTES {
        return (FLAG_RAW, body.to_vec());
    }
    let compressed = lz4_flex::block::compress_prepend_size(body);
    if compressed.len() < body.len() {
        (FLAG_LZ4, compressed)
    } else {
        (FLAG_RAW, body.to_vec())
    }
}

fn decode_loose(id: &ObjectId, data: &[u8]) -> Result<(ObjectKind, Vec<u8>)> {
    if data.len() < HEADER_LEN {
        return Err(corrupt(*id, "truncated object header"));
    }
    if data[..4] != MAGIC {
        return Err(corrupt(*id, "bad magic"));
    }
    let kind = ObjectKind::from_u8(data[4]).map_err(|e| corrupt(*id, e.to_string()))?;
    let body = match data[5] {
        FLAG_RAW => data[HEADER_LEN..].to_vec(),
        FLAG_LZ4 => decompress_payload(id, &data[HEADER_LEN..])?,
        flag => return Err(corrupt(*id, format!("unknown encoding {flag}"))),
    };
    Ok((kind, body))
}

fn decompress_payload(id: &ObjectId, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < 4 {
        return Err(corrupt(*id, "truncated lz4 length"));
    }
    let mut size_bytes = [0u8; 4];
    size_bytes.copy_from_slice(&payload[..4]);
    let claimed = u32::from_le_bytes(size_bytes) as usize;
    if claimed > MAX_OBJECT_BYTES {
        return Err(corrupt(
            *id,
            format!("uncompressed size {claimed} exceeds limit"),
        ));
    }
    let expand_limit = payload.len().saturating_mul(MAX_EXPAND).saturating_add(64);
    if claimed > expand_limit {
        return Err(corrupt(
            *id,
            format!("uncompressed size {claimed} exceeds expansion bound"),
        ));
    }
    lz4_flex::block::decompress_size_prepended(payload)
        .map_err(|e| corrupt(*id, format!("lz4: {e}")))
}

fn corrupt(id: ObjectId, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        id,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{EntryKind, Object, Tree, TreeEntry};
    use crate::store::StoreExt;

    fn open_tmp() -> (tempfile::TempDir, DiskStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let store = DiskStore::open(dir.path()).unwrap();
        (dir, store)
    }

    fn assert_tmp_empty(store: &DiskStore) {
        let left: Vec<_> = fs::read_dir(store.root().join("tmp"))
            .unwrap()
            .map(|ent| ent.unwrap().file_name())
            .collect();
        assert!(left.is_empty(), "temp files left behind: {left:?}");
    }

    fn flag_of(store: &DiskStore, id: &ObjectId) -> u8 {
        let bytes = fs::read(store.object_path(id)).unwrap();
        assert!(bytes.len() >= HEADER_LEN);
        assert_eq!(&bytes[..4], &MAGIC);
        bytes[5]
    }

    #[test]
    fn kind_present_and_missing() {
        let (_dir, store) = open_tmp();
        for kind in [
            ObjectKind::Blob,
            ObjectKind::Tree,
            ObjectKind::Revision,
            ObjectKind::Operation,
            ObjectKind::View,
        ] {
            let id = hash_object(kind, b"body");
            store.put_raw(&id, kind, b"body").unwrap();
            assert_eq!(store.kind(&id).unwrap(), Some(kind));
        }
        assert_eq!(store.kind(&ObjectId([9; 32])).unwrap(), None);
    }

    #[test]
    fn kind_rejects_corrupt_headers() {
        let (_dir, store) = open_tmp();
        let id = store.put_blob(b"hello").unwrap();
        let path = store.object_path(&id);
        let header = [b'T', b'I', b'G', b'1', ObjectKind::Blob as u8];
        for len in 0..header.len() {
            fs::write(&path, &header[..len]).unwrap();
            assert!(matches!(store.kind(&id), Err(Error::Corrupt { id: bad, .. }) if bad == id));
        }
        let mut bad_magic = header;
        bad_magic[0] = b'X';
        fs::write(&path, bad_magic).unwrap();
        assert!(matches!(store.kind(&id), Err(Error::Corrupt { id: bad, .. }) if bad == id));
        for invalid_kind in [0, 7, 255] {
            let mut bad_kind = header;
            bad_kind[4] = invalid_kind;
            fs::write(&path, bad_kind).unwrap();
            assert!(matches!(store.kind(&id), Err(Error::Corrupt { id: bad, .. }) if bad == id));
        }
    }

    #[test]
    fn kind_does_not_read_or_verify_body() {
        let (_dir, store) = open_tmp();
        for body in [b"hello".to_vec(), vec![b'a'; 1024]] {
            let id = store.put_blob(&body).unwrap();
            let path = store.object_path(&id);
            let mut bytes = fs::read(&path).unwrap();
            bytes.truncate(HEADER_LEN);
            fs::write(&path, &bytes).unwrap();
            assert_eq!(store.kind(&id).unwrap(), Some(ObjectKind::Blob));
            assert!(matches!(store.get_raw(&id), Err(Error::Corrupt { .. })));
            // Even the encoding flag is outside the magic-and-kind prefix.
            bytes.truncate(5);
            fs::write(&path, &bytes).unwrap();
            assert_eq!(store.kind(&id).unwrap(), Some(ObjectKind::Blob));
            assert!(matches!(store.get_raw(&id), Err(Error::Corrupt { .. })));
        }
    }

    #[test]
    fn roundtrip_blobs_and_trees() {
        let (_dir, store) = open_tmp();

        let empty = store.put_blob(b"").unwrap();
        assert_eq!(store.get_blob(&empty).unwrap(), b"");
        assert_eq!(flag_of(&store, &empty), FLAG_RAW);
        assert!(store.has(&empty).unwrap());
        let hex = empty.to_hex();
        assert_eq!(
            store.object_path(&empty),
            store.root().join(&hex[..2]).join(&hex[2..])
        );

        let small = store.put_blob(b"hello").unwrap();
        assert_eq!(store.get(&small).unwrap(), Object::Blob(b"hello".to_vec()));
        assert_eq!(flag_of(&store, &small), FLAG_RAW);
        assert_eq!(store.put_blob(b"hello").unwrap(), small);

        let big = vec![b'a'; 1024 * 1024];
        let big_id = store.put_blob(&big).unwrap();
        assert_eq!(flag_of(&store, &big_id), FLAG_LZ4);
        assert_eq!(store.get_blob(&big_id).unwrap(), big);

        let mut random = vec![0u8; 32 * 1024];
        getrandom::getrandom(&mut random).unwrap();
        let random_id = store.put_blob(&random).unwrap();
        assert!(
            lz4_flex::block::compress_prepend_size(&random).len() >= random.len(),
            "expected incompressible test data"
        );
        assert_eq!(flag_of(&store, &random_id), FLAG_RAW);
        assert_eq!(store.get_blob(&random_id).unwrap(), random);

        let file_id = store.put_blob(b"contents").unwrap();
        let tree = Tree::new(vec![
            TreeEntry {
                name: "a".into(),
                kind: EntryKind::File,
                id: file_id,
            },
            TreeEntry {
                name: "b".into(),
                kind: EntryKind::Executable,
                id: file_id,
            },
        ])
        .unwrap();
        let tree_obj = Object::Tree(tree);
        let tree_id = store.put(&tree_obj).unwrap();
        assert_eq!(store.get(&tree_id).unwrap(), tree_obj);

        let empty_tree = Object::Tree(Tree::empty());
        let empty_tree_id = store.put(&empty_tree).unwrap();
        assert_eq!(store.get_tree(&empty_tree_id).unwrap().entries(), &[]);

        assert_tmp_empty(&store);
    }

    #[test]
    fn persists_across_reopen() {
        let dir = tempfile::TempDir::new().unwrap();
        let blob_id;
        let tree_id;
        {
            let store = DiskStore::open(dir.path()).unwrap();
            blob_id = store.put_blob(b"persist").unwrap();
            tree_id = store.put(&Object::Tree(Tree::empty())).unwrap();
        }
        let store = DiskStore::open(dir.path()).unwrap();
        assert_eq!(store.get_blob(&blob_id).unwrap(), b"persist");
        assert!(store.get_tree(&tree_id).unwrap().is_empty());
        assert!(store.has(&blob_id).unwrap());
    }

    #[test]
    fn flipped_byte_is_corrupt() {
        let (_dir, store) = open_tmp();

        let raw_id = store.put_blob(b"hello").unwrap();
        let raw_path = store.object_path(&raw_id);
        let mut raw = fs::read(&raw_path).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xff;
        fs::write(&raw_path, &raw).unwrap();
        let err = store.get_raw(&raw_id).unwrap_err();
        assert!(
            matches!(err, Error::Corrupt { id, .. } if id == raw_id),
            "{err}"
        );

        let big = vec![b'b'; 1024 * 1024];
        let lz4_id = store.put_blob(&big).unwrap();
        let lz4_path = store.object_path(&lz4_id);
        let mut compressed = fs::read(&lz4_path).unwrap();
        let mid = compressed.len() / 2;
        compressed[mid] ^= 0xff;
        fs::write(&lz4_path, &compressed).unwrap();
        let err = store.get_raw(&lz4_id).unwrap_err();
        assert!(
            matches!(err, Error::Corrupt { id, .. } if id == lz4_id),
            "{err}"
        );
    }

    #[test]
    fn truncated_file_errors() {
        let (_dir, store) = open_tmp();
        let id = store.put_blob(b"hello").unwrap();
        let path = store.object_path(&id);

        fs::write(&path, b"TIG").unwrap();
        let err = store.get_raw(&id).unwrap_err();
        assert!(matches!(err, Error::Corrupt { .. }), "{err}");

        fs::write(&path, b"TIG1\x01").unwrap();
        let err = store.get_raw(&id).unwrap_err();
        assert!(matches!(err, Error::Corrupt { .. }), "{err}");

        // Header plus an lz4 flag and a short length prefix.
        let mut hostile = Vec::from(MAGIC);
        hostile.push(ObjectKind::Blob as u8);
        hostile.push(FLAG_LZ4);
        hostile.extend_from_slice(&200_000_000u32.to_le_bytes());
        hostile.extend_from_slice(&[0, 1, 2, 3]);
        fs::write(&path, &hostile).unwrap();
        let err = store.get_raw(&id).unwrap_err();
        assert!(matches!(err, Error::Corrupt { .. }), "{err}");
    }

    #[test]
    fn missing_object_is_absent() {
        let (_dir, store) = open_tmp();
        let id = ObjectId([0x11; 32]);
        assert!(store.get_raw(&id).unwrap().is_none());
        assert!(!store.has(&id).unwrap());
    }

    #[test]
    fn concurrent_puts_roundtrip_and_leave_no_temps() {
        let (_dir, store) = open_tmp();
        let shared_body = vec![b'z'; 64 * 1024];
        std::thread::scope(|scope| {
            for t in 0..8u8 {
                let store = &store;
                let shared_body = &shared_body;
                scope.spawn(move || {
                    let shared = store.put_blob(shared_body).unwrap();
                    assert_eq!(store.get_blob(&shared).unwrap(), *shared_body);
                    let own = format!("thread-{t}-{}", "x".repeat(80)).into_bytes();
                    let id = store.put_blob(&own).unwrap();
                    assert_eq!(store.get_blob(&id).unwrap(), own);
                    let again = store.put_blob(b"shared-small").unwrap();
                    assert_eq!(store.get_blob(&again).unwrap(), b"shared-small");
                });
            }
        });
        let shared = store.put_blob(&shared_body).unwrap();
        assert_eq!(store.get_blob(&shared).unwrap(), shared_body);
        assert_eq!(
            store
                .get_blob(&store.put_blob(b"shared-small").unwrap())
                .unwrap(),
            b"shared-small"
        );
        assert_tmp_empty(&store);
    }
}
