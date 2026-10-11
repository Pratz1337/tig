//! A store that appends small objects to one journal file per repo.
//!
//! Why: on Windows the antivirus scans a file the first time it is opened
//! after a change (measured: ~6 ms per file, flat up to a few MB). A
//! snapshot writes a blob, a few trees, a revision, a view and an operation;
//! as loose files that is seven new files the next command pays to read.
//! git gets the same effect from packfiles; here the journal is the mutation
//! ledger over the loose-object base (the same frozen-base + ledger shape as
//! the path index), folded into loose objects once it passes a few
//! megabytes, before the scan cost starts to grow with its size.
//!
//! Format: the magic, then records `body_len u32 LE || kind u8 || id [32] ||
//! body`. A record counts only if `hash_object(kind, body) == id`, so a torn
//! tail (crash mid-append) is detected and ignored, never misread. Appends
//! from several processes are serialized with an OS file lock. One handle is
//! kept open for the store's lifetime: reopening a just-modified file would
//! make the antivirus scan it again.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::error::Result;
use crate::id::ObjectId;
use crate::object::{hash_object, ObjectKind};
use crate::store::{DiskStore, Store};

const MAGIC: &[u8; 8] = b"TIGJRNL1";
const HEADER: usize = 4 + 1 + 32;
/// Objects larger than this go straight to loose files.
const SMALL_OBJECT: usize = 64 * 1024;
/// Fold the journal into loose objects once it grows past this, before the
/// antivirus rescan cost starts growing with the file size.
const COMPACT_AT: u64 = 4 * 1024 * 1024;

pub struct JournalStore {
    disk: DiskStore,
    path: PathBuf,
    inner: Mutex<Inner>,
}

/// What this process knows of the journal: the kept handle, its valid bytes
/// so far, and where each object sits in them.
#[derive(Default)]
struct Inner {
    file: Option<File>,
    bytes: Vec<u8>,
    index: HashMap<ObjectId, (ObjectKind, Range<usize>)>,
}

impl JournalStore {
    /// Opens the loose store at `root` and its journal at `root/journal`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let disk = DiskStore::open(root)?;
        let path = disk.root().join("journal");
        let store = JournalStore { disk, path, inner: Mutex::new(Inner::default()) };
        let size = {
            let mut inner = store.inner.lock().expect("journal lock poisoned");
            store.refresh(&mut inner)?;
            inner.bytes.len() as u64
        };
        if size > COMPACT_AT {
            store.compact()?;
        }
        Ok(store)
    }

    /// The loose store underneath.
    pub fn disk(&self) -> &DiskStore {
        &self.disk
    }

    /// Path of the journal file (for tests and diagnostics).
    pub fn journal_path(&self) -> &Path {
        &self.path
    }

    /// Opens the kept handle if needed. Without `create`, a missing journal
    /// is `Ok(false)`.
    fn ensure_file(&self, inner: &mut Inner, create: bool) -> Result<bool> {
        if inner.file.is_none() {
            let opened = OpenOptions::new()
                .read(true)
                .write(true)
                .create(create)
                .truncate(false)
                .open(&self.path);
            match opened {
                Ok(file) => inner.file = Some(file),
                Err(e) if !create && e.kind() == ErrorKind::NotFound => return Ok(false),
                Err(e) => return Err(e.into()),
            }
        }
        Ok(true)
    }

    /// Catches up with appends by other processes, under a shared lock (on
    /// Windows locks are mandatory, so a reader waits for a writer instead
    /// of failing).
    fn refresh(&self, inner: &mut Inner) -> Result<()> {
        if !self.ensure_file(inner, false)? {
            return Ok(());
        }
        let mut file = inner.file.take().expect("ensured above");
        let result = file.lock_shared().map_err(Into::into).and_then(|()| read_new(&mut file, inner));
        let _ = file.unlock();
        inner.file = Some(file);
        result
    }

    /// Appends one record under an exclusive lock, after catching up with
    /// other writers (so an object is never appended twice).
    fn append(&self, inner: &mut Inner, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> Result<()> {
        self.ensure_file(inner, true)?;
        let mut file = inner.file.take().expect("ensured above");
        let result = file.lock().map_err(Into::into).and_then(|()| {
            read_new(&mut file, inner)?;
            if inner.index.contains_key(id) {
                return Ok(());
            }
            if inner.bytes.is_empty() {
                // New (or foreign/empty) file: start it with the header.
                file.set_len(0)?;
                file.seek(SeekFrom::Start(0))?;
                file.write_all(MAGIC)?;
                inner.bytes.extend_from_slice(MAGIC);
            } else if file.metadata()?.len() as usize != inner.bytes.len() {
                // Drop a torn tail before appending after it.
                file.set_len(inner.bytes.len() as u64)?;
            }
            let mut record = Vec::with_capacity(HEADER + body.len());
            record.extend_from_slice(&(body.len() as u32).to_le_bytes());
            record.push(kind as u8);
            record.extend_from_slice(id.as_bytes());
            record.extend_from_slice(body);
            file.seek(SeekFrom::Start(inner.bytes.len() as u64))?;
            file.write_all(&record)?;
            let start = inner.bytes.len() + HEADER;
            inner.bytes.extend_from_slice(&record);
            inner.index.insert(*id, (kind, start..start + body.len()));
            Ok(())
        });
        let _ = file.unlock();
        inner.file = Some(file);
        result
    }

    /// Moves every journal object into the loose store, then empties the
    /// journal. Other processes keep reading from their in-memory copy; their
    /// next refresh sees the shorter file and reloads.
    pub fn compact(&self) -> Result<()> {
        let mut inner = self.inner.lock().expect("journal lock poisoned");
        self.ensure_file(&mut inner, true)?;
        let mut file = inner.file.take().expect("ensured above");
        let result = file.lock().map_err(Into::into).and_then(|()| {
            read_new(&mut file, &mut inner)?;
            for (id, (kind, range)) in &inner.index {
                self.disk.put_raw(id, *kind, &inner.bytes[range.clone()])?;
            }
            file.set_len(0)?;
            inner.bytes.clear();
            inner.index.clear();
            Ok(())
        });
        let _ = file.unlock();
        inner.file = Some(file);
        result
    }

    fn copy_out(inner: &Inner, id: &ObjectId) -> Option<(ObjectKind, Vec<u8>)> {
        inner.index.get(id).map(|(kind, range)| (*kind, inner.bytes[range.clone()].to_vec()))
    }
}

/// Reads whatever was appended since `inner` last looked, through `file`
/// (whose lock the caller holds). If the file shrank (another process
/// compacted it), starts over.
fn read_new(file: &mut File, inner: &mut Inner) -> Result<()> {
    let len = file.metadata()?.len() as usize;
    if len < inner.bytes.len() || inner.bytes.is_empty() {
        inner.bytes.clear();
        inner.index.clear();
        let mut all = Vec::with_capacity(len);
        file.seek(SeekFrom::Start(0))?;
        file.read_to_end(&mut all)?;
        if all.len() < MAGIC.len() || &all[..MAGIC.len()] != MAGIC {
            // Empty or foreign file: no records; the next append rewrites
            // the header.
            return Ok(());
        }
        let valid = index_records(&all, MAGIC.len(), &mut inner.index);
        all.truncate(valid);
        inner.bytes = all;
    } else if len > inner.bytes.len() {
        let start = inner.bytes.len();
        file.seek(SeekFrom::Start(start as u64))?;
        file.read_to_end(&mut inner.bytes)?;
        let valid = index_records(&inner.bytes, start, &mut inner.index);
        inner.bytes.truncate(valid);
    }
    Ok(())
}

/// Indexes valid records from `start`; returns the end of the last valid
/// one. Stops at the first short, unknown or mismatching record (torn tail).
fn index_records(bytes: &[u8], start: usize, index: &mut HashMap<ObjectId, (ObjectKind, Range<usize>)>) -> usize {
    let mut pos = start;
    while bytes.len() - pos >= HEADER {
        let len = u32::from_le_bytes(bytes[pos..pos + 4].try_into().expect("4 bytes")) as usize;
        let Ok(kind) = ObjectKind::from_u8(bytes[pos + 4]) else { break };
        let id = ObjectId(bytes[pos + 5..pos + HEADER].try_into().expect("32 bytes"));
        let body_start = pos + HEADER;
        let Some(body_end) = body_start.checked_add(len).filter(|end| *end <= bytes.len()) else { break };
        if hash_object(kind, &bytes[body_start..body_end]) != id {
            break;
        }
        index.insert(id, (kind, body_start..body_end));
        pos = body_end;
    }
    pos
}

impl Store for JournalStore {
    fn get_raw(&self, id: &ObjectId) -> Result<Option<(ObjectKind, Vec<u8>)>> {
        if let Some(found) = Self::copy_out(&self.inner.lock().expect("journal lock poisoned"), id) {
            return Ok(Some(found));
        }
        if let Some(found) = self.disk.get_raw(id)? {
            return Ok(Some(found));
        }
        // Another process may have appended it since we last looked.
        let mut inner = self.inner.lock().expect("journal lock poisoned");
        self.refresh(&mut inner)?;
        Ok(Self::copy_out(&inner, id))
    }

    fn kind(&self, id: &ObjectId) -> Result<Option<ObjectKind>> {
        if let Some((kind, _)) = self.inner.lock().expect("journal lock poisoned").index.get(id) {
            return Ok(Some(*kind));
        }
        if let Some(kind) = self.disk.kind(id)? {
            return Ok(Some(kind));
        }
        Ok(self.get_raw(id)?.map(|(kind, _)| kind))
    }

    fn put_raw(&self, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> Result<()> {
        if body.len() > SMALL_OBJECT {
            return self.disk.put_raw(id, kind, body);
        }
        let mut inner = self.inner.lock().expect("journal lock poisoned");
        if inner.index.contains_key(id) {
            return Ok(());
        }
        self.append(&mut inner, id, kind, body)
    }

    /// No cross-process refresh here: a false "no" only means `put` appends,
    /// and `append` re-checks under the lock first.
    fn has(&self, id: &ObjectId) -> Result<bool> {
        if self.inner.lock().expect("journal lock poisoned").index.contains_key(id) {
            return Ok(true);
        }
        self.disk.has(id)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::store::StoreExt;

    #[test]
    fn small_objects_go_to_one_file_and_survive_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let s = JournalStore::open(dir.path()).unwrap();
        let ids: Vec<_> = (0..20).map(|i| s.put_blob(format!("obj {i}").as_bytes()).unwrap()).collect();
        let big = s.put_blob(&vec![7u8; SMALL_OBJECT + 1]).unwrap();
        // Small objects created no loose files; the big one did.
        assert!(!s.disk().has(&ids[0]).unwrap());
        assert!(s.disk().has(&big).unwrap());
        drop(s);
        let s = JournalStore::open(dir.path()).unwrap();
        for (i, id) in ids.iter().enumerate() {
            assert_eq!(s.get_blob(id).unwrap(), format!("obj {i}").as_bytes());
        }
        assert_eq!(s.kind(&ids[3]).unwrap(), Some(ObjectKind::Blob));
    }

    #[test]
    fn torn_tail_is_ignored_and_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let s = JournalStore::open(dir.path()).unwrap();
        let a = s.put_blob(b"kept").unwrap();
        drop(s);
        // A crash mid-append leaves a partial record.
        let path = dir.path().join("journal");
        let mut f = OpenOptions::new().append(true).open(&path).unwrap();
        f.write_all(&[9, 0, 0, 0, 1, 0xAB]).unwrap();
        drop(f);
        let s = JournalStore::open(dir.path()).unwrap();
        assert_eq!(s.get_blob(&a).unwrap(), b"kept");
        let b = s.put_blob(b"after the tear").unwrap();
        drop(s);
        let s = JournalStore::open(dir.path()).unwrap();
        assert_eq!(s.get_blob(&a).unwrap(), b"kept");
        assert_eq!(s.get_blob(&b).unwrap(), b"after the tear");
    }

    #[test]
    fn a_second_handle_sees_appends_and_compaction() {
        let dir = tempfile::tempdir().unwrap();
        let one = JournalStore::open(dir.path()).unwrap();
        let two = JournalStore::open(dir.path()).unwrap();
        let a = one.put_blob(b"from one").unwrap();
        assert_eq!(two.get_blob(&a).unwrap(), b"from one", "two catches up on a miss");
        let b = two.put_blob(b"from two").unwrap();
        one.compact().unwrap();
        assert!(one.disk().has(&a).unwrap() && one.disk().has(&b).unwrap());
        assert_eq!(fs::metadata(dir.path().join("journal")).unwrap().len(), 0);
        // Both handles still read everything; new appends restart the file.
        assert_eq!(two.get_blob(&b).unwrap(), b"from two");
        let c = two.put_blob(b"after compaction").unwrap();
        assert_eq!(one.get_blob(&c).unwrap(), b"after compaction");
    }

    #[test]
    fn corrupt_record_body_is_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let s = JournalStore::open(dir.path()).unwrap();
        let a = s.put_blob(b"original").unwrap();
        drop(s);
        let path = dir.path().join("journal");
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, &bytes).unwrap();
        let s = JournalStore::open(dir.path()).unwrap();
        assert!(s.get_raw(&a).unwrap().is_none(), "hash mismatch means not present");
    }
}
