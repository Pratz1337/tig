//! The single mutable pointer in a repo: the id of the latest operation.
//! Everything else is immutable objects.

use std::fs;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::id::ObjectId;

pub trait OpHeadStore: Send + Sync {
    fn get(&self) -> Result<Option<ObjectId>>;
    /// Moves the head from `expected` to `new`. Returns false (and changes
    /// nothing) if someone else moved it first.
    fn compare_and_set(&self, expected: Option<ObjectId>, new: ObjectId) -> Result<bool>;
    /// Recent prior heads, newest first, saved with the head update.
    fn recovery_heads(&self) -> Result<Vec<ObjectId>> {
        Ok(Vec::new())
    }
}

#[derive(Default)]
pub struct MemoryOpHead {
    head: Mutex<Option<ObjectId>>,
    prior: Mutex<Vec<ObjectId>>,
}

impl MemoryOpHead {
    pub fn new() -> Self {
        Self::default()
    }
}

impl OpHeadStore for MemoryOpHead {
    fn get(&self) -> Result<Option<ObjectId>> {
        Ok(*self.head.lock().expect("lock poisoned"))
    }

    fn compare_and_set(&self, expected: Option<ObjectId>, new: ObjectId) -> Result<bool> {
        let mut head = self.head.lock().expect("lock poisoned");
        if *head != expected {
            return Ok(false);
        }
        if let Some(old) = *head {
            remember(&mut self.prior.lock().expect("lock poisoned"), old);
        }
        *head = Some(new);
        Ok(true)
    }

    fn recovery_heads(&self) -> Result<Vec<ObjectId>> {
        Ok(self.prior.lock().expect("lock poisoned").clone())
    }
}

/// Op head kept in one file, updated by write-temp-then-rename under a lock
/// file so concurrent `tig` processes cannot lose an operation.
pub struct FileOpHead {
    path: PathBuf,
    lock: PathBuf,
}

const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const RECENT_HEADS: usize = 32;

fn remember(prior: &mut Vec<ObjectId>, old: ObjectId) {
    prior.retain(|id| *id != old);
    prior.insert(0, old);
    prior.truncate(RECENT_HEADS);
}

impl FileOpHead {
    pub fn new(dir: &Path) -> Self {
        FileOpHead {
            path: dir.join("op_head"),
            lock: dir.join("op_head.lock"),
        }
    }

    fn read(&self) -> Result<Option<ObjectId>> {
        Ok(self.read_heads()?.first().copied())
    }

    fn read_heads(&self) -> Result<Vec<ObjectId>> {
        match fs::read_to_string(&self.path) {
            Ok(s) => {
                let lines: Vec<_> = s.trim().lines().collect();
                if lines.is_empty() || lines.len() > RECENT_HEADS + 1 {
                    return Err(Error::Invalid("invalid operation head record".into()));
                }
                lines.into_iter().map(|line| line.trim().parse()).collect()
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(e.into()),
        }
    }
}

struct LockGuard<'a>(&'a Path);

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0);
    }
}

impl OpHeadStore for FileOpHead {
    fn get(&self) -> Result<Option<ObjectId>> {
        self.read()
    }

    fn recovery_heads(&self) -> Result<Vec<ObjectId>> {
        Ok(self.read_heads()?.into_iter().skip(1).collect())
    }

    fn compare_and_set(&self, expected: Option<ObjectId>, new: ObjectId) -> Result<bool> {
        let start = Instant::now();
        let _guard = loop {
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&self.lock)
            {
                Ok(_) => break LockGuard(&self.lock),
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                    if start.elapsed() > LOCK_TIMEOUT {
                        return Err(Error::Invalid(format!(
                            "timed out waiting for {}; if no other tig process is running, delete it",
                            self.lock.display()
                        )));
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(e) => return Err(e.into()),
            }
        };
        let heads = self.read_heads()?;
        if heads.first().copied() != expected {
            return Ok(false);
        }
        let mut prior: Vec<_> = heads.into_iter().skip(1).collect();
        if let Some(old) = expected {
            remember(&mut prior, old);
        }
        let mut record = new.to_hex();
        for old in prior {
            record.push('\n');
            record.push_str(&old.to_hex());
        }
        // Unpredictable name + create_new: never truncate or follow a file
        // (or link) that someone planted in the metadata directory.
        let mut suffix = [0u8; 8];
        getrandom::getrandom(&mut suffix)
            .map_err(|e| Error::Invalid(format!("no randomness: {e}")))?;
        let tmp = self
            .path
            .with_extension(format!("tmp-{}", hex::encode(suffix)));
        let written = (|| -> Result<()> {
            let mut f = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            f.write_all(record.as_bytes())?;
            f.sync_all()?;
            Ok(fs::rename(&tmp, &self.path)?)
        })();
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written.map(|()| true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(h: &dyn OpHeadStore) {
        let a = ObjectId([1; 32]);
        let b = ObjectId([2; 32]);
        assert_eq!(h.get().unwrap(), None);
        assert!(h.compare_and_set(None, a).unwrap());
        assert!(!h.compare_and_set(None, b).unwrap());
        assert!(h.recovery_heads().unwrap().is_empty());
        assert!(h.compare_and_set(Some(a), b).unwrap());
        assert_eq!(h.get().unwrap(), Some(b));
        assert_eq!(h.recovery_heads().unwrap(), vec![a]);
        assert!(!h.compare_and_set(Some(a), a).unwrap());
        assert_eq!(h.recovery_heads().unwrap(), vec![a]);
    }

    #[test]
    fn memory() {
        check(&MemoryOpHead::new());
    }

    #[test]
    fn file() {
        let dir = tempfile::tempdir().unwrap();
        check(&FileOpHead::new(dir.path()));
    }

    #[test]
    fn legacy_head_is_upgraded_and_history_is_bounded_and_persistent() {
        let dir = tempfile::tempdir().unwrap();
        let mut current = ObjectId([1; 32]);
        fs::write(
            dir.path().join("op_head"),
            format!("{}\n", current.to_hex()),
        )
        .unwrap();
        let head = FileOpHead::new(dir.path());
        assert_eq!(head.get().unwrap(), Some(current));
        assert!(head.recovery_heads().unwrap().is_empty());
        for byte in 2..=40 {
            let next = ObjectId([byte; 32]);
            assert!(head.compare_and_set(Some(current), next).unwrap());
            current = next;
        }
        let reopened = FileOpHead::new(dir.path());
        assert_eq!(reopened.get().unwrap(), Some(current));
        let prior = reopened.recovery_heads().unwrap();
        assert_eq!(prior.len(), RECENT_HEADS);
        assert_eq!(prior[0], ObjectId([39; 32]));
        assert_eq!(prior[31], ObjectId([8; 32]));
    }
}
