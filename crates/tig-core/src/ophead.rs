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
}

#[derive(Default)]
pub struct MemoryOpHead {
    head: Mutex<Option<ObjectId>>,
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
        *head = Some(new);
        Ok(true)
    }
}

/// Op head kept in one file, updated by write-temp-then-rename under a lock
/// file so concurrent `tig` processes cannot lose an operation.
pub struct FileOpHead {
    path: PathBuf,
    lock: PathBuf,
}

const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

impl FileOpHead {
    pub fn new(dir: &Path) -> Self {
        FileOpHead { path: dir.join("op_head"), lock: dir.join("op_head.lock") }
    }

    fn read(&self) -> Result<Option<ObjectId>> {
        match fs::read_to_string(&self.path) {
            Ok(s) => Ok(Some(s.trim().parse()?)),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
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

    fn compare_and_set(&self, expected: Option<ObjectId>, new: ObjectId) -> Result<bool> {
        let start = Instant::now();
        let _guard = loop {
            match fs::OpenOptions::new().write(true).create_new(true).open(&self.lock) {
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
        if self.read()? != expected {
            return Ok(false);
        }
        let tmp = self.path.with_extension("tmp");
        {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(new.to_hex().as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(true)
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
        assert!(h.compare_and_set(Some(a), b).unwrap());
        assert_eq!(h.get().unwrap(), Some(b));
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
}
