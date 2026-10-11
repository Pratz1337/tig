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
    /// Like `compare_and_set`, for operations that only record what is
    /// already on disk (working-copy snapshots). Losing one in a crash loses
    /// nothing: the next command snapshots the same files again. So the
    /// update need not be synced, which saves an fsync on every edit (git
    /// does not sync its index either). Defaults to the durable update.
    fn compare_and_set_light(&self, expected: Option<ObjectId>, new: ObjectId) -> Result<bool> {
        self.compare_and_set(expected, new)
    }
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
///
/// Snapshot operations go to a second, unsynced record (`op_head.light`)
/// holding `(head, base, checksum)`. It counts only while its checksum holds
/// and `base` is still the durable head; a torn or stale light record is
/// ignored, falling back to the durable head.
pub struct FileOpHead {
    path: PathBuf,
    light: PathBuf,
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
            light: dir.join("op_head.light"),
            lock: dir.join("op_head.lock"),
        }
    }

    /// The light heads (current first, then recent ones), if the record is
    /// intact and sits on `durable`. Record: label, base, heads..., checksum.
    fn read_light(&self, durable: Option<ObjectId>) -> Option<Vec<ObjectId>> {
        let text = fs::read_to_string(&self.light).ok()?;
        let lines: Vec<&str> = text.lines().collect();
        let (sum, body_lines) = lines.split_last()?;
        if body_lines.len() < 3
            || body_lines.len() > RECENT_HEADS + 2
            || body_lines[0] != crate::domain::LIGHT_OP_HEAD
        {
            return None;
        }
        let body: String = body_lines.iter().map(|l| format!("{l}\n")).collect();
        if blake3::hash(body.as_bytes()).to_hex().as_str() != *sum {
            return None;
        }
        let base: ObjectId = body_lines[1].parse().ok()?;
        if Some(base) != durable {
            return None;
        }
        body_lines[2..].iter().map(|l| l.parse().ok()).collect()
    }

    /// The current head: the light head when valid, else the durable one.
    fn effective(&self, durable: &[ObjectId]) -> Option<ObjectId> {
        let durable_head = durable.first().copied();
        self.read_light(durable_head)
            .and_then(|light| light.first().copied())
            .or(durable_head)
    }

    fn lock(&self) -> Result<LockGuard<'_>> {
        let start = Instant::now();
        loop {
            match fs::OpenOptions::new().write(true).create_new(true).open(&self.lock) {
                Ok(_) => return Ok(LockGuard(&self.lock)),
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
        }
    }

    /// Writes `bytes` to `dest` via a fresh unpredictable temp file and a
    /// rename; `sync` decides whether the data is flushed first.
    fn replace_file(dest: &Path, bytes: &[u8], sync: bool) -> Result<()> {
        // Unpredictable name + create_new: never truncate or follow a file
        // (or link) that someone planted in the metadata directory.
        let mut suffix = [0u8; 8];
        getrandom::getrandom(&mut suffix).map_err(|e| Error::Invalid(format!("no randomness: {e}")))?;
        let tmp = dest.with_extension(format!("tmp-{}", hex::encode(suffix)));
        let written = (|| -> Result<()> {
            let mut f = fs::OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            f.write_all(bytes)?;
            if sync {
                f.sync_all()?;
            }
            Ok(fs::rename(&tmp, dest)?)
        })();
        if written.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        written
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
        Ok(self.effective(&self.read_heads()?))
    }

    fn recovery_heads(&self) -> Result<Vec<ObjectId>> {
        let heads = self.read_heads()?;
        Ok(match self.read_light(heads.first().copied()) {
            // Recent light heads first, then every durable head (the durable
            // head under the light ones is older than all of them).
            Some(light) => light.into_iter().skip(1).chain(heads).collect(),
            None => heads.into_iter().skip(1).collect(),
        })
    }

    fn compare_and_set_light(&self, expected: Option<ObjectId>, new: ObjectId) -> Result<bool> {
        let _guard = self.lock()?;
        let heads = self.read_heads()?;
        if self.effective(&heads) != expected {
            return Ok(false);
        }
        let Some(base) = heads.first().copied() else {
            // No durable head yet (a brand-new repo): nothing to sit on.
            drop(_guard);
            return self.compare_and_set(expected, new);
        };
        // Keep a short list of recent light heads for recovery: losing the
        // light record only loses snapshots, which the disk still holds.
        let mut recent = self.read_light(Some(base)).unwrap_or_default();
        recent.retain(|id| *id != new);
        recent.insert(0, new);
        recent.truncate(RECENT_HEADS);
        let mut body = format!("{}\n{}\n", crate::domain::LIGHT_OP_HEAD, base.to_hex());
        for id in &recent {
            body.push_str(&id.to_hex());
            body.push('\n');
        }
        let record = format!("{body}{}\n", blake3::hash(body.as_bytes()).to_hex());
        Self::replace_file(&self.light, record.as_bytes(), false)?;
        Ok(true)
    }

    fn compare_and_set(&self, expected: Option<ObjectId>, new: ObjectId) -> Result<bool> {
        let _guard = self.lock()?;
        let heads = self.read_heads()?;
        let durable = heads.first().copied();
        if self.effective(&heads) != expected {
            return Ok(false);
        }
        let mut prior: Vec<_> = heads.into_iter().skip(1).collect();
        // If a light head was current, the durable head under it is older.
        if let Some(old) = durable.filter(|d| Some(*d) != expected) {
            remember(&mut prior, old);
        }
        if let Some(old) = expected {
            remember(&mut prior, old);
        }
        let mut record = new.to_hex();
        for old in prior {
            record.push('\n');
            record.push_str(&old.to_hex());
        }
        Self::replace_file(&self.path, record.as_bytes(), true)?;
        // The light record now sits on an outdated base and no longer
        // counts; removing it is just tidying.
        let _ = fs::remove_file(&self.light);
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
    fn light_heads_sit_on_the_durable_head_and_never_outrank_it() {
        let dir = tempfile::tempdir().unwrap();
        let h = FileOpHead::new(dir.path());
        let [d1, l1, l2, d2] = [1u8, 2, 3, 4].map(|b| ObjectId([b; 32]));
        assert!(h.compare_and_set(None, d1).unwrap());
        // Light updates chain on top of the durable head.
        assert!(h.compare_and_set_light(Some(d1), l1).unwrap());
        assert!(!h.compare_and_set_light(Some(d1), l2).unwrap(), "stale expectation");
        assert!(h.compare_and_set_light(Some(l1), l2).unwrap());
        assert_eq!(h.get().unwrap(), Some(l2));
        // Recovery candidates: older light heads, then every durable head.
        assert_eq!(h.recovery_heads().unwrap(), vec![l1, d1]);
        // A durable update supersedes and removes the light record.
        assert!(h.compare_and_set(Some(l2), d2).unwrap());
        assert_eq!(h.get().unwrap(), Some(d2));
        assert!(!dir.path().join("op_head.light").exists());
        assert_eq!(h.recovery_heads().unwrap()[..2], [l2, d1]);
    }

    #[test]
    fn torn_or_stale_light_records_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let h = FileOpHead::new(dir.path());
        let [d1, l1, d2] = [1u8, 2, 3].map(|b| ObjectId([b; 32]));
        assert!(h.compare_and_set(None, d1).unwrap());
        assert!(h.compare_and_set_light(Some(d1), l1).unwrap());
        let light = dir.path().join("op_head.light");
        let good = fs::read(&light).unwrap();
        // A crash can leave an unsynced file zeroed or cut short.
        for torn in [vec![0u8; good.len()], good[..good.len() / 2].to_vec(), Vec::new()] {
            fs::write(&light, &torn).unwrap();
            assert_eq!(h.get().unwrap(), Some(d1), "falls back to the durable head");
        }
        // A light record left over from an older durable head does not count.
        fs::write(&light, &good).unwrap();
        assert_eq!(h.get().unwrap(), Some(l1));
        let durable = fs::read(dir.path().join("op_head")).unwrap();
        assert!(h.compare_and_set(Some(l1), d2).unwrap());
        fs::write(&light, &good).unwrap(); // resurrect the old light record
        assert_eq!(h.get().unwrap(), Some(d2));
        assert!(!durable.is_empty());
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
