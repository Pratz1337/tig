//! The working-copy walk: every file the snapshot must look at.
//!
//! Like git's `core.fscache` + `core.preloadIndex`, it lists each directory
//! with one `read_dir` (on Windows that listing already carries each file's
//! size and timestamps, so there is no per-file stat call) and spreads
//! directories over a small thread pool. The caller's `visit` runs on the
//! worker threads too, so per-file work (cache comparison) is parallel.
//!
//! Rules, identical to the earlier `ignore::Walk` setup:
//! - `.tig`, tig scratch files, and other VCS metadata (`.git`, `.hg`,
//!   `.svn`, `.jj`) are never content.
//! - A subdirectory whose listing contains `.tig` is another workspace or a
//!   nested repo and is skipped whole.
//! - `.gitignore` and `.tigignore` apply (gitignore syntax; `.tigignore`
//!   lines come later, so they win). The nearest directory decides first.
//!   No global excludes, no `.ignore` files, no parent-of-root files.
//! - Hidden files are included (`.env` is part of the working copy).
//! - Symlinks are reported as files and never followed.

use std::collections::{BTreeSet, VecDeque};
use std::ffi::{OsStr, OsString};
use std::fs::{self, FileType, Metadata};
use std::io;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex};

use ignore::gitignore::{Gitignore, GitignoreBuilder};
use ignore::Match;
use tig_core::RepoPath;

/// A file or symlink found by the walk.
pub struct Found<'a> {
    /// Repo path, or the raw name if it is not a valid repo path.
    pub path: Result<RepoPath, String>,
    pub disk: PathBuf,
    pub file_type: FileType,
    pub meta: &'a Metadata,
}

/// One unit of work: a directory to list.
struct Dir {
    disk: PathBuf,
    /// `None` once a parent's name failed validation; its files are then
    /// reported with an error path.
    repo: Result<RepoPath, String>,
    depth: usize,
    /// Ignore matchers of this directory's ancestors, nearest last.
    ignores: Arc<Vec<Arc<Gitignore>>>,
}

type ListedEntry = (fs::DirEntry, OsString, Option<FileType>);

struct FileBatch {
    dir: Dir,
    entries: Vec<ListedEntry>,
}

enum Job {
    Directory(Dir),
    Files(Arc<FileBatch>, Range<usize>),
}

struct Shared {
    queue: VecDeque<Job>,
    active: usize,
    failed: Option<io::Error>,
}

/// Walks `root`, calling `visit` (on worker threads) for every file and
/// symlink. Returns the visit results in no particular order, plus warnings
/// about unreadable ignore files and skipped special files.
pub fn walk<T, F>(root: &Path, is_scratch: fn(&OsStr) -> bool, visit: F) -> io::Result<(Vec<T>, Vec<String>)>
where
    T: Send,
    F: Fn(Found<'_>) -> T + Sync,
{
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(1, 16);
    walk_with_workers(root, is_scratch, visit, workers)
}

fn walk_with_workers<T, F>(root: &Path, is_scratch: fn(&OsStr) -> bool, visit: F, workers: usize) -> io::Result<(Vec<T>, Vec<String>)>
where
    T: Send,
    F: Fn(Found<'_>) -> T + Sync,
{
    let shared = Mutex::new(Shared {
        queue: VecDeque::from([Job::Directory(Dir {
            disk: root.to_path_buf(),
            repo: Ok(RepoPath::root()),
            depth: 0,
            ignores: Arc::new(Vec::new()),
        })]),
        active: 0,
        failed: None,
    });
    let wake = Condvar::new();
    let mut results = Vec::new();
    let mut warnings = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut out = Vec::new();
                    let mut warn = Vec::new();
                    while let Some(job) = next_job(&shared, &wake) {
                        let result = match job {
                            Job::Directory(dir) => list_dir(dir, is_scratch, &visit, &mut out, &mut warn, workers, |jobs| {
                                let mut s = shared.lock().expect("walk lock poisoned");
                                if s.failed.is_none() {
                                    s.queue.extend(jobs);
                                    wake.notify_all();
                                }
                            }),
                            Job::Files(batch, range) => visit_files(&batch.dir, &batch.entries[range], &visit, &mut out, &mut warn),
                        };
                        let mut s = shared.lock().expect("walk lock poisoned");
                        if let Err(e) = result {
                            s.failed.get_or_insert(e);
                            s.queue.clear();
                        }
                        s.active -= 1;
                        wake.notify_all();
                    }
                    (out, warn)
                })
            })
            .collect();
        for handle in handles {
            let (out, warn) = handle.join().expect("walk worker panicked");
            results.extend(out);
            warnings.extend(warn);
        }
    });
    let shared = shared.into_inner().expect("walk lock poisoned");
    match shared.failed {
        Some(e) => Err(e),
        None => Ok((results, warnings)),
    }
}

/// Looks at event-selected files using the same exclusions as a full walk.
/// Directory changes and ignore-rule changes require a full walk instead.
pub fn walk_paths<T, F>(
    root: &Path,
    is_scratch: fn(&OsStr) -> bool,
    paths: &BTreeSet<RepoPath>,
    visit: F,
) -> io::Result<(Vec<T>, Vec<String>)>
where
    F: Fn(Found<'_>) -> T,
{
    let mut out = Vec::new();
    let mut warnings = Vec::new();
    for path in paths {
        let components: Vec<_> = path.components().collect();
        if components.is_empty() || components.iter().any(|name| {
            let name = OsStr::new(name);
            name == OsStr::new(".tig") || is_scratch(name) || is_vcs_metadata(name)
        }) {
            continue;
        }
        let mut dir = root.to_path_buf();
        let mut ignores = Vec::new();
        for (depth, name) in components.iter().enumerate() {
            if depth > 0 {
                let meta = match fs::symlink_metadata(&dir) {
                    Ok(meta) => meta,
                    Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => break,
                    Err(error) => return Err(error),
                };
                if !meta.is_dir() || meta.file_type().is_symlink() {
                    break;
                }
                match fs::symlink_metadata(dir.join(".tig")) {
                    Ok(_) => break,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error),
                }
            }
            let mut builder = GitignoreBuilder::new(&dir);
            for file in [".gitignore", ".tigignore"] {
                let ignore_path = dir.join(file);
                if ignore_path.is_file() {
                    if let Some(error) = builder.add(&ignore_path) {
                        warnings.push(format!("ignore rules near {}: {error}", ignore_path.display()));
                    }
                }
            }
            match builder.build() {
                Ok(matcher) => ignores.push(Arc::new(matcher)),
                Err(error) => warnings.push(format!("ignore rules near {}: {error}", dir.display())),
            }
            let disk = dir.join(name);
            let is_parent = depth + 1 < components.len();
            if ignored(&ignores, &disk, is_parent) {
                break;
            }
            if is_parent {
                dir = disk;
                continue;
            }
            let meta = match fs::symlink_metadata(&disk) {
                Ok(meta) => meta,
                Err(error) if matches!(error.kind(), io::ErrorKind::NotFound | io::ErrorKind::NotADirectory) => break,
                Err(error) => return Err(error),
            };
            let file_type = meta.file_type();
            if file_type.is_file() || file_type.is_symlink() {
                out.push(visit(Found { path: Ok(path.clone()), disk, file_type, meta: &meta }));
            } else if !file_type.is_dir() {
                warnings.push(format!("skipping special file {}", disk.display()));
            }
        }
    }
    Ok((out, warnings))
}

/// Blocks until a directory is available, or returns `None` when the queue
/// is empty and no worker can add more.
fn next_job(shared: &Mutex<Shared>, wake: &Condvar) -> Option<Job> {
    let mut s = shared.lock().expect("walk lock poisoned");
    loop {
        if let Some(dir) = s.queue.pop_front() {
            s.active += 1;
            return Some(dir);
        }
        if s.active == 0 {
            return None;
        }
        s = wake.wait(s).expect("walk lock poisoned");
    }
}

pub(crate) fn is_vcs_metadata(name: &OsStr) -> bool {
    // Encoded OS strings preserve ASCII. Ignorable prefixes are non-ASCII,
    // so an ASCII non-dot prefix cannot become a metadata name.
    if name.as_encoded_bytes().first().is_some_and(|&byte| byte.is_ascii() && byte != b'.') {
        return false;
    }
    name.to_str().is_some_and(|name| {
        [".git", ".hg", ".svn", ".jj"].iter()
            .any(|vcs| tig_core::object::is_metadata_alias(name, vcs))
    })
}

/// Lists one directory, queues its children, then visits its files.
fn list_dir<T, F>(
    dir: Dir,
    is_scratch: fn(&OsStr) -> bool,
    visit: &F,
    out: &mut Vec<T>,
    warnings: &mut Vec<String>,
    workers: usize,
    mut enqueue: impl FnMut(Vec<Job>),
) -> io::Result<()>
where
    F: Fn(Found<'_>) -> T,
{
    let mut entries: Vec<_> = fs::read_dir(&dir.disk)?.map(|entry| {
        entry.map(|entry| {
            let name = entry.file_name();
            (entry, name, None)
        })
    }).collect::<io::Result<_>>()?;
    // A subdirectory with its own `.tig` is another workspace or a nested
    // repo: never sweep it into this one (git skips nested repos too).
    if dir.depth > 0 && entries.iter().any(|(_, name, _)| name.as_os_str() == OsStr::new(".tig")) {
        return Ok(());
    }

    let mut ignores = dir.ignores.clone();
    let has = |name: &str| entries.iter().any(|(_, found, _)| found.as_os_str() == OsStr::new(name));
    if has(".gitignore") || has(".tigignore") {
        let mut builder = GitignoreBuilder::new(&dir.disk);
        for file in [".gitignore", ".tigignore"] {
            let path = dir.disk.join(file);
            if path.is_file() {
                if let Some(err) = builder.add(&path) {
                    warnings.push(format!("ignore rules near {}: {err}", path.display()));
                }
            }
        }
        match builder.build() {
            Ok(matcher) => {
                let mut chain = (*ignores).clone();
                chain.push(Arc::new(matcher));
                ignores = Arc::new(chain);
            }
            Err(err) => warnings.push(format!("ignore rules near {}: {err}", dir.disk.display())),
        }
    }

    let mut children = Vec::new();
    for (entry, name, kind) in &mut entries {
        let name = name.as_os_str();
        if name == OsStr::new(".tig") || is_scratch(name) || is_vcs_metadata(name) {
            continue;
        }
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let disk = entry.path();
            if ignored(&ignores, &disk, true) { continue; }
            let repo = entry_repo_path(&dir, name, &disk);
            children.push(Dir { disk, repo, depth: dir.depth + 1, ignores: ignores.clone() });
        } else {
            *kind = Some(file_type);
        }
    }
    // A slow file read must not keep the other workers waiting for children.
    if !children.is_empty() {
        enqueue(children.into_iter().map(Job::Directory).collect());
    }
    let dir = Dir { ignores, ..dir };
    if workers > 1 && entries.len() > 1024 {
        // Share the original listing; only large directories need file jobs.
        // Every disjoint range keeps the same ignore chain and cached types.
        let count = entries.len();
        let batch = Arc::new(FileBatch { dir, entries });
        enqueue((0..count).step_by(512).map(|start| {
            Job::Files(batch.clone(), start..(start + 512).min(count))
        }).collect());
        Ok(())
    } else {
        visit_files(&dir, &entries, visit, out, warnings)
    }
}

fn visit_files<T, F>(
    dir: &Dir,
    entries: &[ListedEntry],
    visit: &F,
    out: &mut Vec<T>,
    warnings: &mut Vec<String>,
) -> io::Result<()>
where
    F: Fn(Found<'_>) -> T,
{
    for (entry, name, kind) in entries {
        let Some(file_type) = kind else { continue; };
        let disk = entry.path();
        if ignored(&dir.ignores, &disk, false) { continue; }
        if file_type.is_file() || file_type.is_symlink() {
            let repo = entry_repo_path(dir, name, &disk);
            let meta = entry.metadata()?;
            out.push(visit(Found { path: repo, disk, file_type: *file_type, meta: &meta }));
        } else {
            warnings.push(format!("skipping special file {}", disk.display()));
        }
    }
    Ok(())
}

fn entry_repo_path(dir: &Dir, name: &OsStr, disk: &Path) -> Result<RepoPath, String> {
    match (&dir.repo, name.to_str()) {
        (Ok(parent), Some(text)) => parent.join(text).map_err(|e| format!("{}: {e}", disk.display())),
        (Ok(_), None) => Err(format!("{}: path is not valid UTF-8", disk.display())),
        (Err(e), _) => Err(e.clone()),
    }
}

/// The nearest matcher with an opinion decides; a whitelist (`!pattern`)
/// in a nearer directory overrides an ignore further up.
fn ignored(chain: &[Arc<Gitignore>], path: &Path, is_dir: bool) -> bool {
    for matcher in chain.iter().rev() {
        match matcher.matched(path, is_dir) {
            Match::Ignore(_) => return true,
            Match::Whitelist(_) => return false,
            Match::None => {}
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn vcs_aliases_keep_ignorable_prefixes_and_case_matching() {
        for metadata in [".git", ".hg", ".svn", ".jj"] {
            for name in [metadata.to_string(), metadata.to_uppercase(),
                format!("\u{200c}{metadata}"), format!("\u{feff}{metadata}\u{200f}"),
                format!(".\u{200d}{}", &metadata[1..])] {
                assert!(is_vcs_metadata(OsStr::new(&name)), "{name:?}");
            }
            for prefix in (0..=127u8).filter(|byte| *byte != b'.') {
                let name = format!("{}{metadata}", char::from(prefix));
                assert!(!is_vcs_metadata(OsStr::new(&name)), "{name:?}");
            }
        }
        for name in ["", "git", "README.md", ".gitignore", ".github", ".git~1", ".tig", "é.git", "a\u{200c}.git"] {
            assert!(!is_vcs_metadata(OsStr::new(name)), "{name:?}");
        }
    }

    #[test]
    fn non_unicode_os_names_are_not_vcs_metadata() {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            for bytes in [b"f\xff.git".as_slice(), b".g\xffit", b"\xff.git"] {
                let name = OsStr::from_bytes(bytes);
                assert!(name.to_str().is_none());
                assert!(!is_vcs_metadata(name));
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            for units in [vec![102, 0xd800, 46, 103, 105, 116],
                vec![46, 103, 0xd800, 105, 116], vec![0xd800, 46, 103, 105, 116]] {
                let name = OsString::from_wide(&units);
                assert!(name.to_str().is_none());
                assert!(!is_vcs_metadata(&name));
            }
        }
    }

    #[test]
    fn a_waiting_parent_file_does_not_stall_descendant_visits() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join("root.txt"), b"root").unwrap();
        fs::create_dir(root.path().join("child")).unwrap();
        fs::write(root.path().join("child/leaf"), b"child").unwrap();
        let (sent, received) = mpsc::sync_channel(1);
        let received = Mutex::new(received);
        let (found, warnings) = walk_with_workers(root.path(), |_| false, |item| {
            let path = item.path.unwrap();
            let child_finished = if path.as_str() == "root.txt" {
                received.lock().unwrap().recv_timeout(Duration::from_secs(5)).is_ok()
            } else {
                sent.send(()).unwrap();
                true
            };
            (path, child_finished)
        }, 2).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|(_, child_finished)| *child_finished),
            "a root-file visitor blocked every child-directory worker");
    }

    #[test]
    fn worker_counts_preserve_each_file_exactly_once() {
        let root = tempfile::tempdir().unwrap();
        let mut expected = BTreeSet::new();
        for i in 0..8 {
            fs::create_dir_all(root.path().join(format!("dir{i}/nested"))).unwrap();
            for name in [format!("dir{i}/file"), format!("dir{i}/nested/file")] {
                fs::write(root.path().join(&name), b"file").unwrap();
                expected.insert(RepoPath::new(&name).unwrap());
            }
        }
        for workers in [1, 2, 4] {
            let (files, warnings) = walk_with_workers(root.path(), |_| false, |item| item.path.unwrap(), workers).unwrap();
            assert!(warnings.is_empty());
            assert_eq!(files.len(), expected.len());
            assert_eq!(files.into_iter().collect::<BTreeSet<_>>(), expected);
        }
        assert!(walk_with_workers(&root.path().join("absent"), |_| false, |_| (), 2).is_err());
    }

    #[test]
    fn a_waiting_file_does_not_stall_a_wide_directory() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let root = tempfile::tempdir().unwrap();
        for i in 0..1025 {
            fs::write(root.path().join(format!("file{i}")), b"file").unwrap();
        }
        let first = AtomicBool::new(true);
        let (sent, received) = mpsc::sync_channel(1);
        let received = Mutex::new(received);
        let (found, warnings) = walk_with_workers(root.path(), |_| false, |item| {
            let another_file_finished = if first.swap(false, Ordering::Relaxed) {
                received.lock().unwrap().recv_timeout(Duration::from_secs(5)).is_ok()
            } else {
                let _ = sent.try_send(());
                true
            };
            (item.path.unwrap(), another_file_finished)
        }, 2).unwrap();
        assert!(warnings.is_empty());
        assert_eq!(found.len(), 1025);
        assert!(found.iter().all(|(_, finished)| *finished),
            "one file visitor blocked every other visit in a wide directory");
        assert_eq!(found.into_iter().map(|(path, _)| path).collect::<BTreeSet<_>>().len(), 1025);
    }

    #[test]
    fn wide_directory_batches_preserve_discovery_rules() {
        let root = tempfile::tempdir().unwrap();
        let mut expected = BTreeSet::new();
        for i in 0..1025 {
            let name = format!("file{i}");
            fs::write(root.path().join(&name), b"file").unwrap();
            expected.insert(RepoPath::new(&name).unwrap());
        }
        fs::write(root.path().join(".gitignore"), b"*.skip\nignored/\n").unwrap();
        fs::write(root.path().join(".tigignore"), b"!keep.skip\n").unwrap();
        for name in [".gitignore", ".tigignore", "keep.skip", ".env", "child/leaf"] {
            let path = root.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            if !name.ends_with("ignore") { fs::write(path, b"file").unwrap(); }
            expected.insert(RepoPath::new(name).unwrap());
        }
        for name in ["drop.skip", "ignored/leaf", "scratch/leaf", "nested/.tig/state", "nested/leaf",
            ".git/config", ".GIT/config", ".g\u{200c}it/config", ".hg/hgrc", ".svn/entries", ".jj/repo"] {
            let path = root.path().join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, b"excluded").unwrap();
        }
        for workers in [1, 2, 4] {
            let (found, warnings) = walk_with_workers(root.path(), |name| name == OsStr::new("scratch"),
                |item| item.path.unwrap(), workers).unwrap();
            assert!(warnings.is_empty());
            assert_eq!(found.len(), expected.len());
            assert_eq!(found.into_iter().collect::<BTreeSet<_>>(), expected);
        }
    }
}
