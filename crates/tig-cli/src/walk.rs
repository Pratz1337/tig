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
use std::ffi::OsStr;
use std::fs::{self, FileType, Metadata};
use std::io;
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

struct Shared {
    queue: VecDeque<Dir>,
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
    let shared = Mutex::new(Shared {
        queue: VecDeque::from([Dir {
            disk: root.to_path_buf(),
            repo: Ok(RepoPath::root()),
            depth: 0,
            ignores: Arc::new(Vec::new()),
        }]),
        active: 0,
        failed: None,
    });
    let wake = Condvar::new();
    let workers = std::thread::available_parallelism().map_or(4, |n| n.get()).clamp(1, 16);
    let mut results = Vec::new();
    let mut warnings = Vec::new();
    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut out = Vec::new();
                    let mut warn = Vec::new();
                    while let Some(dir) = next_job(&shared, &wake) {
                        let result = list_dir(&dir, is_scratch, &visit, &mut out, &mut warn);
                        let mut s = shared.lock().expect("walk lock poisoned");
                        match result {
                            Ok(children) => s.queue.extend(children),
                            Err(e) => {
                                s.failed.get_or_insert(e);
                                s.queue.clear();
                            }
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
fn next_job(shared: &Mutex<Shared>, wake: &Condvar) -> Option<Dir> {
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

fn is_vcs_metadata(name: &OsStr) -> bool {
    [".git", ".hg", ".svn", ".jj"].iter().any(|vcs| name == OsStr::new(vcs))
}

/// Lists one directory: visits its files, returns its subdirectories.
fn list_dir<T, F>(
    dir: &Dir,
    is_scratch: fn(&OsStr) -> bool,
    visit: &F,
    out: &mut Vec<T>,
    warnings: &mut Vec<String>,
) -> io::Result<Vec<Dir>>
where
    F: Fn(Found<'_>) -> T,
{
    let entries: Vec<fs::DirEntry> = fs::read_dir(&dir.disk)?.collect::<io::Result<_>>()?;
    // A subdirectory with its own `.tig` is another workspace or a nested
    // repo: never sweep it into this one (git skips nested repos too).
    if dir.depth > 0 && entries.iter().any(|e| e.file_name() == OsStr::new(".tig")) {
        return Ok(Vec::new());
    }

    let mut ignores = dir.ignores.clone();
    let has = |name: &str| entries.iter().any(|e| e.file_name() == OsStr::new(name));
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
    for entry in entries {
        let name = entry.file_name();
        if name == OsStr::new(".tig") || is_scratch(&name) || is_vcs_metadata(&name) {
            continue;
        }
        let file_type = entry.file_type()?;
        let disk = entry.path();
        let is_dir = file_type.is_dir();
        if ignored(&ignores, &disk, is_dir) {
            continue;
        }
        let repo = match (&dir.repo, name.to_str()) {
            (Ok(parent), Some(text)) => parent.join(text).map_err(|e| format!("{}: {e}", disk.display())),
            (Ok(_), None) => Err(format!("{}: path is not valid UTF-8", disk.display())),
            (Err(e), _) => Err(e.clone()),
        };
        if is_dir {
            children.push(Dir { disk, repo, depth: dir.depth + 1, ignores: ignores.clone() });
        } else if file_type.is_file() || file_type.is_symlink() {
            let meta = entry.metadata()?;
            out.push(visit(Found { path: repo, disk, file_type, meta: &meta }));
        } else {
            warnings.push(format!("skipping special file {}", disk.display()));
        }
    }
    Ok(children)
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
