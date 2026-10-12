//! Opens recently edited files early, so their antivirus scan overlaps
//! startup instead of the walk.
//!
//! On Windows the first open of a modified file waits for the antivirus scan
//! (about 6-15 ms). A snapshot cannot avoid reading a changed file, but it
//! can start that wait sooner. `hot` lists the files whose content changed in
//! recent snapshots, newest first. When a workspace opens, a few detached
//! threads open each one and close it again, before the journal and the stat
//! cache are even loaded; the walk's own open then finds the scan done.
//!
//! This is only a hint. Nothing is read and no result is used, so a stale,
//! missing or torn list costs a wasted open and nothing else. The list holds
//! paths tig itself recorded, revalidated on load; `.tig` is trusted local
//! metadata (DESIGN.md "Known gaps").

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tig_core::RepoPath;

const HEADER: &str = "tig hot v1";
/// Files remembered. Each costs one open per command when unchanged.
const MAX_HOT: usize = 32;
const MAX_FILE: u64 = 64 * 1024;
const THREADS: usize = 4;

fn hot_path(tig_dir: &Path, name: &str) -> PathBuf {
    tig_dir.join("workspaces").join(name).join("hot")
}

/// The remembered list. Anything unreadable is an empty list.
fn load(tig_dir: &Path, name: &str) -> Vec<RepoPath> {
    let mut text = String::new();
    let read = File::open(hot_path(tig_dir, name))
        .and_then(|file| file.take(MAX_FILE).read_to_string(&mut text));
    if read.is_err() {
        return Vec::new();
    }
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Vec::new();
    }
    lines
        .filter_map(|line| RepoPath::new(line).ok())
        .filter(|path| !path.is_root())
        .take(MAX_HOT)
        .collect()
}

/// Starts opening the remembered files on background threads and returns at
/// once. The threads are never joined; process exit ends them.
pub fn start(root: &Path, tig_dir: &Path, name: &str) {
    let paths = load(tig_dir, name);
    if paths.is_empty() {
        return;
    }
    let files: Arc<Vec<PathBuf>> = Arc::new(paths.iter().map(|path| crate::wc::disk_path(root, path)).collect());
    let next = Arc::new(AtomicUsize::new(0));
    for _ in 0..THREADS.min(files.len()) {
        let (files, next) = (Arc::clone(&files), Arc::clone(&next));
        // Best effort: if a thread cannot start, the walk simply waits.
        let _ = std::thread::Builder::new()
            .name("tig-prefetch".into())
            .spawn(move || loop {
                let Some(file) = files.get(next.fetch_add(1, Ordering::Relaxed)) else {
                    return;
                };
                drop(File::open(file));
            });
    }
}

/// Puts `changed` (files whose content a snapshot just recorded) in front of
/// the list. Writes only when the list changes, so editing the same files
/// over and over costs nothing. Not atomic and not synced: it is a hint.
pub fn remember(tig_dir: &Path, name: &str, changed: &[RepoPath]) {
    let previous = load(tig_dir, name);
    let mut next: Vec<RepoPath> = Vec::with_capacity(MAX_HOT);
    for path in changed.iter().chain(&previous) {
        if next.len() == MAX_HOT {
            break;
        }
        if !next.contains(path) {
            next.push(path.clone());
        }
    }
    if next == previous {
        return;
    }
    let mut text = String::from(HEADER);
    for path in &next {
        text.push('\n');
        text.push_str(path.as_str());
    }
    text.push('\n');
    // A failed write only loses the hint.
    let _ = fs::write(hot_path(tig_dir, name), text);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> RepoPath {
        RepoPath::new(s).unwrap()
    }

    #[test]
    fn newest_first_deduplicated_bounded_and_garbage_tolerant() {
        let dir = tempfile::TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join("workspaces").join("default")).unwrap();
        assert!(load(dir.path(), "default").is_empty());

        remember(dir.path(), "default", &[p("a"), p("b")]);
        remember(dir.path(), "default", &[p("c"), p("a")]);
        assert_eq!(load(dir.path(), "default"), vec![p("c"), p("a"), p("b")]);

        let many: Vec<RepoPath> = (0..100).map(|i| p(&format!("f{i}"))).collect();
        remember(dir.path(), "default", &many);
        assert_eq!(load(dir.path(), "default"), many[..MAX_HOT].to_vec());

        let file = hot_path(dir.path(), "default");
        fs::write(&file, "something else\na\n").unwrap();
        assert!(load(dir.path(), "default").is_empty());
        fs::write(&file, format!("{HEADER}\n../escape\nok/x\n\n")).unwrap();
        assert_eq!(load(dir.path(), "default"), vec![p("ok/x")]);
    }
}
