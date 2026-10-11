//! Filesystem working-copy tests. The clock is injected so the racy-git
//! window does not require a two-second sleep.

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tempfile::TempDir;
use tig_cli::wc::WorkingCopy;
use tig_core::object::EntryKind;
use tig_core::path::RepoPath;
use tig_core::repo::{Settings, DEFAULT_WORKSPACE};
use tig_core::store::StoreExt;
use tig_core::treeops::Leaf;
use tig_core::workspace::Workspace;
use tig_private::rules::DEFAULT_PRIVATE;

fn settings() -> Settings {
    Settings::default()
}

fn path(text: &str) -> RepoPath {
    RepoPath::new(text).unwrap()
}

fn set_mtime(path: &Path, when: SystemTime) {
    let file = OpenOptions::new().write(true).open(path).unwrap();
    file.set_modified(when).unwrap();
}

/// Moves every working-tree file (not `.tig`) to `when`.
fn backdate(root: &Path, when: SystemTime) {
    fn walk(dir: &Path, when: SystemTime) {
        for ent in fs::read_dir(dir).unwrap() {
            let ent = ent.unwrap();
            if ent.file_name() == ".tig" {
                continue;
            }
            let path = ent.path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                continue;
            }
            if meta.is_dir() {
                walk(&path, when);
            } else if meta.is_file() {
                set_mtime(&path, when);
            }
        }
    }
    walk(root, when);
}

/// One snapshot to record backdated mtimes, then a second that must not hash.
fn settle(wc: &mut WorkingCopy, repo: &mut tig_core::repo::Repo, clock: SystemTime) {
    wc.set_clock(Some(clock));
    wc.snapshot(repo).unwrap();
    let quiet = wc.snapshot(repo).unwrap();
    assert_eq!(quiet.hashed, 0, "unchanged files were hashed: {quiet:?}");
    assert_eq!(quiet.changed, 0, "unchanged files wrote an operation: {quiet:?}");
}

fn file_bytes(wc: &WorkingCopy, rel: &str) -> Vec<u8> {
    fs::read(wc.root().join(rel)).unwrap()
}

fn tracked(repo: &tig_core::repo::Repo, rel: &str) -> Option<Vec<u8>> {
    let ws = Workspace::open(repo, DEFAULT_WORKSPACE).unwrap();
    ws.read(repo, &path(rel)).unwrap()
}

#[test]
fn init_snapshots_env_in_plaintext_and_open_finds_it() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".env"), b"SECRET=1\n").unwrap();
    fs::write(dir.path().join("hello.txt"), b"hello\r\n").unwrap();

    let (repo, wc) = WorkingCopy::init(dir.path(), settings()).unwrap();
    assert_eq!(wc.name(), DEFAULT_WORKSPACE);
    assert_eq!(
        fs::read_to_string(wc.root().join(".private")).unwrap(),
        DEFAULT_PRIVATE
    );
    assert_eq!(file_bytes(&wc, ".env"), b"SECRET=1\n");
    assert_eq!(tracked(&repo, ".env").unwrap(), b"SECRET=1\n");
    assert_eq!(tracked(&repo, "hello.txt").unwrap(), b"hello\r\n");

    let nested = wc.root().join("sub");
    fs::create_dir(&nested).unwrap();
    let (_opened_repo, opened) = WorkingCopy::open(&nested, settings()).unwrap();
    assert_eq!(opened.name(), "default");
    assert_eq!(opened.root(), wc.root());
}

#[test]
fn snapshot_detects_add_modify_delete_and_skips_unchanged() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.txt"), b"hello").unwrap();
    fs::write(dir.path().join("gone.txt"), b"gone").unwrap();
    fs::write(dir.path().join(".env"), b"x").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), settings()).unwrap();

    let clock = SystemTime::now();
    backdate(wc.root(), clock - Duration::from_secs(3600));
    settle(&mut wc, &mut repo, clock);
    let op_before = repo.op_id();
    let quiet = wc.snapshot(&mut repo).unwrap();
    assert_eq!(quiet.hashed, 0);
    assert_eq!(quiet.changed, 0);
    assert_eq!(repo.op_id(), op_before);

    fs::write(wc.root().join("hello.txt"), b"changed\r\n").unwrap();
    fs::write(wc.root().join("added.txt"), b"added").unwrap();
    fs::remove_file(wc.root().join("gone.txt")).unwrap();
    let stats = wc.snapshot(&mut repo).unwrap();
    assert_eq!(stats.hashed, 2, "{stats:?}");
    assert_eq!(stats.changed, 3, "{stats:?}");
    assert_eq!(tracked(&repo, "hello.txt").unwrap(), b"changed\r\n");
    assert_eq!(tracked(&repo, "added.txt").unwrap(), b"added");
    assert_eq!(tracked(&repo, "gone.txt"), None);
}

#[test]
fn racy_entry_is_rehashed_without_a_new_operation() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("keep.txt"), b"keep").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), settings()).unwrap();
    let clock = SystemTime::now();
    backdate(wc.root(), clock - Duration::from_secs(3600));
    settle(&mut wc, &mut repo, clock);

    let racy = wc.root().join("racy.txt");
    fs::write(&racy, b"one").unwrap();
    set_mtime(&racy, clock - Duration::from_secs(1));
    let first = wc.snapshot(&mut repo).unwrap();
    assert_eq!(first.hashed, 1, "{first:?}");
    assert_eq!(first.changed, 1, "{first:?}");

    let second = wc.snapshot(&mut repo).unwrap();
    assert_eq!(second.hashed, 1, "{second:?}");
    assert_eq!(second.changed, 0, "{second:?}");
    assert_eq!(tracked(&repo, "racy.txt").unwrap(), b"one");
}

#[test]
fn ignore_files_and_tig_dir_are_not_scanned() {
    let parent = TempDir::new().unwrap();
    fs::write(parent.path().join(".gitignore"), b"from-parent.txt\n").unwrap();
    let root = parent.path().join("workspace");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("from-parent.txt"), b"parent").unwrap();
    fs::write(root.join(".gitignore"), b"from-here.txt\n").unwrap();
    fs::write(root.join("from-here.txt"), b"here").unwrap();
    fs::write(root.join(".tigignore"), b"from-tig.txt\n").unwrap();
    fs::write(root.join("from-tig.txt"), b"tig").unwrap();
    fs::write(root.join(".ignore"), b"from-dot-ignore.txt\n").unwrap();
    fs::write(root.join("from-dot-ignore.txt"), b"dot").unwrap();
    fs::write(root.join(".env"), b"secret").unwrap();
    fs::write(root.join("keep.txt"), b"keep").unwrap();

    let (mut repo, mut wc) = WorkingCopy::init(&root, settings()).unwrap();
    assert_eq!(tracked(&repo, "from-parent.txt").unwrap(), b"parent");
    assert_eq!(tracked(&repo, "from-here.txt"), None);
    assert_eq!(tracked(&repo, "from-tig.txt"), None);
    assert_eq!(tracked(&repo, "from-dot-ignore.txt").unwrap(), b"dot");
    assert_eq!(tracked(&repo, ".env").unwrap(), b"secret");
    assert_eq!(tracked(&repo, "keep.txt").unwrap(), b"keep");

    fs::write(wc.root().join(".tig").join("not-in-repo.txt"), b"hidden").unwrap();
    let stats = wc.snapshot(&mut repo).unwrap();
    let ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    let files = ws.list(&repo, &RepoPath::root()).unwrap();
    assert!(
        files
            .iter()
            .all(|(p, _)| p.as_str() != ".tig" && !p.as_str().starts_with(".tig/")),
        "metadata dir was snapshotted: {files:?}"
    );
    assert!(
        stats
            .warnings
            .iter()
            .all(|w| !w.contains("not-in-repo")),
        "{stats:?}"
    );
}

#[test]
fn checkout_after_new_edit_and_undo_restores_bytes_and_directories() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.txt"), b"hello\r\nworld").unwrap();
    fs::write(dir.path().join("stay.txt"), b"stay").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), settings()).unwrap();

    let mut tx = repo.start("new");
    let cur = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let child = tx.new_change(&[cur], "edit").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
    repo.commit(tx).unwrap();
    let emptied = wc.checkout(&repo).unwrap();
    assert_eq!(emptied.written, 0);
    assert_eq!(emptied.removed, 0);

    fs::write(wc.root().join("hello.txt"), b"edited\r\n").unwrap();
    fs::create_dir_all(wc.root().join("dir").join("sub")).unwrap();
    fs::write(wc.root().join("dir").join("sub").join("n.txt"), b"nested").unwrap();
    fs::remove_file(wc.root().join("stay.txt")).unwrap();
    let snap = wc.snapshot(&mut repo).unwrap();
    assert!(snap.changed >= 3, "{snap:?}");

    repo.undo().unwrap();
    let restored = wc.checkout(&repo).unwrap();
    assert!(restored.written >= 2, "{restored:?}");
    assert!(restored.removed >= 1, "{restored:?}");
    assert_eq!(file_bytes(&wc, "hello.txt"), b"hello\r\nworld");
    assert_eq!(file_bytes(&wc, "stay.txt"), b"stay");
    assert!(!wc.root().join("dir").exists());

    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("dir/made.txt"), b"made").unwrap();
    assert!(ws.snapshot(&mut repo).unwrap());
    let created = wc.checkout(&repo).unwrap();
    assert_eq!(created.written, 1, "{created:?}");
    assert_eq!(file_bytes(&wc, "dir/made.txt"), b"made");

    repo.undo().unwrap();
    let removed = wc.checkout(&repo).unwrap();
    assert_eq!(removed.removed, 1, "{removed:?}");
    assert!(!wc.root().join("dir").join("made.txt").exists());
    assert!(!wc.root().join("dir").exists());
}

#[cfg(windows)]
#[test]
fn checkout_refuses_device_names_case_collisions_and_short_names() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("keep.txt"), b"keep").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), settings()).unwrap();

    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("ok.txt"), b"ok").unwrap();
    ws.write(&repo, &path("aux.c"), b"device").unwrap();
    assert!(ws.snapshot(&mut repo).unwrap());
    let err = wc.checkout(&repo).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("aux.c"), "{msg}");
    assert!(!wc.root().join("ok.txt").exists(), "partial checkout wrote ok.txt");
    assert!(!wc.root().join("aux.c").exists());
    assert_eq!(file_bytes(&wc, "keep.txt"), b"keep");

    repo.undo().unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("A"), b"upper").unwrap();
    ws.write(&repo, &path("a"), b"lower").unwrap();
    assert!(ws.snapshot(&mut repo).unwrap());
    let err = wc.checkout(&repo).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("case-insensitive"), "{msg}");
    assert!(!wc.root().join("A").exists());
    assert!(!wc.root().join("a").exists());

    repo.undo().unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("TIG~1"), b"short").unwrap();
    assert!(ws.snapshot(&mut repo).unwrap());
    let err = wc.checkout(&repo).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("TIG~1"), "{msg}");
    // NTFS publishes `.tig` itself as the short name `TIG~1`, so the path
    // can exist and still be the metadata directory. It must not be a file.
    match fs::symlink_metadata(wc.root().join("TIG~1")) {
        Ok(meta) => assert!(meta.is_dir(), "checkout wrote a file at TIG~1"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("stat TIG~1: {e}"),
    }
}

#[test]
fn secondary_workspace_shares_the_store() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.txt"), b"hello").unwrap();
    let (mut repo, wc) = WorkingCopy::init(dir.path(), settings()).unwrap();
    let parent = repo.working_revision(DEFAULT_WORKSPACE).unwrap();

    let other = TempDir::new().unwrap();
    let mut secondary =
        WorkingCopy::add_workspace(&mut repo, &wc, "feature", other.path(), parent).unwrap();
    assert_eq!(secondary.name(), "feature");

    let pointer = fs::read_to_string(secondary.root().join(".tig")).unwrap();
    let pointed = fs::canonicalize(pointer.trim()).unwrap();
    assert_eq!(pointed, fs::canonicalize(wc.root().join(".tig")).unwrap());
    assert!(fs::metadata(wc.root().join(".tig")).unwrap().is_dir());
    assert!(fs::metadata(secondary.root().join(".tig")).unwrap().is_file());

    let root_file = fs::read_to_string(
        wc.root()
            .join(".tig")
            .join("workspaces")
            .join("feature")
            .join("root"),
    )
    .unwrap();
    assert_eq!(
        fs::canonicalize(PathBuf::from(root_file.trim())).unwrap(),
        fs::canonicalize(secondary.root()).unwrap()
    );
    assert_eq!(file_bytes(&secondary, "hello.txt"), b"hello");

    let feature_rev = repo.revision(&repo.working_revision("feature").unwrap()).unwrap();
    assert_eq!(feature_rev.parents, vec![parent]);

    fs::write(secondary.root().join("only-feature.txt"), b"feat").unwrap();
    let before_default = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    secondary.snapshot(&mut repo).unwrap();
    assert_eq!(
        repo.working_revision(DEFAULT_WORKSPACE).unwrap(),
        before_default
    );
    assert_ne!(repo.working_revision("feature").unwrap(), before_default);
    assert_eq!(tracked(&repo, "only-feature.txt"), None);
    let feature = Workspace::open(&repo, "feature").unwrap();
    assert_eq!(
        feature
            .read(&repo, &path("only-feature.txt"))
            .unwrap()
            .unwrap(),
        b"feat"
    );

    let (_reopened, found) = WorkingCopy::open(secondary.root(), settings()).unwrap();
    assert_eq!(found.name(), "feature");
    assert_eq!(found.root(), secondary.root());
}

#[test]
fn snapshot_refuses_a_stale_workspace() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.txt"), b"hello").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), settings()).unwrap();

    let mut tx = repo.start("move");
    let cur = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let child = tx.new_change(&[cur], "elsewhere").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
    repo.commit(tx).unwrap();

    let err = wc.snapshot(&mut repo).unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("workspace is stale; run `tig workspace update-stale`"),
        "{msg}"
    );
    assert_eq!(file_bytes(&wc, "hello.txt"), b"hello");
}

#[test]
fn corrupt_state_rescans_and_checkout_waits() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("hello.txt"), b"hello").unwrap();
    let (repo, wc) = WorkingCopy::init(dir.path(), settings()).unwrap();
    let state = wc
        .root()
        .join(".tig")
        .join("workspaces")
        .join("default")
        .join("state");
    fs::write(&state, b"garbage").unwrap();
    drop(repo);
    drop(wc);

    let (mut repo, mut wc) = WorkingCopy::open(dir.path(), settings()).unwrap();
    let err = wc.checkout(&repo).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("re-scan"), "{msg}");

    let stats = wc.snapshot(&mut repo).unwrap();
    assert!(stats.hashed > 0, "{stats:?}");
    assert!(
        stats.warnings.iter().any(|w| w.contains("corrupt")),
        "{stats:?}"
    );
    assert_eq!(tracked(&repo, "hello.txt").unwrap(), b"hello");

    fs::write(wc.root().join("hello.txt"), b"after").unwrap();
    let again = wc.snapshot(&mut repo).unwrap();
    assert!(again.changed >= 1, "{again:?}");
    assert_eq!(tracked(&repo, "hello.txt").unwrap(), b"after");
}

#[cfg(unix)]
#[test]
fn symlink_round_trip() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("keep.txt"), b"keep").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), settings()).unwrap();

    let id = repo.store().put_blob(b"target.txt").unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.set(&repo, path("link"), Some(Leaf::symlink(id))).unwrap();
    assert!(ws.snapshot(&mut repo).unwrap());
    wc.checkout(&repo).unwrap();

    let link = wc.root().join("link");
    assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    assert_eq!(fs::read_link(&link).unwrap(), PathBuf::from("target.txt"));

    let clock = SystemTime::now();
    wc.set_clock(Some(clock + Duration::from_secs(3600)));
    wc.snapshot(&mut repo).unwrap();
    let quiet = wc.snapshot(&mut repo).unwrap();
    assert_eq!(quiet.changed, 0, "{quiet:?}");
    assert_kind(&repo, "link", EntryKind::Symlink);
}

#[cfg(windows)]
#[test]
fn symlink_round_trip_or_stand_in() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("keep.txt"), b"keep").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), settings()).unwrap();

    let id = repo.store().put_blob(b"target.txt").unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.set(&repo, path("link"), Some(Leaf::symlink(id))).unwrap();
    assert!(ws.snapshot(&mut repo).unwrap());
    wc.checkout(&repo).unwrap();

    let link = wc.root().join("link");
    let meta = fs::symlink_metadata(&link).unwrap();
    if meta.file_type().is_symlink() {
        assert_eq!(fs::read_link(&link).unwrap(), PathBuf::from("target.txt"));
    } else {
        assert!(meta.is_file(), "stand-in should be a regular file");
        assert_eq!(fs::read(&link).unwrap(), b"target.txt");
    }

    let clock = SystemTime::now();
    backdate(wc.root(), clock - Duration::from_secs(3600));
    wc.set_clock(Some(clock));
    wc.snapshot(&mut repo).unwrap();
    let quiet = wc.snapshot(&mut repo).unwrap();
    assert_eq!(quiet.changed, 0, "{quiet:?}");
    assert_kind(&repo, "link", EntryKind::Symlink);
}

fn assert_kind(repo: &tig_core::repo::Repo, rel: &str, kind: EntryKind) {
    let ws = Workspace::open(repo, DEFAULT_WORKSPACE).unwrap();
    let files = ws.list(repo, &RepoPath::root()).unwrap();
    let leaf = files
        .iter()
        .find(|(p, _)| p.as_str() == rel)
        .unwrap_or_else(|| panic!("{rel} missing from tree"))
        .1;
    assert_eq!(leaf.kind(), kind);
}

/// A workspace or repo nested inside another must never be swept into it.
#[test]
fn nested_workspaces_and_repos_are_not_scanned() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("main.txt"), b"m").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), settings()).unwrap();
    let parent = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let inner = dir.path().join("inner");
    let _side = WorkingCopy::add_workspace(&mut repo, &wc, "inner", &inner, parent).unwrap();
    fs::write(inner.join("only-inner.txt"), b"i").unwrap();
    let other = dir.path().join("other");
    fs::create_dir(&other).unwrap();
    WorkingCopy::init(&other, settings()).unwrap();
    fs::write(other.join("only-other.txt"), b"o").unwrap();

    wc.snapshot(&mut repo).unwrap();
    assert!(tracked(&repo, "main.txt").is_some());
    for nested in ["inner/only-inner.txt", "inner/main.txt", "other/only-other.txt", "other/.private"] {
        assert!(tracked(&repo, nested).is_none(), "{nested} leaked into the outer repo");
    }
}

/// Other version-control metadata is never content: `.git/config` can hold
/// credentials, and tracking it would publish them.
#[test]
fn other_vcs_metadata_is_never_tracked() {
    let dir = TempDir::new().unwrap();
    for vcs in [".git", ".hg", ".svn", ".jj"] {
        fs::create_dir(dir.path().join(vcs)).unwrap();
        fs::write(dir.path().join(vcs).join("config"), b"url = https://user:token@example.com").unwrap();
    }
    fs::write(dir.path().join("real.txt"), b"r").unwrap();
    let (repo, _wc) = WorkingCopy::init(dir.path(), settings()).unwrap();
    assert!(tracked(&repo, "real.txt").is_some());
    for vcs in [".git", ".hg", ".svn", ".jj"] {
        assert!(tracked(&repo, &format!("{vcs}/config")).is_none(), "{vcs} was tracked");
    }
}
