use std::fs::{self, OpenOptions};
use std::path::Path;
use std::time::{Duration, SystemTime};

use tempfile::TempDir;
use tig_cli::wc::WorkingCopy;
use tig_core::path::RepoPath;
use tig_core::repo::{Settings, DEFAULT_WORKSPACE};
use tig_core::workspace::Workspace;

fn path(text: &str) -> RepoPath {
    RepoPath::new(text).unwrap()
}

fn backdate(file: &Path, time: SystemTime) {
    OpenOptions::new()
        .write(true)
        .open(file)
        .unwrap()
        .set_modified(time)
        .unwrap();
}

#[test]
fn checkout_preserves_same_size_edits_with_restored_mtime() {
    for delete in [false, true] {
        let dir = TempDir::new().unwrap();
        let file = dir.path().join("work.txt");
        fs::write(&file, b"saved").unwrap();
        let old_time = SystemTime::now() - Duration::from_secs(3600);
        backdate(&file, old_time);
        let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
        wc.set_clock(Some(SystemTime::now() + Duration::from_secs(3600)));
        wc.snapshot(&mut repo).unwrap();
        assert_eq!(wc.snapshot(&mut repo).unwrap().hashed, 0);
        let recorded = fs::metadata(&file).unwrap().modified().unwrap();
        fs::write(&file, b"local").unwrap();
        backdate(&file, recorded);
        let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
        if delete {
            ws.remove(&repo, &path("work.txt")).unwrap();
        } else {
            ws.write(&repo, &path("work.txt"), b"replacement").unwrap();
        }
        ws.snapshot(&mut repo).unwrap();
        assert!(
            wc.checkout(&repo).is_err(),
            "checkout destroyed an unsnapshotted edit"
        );
        assert_eq!(fs::read(&file).unwrap(), b"local");
    }
}

#[cfg(windows)]
fn junction(link: &Path, target: &Path) {
    let output = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(link.as_os_str().to_str().unwrap().replace('/', "\\"))
        .arg(target.as_os_str().to_str().unwrap().replace('/', "\\"))
        .output()
        .unwrap();
    assert!(output.status.success(), "junction failed: {:?}", output);
}

#[cfg(unix)]
fn junction(link: &Path, target: &Path) {
    std::os::unix::fs::symlink(target, link).unwrap();
}

#[cfg(any(windows, unix))]
#[test]
fn checkout_never_deletes_through_a_replaced_directory() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested/work.txt"), b"saved").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.remove(&repo, &path("nested/work.txt")).unwrap();
    ws.snapshot(&mut repo).unwrap();
    fs::rename(dir.path().join("nested"), dir.path().join("original")).unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("work.txt"), b"saved").unwrap();
    junction(&dir.path().join("nested"), outside.path());
    let result = wc.checkout(&repo);
    assert!(
        result.is_err(),
        "checkout followed a directory link: {result:?}"
    );
    assert_eq!(fs::read(outside.path().join("work.txt")).unwrap(), b"saved");
}

#[cfg(windows)]
#[test]
fn workspace_name_must_not_alias_existing_metadata() {
    for name in ["DEFAULT", "default.", "default "] {
        let dir = TempDir::new().unwrap();
        let (mut repo, wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
        let original = fs::read(wc.root().join(".tig/workspaces/default/root")).unwrap();
        let op = repo.op_id();
        let parent = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
        let other = TempDir::new().unwrap();
        let result = WorkingCopy::add_workspace(&mut repo, &wc, name, other.path(), parent);
        assert!(result.is_err(), "accepted aliased workspace name {name}");
        assert_eq!(repo.op_id(), op, "rejection happened after repo mutation");
        assert_eq!(
            fs::read(wc.root().join(".tig/workspaces/default/root")).unwrap(),
            original
        );
        assert!(!other.path().join(".tig").exists());
    }
}

#[test]
fn checkout_replaces_a_tracked_directory_with_a_file() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested/work.txt"), b"saved").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("nested"), b"replacement").unwrap();
    ws.snapshot(&mut repo).unwrap();
    wc.checkout(&repo).unwrap();
    assert_eq!(fs::read(dir.path().join("nested")).unwrap(), b"replacement");
}

#[test]
fn directory_replacement_preserves_untracked_files() {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested/work.txt"), b"saved").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(dir.path().join("nested/local.txt"), b"local").unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("nested"), b"replacement").unwrap();
    ws.snapshot(&mut repo).unwrap();
    assert!(wc.checkout(&repo).is_err());
    assert_eq!(
        fs::read(dir.path().join("nested/local.txt")).unwrap(),
        b"local"
    );
    assert_eq!(
        fs::read(dir.path().join("nested/work.txt")).unwrap(),
        b"saved"
    );
}

#[cfg(unix)]
#[test]
fn snapshot_detects_same_size_edit_with_restored_mtime() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("work.txt");
    fs::write(&file, b"saved").unwrap();
    backdate(&file, SystemTime::now() - Duration::from_secs(3600));
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let time = fs::metadata(&file).unwrap().modified().unwrap();
    fs::write(&file, b"local").unwrap();
    backdate(&file, time);
    wc.snapshot(&mut repo).unwrap();
    let ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    assert_eq!(
        ws.read(&repo, &path("work.txt")).unwrap().unwrap(),
        b"local"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn open_refuses_metadata_junctions_instead_of_finding_parent_repo() {
    let dir = TempDir::new().unwrap();
    let (_repo, wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let nested = dir.path().join("child");
    fs::create_dir(&nested).unwrap();
    junction(&nested.join(".tig"), &dir.path().join(".tig"));
    assert!(
        WorkingCopy::open(&nested, Settings::default()).is_err(),
        "opening a linked .tig selected the parent workspace {}",
        wc.root().display()
    );
}

#[cfg(any(windows, unix))]
#[test]
fn open_refuses_redirected_workspace_state_directory() {
    let dir = TempDir::new().unwrap();
    let (_repo, wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let meta = dir.path().join(".tig/workspaces/default");
    let outside = TempDir::new().unwrap();
    fs::write(
        outside.path().join("root"),
        format!("{}\n", wc.root().display()),
    )
    .unwrap();
    fs::copy(meta.join("state"), outside.path().join("state")).unwrap();
    fs::rename(&meta, dir.path().join(".tig/workspaces/original")).unwrap();
    fs::remove_file(dir.path().join(".tig/workspaces/original/root")).unwrap();
    junction(&meta, outside.path());
    assert!(
        WorkingCopy::open(dir.path(), Settings::default()).is_err(),
        "open trusted a workspace state directory redirected outside metadata"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn open_refuses_redirected_metadata_parent() {
    let dir = TempDir::new().unwrap();
    let (_repo, _wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let metadata = dir.path().join(".tig");
    fs::rename(
        metadata.join("workspaces"),
        metadata.join("original-workspaces"),
    )
    .unwrap();
    junction(
        &metadata.join("workspaces"),
        &metadata.join("original-workspaces"),
    );
    assert!(
        WorkingCopy::open(dir.path(), Settings::default()).is_err(),
        "open trusted a redirected metadata parent"
    );
}

#[cfg(any(windows, unix))]
#[test]
fn checkout_refuses_a_replaced_root() {
    let dir = TempDir::new().unwrap();
    let root = dir.path().join("root");
    let (mut repo, mut wc) = WorkingCopy::init(&root, Settings::default()).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("new.txt"), b"new").unwrap();
    ws.snapshot(&mut repo).unwrap();
    fs::rename(&root, dir.path().join("original-root")).unwrap();
    let outside = TempDir::new().unwrap();
    junction(&root, outside.path());
    assert!(wc.checkout(&repo).is_err());
    assert!(!outside.path().join("new.txt").exists());
}

#[test]
fn relative_pointer_is_rejected() {
    let dir = TempDir::new().unwrap();
    let (mut repo, wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let other = TempDir::new().unwrap();
    let parent = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let secondary =
        WorkingCopy::add_workspace(&mut repo, &wc, "other", other.path(), parent).unwrap();
    // A cwd-relative pointer currently resolves successfully, even though
    // pointer files are specified to contain absolute paths.
    let cwd = std::env::current_dir().unwrap();
    let shared = dir.path().join(".tig");
    let cwd_parts: Vec<_> = cwd.components().collect();
    let target_parts: Vec<_> = shared.components().collect();
    let common = cwd_parts
        .iter()
        .zip(&target_parts)
        .take_while(|(a, b)| a == b)
        .count();
    let mut relative = std::path::PathBuf::new();
    for _ in common..cwd_parts.len() {
        relative.push("..");
    }
    for component in &target_parts[common..] {
        relative.push(component.as_os_str());
    }
    fs::write(
        secondary.root().join(".tig"),
        format!("{}\n", relative.display()),
    )
    .unwrap();
    assert!(WorkingCopy::open(secondary.root(), Settings::default()).is_err());
}

#[cfg(windows)]
#[test]
fn long_paths_round_trip_without_partial_checkout() {
    let dir = TempDir::new().unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let rel = format!(
        "{}/{}/{}/work.txt",
        "a".repeat(100),
        "b".repeat(100),
        "c".repeat(100)
    );
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path(&rel), b"long").unwrap();
    ws.snapshot(&mut repo).unwrap();
    wc.checkout(&repo).unwrap();
    assert_eq!(fs::read(wc.root().join(&rel)).unwrap(), b"long");
    let stats = wc.snapshot(&mut repo).unwrap();
    assert_eq!(stats.changed, 0);
}

#[test]
fn user_files_with_temp_prefix_are_snapshotted() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join(".tig-tmp-notes.txt"), b"user work").unwrap();
    let (repo, _wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    assert_eq!(
        ws.read(&repo, &path(".tig-tmp-notes.txt")).unwrap(),
        Some(b"user work".to_vec())
    );
}

#[cfg(windows)]
#[test]
#[ignore = "Decision required: blobs do not represent NTFS alternate streams"]
fn checkout_preserves_unsnapshotted_alternate_streams() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"saved").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let stream = wc.root().join("work.txt:notes");
    fs::write(&stream, b"unsnapshotted stream").unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("work.txt"), b"replacement").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let result = wc.checkout(&repo);
    assert!(
        result.is_err(),
        "checkout silently discarded an alternate stream"
    );
    assert_eq!(fs::read(&stream).unwrap(), b"unsnapshotted stream");
}

#[test]
fn checkout_uses_tree_identity_instead_of_corrupt_cache_blob_id() {
    use tig_core::object::{hash_object, ObjectKind};
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"saved").unwrap();
    let (mut repo, wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let state_file = wc.root().join(".tig/workspaces/default/state");
    let mut state = fs::read(&state_file).unwrap();
    let saved = hash_object(ObjectKind::Blob, b"saved");
    let local = hash_object(ObjectKind::Blob, b"local");
    let at = state
        .windows(32)
        .position(|bytes| bytes == saved.0)
        .unwrap();
    state[at..at + 32].copy_from_slice(&local.0);
    fs::write(&state_file, state).unwrap();
    fs::write(wc.root().join("work.txt"), b"local").unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("work.txt"), b"replacement").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let (_loaded_repo, mut reopened) = WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    assert!(
        reopened.checkout(&repo).is_err(),
        "checkout trusted a corrupt row ID"
    );
    assert_eq!(fs::read(wc.root().join("work.txt")).unwrap(), b"local");
}

#[cfg(any(windows, unix))]
#[test]
fn checkout_refuses_reparse_ancestors_above_the_workspace_root() {
    let main = TempDir::new().unwrap();
    let (mut repo, wc) = WorkingCopy::init(main.path(), Settings::default()).unwrap();
    let container = TempDir::new().unwrap();
    let parent_dir = container.path().join("parent");
    let root = parent_dir.join("workspace");
    let parent_rev = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let mut secondary =
        WorkingCopy::add_workspace(&mut repo, &wc, "other", &root, parent_rev).unwrap();
    let mut ws = Workspace::open(&repo, "other").unwrap();
    ws.write(&repo, &path("new.txt"), b"new").unwrap();
    ws.snapshot(&mut repo).unwrap();
    fs::rename(&parent_dir, container.path().join("original-parent")).unwrap();
    let outside = TempDir::new().unwrap();
    fs::create_dir(outside.path().join("workspace")).unwrap();
    junction(&parent_dir, outside.path());
    assert!(
        secondary.checkout(&repo).is_err(),
        "checkout followed a root ancestor"
    );
    assert!(!outside.path().join("workspace/new.txt").exists());
}

#[cfg(any(windows, unix))]
#[test]
#[ignore = "Core scope: DiskStore follows reparse points in object shard directories"]
fn snapshot_never_writes_through_a_redirected_object_shard() {
    use tig_core::object::{hash_object, ObjectKind};
    let dir = TempDir::new().unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let store = dir.path().join(".tig/store");
    let (data, shard) = (0..1000)
        .find_map(|i| {
            let data = format!("changed {i}").into_bytes();
            let id = hash_object(ObjectKind::Blob, &data).to_hex();
            let shard = store.join(&id[..2]);
            (!shard.exists()).then_some((data, shard))
        })
        .unwrap();
    let outside = TempDir::new().unwrap();
    junction(&shard, outside.path());
    fs::write(wc.root().join("work.txt"), &data).unwrap();
    let _result = wc.snapshot(&mut repo);
    assert!(
        fs::read_dir(outside.path()).unwrap().next().is_none(),
        "snapshot published objects outside the metadata directory"
    );
}

#[cfg(windows)]
#[test]
fn invalid_windows_names_are_rejected_before_any_checkout_write() {
    for bad in [
        "zmissing/bad?.txt".to_string(),
        format!("zmissing/{}", "x".repeat(256)),
    ] {
        let dir = TempDir::new().unwrap();
        let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
        let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
        ws.write(&repo, &path("a.txt"), b"safe").unwrap();
        ws.write(&repo, &path(&bad), b"bad").unwrap();
        ws.snapshot(&mut repo).unwrap();
        assert!(wc.checkout(&repo).is_err());
        assert!(
            !wc.root().join("a.txt").exists(),
            "invalid name caused a partial checkout: {bad}"
        );
    }
}

#[cfg(windows)]
#[test]
fn checkout_removes_a_tracked_junction_without_removing_its_target() {
    let dir = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    fs::write(outside.path().join("work.txt"), b"outside").unwrap();
    junction(&dir.path().join("linked"), outside.path());
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    assert!(ws.read(&repo, &path("linked")).unwrap().is_some());
    ws.remove(&repo, &path("linked")).unwrap();
    ws.snapshot(&mut repo).unwrap();
    wc.checkout(&repo).unwrap();
    assert!(fs::symlink_metadata(dir.path().join("linked")).is_err());
    assert_eq!(
        fs::read(outside.path().join("work.txt")).unwrap(),
        b"outside"
    );
}

#[cfg(windows)]
#[test]
fn checkout_refuses_generated_metadata_aliases() {
    let dir = TempDir::new().unwrap();
    // Force NTFS past its simple numeric short-name candidates.
    for i in 1..=9 {
        fs::write(dir.path().join(format!("TIG~{i}")), b"occupied").unwrap();
    }
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let output = std::process::Command::new("cmd")
        .args(["/c", "dir", "/x"])
        .arg(dir.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let listing = String::from_utf8_lossy(&output.stdout);
    let line = listing
        .lines()
        .find(|line| line.trim_end().ends_with(" .tig"))
        .unwrap();
    let columns: Vec<_> = line.split_whitespace().collect();
    let alias = columns[columns.len() - 2];
    if alias == "<DIR>" {
        // This filesystem has short-name creation disabled.
        return;
    }
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path(&format!("{alias}/intruder.txt")), b"intruder")
        .unwrap();
    ws.snapshot(&mut repo).unwrap();
    assert!(
        wc.checkout(&repo).is_err(),
        "checkout wrote through metadata alias {alias}"
    );
    assert!(!wc.root().join(".tig/intruder.txt").exists());
}
