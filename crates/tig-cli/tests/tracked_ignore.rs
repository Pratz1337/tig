use std::fs;
use std::time::{Duration, SystemTime};

use tig_cli::wc::WorkingCopy;
use tig_core::repo::{Settings, DEFAULT_WORKSPACE};
use tig_core::workspace::Workspace;
use tig_core::RepoPath;

fn bytes(repo: &tig_core::repo::Repo, name: &str) -> Option<Vec<u8>> {
    Workspace::open(repo, DEFAULT_WORKSPACE).unwrap()
        .read(repo, &RepoPath::new(name).unwrap()).unwrap()
}

#[test]
fn tracked_ignored_files_detect_edits_and_reuse_clean_stat_rows() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("ignored")).unwrap();
    fs::write(dir.path().join("ignored/work.txt"), b"before").unwrap();
    fs::write(dir.path().join("work.cached"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let clock = SystemTime::now() + Duration::from_secs(3600);
    wc.set_clock(Some(clock));
    wc.snapshot(&mut repo).unwrap();
    fs::write(dir.path().join(".gitignore"), b"*.cached\n").unwrap();
    fs::write(dir.path().join(".tigignore"), b"ignored/\n").unwrap();
    wc.snapshot(&mut repo).unwrap();
    assert_eq!(wc.snapshot(&mut repo).unwrap().hashed, 0);

    fs::write(dir.path().join("ignored/work.txt"), b"edited nested file").unwrap();
    fs::write(dir.path().join("work.cached"), b"edited root file").unwrap();
    fs::write(dir.path().join("ignored/new.txt"), b"keep untracked").unwrap();
    let stats = wc.snapshot(&mut repo).unwrap();
    assert_eq!(stats.hashed, 2, "{stats:?}");
    assert_eq!(bytes(&repo, "ignored/work.txt").unwrap(), b"edited nested file");
    assert_eq!(bytes(&repo, "work.cached").unwrap(), b"edited root file");
    assert!(bytes(&repo, "ignored/new.txt").is_none());
    let quiet = wc.snapshot(&mut repo).unwrap();
    assert_eq!((quiet.hashed, quiet.changed), (0, 0));

    fs::remove_file(dir.path().join("ignored/work.txt")).unwrap();
    assert_eq!(wc.snapshot(&mut repo).unwrap().changed, 1);
    assert!(bytes(&repo, "ignored/work.txt").is_none());
    let (mut repo, mut reopened) = WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    reopened.set_clock(Some(clock));
    assert_eq!(reopened.snapshot(&mut repo).unwrap().hashed, 0);
}

#[test]
fn ignored_legacy_blobs_keep_their_ids_when_rehashed() {
    use tig_core::store::StoreExt;
    use tig_core::treeops::Leaf;

    let dir = tempfile::tempdir().unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let data = vec![19; tig_core::blob::CHUNK_LEN + 17];
    let id = repo.store().put(&tig_core::Object::Blob(data.clone())).unwrap();
    let path = RepoPath::new("legacy.bin").unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.set(&repo, path.clone(), Some(Leaf::file(id))).unwrap();
    ws.snapshot(&mut repo).unwrap();
    wc.checkout(&repo).unwrap();
    fs::write(dir.path().join(".tigignore"), b"legacy.bin\n").unwrap();
    wc.snapshot(&mut repo).unwrap();
    assert_eq!(wc.snapshot_with_rehash(&mut repo, true).unwrap().changed, 0);
    assert_eq!(Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap().leaf(&repo, &path).unwrap().unwrap().id(), id);
    assert_eq!(fs::read(dir.path().join("legacy.bin")).unwrap(), data);
}

#[test]
fn tracked_paths_inside_a_new_nested_workspace_are_not_read() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested/work"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(dir.path().join("nested/.tig"), b"another workspace").unwrap();
    let secret = b"new nested workspace content must stay outside the parent store";
    fs::write(dir.path().join("nested/work"), secret).unwrap();
    assert!(wc.snapshot(&mut repo).unwrap_err().to_string().contains("nested workspace"));
    assert!(!repo.store().has(&tig_core::object::hash_object(tig_core::ObjectKind::Blob, secret)).unwrap());
    assert_eq!(fs::read(dir.path().join("nested/work")).unwrap(), secret);
}

#[cfg(unix)]
#[test]
fn ignored_tracked_reads_refuse_redirected_ancestors() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("ignored")).unwrap();
    fs::write(dir.path().join("ignored/work"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(dir.path().join(".tigignore"), b"ignored\n").unwrap();
    wc.snapshot(&mut repo).unwrap();
    fs::remove_file(dir.path().join("ignored/work")).unwrap();
    fs::remove_dir(dir.path().join("ignored")).unwrap();
    let secret = b"outside content must not enter the store";
    fs::write(outside.path().join("work"), secret).unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("ignored")).unwrap();
    assert!(wc.snapshot(&mut repo).unwrap_err().to_string().contains("symlink or reparse point"));
    assert!(!repo.store().has(&tig_core::object::hash_object(tig_core::ObjectKind::Blob, secret)).unwrap());
    assert_eq!(fs::read(outside.path().join("work")).unwrap(), secret);
}

#[cfg(unix)]
#[test]
fn a_discovered_parent_symlink_replaces_cached_children_without_reading_them() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("folder")).unwrap();
    fs::write(dir.path().join("folder/work"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(dir.path().join(".tigignore"), b"folder/\n").unwrap();
    wc.snapshot(&mut repo).unwrap();
    fs::remove_file(dir.path().join("folder/work")).unwrap();
    fs::remove_dir(dir.path().join("folder")).unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("folder")).unwrap();
    wc.snapshot(&mut repo).unwrap();
    assert!(bytes(&repo, "folder/work").is_none());
    assert_eq!(bytes(&repo, "folder").unwrap(), outside.path().as_os_str().as_encoded_bytes());
    assert_eq!(wc.snapshot(&mut repo).unwrap().changed, 0);
}
