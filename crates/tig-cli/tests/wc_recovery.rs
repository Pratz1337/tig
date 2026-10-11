//! Recovery preserves the disk baseline separately from the repository view.

use std::fs::{self, OpenOptions};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

use tempfile::TempDir;
use tig_cli::wc::WorkingCopy;
use tig_core::path::RepoPath;
use tig_core::repo::{Settings, DEFAULT_WORKSPACE};
use tig_core::store::StoreExt;
use tig_core::workspace::Workspace;
use tig_core::ObjectId;

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
fn committed_snapshot_recovers_after_old_state_file_survives() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let clock = SystemTime::now() + Duration::from_secs(3600);
    wc.set_clock(Some(clock));
    wc.snapshot(&mut repo).unwrap();
    let state_file = dir.path().join(".tig/workspaces/default/state");
    let previous_state = fs::read(&state_file).unwrap();
    fs::write(dir.path().join("work.txt"), b"after").unwrap();
    wc.snapshot(&mut repo).unwrap();
    let committed = repo.op_id();
    // Crash after the op head moved but before the state rename completed.
    fs::write(&state_file, previous_state).unwrap();
    let (mut reopened_repo, mut reopened) =
        WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    reopened.set_clock(Some(clock));
    let stats = reopened.snapshot(&mut reopened_repo).unwrap();
    assert_eq!(stats.changed, 0);
    assert_eq!(reopened_repo.op_id(), committed);
    assert!(stats
        .warnings
        .iter()
        .any(|warning| warning.contains("recovered workspace state")));
    assert_eq!(fs::read(dir.path().join("work.txt")).unwrap(), b"after");
    assert_eq!(reopened.snapshot(&mut reopened_repo).unwrap().hashed, 0);
}

#[test]
fn snapshot_recovery_refuses_disk_edits_after_commit() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let state_file = dir.path().join(".tig/workspaces/default/state");
    let previous_state = fs::read(&state_file).unwrap();
    fs::write(dir.path().join("work.txt"), b"committed").unwrap();
    wc.snapshot(&mut repo).unwrap();
    fs::write(&state_file, previous_state).unwrap();
    fs::write(dir.path().join("work.txt"), b"later edits").unwrap();
    let (mut reopened_repo, mut reopened) =
        WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    let committed = reopened_repo.op_id();
    assert!(reopened
        .snapshot(&mut reopened_repo)
        .unwrap_err()
        .to_string()
        .contains("workspace is stale"));
    assert_eq!(reopened_repo.op_id(), committed);
    assert_eq!(
        fs::read(dir.path().join("work.txt")).unwrap(),
        b"later edits"
    );
}

#[test]
fn snapshot_recovery_checks_ignored_tracked_files() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(dir.path().join(".tigignore"), b"work.txt\n").unwrap();
    wc.snapshot(&mut repo).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("work.txt"), b"remote edit").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let committed = repo.op_id();
    assert!(wc
        .snapshot(&mut repo)
        .unwrap_err()
        .to_string()
        .contains("workspace is stale"));
    assert_eq!(repo.op_id(), committed);
    assert_eq!(fs::read(dir.path().join("work.txt")).unwrap(), b"before");
}

#[test]
fn clean_stale_update_checks_out_without_writing_an_operation() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("work.txt"), b"remote edit").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let committed = repo.op_id();
    let current = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let stats = wc.update_stale(&mut repo).unwrap();
    assert!(stats.saved.is_none());
    assert_eq!(stats.checkout.written, 1);
    assert_eq!(repo.op_id(), committed);
    assert_eq!(repo.working_revision(DEFAULT_WORKSPACE).unwrap(), current);
    assert_eq!(
        fs::read(dir.path().join("work.txt")).unwrap(),
        b"remote edit"
    );
    assert_eq!(wc.snapshot(&mut repo).unwrap().changed, 0);
}

#[test]
fn dirty_stale_update_saves_disk_edits_based_on_recorded_revision() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("work.txt");
    fs::write(&file, b"saved").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let recorded = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let recorded_time = fs::metadata(&file).unwrap().modified().unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("work.txt"), b"remote edit").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let current = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    fs::write(&file, b"local").unwrap();
    backdate(&file, recorded_time);
    fs::write(dir.path().join("added.txt"), b"new local file").unwrap();
    let stats = wc.update_stale(&mut repo).unwrap();
    let saved = stats.saved.expect("local edits saved as a new change");
    let saved_revision = repo.revision(&saved).unwrap();
    assert_eq!(saved_revision.parents, vec![recorded]);
    assert_ne!(
        saved_revision.change_id,
        repo.revision(&recorded).unwrap().change_id
    );
    assert!(repo.view().heads.contains(&saved));
    let saved_ws = Workspace::at_revision(&repo, DEFAULT_WORKSPACE, saved).unwrap();
    assert_eq!(
        saved_ws.read(&repo, &path("work.txt")).unwrap().unwrap(),
        b"local"
    );
    assert_eq!(
        saved_ws.read(&repo, &path("added.txt")).unwrap().unwrap(),
        b"new local file"
    );
    assert_eq!(repo.working_revision(DEFAULT_WORKSPACE).unwrap(), current);
    assert_eq!(fs::read(&file).unwrap(), b"remote edit");
    assert!(!dir.path().join("added.txt").exists());
    assert_eq!(wc.snapshot(&mut repo).unwrap().changed, 0);
}

#[test]
fn rehash_detects_restored_timestamp_edit_and_keeps_checkout_safe() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("work.txt");
    fs::write(&file, b"saved").unwrap();
    backdate(&file, SystemTime::now() - Duration::from_secs(3600));
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let time = fs::metadata(&file).unwrap().modified().unwrap();
    fs::write(&file, b"local").unwrap();
    backdate(&file, time);
    let stats = wc.snapshot_with_rehash(&mut repo, true).unwrap();
    assert_eq!(stats.hashed, stats.scanned);
    assert_eq!(stats.changed, 1);
    let ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    assert_eq!(
        ws.read(&repo, &path("work.txt")).unwrap().unwrap(),
        b"local"
    );
    assert_eq!(wc.checkout(&repo).unwrap().written, 0);
}

#[test]
fn legacy_state_is_rescanned_before_checkout_can_run() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"saved").unwrap();
    let (_repo, _wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(
        dir.path().join(".tig/workspaces/default/state"),
        b"TIGW\x01",
    )
    .unwrap();
    let (mut repo, mut wc) = WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    assert!(wc.checkout(&repo).is_err());
    let stats = wc.snapshot(&mut repo).unwrap();
    assert_eq!(stats.hashed, stats.scanned);
    assert!(stats
        .warnings
        .iter()
        .any(|warning| warning.contains("unsupported version 1")));
    wc.checkout(&repo).unwrap();
}

#[test]
fn dirty_stale_update_preserves_deletions_and_ignored_tracked_edits() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("ignored.txt"), b"before").unwrap();
    fs::write(dir.path().join("deleted.txt"), b"delete me").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(dir.path().join(".tigignore"), b"ignored.txt\n").unwrap();
    wc.snapshot(&mut repo).unwrap();
    let recorded = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("remote.txt"), b"remote addition")
        .unwrap();
    ws.snapshot(&mut repo).unwrap();
    fs::write(dir.path().join("ignored.txt"), b"local ignored edit").unwrap();
    fs::remove_file(dir.path().join("deleted.txt")).unwrap();
    let saved = wc.update_stale(&mut repo).unwrap().saved.unwrap();
    assert_eq!(repo.revision(&saved).unwrap().parents, vec![recorded]);
    let saved_ws = Workspace::at_revision(&repo, DEFAULT_WORKSPACE, saved).unwrap();
    assert_eq!(
        saved_ws.read(&repo, &path("ignored.txt")).unwrap().unwrap(),
        b"local ignored edit"
    );
    assert!(saved_ws
        .read(&repo, &path("deleted.txt"))
        .unwrap()
        .is_none());
    assert_eq!(fs::read(dir.path().join("ignored.txt")).unwrap(), b"before");
    assert_eq!(
        fs::read(dir.path().join("deleted.txt")).unwrap(),
        b"delete me"
    );
    assert_eq!(
        fs::read(dir.path().join("remote.txt")).unwrap(),
        b"remote addition"
    );
}

#[test]
fn stale_directory_replacement_is_saved_before_checkout() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("nested"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("remote.txt"), b"remote addition")
        .unwrap();
    ws.snapshot(&mut repo).unwrap();
    fs::remove_file(dir.path().join("nested")).unwrap();
    fs::create_dir(dir.path().join("nested")).unwrap();
    fs::write(dir.path().join("nested/local.txt"), b"local child").unwrap();
    let saved = wc.update_stale(&mut repo).unwrap().saved.unwrap();
    let saved_ws = Workspace::at_revision(&repo, DEFAULT_WORKSPACE, saved).unwrap();
    assert_eq!(
        saved_ws
            .read(&repo, &path("nested/local.txt"))
            .unwrap()
            .unwrap(),
        b"local child"
    );
    assert_eq!(fs::read(dir.path().join("nested")).unwrap(), b"before");
}

#[test]
fn failed_stale_checkout_reports_saved_change_and_preserves_disk() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"before").unwrap();
    fs::write(dir.path().join(".tigignore"), b"blocked.txt\n").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("blocked.txt"), b"remote addition")
        .unwrap();
    ws.snapshot(&mut repo).unwrap();
    let current = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    fs::write(dir.path().join("work.txt"), b"local edit").unwrap();
    fs::write(dir.path().join("blocked.txt"), b"ignored local file").unwrap();
    let error = wc.update_stale(&mut repo).unwrap_err().to_string();
    assert!(error.contains("saved local edits as"), "{error}");
    assert!(error.contains("stale checkout failed"), "{error}");
    assert_eq!(repo.working_revision(DEFAULT_WORKSPACE).unwrap(), current);
    assert_eq!(
        fs::read(dir.path().join("work.txt")).unwrap(),
        b"local edit"
    );
    assert_eq!(
        fs::read(dir.path().join("blocked.txt")).unwrap(),
        b"ignored local file"
    );
    let saved = repo.view().heads.iter().find(|id| **id != current).unwrap();
    assert!(error.contains(&saved.short(12)), "{error}");
    let saved_ws = Workspace::at_revision(&repo, DEFAULT_WORKSPACE, *saved).unwrap();
    assert_eq!(
        saved_ws.read(&repo, &path("work.txt")).unwrap().unwrap(),
        b"local edit"
    );
}

#[test]
fn snapshot_recovery_does_not_follow_multiple_rewrites_or_description_moves() {
    for description_move in [false, true] {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("work.txt"), b"before").unwrap();
        let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
        let state_file = dir.path().join(".tig/workspaces/default/state");
        let previous_state = fs::read(&state_file).unwrap();
        if description_move {
            let mut tx = repo.start("describe elsewhere");
            let working = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
            tx.rewrite(working, |rev| rev.description = "remote description".into())
                .unwrap();
            repo.commit(tx).unwrap();
        } else {
            fs::write(dir.path().join("work.txt"), b"first edit").unwrap();
            wc.snapshot(&mut repo).unwrap();
            fs::write(dir.path().join("work.txt"), b"second edit").unwrap();
            wc.snapshot(&mut repo).unwrap();
        }
        fs::write(&state_file, previous_state).unwrap();
        let (mut repo, mut wc) = WorkingCopy::open(dir.path(), Settings::default()).unwrap();
        let committed = repo.op_id();
        assert!(wc
            .snapshot(&mut repo)
            .unwrap_err()
            .to_string()
            .contains("workspace is stale"));
        assert_eq!(repo.op_id(), committed);
    }
}

fn tig(root: &Path, args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_tig"))
        .current_dir(root)
        .env("TIG_AUTHOR_NAME", "Ada")
        .env("TIG_AUTHOR_EMAIL", "ada@example.com")
        .env("TIG_TIMESTAMP_MS", "1700000000000")
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8(output.stdout).unwrap(),
        String::from_utf8(output.stderr).unwrap()
    )
}

fn remove_object(root: &Path, id: ObjectId) {
    let hex = id.to_hex();
    fs::remove_file(root.join(".tig/store").join(&hex[..2]).join(&hex[2..])).unwrap();
}

#[test]
fn automatic_operation_recovery_rescans_and_preserves_disk_edits() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"old").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(dir.path().join("work.txt"), b"snapshot").unwrap();
    wc.snapshot(&mut repo).unwrap();
    let lost = repo.op_id();
    remove_object(dir.path(), lost);
    fs::write(dir.path().join("work.txt"), b"later disk edit").unwrap();
    let out = tig(dir.path(), &["snapshot"]);
    assert!(out.contains("recovered operation"), "{out}");
    assert_eq!(
        fs::read(dir.path().join("work.txt")).unwrap(),
        b"later disk edit"
    );
    let (repo, _) = WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    assert_eq!(
        Workspace::open(&repo, DEFAULT_WORKSPACE)
            .unwrap()
            .read(&repo, &path("work.txt"))
            .unwrap()
            .unwrap(),
        b"later disk edit"
    );
    tig(dir.path(), &["status"]);
}

#[test]
fn explicit_recovery_preserves_disk_and_rehashes_tracked_ignored_files() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(dir.path().join(".tigignore"), b"work.txt\n").unwrap();
    wc.snapshot(&mut repo).unwrap();
    let previous = repo.op_id();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("work.txt"), b"lost content").unwrap();
    ws.snapshot(&mut repo).unwrap();
    remove_object(dir.path(), repo.store().put_blob(b"lost content").unwrap());
    fs::write(dir.path().join("work.txt"), b"local ignored edit").unwrap();
    let out = tig(dir.path(), &["op", "recover"]);
    assert!(out.contains(&previous.short(12)), "{out}");
    assert!(out.contains("files on disk preserved"), "{out}");
    assert_eq!(
        fs::read(dir.path().join("work.txt")).unwrap(),
        b"local ignored edit"
    );
    tig(dir.path(), &["snapshot"]);
    let (repo, _) = WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    assert_eq!(
        Workspace::open(&repo, DEFAULT_WORKSPACE)
            .unwrap()
            .read(&repo, &path("work.txt"))
            .unwrap()
            .unwrap(),
        b"local ignored edit"
    );
}

#[test]
fn healthy_recovery_keeps_the_recorded_stale_baseline() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"disk baseline").unwrap();
    let (mut repo, _) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let state_path = dir.path().join(".tig/workspaces/default/state");
    let state = fs::read(&state_path).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("work.txt"), b"remote edit").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let out = tig(dir.path(), &["op", "recover"]);
    assert!(out.contains("is complete"), "{out}");
    assert_eq!(fs::read(&state_path).unwrap(), state);
    let (mut repo, mut wc) = WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    assert!(wc
        .snapshot(&mut repo)
        .unwrap_err()
        .to_string()
        .contains("workspace is stale"));
    assert_eq!(
        fs::read(dir.path().join("work.txt")).unwrap(),
        b"disk baseline"
    );
    tig(dir.path(), &["workspace", "update-stale"]);
    assert_eq!(
        fs::read(dir.path().join("work.txt")).unwrap(),
        b"remote edit"
    );
}

#[test]
fn recovery_during_reload_discards_the_lost_operation_cache() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"before").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    fs::write(dir.path().join("work.txt"), b"after").unwrap();
    wc.snapshot(&mut repo).unwrap();
    remove_object(dir.path(), repo.op_id());
    let stats = wc.snapshot(&mut repo).unwrap();
    assert!(stats
        .warnings
        .iter()
        .any(|warning| warning.contains("recovered operation")));
    assert_eq!(fs::read(dir.path().join("work.txt")).unwrap(), b"after");
}

#[cfg(windows)]
#[test]
fn recovery_rescan_keeps_windows_executable_and_symlink_representations() {
    use tig_core::treeops::{lookup, Leaf};
    use tig_core::EntryKind;
    let dir = TempDir::new().unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let executable = repo.store().put_blob(b"program").unwrap();
    let target = repo.store().put_blob(b"target.txt").unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.set(&repo, path("program"), Some(Leaf::executable(executable)))
        .unwrap();
    ws.set(&repo, path("link"), Some(Leaf::symlink(target)))
        .unwrap();
    ws.snapshot(&mut repo).unwrap();
    wc.checkout(&repo).unwrap();
    // A further operation is lost; recovery must preserve verified baseline kinds.
    fs::write(dir.path().join("other.txt"), b"new").unwrap();
    wc.snapshot(&mut repo).unwrap();
    remove_object(dir.path(), repo.op_id());
    tig(dir.path(), &["op", "recover"]);
    tig(dir.path(), &["snapshot"]);
    let (repo, _) = WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    let tree = repo
        .revision(&repo.working_revision(DEFAULT_WORKSPACE).unwrap())
        .unwrap()
        .tree;
    assert_eq!(
        lookup(repo.store().as_ref(), &tree, &path("program"))
            .unwrap()
            .unwrap()
            .kind(),
        EntryKind::Executable
    );
    assert_eq!(
        lookup(repo.store().as_ref(), &tree, &path("link"))
            .unwrap()
            .unwrap()
            .kind(),
        EntryKind::Symlink
    );
}

#[test]
fn cli_snapshot_rehash_and_stale_update_are_available() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("work.txt"), b"before").unwrap();
    tig(dir.path(), &["init"]);
    let snapshot = tig(dir.path(), &["snapshot", "--rehash"]);
    assert!(
        snapshot.contains("snapshotted 0 changed paths"),
        "{snapshot}"
    );
    let (mut repo, _wc) = WorkingCopy::open(dir.path(), Settings::default()).unwrap();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &path("work.txt"), b"remote edit").unwrap();
    ws.snapshot(&mut repo).unwrap();
    fs::write(dir.path().join("work.txt"), b"local edit").unwrap();
    let updated = tig(dir.path(), &["workspace", "update-stale"]);
    assert!(updated.contains("saved local edits as"), "{updated}");
    assert!(updated.contains("workspace updated"), "{updated}");
    assert_eq!(
        fs::read(dir.path().join("work.txt")).unwrap(),
        b"remote edit"
    );
}
