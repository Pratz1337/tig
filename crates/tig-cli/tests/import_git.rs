use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tig_cli::wc::WorkingCopy;
use tig_core::repo::Settings;

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["-c", "commit.gpgsign=false", "-c", "core.autocrlf=false"])
        .args(args)
        .env("GIT_AUTHOR_NAME", "original")
        .env("GIT_AUTHOR_EMAIL", "original@x")
        .env("GIT_COMMITTER_NAME", "original")
        .env("GIT_COMMITTER_EMAIL", "original@x")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn tig(dir: &Path, args: &[&str], paths: &[&Path]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tig"));
    cmd.arg("-R")
        .arg(dir)
        .args(args)
        .args(paths)
        .env("TIG_AUTHOR_NAME", "importer")
        .env("TIG_AUTHOR_EMAIL", "importer@x")
        .env("TIG_IDENTITY_PASSPHRASE", "tig test identity passphrase")
        .env(
            "TIG_IDENTITY_FILE",
            dir.parent().unwrap().join("importer.id"),
        );
    cmd.output().unwrap()
}

fn ok(output: &Output) -> String {
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn source(root: &Path) -> std::path::PathBuf {
    let source = root.join("source");
    fs::create_dir(&source).unwrap();
    git(&source, &["init", "-q", "-b", "main"]);
    fs::write(source.join(".env"), b"once-in-Git-secret").unwrap();
    fs::write(source.join("public"), b"public").unwrap();
    git(&source, &["add", "-A"]);
    git(&source, &["commit", "-qm", "first"]);
    fs::remove_file(source.join(".env")).unwrap();
    git(&source, &["add", "-A"]);
    git(&source, &["commit", "-qm", "deleted"]);
    source
}

#[test]
fn import_checks_out_head_preserves_work_on_reimport_and_seeds_first_publish() {
    let tmp = tempfile::tempdir().unwrap();
    let source = source(tmp.path());
    let dest = tmp.path().join("tig");
    let out = tig(&dest, &["import-git"], &[&source]);
    assert!(ok(&out).contains("imported 2 revisions"));
    let warnings = String::from_utf8_lossy(&out.stderr);
    assert!(warnings.contains(".env: already exposed in git history — rotate these secrets"));
    assert_eq!(fs::read(dest.join("public")).unwrap(), b"public");
    assert!(!dest.join(".env").exists());
    assert!(!dest.join(".private").exists());
    let (repo, _) = WorkingCopy::open(&dest, Settings::default()).unwrap();
    let working = repo
        .revision(&repo.working_revision("default").unwrap())
        .unwrap();
    let head = repo.view().bookmarks["main"];
    assert_eq!(working.parents, vec![head]);
    let op = repo.op_id();
    drop(repo);
    assert!(ok(&tig(&dest, &["import-git"], &[&source])).contains("imported 0 revisions; reused 2"));
    let (repo, _) = WorkingCopy::open(&dest, Settings::default()).unwrap();
    assert_eq!(
        repo.op_id(),
        op,
        "idempotent re-import must not add an operation"
    );
    drop(repo);
    fs::write(dest.join("public"), b"local work").unwrap();
    fs::write(source.join("new"), b"source update").unwrap();
    git(&source, &["add", "-A"]);
    git(&source, &["commit", "-qm", "incremental"]);
    assert!(ok(&tig(&dest, &["import-git"], &[&source])).contains("imported 1 revisions; reused 2"));
    assert_eq!(fs::read(dest.join("public")).unwrap(), b"local work");
    let remote = tmp.path().join("remote");
    ok(&tig(&dest, &["remote", "add", "origin"], &[&remote]));
    let refused = tig(&dest, &["publish", "origin"], &[]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("already leaked"));
    assert!(!remote.join("keyring").exists());
    ok(&tig(
        &dest,
        &["publish", "origin", "--acknowledge-leaked"],
        &[],
    ));
}

#[test]
fn stripped_import_publishes_without_leak_ack_and_rejects_mode_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let source = source(tmp.path());
    let dest = tmp.path().join("stripped");
    let out = tig(&dest, &["import-git", "--strip-private"], &[&source]);
    ok(&out);
    assert!(String::from_utf8_lossy(&out.stderr).contains("stripped private path: .env"));
    let (repo, _) = WorkingCopy::open(&dest, Settings::default()).unwrap();
    for (_, revision) in repo.visible_revisions().unwrap() {
        assert!(tig_core::treeops::lookup(
            repo.store().as_ref(),
            &revision.tree,
            &tig_core::RepoPath::new(".env").unwrap()
        )
        .unwrap()
        .is_none());
    }
    drop(repo);
    let wrong_mode = tig(&dest, &["import-git"], &[&source]);
    assert!(!wrong_mode.status.success());
    assert!(String::from_utf8_lossy(&wrong_mode.stderr).contains("same --strip-private mode"));
    ok(&tig(&dest, &["import-git", "--strip-private"], &[&source]));
    let remote = tmp.path().join("remote");
    ok(&tig(&dest, &["remote", "add", "origin"], &[&remote]));
    ok(&tig(&dest, &["publish", "origin"], &[]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(dest.join(".tig/git-import"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn retry_after_object_and_state_writes_still_attaches_head() {
    use tig_core::store::DiskStore;
    use tig_private::import_git::{import_git, ImportState};
    let tmp = tempfile::tempdir().unwrap();
    let source = source(tmp.path());
    let dest = tmp.path().join("retry");
    let (_repo, _wc) = WorkingCopy::init_for_import(&dest, Settings::default()).unwrap();
    let bulk = DiskStore::open(dest.join(".tig/store")).unwrap();
    let mut state = ImportState::new(false).unwrap();
    let report = import_git(&source, &bulk, &mut state).unwrap();
    fs::write(dest.join(".tig/git-import"), &*state.encode()).unwrap();
    // No view transaction occurred before the simulated crash.
    drop(_repo);
    drop(_wc);
    assert!(ok(&tig(&dest, &["import-git"], &[&source])).contains("reused 2"));
    let (repo, _) = WorkingCopy::open(&dest, Settings::default()).unwrap();
    let working = repo
        .revision(&repo.working_revision("default").unwrap())
        .unwrap();
    assert_eq!(working.parents, vec![report.head.unwrap()]);
    assert_eq!(fs::read(dest.join("public")).unwrap(), b"public");
}

#[cfg(unix)]
#[test]
fn imported_executable_and_symlink_are_checked_out_with_their_modes() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let tmp = tempfile::tempdir().unwrap();
    let source = source(tmp.path());
    fs::write(source.join("run"), b"#!/bin/sh\n").unwrap();
    fs::set_permissions(source.join("run"), fs::Permissions::from_mode(0o755)).unwrap();
    symlink("run", source.join("link")).unwrap();
    git(&source, &["add", "-A"]);
    git(&source, &["commit", "-qm", "modes"]);
    let dest = tmp.path().join("modes");
    ok(&tig(&dest, &["import-git"], &[&source]));
    assert_eq!(
        fs::metadata(dest.join("run")).unwrap().permissions().mode() & 0o111,
        0o111
    );
    assert_eq!(fs::read_link(dest.join("link")).unwrap(), Path::new("run"));
}
