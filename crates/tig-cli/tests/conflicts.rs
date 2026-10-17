use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tig_cli::wc::WorkingCopy;
use tig_core::repo::{Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::store::StoreExt;
use tig_core::treeops::{apply_edits, lookup, Leaf};
use tig_core::{EntryKind, ObjectId, RepoPath};

fn p(path: &str) -> RepoPath {
    RepoPath::new(path).unwrap()
}

fn branch(repo: &mut Repo, parent: ObjectId, path: &str, bytes: &[u8]) -> ObjectId {
    let tree = apply_edits(
        repo.store().as_ref(),
        &repo.revision(&parent).unwrap().tree,
        &[(
            p(path),
            Some(Leaf::file(repo.store().put_blob(bytes).unwrap())),
        )]
        .into(),
    )
    .unwrap();
    let mut tx = repo.start("branch");
    let child = tx.new_change(&[parent], "branch").unwrap();
    let child = tx.rewrite(child, |rev| rev.tree = tree).unwrap();
    repo.commit(tx).unwrap();
    child
}

fn command(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tig"))
        .current_dir(root)
        .env("TIG_AUTHOR_NAME", "Conflict test")
        .env("TIG_AUTHOR_EMAIL", "conflict@example.com")
        .env("TIG_IDENTITY_PASSPHRASE", "tig test identity passphrase").env("TIG_IDENTITY_FILE", root.join(".tig/test-identity"))
        .args(args)
        .output()
        .unwrap()
}
fn run(root: &Path, args: &[&str]) -> String {
    let out = command(root, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}
fn leaf(root: &Path, path: &str) -> Leaf {
    let (repo, _) = WorkingCopy::open(root, Settings::default()).unwrap();
    lookup(
        repo.store().as_ref(),
        &repo
            .revision(&repo.working_revision(DEFAULT_WORKSPACE).unwrap())
            .unwrap()
            .tree,
        &p(path),
    )
    .unwrap()
    .unwrap()
}

#[test]
fn markers_drafts_resolution_and_undo_survive_reopening_and_rehash() {
    let dir = tempfile::tempdir().unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let root = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let base = branch(&mut repo, root, "file", b"base");
    let mut parents = Vec::new();
    for bytes in [b"A", b"B", b"C"] {
        parents.push(branch(&mut repo, base, "file", bytes));
    }
    let mut tx = repo.start("merge");
    let merged = tx.new_change(&parents, "merge").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, merged).unwrap();
    tx.set_bookmark("merge", merged).unwrap();
    tx.set_bookmark("base", base).unwrap();
    repo.commit(tx).unwrap();
    wc.checkout(&repo).unwrap();
    let original = fs::read(dir.path().join("file")).unwrap();
    assert_eq!(leaf(dir.path(), "file").kind(), EntryKind::Conflict);
    for _ in 0..3 {
        assert!(run(dir.path(), &["status"]).contains("C file"));
    }
    assert_eq!(run(dir.path(), &["status", "--short"]), "C file\n");
    assert_eq!(run(dir.path(), &["status", "-z"]), "C file\0");
    run(dir.path(), &["snapshot", "--rehash"]);
    assert_eq!(
        leaf(dir.path(), "file").id(),
        leaf_of_revision(&repo, merged, "file").id()
    );
    assert!(run(dir.path(), &["diff"]).contains("Conflict file"));
    run(dir.path(), &["new", "-m", "inherited conflict"]);
    assert!(run(dir.path(), &["diff"]).contains("Conflict file"));
    run(dir.path(), &["edit", "merge"]);
    let draft = String::from_utf8(original)
        .unwrap()
        .replace("[File]", "[File] draft");
    fs::write(dir.path().join("file"), &draft).unwrap();
    run(dir.path(), &["status"]);
    assert_eq!(leaf(dir.path(), "file").kind(), EntryKind::Conflict);
    run(dir.path(), &["edit", "base"]);
    run(dir.path(), &["edit", "merge"]);
    assert_eq!(fs::read(dir.path().join("file")).unwrap(), draft.as_bytes());
    fs::write(dir.path().join("file"), b"resolved\n").unwrap();
    run(dir.path(), &["status"]);
    assert_eq!(leaf(dir.path(), "file").kind(), EntryKind::File);
    run(dir.path(), &["undo"]);
    assert_eq!(leaf(dir.path(), "file").kind(), EntryKind::Conflict);
    assert_eq!(fs::read(dir.path().join("file")).unwrap(), draft.as_bytes());
    fs::remove_file(dir.path().join(".tig/workspaces/default/state")).unwrap();
    run(dir.path(), &["snapshot", "--rehash"]);
    assert_eq!(leaf(dir.path(), "file").kind(), EntryKind::Conflict);
    fs::remove_file(dir.path().join("file")).unwrap();
    fs::create_dir(dir.path().join("file")).unwrap();
    fs::write(dir.path().join("file/chosen"), b"manual directory resolution").unwrap();
    assert!(!run(dir.path(), &["status"]).contains("C file"));
    assert_eq!(leaf(dir.path(), "file").kind(), EntryKind::Tree);
    assert!(!run(dir.path(), &["status"]).contains("C file"));
}

fn leaf_of_revision(repo: &Repo, id: ObjectId, path: &str) -> Leaf {
    lookup(
        repo.store().as_ref(),
        &repo.revision(&id).unwrap().tree,
        &p(path),
    )
    .unwrap()
    .unwrap()
}

#[test]
fn structural_sides_can_be_selected_and_conflicted_history_cannot_publish_or_export() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join(".private"), b"file\n").unwrap();
    let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
    let root = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let base = branch(&mut repo, root, "file", b"base");
    let a = branch(&mut repo, base, "file/child", b"directory bytes");
    let b = branch(&mut repo, base, "file", b"file bytes");
    let mut tx = repo.start("merge");
    let merged = tx.new_change(&[a, b], "merge").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, merged).unwrap();
    tx.set_bookmark("main", merged).unwrap();
    repo.commit(tx).unwrap();
    wc.checkout(&repo).unwrap();
    let conflict = repo
        .store()
        .get_conflict(&leaf_of_revision(&repo, merged, "file").id())
        .unwrap();
    let tree_side = conflict
        .adds()
        .iter()
        .position(|leaf| leaf.is_some_and(|leaf| leaf.kind() == EntryKind::Tree))
        .unwrap()
        + 1;
    let remote = dir.path().join(".tig/test-remote");
    run(
        dir.path(),
        &["remote", "add", "test", remote.to_str().unwrap()],
    );
    let pub_out = command(dir.path(), &["publish", "test"]);
    assert!(!pub_out.status.success());
    assert!(String::from_utf8_lossy(&pub_out.stderr).contains("unresolved conflict"));
    assert!(!remote.join("manifest").exists());
    assert!(!remote.join("keyring").exists());
    let git = dir.path().join(".tig/test-export.git");
    let export = command(dir.path(), &["export-git", git.to_str().unwrap()]);
    assert!(!export.status.success());
    assert!(String::from_utf8_lossy(&export.stderr).contains("unresolved conflict"));
    run(
        dir.path(),
        &["resolve", "file", "--side", &tree_side.to_string()],
    );
    assert_eq!(
        fs::read(dir.path().join("file/child")).unwrap(),
        b"directory bytes"
    );
    assert!(!run(dir.path(), &["status"]).contains("unresolved conflict"));
    run(dir.path(), &["publish", "test"]);
    run(dir.path(), &["export-git", git.to_str().unwrap()]);
}
