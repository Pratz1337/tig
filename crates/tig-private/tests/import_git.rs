use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use tig_core::repo::root_revision_id;
use tig_core::store::{Store, StoreExt};
use tig_core::treeops::{lookup, walk};
use tig_core::{EntryKind, MemoryStore, RepoPath};
use tig_private::import_git::{import_git, ImportState};

fn git(dir: &Path, args: &[&str]) -> String {
    let out = command(dir).args(args).output().unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn command(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(dir)
        .args(["-c", "core.autocrlf=false", "-c", "commit.gpgsign=false"])
        .env("GIT_AUTHOR_NAME", "Original author")
        .env("GIT_AUTHOR_EMAIL", "author@example.com")
        .env("GIT_COMMITTER_NAME", "Original committer")
        .env("GIT_COMMITTER_EMAIL", "committer@example.com")
        .env("GIT_AUTHOR_DATE", "1700000000 +0530")
        .env("GIT_COMMITTER_DATE", "1700000010 -0700");
    command
}

fn input(dir: &Path, args: &[&str], data: &[u8]) -> String {
    let mut child = command(dir)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(data).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn init() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q", "-b", "main"]);
    dir
}

fn commit(dir: &Path, message: &str) -> gix::ObjectId {
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-qm", message]);
    gix::ObjectId::from_hex(git(dir, &["rev-parse", "HEAD"]).as_bytes()).unwrap()
}

#[test]
fn linear_merge_rename_metadata_and_incremental_identity() {
    let source = init();
    let dir = source.path();
    fs::write(dir.join("old"), b"base").unwrap();
    let first = commit(dir, "first\n\nBody with UTF-8: café");
    git(dir, &["checkout", "-qb", "side"]);
    fs::write(dir.join("side"), b"side contents").unwrap();
    let side = commit(dir, "side");
    git(dir, &["checkout", "-q", "main"]);
    git(dir, &["mv", "old", "renamed"]);
    let renamed = commit(dir, "rename");
    git(dir, &["merge", "-q", "--no-ff", "side", "-m", "merge"]);
    let merge = gix::ObjectId::from_hex(git(dir, &["rev-parse", "HEAD"]).as_bytes()).unwrap();
    let store = MemoryStore::new();
    let mut state = ImportState::new(false).unwrap();
    let report = import_git(dir, &store, &mut state).unwrap();
    assert_eq!(report.imported, 4);
    assert_eq!(report.bookmarks["side"], state.revisions[&side]);
    assert_eq!(report.head, Some(report.bookmarks["main"]));
    let base = store.get_revision(&state.revisions[&first]).unwrap();
    assert_eq!(base.parents, vec![root_revision_id()]);
    assert_eq!(base.author.name, "Original author");
    assert_eq!(base.author.email, "author@example.com");
    assert_eq!(base.author.timestamp_ms, 1_700_000_000_000);
    assert_eq!(base.author.tz_offset_min, 330);
    assert_eq!(base.committer.name, "Original committer");
    assert_eq!(base.committer.timestamp_ms, 1_700_000_010_000);
    assert_eq!(base.committer.tz_offset_min, -420);
    assert_eq!(base.description, "first\n\nBody with UTF-8: café\n");
    let merged = store.get_revision(&state.revisions[&merge]).unwrap();
    assert_eq!(
        merged.parents,
        vec![state.revisions[&renamed], state.revisions[&side]]
    );
    assert!(lookup(&store, &merged.tree, &RepoPath::new("old").unwrap())
        .unwrap()
        .is_none());
    assert!(
        lookup(&store, &merged.tree, &RepoPath::new("renamed").unwrap())
            .unwrap()
            .is_some()
    );
    let count = store.len();
    let saved = state.encode();
    state = ImportState::decode(&saved).unwrap();
    let repeat = import_git(dir, &store, &mut state).unwrap();
    assert_eq!(repeat.imported, 0);
    assert_eq!(repeat.reused, 4);
    assert_eq!(store.len(), count);
    assert_eq!(&*state.encode(), &*saved);
    fs::write(dir.join("new"), b"incremental").unwrap();
    commit(dir, "next");
    let next = import_git(dir, &store, &mut state).unwrap();
    assert_eq!((next.imported, next.reused), (1, 4));
}

#[test]
fn deleted_env_is_reported_and_strip_removes_it_without_storing_its_blob() {
    let source = init();
    let dir = source.path();
    const SECRET: &[u8] = b"unique-history-secret";
    fs::write(dir.join(".env"), SECRET).unwrap();
    fs::write(dir.join(".private"), b"secrets/\n!secrets/README\n").unwrap();
    fs::create_dir(dir.join("secrets")).unwrap();
    fs::write(dir.join("secrets/token"), b"other secret").unwrap();
    fs::write(dir.join("secrets/README"), b"public").unwrap();
    commit(dir, "secrets once existed");
    fs::remove_file(dir.join(".env")).unwrap();
    fs::remove_file(dir.join(".private")).unwrap();
    fs::remove_dir_all(dir.join("secrets")).unwrap();
    fs::write(dir.join("public"), b"later").unwrap();
    commit(dir, "deleted");
    let store = MemoryStore::new();
    let mut state = ImportState::new(false).unwrap();
    import_git(dir, &store, &mut state).unwrap();
    let env = RepoPath::new(".env").unwrap();
    assert!(state.exposed.contains(&env));
    assert!(state
        .exposed
        .contains(&RepoPath::new("secrets/token").unwrap()));
    assert!(!state
        .exposed
        .contains(&RepoPath::new("secrets/README").unwrap()));
    let store = MemoryStore::new();
    let mut stripped = ImportState::decode(&state.encode()).unwrap();
    stripped.strip_private = true;
    stripped.revisions.clear();
    stripped.exposed.clear();
    let report = import_git(dir, &store, &mut stripped).unwrap();
    assert!(report.matched.contains(&env));
    assert!(stripped.exposed.is_empty());
    assert!(!store
        .has(&tig_core::object::hash_object(
            tig_core::ObjectKind::Blob,
            SECRET
        ))
        .unwrap());
    for (git, id) in &stripped.revisions {
        let revision = store.get_revision(id).unwrap();
        assert!(lookup(&store, &revision.tree, &env).unwrap().is_none());
        assert_ne!(revision.change_id, state.change_id(git));
        assert!(!walk(&store, &revision.tree, &RepoPath::root())
            .unwrap()
            .iter()
            .any(|(path, _)| path.as_str() == "secrets/token"));
    }
    let repeated = import_git(dir, &store, &mut stripped).unwrap();
    assert_eq!((repeated.imported, repeated.reused), (0, 2));
}

#[test]
fn modes_submodules_and_invalid_names_are_handled_without_checkout() {
    let source = init();
    let dir = source.path();
    fs::write(dir.join("base"), "base").unwrap();
    let parent = commit(dir, "base").to_string();
    let blob = input(dir, &["hash-object", "-w", "--stdin"], b"target");
    let hidden = input(
        dir,
        &["mktree"],
        format!("100644 blob {blob}\t.env\n").as_bytes(),
    );
    let lines = format!("100644 blob {blob}\tordinary\n100755 blob {blob}\texecutable\n120000 blob {blob}\tlink\n160000 commit {parent}\tsubmodule\n100644 blob {blob}\tbad:name\n100644 blob {blob}\tname:key.key\n040000 tree {hidden}\tbad:dir\n100644 blob {blob}\t.TiG\n");
    let tree = input(dir, &["mktree"], lines.as_bytes());
    let tip = git(dir, &["commit-tree", &tree, "-p", &parent, "-m", "modes"]);
    git(dir, &["update-ref", "refs/heads/main", &tip]);
    let store = MemoryStore::new();
    let mut state = ImportState::new(false).unwrap();
    let report = import_git(dir, &store, &mut state).unwrap();
    let rev = store.get_revision(&report.head.unwrap()).unwrap();
    let at = |name| {
        lookup(&store, &rev.tree, &RepoPath::new(name).unwrap())
            .unwrap()
            .unwrap()
    };
    assert_eq!(at("ordinary").kind(), EntryKind::File);
    assert_eq!(at("executable").kind(), EntryKind::Executable);
    assert_eq!(at("link").kind(), EntryKind::Symlink);
    assert_eq!(store.get_blob(&at("link").id()).unwrap(), b"target");
    assert!(
        lookup(&store, &rev.tree, &RepoPath::new("submodule").unwrap())
            .unwrap()
            .is_none()
    );
    for path in ["submodule", "bad:name", ".TiG"] {
        assert!(
            report.warnings.iter().any(|warning| warning.contains(path)),
            "{path}"
        );
    }
    for path in ["bad:dir/.env", "name:key.key"] {
        assert!(
            report.warnings.iter().any(|warning| warning.contains(path)
                && warning.contains("already exposed in git history — rotate these secrets")),
            "{path}"
        );
    }
}

#[test]
fn sha256_bare_history_and_empty_trees_are_preserved() {
    let source = tempfile::tempdir().unwrap();
    let dir = source.path();
    git(
        dir,
        &[
            "init",
            "-q",
            "--bare",
            "--object-format=sha256",
            "-b",
            "main",
        ],
    );
    let blob = input(dir, &["hash-object", "-w", "--stdin"], b"SHA-256 contents");
    let empty = input(dir, &["mktree"], b"");
    let lines = format!("100644 blob {blob}\tfile\n040000 tree {empty}\tempty\n");
    let tree = input(dir, &["mktree"], lines.as_bytes());
    let tip = git(dir, &["commit-tree", &tree, "-m", "SHA-256 bare history"]);
    git(dir, &["update-ref", "refs/heads/main", &tip]);
    let store = MemoryStore::new();
    let mut state = ImportState::new(false).unwrap();
    let report = import_git(dir, &store, &mut state).unwrap();
    assert_eq!(report.imported, 1);
    let revision = store.get_revision(&report.head.unwrap()).unwrap();
    let path = RepoPath::new("empty").unwrap();
    let empty_entry = lookup(&store, &revision.tree, &path).unwrap();
    assert!(
        empty_entry.is_some(),
        "an explicit empty Git tree must survive import"
    );
    assert_eq!(empty_entry.unwrap().id(), tig_core::store::empty_tree_id());
    let saved = state.encode();
    let mut state = ImportState::decode(&saved).unwrap();
    assert_eq!(import_git(dir, &store, &mut state).unwrap().reused, 1);
    assert_eq!(&*state.encode(), &*saved);
}

#[test]
fn non_utf8_subtrees_report_each_unclassifiable_leaf_without_importing_it() {
    let source = init();
    let dir = source.path();
    let blob = input(
        dir,
        &["hash-object", "-w", "--stdin"],
        b"skipped secret bytes",
    );
    let hidden = input(
        dir,
        &["mktree"],
        format!("100644 blob {blob}\t.env\n").as_bytes(),
    );
    let mut entry = format!("040000 tree {hidden}\t").into_bytes();
    entry.extend_from_slice(&[b'b', 0xff, 0]);
    let tree = input(dir, &["mktree", "-z"], &entry);
    let tip = git(dir, &["commit-tree", &tree, "-m", "non-UTF-8"]);
    git(dir, &["update-ref", "refs/heads/main", &tip]);
    let store = MemoryStore::new();
    let mut state = ImportState::new(false).unwrap();
    let report = import_git(dir, &store, &mut state).unwrap();
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("62ff2f2e656e76 cannot be classified as UTF-8")));
    assert!(!store
        .has(&tig_core::object::hash_object(
            tig_core::ObjectKind::Blob,
            b"skipped secret bytes"
        ))
        .unwrap());
}

#[test]
fn tags_detached_head_empty_repo_and_invalid_rules() {
    let source = init();
    let dir = source.path();
    let store = MemoryStore::new();
    let mut state = ImportState::new(false).unwrap();
    assert_eq!(import_git(dir, &store, &mut state).unwrap().imported, 0);
    fs::write(dir.join("tagged"), b"tag history").unwrap();
    let tagged = commit(dir, "tagged");
    git(dir, &["tag", "-a", "keep", "-m", "tag"]);
    git(dir, &["checkout", "-q", "--orphan", "main2"]);
    git(dir, &["rm", "-q", "-rf", "."]);
    fs::write(dir.join("new-root"), b"another root").unwrap();
    let detached = commit(dir, "unrelated");
    git(dir, &["branch", "-D", "main"]);
    git(dir, &["checkout", "-q", "--detach"]);
    let report = import_git(dir, &store, &mut state).unwrap();
    assert!(state.revisions.contains_key(&tagged));
    assert_eq!(report.head, Some(state.revisions[&detached]));
    fs::write(dir.join(".private"), b"[bad\n").unwrap();
    commit(dir, "invalid rules");
    let saved = state.encode();
    assert!(import_git(dir, &store, &mut state).is_err());
    assert_eq!(&*state.encode(), &*saved);
}

#[test]
fn import_identity_encoding_is_frozen_and_malformed_state_is_refused() {
    let mut bytes = vec![1, 0];
    bytes.extend_from_slice(&[7; 32]);
    bytes.extend_from_slice(&[0, 0]);
    let state = ImportState::decode(&bytes).unwrap();
    assert_eq!(&*state.encode(), &bytes);
    let git = gix::ObjectId::from_hex("01".repeat(20).as_bytes()).unwrap();
    assert_eq!(
        hex::encode(state.change_id(&git).0),
        "a499b23a46e782e59b477ecb5d3e4f80"
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(ImportState::decode(&trailing).is_err());
    for end in 0..bytes.len() {
        assert!(ImportState::decode(&bytes[..end]).is_err());
    }
    let mut bad_flag = bytes;
    bad_flag[1] = 2;
    assert!(ImportState::decode(&bad_flag).is_err());
}

#[test]
fn strip_removes_historically_private_paths_from_every_revision() {
    let source = init();
    let dir = source.path();
    const SECRET: &[u8] = b"public-before-the-rule-history-secret";
    fs::write(dir.join("settings.cfg"), SECRET).unwrap();
    commit(dir, "before the private rule");
    fs::write(dir.join(".private"), b"settings.cfg\n").unwrap();
    commit(dir, "now private");
    let store = MemoryStore::new();
    let mut state = ImportState::new(true).unwrap();
    import_git(dir, &store, &mut state).unwrap();
    let path = RepoPath::new("settings.cfg").unwrap();
    for id in state.revisions.values() {
        let revision = store.get_revision(id).unwrap();
        assert!(lookup(&store, &revision.tree, &path).unwrap().is_none());
    }
    assert!(!store
        .has(&tig_core::object::hash_object(
            tig_core::ObjectKind::Blob,
            SECRET
        ))
        .unwrap());
    fs::write(dir.join("later.cfg"), b"later public").unwrap();
    commit(dir, "valid incremental extension");
    assert_eq!(import_git(dir, &store, &mut state).unwrap().imported, 1);
    let saved = state.encode();
    fs::write(dir.join(".private"), b"settings.cfg\nlater.cfg\n").unwrap();
    commit(dir, "retroactive private classification");
    let error = import_git(dir, &store, &mut state).err().unwrap();
    assert!(error.to_string().contains("fresh destination"), "{error}");
    assert_eq!(&*state.encode(), &*saved);
}
