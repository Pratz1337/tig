use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::process::Command;

use tig_core::repo::root_revision_id;
use tig_core::seal::SealedId;
use tig_core::store::{empty_tree_id, StoreExt};
use tig_core::treeops::{apply_edits, lookup, Leaf};
use tig_core::{ChangeId, EntryKind, MemoryStore, Object, ObjectId, RepoPath, Revision, Signature};
use tig_private::export_git::{export_git, ExportOptions, ExportState};
use tig_private::import_git::{import_git, ImportState};

const SECRET: &[u8] = b"export-git-secret-bytes-9f3a";
const PUBLIC: &[u8] = b"public-readme";

#[test]
fn chunked_public_file_exports_exact_git_bytes_and_imports_chunked() {
    let store = MemoryStore::new();
    let mut bytes = vec![23; 9 * 1024 * 1024];
    bytes[4 * 1024 * 1024] = 61;
    let id = tig_core::blob::put_bytes(&store, &bytes).unwrap();
    let root = apply_edits(&store, &empty_tree_id(), &BTreeMap::from([
        (RepoPath::new("large.bin").unwrap(), Some(Leaf::file(id))),
    ])).unwrap();
    let rev = revision(&store, root, &[root_revision_id()], "large file");
    let dir = tempfile::tempdir().unwrap();
    export_to(dir.path(), &store, &marks(&[("main", rev)]));
    let output = Command::new("git").current_dir(dir.path())
        .args(["cat-file", "blob", "main:large.bin"]).output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, bytes);
    let imported = MemoryStore::new();
    let mut state = ImportState::new(false).unwrap();
    let report = import_git(dir.path(), &imported, &mut state).unwrap();
    let tree = imported.get_revision(&report.bookmarks["main"]).unwrap().tree;
    let leaf = lookup(&imported, &tree, &RepoPath::new("large.bin").unwrap()).unwrap().unwrap();
    assert_eq!(leaf.id(), id);
    assert_eq!(imported.get_blob(&leaf.id()).unwrap(), bytes);
}

#[test]
fn private_chunk_copied_to_public_file_is_refused_before_git_objects() {
    let store = MemoryStore::new();
    let bytes = vec![47; tig_core::blob::CHUNK_LEN + 1];
    let private = tig_core::blob::put_bytes(&store, &bytes).unwrap();
    let chunk = tig_core::blob::content_ids(&store, &private).unwrap()[0];
    let mut root = tree(&store, &[(".private", b"secrets/\n")]);
    root = apply_edits(&store, &root, &BTreeMap::from([
        (RepoPath::new("secrets/file").unwrap(), Some(Leaf::file(private))),
        (RepoPath::new("public.bin").unwrap(), Some(Leaf::file(chunk))),
    ])).unwrap();
    let rev = revision(&store, root, &[root_revision_id()], "chunk paste");
    let dir = tempfile::tempdir().unwrap();
    let error = export_git(dir.path(), &store, &marks(&[("main", rev)]),
        &mut ExportState::default(), &ExportOptions::default()).unwrap_err();
    assert!(matches!(error, tig_private::export_git::ExportError::PastedSecret { .. }));
}

#[test]
fn legacy_blob_copy_of_chunked_private_bytes_is_refused() {
    let store = MemoryStore::new();
    let bytes = vec![37; tig_core::blob::CHUNK_LEN + 1];
    let private = store.put_blob(&bytes).unwrap();
    let legacy = store.put(&Object::Blob(bytes)).unwrap();
    assert_ne!(private, legacy);
    let root = apply_edits(&store, &tree(&store, &[(".private", b"secrets/\n")]), &BTreeMap::from([
        (RepoPath::new("secrets/file").unwrap(), Some(Leaf::file(private))),
        (RepoPath::new("public.bin").unwrap(), Some(Leaf::file(legacy))),
    ])).unwrap();
    let rev = revision(&store, root, &[root_revision_id()], "legacy paste");
    let dir = tempfile::tempdir().unwrap();
    let error = export_git(dir.path(), &store, &marks(&[("main", rev)]),
        &mut ExportState::default(), &ExportOptions::default()).unwrap_err();
    assert!(matches!(error, tig_private::export_git::ExportError::PastedSecret { .. }));
}

#[test]
fn ambiguous_double_star_rules_omit_private_files_and_warn() {
    let store = MemoryStore::new();
    let rev = revision(
        &store,
        tree(
            &store,
            &[
                (".private", b"a**/b\n"),
                ("ax/y/b", SECRET),
                ("README", PUBLIC),
            ],
        ),
        &[root_revision_id()],
        "compatibility",
    );
    let dir = tempfile::tempdir().unwrap();
    let report = export_git(
        dir.path(),
        &store,
        &marks(&[("main", rev)]),
        &mut ExportState::default(),
        &ExportOptions::default(),
    )
    .unwrap();
    assert!(!git(dir.path(), &["ls-tree", "-r", "--name-only", "main"]).contains("ax/y/b"));
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("Git versions") && !warning.contains("ax/y/b")));
}

#[test]
fn deep_tree_export_does_not_overflow_the_stack() {
    if let Some(destination) = std::env::var_os("TIG_EXPORT_DEPTH_CHILD") {
        let store = MemoryStore::new();
        let mut root = tree(&store, &[("README", PUBLIC)]);
        for _ in 1..tig_core::treeops::MAX_TREE_DEPTH {
            let entry = tig_core::TreeEntry::new("d", EntryKind::Tree, root).unwrap();
            root = store
                .put(&Object::Tree(tig_core::Tree::new(vec![entry]).unwrap()))
                .unwrap();
        }
        let rev = revision(&store, root, &[root_revision_id()], "deep");
        export_to(Path::new(&destination), &store, &marks(&[("main", rev)]));
        return;
    }
    // Stack overflow aborts rather than unwinds: isolate the regression in a
    // child, while the parent owns and cleans up the destination directory.
    let dir = tempfile::tempdir().unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "deep_tree_export_does_not_overflow_the_stack",
            "--nocapture",
        ])
        .env("TIG_EXPORT_DEPTH_CHILD", dir.path())
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}

#[test]
fn unicode_destination_names_are_regular_repositories() {
    let store = MemoryStore::new();
    let rev = revision(
        &store,
        tree(&store, &[("README", PUBLIC)]),
        &[root_revision_id()],
        "unicode",
    );
    let dir = tempfile::tempdir().unwrap();
    let destination = dir.path().join("仓库");
    export_to(&destination, &store, &marks(&[("main", rev)]));
    assert!(destination.join(".git").is_dir());
}

#[test]
fn cached_commits_do_not_hide_missing_trees_or_blobs() {
    for object in ["main", "main^{tree}", "main:README"] {
        let store = MemoryStore::new();
        let rev = revision(
            &store,
            tree(&store, &[("README", PUBLIC)]),
            &[root_revision_id()],
            "complete",
        );
        let dir = tempfile::tempdir().unwrap();
        let bookmarks = marks(&[("main", rev)]);
        let (mut state, original) = export_to(dir.path(), &store, &bookmarks);
        let missing = git(dir.path(), &["rev-parse", object]);
        fs::remove_file(
            dir.path()
                .join(".git/objects")
                .join(&missing[..2])
                .join(&missing[2..]),
        )
        .unwrap();
        export_git(
            dir.path(),
            &store,
            &bookmarks,
            &mut state,
            &ExportOptions::default(),
        )
        .unwrap();
        assert_eq!(
            git(dir.path(), &["rev-parse", "main"]),
            original.to_string()
        );
        git(dir.path(), &["fsck", "--full"]);
    }
}

#[test]
fn corrupt_cached_objects_refuse_export_without_moving_refs_or_state() {
    for object in ["main", "main^{tree}", "main:README"] {
        let store = MemoryStore::new();
        let rev = revision(
            &store,
            tree(&store, &[("README", PUBLIC)]),
            &[root_revision_id()],
            "valid",
        );
        let dir = tempfile::tempdir().unwrap();
        let bookmarks = marks(&[("main", rev)]);
        let (mut state, original) = export_to(dir.path(), &store, &bookmarks);
        let saved = state.encode();
        let corrupt = git(dir.path(), &["rev-parse", object]);
        fs::write(
            dir.path()
                .join(".git/objects")
                .join(&corrupt[..2])
                .join(&corrupt[2..]),
            b"truncated",
        )
        .unwrap();
        assert!(export_git(
            dir.path(),
            &store,
            &bookmarks,
            &mut state,
            &ExportOptions::default()
        )
        .is_err());
        assert_eq!(state.encode(), saved);
        assert_eq!(
            git(dir.path(), &["rev-parse", "main"]),
            original.to_string()
        );
    }
}

fn sig(name: &str, email: &str, ms: i64, tz: i32) -> Signature {
    Signature {
        name: name.into(),
        email: email.into(),
        timestamp_ms: ms,
        tz_offset_min: tz,
    }
}

fn p(text: &str) -> RepoPath {
    RepoPath::new(text).unwrap()
}

fn tree(store: &MemoryStore, files: &[(&str, &[u8])]) -> ObjectId {
    let edits = files
        .iter()
        .map(|(path, data)| (p(path), Some(Leaf::file(store.put_blob(data).unwrap()))))
        .collect();
    apply_edits(store, &empty_tree_id(), &edits).unwrap()
}

fn revision(
    store: &MemoryStore,
    tree: ObjectId,
    parents: &[ObjectId],
    description: &str,
) -> ObjectId {
    store
        .put(&Object::Revision(Revision {
            tree,
            parents: parents.to_vec(),
            change_id: ChangeId::random().unwrap(),
            predecessors: Vec::new(),
            author: sig("Ada Lovelace", "ada@example.com", 1_700_000_000_000, 330),
            committer: sig("Grace Hopper", "grace@example.com", 1_700_000_010_000, -420),
            description: description.into(),
        }))
        .unwrap()
}

fn marks(pairs: &[(&str, ObjectId)]) -> BTreeMap<String, ObjectId> {
    pairs
        .iter()
        .map(|(name, id)| ((*name).to_string(), *id))
        .collect()
}

fn export_to(
    dir: &Path,
    store: &MemoryStore,
    bookmarks: &BTreeMap<String, ObjectId>,
) -> (ExportState, gix::ObjectId) {
    let mut state = ExportState::default();
    let report = export_git(dir, store, bookmarks, &mut state, &ExportOptions::default()).unwrap();
    let main = report.bookmarks["main"];
    (state, main)
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Export test")
        .env("GIT_AUTHOR_EMAIL", "export@example.com")
        .env("GIT_COMMITTER_NAME", "Export test")
        .env("GIT_COMMITTER_EMAIL", "export@example.com")
        .args(["-c", "core.autocrlf=false", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn git_objects(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["cat-file", "--batch-all-objects", "--batch", "--unordered"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let data = out.stdout;
    let mut objects = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let header_end = data[i..].iter().position(|byte| *byte == b'\n').unwrap() + i;
        let header = std::str::from_utf8(&data[i..header_end]).unwrap();
        let mut parts = header.split(' ');
        let kind = parts.nth(1).unwrap().to_string();
        let size: usize = parts.next().unwrap().parse().unwrap();
        i = header_end + 1;
        objects.push((kind, data[i..i + size].to_vec()));
        i += size + 1;
    }
    objects
}

#[test]
fn round_trip_keeps_public_history_parents_and_metadata() {
    let store = MemoryStore::new();
    let base_tree = tree(
        &store,
        &[("README", PUBLIC), ("bin/tool", b"#!/bin/true\n")],
    );
    let exec = store.put_blob(b"#!/bin/true\n").unwrap();
    let link = store.put_blob(b"README").unwrap();
    let edits = [
        (p("bin/tool"), Some(Leaf::executable(exec))),
        (p("link"), Some(Leaf::symlink(link))),
    ]
    .into_iter()
    .collect();
    let base_tree = apply_edits(&store, &base_tree, &edits).unwrap();
    let base = revision(&store, base_tree, &[root_revision_id()], "first\n");
    let left_tree = tree(&store, &[("README", PUBLIC), ("left", b"L")]);
    let left = revision(&store, left_tree, &[base], "left\n");
    let right_tree = tree(&store, &[("README", PUBLIC), ("right", b"R")]);
    let right = revision(&store, right_tree, &[base], "right\n");
    let merged_tree = tree(
        &store,
        &[("README", PUBLIC), ("left", b"L"), ("right", b"R")],
    );
    let merged = revision(&store, merged_tree, &[left, right], "merge\n");
    let dir = tempfile::tempdir().unwrap();
    let (state, tip) = export_to(dir.path(), &store, &marks(&[("main", merged)]));
    let parents = git(
        dir.path(),
        &["rev-parse", &format!("{tip}^1"), &format!("{tip}^2")],
    );
    let mut lines = parents.lines();
    assert_eq!(lines.next().unwrap(), state.revisions[&left].to_string());
    assert_eq!(lines.next().unwrap(), state.revisions[&right].to_string());
    assert_eq!(
        git(dir.path(), &["rev-list", "--max-parents=0", "main"]),
        state.revisions[&base].to_string()
    );

    let imported = MemoryStore::new();
    let mut import_state = ImportState::new(false).unwrap();
    import_git(dir.path(), &imported, &mut import_state).unwrap();
    let got = imported
        .get_revision(&import_state.revisions[&tip])
        .unwrap();
    assert_eq!(got.description, "merge\n");
    assert_eq!(got.author.name, "Ada Lovelace");
    assert_eq!(got.author.email, "ada@example.com");
    assert_eq!(got.author.timestamp_ms, 1_700_000_000_000);
    assert_eq!(got.author.tz_offset_min, 330);
    assert_eq!(got.committer.name, "Grace Hopper");
    assert_eq!(got.committer.timestamp_ms, 1_700_000_010_000);
    assert_eq!(got.committer.tz_offset_min, -420);
    assert_eq!(
        got.parents,
        vec![
            import_state.revisions[&state.revisions[&left]],
            import_state.revisions[&state.revisions[&right]]
        ]
    );
    let at = |name: &str| {
        lookup(&imported, &got.tree, &p(name))
            .unwrap()
            .unwrap()
            .kind()
    };
    assert_eq!(at("README"), EntryKind::File);
    assert_eq!(at("left"), EntryKind::File);
    assert_eq!(
        imported
            .get_blob(
                &lookup(&imported, &got.tree, &p("README"))
                    .unwrap()
                    .unwrap()
                    .id()
            )
            .unwrap(),
        PUBLIC
    );
    let base_got = imported
        .get_revision(&import_state.revisions[&state.revisions[&base]])
        .unwrap();
    assert_eq!(base_got.parents, vec![root_revision_id()]);
    assert_eq!(
        lookup(&imported, &base_got.tree, &p("bin/tool"))
            .unwrap()
            .unwrap()
            .kind(),
        EntryKind::Executable
    );
    assert_eq!(
        lookup(&imported, &base_got.tree, &p("link"))
            .unwrap()
            .unwrap()
            .kind(),
        EntryKind::Symlink
    );
}

#[test]
fn private_paths_and_seals_never_reach_git_objects() {
    let store = MemoryStore::new();
    let secret = store.put_blob(SECRET).unwrap();
    let rules = store.put_blob(b"secrets/ @billing\n").unwrap();
    let readme = store.put_blob(PUBLIC).unwrap();
    let edits = [
        (p(".private"), Some(Leaf::file(rules))),
        (p(".env"), Some(Leaf::file(secret))),
        (p("secrets/token"), Some(Leaf::file(secret))),
        (p("README"), Some(Leaf::file(readme))),
        (
            p("foreign"),
            Some(Leaf::sealed(SealedId::from_stored([9; 32]))),
        ),
    ]
    .into_iter()
    .collect();
    let root = apply_edits(&store, &empty_tree_id(), &edits).unwrap();
    let rev = revision(&store, root, &[root_revision_id()], "public\n");
    let dir = tempfile::tempdir().unwrap();
    let mut state = ExportState::default();
    let report = export_git(
        dir.path(),
        &store,
        &marks(&[("main", rev)]),
        &mut state,
        &ExportOptions::default(),
    )
    .unwrap();
    assert!(report.omitted_private_paths >= 3);
    assert!(!report
        .warnings
        .iter()
        .any(|warning| warning.contains(".env") || warning.contains("secrets")));
    assert!(!dir.path().join(".env").exists());
    assert!(
        !dir.path().join("README").exists(),
        "export must not check out the worktree"
    );
    for (kind, body) in git_objects(dir.path()) {
        assert!(
            !body.windows(SECRET.len()).any(|window| window == SECRET),
            "{kind} contains the secret"
        );
        if kind == "tree" {
            assert!(!body
                .windows(b" .env\0".len())
                .any(|window| window == b" .env\0"));
            assert!(!body
                .windows(b" secrets\0".len())
                .any(|window| window == b" secrets\0"));
            assert!(!body
                .windows(b" token\0".len())
                .any(|window| window == b" token\0"));
            assert!(!body
                .windows(b" foreign\0".len())
                .any(|window| window == b" foreign\0"));
        }
    }
    let imported = MemoryStore::new();
    let mut import_state = ImportState::new(false).unwrap();
    import_git(dir.path(), &imported, &mut import_state).unwrap();
    let got = imported
        .get_revision(import_state.revisions.values().next().unwrap())
        .unwrap();
    assert!(lookup(&imported, &got.tree, &p(".private"))
        .unwrap()
        .is_some());
    assert!(lookup(&imported, &got.tree, &p(".env")).unwrap().is_none());
    assert!(lookup(&imported, &got.tree, &p("secrets/token"))
        .unwrap()
        .is_none());
}

#[test]
fn paste_is_refused_until_the_public_path_is_declassified() {
    let store = MemoryStore::new();
    let root = tree(
        &store,
        &[(".env", SECRET), ("notes", SECRET), ("README", PUBLIC)],
    );
    let rev = revision(&store, root, &[root_revision_id()], "copied\n");
    let dir = tempfile::tempdir().unwrap();
    let bookmarks = marks(&[("main", rev)]);
    let err = export_git(
        dir.path(),
        &store,
        &bookmarks,
        &mut ExportState::default(),
        &ExportOptions::default(),
    )
    .unwrap_err();
    let message = err.to_string();
    assert!(message.contains("notes"), "{message}");
    assert!(message.contains("--declassify"), "{message}");
    let mut state = ExportState::default();
    let report = export_git(
        dir.path(),
        &store,
        &bookmarks,
        &mut state,
        &ExportOptions {
            declassify: [p("notes")].into(),
            ..ExportOptions::default()
        },
    )
    .unwrap();
    assert!(report.bookmarks.contains_key("main"));
    let dumped = git_objects(dir.path());
    assert!(dumped
        .iter()
        .any(|(_, body)| body.windows(SECRET.len()).any(|window| window == SECRET)));
    assert!(dumped
        .iter()
        .filter(|(kind, _)| kind == "tree")
        .all(|(_, body)| {
            !body
                .windows(b" .env\0".len())
                .any(|window| window == b" .env\0")
        }));
}

#[test]
fn reexport_is_idempotent_and_commit_ids_match_across_destinations() {
    let store = MemoryStore::new();
    let rev = revision(
        &store,
        tree(&store, &[("README", PUBLIC)]),
        &[root_revision_id()],
        "same\n",
    );
    let bookmarks = marks(&[("main", rev)]);
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let (mut state, tip) = export_to(first.path(), &store, &bookmarks);
    let (_, other) = export_to(second.path(), &store, &bookmarks);
    assert_eq!(tip, other);
    let saved = state.encode();
    let before = git(first.path(), &["rev-parse", "main"]);
    let count = git(first.path(), &["count-objects"]);
    let again = export_git(
        first.path(),
        &store,
        &bookmarks,
        &mut state,
        &ExportOptions::default(),
    )
    .unwrap();
    assert_eq!((again.exported, again.reused), (0, 1));
    assert_eq!(git(first.path(), &["rev-parse", "main"]), before);
    assert_eq!(git(first.path(), &["count-objects"]), count);
    assert_eq!(state.encode(), saved);
    let decoded = ExportState::decode(&saved).unwrap();
    assert_eq!(decoded, state);
    let mut corrupt = saved.clone();
    let last = corrupt.len() - 1;
    corrupt[last] ^= 0xff;
    assert!(ExportState::decode(&corrupt).is_err());
}

#[test]
fn incremental_export_keeps_the_previous_commit() {
    let store = MemoryStore::new();
    let first = revision(
        &store,
        tree(&store, &[("README", PUBLIC)]),
        &[root_revision_id()],
        "one\n",
    );
    let bookmarks = marks(&[("main", first)]);
    let dir = tempfile::tempdir().unwrap();
    let (mut state, tip) = export_to(dir.path(), &store, &bookmarks);
    let second = revision(
        &store,
        tree(&store, &[("README", b"next")]),
        &[first],
        "two\n",
    );
    let bookmarks = marks(&[("main", second)]);
    let report = export_git(
        dir.path(),
        &store,
        &bookmarks,
        &mut state,
        &ExportOptions::default(),
    )
    .unwrap();
    assert_eq!(report.exported, 1);
    assert_eq!(report.reused, 1);
    assert_eq!(state.revisions[&first], tip);
    assert_eq!(git(dir.path(), &["rev-parse", "main^"]), tip.to_string());
}

#[test]
fn a_moved_branch_is_refused_until_force() {
    let store = MemoryStore::new();
    let rev = revision(
        &store,
        tree(&store, &[("README", PUBLIC)]),
        &[root_revision_id()],
        "one\n",
    );
    let bookmarks = marks(&[("main", rev)]);
    let dir = tempfile::tempdir().unwrap();
    let (mut state, tip) = export_to(dir.path(), &store, &bookmarks);
    let extra = git(
        dir.path(),
        &[
            "commit-tree",
            "main^{tree}",
            "-p",
            "main",
            "-m",
            "someone else",
        ],
    );
    git(dir.path(), &["update-ref", "refs/heads/main", &extra]);
    let next = revision(
        &store,
        tree(&store, &[("README", b"ours")]),
        &[rev],
        "two\n",
    );
    let bookmarks = marks(&[("main", next)]);
    let err = export_git(
        dir.path(),
        &store,
        &bookmarks,
        &mut state,
        &ExportOptions::default(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("changed in Git"), "{err}");
    assert_eq!(git(dir.path(), &["rev-parse", "main"]), extra);
    export_git(
        dir.path(),
        &store,
        &bookmarks,
        &mut state,
        &ExportOptions {
            force: true,
            ..ExportOptions::default()
        },
    )
    .unwrap();
    assert_ne!(git(dir.path(), &["rev-parse", "main"]), extra);
    assert_ne!(
        state.revisions[&rev],
        gix::ObjectId::from_hex(extra.as_bytes()).unwrap()
    );
    let _ = tip;
}

#[test]
fn invalid_branch_names_are_skipped_and_unbookmarked_work_is_not_exported() {
    let store = MemoryStore::new();
    let first = revision(
        &store,
        tree(&store, &[("README", PUBLIC)]),
        &[root_revision_id()],
        "one\n",
    );
    let second = revision(
        &store,
        tree(&store, &[("README", b"work")]),
        &[first],
        "work\n",
    );
    let bookmarks = marks(&[("main", first), ("HEAD", second), ("foo..bar", second)]);
    let dir = tempfile::tempdir().unwrap();
    let mut state = ExportState::default();
    let report = export_git(
        dir.path(),
        &store,
        &bookmarks,
        &mut state,
        &ExportOptions::default(),
    )
    .unwrap();
    assert_eq!(report.bookmarks.len(), 1);
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("HEAD")));
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("foo..bar")));
    assert_eq!(
        git(dir.path(), &["rev-parse", "main"]),
        state.revisions[&first].to_string()
    );
    assert!(!state.revisions.contains_key(&second));
    let refused = tempfile::tempdir().unwrap();
    fs::write(refused.path().join("occupied"), b"x").unwrap();
    let err = export_git(
        &refused.path().join("occupied"),
        &store,
        &bookmarks,
        &mut ExportState::default(),
        &ExportOptions::default(),
    )
    .unwrap_err();
    assert!(
        err.to_string().contains("not a Git repository") || err.to_string().contains("file"),
        "{err}"
    );
}

#[test]
fn metadata_warning_names_hidden_files_and_a_private_rules_file_is_refused() {
    let store = MemoryStore::new();
    let rules = store.put_blob(b"secrets/\n").unwrap();
    let token = store.put_blob(b"tok").unwrap();
    let edits = [
        (p(".private"), Some(Leaf::file(rules))),
        (p("secrets/token"), Some(Leaf::file(token))),
        (
            p("README"),
            Some(Leaf::file(store.put_blob(PUBLIC).unwrap())),
        ),
    ]
    .into_iter()
    .collect();
    let rev = revision(
        &store,
        apply_edits(&store, &empty_tree_id(), &edits).unwrap(),
        &[root_revision_id()],
        "rotate token please\n",
    );
    let dir = tempfile::tempdir().unwrap();
    let report = export_git(
        dir.path(),
        &store,
        &marks(&[("main", rev)]),
        &mut ExportState::default(),
        &ExportOptions::default(),
    )
    .unwrap();
    assert!(
        report
            .warnings
            .iter()
            .any(|warning| warning.contains("token") && warning.contains("exported as-is")),
        "{:?}",
        report.warnings
    );

    let bad = tree(&store, &[(".private", b".private\n"), ("README", PUBLIC)]);
    let rev = revision(&store, bad, &[root_revision_id()], "nope\n");
    let refused = tempfile::tempdir().unwrap();
    let err = export_git(
        &refused.path().join("out"),
        &store,
        &marks(&[("main", rev)]),
        &mut ExportState::default(),
        &ExportOptions::default(),
    )
    .unwrap_err();
    assert!(err.to_string().contains(".private"), "{err}");
}
