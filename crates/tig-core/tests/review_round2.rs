use std::sync::Arc;

use tig_core::merge::{merge_trees, MergeOutcome};
use tig_core::ophead::MemoryOpHead;
use tig_core::repo::{root_revision, root_revision_id, Repo, Settings};
use tig_core::store::{empty_tree_id, StoreExt};
use tig_core::treeops::{apply_edits, Leaf};
use tig_core::workspace::Workspace;
use tig_core::{MemoryStore, Object, ObjectId, RepoPath};

fn p(path: &str) -> RepoPath {
    RepoPath::new(path).unwrap()
}

fn repo() -> Repo {
    Repo::init(
        Arc::new(MemoryStore::new()),
        Arc::new(MemoryOpHead::new()),
        Settings {
            fixed_time_ms: Some(1),
            ..Settings::default()
        },
    )
    .unwrap()
}

#[test]
fn listing_an_edited_file_matches_its_snapshot() {
    let mut r = repo();
    let mut w = Workspace::open(&r, "default").unwrap();
    for kind in [
        tig_core::EntryKind::File,
        tig_core::EntryKind::Executable,
        tig_core::EntryKind::Symlink,
    ] {
        w.write_kind(&r, &p("file"), b"contents", kind).unwrap();
        let before = w.list(&r, &p("file")).unwrap();
        w.snapshot(&mut r).unwrap();
        assert_eq!(before, w.list(&r, &p("file")).unwrap());
        assert_eq!(before.len(), 1);
    }
}

#[test]
fn reparenting_keeps_workspace_and_bookmark_leaves_as_heads() {
    for reference in ["workspace", "bookmark"] {
        let mut r = repo();
        let a = r.working_revision("default").unwrap();
        let mut tx = r.start("graph");
        let b = tx.new_change(&[a], "b").unwrap();
        if reference == "workspace" {
            tx.set_working("other", a).unwrap();
        } else {
            tx.set_bookmark("keep", a).unwrap();
        }
        tx.set_working("default", b).unwrap();
        r.commit(tx).unwrap();
        let mut tx = r.start("reparent b");
        let new = tx
            .rewrite(b, |rev| rev.parents = vec![root_revision_id()])
            .unwrap();
        r.commit(tx).unwrap();
        assert_eq!(r.view().heads, [a, new].into_iter().collect());
        if reference == "workspace" {
            let mut tx = r.start("leave empty a");
            tx.set_working("other", new).unwrap();
            r.commit(tx).unwrap();
            assert!(!r
                .visible_revisions()
                .unwrap()
                .iter()
                .any(|(id, _)| *id == a));
        }
    }
}

#[test]
fn lookup_rejects_paths_over_the_tree_depth_limit() {
    let s = MemoryStore::new();
    let path = p(&vec!["a"; tig_core::treeops::MAX_TREE_DEPTH + 1].join("/"));
    let result = tig_core::treeops::lookup(&s, &tig_core::store::empty_tree_id(), &path);
    assert!(
        matches!(result, Err(tig_core::Error::Invalid(ref message)) if message.contains("MAX_TREE_DEPTH"))
    );
}

#[test]
fn file_directory_merges_are_symmetric() {
    let s = MemoryStore::new();
    let contents = [s.put_blob(b"one").unwrap(), s.put_blob(b"two").unwrap()];
    let shapes: &[&[(&str, usize)]] = &[
        &[],
        &[("a", 0)],
        &[("a", 1)],
        &[("a/x", 0)],
        &[("a/x", 1)],
        &[("a/y", 0)],
        &[("a/x", 0), ("a/y", 0)],
        &[("a/x/y", 0)],
        &[("a/x/y", 1)],
        &[("a/x/z", 0)],
        &[("a/x/y", 0), ("a/y", 0)],
    ];
    let trees: Vec<_> = shapes
        .iter()
        .map(|files| {
            let edits = files
                .iter()
                .map(|&(path, value)| (p(path), Some(Leaf::file(contents[value]))))
                .collect();
            apply_edits(&s, &empty_tree_id(), &edits).unwrap()
        })
        .collect();
    for (bi, base) in trees.iter().enumerate() {
        for (oi, ours) in trees.iter().enumerate() {
            for (ti, theirs) in trees.iter().enumerate() {
                let forward = merge_trees(&s, base, ours, theirs).unwrap();
                let reverse = merge_trees(&s, base, theirs, ours).unwrap();
                match (forward, reverse) {
                    (MergeOutcome::Clean(a), MergeOutcome::Clean(b)) => {
                        assert_eq!(a, b, "base={bi}, ours={oi}, theirs={ti}")
                    }
                    (MergeOutcome::Conflict(_), MergeOutcome::Conflict(_)) => {}
                    pair => panic!("asymmetric base={bi}, ours={oi}, theirs={ti}: {pair:?}"),
                }
            }
        }
    }
}

#[test]
fn resolve_validates_the_final_parent_and_loaded_view_targets() {
    let r = repo();
    let blob = r.store().put_blob(b"not a revision").unwrap();
    for parent in [blob, ObjectId([9; 32])] {
        let mut rev = root_revision();
        rev.parents = vec![parent];
        let id = r.store().put(&Object::Revision(rev)).unwrap();
        assert!(r.resolve("default", &format!("{id}-")).is_err());
    }
    let store = Arc::new(MemoryStore::new());
    let head = Arc::new(MemoryOpHead::new());
    let r = Repo::init(store.clone(), head.clone(), Settings::default()).unwrap();
    let blob = store.put_blob(b"not a revision").unwrap();
    let mut view = r.view().clone();
    view.workspaces.insert("default".into(), blob);
    view.bookmarks.insert("bad".into(), blob);
    let mut op = r.operation().clone();
    op.view = store.put(&Object::View(view)).unwrap();
    let id = store.put(&Object::Operation(op)).unwrap();
    tig_core::ophead::OpHeadStore::compare_and_set(&*head, Some(r.op_id()), id).unwrap();
    let loaded = Repo::load(store, head, Settings::default()).unwrap();
    for spec in ["@", "bad"] {
        assert!(loaded.resolve("default", spec).is_err(), "{spec}");
    }
}

#[test]
fn hex_revision_prefixes_accept_uppercase_like_full_ids() {
    let r = repo();
    let id = root_revision_id();
    assert_eq!(
        r.resolve("default", &id.to_hex().to_ascii_uppercase())
            .unwrap(),
        id
    );
    assert_eq!(
        r.resolve("default", &id.short(12).to_ascii_uppercase())
            .unwrap(),
        id
    );
}

#[test]
fn portable_paths_and_prefix_ranges_do_not_alias_metadata_or_neighbors() {
    for name in [
        ".tig",
        ".TiG",
        ".tig\u{feff}",
        ".t\u{200d}ig",
        "\u{206a}.tig\u{202e}",
    ] {
        assert!(RepoPath::new(name).is_err(), "{name:?}");
        assert!(
            tig_core::TreeEntry::new(name, tig_core::EntryKind::File, ObjectId([1; 32])).is_err()
        );
    }
    for path in [
        r"C:\outside",
        r"\\host\share",
        r"a\..\x",
        "../x",
        "/x",
        "a:b",
        "a//b",
        "a/",
        "a/./b",
    ] {
        assert!(RepoPath::from_os_relative(path).is_err(), "{path:?}");
    }
    for name in [
        "．tig",
        ".tİg",
        ".tığ",
        ".tig\u{200b}",
        "aux.c",
        "CON",
        "A",
        "a",
        "café",
        "name\u{a0}",
    ] {
        assert!(RepoPath::new(name).is_ok(), "{name:?}");
    }
    let mut map: std::collections::BTreeMap<_, _> = ["a", "a/x", "a/y/z", "a.b", "a0", "é/x", "é0"]
        .into_iter()
        .map(|path| (p(path), ()))
        .collect();
    assert!(tig_core::path::has_ancestor(&map, &p("a/y/z")));
    assert!(!tig_core::path::has_ancestor(&map, &p("ab/x")));
    assert_eq!(
        tig_core::path::range_inside(&map, &p("a"))
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        ["a/x", "a/y/z"]
    );
    tig_core::path::remove_inside(&mut map, &p("a"));
    assert_eq!(
        map.keys().map(|path| path.as_str()).collect::<Vec<_>>(),
        ["a", "a.b", "a0", "é/x", "é0"]
    );
    tig_core::path::remove_inside(&mut map, &RepoPath::root());
    assert!(map.is_empty());
}

#[test]
fn sealed_leaves_need_typed_ids_and_survive_tree_edits() {
    use tig_core::seal::{SealSalt, SealedId};
    use tig_core::treeops::{lookup, walk};
    let s = MemoryStore::new();
    let internal = s.put_blob(b"secret").unwrap();
    assert!(Leaf::new(tig_core::EntryKind::Sealed, internal).is_err());
    assert!(tig_core::TreeEntry::new("secret", tig_core::EntryKind::Sealed, internal).is_err());
    let sid = SealedId::compute(
        &SealSalt::from_bytes([2; 32]),
        tig_core::EntryKind::File,
        &internal,
    );
    let secret = Leaf::sealed(sid);
    let edits = [(p("secret"), Some(secret))].into_iter().collect();
    let tree = apply_edits(&s, &empty_tree_id(), &edits).unwrap();
    let edits = [(
        p("public"),
        Some(Leaf::file(s.put_blob(b"public").unwrap())),
    )]
    .into_iter()
    .collect();
    let changed = apply_edits(&s, &tree, &edits).unwrap();
    assert_eq!(lookup(&s, &changed, &p("secret")).unwrap(), Some(secret));
    assert_eq!(secret.sealed_id(), Some(sid));
    assert_ne!(secret.id(), internal);
    assert_eq!(
        walk(&s, &changed, &p("secret")).unwrap(),
        vec![(p("secret"), secret)]
    );
}

#[test]
fn graft_file_listings_match_snapshots_at_every_prefix() {
    let mut r = repo();
    let mut w = Workspace::open(&r, "default").unwrap();
    for path in ["a/x", "a/y/z", "keep"] {
        w.write(&r, &p(path), b"base").unwrap();
    }
    w.snapshot(&mut r).unwrap();
    for (path, data) in [
        ("a", None),
        ("a/y/z", Some(b"new".as_slice())),
        ("a/x", Some(b"x")),
        ("a/y/z", None),
        ("a", Some(b"file")),
    ] {
        if let Some(data) = data {
            w.write(&r, &p(path), data).unwrap();
        } else {
            w.remove(&r, &p(path)).unwrap();
        }
        let expected = apply_edits(
            &**r.store(),
            &r.revision(&w.working_revision()).unwrap().tree,
            w.pending(),
        )
        .unwrap();
        for prefix in ["", "a", "a/x", "a/y", "a/y/z", "keep"] {
            assert_eq!(
                w.list(&r, &p(prefix)).unwrap(),
                tig_core::treeops::walk(&**r.store(), &expected, &p(prefix)).unwrap(),
                "{path}: {prefix}"
            );
        }
    }
}

#[test]
fn undo_restore_and_rejected_steps_preserve_views() {
    let mut r = repo();
    let initial = r.view().clone();
    let mut states = Vec::new();
    for description in ["a", "b", "c"] {
        let mut tx = r.start(description);
        tx.rewrite(r.working_revision("default").unwrap(), |rev| {
            rev.description = description.into()
        })
        .unwrap();
        r.commit(tx).unwrap();
        states.push((r.op_id(), r.view().clone()));
    }
    r.undo().unwrap();
    assert_eq!(*r.view(), states[1].1);
    r.restore_operation(&states[2].0).unwrap();
    assert_eq!(*r.view(), states[2].1);
    r.undo().unwrap();
    assert_eq!(*r.view(), states[1].1);
    let mut tx = r.start("failed steps");
    let saved = tx.view().clone();
    assert!(tx.set_bookmark("bad", ObjectId([9; 32])).is_err());
    assert!(tx.new_change(&[], "no parents").is_err());
    assert!(tx.set_working("default", ObjectId([9; 32])).is_err());
    assert!(tx.remove_workspace("missing").is_err());
    assert_eq!(*tx.view(), saved);
    r.undo().unwrap();
    assert_eq!(*r.view(), states[0].1);
    r.undo().unwrap();
    assert_eq!(*r.view(), initial);
    assert!(r.undo().is_err());
}

#[test]
fn file_ophead_serializes_writers_and_keeps_existing_temp_names() {
    use tig_core::ophead::{FileOpHead, OpHeadStore};
    let dir = tempfile::tempdir().unwrap();
    let planted = dir.path().join("op_head.tmp");
    std::fs::write(&planted, b"keep").unwrap();
    let head = FileOpHead::new(dir.path());
    let wins = std::thread::scope(|scope| {
        let handles: Vec<_> = (1..=4)
            .map(|n| {
                let head = &head;
                scope.spawn(move || head.compare_and_set(None, ObjectId([n; 32])).unwrap())
            })
            .collect();
        handles
            .into_iter()
            .map(|handle| usize::from(handle.join().unwrap()))
            .sum::<usize>()
    });
    // Check the persisted winner and that no lock/random temp survives.
    assert_eq!(wins, 1);
    assert!(head.get().unwrap().is_some());
    assert_eq!(std::fs::read(&planted).unwrap(), b"keep");
    let mut names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            std::ffi::OsString::from("op_head"),
            std::ffi::OsString::from("op_head.tmp")
        ]
    );
}

#[test]
fn rewrite_rejects_parentless_revisions() {
    let r = repo();
    let old = r.working_revision("default").unwrap();
    let mut tx = r.start("parentless");
    let saved = tx.view().clone();
    assert!(tx
        .rewrite(old, |revision| revision.parents.clear())
        .is_err());
    assert_eq!(*tx.view(), saved);
}

#[test]
#[ignore = "decision: validating rewrite roots reloads trees on the snapshot hot path"]
fn rewrite_rejects_non_tree_roots() {
    let r = repo();
    let old = r.working_revision("default").unwrap();
    let blob = r.store().put_blob(b"not a tree").unwrap();
    for invalid_tree in [blob, ObjectId([9; 32])] {
        let mut tx = r.start("invalid tree");
        let saved = tx.view().clone();
        assert!(tx
            .rewrite(old, |revision| revision.tree = invalid_tree)
            .is_err());
        assert_eq!(*tx.view(), saved);
    }
}

#[test]
fn rewrite_cannot_reparent_a_change_onto_itself_or_its_descendant() {
    let mut r = repo();
    let a = r.working_revision("default").unwrap();
    let mut tx = r.start("child");
    let b = tx.new_change(&[a], "b").unwrap();
    tx.set_working("default", b).unwrap();
    r.commit(tx).unwrap();
    for parent in [a, b] {
        let mut tx = r.start("invalid reparent");
        let saved = tx.view().clone();
        assert!(tx
            .rewrite(a, |revision| revision.parents = vec![parent])
            .is_err());
        assert_eq!(*tx.view(), saved);
    }
}
