use std::sync::Arc;

use tig_core::ophead::MemoryOpHead;
use tig_core::repo::{Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::store::StoreExt;
use tig_core::treeops::{apply_edits, lookup, Leaf};
use tig_core::{EntryKind, MemoryStore, ObjectId, RepoPath};

fn branch(repo: &mut Repo, parent: ObjectId, bytes: &[u8]) -> ObjectId {
    let path = RepoPath::new("file").unwrap();
    let tree = apply_edits(
        repo.store().as_ref(),
        &repo.revision(&parent).unwrap().tree,
        &[(
            path,
            Some(Leaf::file(repo.store().put_blob(bytes).unwrap())),
        )]
        .into(),
    )
    .unwrap();
    let mut tx = repo.start("branch");
    let id = tx.new_change(&[parent], "branch").unwrap();
    let id = tx.rewrite(id, |rev| rev.tree = tree).unwrap();
    repo.commit(tx).unwrap();
    id
}

#[test]
fn overlapping_edits_complete_as_a_stored_merge() {
    let mut repo = Repo::init(
        Arc::new(MemoryStore::new()),
        Arc::new(MemoryOpHead::new()),
        Settings::default(),
    )
    .unwrap();
    let root = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let base = branch(&mut repo, root, b"base");
    let a = branch(&mut repo, base, b"A");
    let b = branch(&mut repo, base, b"B");
    let c = branch(&mut repo, base, b"C");
    let mut tx = repo.start("merge three contributors");
    let merged = tx
        .new_change(&[a, b, c], "merge")
        .expect("conflicts must be stored, not refused");
    tx.set_working(DEFAULT_WORKSPACE, merged).unwrap();
    repo.commit(tx).unwrap();
    let leaf = lookup(
        repo.store().as_ref(),
        &repo.revision(&merged).unwrap().tree,
        &RepoPath::new("file").unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(leaf.kind(), EntryKind::Conflict);
    let conflict = repo.store().get_conflict(&leaf.id()).unwrap();
    assert_eq!(conflict.adds().len(), 3);
    for bytes in [b"A", b"B", b"C"] {
        assert!(conflict.adds().iter().flatten().any(|leaf| repo
            .store()
            .get_blob(&leaf.id())
            .unwrap()
            == bytes));
    }
    assert_eq!(
        tig_core::conflict::Conflict::decode(&conflict.encode()).unwrap(),
        conflict
    );
    let mut ws = tig_core::workspace::Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    let original = ws
        .read(&repo, &RepoPath::new("file").unwrap())
        .unwrap()
        .unwrap();
    ws.write(&repo, &RepoPath::new("file").unwrap(), &original)
        .unwrap();
    assert!(!ws.snapshot(&mut repo).unwrap());
    let draft = String::from_utf8(original)
        .unwrap()
        .replace("[File]", "[File] edited draft");
    ws.write(&repo, &RepoPath::new("file").unwrap(), draft.as_bytes())
        .unwrap();
    assert!(ws.snapshot(&mut repo).unwrap());
    assert_eq!(
        ws.read(&repo, &RepoPath::new("file").unwrap())
            .unwrap()
            .unwrap(),
        draft.as_bytes()
    );
    let draft_rev = ws.working_revision();
    ws.write(&repo, &RepoPath::new("file").unwrap(), b"resolved")
        .unwrap();
    assert!(ws.snapshot(&mut repo).unwrap());
    assert_eq!(
        ws.leaf(&repo, &RepoPath::new("file").unwrap())
            .unwrap()
            .unwrap()
            .kind(),
        EntryKind::File
    );
    repo.undo().unwrap();
    assert_eq!(repo.working_revision(DEFAULT_WORKSPACE).unwrap(), draft_rev);
}

#[test]
fn selecting_typed_and_deleted_sides_preserves_exact_bytes_and_modes() {
    for kind in [EntryKind::Executable, EntryKind::Symlink] {
        let mut repo = Repo::init(
            Arc::new(MemoryStore::new()),
            Arc::new(MemoryOpHead::new()),
            Settings::default(),
        )
        .unwrap();
        let bytes = b"binary\0or-symlink-without-newline";
        let selected = Leaf::new(kind, repo.store().put_blob(bytes).unwrap()).unwrap();
        let base = Leaf::file(repo.store().put_blob(b"base").unwrap());
        let conflict =
            tig_core::conflict::merge(repo.store().as_ref(), Some(base), Some(selected), None)
                .unwrap()
                .unwrap();
        let tree = apply_edits(
            repo.store().as_ref(),
            &tig_core::store::empty_tree_id(),
            &[(RepoPath::new("file").unwrap(), Some(conflict))].into(),
        )
        .unwrap();
        let working = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
        let mut tx = repo.start("conflict");
        tx.rewrite(working, |rev| rev.tree = tree).unwrap();
        repo.commit(tx).unwrap();
        let mut ws = tig_core::workspace::Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
        ws.resolve(&repo, &RepoPath::new("file").unwrap(), Some(selected))
            .unwrap();
        ws.snapshot(&mut repo).unwrap();
        assert_eq!(
            ws.leaf(&repo, &RepoPath::new("file").unwrap()).unwrap(),
            Some(selected)
        );
        assert_eq!(
            ws.read(&repo, &RepoPath::new("file").unwrap())
                .unwrap()
                .unwrap(),
            bytes
        );
        repo.undo().unwrap();
        ws.sync(&repo).unwrap();
        ws.resolve(&repo, &RepoPath::new("file").unwrap(), None)
            .unwrap();
        ws.snapshot(&mut repo).unwrap();
        assert_eq!(
            ws.leaf(&repo, &RepoPath::new("file").unwrap()).unwrap(),
            None
        );
    }
}

#[test]
fn repeated_merges_flatten_and_cancel_sides_and_retain_drafts() {
    let store = MemoryStore::new();
    let files: Vec<_> = [b"base".as_slice(), b"left", b"right", b"third"]
        .iter()
        .map(|bytes| Leaf::file(store.put_blob(bytes).unwrap()))
        .collect();
    let first = tig_core::conflict::merge(&store, Some(files[0]), Some(files[1]), Some(files[2]))
        .unwrap()
        .unwrap();
    let next = tig_core::conflict::merge(&store, Some(files[0]), Some(first), Some(files[3]))
        .unwrap()
        .unwrap();
    let expression = store.get_conflict(&next.id()).unwrap();
    assert_eq!(expression.adds().len(), 3);
    assert_eq!(expression.removes().len(), 2);
    assert!(expression
        .adds()
        .iter()
        .flatten()
        .all(|leaf| leaf.kind() == EntryKind::File));
    assert_eq!(
        tig_core::conflict::merge(&store, Some(files[1]), Some(first), Some(files[0])).unwrap(),
        Some(files[2])
    );
    let mut progress = tig_core::conflict::materialize(&store, first).unwrap();
    progress.extend_from_slice(b"progress");
    let draft =
        tig_core::conflict::snapshot_file(&store, first, &progress, EntryKind::File).unwrap();
    let later = tig_core::conflict::merge(&store, Some(files[0]), Some(draft), Some(files[3]))
        .unwrap()
        .unwrap();
    assert!(
        store
            .get_conflict(&later.id())
            .unwrap()
            .adds()
            .contains(&Some(draft)),
        "a later merge must retain partial resolution work"
    );
}

#[test]
fn conflict_encodings_reject_truncation_and_require_new_tree_version() {
    let store = MemoryStore::new();
    let a = Leaf::file(store.put_blob(b"A").unwrap());
    let b = Leaf::file(store.put_blob(b"B").unwrap());
    let leaf = tig_core::conflict::merge(&store, None, Some(a), Some(b))
        .unwrap()
        .unwrap();
    let body = store.get_conflict(&leaf.id()).unwrap().encode();
    for end in 0..body.len() {
        assert!(tig_core::conflict::Conflict::decode(&body[..end]).is_err());
    }
    let mut trailing = body.clone();
    trailing.push(0);
    assert!(tig_core::conflict::Conflict::decode(&trailing).is_err());
    let tree = tig_core::Tree::new(vec![tig_core::TreeEntry::new(
        "file",
        EntryKind::Conflict,
        leaf.id(),
    )
    .unwrap()])
    .unwrap();
    let mut encoded = tree.encode();
    assert_eq!(encoded[0], 2);
    assert_eq!(tig_core::Tree::decode(&encoded).unwrap(), tree);
    encoded[0] = 1;
    assert!(tig_core::Tree::decode(&encoded).is_err());
    let mut ordinary = tig_core::Tree::empty().encode();
    assert_eq!(ordinary, [1, 0]);
    ordinary[0] = 2;
    assert!(tig_core::Tree::decode(&ordinary).is_err());
}

#[test]
fn marker_files_do_not_disclose_internal_ids_or_confuse_literal_markers() {
    let store = MemoryStore::new();
    let a = Leaf::file(
        store
            .put_blob(b"<<<<<<< tig conflict\nliteral example\n")
            .unwrap(),
    );
    let b = Leaf::file(store.put_blob(b"other").unwrap());
    let leaf = tig_core::conflict::merge(&store, None, Some(a), Some(b))
        .unwrap()
        .unwrap();
    let rendered = tig_core::conflict::materialize(&store, leaf).unwrap();
    let text = std::str::from_utf8(&rendered).unwrap();
    for id in [a.id(), b.id(), leaf.id()] {
        assert!(
            !text.contains(&id.to_hex()),
            "markers must not disclose internal IDs"
        );
    }
    assert_eq!(
        tig_core::conflict::snapshot_file(&store, leaf, &rendered, EntryKind::File).unwrap(),
        leaf
    );
    assert_eq!(
        tig_core::conflict::snapshot_file(
            &store,
            leaf,
            &store.get_blob(&a.id()).unwrap(),
            EntryKind::File
        )
        .unwrap(),
        a
    );
    let tree = Leaf::tree(tig_core::store::empty_tree_id());
    let structural = tig_core::conflict::merge(&store, None, Some(tree), Some(b))
        .unwrap()
        .unwrap();
    // Empty trees are canonical objects but need to exist before rendering.
    store
        .put(&tig_core::Object::Tree(tig_core::Tree::empty()))
        .unwrap();
    assert!(
        !String::from_utf8(tig_core::conflict::materialize(&store, structural).unwrap())
            .unwrap()
            .contains(&tree.id().to_hex())
    );
}
