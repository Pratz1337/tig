//! Lost loose objects simulate a head whose writes did not survive a crash.
use std::fs;
use std::sync::Arc;

use tig_core::object::{EntryKind, Object, Tree, TreeEntry};
use tig_core::ophead::{FileOpHead, OpHeadStore};
use tig_core::repo::{Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::seal::SealedId;
use tig_core::store::{DiskStore, StoreExt};
use tig_core::workspace::Workspace;
use tig_core::{ObjectId, RepoPath};

struct Fixture {
    dir: tempfile::TempDir,
    store: Arc<DiskStore>,
    head: Arc<FileOpHead>,
    repo: Repo,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(DiskStore::open(dir.path().join("store")).unwrap());
        let head = Arc::new(FileOpHead::new(dir.path()));
        let repo = Repo::init(store.clone(), head.clone(), Settings::default()).unwrap();
        Self {
            dir,
            store,
            head,
            repo,
        }
    }

    fn snapshot(&mut self, bytes: &[u8]) -> ObjectId {
        let mut ws = Workspace::open(&self.repo, DEFAULT_WORKSPACE).unwrap();
        ws.write(&self.repo, &RepoPath::new("work.txt").unwrap(), bytes)
            .unwrap();
        ws.snapshot(&mut self.repo).unwrap();
        self.repo.op_id()
    }

    fn object_path(&self, id: ObjectId) -> std::path::PathBuf {
        let hex = id.to_hex();
        self.store.root().join(&hex[..2]).join(&hex[2..])
    }

    fn remove(&self, id: ObjectId) {
        fs::remove_file(self.object_path(id)).unwrap();
    }

    fn load(&self) -> Repo {
        Repo::load(self.store.clone(), self.head.clone(), Settings::default()).unwrap()
    }
}

#[test]
fn recovery_checks_conflict_objects_sides_trees_and_drafts() {
    for missing in ["conflict", "side", "tree child", "draft"] {
        let mut f = Fixture::new();
        let before = f.repo.op_id();
        let blob = f.store.put_blob(b"only in a conflict side").unwrap();
        let side_tree = f.store.put(&Object::Tree(Tree::new(vec![TreeEntry::new("child", EntryKind::File, blob).unwrap()]).unwrap())).unwrap();
        let other = f.store.put_blob(b"competing file").unwrap();
        let original = tig_core::conflict::merge(f.store.as_ref(), None,
            Some(tig_core::treeops::Leaf::tree(side_tree)), Some(tig_core::treeops::Leaf::file(other))).unwrap().unwrap();
        let mut leaf = original;
        if missing == "draft" {
            let mut draft = tig_core::conflict::materialize(f.store.as_ref(), original).unwrap();
            draft.extend_from_slice(b"resolution progress");
            leaf = tig_core::conflict::snapshot_file(f.store.as_ref(), original, &draft, EntryKind::File).unwrap();
        }
        let root = f.store.put(&Object::Tree(Tree::new(vec![TreeEntry::new("conflicted", EntryKind::Conflict, leaf.id()).unwrap()]).unwrap())).unwrap();
        let working = f.repo.working_revision(DEFAULT_WORKSPACE).unwrap();
        let mut tx = f.repo.start("stored conflict");
        tx.rewrite(working, |rev| rev.tree = root).unwrap(); f.repo.commit(tx).unwrap();
        assert!(!f.repo.recover().unwrap(), "valid conflict must be recoverable");
        let id = match missing {
            "conflict" => leaf.id(), "side" => other, "tree child" => blob,
            "draft" => f.store.get_conflict(&leaf.id()).unwrap().draft().unwrap(), _ => unreachable!(),
        };
        f.remove(id);
        assert!(f.repo.recover().unwrap(), "missing {missing} must invalidate the view");
        assert_eq!(f.repo.op_id(), before);
    }
}

#[test]
fn missing_or_corrupt_current_metadata_recovers_the_previous_head() {
    for view in [false, true] {
        for corrupt in [false, true] {
            let mut f = Fixture::new();
            let previous = f.repo.op_id();
            let lost = f.snapshot(b"new bytes");
            let id = if view {
                f.store.get_operation(&lost).unwrap().view
            } else {
                lost
            };
            if corrupt {
                fs::write(f.object_path(id), b"truncated").unwrap();
            } else {
                f.remove(id);
            }
            let loaded = f.load();
            assert_eq!(loaded.op_id(), previous);
            assert_eq!(loaded.recovered_from(), Some(lost));
            assert_eq!(f.head.get().unwrap(), Some(previous));
        }
    }
}

#[test]
fn explicit_recovery_checks_revisions_trees_and_blobs_without_slowing_normal_load() {
    for kind in ["revision", "tree", "blob"] {
        let mut f = Fixture::new();
        let previous = f.snapshot(b"old bytes");
        let lost = f.snapshot(b"new bytes");
        let working = f.repo.working_revision(DEFAULT_WORKSPACE).unwrap();
        let tree = f.repo.revision(&working).unwrap().tree;
        let blob = f.store.get_tree(&tree).unwrap().entries()[0].id();
        f.remove(match kind {
            "revision" => working,
            "tree" => tree,
            _ => blob,
        });
        let mut loaded = f.load();
        assert_eq!(loaded.op_id(), lost, "normal loading checks only metadata");
        assert!(loaded.recover().unwrap());
        assert_eq!(loaded.op_id(), previous);
        assert_eq!(loaded.recovered_from(), Some(lost));
        assert_eq!(
            Workspace::open(&loaded, DEFAULT_WORKSPACE)
                .unwrap()
                .read(&loaded, &RepoPath::new("work.txt").unwrap())
                .unwrap()
                .unwrap(),
            b"old bytes"
        );
    }
}

#[test]
fn recovery_skips_incomplete_recent_heads() {
    let mut f = Fixture::new();
    let complete = f.snapshot(b"complete");
    let incomplete = f.snapshot(b"incomplete");
    let view = f.store.get_operation(&incomplete).unwrap().view;
    f.remove(view);
    let missing = f.snapshot(b"last");
    f.remove(missing);
    assert_eq!(f.load().op_id(), complete);
}

#[test]
fn legacy_single_head_can_recover_through_readable_operation_parents() {
    let mut f = Fixture::new();
    let previous = f.repo.op_id();
    let lost = f.snapshot(b"latest");
    let view = f.store.get_operation(&lost).unwrap().view;
    fs::write(f.dir.path().join("op_head"), lost.to_hex()).unwrap();
    f.remove(view);
    assert_eq!(f.load().op_id(), previous);
}

#[test]
fn no_complete_candidate_leaves_the_head_unchanged() {
    let mut f = Fixture::new();
    f.snapshot(b"last");
    let original = fs::read(f.dir.path().join("op_head")).unwrap();
    // Every revision depends on the root tree.
    f.remove(tig_core::store::empty_tree_id());
    assert!(f
        .repo
        .recover()
        .unwrap_err()
        .to_string()
        .contains("no complete operation"));
    assert_eq!(fs::read(f.dir.path().join("op_head")).unwrap(), original);
}

#[test]
fn corrupted_blob_is_not_a_complete_view() {
    let mut f = Fixture::new();
    let previous = f.repo.op_id();
    f.snapshot(b"content");
    let blob = f.store.put_blob(b"content").unwrap();
    let mut bytes = fs::read(f.object_path(blob)).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(f.object_path(blob), bytes).unwrap();
    assert!(f.repo.recover().unwrap());
    assert_eq!(f.repo.op_id(), previous);
}

#[test]
fn opaque_sealed_ids_are_not_missing_objects_and_healthy_recovery_does_not_move_head() {
    let mut f = Fixture::new();
    let tree = Tree::new(vec![TreeEntry::sealed(
        ".env",
        SealedId::from_stored([41; 32]),
    )
    .unwrap()])
    .unwrap();
    let tree = f.store.put(&Object::Tree(tree)).unwrap();
    let mut tx = f.repo.start("sealed view");
    let working = f.repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    tx.rewrite(working, |rev| rev.tree = tree).unwrap();
    f.repo.commit(tx).unwrap();
    let original = fs::read(f.dir.path().join("op_head")).unwrap();
    assert!(!f.repo.recover().unwrap());
    assert_eq!(f.repo.recovered_from(), None);
    assert_eq!(fs::read(f.dir.path().join("op_head")).unwrap(), original);
    assert_eq!(
        f.store.get_tree(&tree).unwrap().entries()[0].kind(),
        EntryKind::Sealed
    );
}
