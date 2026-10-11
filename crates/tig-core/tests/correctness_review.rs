use std::{collections::BTreeMap, sync::Arc};
use tig_core::merge::{merge_base, merge_trees, MergeOutcome};
use tig_core::ophead::MemoryOpHead;
use tig_core::repo::{root_revision, root_revision_id, Repo, Settings};
use tig_core::store::{empty_tree_id, StoreExt};
use tig_core::treeops::{apply_edits, lookup, Leaf};
use tig_core::workspace::Workspace;
use tig_core::{MemoryStore, Object, ObjectId, RepoPath, Store};

fn p(s: &str) -> RepoPath {
    RepoPath::new(s).unwrap()
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
fn tree(s: &dyn Store, files: &[(&str, &[u8])]) -> ObjectId {
    let edits = files
        .iter()
        .map(|(path, data)| (p(path), Some(Leaf::file(s.put_blob(data).unwrap()))))
        .collect();
    apply_edits(s, &empty_tree_id(), &edits).unwrap()
}
fn raw_rev(s: &dyn Store, parents: &[ObjectId], tree: ObjectId, name: &str) -> ObjectId {
    let mut r = root_revision();
    r.parents = parents.to_vec();
    r.tree = tree;
    r.description = name.into();
    s.put(&Object::Revision(r)).unwrap()
}
fn describe(r: &mut Repo, text: &str) {
    let old = r.working_revision("default").unwrap();
    let mut tx = r.start(text);
    tx.rewrite(old, |r| r.description = text.into()).unwrap();
    r.commit(tx).unwrap();
}

#[test]
fn deleting_directory_then_recreating_child_keeps_siblings_deleted() {
    let mut r = repo();
    let mut w = Workspace::open(&r, "default").unwrap();
    w.write(&r, &p("a/x"), b"x").unwrap();
    w.write(&r, &p("a/y"), b"y").unwrap();
    w.snapshot(&mut r).unwrap();
    w.remove(&r, &p("a")).unwrap();
    w.write(&r, &p("a/x"), b"new").unwrap();
    assert_eq!(w.read(&r, &p("a/y")).unwrap(), None);
    assert_eq!(
        w.list(&r, &p("a"))
            .unwrap()
            .iter()
            .map(|(p, _)| p.as_str())
            .collect::<Vec<_>>(),
        vec!["a/x"]
    );
    w.snapshot(&mut r).unwrap();
    assert_eq!(w.read(&r, &p("a/y")).unwrap(), None);
}

#[test]
fn writing_descendant_hides_base_file_before_snapshot() {
    let mut r = repo();
    let mut w = Workspace::open(&r, "default").unwrap();
    w.write(&r, &p("a"), b"file").unwrap();
    w.snapshot(&mut r).unwrap();
    w.write(&r, &p("a/b"), b"child").unwrap();
    assert_eq!(w.read(&r, &p("a")).unwrap(), None);
}

#[test]
fn undo_after_new_operation_does_not_redo_previously_undone_operation() {
    let mut r = repo();
    let initial = r.view().clone();
    describe(&mut r, "A");
    describe(&mut r, "B");
    r.undo().unwrap();
    describe(&mut r, "C");
    r.undo().unwrap();
    r.undo().unwrap();
    assert_eq!(*r.view(), initial);
}

#[test]
fn merge_base_must_not_return_ancestor_of_another_common_ancestor() {
    let s = MemoryStore::new();
    let t = empty_tree_id();
    let root = raw_rev(&s, &[], t, "root");
    let c = raw_rev(&s, &[root], t, "common");
    let side = raw_rev(&s, &[root], t, "side");
    let f = raw_rev(&s, &[c], t, "f");
    let e = raw_rev(&s, &[f], t, "e");
    let a = raw_rev(&s, &[side, e], t, "a");
    let b = raw_rev(&s, &[c], t, "b");
    assert_eq!(merge_base(&s, &a, &b).unwrap(), vec![c]);
}

#[test]
fn three_parent_merge_uses_base_of_accumulated_parents() {
    let mut r = repo();
    let s = &**r.store();
    let root = root_revision_id();
    let common = raw_rev(s, &[root], tree(s, &[("x", b"1")]), "common");
    let a = raw_rev(s, &[common], tree(s, &[("x", b"1"), ("a", b"a")]), "a");
    let b = raw_rev(s, &[root], tree(s, &[("b", b"b")]), "b");
    let c = raw_rev(s, &[common], tree(s, &[("x", b"2")]), "c");
    let want = tree(s, &[("x", b"2"), ("a", b"a"), ("b", b"b")]);
    let mut tx = r.start("merge");
    let m = tx.new_change(&[a, b, c], "merge").unwrap();
    r.commit(tx).unwrap();
    assert_eq!(r.revision(&m).unwrap().tree, want);
}

#[test]
fn same_file_to_directory_replacement_with_extra_child_is_clean() {
    let s = MemoryStore::new();
    let base = tree(&s, &[("a", b"file")]);
    let ours = tree(&s, &[("a/x", b"x")]);
    let theirs = tree(&s, &[("a/x", b"x"), ("a/y", b"y")]);
    assert_eq!(
        merge_trees(&s, &base, &ours, &theirs).unwrap(),
        MergeOutcome::Clean(theirs)
    );
    assert_eq!(
        merge_trees(&s, &base, &theirs, &ours).unwrap(),
        MergeOutcome::Clean(theirs)
    );
}

#[test]
fn deleted_directory_graft_cancels_only_when_the_whole_base_is_restored() {
    let mut r = repo();
    let mut w = Workspace::open(&r, "default").unwrap();
    w.write(&r, &p("a/nested/x"), b"x").unwrap();
    w.write(&r, &p("a/y"), b"y").unwrap();
    w.snapshot(&mut r).unwrap();
    let op = r.op_id();
    w.remove(&r, &p("a")).unwrap();
    w.write(&r, &p("a/nested/x"), b"x").unwrap();
    assert!(w.is_dirty());
    assert_eq!(w.read(&r, &p("a/y")).unwrap(), None);
    assert_eq!(w.read(&r, &p("a/nested/x")).unwrap(), Some(b"x".to_vec()));
    assert_eq!(
        w.pending()[&p("a")].unwrap().kind(),
        tig_core::EntryKind::Tree
    );
    let listed = w.list(&r, &p("a/nested")).unwrap();
    assert_eq!(
        listed.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        vec!["a/nested/x"]
    );
    assert_eq!(w.list(&r, &p("")).unwrap(), listed);
    w.write(&r, &p("a/y"), b"y").unwrap();
    assert!(!w.is_dirty());
    assert!(!w.snapshot(&mut r).unwrap());
    assert_eq!(r.op_id(), op);
}

#[test]
fn empty_graft_stays_deleted_and_user_tree_and_sealed_edits_are_refused() {
    let mut r = repo();
    let mut w = Workspace::open(&r, "default").unwrap();
    w.write(&r, &p("a"), b"file").unwrap();
    w.snapshot(&mut r).unwrap();
    w.remove(&r, &p("a/missing")).unwrap();
    assert!(!w.is_dirty());
    w.write(&r, &p("a/b/x"), b"child").unwrap();
    w.remove(&r, &p("a/b")).unwrap();
    assert_eq!(w.pending().get(&p("a")), Some(&None));
    assert_eq!(w.read(&r, &p("a")).unwrap(), None);
    assert!(w.list(&r, &p("")).unwrap().is_empty());
    let before = w.pending().clone();
    let sealed = Leaf::sealed(tig_core::seal::SealedId::compute(
        &tig_core::seal::SealSalt::from_bytes([7; 32]),
        tig_core::EntryKind::Tree,
        &empty_tree_id(),
    ));
    for leaf in [Leaf::tree(empty_tree_id()), sealed] {
        assert!(w.set(&r, p("a"), Some(leaf)).is_err());
        assert_eq!(*w.pending(), before);
    }
    w.snapshot(&mut r).unwrap();
    assert_eq!(w.read(&r, &p("a")).unwrap(), None);
}

#[test]
fn workspace_overlay_matches_sequential_tree_edits() {
    // Include files, directories, and absent ancestors; compare every prefix
    // of each sequence before snapshot as well as the final stored tree.
    let edits = [
        ("a", Some(b"file".as_slice())),
        ("a/x", Some(b"x".as_slice())),
        ("a/y/z", Some(b"z".as_slice())),
        ("a", None),
        ("a/x", None),
        ("a/y", None),
    ];
    for initial in [
        vec![("a", b"file".as_slice())],
        vec![("a/x", b"x".as_slice()), ("a/y/z", b"z".as_slice())],
    ] {
        for i in 0..edits.len().pow(3) {
            let mut r = repo();
            let mut w = Workspace::open(&r, "default").unwrap();
            let mut expected = tree(&**r.store(), &initial);
            let mut tx = r.start("seed tree");
            tx.rewrite(w.working_revision(), |revision| revision.tree = expected)
                .unwrap();
            r.commit(tx).unwrap();
            w.sync(&r).unwrap();
            let mut sequence = i;
            for _ in 0..3 {
                let (path, data) = edits[sequence % edits.len()];
                sequence /= edits.len();
                let leaf = data.map(|data| Leaf::file(r.store().put_blob(data).unwrap()));
                expected = apply_edits(&**r.store(), &expected, &BTreeMap::from([(p(path), leaf)]))
                    .unwrap();
                w.set(&r, p(path), leaf).unwrap();
                assert_eq!(
                    w.list(&r, &p("")).unwrap(),
                    tig_core::treeops::walk(&**r.store(), &expected, &p("")).unwrap()
                );
                for path in ["a", "a/x", "a/y", "a/y/z"] {
                    let expected = lookup(&**r.store(), &expected, &p(path))
                        .unwrap()
                        .filter(|leaf| leaf.is_file_like())
                        .map(|leaf| r.store().get_blob(&leaf.id()).unwrap());
                    assert_eq!(w.read(&r, &p(path)).unwrap(), expected);
                }
            }
            w.snapshot(&mut r).unwrap();
            assert_eq!(r.revision(&w.working_revision()).unwrap().tree, expected);
        }
    }
}

#[test]
fn conflicting_virtual_base_refuses_even_identical_outer_trees() {
    let r = repo();
    let s = &**r.store();
    let root = root_revision_id();
    let a = raw_rev(s, &[root], tree(s, &[("x", b"1")]), "a");
    let b = raw_rev(s, &[root], tree(s, &[("x", b"2")]), "b");
    let resolved = tree(s, &[("x", b"resolved")]);
    let m1 = raw_rev(s, &[a, b], resolved, "m1");
    let m2 = raw_rev(s, &[b, a], resolved, "m2");
    let mut want = vec![a, b];
    want.sort();
    assert_eq!(merge_base(s, &m1, &m2).unwrap(), want);
    let mut tx = r.start("merge");
    let before = tx.view().clone();
    assert!(tx
        .new_change(&[m1, m2], "merge")
        .unwrap_err()
        .to_string()
        .contains("conflict in x"));
    assert_eq!(*tx.view(), before);
}

#[test]
fn nested_criss_cross_builds_recursive_virtual_bases() {
    let mut r = repo();
    let s = &**r.store();
    let root = root_revision_id();
    let a = raw_rev(s, &[root], tree(s, &[("x", b"1")]), "a");
    let b = raw_rev(s, &[root], tree(s, &[("y", b"1")]), "b");
    let xy = tree(s, &[("x", b"1"), ("y", b"1")]);
    let m1 = raw_rev(s, &[a, b], xy, "m1");
    let m2 = raw_rev(s, &[b, a], xy, "m2");
    let c = raw_rev(
        s,
        &[m1],
        tree(s, &[("x", b"1"), ("y", b"1"), ("u", b"u")]),
        "c",
    );
    let d = raw_rev(
        s,
        &[m2],
        tree(s, &[("x", b"1"), ("y", b"1"), ("v", b"v")]),
        "d",
    );
    let both = tree(s, &[("x", b"1"), ("y", b"1"), ("u", b"u"), ("v", b"v")]);
    let n1 = raw_rev(s, &[c, d], both, "n1");
    let n2 = raw_rev(s, &[d, c], both, "n2");
    let left = raw_rev(
        s,
        &[n1],
        tree(s, &[("y", b"1"), ("u", b"u"), ("v", b"v")]),
        "left",
    );
    let right = raw_rev(
        s,
        &[n2],
        tree(s, &[("x", b"1"), ("y", b"2"), ("u", b"u"), ("v", b"v")]),
        "right",
    );
    let want = tree(s, &[("y", b"2"), ("u", b"u"), ("v", b"v")]);
    for parents in [[left, right], [right, left]] {
        let mut tx = r.start("merge");
        let merged = tx.new_change(&parents, "merge").unwrap();
        r.commit(tx).unwrap();
        assert_eq!(r.revision(&merged).unwrap().tree, want);
    }
}

#[test]
fn different_file_directory_replacements_still_conflict() {
    let s = MemoryStore::new();
    let base = tree(&s, &[("a", b"file")]);
    let changed = tree(&s, &[("a", b"modified")]);
    let directory = tree(&s, &[("a/x", b"x")]);
    let different_child = tree(&s, &[("a/x", b"different")]);
    for (ours, theirs) in [(changed, directory), (directory, different_child)] {
        for (ours, theirs) in [(ours, theirs), (theirs, ours)] {
            assert!(matches!(
                merge_trees(&s, &base, &ours, &theirs).unwrap(),
                MergeOutcome::Conflict(_)
            ));
        }
    }
}

/// A conflicting descendant no longer fails the rewrite (that stranded every
/// command, since each one snapshots first). It stays on the previous
/// version of its parent, and the commit reports it.
#[test]
fn conflicting_descendant_stays_on_previous_parent() {
    let mut r = repo();
    let mut w = Workspace::open(&r, "default").unwrap();
    w.write(&r, &p("x"), b"base").unwrap();
    w.snapshot(&mut r).unwrap();
    let a = w.working_revision();
    let mut tx = r.start("new");
    let b = tx.new_change(&[a], "child").unwrap();
    tx.set_working("default", b).unwrap();
    r.commit(tx).unwrap();
    w.sync(&r).unwrap();
    w.write(&r, &p("x"), b"child").unwrap();
    w.snapshot(&mut r).unwrap();
    let changed = tree(&**r.store(), &[("x", b"parent edit")]);
    let child = w.working_revision();
    let mut tx = r.start("rewrite");
    let a2 = tx.rewrite(a, |r| r.tree = changed).unwrap();
    r.commit(tx).unwrap();
    let skipped = r.last_skipped_rebases();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].paths, vec![p("x")]);
    // The child kept its old parent, and both stay visible.
    assert_eq!(r.working_revision("default").unwrap(), child);
    assert_eq!(r.revision(&child).unwrap().parents, vec![a]);
    let visible: Vec<_> = r.visible_revisions().unwrap().into_iter().map(|(id, _)| id).collect();
    assert!(visible.contains(&a) && visible.contains(&a2) && visible.contains(&child));
}

#[test]
fn rewrite_preserves_change_identity_even_when_closure_changes_it() {
    let r = repo();
    let a = r.working_revision("default").unwrap();
    let mut tx = r.start("rewrite");
    let b = tx
        .rewrite(a, |r| {
            r.description = "changed".into();
            r.change_id = tig_core::ChangeId([7; 16]);
        })
        .unwrap();
    assert_eq!(
        r.revision(&a).unwrap().change_id,
        r.revision(&b).unwrap().change_id
    );
}

#[test]
fn full_blob_id_is_not_a_revision_expression() {
    let r = repo();
    let blob = r.store().put_blob(b"blob").unwrap();
    assert!(r.resolve("default", &blob.to_hex()).is_err());
}

#[test]
fn abandon_merge_deduplicates_nonadjacent_parents() {
    let mut r = repo();
    let root = root_revision_id();
    let mut tx = r.start("graph");
    let a = tx.new_change(&[root], "a").unwrap();
    let b = tx.new_change(&[root], "b").unwrap();
    let m = tx.new_change(&[a, b], "m").unwrap();
    let child = tx.new_change(&[m, a], "child").unwrap();
    tx.set_working("default", child).unwrap();
    r.commit(tx).unwrap();
    let mut tx = r.start("abandon");
    tx.abandon(m).unwrap();
    r.commit(tx).unwrap();
    let wc = r.working_revision("default").unwrap();
    assert_eq!(r.revision(&wc).unwrap().parents, vec![a, b]);
}

#[test]
fn noop_reparentless_rewrite_returns_same_id() {
    let r = repo();
    let a = r.working_revision("default").unwrap();
    let mut tx = r.start("noop");
    let before = tx.view().clone();
    assert_eq!(tx.rewrite(a, |_| {}).unwrap(), a);
    assert_eq!(*tx.view(), before);
}

#[test]
fn tree_output_is_sorted_and_restoring_tree_is_noop() {
    let s = MemoryStore::new();
    let paths = ["a0", "a/b", "a.b", "a-b"];
    let t = tree(&s, &paths.map(|p| (p, b"x".as_slice())));
    let walk = tig_core::treeops::walk(&s, &t, &p("")).unwrap();
    assert_eq!(
        walk.iter().map(|(p, _)| p.as_str()).collect::<Vec<_>>(),
        vec!["a-b", "a.b", "a/b", "a0"]
    );
    let leaf = lookup(&s, &t, &p("a/b")).unwrap();
    assert_eq!(
        apply_edits(&s, &t, &BTreeMap::from([(p("a/b"), leaf)])).unwrap(),
        t
    );
}

#[test]
fn committing_stale_transaction_on_same_repo_is_refused() {
    let mut r = repo();
    let wc = r.working_revision("default").unwrap();
    let mut a = r.start("a");
    let mut b = r.start("b");
    a.set_bookmark("a", wc).unwrap();
    b.set_bookmark("b", wc).unwrap();
    r.commit(a).unwrap();
    assert!(r.commit(b).is_err());
}

#[test]
fn new_change_on_hidden_descendant_normalizes_heads() {
    let mut r = repo();
    let a = r.working_revision("default").unwrap();
    let mut tx = r.start("b");
    let b = tx.new_change(&[a], "b").unwrap();
    r.commit(tx).unwrap();
    r.undo().unwrap();
    let mut tx = r.start("c");
    let c = tx.new_change(&[b], "c").unwrap();
    r.commit(tx).unwrap();
    assert_eq!(r.view().heads.iter().copied().collect::<Vec<_>>(), vec![c]);
}

#[test]
fn criss_cross_requires_merging_all_best_bases() {
    let mut r = repo();
    let s = &**r.store();
    let root = root_revision_id();
    let a = raw_rev(s, &[root], tree(s, &[("x", b"1")]), "a");
    let b = raw_rev(s, &[root], tree(s, &[("y", b"1")]), "b");
    let t = tree(s, &[("x", b"1"), ("y", b"1")]);
    let m1 = raw_rev(s, &[a, b], t, "m1");
    let m2 = raw_rev(s, &[b, a], t, "m2");
    let left = raw_rev(s, &[m1], tree(s, &[("y", b"1")]), "left");
    let right = raw_rev(s, &[m2], tree(s, &[("x", b"1"), ("y", b"2")]), "right");
    let want = tree(s, &[("y", b"2")]);
    let mut tx = r.start("merge");
    let m = tx.new_change(&[left, right], "merge").unwrap();
    r.commit(tx).unwrap();
    assert_eq!(r.revision(&m).unwrap().tree, want);
}

use std::sync::atomic::{AtomicUsize, Ordering};
struct ByteStore {
    inner: MemoryStore,
    read: AtomicUsize,
    written: AtomicUsize,
    gets: AtomicUsize,
}
impl ByteStore {
    fn new() -> Self {
        Self {
            inner: MemoryStore::new(),
            read: AtomicUsize::new(0),
            written: AtomicUsize::new(0),
            gets: AtomicUsize::new(0),
        }
    }
    fn reset(&self) {
        self.read.store(0, Ordering::Relaxed);
        self.written.store(0, Ordering::Relaxed);
        self.gets.store(0, Ordering::Relaxed);
    }
    fn bytes(&self) -> usize {
        self.read.load(Ordering::Relaxed) + self.written.load(Ordering::Relaxed)
    }
}
impl Store for ByteStore {
    fn get_raw(&self, id: &ObjectId) -> tig_core::Result<Option<(tig_core::ObjectKind, Vec<u8>)>> {
        self.gets.fetch_add(1, Ordering::Relaxed);
        let v = self.inner.get_raw(id)?;
        if let Some((_, body)) = &v {
            self.read.fetch_add(body.len(), Ordering::Relaxed);
        }
        Ok(v)
    }
    fn put_raw(
        &self,
        id: &ObjectId,
        kind: tig_core::ObjectKind,
        body: &[u8],
    ) -> tig_core::Result<()> {
        self.written.fetch_add(body.len(), Ordering::Relaxed);
        self.inner.put_raw(id, kind, body)
    }
    fn has(&self, id: &ObjectId) -> tig_core::Result<bool> {
        self.inner.has(id)
    }
}
fn one_path_cost(n: usize) -> (usize, usize, usize, usize) {
    let s = Arc::new(ByteStore::new());
    let mut r = Repo::init(
        s.clone(),
        Arc::new(MemoryOpHead::new()),
        Settings::default(),
    )
    .unwrap();
    let mut w = Workspace::open(&r, "default").unwrap();
    for i in 0..n {
        w.write(&r, &p(&format!("f{i:05}")), b"old").unwrap();
    }
    w.snapshot(&mut r).unwrap();
    let old = r.revision(&w.working_revision()).unwrap().tree;
    s.reset();
    w.read(&r, &p("f00000")).unwrap();
    let read = s.bytes();
    s.reset();
    w.write(&r, &p("f00000"), b"new").unwrap();
    let write = s.bytes();
    s.reset();
    w.snapshot(&mut r).unwrap();
    let snap = s.bytes();
    let new = r.revision(&w.working_revision()).unwrap().tree;
    s.reset();
    tig_core::treeops::diff_trees(&*s, &old, &new).unwrap();
    let diff = s.bytes();
    (read, write, snap, diff)
}
#[test]
#[ignore = "wide directories: deferred format decision, see DESIGN.md Known gaps"]
fn one_path_hot_operations_do_not_scale_with_unrelated_files() {
    let small = one_path_cost(10);
    let large = one_path_cost(1000);
    println!("10 files bytes (read,write,snapshot,diff): {small:?}; 1000 files: {large:?}");
    assert!(
        large.0 < small.0 * 4
            && large.1 < small.1 * 4
            && large.2 < small.2 * 4
            && large.3 < small.3 * 4
    );
}

#[test]
fn graft_hot_operations_do_not_read_unrelated_subtrees() {
    fn cost(n: usize) -> usize {
        let s = Arc::new(ByteStore::new());
        let mut r = Repo::init(
            s.clone(),
            Arc::new(MemoryOpHead::new()),
            Settings::default(),
        )
        .unwrap();
        let mut w = Workspace::open(&r, "default").unwrap();
        let mut edits = BTreeMap::new();
        let blob = s.put_blob(b"old").unwrap();
        for i in 0..n {
            edits.insert(p(&format!("unrelated/f{i:05}")), Some(Leaf::file(blob)));
        }
        for path in ["a/x", "a/y"] {
            edits.insert(p(path), Some(Leaf::file(blob)));
        }
        let tree = apply_edits(&*s, &empty_tree_id(), &edits).unwrap();
        let mut tx = r.start("seed tree");
        tx.rewrite(w.working_revision(), |revision| revision.tree = tree)
            .unwrap();
        r.commit(tx).unwrap();
        w.sync(&r).unwrap();
        s.reset();
        w.remove(&r, &p("a")).unwrap();
        w.write(&r, &p("a/x"), b"old").unwrap();
        w.read(&r, &p("a/x")).unwrap();
        w.list(&r, &p("a")).unwrap();
        w.remove(&r, &p("a/x")).unwrap();
        w.write(&r, &p("a/x"), b"new").unwrap();
        w.snapshot(&mut r).unwrap();
        s.bytes()
    }
    assert_eq!(cost(10), cost(1000));
}

#[test]
fn best_base_search_loads_shared_history_once() {
    let s = ByteStore::new();
    let mut common = raw_rev(&s, &[], empty_tree_id(), "root");
    for i in 1..256 {
        common = raw_rev(&s, &[common], empty_tree_id(), &format!("common {i}"));
    }
    let left = raw_rev(&s, &[common], empty_tree_id(), "left");
    let right = raw_rev(&s, &[common], empty_tree_id(), "right");
    s.reset();
    assert_eq!(merge_base(&s, &left, &right).unwrap(), vec![common]);
    assert_eq!(s.gets.load(Ordering::Relaxed), 258);
    assert_eq!(merge_base(&s, &left, &common).unwrap(), vec![common]);
    let other = raw_rev(&s, &[], empty_tree_id(), "unrelated");
    assert!(merge_base(&s, &left, &other).unwrap().is_empty());
    assert!(merge_base(&s, &left, &s.put_blob(b"not a revision").unwrap()).is_err());
}

#[test]
fn bookmark_visible_child_prevents_discarding_its_parent() {
    let mut r = repo();
    let a = r.working_revision("default").unwrap();
    let mut tx = r.start("b");
    let b = tx.new_change(&[a], "b").unwrap();
    r.commit(tx).unwrap();
    r.undo().unwrap();
    let mut tx = r.start("bookmark old child");
    tx.set_bookmark("saved", b).unwrap();
    r.commit(tx).unwrap();
    let mut tx = r.start("edit sibling");
    let c = tx.new_change(&[root_revision_id()], "c").unwrap();
    tx.set_working("default", c).unwrap();
    r.commit(tx).unwrap();
    assert_eq!(r.view().bookmarks["saved"], b);
    assert!(r
        .visible_revisions()
        .unwrap()
        .iter()
        .any(|(id, _)| *id == a));
}

#[test]
fn graph_rewrite_rebases_merge_both_parents_and_grandchild_workspaces() {
    let mut r = repo();
    let s = &**r.store();
    let root = root_revision_id();
    let a = raw_rev(s, &[root], tree(s, &[("x", b"1")]), "a");
    let b = raw_rev(s, &[a], tree(s, &[("x", b"1"), ("b", b"b")]), "b");
    let c = raw_rev(s, &[a], tree(s, &[("x", b"1"), ("c", b"c")]), "c");
    let mt = tree(s, &[("x", b"1"), ("b", b"b"), ("c", b"c")]);
    let m = raw_rev(s, &[b, c], mt, "merge");
    let g = raw_rev(
        s,
        &[m],
        tree(s, &[("x", b"1"), ("b", b"b"), ("c", b"c"), ("g", b"g")]),
        "g",
    );
    let changed = tree(s, &[("x", b"2")]);
    let mut tx = r.start("workspaces");
    tx.set_working("default", g).unwrap();
    tx.set_working("bws", b).unwrap();
    tx.set_working("cws", c).unwrap();
    tx.set_bookmark("merged", m).unwrap();
    r.commit(tx).unwrap();
    let mut tx = r.start("rewrite");
    let anew = tx.rewrite(a, |r| r.tree = changed).unwrap();
    r.commit(tx).unwrap();
    let bnew = r.working_revision("bws").unwrap();
    let cnew = r.working_revision("cws").unwrap();
    assert_eq!(r.revision(&bnew).unwrap().parents, vec![anew]);
    assert_eq!(r.revision(&cnew).unwrap().parents, vec![anew]);
    let mnew = r.view().bookmarks["merged"];
    assert_eq!(r.revision(&mnew).unwrap().parents, vec![bnew, cnew]);
    assert_eq!(
        r.revision(&r.working_revision("default").unwrap())
            .unwrap()
            .parents,
        vec![mnew]
    );
    let w = Workspace::open(&r, "default").unwrap();
    for (path, data) in [("x", b"2"), ("b", b"b"), ("c", b"c"), ("g", b"g")] {
        assert_eq!(w.read(&r, &p(path)).unwrap().unwrap(), data);
    }
    assert!(r
        .visible_revisions()
        .unwrap()
        .iter()
        .all(|(id, _)| ![a, b, c, m, g].contains(id)));
}

#[test]
fn abandon_rebases_grandchildren_and_moves_bookmark() {
    let mut r = repo();
    let s = &**r.store();
    let root = root_revision_id();
    let a = raw_rev(s, &[root], tree(s, &[("x", b"x")]), "a");
    let b = raw_rev(s, &[a], tree(s, &[("x", b"x"), ("b", b"b")]), "b");
    let c = raw_rev(
        s,
        &[b],
        tree(s, &[("x", b"x"), ("b", b"b"), ("c", b"c")]),
        "c",
    );
    let mut tx = r.start("graph");
    tx.set_working("default", c).unwrap();
    tx.set_bookmark("a", a).unwrap();
    tx.set_bookmark("b", b).unwrap();
    r.commit(tx).unwrap();
    let mut tx = r.start("abandon");
    tx.abandon(a).unwrap();
    r.commit(tx).unwrap();
    assert_eq!(r.view().bookmarks["a"], root);
    let bnew = r.view().bookmarks["b"];
    assert_eq!(r.revision(&bnew).unwrap().parents, vec![root]);
    assert_eq!(
        r.revision(&r.working_revision("default").unwrap())
            .unwrap()
            .parents,
        vec![bnew]
    );
    let w = Workspace::open(&r, "default").unwrap();
    assert_eq!(w.read(&r, &p("x")).unwrap(), None);
    assert_eq!(w.read(&r, &p("b")).unwrap().unwrap(), b"b");
    assert_eq!(w.read(&r, &p("c")).unwrap().unwrap(), b"c");
    assert_eq!(r.view().heads.len(), 1);
}

#[test]
fn stale_workspace_refuses_snapshot_without_losing_overlay() {
    let mut r = repo();
    let mut w = Workspace::open(&r, "default").unwrap();
    w.write(&r, &p("x"), b"x").unwrap();
    describe(&mut r, "changed");
    let op = r.op_id();
    assert!(w
        .snapshot(&mut r)
        .unwrap_err()
        .to_string()
        .contains("stale"));
    assert!(w.is_dirty());
    assert_eq!(r.op_id(), op);
    assert!(w.sync(&r).is_err());
}

#[test]
fn set_working_preserves_bookmarks_other_workspaces_ancestors_and_root() {
    for guard in ["bookmark", "workspace", "ancestor", "root"] {
        let mut r = repo();
        let old = r.working_revision("default").unwrap();
        let mut tx = r.start("move");
        if guard == "bookmark" {
            tx.set_bookmark("keep", old).unwrap();
        }
        if guard == "workspace" {
            tx.set_working("other", old).unwrap();
        }
        let parent = if guard == "ancestor" {
            old
        } else {
            root_revision_id()
        };
        let new = if guard == "root" {
            root_revision_id()
        } else {
            tx.new_change(&[parent], "new").unwrap()
        };
        if guard == "root" {
            // A workspace may never sit on the root: it could not record edits.
            assert!(tx.set_working("default", new).is_err());
            continue;
        }
        tx.set_working("default", new).unwrap();
        r.commit(tx).unwrap();
        assert!(r.revision(&root_revision_id()).is_ok());
        if guard != "root" {
            assert!(r
                .visible_revisions()
                .unwrap()
                .iter()
                .any(|(id, _)| *id == old));
        }
    }
}

#[test]
fn workspace_nested_overlays_delete_replace_and_cancel() {
    let mut r = repo();
    let mut w = Workspace::open(&r, "default").unwrap();
    w.write(&r, &p("a/b"), b"b").unwrap();
    w.remove(&r, &p("a")).unwrap();
    assert!(!w.is_dirty());
    w.write(&r, &p("a"), b"file").unwrap();
    assert_eq!(w.list(&r, &p("a")).unwrap().len(), 1);
    assert_eq!(w.read(&r, &p("a/b")).unwrap(), None);
    w.snapshot(&mut r).unwrap();
    assert_eq!(w.read(&r, &p("a")).unwrap().unwrap(), b"file");
    w.write(&r, &p("a/b"), b"b").unwrap();
    w.write(&r, &p("a"), b"file").unwrap();
    assert!(!w.is_dirty());
}

#[test]
fn resolve_prefix_ambiguity_parent_steps_and_bookmark_precedence() {
    let mut r = repo();
    let mut tx = r.start("graph");
    let a = r.working_revision("default").unwrap();
    let b = tx.new_change(&[a], "b").unwrap();
    tx.set_working("default", b).unwrap();
    tx.set_bookmark("abcd", a).unwrap();
    r.commit(tx).unwrap();
    assert_eq!(r.resolve("default", "@--").unwrap(), root_revision_id());
    assert_eq!(r.resolve("default", "abcd").unwrap(), a);
    assert!(r.resolve("default", "root-").is_err());
    let change = r.revision(&b).unwrap().change_id;
    let all = r.visible_revisions().unwrap();
    let short = r.short_change_id(&change, &all);
    assert!(short.len() >= 4);
    assert_eq!(r.resolve("default", &short).unwrap(), b);
    let mut other = r.revision(&a).unwrap();
    other.change_id = change;
    let text = change.to_text();
    let mut bytes = other.change_id.0;
    bytes[15] ^= 1;
    other.change_id = tig_core::ChangeId(bytes);
    let mut synthetic = all.clone();
    synthetic.push((ObjectId([9; 32]), other));
    assert_eq!(r.short_change_id(&change, &synthetic), text);
}

#[test]
fn merge_basic_delete_modify_same_change_and_executable_cases() {
    let s = MemoryStore::new();
    let base = tree(&s, &[("a", b"1"), ("d/x", b"1")]);
    let same = tree(&s, &[("a", b"2"), ("d/x", b"1")]);
    assert_eq!(
        merge_trees(&s, &base, &same, &same).unwrap(),
        MergeOutcome::Clean(same)
    );
    let deleted = tree(&s, &[("a", b"1")]);
    let modified = tree(&s, &[("a", b"1"), ("d/x", b"2")]);
    assert!(matches!(
        merge_trees(&s, &base, &deleted, &modified).unwrap(),
        MergeOutcome::Conflict(_)
    ));
    let added = tree(&s, &[("a", b"1"), ("d/x", b"1"), ("d/y", b"y")]);
    let want = tree(&s, &[("a", b"1"), ("d/y", b"y")]);
    assert_eq!(
        merge_trees(&s, &base, &deleted, &added).unwrap(),
        MergeOutcome::Clean(want)
    );
    let id = s.put_blob(b"1").unwrap();
    let exec = apply_edits(
        &s,
        &base,
        &BTreeMap::from([(p("a"), Some(Leaf::executable(id)))]),
    )
    .unwrap();
    assert_eq!(
        merge_trees(&s, &base, &modified, &exec).unwrap(),
        MergeOutcome::Clean(
            apply_edits(
                &s,
                &modified,
                &BTreeMap::from([(p("a"), Some(Leaf::executable(id)))])
            )
            .unwrap()
        )
    );
}

#[test]
fn visible_order_is_topological_despite_parent_newer_timestamp() {
    let mut r = repo();
    let mut parent = root_revision();
    parent.parents = vec![root_revision_id()];
    parent.description = "parent".into();
    parent.committer.timestamp_ms = 100;
    let a = r.store().put(&Object::Revision(parent)).unwrap();
    let mut child = r.revision(&a).unwrap();
    child.parents = vec![a];
    child.description = "child".into();
    child.committer.timestamp_ms = 10;
    let b = r.store().put(&Object::Revision(child)).unwrap();
    let mut other = r.revision(&a).unwrap();
    other.parents = vec![root_revision_id()];
    other.description = "unrelated".into();
    other.committer.timestamp_ms = 20;
    let c = r.store().put(&Object::Revision(other)).unwrap();
    let mut tx = r.start("graph");
    tx.set_working("default", b).unwrap();
    tx.set_working("other", c).unwrap();
    r.commit(tx).unwrap();
    let all = r.visible_revisions().unwrap();
    assert_eq!(
        all.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
        vec![c, b, a, root_revision_id()]
    );
}
