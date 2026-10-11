//! End-to-end tests of the change model on the in-memory backend.

use std::sync::Arc;

use tig_core::ophead::MemoryOpHead;
use tig_core::repo::{root_revision_id, Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::workspace::Workspace;
use tig_core::{MemoryStore, RepoPath};

fn p(s: &str) -> RepoPath {
    RepoPath::new(s).unwrap()
}

fn repo() -> Repo {
    let settings = Settings { fixed_time_ms: Some(1_700_000_000_000), ..Settings::default() };
    Repo::init(Arc::new(MemoryStore::new()), Arc::new(MemoryOpHead::new()), settings).unwrap()
}

#[test]
fn init_has_empty_working_change_on_root() {
    let repo = repo();
    let wc = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let rev = repo.revision(&wc).unwrap();
    assert_eq!(rev.parents, vec![root_revision_id()]);
    let log = repo.visible_revisions().unwrap();
    assert_eq!(log.len(), 2);
    assert_eq!(log[0].0, wc);
    assert_eq!(log[1].0, root_revision_id());
}

#[test]
fn snapshot_keeps_change_id_and_records_predecessor() {
    let mut repo = repo();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    let before = ws.working_revision();
    ws.write(&repo, &p("src/main.rs"), b"fn main() {}").unwrap();
    assert!(ws.snapshot(&mut repo).unwrap());
    let after = ws.working_revision();
    assert_ne!(before, after);
    let (a, b) = (repo.revision(&before).unwrap(), repo.revision(&after).unwrap());
    assert_eq!(a.change_id, b.change_id);
    assert_eq!(b.predecessors, vec![before]);
    assert_eq!(ws.read(&repo, &p("src/main.rs")).unwrap().unwrap(), b"fn main() {}");
    // Old revision is hidden, not deleted.
    assert_eq!(repo.visible_revisions().unwrap().len(), 2);
    assert!(repo.revision(&before).is_ok());
}

#[test]
fn save_revert_loop_is_a_noop() {
    let mut repo = repo();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &p("a.txt"), b"1").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let op = repo.op_id();
    ws.write(&repo, &p("a.txt"), b"2").unwrap();
    ws.write(&repo, &p("a.txt"), b"1").unwrap();
    ws.write(&repo, &p("tmp"), b"x").unwrap();
    ws.remove(&repo, &p("tmp")).unwrap();
    assert!(!ws.is_dirty());
    assert!(!ws.snapshot(&mut repo).unwrap());
    assert_eq!(repo.op_id(), op);
}

#[test]
fn new_describe_and_undo() {
    let mut repo = repo();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &p("a.txt"), b"1").unwrap();
    ws.snapshot(&mut repo).unwrap();

    let mut tx = repo.start("describe");
    let wc = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    tx.rewrite(wc, |r| r.description = "first".into()).unwrap();
    repo.commit(tx).unwrap();

    let mut tx = repo.start("new");
    let first = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let child = tx.new_change(&[first], "").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
    repo.commit(tx).unwrap();
    ws.sync(&repo).unwrap();
    assert_eq!(ws.read(&repo, &p("a.txt")).unwrap().unwrap(), b"1");
    assert_eq!(repo.visible_revisions().unwrap().len(), 3);

    // Undo "new", then "describe", then the snapshot: back to an empty change.
    repo.undo().unwrap();
    assert_eq!(repo.working_revision(DEFAULT_WORKSPACE).unwrap(), first);
    repo.undo().unwrap();
    let wc = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    assert_eq!(repo.revision(&wc).unwrap().description, "");
    repo.undo().unwrap();
    ws.sync(&repo).unwrap();
    assert_eq!(ws.read(&repo, &p("a.txt")).unwrap(), None);
    // Undoing the init itself is refused.
    assert!(repo.undo().is_err());
    // restore jumps anywhere, including forward.
    let ops = repo.op_log(100).unwrap();
    let describe_op = ops.iter().find(|(_, o)| o.description == "describe").unwrap().0;
    repo.restore_operation(&describe_op).unwrap();
    let wc = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    assert_eq!(repo.revision(&wc).unwrap().description, "first");
}

#[test]
fn editing_a_parent_rebases_children() {
    let mut repo = repo();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &p("a.txt"), b"a1").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let parent = ws.working_revision();

    let mut tx = repo.start("new");
    let child = tx.new_change(&[parent], "").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
    repo.commit(tx).unwrap();
    ws.sync(&repo).unwrap();
    ws.write(&repo, &p("b.txt"), b"b1").unwrap();
    ws.snapshot(&mut repo).unwrap();

    // A second workspace edits the parent change directly.
    let mut tx = repo.start("edit parent");
    tx.set_working("other", parent).unwrap();
    repo.commit(tx).unwrap();
    let mut other = Workspace::open(&repo, "other").unwrap();
    other.write(&repo, &p("a.txt"), b"a2").unwrap();
    other.snapshot(&mut repo).unwrap();

    // The child was rebased: it sees a2 and still has b1.
    ws.sync(&repo).unwrap();
    assert_eq!(ws.read(&repo, &p("a.txt")).unwrap().unwrap(), b"a2");
    assert_eq!(ws.read(&repo, &p("b.txt")).unwrap().unwrap(), b"b1");
    let wc = repo.revision(&ws.working_revision()).unwrap();
    assert_eq!(wc.parents, vec![other.working_revision()]);
}

#[test]
fn conflicting_rebase_is_refused_without_changes() {
    let mut repo = repo();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &p("a.txt"), b"base").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let parent = ws.working_revision();
    let mut tx = repo.start("new");
    let child = tx.new_change(&[parent], "").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
    repo.commit(tx).unwrap();
    ws.sync(&repo).unwrap();
    ws.write(&repo, &p("a.txt"), b"child").unwrap();
    ws.snapshot(&mut repo).unwrap();

    let mut tx = repo.start("edit parent");
    tx.set_working("other", parent).unwrap();
    repo.commit(tx).unwrap();
    let mut other = Workspace::open(&repo, "other").unwrap();
    other.write(&repo, &p("a.txt"), b"parent edit").unwrap();
    let op = repo.op_id();
    let err = other.snapshot(&mut repo).unwrap_err().to_string();
    assert!(err.contains("a.txt"), "{err}");
    assert_eq!(repo.op_id(), op);
}

#[test]
fn moving_away_from_empty_change_abandons_it() {
    let mut repo = repo();
    let wc = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let mut tx = repo.start("new");
    let sibling = tx.new_change(&[root_revision_id()], "").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, sibling).unwrap();
    repo.commit(tx).unwrap();
    let visible: Vec<_> = repo.visible_revisions().unwrap().into_iter().map(|(id, _)| id).collect();
    assert!(!visible.contains(&wc));
    assert_eq!(visible.len(), 2);
}

#[test]
fn resolve_specs() {
    let mut repo = repo();
    let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    ws.write(&repo, &p("a"), b"1").unwrap();
    ws.snapshot(&mut repo).unwrap();
    let wc = ws.working_revision();
    let rev = repo.revision(&wc).unwrap();
    assert_eq!(repo.resolve(DEFAULT_WORKSPACE, "@").unwrap(), wc);
    assert_eq!(repo.resolve(DEFAULT_WORKSPACE, "@-").unwrap(), root_revision_id());
    assert_eq!(repo.resolve(DEFAULT_WORKSPACE, &rev.change_id.short(8)).unwrap(), wc);
    assert_eq!(repo.resolve(DEFAULT_WORKSPACE, &wc.short(10)).unwrap(), wc);
    let mut tx = repo.start("bookmark");
    tx.set_bookmark("main", wc).unwrap();
    repo.commit(tx).unwrap();
    assert_eq!(repo.resolve(DEFAULT_WORKSPACE, "main").unwrap(), wc);
    assert!(repo.resolve(DEFAULT_WORKSPACE, "nope!").is_err());
    assert!(repo.resolve(DEFAULT_WORKSPACE, "root-").is_err());
}

#[test]
fn concurrent_commit_is_detected() {
    let store: Arc<MemoryStore> = Arc::new(MemoryStore::new());
    let head = Arc::new(MemoryOpHead::new());
    let mut a = Repo::init(store.clone(), head.clone(), Settings::default()).unwrap();
    let mut b = Repo::load(store, head, Settings::default()).unwrap();
    let tx = a.start("a");
    a.commit(tx).unwrap();
    let tx = b.start("b");
    assert!(b.commit(tx).is_err());
    b.reload().unwrap();
    let tx = b.start("b");
    b.commit(tx).unwrap();
}

/// Security review round 1, finding 6: two transactions from the same repo
/// used to both commit, silently dropping the first one's bookmark.
#[test]
fn stale_transaction_is_rejected() {
    let mut repo = repo();
    let wc = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let mut a = repo.start("a");
    let mut b = repo.start("b");
    a.set_bookmark("first", wc).unwrap();
    b.set_bookmark("second", wc).unwrap();
    repo.commit(a).unwrap();
    assert!(repo.commit(b).is_err());
    assert!(repo.view().bookmarks.contains_key("first"));

    let other = Repo::init(Arc::new(MemoryStore::new()), Arc::new(MemoryOpHead::new()), Settings::default()).unwrap();
    assert!(repo.commit(other.start("foreign")).is_err());
}
