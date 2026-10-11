//! A repo is a store plus an op-head pointer. All state lives in the `View` of
//! the current operation; every change goes through a `Transaction` that
//! writes a new view and operation. See DESIGN.md "Changes, not commits" and
//! "Operation log".
//!
//! Phase 1 walks the revision graph from the heads where it needs the visible
//! set (log, rebasing descendants). That is fine for small and medium repos;
//! a persistent revision index replaces these walks before large-repo work.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{Error, Result};
use crate::id::{ChangeId, ObjectId};
use crate::merge::{ancestors, merge_base, merge_trees, MergeOutcome};
use crate::object::{Object, Operation, Revision, Signature, View};
use crate::ophead::OpHeadStore;
use crate::store::{empty_tree_id, Store, StoreExt};

pub const DEFAULT_WORKSPACE: &str = "default";

#[derive(Clone, Debug)]
pub struct Settings {
    pub user_name: String,
    pub user_email: String,
    pub tz_offset_min: i32,
    /// Freezes the clock (tests, reproducible scripts).
    pub fixed_time_ms: Option<i64>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { user_name: "tig user".into(), user_email: "user@localhost".into(), tz_offset_min: 0, fixed_time_ms: None }
    }
}

impl Settings {
    pub fn now_ms(&self) -> i64 {
        self.fixed_time_ms.unwrap_or_else(|| {
            SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
        })
    }

    pub fn signature(&self) -> Signature {
        Signature {
            name: self.user_name.clone(),
            email: self.user_email.clone(),
            timestamp_ms: self.now_ms(),
            tz_offset_min: self.tz_offset_min,
        }
    }

    fn user(&self) -> String {
        format!("{} <{}>", self.user_name, self.user_email)
    }
}

/// The revision every history starts from: empty tree, no parents, all-zero
/// change id. Identical in every repo.
pub fn root_revision() -> Revision {
    let zero = Signature { name: String::new(), email: String::new(), timestamp_ms: 0, tz_offset_min: 0 };
    Revision {
        tree: empty_tree_id(),
        parents: vec![],
        change_id: ChangeId([0; 16]),
        predecessors: vec![],
        author: zero.clone(),
        committer: zero,
        description: String::new(),
    }
}

pub fn root_revision_id() -> ObjectId {
    Object::Revision(root_revision()).id()
}

pub struct Repo {
    store: Arc<dyn Store>,
    op_head: Arc<dyn OpHeadStore>,
    settings: Settings,
    op_id: ObjectId,
    op: Operation,
    view: View,
}

impl Repo {
    /// Creates a new repo with an empty `default` workspace on top of root.
    pub fn init(store: Arc<dyn Store>, op_head: Arc<dyn OpHeadStore>, settings: Settings) -> Result<Repo> {
        if op_head.get()?.is_some() {
            return Err(Error::Invalid("a repo already exists here".into()));
        }
        store.put(&Object::Tree(crate::object::Tree::empty()))?;
        store.put(&Object::Revision(root_revision()))?;
        let mut tx = Transaction {
            store: store.clone(),
            settings: settings.clone(),
            view: View::default(),
            description: "initialize repo".into(),
            undo_of: None,
            base_op: None,
        };
        tx.view.heads.insert(root_revision_id());
        let wc = tx.new_change(&[root_revision_id()], "")?;
        tx.view.workspaces.insert(DEFAULT_WORKSPACE.into(), wc);
        let (op_id, op) = tx.write_operation(None)?;
        if !op_head.compare_and_set(None, op_id)? {
            return Err(Error::Invalid("a repo was created here concurrently".into()));
        }
        Ok(Repo { store, op_head, settings, op_id, op, view: tx.view })
    }

    pub fn load(store: Arc<dyn Store>, op_head: Arc<dyn OpHeadStore>, settings: Settings) -> Result<Repo> {
        let op_id = op_head.get()?.ok_or_else(|| Error::Invalid("no repo here (no operation head)".into()))?;
        let op = store.get_operation(&op_id)?;
        let view = store.get_view(&op.view)?;
        Ok(Repo { store, op_head, settings, op_id, op, view })
    }

    /// Re-reads the op head (after another process or workspace changed it).
    pub fn reload(&mut self) -> Result<()> {
        let fresh = Repo::load(self.store.clone(), self.op_head.clone(), self.settings.clone())?;
        *self = fresh;
        Ok(())
    }

    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    pub fn settings(&self) -> &Settings {
        &self.settings
    }

    pub fn view(&self) -> &View {
        &self.view
    }

    pub fn op_id(&self) -> ObjectId {
        self.op_id
    }

    pub fn operation(&self) -> &Operation {
        &self.op
    }

    pub fn revision(&self, id: &ObjectId) -> Result<Revision> {
        self.store.get_revision(id)
    }

    pub fn working_revision(&self, workspace: &str) -> Result<ObjectId> {
        self.view
            .workspaces
            .get(workspace)
            .copied()
            .ok_or_else(|| Error::Invalid(format!("no workspace named {workspace:?}")))
    }

    pub fn start(&self, description: impl Into<String>) -> Transaction {
        Transaction {
            store: self.store.clone(),
            settings: self.settings.clone(),
            view: self.view.clone(),
            description: description.into(),
            undo_of: None,
            base_op: Some(self.op_id),
        }
    }

    /// Writes the transaction as a new operation and makes it current.
    /// Fails without side effects (other than unreachable objects) if another
    /// process committed an operation since this repo was loaded.
    pub fn commit(&mut self, tx: Transaction) -> Result<ObjectId> {
        // A transaction is a diff against the view it started from. Committing
        // it on top of anything else would silently drop the operations in
        // between, so it must belong to this repo and this exact operation.
        if !same_store(&tx.store, &self.store) {
            return Err(Error::Invalid("transaction belongs to a different repo".into()));
        }
        if tx.base_op != Some(self.op_id) {
            return Err(Error::Invalid(
                "transaction was started before the latest operation; start a new one".into(),
            ));
        }
        let (op_id, op) = tx.write_operation(Some(self.op_id))?;
        if !self.op_head.compare_and_set(Some(self.op_id), op_id)? {
            return Err(Error::Invalid(
                "the repo changed while this command ran (another tig process?); run it again".into(),
            ));
        }
        self.op_id = op_id;
        self.op = op;
        self.view = tx.view;
        Ok(op_id)
    }

    /// Undoes the latest operation. Repeated undo keeps stepping back.
    pub fn undo(&mut self) -> Result<ObjectId> {
        // Undo the operation at the current logical position: the repo then
        // looks as it did at the position before it.
        let target = self.logical_position(self.op_id)?;
        let target_op = self.store.get_operation(&target)?;
        let Some(parent) = target_op.parents.first() else {
            return Err(Error::Invalid("nothing left to undo: the repo is back at its first operation".into()));
        };
        let restore = self.logical_position(*parent)?;
        let mut tx = self.start(format!("undo: {}", target_op.description));
        tx.view = self.store.get_view(&self.store.get_operation(&restore)?.view)?;
        tx.undo_of = Some(target);
        self.commit(tx)
    }

    /// The non-undo operation whose state `op` represents. A normal operation
    /// is its own position. An undo of T sits where history was before T, so
    /// undo, new work, undo, undo... always walks back through real history
    /// and never re-applies something already undone.
    fn logical_position(&self, mut op: ObjectId) -> Result<ObjectId> {
        loop {
            let Some(undone) = self.store.get_operation(&op)?.undo_of else {
                return Ok(op);
            };
            let Some(&before) = self.store.get_operation(&undone)?.parents.first() else {
                return Ok(undone);
            };
            op = before;
        }
    }

    /// Makes the repo look exactly as it did after `op`.
    pub fn restore_operation(&mut self, op: &ObjectId) -> Result<ObjectId> {
        let target = self.store.get_operation(op)?;
        let mut tx = self.start(format!("restore to operation {}", op.short(12)));
        tx.view = self.store.get_view(&target.view)?;
        self.commit(tx)
    }

    /// Operations newest first, following first parents.
    pub fn op_log(&self, limit: usize) -> Result<Vec<(ObjectId, Operation)>> {
        let mut out = Vec::new();
        let mut cur = Some(self.op_id);
        while let Some(id) = cur {
            if out.len() >= limit {
                break;
            }
            let op = self.store.get_operation(&id)?;
            cur = op.parents.first().copied();
            out.push((id, op));
        }
        Ok(out)
    }

    /// Visible revisions in topological order (children before parents),
    /// newest first among unrelated ones. Includes the root revision last.
    pub fn visible_revisions(&self) -> Result<Vec<(ObjectId, Revision)>> {
        visible_revisions(&*self.store, &self.view)
    }

    /// Resolves a revision expression:
    /// `@` (this workspace's working revision), `root`, a bookmark name, a
    /// change-id prefix, or an object-id prefix (4+ hex chars). Any of these
    /// may be followed by one or more `-` to step to the first parent.
    pub fn resolve(&self, workspace: &str, spec: &str) -> Result<ObjectId> {
        let base = spec.trim_end_matches('-');
        let steps = spec.len() - base.len();
        let mut id = self.resolve_base(workspace, base)?;
        for _ in 0..steps {
            id = *self
                .revision(&id)?
                .parents
                .first()
                .ok_or_else(|| Error::Invalid(format!("{spec:?}: the root revision has no parent")))?;
        }
        Ok(id)
    }

    fn resolve_base(&self, workspace: &str, spec: &str) -> Result<ObjectId> {
        if spec == "@" {
            return self.working_revision(workspace);
        }
        if spec == "root" {
            return Ok(root_revision_id());
        }
        if let Some(id) = self.view.bookmarks.get(spec) {
            return Ok(*id);
        }
        if spec.len() == 64 {
            if let Ok(id) = spec.parse::<ObjectId>() {
                if self.store.has(&id)? {
                    self.store.get_revision(&id)?; // must be a revision, not a blob
                    return Ok(id);
                }
            }
        }
        if spec.is_empty() {
            return Err(Error::Invalid("empty revision".into()));
        }
        let is_change = spec.bytes().all(|b| (b'k'..=b'z').contains(&b));
        let is_hex = spec.len() >= 4 && spec.bytes().all(|b| b.is_ascii_hexdigit());
        if !is_change && !is_hex {
            return Err(Error::Invalid(format!("unknown revision {spec:?}")));
        }
        let mut matches: Vec<ObjectId> = Vec::new();
        for (id, rev) in self.visible_revisions()? {
            if (is_change && rev.change_id.to_text().starts_with(spec)) || (is_hex && id.to_hex().starts_with(spec)) {
                matches.push(id);
            }
        }
        match matches.len() {
            0 => Err(Error::Invalid(format!("unknown revision {spec:?}"))),
            1 => Ok(matches[0]),
            n => Err(Error::Invalid(format!("revision {spec:?} is ambiguous ({n} matches); use a longer prefix"))),
        }
    }

    /// Shortest unambiguous change-id prefix (min 4 chars) for display.
    pub fn short_change_id(&self, change: &ChangeId, all: &[(ObjectId, Revision)]) -> String {
        let text = change.to_text();
        let mut n = 4;
        while n < 32 && all.iter().any(|(_, r)| r.change_id != *change && r.change_id.to_text().starts_with(&text[..n])) {
            n += 1;
        }
        text[..n].to_string()
    }
}

/// Visible revisions: everything reachable from heads, workspaces, and bookmarks.
pub fn visible_revisions(store: &dyn Store, view: &View) -> Result<Vec<(ObjectId, Revision)>> {
    let mut revs: HashMap<ObjectId, Revision> = HashMap::new();
    let mut stack: Vec<ObjectId> =
        view.heads.iter().chain(view.workspaces.values()).chain(view.bookmarks.values()).copied().collect();
    while let Some(id) = stack.pop() {
        if revs.contains_key(&id) {
            continue;
        }
        let rev = store.get_revision(&id)?;
        stack.extend(rev.parents.iter().filter(|p| !revs.contains_key(p)).copied());
        revs.insert(id, rev);
    }
    // Kahn's algorithm from childless revisions; newest committer time first.
    let mut child_count: HashMap<ObjectId, usize> = revs.keys().map(|id| (*id, 0)).collect();
    for rev in revs.values() {
        for p in &rev.parents {
            *child_count.get_mut(p).expect("parents of visible revisions are visible") += 1;
        }
    }
    let key = |id: &ObjectId, revs: &HashMap<ObjectId, Revision>| (revs[id].committer.timestamp_ms, *id);
    let mut ready: BTreeSet<(i64, ObjectId)> =
        child_count.iter().filter(|(_, n)| **n == 0).map(|(id, _)| key(id, &revs)).collect();
    let mut out = Vec::with_capacity(revs.len());
    while let Some(entry) = ready.pop_last() {
        let id = entry.1;
        for p in &revs[&id].parents {
            let n = child_count.get_mut(p).expect("visible");
            *n -= 1;
            if *n == 0 {
                ready.insert(key(p, &revs));
            }
        }
        out.push(id);
    }
    Ok(out.into_iter().map(|id| { let r = revs.remove(&id).expect("present"); (id, r) }).collect())
}

/// A set of changes to the view, committed atomically by `Repo::commit`.
pub struct Transaction {
    store: Arc<dyn Store>,
    settings: Settings,
    view: View,
    description: String,
    undo_of: Option<ObjectId>,
    /// The operation this transaction's view was read from.
    base_op: Option<ObjectId>,
}

fn same_store(a: &Arc<dyn Store>, b: &Arc<dyn Store>) -> bool {
    // Compare data pointers only; vtable pointers may differ for one object.
    std::ptr::eq(Arc::as_ptr(a) as *const (), Arc::as_ptr(b) as *const ())
}

impl Transaction {
    pub fn store(&self) -> &Arc<dyn Store> {
        &self.store
    }

    pub fn view(&self) -> &View {
        &self.view
    }

    fn write_operation(&self, parent: Option<ObjectId>) -> Result<(ObjectId, Operation)> {
        let view_id = self.store.put(&Object::View(self.view.clone()))?;
        let op = Operation {
            parents: parent.into_iter().collect(),
            view: view_id,
            user: self.settings.user(),
            timestamp_ms: self.settings.now_ms(),
            description: self.description.clone(),
            undo_of: self.undo_of,
        };
        let id = self.store.put(&Object::Operation(op.clone()))?;
        Ok((id, op))
    }

    fn write_revision(&mut self, rev: Revision) -> Result<ObjectId> {
        let id = self.store.put(&Object::Revision(rev.clone()))?;
        for p in &rev.parents {
            self.view.heads.remove(p);
        }
        self.view.heads.insert(id);
        Ok(id)
    }

    /// Creates an empty change on top of `parents` (merging their trees when
    /// there are several). Does not move any workspace.
    pub fn new_change(&mut self, parents: &[ObjectId], description: &str) -> Result<ObjectId> {
        self.atomically(|tx| tx.new_change_inner(parents, description))
    }

    /// Runs one public step. If it fails, the view is restored exactly, so a
    /// refused step never leaves a half-applied transaction that could still
    /// be committed. (Objects already written stay in the store, unreachable.)
    fn atomically<T>(&mut self, step: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let saved = self.view.clone();
        let result = step(self);
        if result.is_err() {
            self.view = saved;
        }
        result
    }

    fn new_change_inner(&mut self, parents: &[ObjectId], description: &str) -> Result<ObjectId> {
        let tree = self.merged_tree(parents)?;
        let sig = self.settings.signature();
        self.write_revision(Revision {
            tree,
            parents: parents.to_vec(),
            change_id: ChangeId::random()?,
            predecessors: vec![],
            author: sig.clone(),
            committer: sig,
            description: description.to_string(),
        })
        .and_then(|id| {
            // A parent may have been hidden (e.g. after undo), leaving one of
            // its ancestors as a head.
            self.normalize_heads()?;
            Ok(id)
        })
    }

    fn merged_tree(&self, parents: &[ObjectId]) -> Result<ObjectId> {
        let store = &*self.store;
        let Some((first, rest)) = parents.split_first() else {
            return Err(Error::Invalid("a change needs at least one parent".into()));
        };
        let mut tree = store.get_revision(first)?.tree;
        let mut merged_head = *first;
        for p in rest {
            let theirs = store.get_revision(p)?.tree;
            let base = match merge_base(store, &merged_head, p)? {
                Some(b) => store.get_revision(&b)?.tree,
                None => empty_tree_id(),
            };
            match merge_trees(store, &base, &tree, &theirs)? {
                MergeOutcome::Clean(t) => tree = t,
                MergeOutcome::Conflict(paths) => return Err(conflict_error("merge", &paths)),
            }
            merged_head = *p;
        }
        Ok(tree)
    }

    /// Writes a new revision of the same change and points everything that
    /// referenced `old` at it. Visible descendants are rebased onto it.
    /// Returns `old` unchanged if `edit` changed nothing.
    pub fn rewrite(&mut self, old: ObjectId, edit: impl FnOnce(&mut Revision)) -> Result<ObjectId> {
        self.atomically(|tx| tx.rewrite_inner(old, edit))
    }

    fn rewrite_inner(&mut self, old: ObjectId, edit: impl FnOnce(&mut Revision)) -> Result<ObjectId> {
        if old == root_revision_id() {
            return Err(Error::Invalid("the root revision cannot be changed".into()));
        }
        let before = self.store.get_revision(&old)?;
        let mut rev = before.clone();
        edit(&mut rev);
        // A rewrite is a new revision of the *same* change.
        rev.change_id = before.change_id;
        if rev.tree == before.tree && rev.parents == before.parents && rev.description == before.description {
            return Ok(old);
        }
        rev.predecessors = vec![old];
        rev.committer = self.settings.signature();
        let new = self.write_revision(rev)?;
        self.replace(old, new);
        self.rebase_descendants(HashMap::from([(old, new)]))?;
        Ok(new)
    }

    /// Hides a revision. Its children are rebased onto its parents; workspaces
    /// on it get a fresh empty change on its parents.
    pub fn abandon(&mut self, id: ObjectId) -> Result<()> {
        self.atomically(|tx| tx.abandon_inner(id))
    }

    fn abandon_inner(&mut self, id: ObjectId) -> Result<()> {
        if id == root_revision_id() {
            return Err(Error::Invalid("the root revision cannot be abandoned".into()));
        }
        let rev = self.store.get_revision(&id)?;
        // Only the root may be parentless; a stored revision that claims
        // otherwise is malformed, and must not crash us.
        let Some(&first_parent) = rev.parents.first() else {
            return Err(Error::Invalid(format!("revision {} has no parents and cannot be abandoned", id.short(12))));
        };
        self.view.heads.remove(&id);
        for p in &rev.parents {
            self.view.heads.insert(*p);
        }
        for target in self.view.bookmarks.values_mut() {
            if *target == id {
                *target = first_parent;
            }
        }
        let on_it: Vec<String> =
            self.view.workspaces.iter().filter(|(_, wc)| **wc == id).map(|(n, _)| n.clone()).collect();
        for ws in on_it {
            let fresh = self.new_change_inner(&rev.parents, "")?;
            self.view.workspaces.insert(ws, fresh);
        }
        self.rebase_children_onto_parents(id, &rev)?;
        self.normalize_heads()
    }

    /// Points `workspace` at `rev`. The revision it leaves is abandoned if it
    /// is an empty, undescribed leaf nobody else uses (so `new`/`edit` do not
    /// litter the log with empty changes).
    pub fn set_working(&mut self, workspace: &str, rev: ObjectId) -> Result<()> {
        self.atomically(|tx| tx.set_working_inner(workspace, rev))
    }

    fn set_working_inner(&mut self, workspace: &str, rev: ObjectId) -> Result<()> {
        self.store.get_revision(&rev)?;
        // Visible first, so `is_discardable` sees `rev` as using its parents.
        self.view.heads.insert(rev);
        self.normalize_heads()?;
        let old = self.view.workspaces.insert(workspace.to_string(), rev);
        if let Some(old) = old {
            if old != rev && self.is_discardable(old)? {
                self.abandon_inner(old)?;
            }
        }
        Ok(())
    }

    pub fn remove_workspace(&mut self, workspace: &str) -> Result<()> {
        self.atomically(|tx| tx.remove_workspace_inner(workspace))
    }

    fn remove_workspace_inner(&mut self, workspace: &str) -> Result<()> {
        let old = self
            .view
            .workspaces
            .remove(workspace)
            .ok_or_else(|| Error::Invalid(format!("no workspace named {workspace:?}")))?;
        if self.is_discardable(old)? {
            self.abandon_inner(old)?;
        }
        Ok(())
    }

    pub fn set_bookmark(&mut self, name: &str, rev: ObjectId) -> Result<()> {
        validate_bookmark(name)?;
        self.store.get_revision(&rev)?;
        self.atomically(|tx| {
            tx.view.bookmarks.insert(name.to_string(), rev);
            // A bookmark can make a hidden revision visible again; keep heads
            // exact so "is a head" keeps meaning "has no visible children".
            tx.view.heads.insert(rev);
            tx.normalize_heads()
        })
    }

    pub fn delete_bookmark(&mut self, name: &str) -> Result<()> {
        self.view
            .bookmarks
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| Error::Invalid(format!("no bookmark named {name:?}")))
    }

    /// Relies on the invariant that `heads` is exactly the set of visible
    /// revisions without visible children (every step that changes
    /// visibility ends with `normalize_heads`).
    fn is_discardable(&self, id: ObjectId) -> Result<bool> {
        if id == root_revision_id() || !self.view.heads.contains(&id) {
            return Ok(false);
        }
        if self.view.workspaces.values().any(|w| *w == id) || self.view.bookmarks.values().any(|b| *b == id) {
            return Ok(false);
        }
        let rev = self.store.get_revision(&id)?;
        if !rev.description.is_empty() || rev.parents.len() != 1 {
            return Ok(false);
        }
        Ok(self.store.get_revision(&rev.parents[0])?.tree == rev.tree)
    }

    fn replace(&mut self, old: ObjectId, new: ObjectId) {
        self.view.heads.remove(&old);
        for target in self.view.workspaces.values_mut().chain(self.view.bookmarks.values_mut()) {
            if *target == old {
                *target = new;
            }
        }
    }

    /// Rebases every visible descendant of the rewritten revisions.
    fn rebase_descendants(&mut self, mut rewritten: HashMap<ObjectId, ObjectId>) -> Result<()> {
        // Children of rewritten revisions, processed parents-first.
        let visible = visible_revisions(&*self.store, &self.view)?;
        for (id, rev) in visible.into_iter().rev() {
            if rewritten.contains_key(&id) || !rev.parents.iter().any(|p| rewritten.contains_key(p)) {
                continue;
            }
            let new_parents: Vec<ObjectId> = rev.parents.iter().map(|p| *rewritten.get(p).unwrap_or(p)).collect();
            let old_base = self.merged_tree(&rev.parents)?;
            let new_base = self.merged_tree(&new_parents)?;
            let tree = match merge_trees(&*self.store, &old_base, &new_base, &rev.tree)? {
                MergeOutcome::Clean(t) => t,
                MergeOutcome::Conflict(paths) => {
                    return Err(conflict_error(&format!("rebasing change {}", rev.change_id.short(8)), &paths))
                }
            };
            let mut next = rev.clone();
            next.parents = new_parents;
            next.tree = tree;
            next.predecessors = vec![id];
            next.committer = self.settings.signature();
            let new = self.write_revision(next)?;
            self.replace(id, new);
            rewritten.insert(id, new);
        }
        self.normalize_heads()
    }

    fn rebase_children_onto_parents(&mut self, id: ObjectId, rev: &Revision) -> Result<()> {
        let visible = visible_revisions(&*self.store, &self.view)?;
        let mut rewritten: HashMap<ObjectId, ObjectId> = HashMap::new();
        for (child_id, child) in visible.into_iter().rev() {
            let touches_abandoned = child.parents.contains(&id);
            let touches_rewritten = child.parents.iter().any(|p| rewritten.contains_key(p));
            if !touches_abandoned && !touches_rewritten {
                continue;
            }
            let mut new_parents: Vec<ObjectId> = Vec::new();
            for p in &child.parents {
                if *p == id {
                    new_parents.extend(rev.parents.iter().copied());
                } else {
                    new_parents.push(*rewritten.get(p).unwrap_or(p));
                }
            }
            let mut seen = HashSet::new();
            new_parents.retain(|p| seen.insert(*p));
            let old_base = self.merged_tree(&child.parents)?;
            let new_base = self.merged_tree(&new_parents)?;
            let tree = match merge_trees(&*self.store, &old_base, &new_base, &child.tree)? {
                MergeOutcome::Clean(t) => t,
                MergeOutcome::Conflict(paths) => return Err(conflict_error("abandon", &paths)),
            };
            let mut next = child.clone();
            next.parents = new_parents;
            next.tree = tree;
            next.predecessors = vec![child_id];
            next.committer = self.settings.signature();
            let new = self.write_revision(next)?;
            self.replace(child_id, new);
            rewritten.insert(child_id, new);
        }
        Ok(())
    }

    /// Drops heads that are ancestors of other heads, and the root when
    /// anything else exists.
    fn normalize_heads(&mut self) -> Result<()> {
        let heads: Vec<ObjectId> = self.view.heads.iter().copied().collect();
        let mut covered: HashSet<ObjectId> = HashSet::new();
        for h in &heads {
            let rev = self.store.get_revision(h)?;
            for p in &rev.parents {
                if !covered.contains(p) {
                    covered.extend(ancestors(&*self.store, p)?);
                }
            }
        }
        self.view.heads.retain(|h| !covered.contains(h));
        if self.view.heads.len() > 1 {
            self.view.heads.remove(&root_revision_id());
        }
        Ok(())
    }
}

fn conflict_error(what: &str, paths: &[crate::path::RepoPath]) -> Error {
    let list: Vec<String> = paths.iter().take(10).map(|p| p.to_string()).collect();
    let more = if paths.len() > 10 { format!(" and {} more", paths.len() - 10) } else { String::new() };
    Error::Invalid(format!(
        "{what} would conflict in {}{more}. Conflicts as first-class objects are not built yet, so tig made no changes",
        list.join(", ")
    ))
}

fn validate_bookmark(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && name != "@"
        && name != "root"
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name.chars().all(|c| c.is_alphanumeric() || "-_./".contains(c));
    if ok {
        Ok(())
    } else {
        Err(Error::Invalid(format!("invalid bookmark name {name:?}")))
    }
}
