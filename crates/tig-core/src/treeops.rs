//! Tree edits, lookup, and diff over any [`Store`](crate::store::Store).
//!
//! Cost follows the paths being touched. A subtree whose id did not change is
//! reused as-is and never loaded. Directory entries stay sorted inside each
//! tree; results that list paths are sorted by [`RepoPath`], which compares the
//! whole path bytewise. That order is not the same as per-tree name order
//! (`a-b`, then `a.b`, then `a/...`).

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::{EntryKind, Object, Tree, TreeEntry};
use crate::path::RepoPath;
use crate::store::{empty_tree_id, Store, StoreExt};

/// A non-directory record, or a tree id when lookup hits a directory.
/// `Sealed` is a leaf: it stands in for a private subtree and is not walked.
pub type Leaf = (EntryKind, ObjectId);

/// One leaf-level change. `old`/`new` is `None` when the leaf was added or removed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffEntry {
    pub path: RepoPath,
    pub old: Option<Leaf>,
    pub new: Option<Leaf>,
}

/// Resolves `path` inside the tree `root`.
///
/// The empty path returns `(Tree, root)` without reading the store. A missing
/// component, a non-tree in the middle of the path (file, symlink, executable,
/// or sealed), yields `Ok(None)`.
pub fn lookup(store: &dyn Store, root: &ObjectId, path: &RepoPath) -> Result<Option<Leaf>> {
    if path.is_root() {
        return Ok(Some((EntryKind::Tree, *root)));
    }
    let mut current = *root;
    let parts: Vec<&str> = path.components().collect();
    for (i, name) in parts.iter().enumerate() {
        let tree = read_tree(store, &current)?;
        let Some(entry) = tree.get(name) else {
            return Ok(None);
        };
        let last = i + 1 == parts.len();
        if entry.kind == EntryKind::Tree {
            current = entry.id;
            if last {
                return Ok(Some((EntryKind::Tree, current)));
            }
            continue;
        }
        if last {
            return Ok(Some((entry.kind, entry.id)));
        }
        // File-like or sealed with further components: the path does not exist.
        return Ok(None);
    }
    Ok(Some((EntryKind::Tree, current)))
}

/// Every non-tree leaf at `dir` or inside it, sorted by [`RepoPath`].
///
/// `Sealed` is included and not opened. A missing directory is an empty list.
/// A path that itself names a file, symlink, or seal returns that one leaf.
pub fn walk(store: &dyn Store, root: &ObjectId, dir: &RepoPath) -> Result<Vec<(RepoPath, Leaf)>> {
    let mut out = Vec::new();
    match lookup(store, root, dir)? {
        None => return Ok(out),
        Some((EntryKind::Tree, id)) => collect_leaves(store, id, dir, &mut out)?,
        Some(leaf) => out.push((dir.clone(), leaf)),
    }
    // Tree-name order would emit `a/c` before `a-b` and `a.b`. RepoPath does not.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Applies `edits` to `base` and returns the new root id.
///
/// `Some(leaf)` writes that entry, creating parent directories as needed.
/// `None` deletes the path (a whole subtree, when it is a directory); deleting
/// a path that is already absent is a no-op. A file, symlink, executable, or
/// seal on the way to a deeper edit is replaced by directories. A directory
/// that loses its last entry is removed, except the root, which may be empty.
///
/// Putting an entry at `a` in the same batch as an edit at `a/...` is
/// [`Error::Invalid`]: the batch does not say which one wins. Replacing the
/// root itself is allowed only with `Some((Tree, id))`; `None` clears the tree.
/// The empty tree object is written whenever this returns its id.
///
/// Only directories on the way to an edit are loaded. Every other subtree is
/// copied by id.
pub fn apply_edits(
    store: &dyn Store,
    base: &ObjectId,
    edits: &BTreeMap<RepoPath, Option<Leaf>>,
) -> Result<ObjectId> {
    reject_ambiguous(edits)?;
    if let Some(edit) = edits.get(&RepoPath::root()) {
        return finish_root(store, root_replacement(edit)?);
    }
    if edits.is_empty() {
        return finish_root(store, *base);
    }
    match rewrite(store, base, edits, true)? {
        Some(id) => finish_root(store, id),
        None => Err(Error::Invalid("root rewrite produced no tree".into())),
    }
}

/// Leaf-level differences between two roots, sorted by [`RepoPath`].
///
/// Equal subtree ids are skipped without loading. A file (or seal) that becomes
/// a directory is reported as the removal of that leaf plus the additions of
/// the directory's leaves, and the other way around. A kind change that keeps
/// the same id (`File` to `Executable`) is one modification.
pub fn diff_trees(store: &dyn Store, old: &ObjectId, new: &ObjectId) -> Result<Vec<DiffEntry>> {
    diff_trees_under(store, old, new, &RepoPath::root())
}

/// [`diff_trees`] limited to leaves at `dir` or inside it.
///
/// Identical roots return nothing and touch the store zero times. Ancestors
/// outside `dir` are not reported: a file at `a` replaced by `a/b` shows up
/// under `a`, and under `a/b` only the added leaf is reported.
pub fn diff_trees_under(
    store: &dyn Store,
    old: &ObjectId,
    new: &ObjectId,
    dir: &RepoPath,
) -> Result<Vec<DiffEntry>> {
    if old == new {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let old_leaf = resolved_leaf(resolve(store, *old, dir)?);
    let new_leaf = resolved_leaf(resolve(store, *new, dir)?);
    diff_leaf(store, dir.clone(), old_leaf, new_leaf, &mut out)?;
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

// --- lookup / walk ---------------------------------------------------------

fn collect_leaves(
    store: &dyn Store,
    id: ObjectId,
    prefix: &RepoPath,
    out: &mut Vec<(RepoPath, Leaf)>,
) -> Result<()> {
    let tree = read_tree(store, &id)?;
    for entry in tree.entries() {
        let kind = entry.kind;
        let child = entry.id;
        let path = prefix.join(&entry.name)?;
        if kind == EntryKind::Tree {
            collect_leaves(store, child, &path, out)?;
        } else {
            out.push((path, (kind, child)));
        }
    }
    Ok(())
}

// --- edits -----------------------------------------------------------------

fn root_replacement(edit: &Option<Leaf>) -> Result<ObjectId> {
    match edit {
        Some((EntryKind::Tree, id)) => Ok(*id),
        Some((kind, _)) => Err(Error::Invalid(format!(
            "cannot place {kind:?} at the repo root"
        ))),
        None => Ok(empty_tree_id()),
    }
}

/// The empty root is a real object. Callers may pass its id before anyone has
/// written it; returning it always stores it.
fn finish_root(store: &dyn Store, id: ObjectId) -> Result<ObjectId> {
    if id == empty_tree_id() {
        store.put(&Object::Tree(Tree::empty()))?;
    }
    Ok(id)
}

fn reject_ambiguous(edits: &BTreeMap<RepoPath, Option<Leaf>>) -> Result<()> {
    for path in edits.keys() {
        let mut parent = path.parent();
        while let Some(ancestor) = parent {
            if edits.contains_key(&ancestor) {
                return Err(Error::Invalid(format!(
                    "ambiguous edits at {} and {}",
                    display_path(&ancestor),
                    display_path(path)
                )));
            }
            parent = ancestor.parent();
        }
    }
    Ok(())
}

fn display_path(path: &RepoPath) -> String {
    if path.is_root() {
        "/".to_string()
    } else {
        path.as_str().to_string()
    }
}

/// `Here` replaces this entry. `Below` holds edits relative to it.
/// One batch never has both: that is the ambiguous case.
enum Group {
    Here(Option<Leaf>),
    Below(BTreeMap<RepoPath, Option<Leaf>>),
}

fn partition(edits: &BTreeMap<RepoPath, Option<Leaf>>) -> Result<BTreeMap<String, Group>> {
    let mut groups: BTreeMap<String, Group> = BTreeMap::new();
    for (path, leaf) in edits {
        let (name, rest) = split_first(path)?;
        match groups.entry(name.to_string()) {
            std::collections::btree_map::Entry::Vacant(slot) => {
                if rest.is_root() {
                    slot.insert(Group::Here(*leaf));
                } else {
                    let mut below = BTreeMap::new();
                    below.insert(rest, *leaf);
                    slot.insert(Group::Below(below));
                }
            }
            std::collections::btree_map::Entry::Occupied(mut slot) => match slot.get_mut() {
                Group::Here(_) | Group::Below(_) if rest.is_root() => {
                    return Err(Error::Invalid(format!("ambiguous edits at {name}")));
                }
                Group::Here(_) => {
                    return Err(Error::Invalid(format!("ambiguous edits at {name}")));
                }
                Group::Below(below) => {
                    below.insert(rest, *leaf);
                }
            },
        }
    }
    Ok(groups)
}

fn split_first(path: &RepoPath) -> Result<(&str, RepoPath)> {
    let text = path.as_str();
    if text.is_empty() {
        return Err(Error::Invalid("empty path has no component".into()));
    }
    match text.split_once('/') {
        Some((name, rest)) => Ok((name, RepoPath::new(rest)?)),
        None => Ok((text, RepoPath::root())),
    }
}

/// Rewrites `base` with `edits` (paths relative to this directory).
/// `None` means the directory ended up empty and the parent should drop it.
fn rewrite(
    store: &dyn Store,
    base: &ObjectId,
    edits: &BTreeMap<RepoPath, Option<Leaf>>,
    is_root: bool,
) -> Result<Option<ObjectId>> {
    if edits.is_empty() {
        return Ok(Some(*base));
    }
    let groups = partition(edits)?;
    let base_tree = read_tree(store, base)?;
    let mut entries = base_tree.entries().to_vec();
    for (name, group) in groups {
        apply_group(store, &mut entries, &name, group)?;
    }
    if entries.is_empty() {
        // The root may be empty. Any other empty directory is omitted.
        return Ok(if is_root { Some(empty_tree_id()) } else { None });
    }
    if entries.as_slice() == base_tree.entries() {
        return Ok(Some(*base));
    }
    let id = store.put(&Object::Tree(Tree::new(entries)?))?;
    Ok(Some(id))
}

#[derive(Clone, Copy)]
enum Slot {
    Occupied {
        index: usize,
        kind: EntryKind,
        id: ObjectId,
    },
    Vacant {
        index: usize,
    },
}

fn find_slot(entries: &[TreeEntry], name: &str) -> Slot {
    match entries.binary_search_by(|entry| entry.name.as_bytes().cmp(name.as_bytes())) {
        Ok(index) => Slot::Occupied {
            index,
            kind: entries[index].kind,
            id: entries[index].id,
        },
        Err(index) => Slot::Vacant { index },
    }
}

fn write_slot(entries: &mut Vec<TreeEntry>, name: &str, slot: Slot, kind: EntryKind, id: ObjectId) {
    let entry = TreeEntry {
        name: name.to_string(),
        kind,
        id,
    };
    match slot {
        Slot::Occupied { index, .. } => entries[index] = entry,
        Slot::Vacant { index } => entries.insert(index, entry),
    }
}

fn apply_group(
    store: &dyn Store,
    entries: &mut Vec<TreeEntry>,
    name: &str,
    group: Group,
) -> Result<()> {
    let slot = find_slot(entries, name);
    match group {
        Group::Here(None) => {
            if let Slot::Occupied { index, .. } = slot {
                entries.remove(index);
            }
            Ok(())
        }
        Group::Here(Some((EntryKind::Tree, id))) if id == empty_tree_id() => {
            // An explicit empty directory would just be removed again.
            if let Slot::Occupied { index, .. } = slot {
                entries.remove(index);
            }
            Ok(())
        }
        Group::Here(Some((kind, id))) => {
            write_slot(entries, name, slot, kind, id);
            Ok(())
        }
        Group::Below(below) => {
            let (child_base, replace_tree) = match slot {
                Slot::Occupied {
                    index,
                    kind: EntryKind::Tree,
                    id,
                    ..
                } => (id, Some(index)),
                // A file, symlink, executable, or seal is not a directory.
                // Deletes underneath are a no-op; a put builds a fresh directory.
                _ => (empty_tree_id(), None),
            };
            match rewrite(store, &child_base, &below, false)? {
                Some(id) => write_slot(entries, name, slot, EntryKind::Tree, id),
                None => {
                    if let Some(index) = replace_tree {
                        entries.remove(index);
                    }
                }
            }
            Ok(())
        }
    }
}

// --- diff ------------------------------------------------------------------

enum Resolved {
    Absent,
    Tree(ObjectId),
    Leaf(Leaf),
}

fn resolved_leaf(node: Resolved) -> Option<Leaf> {
    match node {
        Resolved::Absent => None,
        Resolved::Tree(id) => Some((EntryKind::Tree, id)),
        Resolved::Leaf(leaf) => Some(leaf),
    }
}

fn resolve(store: &dyn Store, root: ObjectId, dir: &RepoPath) -> Result<Resolved> {
    let parts: Vec<&str> = dir.components().collect();
    if parts.is_empty() {
        return Ok(Resolved::Tree(root));
    }
    let mut current = root;
    for (i, name) in parts.iter().enumerate() {
        let tree = read_tree(store, &current)?;
        let Some(entry) = tree.get(name) else {
            return Ok(Resolved::Absent);
        };
        let last = i + 1 == parts.len();
        if entry.kind == EntryKind::Tree {
            current = entry.id;
            if last {
                return Ok(Resolved::Tree(current));
            }
            continue;
        }
        if last {
            return Ok(Resolved::Leaf((entry.kind, entry.id)));
        }
        return Ok(Resolved::Absent);
    }
    Ok(Resolved::Tree(current))
}

enum Node {
    Tree(ObjectId),
    /// File, executable, symlink, or sealed. Not walked.
    Leaf(Leaf),
}

fn as_node(leaf: Leaf) -> Node {
    if leaf.0 == EntryKind::Tree {
        Node::Tree(leaf.1)
    } else {
        Node::Leaf(leaf)
    }
}

#[derive(Clone, Copy)]
enum Side {
    Old,
    New,
}

fn diff_ids(
    store: &dyn Store,
    old: ObjectId,
    new: ObjectId,
    prefix: &RepoPath,
    out: &mut Vec<DiffEntry>,
) -> Result<()> {
    if old == new {
        return Ok(());
    }
    let old_tree = read_tree(store, &old)?;
    let new_tree = read_tree(store, &new)?;
    diff_loaded(store, &old_tree, &new_tree, prefix, out)
}

fn diff_loaded(
    store: &dyn Store,
    old_tree: &Tree,
    new_tree: &Tree,
    prefix: &RepoPath,
    out: &mut Vec<DiffEntry>,
) -> Result<()> {
    let old_entries = old_tree.entries();
    let new_entries = new_tree.entries();
    let mut i = 0;
    let mut j = 0;
    while i < old_entries.len() || j < new_entries.len() {
        let ord = match (old_entries.get(i), new_entries.get(j)) {
            (Some(a), Some(b)) => a.name.as_bytes().cmp(b.name.as_bytes()),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => break,
        };
        if ord == Ordering::Equal {
            let kind_old = old_entries[i].kind;
            let id_old = old_entries[i].id;
            let kind_new = new_entries[j].kind;
            let id_new = new_entries[j].id;
            let name = old_entries[i].name.clone();
            i += 1;
            j += 1;
            if kind_old == kind_new && id_old == id_new {
                continue;
            }
            let path = prefix.join(&name)?;
            diff_leaf(
                store,
                path,
                Some((kind_old, id_old)),
                Some((kind_new, id_new)),
                out,
            )?;
        } else if ord == Ordering::Less {
            let kind = old_entries[i].kind;
            let id = old_entries[i].id;
            let path = prefix.join(&old_entries[i].name)?;
            i += 1;
            diff_leaf(store, path, Some((kind, id)), None, out)?;
        } else {
            let kind = new_entries[j].kind;
            let id = new_entries[j].id;
            let path = prefix.join(&new_entries[j].name)?;
            j += 1;
            diff_leaf(store, path, None, Some((kind, id)), out)?;
        }
    }
    Ok(())
}

fn diff_leaf(
    store: &dyn Store,
    path: RepoPath,
    old: Option<Leaf>,
    new: Option<Leaf>,
    out: &mut Vec<DiffEntry>,
) -> Result<()> {
    match (old.map(as_node), new.map(as_node)) {
        (Some(Node::Tree(a)), Some(Node::Tree(b))) if a == b => Ok(()),
        (Some(Node::Tree(a)), Some(Node::Tree(b))) => diff_ids(store, a, b, &path, out),
        (Some(Node::Leaf(a)), Some(Node::Leaf(b))) if a != b => {
            out.push(DiffEntry {
                path,
                old: Some(a),
                new: Some(b),
            });
            Ok(())
        }
        (Some(Node::Leaf(_)), Some(Node::Leaf(_))) => Ok(()),
        (Some(Node::Tree(id)), Some(Node::Leaf(leaf))) => {
            emit_leaves(store, id, &path, Side::Old, out)?;
            out.push(DiffEntry {
                path,
                old: None,
                new: Some(leaf),
            });
            Ok(())
        }
        (Some(Node::Leaf(leaf)), Some(Node::Tree(id))) => {
            out.push(DiffEntry {
                path: path.clone(),
                old: Some(leaf),
                new: None,
            });
            emit_leaves(store, id, &path, Side::New, out)
        }
        (Some(Node::Tree(id)), None) => emit_leaves(store, id, &path, Side::Old, out),
        (Some(Node::Leaf(leaf)), None) => {
            out.push(DiffEntry {
                path,
                old: Some(leaf),
                new: None,
            });
            Ok(())
        }
        (None, Some(Node::Tree(id))) => emit_leaves(store, id, &path, Side::New, out),
        (None, Some(Node::Leaf(leaf))) => {
            out.push(DiffEntry {
                path,
                old: None,
                new: Some(leaf),
            });
            Ok(())
        }
        (None, None) => Ok(()),
    }
}

fn emit_leaves(
    store: &dyn Store,
    id: ObjectId,
    prefix: &RepoPath,
    side: Side,
    out: &mut Vec<DiffEntry>,
) -> Result<()> {
    let tree = read_tree(store, &id)?;
    for entry in tree.entries() {
        let kind = entry.kind;
        let child = entry.id;
        let path = prefix.join(&entry.name)?;
        if kind == EntryKind::Tree {
            emit_leaves(store, child, &path, side, out)?;
        } else {
            let leaf = Some((kind, child));
            out.push(match side {
                Side::Old => DiffEntry {
                    path,
                    old: leaf,
                    new: None,
                },
                Side::New => DiffEntry {
                    path,
                    old: None,
                    new: leaf,
                },
            });
        }
    }
    Ok(())
}

fn read_tree(store: &dyn Store, id: &ObjectId) -> Result<Tree> {
    match store.get_tree(id) {
        Ok(tree) => Ok(tree),
        // A brand-new repo points at this id before the object has been stored.
        // The id is the hash of an empty tree, so nothing else can live there.
        Err(Error::NotFound(missing)) if missing == empty_tree_id() => Ok(Tree::empty()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use proptest::prelude::*;

    use super::*;
    use crate::error::Error;
    use crate::id::ObjectId;
    use crate::object::{EntryKind, ObjectKind};
    use crate::path::RepoPath;
    use crate::store::{empty_tree_id, MemoryStore, Store, StoreExt};

    fn rp(path: &str) -> RepoPath {
        RepoPath::new(path).expect("test path")
    }

    fn batch(pairs: &[(&str, Option<Leaf>)]) -> BTreeMap<RepoPath, Option<Leaf>> {
        pairs.iter().map(|(path, leaf)| (rp(path), *leaf)).collect()
    }

    fn file(store: &MemoryStore, bytes: &[u8]) -> Leaf {
        (EntryKind::File, store.put_blob(bytes).unwrap())
    }

    fn leaf(store: &MemoryStore, bytes: &[u8], kind: EntryKind) -> Leaf {
        (kind, store.put_blob(bytes).unwrap())
    }

    fn paths_of(entries: &[(RepoPath, Leaf)]) -> Vec<&str> {
        entries.iter().map(|(path, _)| path.as_str()).collect()
    }

    /// A file<->directory diff names both a path and something inside it.
    /// One `apply_edits` batch rejects that, so deletions land first.
    fn apply_reported_diff(
        store: &dyn Store,
        base: &ObjectId,
        diff: &[DiffEntry],
    ) -> Result<ObjectId> {
        let mut deletes = BTreeMap::new();
        let mut writes = BTreeMap::new();
        for entry in diff {
            if entry.new.is_none() {
                deletes.insert(entry.path.clone(), None);
            } else {
                writes.insert(entry.path.clone(), entry.new);
            }
        }
        let mid = apply_edits(store, base, &deletes)?;
        apply_edits(store, &mid, &writes)
    }

    #[test]
    fn lookup_walk_and_ordering() {
        let store = MemoryStore::new();
        let ab = file(&store, b"ab");
        let abd = file(&store, b"abd");
        let ac = file(&store, b"ac");
        let link = leaf(&store, b"target", EntryKind::Symlink);
        let run = leaf(&store, b"#!/bin/sh", EntryKind::Executable);
        let secret = leaf(&store, b"hidden", EntryKind::Sealed);

        let root = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[
                ("a-b", Some(ab)),
                ("a.b/d", Some(abd)),
                ("a/c", Some(ac)),
                ("link", Some(link)),
                ("run.sh", Some(run)),
                ("secret", Some(secret)),
            ]),
        )
        .unwrap();

        assert_eq!(
            lookup(&store, &root, &RepoPath::root()).unwrap(),
            Some((EntryKind::Tree, root))
        );
        assert_eq!(lookup(&store, &root, &rp("a/c")).unwrap(), Some(ac));
        assert_eq!(lookup(&store, &root, &rp("link")).unwrap(), Some(link));
        assert_eq!(lookup(&store, &root, &rp("run.sh")).unwrap(), Some(run));
        assert_eq!(lookup(&store, &root, &rp("secret")).unwrap(), Some(secret));
        assert_eq!(
            lookup(&store, &root, &rp("a")).unwrap().unwrap().0,
            EntryKind::Tree
        );
        assert_eq!(lookup(&store, &root, &rp("missing")).unwrap(), None);
        assert_eq!(lookup(&store, &root, &rp("a/c/nope")).unwrap(), None);
        assert_eq!(lookup(&store, &root, &rp("secret/inside")).unwrap(), None);
        assert_eq!(lookup(&store, &root, &rp("no/such")).unwrap(), None);

        let bogus = ObjectId([9; 32]);
        assert_eq!(
            lookup(&store, &bogus, &RepoPath::root()).unwrap(),
            Some((EntryKind::Tree, bogus))
        );
        assert!(matches!(
            lookup(&store, &bogus, &rp("a")),
            Err(Error::NotFound(_))
        ));

        let listed = walk(&store, &root, &RepoPath::root()).unwrap();
        assert_eq!(
            paths_of(&listed),
            vec!["a-b", "a.b/d", "a/c", "link", "run.sh", "secret"]
        );
        assert_eq!(listed[0].1, ab);
        assert_eq!(listed[1].1, abd);
        assert_eq!(listed[2].1, ac);
        assert_eq!(
            paths_of(&walk(&store, &root, &rp("a")).unwrap()),
            vec!["a/c"]
        );
        assert_eq!(
            paths_of(&walk(&store, &root, &rp("a.b")).unwrap()),
            vec!["a.b/d"]
        );
        assert_eq!(
            walk(&store, &root, &rp("a-b")).unwrap(),
            vec![(rp("a-b"), ab)]
        );
        assert!(walk(&store, &root, &rp("nope")).unwrap().is_empty());

        // Graft an existing tree without rewriting it.
        let sub = lookup(&store, &root, &rp("a")).unwrap().unwrap().1;
        let grafted = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[("vendor", Some((EntryKind::Tree, sub)))]),
        )
        .unwrap();
        assert_eq!(
            lookup(&store, &grafted, &rp("vendor")).unwrap(),
            Some((EntryKind::Tree, sub))
        );
        assert_eq!(
            paths_of(&walk(&store, &grafted, &RepoPath::root()).unwrap()),
            vec!["vendor/c"]
        );
    }

    #[test]
    fn delete_removes_empty_directories() {
        let store = MemoryStore::new();
        let keep = file(&store, b"keep");
        let gone = file(&store, b"gone");
        let nested = file(&store, b"nested");
        let root = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[
                ("keep.txt", Some(keep)),
                ("a/b/c.txt", Some(gone)),
                ("a/d.txt", Some(nested)),
            ]),
        )
        .unwrap();

        let same = apply_edits(&store, &root, &batch(&[("no/such", None)])).unwrap();
        assert_eq!(same, root);

        let after = apply_edits(&store, &root, &batch(&[("a/b/c.txt", None)])).unwrap();
        assert_eq!(
            paths_of(&walk(&store, &after, &RepoPath::root()).unwrap()),
            vec!["a/d.txt", "keep.txt"]
        );
        assert_eq!(lookup(&store, &after, &rp("a/b")).unwrap(), None);
        assert_eq!(
            lookup(&store, &after, &rp("a")).unwrap().unwrap().0,
            EntryKind::Tree
        );

        let cleared = apply_edits(
            &store,
            &after,
            &batch(&[("a/d.txt", None), ("keep.txt", None)]),
        )
        .unwrap();
        assert_eq!(cleared, empty_tree_id());
        assert!(walk(&store, &cleared, &RepoPath::root())
            .unwrap()
            .is_empty());
        assert_eq!(store.get_tree(&cleared).unwrap().entries(), &[]);

        let empty_put = apply_edits(&store, &empty_tree_id(), &BTreeMap::new()).unwrap();
        assert_eq!(empty_put, empty_tree_id());
        assert!(store.get_tree(&empty_put).is_ok());

        // Grafting the empty tree removes the directory instead of storing it.
        let with_dir =
            apply_edits(&store, &empty_tree_id(), &batch(&[("a/f", Some(keep))])).unwrap();
        let collapsed = apply_edits(
            &store,
            &with_dir,
            &batch(&[("a", Some((EntryKind::Tree, empty_tree_id())))]),
        )
        .unwrap();
        assert_eq!(collapsed, empty_tree_id());
    }

    #[test]
    fn file_and_dir_replace_each_other() {
        let store = MemoryStore::new();
        let a = file(&store, b"a");
        let b = file(&store, b"b");
        let q = file(&store, b"q");
        let root = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[("p/a", Some(a)), ("p/b", Some(b)), ("q", Some(q))]),
        )
        .unwrap();

        let file_at_p = file(&store, b"was a dir");
        let as_file = apply_edits(&store, &root, &batch(&[("p", Some(file_at_p))])).unwrap();
        assert_eq!(lookup(&store, &as_file, &rp("p")).unwrap(), Some(file_at_p));
        assert_eq!(lookup(&store, &as_file, &rp("p/a")).unwrap(), None);
        assert_eq!(
            paths_of(&walk(&store, &as_file, &RepoPath::root()).unwrap()),
            vec!["p", "q"]
        );
        assert_eq!(lookup(&store, &as_file, &rp("q")).unwrap(), Some(q));

        let a2 = file(&store, b"a2");
        let as_dir = apply_edits(
            &store,
            &as_file,
            &batch(&[("p/a", Some(a2)), ("p/n", Some(b))]),
        )
        .unwrap();
        assert_eq!(
            lookup(&store, &as_dir, &rp("p")).unwrap().unwrap().0,
            EntryKind::Tree
        );
        assert_eq!(lookup(&store, &as_dir, &rp("p/a")).unwrap(), Some(a2));
        assert_eq!(
            paths_of(&walk(&store, &as_dir, &RepoPath::root()).unwrap()),
            vec!["p/a", "p/n", "q"]
        );
    }

    #[test]
    fn ambiguous_batch_is_rejected() {
        let store = MemoryStore::new();
        let blob = file(&store, b"x");
        let err = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[("a", Some(blob)), ("a/x", Some(blob))]),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Invalid(ref msg) if msg.contains("ambiguous")),
            "{err}"
        );

        let err = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[("a", None), ("a/x", None)]),
        )
        .unwrap_err();
        assert!(
            matches!(err, Error::Invalid(ref msg) if msg.contains("ambiguous")),
            "{err}"
        );

        let mut edits = BTreeMap::new();
        edits.insert(RepoPath::root(), Some((EntryKind::Tree, empty_tree_id())));
        edits.insert(rp("a"), Some(blob));
        let err = apply_edits(&store, &empty_tree_id(), &edits).unwrap_err();
        assert!(
            matches!(err, Error::Invalid(ref msg) if msg.contains("ambiguous")),
            "{err}"
        );
    }

    #[test]
    fn root_edit_rules() {
        let store = MemoryStore::new();
        let blob = file(&store, b"x");
        let child = apply_edits(&store, &empty_tree_id(), &batch(&[("f", Some(blob))])).unwrap();

        let mut edits = BTreeMap::new();
        edits.insert(RepoPath::root(), Some((EntryKind::File, blob.1)));
        let err = apply_edits(&store, &empty_tree_id(), &edits).unwrap_err();
        assert!(matches!(err, Error::Invalid(_)), "{err}");

        edits.insert(RepoPath::root(), Some((EntryKind::Tree, child)));
        assert_eq!(
            apply_edits(&store, &empty_tree_id(), &edits).unwrap(),
            child
        );

        edits.insert(RepoPath::root(), None);
        let cleared = apply_edits(&store, &child, &edits).unwrap();
        assert_eq!(cleared, empty_tree_id());
        assert!(store.get_tree(&cleared).is_ok());
    }

    #[test]
    fn unchanged_sibling_keeps_its_id() {
        let store = MemoryStore::new();
        let left = file(&store, b"left");
        let right = file(&store, b"right");
        let root = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[("a/f", Some(left)), ("b/f", Some(right))]),
        )
        .unwrap();
        let a_before = lookup(&store, &root, &rp("a")).unwrap().unwrap();
        let b_before = lookup(&store, &root, &rp("b")).unwrap().unwrap();

        let right2 = file(&store, b"right-2");
        let next = apply_edits(&store, &root, &batch(&[("b/f", Some(right2))])).unwrap();
        assert_ne!(next, root);
        assert_eq!(lookup(&store, &next, &rp("a")).unwrap().unwrap(), a_before);
        assert_ne!(lookup(&store, &next, &rp("b")).unwrap().unwrap(), b_before);
        assert_eq!(lookup(&store, &next, &rp("b/f")).unwrap(), Some(right2));
    }

    #[test]
    fn diff_add_remove_modify_kind_and_type() {
        let store = MemoryStore::new();
        let a = file(&store, b"a");
        let b = file(&store, b"b");
        let same = file(&store, b"same");
        let was = file(&store, b"was");
        let old = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[
                ("dir/a.txt", Some(a)),
                ("f.txt", Some(a)),
                ("g.txt", Some(b)),
                ("same.txt", Some(same)),
                ("was_file", Some(was)),
            ]),
        )
        .unwrap();

        let b2 = file(&store, b"b2");
        let added = file(&store, b"new");
        let exec = (EntryKind::Executable, a.1);
        let nested = file(&store, b"x");
        let new = apply_edits(
            &store,
            &old,
            &batch(&[
                ("f.txt", None),
                ("g.txt", Some(b2)),
                ("h.txt", Some(added)),
                ("dir/a.txt", Some(exec)),
                ("was_file/x.txt", Some(nested)),
            ]),
        )
        .unwrap();

        let diff = diff_trees(&store, &old, &new).unwrap();
        let expected = vec![
            DiffEntry {
                path: rp("dir/a.txt"),
                old: Some(a),
                new: Some(exec),
            },
            DiffEntry {
                path: rp("f.txt"),
                old: Some(a),
                new: None,
            },
            DiffEntry {
                path: rp("g.txt"),
                old: Some(b),
                new: Some(b2),
            },
            DiffEntry {
                path: rp("h.txt"),
                old: None,
                new: Some(added),
            },
            DiffEntry {
                path: rp("was_file"),
                old: Some(was),
                new: None,
            },
            DiffEntry {
                path: rp("was_file/x.txt"),
                old: None,
                new: Some(nested),
            },
        ];
        assert_eq!(diff, expected);
        assert!(diff.iter().all(|entry| entry.path.as_str() != "same.txt"));
        assert_eq!(apply_reported_diff(&store, &old, &diff).unwrap(), new);

        // Directory back to a file: removal of the leaves, addition of the file.
        let back = file(&store, b"dir-as-file");
        let flipped = apply_edits(&store, &new, &batch(&[("dir", Some(back))])).unwrap();
        let flip_diff = diff_trees(&store, &new, &flipped).unwrap();
        assert_eq!(
            flip_diff,
            vec![
                DiffEntry {
                    path: rp("dir"),
                    old: None,
                    new: Some(back)
                },
                DiffEntry {
                    path: rp("dir/a.txt"),
                    old: Some(exec),
                    new: None
                },
            ]
        );
        assert_eq!(
            apply_reported_diff(&store, &new, &flip_diff).unwrap(),
            flipped
        );

        // `a.b` sorts before `a/c` even though the tree named `a` comes first.
        let dot = file(&store, b"dot");
        let inside = file(&store, b"inside");
        let left = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[("a.b", Some(dot)), ("a/c", Some(inside))]),
        )
        .unwrap();
        let dot2 = file(&store, b"dot2");
        let inside2 = file(&store, b"inside2");
        let right = apply_edits(
            &store,
            &left,
            &batch(&[("a.b", Some(dot2)), ("a/c", Some(inside2))]),
        )
        .unwrap();
        let order = diff_trees(&store, &left, &right).unwrap();
        assert_eq!(paths_of_diff(&order), vec!["a.b", "a/c"]);
    }

    fn paths_of_diff(entries: &[DiffEntry]) -> Vec<&str> {
        entries.iter().map(|entry| entry.path.as_str()).collect()
    }

    #[test]
    fn diff_identical_roots_is_empty() {
        let store = MemoryStore::new();
        let blob = file(&store, b"v");
        let root = apply_edits(&store, &empty_tree_id(), &batch(&[("a/b", Some(blob))])).unwrap();
        assert!(diff_trees(&store, &root, &root).unwrap().is_empty());
        let again = apply_edits(&store, &empty_tree_id(), &batch(&[("a/b", Some(blob))])).unwrap();
        assert_eq!(again, root);
        assert!(diff_trees(&store, &root, &again).unwrap().is_empty());
        assert!(diff_trees(&store, &empty_tree_id(), &empty_tree_id())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn diff_under_limits_to_a_directory() {
        let store = MemoryStore::new();
        let x = file(&store, b"x");
        let y = file(&store, b"y");
        let z = file(&store, b"z");
        let old = apply_edits(
            &store,
            &empty_tree_id(),
            &batch(&[("a/x", Some(x)), ("a/y", Some(y)), ("b/z", Some(z))]),
        )
        .unwrap();
        let x2 = file(&store, b"x2");
        let z2 = file(&store, b"z2");
        let new = apply_edits(
            &store,
            &old,
            &batch(&[("a/x", Some(x2)), ("b/z", Some(z2))]),
        )
        .unwrap();

        let only_a = diff_trees_under(&store, &old, &new, &rp("a")).unwrap();
        assert_eq!(
            only_a,
            vec![DiffEntry {
                path: rp("a/x"),
                old: Some(x),
                new: Some(x2)
            }]
        );
        let only_b = diff_trees_under(&store, &old, &new, &rp("b")).unwrap();
        assert_eq!(
            only_b,
            vec![DiffEntry {
                path: rp("b/z"),
                old: Some(z),
                new: Some(z2)
            }]
        );
        assert!(diff_trees_under(&store, &old, &new, &rp("a/y"))
            .unwrap()
            .is_empty());
        assert!(diff_trees_under(&store, &old, &new, &rp("missing"))
            .unwrap()
            .is_empty());

        let file_p = file(&store, b"p");
        let with_file =
            apply_edits(&store, &empty_tree_id(), &batch(&[("p", Some(file_p))])).unwrap();
        let nested = file(&store, b"q");
        let with_dir = apply_edits(&store, &with_file, &batch(&[("p/q", Some(nested))])).unwrap();
        let at_p = diff_trees_under(&store, &with_file, &with_dir, &rp("p")).unwrap();
        assert_eq!(
            at_p,
            vec![
                DiffEntry {
                    path: rp("p"),
                    old: Some(file_p),
                    new: None
                },
                DiffEntry {
                    path: rp("p/q"),
                    old: None,
                    new: Some(nested)
                },
            ]
        );
        let at_pq = diff_trees_under(&store, &with_file, &with_dir, &rp("p/q")).unwrap();
        assert_eq!(
            at_pq,
            vec![DiffEntry {
                path: rp("p/q"),
                old: None,
                new: Some(nested)
            }]
        );
    }

    struct CountStore<'a> {
        inner: &'a MemoryStore,
        gets: AtomicUsize,
    }

    impl<'a> CountStore<'a> {
        fn new(inner: &'a MemoryStore) -> Self {
            Self {
                inner,
                gets: AtomicUsize::new(0),
            }
        }

        fn gets(&self) -> usize {
            self.gets.load(Ordering::Relaxed)
        }

        fn reset(&self) {
            self.gets.store(0, Ordering::Relaxed);
        }
    }

    impl Store for CountStore<'_> {
        fn get_raw(&self, id: &ObjectId) -> crate::error::Result<Option<(ObjectKind, Vec<u8>)>> {
            self.gets.fetch_add(1, Ordering::Relaxed);
            self.inner.get_raw(id)
        }

        fn put_raw(
            &self,
            id: &ObjectId,
            kind: ObjectKind,
            body: &[u8],
        ) -> crate::error::Result<()> {
            self.inner.put_raw(id, kind, body)
        }

        fn has(&self, id: &ObjectId) -> crate::error::Result<bool> {
            self.inner.has(id)
        }
    }

    #[test]
    fn edit_and_diff_load_only_depth() {
        let store = MemoryStore::new();
        let blob = file(&store, b"same");
        let mut edits = BTreeMap::new();
        for i in 0..1000 {
            edits.insert(rp(&format!("s{i:04}/f")), Some(blob));
        }
        let deep = rp("z/a/b/c/file");
        edits.insert(deep.clone(), Some(blob));
        let root = apply_edits(&store, &empty_tree_id(), &edits).unwrap();

        let changed = file(&store, b"changed");
        let mut one = BTreeMap::new();
        one.insert(deep.clone(), Some(changed));
        let counted = CountStore::new(&store);
        let root2 = apply_edits(&counted, &root, &one).unwrap();
        // Trees on the path: root, z, a, b, c. The 1000 sibling dirs stay unloaded.
        assert_eq!(counted.gets(), 5, "edit loaded {} trees", counted.gets());
        assert_eq!(
            lookup(&store, &root, &rp("s0000")).unwrap(),
            lookup(&store, &root2, &rp("s0000")).unwrap()
        );
        assert_eq!(lookup(&store, &root2, &deep).unwrap(), Some(changed));

        counted.reset();
        let diff = diff_trees(&counted, &root, &root2).unwrap();
        assert_eq!(counted.gets(), 10, "diff loaded {} trees", counted.gets());
        assert_eq!(
            diff,
            vec![DiffEntry {
                path: deep,
                old: Some(blob),
                new: Some(changed)
            }]
        );

        counted.reset();
        assert!(diff_trees(&counted, &root2, &root2).unwrap().is_empty());
        assert_eq!(counted.gets(), 0);
    }

    fn arb_path() -> impl Strategy<Value = RepoPath> {
        prop::collection::vec("[a-z][a-z0-9._-]{0,2}", 1..=3).prop_map(|parts| {
            RepoPath::new(&parts.join("/")).expect("generated component is a legal name")
        })
    }

    fn arb_edit() -> impl Strategy<Value = Option<(u8, Vec<u8>)>> {
        prop::option::of((0u8..4, prop::collection::vec(any::<u8>(), 0..=8)))
    }

    /// Drops a path when an ancestor is in the same batch, so `apply_edits` is
    /// never handed the ambiguous case.
    fn drop_ambiguous(
        mut edits: BTreeMap<RepoPath, Option<(u8, Vec<u8>)>>,
    ) -> BTreeMap<RepoPath, Option<(u8, Vec<u8>)>> {
        let paths: Vec<RepoPath> = edits.keys().cloned().collect();
        let mut remove = Vec::new();
        for path in &paths {
            let mut parent = path.parent();
            while let Some(ancestor) = parent {
                if edits.contains_key(&ancestor) {
                    remove.push(path.clone());
                    break;
                }
                parent = ancestor.parent();
            }
        }
        for path in remove {
            edits.remove(&path);
        }
        edits
    }

    fn arb_batch() -> impl Strategy<Value = BTreeMap<RepoPath, Option<(u8, Vec<u8>)>>> {
        prop::collection::btree_map(arb_path(), arb_edit(), 0..=6).prop_map(drop_ambiguous)
    }

    fn kind_of(n: u8) -> EntryKind {
        match n % 4 {
            0 => EntryKind::File,
            1 => EntryKind::Executable,
            2 => EntryKind::Symlink,
            _ => EntryKind::Sealed,
        }
    }

    fn materialize(
        store: &MemoryStore,
        raw: &BTreeMap<RepoPath, Option<(u8, Vec<u8>)>>,
    ) -> BTreeMap<RepoPath, Option<Leaf>> {
        raw.iter()
            .map(|(path, edit)| {
                let leaf = edit
                    .as_ref()
                    .map(|(kind, bytes)| (kind_of(*kind), store.put_blob(bytes).unwrap()));
                (path.clone(), leaf)
            })
            .collect()
    }

    fn model_apply(model: &mut BTreeMap<RepoPath, Leaf>, edits: &BTreeMap<RepoPath, Option<Leaf>>) {
        let mut doomed = Vec::new();
        for (path, edit) in edits {
            for existing in model.keys() {
                if existing.starts_with(path) {
                    doomed.push(existing.clone());
                }
            }
            if edit.is_some() {
                let mut ancestor = path.parent();
                while let Some(parent) = ancestor {
                    if model.contains_key(&parent) {
                        doomed.push(parent.clone());
                    }
                    ancestor = parent.parent();
                }
            }
        }
        for path in doomed {
            model.remove(&path);
        }
        for (path, edit) in edits {
            if let Some(leaf) = edit {
                model.insert(path.clone(), *leaf);
            }
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]
        #[test]
        fn random_edits_match_model_and_diff_roundtrips(
            batches in prop::collection::vec(arb_batch(), 1..=4)
        ) {
            let store = MemoryStore::new();
            let mut model: BTreeMap<RepoPath, Leaf> = BTreeMap::new();
            let mut root = empty_tree_id();
            let mut roots = vec![root];
            for raw in &batches {
                let edits = materialize(&store, raw);
                model_apply(&mut model, &edits);
                root = apply_edits(&store, &root, &edits).expect("apply");
                roots.push(root);
                let walked = walk(&store, &root, &RepoPath::root()).unwrap();
                let expected: Vec<(RepoPath, Leaf)> = model.iter().map(|(path, leaf)| (path.clone(), *leaf)).collect();
                prop_assert_eq!(walked, expected);
            }
            for pair in roots.windows(2) {
                let diff = diff_trees(&store, &pair[0], &pair[1]).unwrap();
                let got = apply_reported_diff(&store, &pair[0], &diff).unwrap();
                if got != pair[1] {
                    let got_leaves = walk(&store, &got, &RepoPath::root()).unwrap();
                    let want_leaves = walk(&store, &pair[1], &RepoPath::root()).unwrap();
                    prop_assert_eq!(got_leaves, want_leaves);
                }
                prop_assert_eq!(got, pair[1]);
            }
        }
    }
}
