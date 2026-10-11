//! Three-way tree merge at the file level, and merge-base search.
//!
//! Phase 1 has no conflict objects yet: a merge that would conflict returns
//! `MergeOutcome::Conflict` with the paths, and the caller refuses the operation
//! instead of writing a half-merged tree.

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::EntryKind;
use crate::path::{has_ancestor, has_inside, RepoPath};
use crate::store::{empty_tree_id, Store, StoreExt};
use crate::treeops::{apply_edits, diff_trees, lookup, Leaf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergeOutcome {
    Clean(ObjectId),
    Conflict(Vec<RepoPath>),
}

/// Applies the changes `base -> theirs` on top of `ours`.
///
/// Cost is proportional to the two diffs, not to the tree size.
pub fn merge_trees(store: &dyn Store, base: &ObjectId, ours: &ObjectId, theirs: &ObjectId) -> Result<MergeOutcome> {
    if base == theirs || ours == theirs {
        return Ok(MergeOutcome::Clean(*ours));
    }
    if base == ours {
        return Ok(MergeOutcome::Clean(*theirs));
    }
    let our_changes: BTreeMap<RepoPath, Option<Leaf>> =
        diff_trees(store, base, ours)?.into_iter().map(|d| (d.path, d.new)).collect();
    let mut edits = BTreeMap::new();
    let mut conflicts = Vec::new();
    for d in diff_trees(store, base, theirs)? {
        match our_changes.get(&d.path) {
            Some(ours_new) if *ours_new != d.new => conflicts.push(d.path),
            Some(_) if d.new.is_some() => {} // both sides wrote the same leaf
            _ => {
                // Compare the final entries at the overlapping path. Two
                // sides replacing the same file with directories are compatible;
                // their individual leaf changes are checked separately.
                // A shared deletion can still be a replacement on one side.
                let mut overlap = (has_inside(&our_changes, &d.path)
                    || (our_changes.contains_key(&d.path)
                        && lookup(store, ours, &d.path)? != lookup(store, theirs, &d.path)?))
                    .then(|| d.path.clone());
                let mut parent = d.path.parent();
                while let Some(at) = parent.filter(|at| !at.is_root()) {
                    if our_changes.contains_key(&at) {
                        // Keep the closest overlap. A shared replacement at
                        // an ancestor must not hide a file/directory clash here.
                        if overlap.is_none() {
                            overlap = Some(at);
                        }
                        break;
                    }
                    parent = at.parent();
                }
                let incompatible = if let Some(at) = overlap {
                    let ours = lookup(store, ours, &at)?;
                    let theirs = lookup(store, theirs, &at)?;
                    ours != theirs && !(ours.is_some_and(|leaf| leaf.kind() == EntryKind::Tree)
                        && theirs.is_some_and(|leaf| leaf.kind() == EntryKind::Tree))
                } else {
                    false
                };
                if incompatible {
                    conflicts.push(d.path);
                } else if !our_changes.contains_key(&d.path) {
                    edits.insert(d.path, d.new);
                }
            }
        }
    }
    if !conflicts.is_empty() {
        return Ok(MergeOutcome::Conflict(conflicts));
    }
    // A file<->directory change diffs as a delete plus puts at a related path
    // (`a` removed, `a/x` added). `apply_edits` rejects that pair as ambiguous,
    // and a put already replaces whatever is in its way, so drop the delete.
    let redundant: Vec<RepoPath> = edits
        .iter()
        .filter(|(p, e)| e.is_none() && (has_ancestor(&edits, p) || has_inside(&edits, p)))
        .map(|(p, _)| p.clone())
        .collect();
    for p in redundant {
        edits.remove(&p);
    }
    Ok(MergeOutcome::Clean(apply_edits(store, ours, &edits)?))
}

/// Best common ancestors, sorted by id. No result is an ancestor of another
/// result. Unrelated histories return an empty vector.
pub fn merge_base(store: &dyn Store, a: &ObjectId, b: &ObjectId) -> Result<Vec<ObjectId>> {
    let graph = MergeGraph::load(store, &[*a, *b])?;
    graph.bases(&[*a], &[*b])
}

/// Merges revisions against the ancestry of all accumulated parents. Multiple
/// best bases are themselves merged into a virtual base; a conflict there is
/// a conflict in the outer merge too. No synthetic revisions are stored.
pub(crate) fn merge_revisions(store: &dyn Store, heads: &[ObjectId]) -> Result<MergeOutcome> {
    let graph = MergeGraph::load(store, heads)?;
    graph.merge(store, heads)
}

/// Load each revision once per merge, including recursive virtual bases. Base
/// selection makes two graph walks and prunes common parents, never a separate
/// history walk for each common ancestor.
struct MergeGraph {
    revisions: HashMap<ObjectId, (ObjectId, Vec<ObjectId>)>,
}

impl MergeGraph {
    fn load(store: &dyn Store, heads: &[ObjectId]) -> Result<Self> {
        let mut revisions = HashMap::new();
        let mut stack = heads.to_vec();
        while let Some(id) = stack.pop() {
            if revisions.contains_key(&id) {
                continue;
            }
            let revision = store.get_revision(&id)?;
            stack.extend(&revision.parents);
            revisions.insert(id, (revision.tree, revision.parents));
        }
        Ok(Self { revisions })
    }

    fn revision(&self, id: &ObjectId) -> Result<&(ObjectId, Vec<ObjectId>)> {
        self.revisions.get(id).ok_or(Error::NotFound(*id))
    }

    fn ancestors(&self, heads: &[ObjectId]) -> Result<HashSet<ObjectId>> {
        let mut seen = HashSet::new();
        let mut stack = heads.to_vec();
        while let Some(id) = stack.pop() {
            if seen.insert(id) {
                stack.extend(&self.revision(&id)?.1);
            }
        }
        Ok(seen)
    }

    fn bases(&self, a: &[ObjectId], b: &[ObjectId]) -> Result<Vec<ObjectId>> {
        let a = self.ancestors(a)?;
        let b = self.ancestors(b)?;
        let common: HashSet<ObjectId> = a.intersection(&b).copied().collect();
        let mut best = common.clone();
        // Any ancestor of a common ancestor is also common. Removing each
        // common member's direct parents therefore removes all inferior bases.
        for id in common {
            for parent in &self.revision(&id)?.1 {
                best.remove(parent);
            }
        }
        let mut best: Vec<ObjectId> = best.into_iter().collect();
        best.sort();
        Ok(best)
    }

    fn merge(&self, store: &dyn Store, heads: &[ObjectId]) -> Result<MergeOutcome> {
        struct Frame {
            heads: Vec<ObjectId>,
            tree: ObjectId,
            next: usize,
        }
        let first = heads.first().ok_or_else(|| Error::Invalid("a merge needs at least one parent".into()))?;
        let mut stack = vec![Frame { heads: heads.to_vec(), tree: self.revision(first)?.0, next: 1 }];
        let mut virtual_trees = BTreeMap::new();
        // Explicit frames keep nested criss-cross histories off the call stack.
        while let Some(frame) = stack.last_mut() {
            if frame.next == frame.heads.len() {
                let tree = frame.tree;
                virtual_trees.insert(frame.heads.clone(), tree);
                stack.pop();
                if stack.is_empty() {
                    return Ok(MergeOutcome::Clean(tree));
                }
                continue;
            }
            let parent = frame.heads[frame.next];
            let bases = self.bases(&frame.heads[..frame.next], &[parent])?;
            let base = match bases.as_slice() {
                [] => empty_tree_id(),
                [base] => self.revision(base)?.0,
                _ => match virtual_trees.get(&bases) {
                    Some(tree) => *tree,
                    None => {
                        let tree = self.revision(&bases[0])?.0;
                        stack.push(Frame { heads: bases, tree, next: 1 });
                        continue;
                    }
                },
            };
            match merge_trees(store, &base, &frame.tree, &self.revision(&parent)?.0)? {
                MergeOutcome::Clean(tree) => frame.tree = tree,
                conflict => return Ok(conflict),
            }
            frame.next += 1;
        }
        Err(Error::Invalid("merge produced no tree".into()))
    }
}

/// All ancestors of `id`, including itself.
pub fn ancestors(store: &dyn Store, id: &ObjectId) -> Result<HashSet<ObjectId>> {
    let mut seen = HashSet::from([*id]);
    let mut stack = vec![*id];
    while let Some(id) = stack.pop() {
        for p in store.get_revision(&id)?.parents {
            if seen.insert(p) {
                stack.push(p);
            }
        }
    }
    Ok(seen)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::EntryKind;
    use crate::seal::{SealSalt, SealedId};
    use crate::store::{empty_tree_id, MemoryStore, StoreExt};
    use crate::treeops::Leaf;

    fn tree(store: &MemoryStore, files: &[(&str, &[u8])]) -> ObjectId {
        let edits = files
            .iter()
            .map(|(p, data)| {
                let id = store.put_blob(data).unwrap();
                (RepoPath::new(p).unwrap(), Some(Leaf::file(id)))
            })
            .collect();
        apply_edits(store, &empty_tree_id(), &edits).unwrap()
    }

    fn tree_leaves(store: &MemoryStore, files: &[(&str, Leaf)]) -> ObjectId {
        let edits = files
            .iter()
            .map(|(p, leaf)| (RepoPath::new(p).unwrap(), Some(*leaf)))
            .collect();
        apply_edits(store, &empty_tree_id(), &edits).unwrap()
    }

    #[test]
    fn clean_merge_of_disjoint_changes() {
        let s = MemoryStore::new();
        let base = tree(&s, &[("a", b"1"), ("b", b"1")]);
        let ours = tree(&s, &[("a", b"2"), ("b", b"1")]);
        let theirs = tree(&s, &[("a", b"1"), ("b", b"2"), ("c", b"new")]);
        let want = tree(&s, &[("a", b"2"), ("b", b"2"), ("c", b"new")]);
        assert_eq!(merge_trees(&s, &base, &ours, &theirs).unwrap(), MergeOutcome::Clean(want));
    }

    #[test]
    fn same_path_different_content_conflicts() {
        let s = MemoryStore::new();
        let base = tree(&s, &[("a", b"1")]);
        let ours = tree(&s, &[("a", b"2")]);
        let theirs = tree(&s, &[("a", b"3")]);
        assert_eq!(
            merge_trees(&s, &base, &ours, &theirs).unwrap(),
            MergeOutcome::Conflict(vec![RepoPath::new("a").unwrap()])
        );
    }

    #[test]
    fn file_to_directory_change_merges() {
        let s = MemoryStore::new();
        let base = tree(&s, &[("a", b"file"), ("z", b"1")]);
        let ours = tree(&s, &[("a", b"file"), ("z", b"2")]);
        let theirs = tree(&s, &[("a/x", b"in dir"), ("z", b"1")]);
        let want = tree(&s, &[("a/x", b"in dir"), ("z", b"2")]);
        assert_eq!(merge_trees(&s, &base, &ours, &theirs).unwrap(), MergeOutcome::Clean(want));
        // And back: directory to file.
        let want_back = tree(&s, &[("a", b"file"), ("z", b"2")]);
        let ours2 = tree(&s, &[("a/x", b"in dir"), ("z", b"2")]);
        assert_eq!(merge_trees(&s, &theirs, &ours2, &base).unwrap(), MergeOutcome::Clean(want_back));
    }

    #[test]
    fn edit_under_a_path_the_other_side_replaced_conflicts() {
        let s = MemoryStore::new();
        let base = tree(&s, &[("a/x", b"1")]);
        let ours = tree(&s, &[("a", b"now a file")]);
        let theirs = tree(&s, &[("a/x", b"2")]);
        assert!(matches!(merge_trees(&s, &base, &ours, &theirs).unwrap(), MergeOutcome::Conflict(_)));
    }

    #[test]
    fn sealed_entries_on_both_sides_merge() {
        let s = MemoryStore::new();
        let a1 = s.put_blob(b"1").unwrap();
        let a2 = s.put_blob(b"2").unwrap();
        let note = s.put_blob(b"n").unwrap();
        let hidden = s.put_blob(b"hidden").unwrap();
        let hidden2 = s.put_blob(b"hidden-2").unwrap();
        let salt = SealSalt::from_bytes([4; 32]);
        let secret = Leaf::sealed(SealedId::compute(&salt, EntryKind::File, &hidden));
        let secret2 = Leaf::sealed(SealedId::compute(&salt, EntryKind::File, &hidden2));

        let base = tree_leaves(&s, &[("a", Leaf::file(a1)), ("secret", secret)]);
        let ours = tree_leaves(&s, &[("a", Leaf::file(a2)), ("secret", secret)]);
        let theirs = tree_leaves(&s, &[
            ("a", Leaf::file(a1)),
            ("secret", secret2),
            ("note", Leaf::file(note)),
        ]);
        let want = tree_leaves(&s, &[
            ("a", Leaf::file(a2)),
            ("secret", secret2),
            ("note", Leaf::file(note)),
        ]);
        let merged = merge_trees(&s, &base, &ours, &theirs).unwrap();
        assert_eq!(merged, MergeOutcome::Clean(want));

        let got = s.get_tree(&want).unwrap();
        let sealed = got.get("secret").unwrap();
        assert_eq!(sealed.kind(), EntryKind::Sealed);
        assert_eq!(sealed.sealed_id(), secret2.sealed_id());

        // The same sealed update on both sides is not a conflict.
        let ours_same = tree_leaves(&s, &[("a", Leaf::file(a2)), ("secret", secret2)]);
        let theirs_same = tree_leaves(&s, &[
            ("a", Leaf::file(a1)),
            ("secret", secret2),
            ("note", Leaf::file(note)),
        ]);
        assert_eq!(
            merge_trees(&s, &base, &ours_same, &theirs_same).unwrap(),
            MergeOutcome::Clean(want)
        );
    }
}
