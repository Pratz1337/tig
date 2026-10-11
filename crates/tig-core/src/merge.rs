//! Three-way tree merge at the file level, and merge-base search.
//!
//! Phase 1 has no conflict objects yet: a merge that would conflict returns
//! `MergeOutcome::Conflict` with the paths, and the caller refuses the operation
//! instead of writing a half-merged tree.

use std::collections::{BTreeMap, HashSet, VecDeque};

use crate::error::Result;
use crate::id::ObjectId;
use crate::path::{has_ancestor, has_inside, RepoPath};
use crate::store::{Store, StoreExt};
use crate::treeops::{apply_edits, diff_trees, Leaf};

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
            Some(_) => {} // both sides made the same change
            None => {
                // A change under a path that `ours` turned into a file (or vice
                // versa) shows up as different leaf paths; catch it here.
                if has_ancestor(&our_changes, &d.path) || has_inside(&our_changes, &d.path) {
                    conflicts.push(d.path);
                } else {
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

/// Nearest common ancestor of two revisions (by BFS distance from `a`), or
/// None if they share no history. Walks revision parents.
pub fn merge_base(store: &dyn Store, a: &ObjectId, b: &ObjectId) -> Result<Option<ObjectId>> {
    let ancestors_b = ancestors(store, b)?;
    let mut queue = VecDeque::from([*a]);
    let mut seen = HashSet::from([*a]);
    while let Some(id) = queue.pop_front() {
        if ancestors_b.contains(&id) {
            return Ok(Some(id));
        }
        for p in store.get_revision(&id)?.parents {
            if seen.insert(p) {
                queue.push_back(p);
            }
        }
    }
    Ok(None)
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
