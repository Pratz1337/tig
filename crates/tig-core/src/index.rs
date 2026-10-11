//! Working-copy path index: a frozen sorted snapshot plus a mutation ledger.
//!
//! Lookups binary-search the base. The learned rank model from HRT-LI is not used.

use std::cmp::Ordering;
use std::collections::btree_map::{self, BTreeMap};
use std::iter::Peekable;
use std::ops::Bound;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::path::RepoPath;

/// Frozen sorted snapshot of `path → value`, plus a small mutation ledger.
///
/// `base` is shared through an [`Arc`] and is not rewritten on the hot path.
/// `ledger` holds the edits since that snapshot: `Some(value)` inserts or
/// overwrites, `None` deletes. An edit whose result equals the base state is
/// dropped, so adding a path and removing it again leaves the ledger empty.
/// When the ledger outgrows [`Self::needs_consolidation`], [`Self::consolidate`]
/// folds it into a new base.
///
/// Directory listings and counts are range queries over bytewise path order.
/// Rank and count results must never cross a trust boundary (publish, fetch,
/// import, or a rule change). A public view gets its own index, in which a
/// sealed folder counts as one entry. See DESIGN.md, "Path index".
#[derive(Clone, Debug)]
pub struct PathIndex<V> {
    /// Sorted, unique, immutable on the hot path. Shared with snapshots.
    base: Arc<[(RepoPath, V)]>,
    /// Edits since `base`. Missing means "same as the base".
    ledger: BTreeMap<RepoPath, Option<V>>,
    /// Live entries. Updated by every edit; never recomputed by scanning.
    len: usize,
}

impl<V> PathIndex<V> {
    /// An empty index.
    pub fn new() -> Self {
        Self {
            base: Arc::from(Vec::new()),
            ledger: BTreeMap::new(),
            len: 0,
        }
    }

    /// Builds an index from entries that are already strictly sorted by path.
    ///
    /// Returns an error if a path is out of order or repeated.
    pub fn from_sorted(entries: Vec<(RepoPath, V)>) -> Result<Self> {
        for pair in entries.windows(2) {
            if pair[0].0 >= pair[1].0 {
                return Err(Error::Invalid(
                    "path index base is not strictly sorted by path".into(),
                ));
            }
        }
        let len = entries.len();
        Ok(Self {
            base: Arc::from(entries),
            ledger: BTreeMap::new(),
            len,
        })
    }

    /// Sorts `entries` by path. When a path appears more than once, the last
    /// value in `entries` is the one that is kept.
    pub fn from_unsorted(entries: Vec<(RepoPath, V)>) -> Self {
        let mut indexed: Vec<(usize, RepoPath, V)> = entries
            .into_iter()
            .enumerate()
            .map(|(i, (p, v))| (i, p, v))
            .collect();
        // Path order. Among duplicates the later input comes first, and
        // `dedup_by` keeps that first element.
        indexed.sort_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
        indexed.dedup_by(|a, b| a.1 == b.1);
        let entries: Vec<(RepoPath, V)> = indexed.into_iter().map(|(_, p, v)| (p, v)).collect();
        let len = entries.len();
        Self {
            base: Arc::from(entries),
            ledger: BTreeMap::new(),
            len,
        }
    }

    /// The live value at `path`: the ledger wins, then the base.
    pub fn get(&self, path: &RepoPath) -> Option<&V> {
        if let Some(edit) = self.ledger.get(path) {
            return edit.as_ref();
        }
        self.base_value(path)
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Edits currently stored in the ledger, after cancellations.
    pub fn ledger_len(&self) -> usize {
        self.ledger.len()
    }

    /// Live entries, in bytewise path order.
    ///
    /// This merges the base with the ledger. It does not collect and re-sort.
    pub fn iter(&self) -> impl Iterator<Item = (&RepoPath, &V)> {
        self.range_dir(&RepoPath::root())
    }

    /// Live entries strictly inside `dir`.
    ///
    /// The root yields everything. A path is inside `dir` exactly when it
    /// begins with `dir + "/"`, a contiguous slice of bytewise order. `a.txt`
    /// and `ab` are not inside `a` (`'.' < '/' < 'b'`).
    pub fn range_dir(&self, dir: &RepoPath) -> impl Iterator<Item = (&RepoPath, &V)> {
        let (rows, ledger) = dir_parts(&self.base, &self.ledger, dir);
        Merge {
            base: rows,
            base_idx: 0,
            ledger: ledger.peekable(),
        }
    }

    /// How many live entries are strictly inside `dir`.
    ///
    /// The base contribution is the length of the directory's slice (two
    /// binary searches). Ledger entries in that same range then adjust the
    /// count. Base rows are not walked.
    pub fn count_dir(&self, dir: &RepoPath) -> usize {
        let (rows, ledger) = dir_parts(&self.base, &self.ledger, dir);
        let mut count = rows.len();
        for (path, edit) in ledger {
            let in_base = rows.binary_search_by(|(p, _)| p.cmp(path)).is_ok();
            match edit {
                None if in_base => count -= 1,
                Some(_) if !in_base => count += 1,
                _ => {}
            }
        }
        count
    }

    /// `ledger_len() > max(1024, base_len / 16)`.
    pub fn needs_consolidation(&self) -> bool {
        self.ledger.len() > std::cmp::max(1024, self.base.len() / 16)
    }

    /// Copy that shares the base and owns its own ledger.
    ///
    /// Edits and consolidation of `self` do not change the returned index.
    pub fn snapshot(&self) -> Self
    where
        V: Clone,
    {
        self.clone()
    }

    fn base_value(&self, path: &RepoPath) -> Option<&V> {
        let i = self.base.binary_search_by(|(p, _)| p.cmp(path)).ok()?;
        Some(&self.base[i].1)
    }
}

impl<V> Default for PathIndex<V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<V: PartialEq> PathIndex<V> {
    /// Inserts or overwrites `path`. A value equal to the base drops the
    /// ledger entry instead of storing another edit.
    pub fn insert(&mut self, path: RepoPath, value: V) {
        let existed = self.get(&path).is_some();
        if self.base_value(&path) == Some(&value) {
            self.ledger.remove(&path);
        } else {
            self.ledger.insert(path, Some(value));
        }
        if !existed {
            self.len += 1;
        }
    }

    /// Removes `path`. Returns whether it was present.
    ///
    /// Removing a path that the base does not have drops the ledger entry
    /// (the inverse of the insert) instead of recording a delete.
    pub fn remove(&mut self, path: &RepoPath) -> bool {
        if self.get(path).is_none() {
            return false;
        }
        if self.base_value(path).is_some() {
            self.ledger.insert(path.clone(), None);
        } else {
            self.ledger.remove(path);
        }
        self.len -= 1;
        true
    }
}

impl<V: Clone> PathIndex<V> {
    /// Folds the ledger into a new base and clears it.
    ///
    /// Snapshots that still hold the previous base are left as they were.
    pub fn consolidate(&mut self) {
        if self.ledger.is_empty() {
            return;
        }
        let entries: Vec<(RepoPath, V)> =
            self.iter().map(|(p, v)| (p.clone(), v.clone())).collect();
        // `len` counts the same rows `iter` yields.
        debug_assert_eq!(entries.len(), self.len);
        self.base = Arc::from(entries);
        self.ledger.clear();
    }
}

type DirParts<'a, V> = (
    &'a [(RepoPath, V)],
    btree_map::Range<'a, RepoPath, Option<V>>,
);

/// Base slice and ledger range for `dir`. Root covers the whole index.
///
/// The exclusive end of a non-root directory is `dir + "0"` because every
/// path inside `dir` starts with `dir + "/"` and `'/' + 1 == '0'`.
fn dir_parts<'a, V>(
    base: &'a [(RepoPath, V)],
    ledger: &'a BTreeMap<RepoPath, Option<V>>,
    dir: &RepoPath,
) -> DirParts<'a, V> {
    if dir.is_root() {
        return (base, ledger.range::<RepoPath, _>(..));
    }
    let prefix = format!("{}/", dir.as_str());
    let end = format!("{}0", dir.as_str());
    let start = base.partition_point(|(p, _)| p.as_str() < prefix.as_str());
    let stop = base.partition_point(|(p, _)| p.as_str() < end.as_str());
    // `Bound<&str>` queries `Borrow<str>`. A `Range<&str>` would ask for `Borrow<&str>`.
    let rows = ledger.range::<str, _>((
        Bound::Included(prefix.as_str()),
        Bound::Excluded(end.as_str()),
    ));
    (&base[start..stop], rows)
}

/// Merge of a sorted base slice with a sorted ledger range.
struct Merge<'a, V> {
    base: &'a [(RepoPath, V)],
    base_idx: usize,
    ledger: Peekable<btree_map::Range<'a, RepoPath, Option<V>>>,
}

enum Step {
    Base,
    Ledger,
    Both,
}

impl<'a, V> Iterator for Merge<'a, V> {
    type Item = (&'a RepoPath, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.base_idx >= self.base.len() {
                let (path, edit) = self.ledger.next()?;
                if let Some(value) = edit.as_ref() {
                    return Some((path, value));
                }
                continue;
            }
            // The peek borrow ends before `ledger.next()` below.
            let step = match self.ledger.peek() {
                None => Step::Base,
                Some(entry) => match self.base[self.base_idx].0.cmp(entry.0) {
                    Ordering::Less => Step::Base,
                    Ordering::Greater => Step::Ledger,
                    Ordering::Equal => Step::Both,
                },
            };
            match step {
                Step::Base => {
                    let (path, value) = &self.base[self.base_idx];
                    self.base_idx += 1;
                    return Some((path, value));
                }
                Step::Ledger => {
                    // `step` came from a peek, so this entry is still there.
                    let (path, edit) = self.ledger.next().expect("ledger entry was peeked");
                    if let Some(value) = edit.as_ref() {
                        return Some((path, value));
                    }
                }
                Step::Both => {
                    self.base_idx += 1;
                    let (path, edit) = self.ledger.next().expect("ledger entry was peeked");
                    if let Some(value) = edit.as_ref() {
                        return Some((path, value));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use proptest::prelude::*;
    use proptest::test_runner::TestCaseError;

    use super::*;

    fn rp(s: &str) -> RepoPath {
        RepoPath::new(s).expect("valid test path")
    }

    fn listed(index: &PathIndex<i32>, dir: &str) -> Vec<String> {
        let dir = if dir.is_empty() {
            RepoPath::root()
        } else {
            rp(dir)
        };
        index
            .range_dir(&dir)
            .map(|(p, _)| p.as_str().to_string())
            .collect()
    }

    fn dump<V: Copy>(index: &PathIndex<V>) -> Vec<(String, V)> {
        index
            .iter()
            .map(|(p, v)| (p.as_str().to_string(), *v))
            .collect()
    }

    #[test]
    fn from_sorted_rejects_disorder_and_duplicates() {
        assert!(PathIndex::from_sorted(vec![(rp("b"), 1), (rp("a"), 2)]).is_err());
        assert!(PathIndex::from_sorted(vec![(rp("a"), 1), (rp("a"), 2)]).is_err());
        let idx = PathIndex::from_sorted(vec![(rp("a"), 1), (rp("b"), 2)]).unwrap();
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.get(&rp("b")), Some(&2));
        assert!(PathIndex::<i32>::from_sorted(vec![]).unwrap().is_empty());
    }

    #[test]
    fn from_unsorted_sorts_and_keeps_the_last_duplicate() {
        let idx = PathIndex::from_unsorted(vec![
            (rp("c"), 1),
            (rp("a"), 2),
            (rp("b"), 3),
            (rp("a"), 4),
            (rp("b"), 5),
        ]);
        assert_eq!(
            dump(&idx),
            vec![("a".into(), 4), ("b".into(), 5), ("c".into(), 1)]
        );
        assert_eq!(idx.ledger_len(), 0);
    }

    #[test]
    fn inverse_edits_cancel() {
        let mut idx = PathIndex::<i32>::new();
        idx.insert(rp("a"), 1);
        assert!(idx.remove(&rp("a")));
        assert_eq!(idx.ledger_len(), 0);
        assert!(idx.is_empty());
        assert!(!idx.remove(&rp("a")));

        let mut idx = PathIndex::from_sorted(vec![(rp("a"), 1), (rp("b"), 2)]).unwrap();
        idx.insert(rp("a"), 1);
        assert_eq!(idx.ledger_len(), 0);

        idx.insert(rp("a"), 9);
        assert_eq!(idx.ledger_len(), 1);
        assert_eq!(idx.get(&rp("a")), Some(&9));
        assert_eq!(idx.len(), 2);
        idx.insert(rp("a"), 1);
        assert_eq!(idx.ledger_len(), 0);
        assert_eq!(idx.get(&rp("a")), Some(&1));

        assert!(idx.remove(&rp("b")));
        assert_eq!(idx.ledger_len(), 1);
        assert_eq!(idx.len(), 1);
        assert!(idx.get(&rp("b")).is_none());
        idx.insert(rp("b"), 2);
        assert_eq!(idx.ledger_len(), 0);
        assert_eq!(idx.len(), 2);

        idx.insert(rp("c"), 3);
        idx.remove(&rp("c"));
        assert_eq!(idx.ledger_len(), 0);
        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn overwrite_replaces_the_live_value() {
        let mut idx = PathIndex::from_sorted(vec![(rp("a"), 1)]).unwrap();
        idx.insert(rp("a"), 2);
        idx.insert(rp("b"), 3);
        idx.insert(rp("b"), 4);
        assert_eq!(idx.get(&rp("a")), Some(&2));
        assert_eq!(idx.get(&rp("b")), Some(&4));
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.ledger_len(), 2);
        idx.remove(&rp("a"));
        idx.insert(rp("a"), 7);
        assert_eq!(idx.get(&rp("a")), Some(&7));
        assert_eq!(idx.len(), 2);
        assert_eq!(idx.ledger_len(), 2);
    }

    #[test]
    fn dir_boundary_dot_sorts_before_slash() {
        // '.' (0x2e) < '/' (0x2f) < 'b', so these are siblings, not nested.
        assert!(rp("a") < rp("a.txt"));
        assert!(rp("a.txt") < rp("a/b"));
        assert!(rp("a/b") < rp("ab"));

        let mut idx = PathIndex::from_sorted(vec![
            (rp("a"), 1),
            (rp("a.txt"), 2),
            (rp("a/b"), 3),
            (rp("ab"), 4),
        ])
        .unwrap();
        assert_eq!(listed(&idx, "a"), vec!["a/b"]);
        assert_eq!(idx.count_dir(&rp("a")), 1);
        assert_eq!(listed(&idx, ""), vec!["a", "a.txt", "a/b", "ab"]);
        assert_eq!(idx.count_dir(&RepoPath::root()), idx.len());

        idx.insert(rp("a/c"), 5);
        idx.remove(&rp("a/b"));
        idx.insert(rp("a.txt"), 8);
        assert_eq!(listed(&idx, "a"), vec!["a/c"]);
        assert_eq!(idx.count_dir(&rp("a")), 1);
        assert_eq!(idx.get(&rp("a.txt")), Some(&8));
        assert_eq!(idx.count_dir(&RepoPath::root()), 4);
        assert_eq!(listed(&idx, "ab"), Vec::<String>::new());
        assert_eq!(idx.count_dir(&rp("a.txt")), 0);
    }

    #[test]
    fn dir_range_uses_slash_prefix_against_neighbors() {
        let mut idx = PathIndex::from_sorted(vec![(rp("a.txt"), 1), (rp("ab"), 2)]).unwrap();
        idx.insert(rp("a/b"), 3);
        assert_eq!(listed(&idx, "a"), vec!["a/b"]);
        assert_eq!(idx.count_dir(&rp("a")), 1);
        assert_eq!(
            dump(&idx),
            vec![("a.txt".into(), 1), ("a/b".into(), 3), ("ab".into(), 2)]
        );

        idx.remove(&rp("a.txt"));
        assert_eq!(listed(&idx, "a"), vec!["a/b"]);
        assert_eq!(idx.count_dir(&rp("a")), 1);
        assert_eq!(idx.count_dir(&RepoPath::root()), 2);
    }

    #[test]
    fn nested_dirs_and_empty_root() {
        let mut idx = PathIndex::new();
        assert_eq!(idx.count_dir(&RepoPath::root()), 0);
        assert!(idx.iter().next().is_none());
        idx.insert(rp("a/b/c"), 1);
        assert_eq!(listed(&idx, "a"), vec!["a/b/c"]);
        assert_eq!(listed(&idx, "a/b"), vec!["a/b/c"]);
        assert_eq!(listed(&idx, "a/b/c"), Vec::<String>::new());
        assert_eq!(idx.count_dir(&rp("a")), 1);
        assert_eq!(idx.count_dir(&rp("a/b")), 1);
        assert_eq!(idx.count_dir(&rp("ab")), 0);
    }

    #[test]
    fn consolidate_preserves_content_and_snapshots() {
        let mut idx =
            PathIndex::from_sorted(vec![(rp("a"), 1), (rp("b"), 2), (rp("c"), 3)]).unwrap();
        idx.insert(rp("b"), 9);
        idx.remove(&rp("c"));
        idx.insert(rp("d"), 4);
        let before = dump(&idx);
        let snap = idx.snapshot();
        assert!(idx.ledger_len() > 0);
        idx.consolidate();
        assert_eq!(idx.ledger_len(), 0);
        assert!(!idx.needs_consolidation());
        assert_eq!(dump(&idx), before);
        assert_eq!(dump(&snap), before);
        assert_eq!(idx.len(), before.len());

        idx.remove(&rp("a"));
        idx.consolidate();
        assert_eq!(snap.get(&rp("a")), Some(&1));
        assert!(idx.get(&rp("a")).is_none());
        assert_eq!(snap.ledger_len(), 3);

        idx.insert(rp("b"), 9);
        assert_eq!(idx.ledger_len(), 0);
        idx.consolidate();
        assert_eq!(dump(&idx), vec![("b".into(), 9), ("d".into(), 4)]);
    }

    #[test]
    fn consolidation_threshold_follows_the_base() {
        let mut small = PathIndex::new();
        for i in 0..1024 {
            small.insert(rp(&format!("s{i:04}")), i);
        }
        assert_eq!(small.ledger_len(), 1024);
        assert!(!small.needs_consolidation());
        small.insert(rp("s_extra"), 0);
        assert!(small.needs_consolidation());
        let before = dump(&small);
        small.consolidate();
        assert_eq!(small.ledger_len(), 0);
        assert_eq!(dump(&small), before);

        let n = 17_000;
        let entries: Vec<_> = (0..n).map(|i| (rp(&format!("p{i:05}")), i)).collect();
        let mut idx = PathIndex::from_unsorted(entries);
        assert_eq!(idx.len(), n);
        assert!(!idx.needs_consolidation());
        let limit = std::cmp::max(1024, n / 16);
        for i in 0..limit {
            idx.insert(rp(&format!("p{i:05}")), i + 1);
        }
        assert_eq!(idx.ledger_len(), limit);
        assert!(!idx.needs_consolidation());
        idx.insert(rp(&format!("p{limit:05}")), 0);
        assert!(idx.needs_consolidation());
        let before = dump(&idx);
        idx.consolidate();
        assert_eq!(idx.ledger_len(), 0);
        assert_eq!(dump(&idx), before);
        assert_eq!(idx.get(&rp("p00000")), Some(&1));
        assert_eq!(idx.get(&rp(&format!("p{limit:05}"))), Some(&0));
    }

    const PATHS: &[&str] = &["a", "a.txt", "a/b", "a/b/c", "a/c", "ab", "b", "b/a"];
    const DIRS: &[&str] = &["", "a", "a/b", "a.txt", "ab", "b", "c"];

    #[derive(Clone, Debug)]
    enum Op {
        Insert(usize, u16),
        Remove(usize),
        Consolidate,
    }

    fn op_strategy() -> impl Strategy<Value = Op> {
        prop_oneof![
            6 => (0..PATHS.len(), any::<u16>()).prop_map(|(i, v)| Op::Insert(i, v)),
            3 => (0..PATHS.len()).prop_map(Op::Remove),
            1 => Just(Op::Consolidate),
        ]
    }

    fn strictly_inside(path: &RepoPath, dir: &RepoPath) -> bool {
        if dir.is_root() {
            return true;
        }
        path.as_str().starts_with(&format!("{}/", dir.as_str()))
    }

    fn agrees(
        index: &PathIndex<u16>,
        oracle: &BTreeMap<RepoPath, u16>,
    ) -> Result<(), TestCaseError> {
        prop_assert_eq!(index.len(), oracle.len());
        prop_assert_eq!(index.is_empty(), oracle.is_empty());

        let mut paths = BTreeSet::new();
        for (p, _) in index.base.iter() {
            paths.insert(p.clone());
        }
        for p in index.ledger.keys() {
            paths.insert(p.clone());
        }
        for p in oracle.keys() {
            paths.insert(p.clone());
        }
        for s in PATHS {
            paths.insert(rp(s));
        }

        for p in &paths {
            prop_assert_eq!(index.get(p), oracle.get(p));
            let base = index.base_value(p).copied();
            let live = oracle.get(p).copied();
            if base == live {
                prop_assert!(!index.ledger.contains_key(p));
            } else {
                match live {
                    None => prop_assert_eq!(index.ledger.get(p), Some(&None)),
                    Some(v) => prop_assert_eq!(index.ledger.get(p), Some(&Some(v))),
                }
            }
        }

        let got: Vec<(RepoPath, u16)> = index.iter().map(|(p, v)| (p.clone(), *v)).collect();
        let expect: Vec<(RepoPath, u16)> = oracle.iter().map(|(p, v)| (p.clone(), *v)).collect();
        prop_assert_eq!(got, expect.clone());
        let root: Vec<(RepoPath, u16)> = index
            .range_dir(&RepoPath::root())
            .map(|(p, v)| (p.clone(), *v))
            .collect();
        prop_assert_eq!(root, expect);
        prop_assert_eq!(index.count_dir(&RepoPath::root()), oracle.len());

        for dir_s in DIRS {
            let dir = if dir_s.is_empty() {
                RepoPath::root()
            } else {
                rp(dir_s)
            };
            let expect_dir: Vec<(RepoPath, u16)> = oracle
                .iter()
                .filter(|(p, _)| strictly_inside(p, &dir))
                .map(|(p, v)| (p.clone(), *v))
                .collect();
            let got_dir: Vec<(RepoPath, u16)> = index
                .range_dir(&dir)
                .map(|(p, v)| (p.clone(), *v))
                .collect();
            let dir_len = expect_dir.len();
            prop_assert_eq!(got_dir, expect_dir, "dir {}", dir.as_str());
            prop_assert_eq!(index.count_dir(&dir), dir_len, "count {}", dir.as_str());
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn random_edits_match_a_btreemap(ops in prop::collection::vec(op_strategy(), 0..80)) {
            let mut index = PathIndex::<u16>::new();
            let mut oracle = BTreeMap::new();
            agrees(&index, &oracle)?;
            for op in ops {
                match op {
                    Op::Insert(i, v) => {
                        let path = rp(PATHS[i]);
                        index.insert(path.clone(), v);
                        oracle.insert(path, v);
                    }
                    Op::Remove(i) => {
                        let path = rp(PATHS[i]);
                        let removed = index.remove(&path);
                        prop_assert_eq!(removed, oracle.remove(&path).is_some());
                    }
                    Op::Consolidate => index.consolidate(),
                }
                agrees(&index, &oracle)?;
                if index.needs_consolidation() {
                    index.consolidate();
                    prop_assert_eq!(index.ledger_len(), 0);
                    agrees(&index, &oracle)?;
                }
            }
        }
    }
}
