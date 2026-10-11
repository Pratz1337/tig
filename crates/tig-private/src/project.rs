//! The public projection of a tree: what outsiders see after publish.
//! See DESIGN.md "Publish and fetch". Runs only at publish time.
//!
//! 1. Classify every file with the `.private` rules of the tree itself.
//! 2. Find the sealed roots: the highest entries whose files are all private
//!    to the same readers. A fully private folder becomes one sealed entry,
//!    so outsiders learn its name and nothing inside it.
//!    Existing foreign seals are neutral: they add no readers and do not
//!    prevent an otherwise private folder from being sealed whole.
//! 3. Replace each sealed root with `Leaf::sealed` in one `apply_edits`
//!    call, so every subtree without private files is reused by ID.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use tig_core::store::{Store, StoreExt};
use tig_core::treeops::{apply_edits, lookup, walk, Leaf};
use tig_core::{EntryKind, ObjectId, RepoPath, Revision};

use crate::keys::EpochKey;
use crate::rules::{RuleError, RuleSource, Rules, Verdict, DEFAULT_PRIVATE};

/// The file that holds the rules. It must itself stay public.
pub const RULES_FILE: &str = ".private";

/// The built-in group of simple mode.
pub const PRIVATE_GROUP: &str = "private";

#[derive(Debug, thiserror::Error)]
pub enum ProjectError {
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error(".private is invalid: {0}")]
    Rules(#[from] RuleError),
    #[error("{RULES_FILE} matches its own rules; it must stay public so everyone can see what is private")]
    RulesFileIsPrivate,
    #[error("roles ({0}) are not supported yet; this version publishes simple mode only (one `private` group)")]
    RolesNotSupported(String),
}

/// One private entry replaced by a sealed entry in the public tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRoot {
    pub path: RepoPath,
    /// The internal entry (a file or a whole directory).
    pub leaf: Leaf,
    pub readers: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub struct Projection {
    pub public_tree: ObjectId,
    pub sealed: Vec<SealedRoot>,
    /// Every public file (path, internal leaf), for leak and paste checks.
    pub public_files: Vec<(RepoPath, Leaf)>,
    /// Every private file, for paste detection.
    pub private_files: Vec<(RepoPath, Leaf)>,
    /// Public files that are public only because a `!` rule said so.
    pub negated: Vec<RepoPath>,
}

/// Reads the `.private` file of `root` and layers it on the built-in floor.
///
/// An absent or empty file still applies [`DEFAULT_PRIVATE`], so `.env` stays
/// private. The file can add paths and can re-publish a default-private path
/// only with an explicit `!` line. Invalid UTF-8, a non-file, or a bad rule
/// is an error.
pub fn rules_of(store: &dyn Store, root: &ObjectId) -> Result<Rules, ProjectError> {
    let path = RepoPath::new(RULES_FILE)?;
    match lookup(store, root, &path)? {
        Some(leaf) if matches!(leaf.kind(), EntryKind::File | EntryKind::Executable) => {
            let bytes = store.get_blob(&leaf.id())?;
            let text = std::str::from_utf8(&bytes).map_err(|_| {
                tig_core::Error::Invalid(".private is invalid: expected UTF-8".into())
            })?;
            Ok(Rules::parse_layered(DEFAULT_PRIVATE, text)?)
        }
        None => Ok(Rules::parse_layered(DEFAULT_PRIVATE, "")?),
        Some(_) => Err(tig_core::Error::Invalid(
            ".private is invalid: expected a regular file".into(),
        )
        .into()),
    }
}

/// Projects `root` for publishing under the `private` group's `key`.
pub fn project_tree(
    store: &dyn Store,
    root: &ObjectId,
    key: &EpochKey,
) -> Result<Projection, ProjectError> {
    let rules = rules_of(store, root)?;
    if !rules.is_simple_mode() {
        let roles: Vec<String> = rules.roles().into_iter().map(|r| format!("@{r}")).collect();
        return Err(ProjectError::RolesNotSupported(roles.join(", ")));
    }

    // 1. Classify files. Already-sealed entries (from a public clone) are
    //    opaque and public-safe; a surrounding private seal may absorb them.
    let mut public_files = Vec::new();
    let mut private_files = Vec::new();
    let mut negated = Vec::new();
    let mut readers_of: HashMap<RepoPath, BTreeSet<String>> = HashMap::new();
    for (path, leaf) in walk(store, root, &RepoPath::root())? {
        if leaf.kind() == EntryKind::Sealed {
            public_files.push((path, leaf));
            continue;
        }
        match rules.classify(&path) {
            Verdict::Public { rule } => {
                // A built-in `!` (`.env.example` and friends) is the floor's
                // own exception, not a user override. A `!` in the file is
                // reported so publish can ask the first time.
                if path.as_str() != RULES_FILE {
                    if let Some(rule) = &rule {
                        if rule.source == RuleSource::File {
                            negated.push(path.clone());
                        }
                    }
                }
                public_files.push((path, leaf));
            }
            Verdict::Private { readers, .. } => {
                if path.as_str() == RULES_FILE {
                    return Err(ProjectError::RulesFileIsPrivate);
                }
                readers_of.insert(path.clone(), readers);
                private_files.push((path, leaf));
            }
        }
    }

    // 2. Aggregate per directory: Some(readers) if every file below is
    //    private to exactly those readers, None if mixed or public.
    let mut dirs: HashMap<RepoPath, Option<BTreeSet<String>>> = HashMap::new();
    let mut fold = |path: &RepoPath, class: Option<&BTreeSet<String>>| {
        let mut cur = path.parent();
        while let Some(dir) = cur.filter(|d| !d.is_root()) {
            let next = match (dirs.get(&dir), class) {
                (None, c) => c.cloned(),
                (Some(Some(have)), Some(c)) if have == c => Some(have.clone()),
                _ => None,
            };
            dirs.insert(dir.clone(), next);
            cur = dir.parent();
        }
    };
    for (path, leaf) in &public_files {
        if leaf.kind() != EntryKind::Sealed {
            fold(path, None);
        }
    }
    for (path, _) in &private_files {
        fold(path, readers_of.get(path));
    }

    // The sealed root of a private file is its highest uniformly private
    // ancestor directory, or the file itself.
    let mut roots: BTreeMap<RepoPath, BTreeSet<String>> = BTreeMap::new();
    for (path, _) in &private_files {
        let readers = &readers_of[path];
        let mut top = path.clone();
        let mut cur = path.parent();
        while let Some(dir) = cur.filter(|d| !d.is_root()) {
            if dirs.get(&dir) == Some(&Some(readers.clone())) {
                top = dir.clone();
            }
            cur = dir.parent();
        }
        roots.insert(top, readers.clone());
    }

    // 3. Build the public tree with one batch of edits.
    let mut sealed = Vec::with_capacity(roots.len());
    let mut edits = BTreeMap::new();
    for (path, readers) in roots {
        let leaf = lookup(store, root, &path)?
            .ok_or_else(|| tig_core::Error::Invalid(format!("sealed root {path} vanished")))?;
        let sid = key.seal(&path, leaf.kind(), &leaf.id());
        edits.insert(path.clone(), Some(Leaf::sealed(sid)));
        sealed.push(SealedRoot {
            path,
            leaf,
            readers,
        });
    }
    let public_tree = apply_edits(store, root, &edits)?;
    // Foreign seals absorbed into a private folder are no longer public leaves.
    public_files.retain(|(path, _)| !tig_core::path::has_ancestor(&edits, path));
    Ok(Projection {
        public_tree,
        sealed,
        public_files,
        private_files,
        negated,
    })
}

/// The public twin of an internal revision: same identity and metadata,
/// public tree and parents, no predecessors (they would expose rewrites
/// and internal IDs).
pub fn public_revision(
    rev: &Revision,
    public_tree: ObjectId,
    public_parents: Vec<ObjectId>,
) -> Revision {
    Revision {
        tree: public_tree,
        parents: public_parents,
        change_id: rev.change_id,
        predecessors: Vec::new(),
        author: rev.author.clone(),
        committer: rev.committer.clone(),
        description: rev.description.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tig_core::store::empty_tree_id;
    use tig_core::MemoryStore;

    fn group() -> crate::keys::GroupEpoch {
        crate::keys::GroupEpoch {
            remote: [0; 16],
            group: PRIVATE_GROUP.into(),
            epoch: 1,
        }
    }

    fn p(s: &str) -> RepoPath {
        RepoPath::new(s).unwrap()
    }

    fn tree(store: &MemoryStore, files: &[(&str, &[u8])]) -> ObjectId {
        let edits = files
            .iter()
            .map(|(path, data)| (p(path), Some(Leaf::file(store.put_blob(data).unwrap()))))
            .collect();
        apply_edits(store, &empty_tree_id(), &edits).unwrap()
    }

    fn sealed_paths(proj: &Projection) -> Vec<&str> {
        proj.sealed.iter().map(|s| s.path.as_str()).collect()
    }

    #[test]
    fn private_folder_becomes_one_sealed_entry() {
        let s = MemoryStore::new();
        let root = tree(
            &s,
            &[
                (".private", b"secrets/\n.env\n"),
                ("secrets/a.key", b"A"),
                ("secrets/deep/b.key", b"B"),
                (".env", b"TOKEN=1"),
                ("src/main.rs", b"fn main() {}"),
            ],
        );
        let key = EpochKey::generate(group()).unwrap();
        let proj = project_tree(&s, &root, &key).unwrap();
        assert_eq!(sealed_paths(&proj), vec![".env", "secrets"]);
        // Outsiders see the names of the sealed roots and nothing below them.
        let public: Vec<String> = walk(&s, &proj.public_tree, &RepoPath::root())
            .unwrap()
            .into_iter()
            .map(|(p, _)| p.to_string())
            .collect();
        assert_eq!(public, vec![".env", ".private", "secrets", "src/main.rs"]);
        assert!(lookup(&s, &proj.public_tree, &p("secrets/a.key"))
            .unwrap()
            .is_none());
        let env = lookup(&s, &proj.public_tree, &p(".env")).unwrap().unwrap();
        assert_eq!(env.kind(), EntryKind::Sealed);
        assert_ne!(
            env.id(),
            lookup(&s, &root, &p(".env")).unwrap().unwrap().id(),
            "never the plain id"
        );
        // Untouched public subtrees are reused by id.
        assert_eq!(
            lookup(&s, &proj.public_tree, &p("src")).unwrap(),
            lookup(&s, &root, &p("src")).unwrap()
        );
    }

    #[test]
    fn negation_splits_a_folder_and_is_reported() {
        let s = MemoryStore::new();
        let root = tree(
            &s,
            &[
                (".private", b"secrets/**\n!secrets/README.md\n"),
                ("secrets/README.md", b"hi"),
                ("secrets/a.key", b"A"),
            ],
        );
        let proj = project_tree(&s, &root, &EpochKey::generate(group()).unwrap()).unwrap();
        assert_eq!(sealed_paths(&proj), vec!["secrets/a.key"]);
        assert_eq!(proj.negated, vec![p("secrets/README.md")]);
    }

    #[test]
    fn a_public_file_keeps_the_same_tree_when_nothing_is_private() {
        let s = MemoryStore::new();
        let root = tree(&s, &[("a.txt", b"a")]);
        let proj = project_tree(&s, &root, &EpochKey::generate(group()).unwrap()).unwrap();
        assert_eq!(proj.public_tree, root);
        assert!(proj.sealed.is_empty());
    }

    #[test]
    fn built_in_floor_hides_env_unless_the_file_negates_it() {
        let s = MemoryStore::new();
        let key = EpochKey::generate(group()).unwrap();

        let absent = tree(&s, &[(".env", b"TOKEN=1"), ("src/main.rs", b"fn main() {}")]);
        let proj = project_tree(&s, &absent, &key).unwrap();
        assert_eq!(sealed_paths(&proj), vec![".env"]);
        match rules_of(&s, &absent).unwrap().classify(&p(".env")) {
            Verdict::Private { rule, .. } => {
                assert_eq!(rule.source, crate::rules::RuleSource::BuiltIn);
                assert_eq!(rule.text, ".env*");
            }
            other => panic!("{other:?}"),
        }

        let extra = tree(
            &s,
            &[
                (".private", b"secrets/\n"),
                (".env", b"TOKEN=1"),
                ("secrets/a.key", b"A"),
                ("src/main.rs", b"fn main() {}"),
            ],
        );
        let proj = project_tree(&s, &extra, &key).unwrap();
        assert_eq!(sealed_paths(&proj), vec![".env", "secrets"]);
        assert!(proj.negated.is_empty());

        let opened = tree(
            &s,
            &[
                (".private", b"!.env\n"),
                (".env", b"TOKEN=1"),
                (".env.local", b"STILL"),
                ("src/main.rs", b"fn main() {}"),
            ],
        );
        let proj = project_tree(&s, &opened, &key).unwrap();
        assert_eq!(sealed_paths(&proj), vec![".env.local"]);
        assert_eq!(proj.negated, vec![p(".env")]);
        assert_eq!(
            lookup(&s, &proj.public_tree, &p(".env"))
                .unwrap()
                .unwrap()
                .kind(),
            EntryKind::File
        );
    }

    #[test]
    fn refusals() {
        let s = MemoryStore::new();
        let key = EpochKey::generate(group()).unwrap();
        let roles = tree(
            &s,
            &[(".private", b"billing/ @billing\n"), ("billing/x", b"x")],
        );
        assert!(
            matches!(project_tree(&s, &roles, &key), Err(ProjectError::RolesNotSupported(r)) if r == "@billing")
        );
        let self_private = tree(&s, &[(".private", b".priv*\n")]);
        assert!(matches!(
            project_tree(&s, &self_private, &key),
            Err(ProjectError::RulesFileIsPrivate)
        ));
    }

    #[test]
    fn sealed_ids_are_stable_across_publishes_of_unchanged_content() {
        let s = MemoryStore::new();
        let key = EpochKey::generate(group()).unwrap();
        let a = tree(
            &s,
            &[(".private", b".env\n"), (".env", b"T=1"), ("x", b"1")],
        );
        let b = tree(
            &s,
            &[(".private", b".env\n"), (".env", b"T=1"), ("x", b"2")],
        );
        let (pa, pb) = (
            project_tree(&s, &a, &key).unwrap(),
            project_tree(&s, &b, &key).unwrap(),
        );
        let sealed = |t| lookup(&s, t, &p(".env")).unwrap().unwrap();
        assert_eq!(sealed(&pa.public_tree), sealed(&pb.public_tree));
    }
}
