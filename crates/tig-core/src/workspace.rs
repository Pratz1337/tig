//! A workspace is `(working revision, overlay)`. Opening one is O(1); reads
//! check the overlay and then the base tree; `snapshot` folds the overlay into
//! new trees (cost proportional to the edited paths). No filesystem involved:
//! this is the API agents use directly. The CLI's on-disk working copy feeds
//! changed files into the same overlay.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::EntryKind;
use crate::path::{range_inside, remove_inside, RepoPath};
use crate::repo::Repo;
use crate::store::{empty_tree_id, StoreExt};
use crate::treeops::{apply_edits, lookup, walk, Leaf, MAX_TREE_DEPTH};

pub struct Workspace {
    name: String,
    working: ObjectId,
    base_tree: ObjectId,
    overlay: BTreeMap<RepoPath, Option<Leaf>>,
}

impl Workspace {
    /// Opens an existing workspace of the repo. O(1): nothing is copied.
    pub fn open(repo: &Repo, name: &str) -> Result<Self> {
        let working = repo.working_revision(name)?;
        Self::at_revision(repo, name, working)
    }

    /// Opens an overlay against a recorded revision, even if the workspace
    /// has since moved. Snapshotting still checks that it is current.
    pub fn at_revision(repo: &Repo, name: &str, working: ObjectId) -> Result<Self> {
        let base_tree = repo.revision(&working)?.tree;
        Ok(Workspace {
            name: name.to_string(),
            working,
            base_tree,
            overlay: BTreeMap::new(),
        })
    }

    /// Creates a new workspace with an empty change on top of `parent`.
    pub fn create(repo: &mut Repo, name: &str, parent: ObjectId) -> Result<Self> {
        if repo.view().workspaces.contains_key(name) {
            return Err(Error::Invalid(format!("workspace {name:?} already exists")));
        }
        let mut tx = repo.start(format!("create workspace {name}"));
        let wc = tx.new_change(&[parent], "")?;
        tx.set_working(name, wc)?;
        repo.commit(tx)?;
        Workspace::open(repo, name)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn working_revision(&self) -> ObjectId {
        self.working
    }

    pub fn is_dirty(&self) -> bool {
        !self.overlay.is_empty()
    }

    /// Paths edited since the last snapshot.
    pub fn pending(&self) -> &BTreeMap<RepoPath, Option<Leaf>> {
        &self.overlay
    }

    pub fn read(&self, repo: &Repo, path: &RepoPath) -> Result<Option<Vec<u8>>> {
        let leaf = match self.covering_edit(path) {
            Some((at, edit)) if at == path => edit,
            Some((at, Some(graft))) if graft.kind() == EntryKind::Tree => {
                lookup(&**repo.store(), &graft.id(), &relative_path(path, at)?)?
            }
            Some(_) => None,
            None => lookup(&**repo.store(), &self.base_tree, path)?,
        };
        match leaf {
            Some(found) if found.is_file_like() => Ok(Some(repo.store().get_blob(&found.id())?)),
            _ => Ok(None),
        }
    }

    pub fn write(&mut self, repo: &Repo, path: &RepoPath, data: &[u8]) -> Result<()> {
        self.write_kind(repo, path, data, EntryKind::File)
    }

    pub fn write_kind(
        &mut self,
        repo: &Repo,
        path: &RepoPath,
        data: &[u8],
        kind: EntryKind,
    ) -> Result<()> {
        if path.is_root() || !kind.is_file_like() {
            return Err(Error::Invalid(format!("cannot write a file at {path}")));
        }
        let id = repo.store().put_blob(data)?;
        self.set(repo, path.clone(), Some(Leaf::new(kind, id)?))
    }

    pub fn remove(&mut self, repo: &Repo, path: &RepoPath) -> Result<()> {
        self.set(repo, path.clone(), None)
    }

    /// Records an edit. An edit that restores the base state cancels out, so
    /// save/revert loops leave the overlay empty.
    /// `leaf` must be a file, executable, or symlink (or None to delete the
    /// path, including a whole directory).
    pub fn set(&mut self, repo: &Repo, path: RepoPath, leaf: Option<Leaf>) -> Result<()> {
        if path.is_root() || leaf.is_some_and(|found| !found.is_file_like()) {
            return Err(Error::Invalid(format!(
                "workspace edits must be files; got {leaf:?} at {path}"
            )));
        }
        if path.components().count() > MAX_TREE_DEPTH {
            return Err(Error::Invalid(format!(
                "tree deeper than MAX_TREE_DEPTH ({MAX_TREE_DEPTH})"
            )));
        }
        if let Some(parent) = path.parent() {
            if let Some((at, edit)) = self.covering_edit(&parent) {
                let at = at.clone();
                return self.edit_graft(repo, at, edit, &path, leaf);
            }
            // Find a non-directory base ancestor in one descent, rather than
            // looking up each prefix from the root. A child write replaces it.
            let mut tree = self.base_tree;
            let mut at = RepoPath::root();
            for name in parent.components() {
                at = at.join(name)?;
                let dir = repo.store().get_tree(&tree)?;
                match dir.get(name) {
                    Some(entry) if entry.kind() == EntryKind::Tree => tree = entry.id(),
                    Some(_) => return self.edit_graft(repo, at, None, &path, leaf),
                    None => break,
                }
            }
        }
        let base = lookup(&**repo.store(), &self.base_tree, &path)?;
        self.record(path, leaf, base);
        Ok(())
    }

    /// The overlay has no ancestor/descendant pairs. A tree edit is a graft
    /// that fully replaces the base subtree, including its deleted siblings.
    fn covering_edit(&self, path: &RepoPath) -> Option<(&RepoPath, Option<Leaf>)> {
        let mut cur = Some(path.clone());
        while let Some(at) = cur {
            if let Some((path, edit)) = self.overlay.get_key_value(&at) {
                return Some((path, *edit));
            }
            cur = at.parent();
        }
        None
    }

    fn edit_graft(
        &mut self,
        repo: &Repo,
        at: RepoPath,
        edit: Option<Leaf>,
        path: &RepoPath,
        leaf: Option<Leaf>,
    ) -> Result<()> {
        let tree = match edit {
            Some(graft) if graft.kind() == EntryKind::Tree => graft.id(),
            _ if leaf.is_none() => return Ok(()), // removing below a non-directory is a no-op
            _ => empty_tree_id(),
        };
        let edits = BTreeMap::from([(relative_path(path, &at)?, leaf)]);
        let tree = apply_edits(&**repo.store(), &tree, &edits)?;
        let graft = (tree != empty_tree_id()).then(|| Leaf::tree(tree));
        let base = lookup(&**repo.store(), &self.base_tree, &at)?;
        self.record(at, graft, base);
        Ok(())
    }

    fn record(&mut self, path: RepoPath, leaf: Option<Leaf>, base: Option<Leaf>) {
        remove_inside(&mut self.overlay, &path);
        if base == leaf {
            self.overlay.remove(&path);
        } else {
            self.overlay.insert(path, leaf);
        }
    }

    /// All files under `dir`, with the overlay applied.
    pub fn list(&self, repo: &Repo, dir: &RepoPath) -> Result<Vec<(RepoPath, Leaf)>> {
        if let Some((at, edit)) = self.covering_edit(dir) {
            return match edit {
                Some(graft) if graft.kind() == EntryKind::Tree => {
                    graft_files(repo, at, graft.id(), &relative_path(dir, at)?)
                }
                Some(leaf) if at == dir => Ok(vec![(dir.clone(), leaf)]),
                _ => Ok(Vec::new()),
            };
        }
        let mut files: BTreeMap<RepoPath, Leaf> = walk(&**repo.store(), &self.base_tree, dir)?
            .into_iter()
            .collect();
        // Only overlay edits inside `dir` matter; cost is O(edits · log n).
        for (path, edit) in range_inside(&self.overlay, dir) {
            remove_inside(&mut files, path);
            let mut cur = path.parent();
            while let Some(a) = cur.filter(|a| !a.is_root()) {
                files.remove(&a);
                cur = a.parent();
            }
            files.remove(path);
            if let Some(leaf) = edit {
                if leaf.kind() == EntryKind::Tree {
                    files.extend(graft_files(repo, path, leaf.id(), &RepoPath::root())?);
                } else {
                    files.insert(path.clone(), *leaf);
                }
            }
        }
        Ok(files.into_iter().collect())
    }

    /// Folds the overlay into the working revision (one operation). Returns
    /// true if anything changed. Fails if another process moved this
    /// workspace's working revision since it was opened (stale workspace).
    pub fn snapshot(&mut self, repo: &mut Repo) -> Result<bool> {
        let current = repo.working_revision(&self.name)?;
        if current != self.working {
            return Err(Error::Invalid(format!(
                "workspace {:?} is stale: its working revision moved since it was opened",
                self.name
            )));
        }
        if self.overlay.is_empty() {
            return Ok(false);
        }
        let tree = apply_edits(&**repo.store(), &self.base_tree, &self.overlay)?;
        let mut tx = repo.start(format!("snapshot workspace {}", self.name));
        let new = tx.rewrite(self.working, |r| r.tree = tree)?;
        repo.commit(tx)?;
        self.working = new;
        self.base_tree = tree;
        self.overlay.clear();
        Ok(true)
    }

    /// Re-reads the working revision after an operation moved it (new, edit,
    /// undo). Fails if there are unsnapshotted edits.
    pub fn sync(&mut self, repo: &Repo) -> Result<()> {
        if self.is_dirty() {
            return Err(Error::Invalid(
                "snapshot the workspace before switching revisions".into(),
            ));
        }
        self.working = repo.working_revision(&self.name)?;
        self.base_tree = repo.revision(&self.working)?.tree;
        Ok(())
    }
}

fn relative_path(path: &RepoPath, ancestor: &RepoPath) -> Result<RepoPath> {
    if path == ancestor {
        return Ok(RepoPath::root());
    }
    if ancestor.is_root() {
        return Ok(path.clone());
    }
    RepoPath::new(&path.as_str()[ancestor.as_str().len() + 1..])
}

fn graft_files(
    repo: &Repo,
    at: &RepoPath,
    tree: ObjectId,
    dir: &RepoPath,
) -> Result<Vec<(RepoPath, Leaf)>> {
    walk(&**repo.store(), &tree, dir)?
        .into_iter()
        .map(|(path, leaf)| {
            let path = RepoPath::new(&format!("{}/{}", at.as_str(), path.as_str()))?;
            if path.components().count() > MAX_TREE_DEPTH {
                return Err(Error::Invalid(format!(
                    "tree deeper than MAX_TREE_DEPTH ({MAX_TREE_DEPTH})"
                )));
            }
            Ok((path, leaf))
        })
        .collect()
}
