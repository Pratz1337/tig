//! A workspace is `(working revision, overlay)`. Opening one is O(1); reads
//! check the overlay and then the base tree; `snapshot` folds the overlay into
//! new trees (cost proportional to the edited paths). No filesystem involved:
//! this is the API agents use directly. The CLI's on-disk working copy feeds
//! changed files into the same overlay.

use std::collections::BTreeMap;

use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::EntryKind;
use crate::path::{has_ancestor, range_inside, remove_inside, RepoPath};
use crate::repo::Repo;
use crate::store::StoreExt;
use crate::treeops::{apply_edits, lookup, walk, Leaf};

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
        let base_tree = repo.revision(&working)?.tree;
        Ok(Workspace { name: name.to_string(), working, base_tree, overlay: BTreeMap::new() })
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
        let leaf = match self.overlay.get(path) {
            Some(edit) => *edit,
            None => {
                if has_ancestor(&self.overlay, path) {
                    // An ancestor was deleted or replaced by a file.
                    return Ok(None);
                }
                lookup(&**repo.store(), &self.base_tree, path)?
            }
        };
        match leaf {
            Some(found) if found.is_file_like() => Ok(Some(repo.store().get_blob(&found.id())?)),
            _ => Ok(None),
        }
    }

    pub fn write(&mut self, repo: &Repo, path: &RepoPath, data: &[u8]) -> Result<()> {
        self.write_kind(repo, path, data, EntryKind::File)
    }

    pub fn write_kind(&mut self, repo: &Repo, path: &RepoPath, data: &[u8], kind: EntryKind) -> Result<()> {
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
            return Err(Error::Invalid(format!("workspace edits must be files; got {leaf:?} at {path}")));
        }
        // Edits to a path and its ancestor in one overlay would be ambiguous;
        // the newer edit wins.
        remove_inside(&mut self.overlay, &path);
        let mut cur = path.parent();
        while let Some(a) = cur.filter(|a| !a.is_root()) {
            self.overlay.remove(&a);
            cur = a.parent();
        }
        let base = lookup(&**repo.store(), &self.base_tree, &path)?;
        if base == leaf {
            self.overlay.remove(&path);
        } else {
            self.overlay.insert(path, leaf);
        }
        Ok(())
    }

    /// All files under `dir`, with the overlay applied.
    pub fn list(&self, repo: &Repo, dir: &RepoPath) -> Result<Vec<(RepoPath, Leaf)>> {
        // An edit at `dir` or above it replaces the whole directory.
        // (Overlay entries are never trees; see `set`.)
        if self.overlay.contains_key(dir) || has_ancestor(&self.overlay, dir) {
            return Ok(Vec::new());
        }
        let mut files: BTreeMap<RepoPath, Leaf> =
            walk(&**repo.store(), &self.base_tree, dir)?.into_iter().collect();
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
                files.insert(path.clone(), *leaf);
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
            return Err(Error::Invalid("snapshot the workspace before switching revisions".into()));
        }
        self.working = repo.working_revision(&self.name)?;
        self.base_tree = repo.revision(&self.working)?.tree;
        Ok(())
    }
}

