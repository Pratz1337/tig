//! Git adoption at a trust boundary. Git is read through gitoxide, never via
//! hooks, filters or a subprocess. The caller saves ImportState before use.
//! ChangeIds are deterministic within that saved state, keyed so a stripped
//! private Git commit hash cannot become a public guessing oracle.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use tig_core::encode::{Reader, Writer};
use tig_core::object::validate_name;
use tig_core::repo::{root_revision_id, validate_bookmark};
use tig_core::store::{Store, StoreExt};
use tig_core::treeops::MAX_TREE_DEPTH;
use tig_core::{
    ChangeId, EntryKind, Object, ObjectId, RepoPath, Revision, Signature, Tree, TreeEntry,
};
use zeroize::Zeroizing;

use crate::rules::{Rules, Verdict, DEFAULT_PRIVATE};

const MAX_ITEMS: usize = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error("git import: {0}")]
    Invalid(String),
}

fn git_error(error: impl std::fmt::Display) -> ImportError {
    ImportError::Invalid(error.to_string())
}

/// Local import identity and durable leak evidence. Never send this file to
/// a remote. Keep its secret with backups to preserve re-import identities.
pub struct ImportState {
    key: Zeroizing<[u8; 32]>,
    pub strip_private: bool,
    pub revisions: BTreeMap<gix::ObjectId, ObjectId>,
    pub exposed: BTreeSet<RepoPath>,
}

impl ImportState {
    pub fn new(strip_private: bool) -> Result<Self, ImportError> {
        let mut key = Zeroizing::new([0; 32]);
        getrandom::getrandom(&mut *key).map_err(git_error)?;
        Ok(Self {
            key,
            strip_private,
            revisions: BTreeMap::new(),
            exposed: BTreeSet::new(),
        })
    }

    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::new();
        w.u8(1);
        w.u8(u8::from(self.strip_private));
        w.buf.extend_from_slice(&*self.key);
        w.varint(self.revisions.len() as u64);
        for (git, tig) in &self.revisions {
            w.bytes(git.as_slice());
            w.id(tig);
        }
        w.varint(self.exposed.len() as u64);
        for path in &self.exposed {
            w.str(path.as_str());
        }
        Zeroizing::new(w.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ImportError> {
        let mut r = Reader::new(bytes, "git import state");
        if r.u8()? != 1 {
            return Err(git_error("unsupported state version"));
        }
        let strip_private = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(git_error("invalid strip flag")),
        };
        let mut key = Zeroizing::new([0; 32]);
        key.copy_from_slice(r.take(32)?);
        let n = r.count(53)?;
        if n > MAX_ITEMS {
            return Err(git_error("too many imported revisions"));
        }
        let mut revisions = BTreeMap::new();
        for _ in 0..n {
            let raw = r.bytes()?;
            let git = gix::ObjectId::from_hex(hex::encode(raw).as_bytes()).map_err(git_error)?;
            if revisions
                .last_key_value()
                .is_some_and(|(previous, _)| *previous >= git)
            {
                return Err(git_error("import revisions are not canonical"));
            }
            revisions.insert(git, r.id()?);
        }
        let n = r.count(1)?;
        if n > MAX_ITEMS {
            return Err(git_error("too many exposed paths"));
        }
        let mut exposed = BTreeSet::new();
        for _ in 0..n {
            let path = RepoPath::new(r.str()?)?;
            if path.is_root() || exposed.last().is_some_and(|previous| *previous >= path) {
                return Err(git_error("exposed paths are not canonical"));
            }
            exposed.insert(path);
        }
        r.finish()?;
        Ok(Self {
            key,
            strip_private,
            revisions,
            exposed,
        })
    }

    pub fn change_id(&self, git: &gix::ObjectId) -> ChangeId {
        let subkey = Zeroizing::new(blake3::derive_key(
            tig_core::domain::GIT_IMPORT_CHANGE_ID,
            &*self.key,
        ));
        let mut h = blake3::Hasher::new_keyed(&subkey);
        h.update(&[u8::from(self.strip_private), git.as_slice().len() as u8]);
        h.update(git.as_slice());
        let mut id = [0; 16];
        id.copy_from_slice(&h.finalize().as_bytes()[..16]);
        ChangeId(id)
    }
}

pub struct ImportReport {
    pub imported: usize,
    pub reused: usize,
    pub bookmarks: BTreeMap<String, ObjectId>,
    /// Includes commits reachable only from tags or other refs.
    pub heads: Vec<ObjectId>,
    pub head: Option<ObjectId>,
    pub matched: BTreeSet<RepoPath>,
    pub warnings: BTreeSet<String>,
}

/// Import all commits reachable from refs and HEAD. Branches become bookmarks;
/// annotated/lightweight tags retain their reachable commits, not tag objects.
/// On failure state is unchanged; already written objects are unreachable.
pub fn import_git(
    source: &Path,
    store: &dyn Store,
    state: &mut ImportState,
) -> Result<ImportReport, ImportError> {
    let mut git = gix::open(source).map_err(git_error)?;
    if git.is_shallow().map_err(git_error)? {
        return Err(git_error(
            "shallow Git history is incomplete; unshallow it first",
        ));
    }
    git.object_cache_size_if_unset(16 * 1024 * 1024);
    let mut warnings = BTreeSet::new();
    let mut branches = BTreeMap::new();
    let mut tips = BTreeSet::new();
    let references = git.references().map_err(git_error)?;
    for reference in references.all().map_err(git_error)? {
        let mut reference = reference.map_err(git_error)?;
        let name = text(reference.name().as_bstr().as_ref(), "reference name")?;
        let object = reference
            .peel_to_id()
            .map_err(git_error)?
            .object()
            .map_err(git_error)?;
        if object.kind != gix::objs::Kind::Commit {
            warnings.insert(format!("skipping non-commit ref {name:?}"));
            continue;
        }
        tips.insert(object.id);
        if let Some(name) = name.strip_prefix("refs/heads/") {
            branches.insert(name.to_string(), object.id);
        }
    }
    let mut head = git.head().map_err(git_error)?;
    let head = if head.is_unborn() {
        None
    } else {
        Some(head.peel_to_commit().map_err(git_error)?.id)
    };
    tips.extend(head);
    let order = parent_first(&git, &tips)?;
    store.put(&Object::Tree(Tree::empty()))?;
    store.put(&Object::Revision(tig_core::repo::root_revision()))?;
    let mut mapped = state.revisions.clone();
    let mut importer = Trees {
        git: &git,
        store,
        strip: state.strip_private,
        trees: BTreeMap::new(),
        blobs: BTreeMap::new(),
        rules: BTreeMap::new(),
        entries: 0,
        strip_paths: BTreeSet::new(),
    };
    if state.strip_private {
        // Discover the union before writing any blob: a path private in one
        // commit must also disappear from earlier and other-branch revisions.
        let mut seen = BTreeSet::new();
        for id in &order {
            let commit = git.find_commit(*id).map_err(git_error)?;
            let root = commit.decode().map_err(git_error)?.tree();
            let rules = importer.rules_of(root)?;
            importer.scan_private(root, rules, &mut seen)?;
        }
    }
    let mut matched = BTreeSet::new();
    let mut imported = 0;
    let mut reused = 0;
    for id in order {
        let commit = git.find_commit(id).map_err(git_error)?;
        let commit = commit.decode().map_err(git_error)?;
        let root = commit.tree();
        let rule_id = importer.rules_of(root)?;
        let converted = importer.convert(root, rule_id)?;
        matched.extend(converted.private);
        warnings.extend(converted.warnings);
        let mut parents = Vec::new();
        for parent in commit.parents() {
            parents.push(
                *mapped
                    .get(&parent)
                    .ok_or_else(|| git_error("parent was not imported"))?,
            );
        }
        if parents.is_empty() {
            parents.push(root_revision_id());
        }
        let revision = Revision {
            tree: converted.id,
            parents,
            change_id: state.change_id(&id),
            predecessors: Vec::new(),
            author: signature(commit.author().map_err(git_error)?)?,
            committer: signature(commit.committer().map_err(git_error)?)?,
            description: text(commit.message.as_ref(), "commit message")?,
        };
        let obj = Object::Revision(revision);
        let tig_id = obj.id();
        if state.strip_private
            && state
                .revisions
                .get(&id)
                .is_some_and(|previous| *previous != tig_id)
        {
            return Err(git_error("new private rules would rewrite prior stripped history; import into a fresh destination"));
        }
        if mapped.get(&id) == Some(&tig_id) && store.has(&tig_id)? {
            reused += 1;
        } else {
            imported += 1;
        }
        store.put(&obj)?;
        mapped.insert(id, tig_id);
    }
    if mapped.len() > MAX_ITEMS || matched.len() > MAX_ITEMS {
        return Err(git_error("import is too large"));
    }
    let mut bookmarks = BTreeMap::new();
    let mut reserved: BTreeSet<String> = branches.keys().cloned().collect();
    for (name, id) in branches {
        let bookmark = if validate_bookmark(&name).is_ok() {
            name.clone()
        } else {
            let base = format!("git/{}", hex::encode(name.as_bytes()));
            let mut candidate = base.clone();
            let mut suffix = 0;
            while reserved.contains(&candidate) {
                suffix += 1;
                candidate = format!("{base}-{suffix}");
            }
            reserved.insert(candidate.clone());
            warnings.insert(format!(
                "branch {name:?} becomes bookmark {candidate:?} (tig name policy)"
            ));
            candidate
        };
        bookmarks.insert(
            bookmark,
            *mapped
                .get(&id)
                .ok_or_else(|| git_error("branch was not imported"))?,
        );
    }
    let heads = tips
        .iter()
        .map(|id| {
            mapped
                .get(id)
                .copied()
                .ok_or_else(|| git_error("tip was not imported"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let head = head
        .map(|id| {
            mapped
                .get(&id)
                .copied()
                .ok_or_else(|| git_error("HEAD was not imported"))
        })
        .transpose()?;
    let mut exposed = state.exposed.clone();
    if !state.strip_private {
        exposed.extend(matched.iter().cloned());
    }
    if exposed.len() > MAX_ITEMS {
        return Err(git_error("too many exposed paths"));
    }
    state.revisions = mapped;
    state.exposed = exposed;
    Ok(ImportReport {
        imported,
        reused,
        bookmarks,
        heads,
        head,
        matched,
        warnings,
    })
}

fn text(bytes: &[u8], what: &str) -> Result<String, ImportError> {
    std::str::from_utf8(bytes)
        .map(str::to_string)
        .map_err(|_| git_error(format!("{what} is not UTF-8; tig metadata must be UTF-8")))
}

fn signature(sig: gix::actor::SignatureRef<'_>) -> Result<Signature, ImportError> {
    let time = sig.time().map_err(git_error)?;
    Ok(Signature {
        name: text(sig.name.as_ref(), "author name")?,
        email: text(sig.email.as_ref(), "author email")?,
        timestamp_ms: time
            .seconds
            .checked_mul(1000)
            .ok_or_else(|| git_error("timestamp overflow"))?,
        tz_offset_min: time.offset / 60,
    })
}

fn parent_first(
    git: &gix::Repository,
    tips: &BTreeSet<gix::ObjectId>,
) -> Result<Vec<gix::ObjectId>, ImportError> {
    let mut colors = BTreeMap::new();
    let mut stack: Vec<_> = tips.iter().rev().map(|id| (*id, false)).collect();
    let mut order = Vec::new();
    while let Some((id, entered)) = stack.pop() {
        if entered {
            colors.insert(id, 2);
            order.push(id);
            continue;
        }
        match colors.get(&id) {
            Some(2) => continue,
            Some(1) => return Err(git_error("commit cycle")),
            _ => {}
        }
        if colors.len() >= MAX_ITEMS || stack.len() > MAX_ITEMS {
            return Err(git_error("history is too large"));
        }
        colors.insert(id, 1);
        stack.push((id, true));
        let commit = git.find_commit(id).map_err(git_error)?;
        let decoded = commit.decode().map_err(git_error)?;
        for parent in decoded.parents().collect::<Vec<_>>().into_iter().rev() {
            stack.push((parent, false));
        }
    }
    Ok(order)
}

#[derive(Clone)]
struct Converted {
    id: ObjectId,
    private: BTreeSet<RepoPath>,
    warnings: BTreeSet<String>,
}

type TreeKey = (gix::ObjectId, RepoPath, Option<gix::ObjectId>);

struct Trees<'a> {
    git: &'a gix::Repository,
    store: &'a dyn Store,
    strip: bool,
    trees: BTreeMap<TreeKey, Converted>,
    blobs: BTreeMap<gix::ObjectId, ObjectId>,
    rules: BTreeMap<Option<gix::ObjectId>, Rules>,
    entries: usize,
    strip_paths: BTreeSet<RepoPath>,
}

impl Trees<'_> {
    // Skipped entries never reach tig objects, but their Git exposure still
    // needs reporting. Walk raw names here; do not construct disk paths.
    fn scan_skipped(
        &mut self,
        id: gix::ObjectId,
        mode: u16,
        prefix: &RepoPath,
        name: &[u8],
        rules: Option<gix::ObjectId>,
    ) -> Result<BTreeSet<String>, ImportError> {
        let mut path = prefix.as_str().as_bytes().to_vec();
        if !path.is_empty() {
            path.push(b'/');
        }
        path.extend_from_slice(name);
        let mut stack = vec![(id, mode, path, prefix.components().count() + 1)];
        let mut warnings = BTreeSet::new();
        while let Some((id, mode, path, depth)) = stack.pop() {
            if depth > MAX_TREE_DEPTH {
                return Err(git_error("skipped tree is too deep"));
            }
            self.entries += 1;
            if self.entries > 10 * MAX_ITEMS {
                return Err(git_error("too many tree entries"));
            }
            if mode == 0o40000 {
                let tree = self.git.find_tree(id).map_err(git_error)?;
                for entry in tree.iter() {
                    let entry = entry.map_err(git_error)?;
                    let mut child = path.clone();
                    child.push(b'/');
                    child.extend_from_slice(entry.filename().as_ref());
                    stack.push((entry.id().detach(), entry.mode().value(), child, depth + 1));
                    if stack.len() > MAX_ITEMS {
                        return Err(git_error("skipped tree is too large"));
                    }
                }
                continue;
            }
            match std::str::from_utf8(&path) {
                Ok(path) => {
                    let rules = self
                        .rules
                        .get(&rules)
                        .ok_or_else(|| git_error("rules were not loaded"))?;
                    if matches!(rules.classify_text(path), Verdict::Private { .. }) {
                        let reason = if self.strip {
                            "skipped private Git path (not portable)"
                        } else {
                            "already exposed in git history — rotate these secrets"
                        };
                        warnings.insert(format!("{path:?}: {reason}"));
                    }
                }
                Err(_) => {
                    warnings.insert(format!("Git path bytes:{} cannot be classified as UTF-8; skipped, inspect history for exposed secrets", hex::encode(path)));
                }
            }
        }
        Ok(warnings)
    }

    fn scan_private(
        &mut self,
        root: gix::ObjectId,
        rules: Option<gix::ObjectId>,
        seen: &mut BTreeSet<TreeKey>,
    ) -> Result<(), ImportError> {
        let mut stack = vec![(root, RepoPath::root())];
        while let Some((id, prefix)) = stack.pop() {
            if prefix.components().count() >= MAX_TREE_DEPTH {
                return Err(git_error("tree is too deep"));
            }
            if !seen.insert((id, prefix.clone(), rules)) {
                continue;
            }
            if seen.len() > MAX_ITEMS {
                return Err(git_error("strip scan is too large"));
            }
            let tree = self.git.find_tree(id).map_err(git_error)?;
            for entry in tree.iter() {
                let entry = entry.map_err(git_error)?;
                let Ok(name) = std::str::from_utf8(entry.filename().as_ref()) else {
                    continue;
                };
                let Ok(path) = prefix.join(name) else {
                    continue;
                };
                if entry.mode().value() == 0o40000 {
                    stack.push((entry.id().detach(), path));
                } else if self
                    .rules
                    .get(&rules)
                    .ok_or_else(|| git_error("rules were not loaded"))?
                    .is_private(&path)
                {
                    self.strip_paths.insert(path);
                    if self.strip_paths.len() > MAX_ITEMS {
                        return Err(git_error("too many private paths"));
                    }
                }
            }
        }
        Ok(())
    }

    fn rules_of(&mut self, root: gix::ObjectId) -> Result<Option<gix::ObjectId>, ImportError> {
        let tree = self.git.find_tree(root).map_err(git_error)?;
        let mut id = None;
        for entry in tree.iter() {
            let entry = entry.map_err(git_error)?;
            if entry.filename() != ".private" {
                continue;
            }
            if !matches!(entry.mode().value(), 0o100644 | 0o100755) {
                return Err(git_error(".private must be a regular UTF-8 file"));
            }
            id = Some(entry.id().detach());
        }
        if !self.rules.contains_key(&id) {
            let file = match id {
                Some(id) => text(&bounded_blob(self.git, id)?.data, ".private")?,
                None => String::new(),
            };
            self.rules.insert(
                id,
                Rules::parse_layered(DEFAULT_PRIVATE, &file).map_err(git_error)?,
            );
        }
        Ok(id)
    }

    fn convert(
        &mut self,
        root: gix::ObjectId,
        rules: Option<gix::ObjectId>,
    ) -> Result<Converted, ImportError> {
        let root_key = (root, RepoPath::root(), rules);
        let mut stack = vec![(root_key.clone(), false)];
        while let Some((key, entered)) = stack.pop() {
            if self.trees.contains_key(&key) {
                continue;
            }
            if key.1.components().count() >= MAX_TREE_DEPTH {
                return Err(git_error("tree is too deep"));
            }
            let tree = self.git.find_tree(key.0).map_err(git_error)?;
            if !entered {
                stack.push((key.clone(), true));
                for entry in tree.iter() {
                    let entry = entry.map_err(git_error)?;
                    if entry.mode().value() != 0o40000 {
                        continue;
                    }
                    let Ok(name) = std::str::from_utf8(entry.filename().as_ref()) else {
                        continue;
                    };
                    let Ok(path) = key.1.join(name) else {
                        continue;
                    };
                    stack.push(((entry.id().detach(), path, rules), false));
                }
                if stack.len() > MAX_ITEMS {
                    return Err(git_error("tree is too large"));
                }
                continue;
            }
            let mut out = Vec::new();
            let mut private = BTreeSet::new();
            let mut warnings = BTreeSet::new();
            for entry in tree.iter() {
                let entry = entry.map_err(git_error)?;
                self.entries += 1;
                if self.entries > 10 * MAX_ITEMS {
                    return Err(git_error("too many tree entries"));
                }
                let raw = entry.filename().as_ref();
                let name = match std::str::from_utf8(raw) {
                    Ok(name) if validate_name(name).is_ok() => name,
                    Ok(name) => {
                        warnings.insert(format!(
                            "skipping {}/{:?}: not a portable UTF-8 name",
                            key.1, name
                        ));
                        warnings.extend(self.scan_skipped(
                            entry.id().detach(),
                            entry.mode().value(),
                            &key.1,
                            raw,
                            rules,
                        )?);
                        continue;
                    }
                    Err(_) => {
                        warnings.insert(format!(
                            "skipping {}/bytes:{}: name is not UTF-8",
                            key.1,
                            hex::encode(raw)
                        ));
                        warnings.extend(self.scan_skipped(
                            entry.id().detach(),
                            entry.mode().value(),
                            &key.1,
                            raw,
                            rules,
                        )?);
                        continue;
                    }
                };
                let path = key.1.join(name)?;
                let mode = entry.mode().value();
                let git_id = entry.id().detach();
                if mode == 0o40000 {
                    let child = self
                        .trees
                        .get(&(git_id, path, rules))
                        .ok_or_else(|| git_error("tree child was not imported"))?;
                    private.extend(child.private.iter().cloned());
                    warnings.extend(child.warnings.iter().cloned());
                    if !self.strip || child.id != tig_core::store::empty_tree_id() {
                        out.push(TreeEntry::new(name, EntryKind::Tree, child.id)?);
                    }
                    continue;
                }
                let is_private = self
                    .rules
                    .get(&rules)
                    .ok_or_else(|| git_error("rules were not loaded"))?
                    .is_private(&path);
                if is_private {
                    private.insert(path.clone());
                }
                let kind = match mode {
                    0o100644 => EntryKind::File,
                    0o100755 => EntryKind::Executable,
                    0o120000 => EntryKind::Symlink,
                    _ => {
                        warnings.insert(format!("skipping {path}: unsupported Git mode {mode:o} (submodules are not imported)"));
                        continue;
                    }
                };
                if self.strip && self.strip_paths.contains(&path) {
                    continue;
                }
                let id = match self.blobs.get(&git_id) {
                    Some(id) => *id,
                    None => {
                        let blob = bounded_blob(self.git, git_id)?;
                        let id = tig_core::blob::put_bytes(self.store, &blob.data)?;
                        self.blobs.insert(git_id, id);
                        id
                    }
                };
                out.push(TreeEntry::new(name, kind, id)?);
            }
            let id = self.store.put(&Object::Tree(Tree::new(out)?))?;
            self.trees.insert(
                key,
                Converted {
                    id,
                    private,
                    warnings,
                },
            );
        }
        self.trees
            .get(&root_key)
            .cloned()
            .ok_or_else(|| git_error("root tree was not imported"))
    }
}

fn bounded_blob(git: &gix::Repository, id: gix::ObjectId) -> Result<gix::Blob<'_>, ImportError> {
    // gitoxide's packed-object API materializes the decoded blob. Refuse
    // oversized inputs from their header before asking it to allocate.
    if git.find_header(id).map_err(git_error)?.size() > tig_core::blob::MAX_MATERIALIZE {
        return Err(git_error("Git import does not yet stream blobs above 256 MiB"));
    }
    git.find_blob(id).map_err(git_error)
}
