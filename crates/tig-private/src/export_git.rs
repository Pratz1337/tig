//! Export bookmarks to a Git repository. Git is a public channel: it has no
//! sealed entries, so private paths and existing seals are left out of every
//! Git object. Objects are written through gitoxide, which does not run hooks
//! or filters, and the destination worktree is never checked out.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};

use tig_core::encode::{Reader, Writer};
use tig_core::object::hash_object;
use tig_core::repo::root_revision_id;
use tig_core::store::{Store, StoreExt};
use tig_core::treeops::{lookup, MAX_TREE_DEPTH};
use tig_core::{EntryKind, ObjectId, ObjectKind, RepoPath, Revision, Signature};

use crate::project::{
    classify_with_roles, metadata_mention_warning, names_hidden_inside, rules_of, uniform_private_roots,
    ClassifiedTree, ProjectError, RULES_FILE,
};
use crate::rules::Rules;

const MAX_ITEMS: usize = 1_000_000;
const STATE_MAGIC: &[u8; 4] = b"TIGE";
const STATE_VERSION: u8 = 2;

#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error(transparent)]
    Project(#[from] ProjectError),
    #[error("git export: {0}")]
    Invalid(String),
    /// A public file repeats bytes of a non-empty private file in the exported history.
    #[error(
        "these public files contain bytes equal to a private file in the exported history; pass --declassify <path> for each one you really mean to export: {}",
        paths.iter().map(RepoPath::as_str).collect::<Vec<_>>().join(", ")
    )]
    PastedSecret { paths: Vec<RepoPath> },
}

fn export_error(error: impl std::fmt::Display) -> ExportError {
    ExportError::Invalid(error.to_string())
}

/// Which bookmarks to write, and the explicit exceptions to the paste check.
#[derive(Clone, Debug, Default)]
pub struct ExportOptions {
    /// Empty exports every bookmark. Names that are not bookmarks are refused.
    pub bookmarks: BTreeSet<String>,
    /// Public paths allowed to keep bytes that also appear in a private file.
    pub declassify: BTreeSet<RepoPath>,
    /// Replace a Git branch that is not a fast-forward of the last export.
    pub force: bool,
    /// When set, [`ExportReport::warnings`] stays the same; the caller prints
    /// [`ExportReport::omitted_paths`]. The flag is recorded so a library caller
    /// and the CLI share one options struct.
    pub verbose: bool,
}

/// Local map from internal revisions and bookmark names to Git commit ids.
/// One file per destination, under `.tig/git-export/`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportState {
    pub revisions: BTreeMap<ObjectId, gix::ObjectId>,
    /// The Git commit this exporter last stored for each branch.
    pub refs: BTreeMap<String, gix::ObjectId>,
}

impl ExportState {
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Writer::new();
        body.varint(self.revisions.len() as u64);
        for (tig, git) in &self.revisions {
            body.id(tig);
            write_git_id(&mut body, git);
        }
        body.varint(self.refs.len() as u64);
        for (name, git) in &self.refs {
            body.str(name);
            write_git_id(&mut body, git);
        }
        let body = body.finish();
        let mut out = Vec::with_capacity(5 + body.len() + 32);
        out.extend_from_slice(STATE_MAGIC);
        out.push(STATE_VERSION);
        out.extend_from_slice(&body);
        let checksum = state_checksum(&out);
        out.extend_from_slice(&checksum.0);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ExportError> {
        if bytes.len() < 5 + 32 || &bytes[..4] != STATE_MAGIC {
            return Err(export_error("unsupported export state"));
        }
        if !(1..=STATE_VERSION).contains(&bytes[4]) {
            return Err(export_error(format!(
                "unsupported export state version {}",
                bytes[4]
            )));
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 32);
        if state_checksum(payload).0 != checksum {
            return Err(export_error("export state checksum mismatch"));
        }
        let mut r = Reader::new(&payload[5..], "git export state");
        let n = r.count(33).map_err(|err| export_error(err.to_string()))?;
        if n > MAX_ITEMS {
            return Err(export_error("too many exported revisions"));
        }
        let mut revisions = BTreeMap::new();
        for _ in 0..n {
            let tig = r.id().map_err(|err| export_error(err.to_string()))?;
            if revisions
                .last_key_value()
                .is_some_and(|(previous, _)| *previous >= tig)
            {
                return Err(export_error("exported revisions are not canonical"));
            }
            revisions.insert(tig, read_git_id(&mut r)?);
        }
        let n = r.count(22).map_err(|err| export_error(err.to_string()))?;
        if n > MAX_ITEMS {
            return Err(export_error("too many exported refs"));
        }
        let mut refs = BTreeMap::new();
        for _ in 0..n {
            let name = r
                .str()
                .map_err(|err| export_error(err.to_string()))?
                .to_string();
            if name.is_empty()
                || refs
                    .last_key_value()
                    .is_some_and(|(previous, _)| *previous >= name)
            {
                return Err(export_error("exported refs are not canonical"));
            }
            refs.insert(name, read_git_id(&mut r)?);
        }
        r.finish().map_err(|err| export_error(err.to_string()))?;
        if bytes[4] < 2 {
            revisions.clear();
        }
        Ok(ExportState { revisions, refs })
    }
}

fn state_checksum(payload: &[u8]) -> ObjectId {
    let mut bytes = tig_core::domain::GIT_EXPORT_STATE.to_vec();
    bytes.extend_from_slice(payload);
    hash_object(ObjectKind::Blob, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_export_cache_reclassifies_history_and_preserves_ref_protection() {
        let git = gix::ObjectId::from_hex(b"1111111111111111111111111111111111111111").unwrap();
        let state = ExportState {
            revisions: BTreeMap::from([(ObjectId([1; 32]), git)]),
            refs: BTreeMap::from([("main".into(), git)]),
        };
        assert_eq!(ExportState::decode(&state.encode()).unwrap(), state);
        let mut legacy = state.encode();
        legacy.truncate(legacy.len() - 32);
        legacy[4] = 1;
        let checksum = state_checksum(&legacy);
        legacy.extend_from_slice(&checksum.0);
        let migrated = ExportState::decode(&legacy).unwrap();
        assert!(migrated.revisions.is_empty());
        assert_eq!(migrated.refs, state.refs);
    }
}

fn write_git_id(body: &mut Writer, id: &gix::ObjectId) {
    let bytes = id.as_bytes();
    body.u8(bytes.len() as u8);
    body.buf.extend_from_slice(bytes);
}

fn read_git_id(r: &mut Reader<'_>) -> Result<gix::ObjectId, ExportError> {
    let n = r.u8().map_err(|err| export_error(err.to_string()))? as usize;
    if n != 20 && n != 32 {
        return Err(export_error("git id has an unsupported length"));
    }
    let bytes = r.take(n).map_err(|err| export_error(err.to_string()))?;
    gix::ObjectId::try_from(bytes).map_err(|_| export_error("git id has an unsupported length"))
}

/// Hex BLAKE3 of the canonical destination path. The CLI stores the map at
/// `.tig/git-export/<this>`.
pub fn destination_key(path: &Path) -> Result<String, ExportError> {
    let canonical = std::fs::canonicalize(path).map_err(export_error)?;
    let text = canonical
        .to_str()
        .ok_or_else(|| export_error("destination path is not valid UTF-8"))?;
    Ok(blake3::hash(text.as_bytes()).to_hex().to_string())
}

#[derive(Debug)]
pub struct ExportReport {
    pub exported: usize,
    pub reused: usize,
    /// Distinct private files and sealed entries left out of Git.
    pub omitted_private_paths: usize,
    pub omitted_paths: BTreeSet<RepoPath>,
    pub warnings: Vec<String>,
    pub bookmarks: BTreeMap<String, gix::ObjectId>,
}

struct Planned {
    revision: Revision,
    classified: ClassifiedTree,
    rules_blob: Option<ObjectId>,
}

struct TreeWriter<'a> {
    repo: &'a gix::Repository,
    store: &'a dyn Store,
    rules: &'a Rules,
    rules_blob: Option<ObjectId>,
    cache: &'a mut HashMap<(Option<ObjectId>, RepoPath, ObjectId), gix::ObjectId>,
}

/// Write `bookmarks` into `destination`. Creates a repository when `destination`
/// is missing or empty. A path whose final component ends in `.git` is bare;
/// any other new repository is a normal one, and its worktree is left untouched.
/// An existing Git repository is updated. Anything else is refused.
///
/// Refs move only after every object is written. A branch that is not a
/// fast-forward of the commit recorded in `state` is refused unless
/// [`ExportOptions::force`] is set. The same is true when the branch in Git
/// is no longer the commit tig last exported.
pub fn export_git(
    destination: &Path,
    store: &dyn Store,
    bookmarks: &BTreeMap<String, ObjectId>,
    state: &mut ExportState,
    options: &ExportOptions,
) -> Result<ExportReport, ExportError> {
    for name in &options.bookmarks {
        if !bookmarks.contains_key(name) {
            return Err(export_error(format!("no bookmark named {name}")));
        }
    }
    let repo = open_destination(destination)?;
    let mut revisions = state.revisions.clone();
    let mut warnings = Vec::new();
    let mut selected: Vec<(String, ObjectId)> = Vec::new();
    for (name, id) in bookmarks {
        if !options.bookmarks.is_empty() && !options.bookmarks.contains(name) {
            continue;
        }
        if !valid_branch(name) {
            warnings.push(format!(
                "skipping bookmark {name:?}: not a valid Git branch name"
            ));
            continue;
        }
        if *id == root_revision_id() {
            warnings.push(format!(
                "skipping bookmark {name:?}: it points at the root revision, which has no Git commit"
            ));
            continue;
        }
        selected.push((name.clone(), *id));
    }
    let order = parent_first(
        store,
        &selected.iter().map(|(_, id)| *id).collect::<Vec<_>>(),
    )?;
    // A cached commit alone is insufficient: its tree, blobs or parents may
    // have been lost. Rebuild the selected graph if any object is missing.
    if !cached_objects_complete(
        &repo,
        order.iter().filter_map(|id| revisions.get(id)).copied(),
    )? {
        revisions.clear();
    }
    let mut plans: BTreeMap<ObjectId, Planned> = BTreeMap::new();
    let mut omitted_paths = BTreeSet::new();
    let mut compatibility = BTreeSet::new();
    for id in &order {
        let revision = store.get_revision(id)?;
        let classified = classify_with_roles(store, &revision.tree)?;
        compatibility.extend(classified.warnings.iter().cloned());
        for (path, _) in &classified.private_files {
            omitted_paths.insert(path.clone());
        }
        for (path, leaf) in &classified.public_files {
            if leaf.kind() == EntryKind::Sealed {
                omitted_paths.insert(path.clone());
            }
        }
        let rules_blob = rules_blob_id(store, &revision.tree)?;
        plans.insert(
            *id,
            Planned {
                revision,
                classified,
                rules_blob,
            },
        );
    }
    refuse_pastes(store, &plans, options)?;
    warnings.extend(compatibility);
    if let Some(warning) = mention_warning(store, &plans)? {
        warnings.push(warning);
    }

    let mut rules_cache: HashMap<Option<ObjectId>, Rules> = HashMap::new();
    let mut tree_cache: HashMap<(Option<ObjectId>, RepoPath, ObjectId), gix::ObjectId> =
        HashMap::new();
    let mut exported = 0;
    let mut reused = 0;
    for id in &order {
        if let Some(git) = revisions.get(id) {
            if commit_exists(&repo, *git) {
                reused += 1;
                continue;
            }
        }
        let plan = &plans[id];
        let rules = rules_for(
            store,
            &plan.revision.tree,
            plan.rules_blob,
            &mut rules_cache,
        )?;
        let mut writer = TreeWriter {
            repo: &repo,
            store,
            rules,
            rules_blob: plan.rules_blob,
            cache: &mut tree_cache,
        };
        let tree = writer.write(&plan.revision.tree, &RepoPath::root(), 0)?;
        let mut parents = Vec::new();
        for parent in &plan.revision.parents {
            if *parent == root_revision_id() {
                continue;
            }
            parents.push(
                *revisions
                    .get(parent)
                    .ok_or_else(|| export_error("a parent was not exported"))?,
            );
        }
        let git = write_commit(&repo, tree, &parents, &plan.revision)?;
        revisions.insert(*id, git);
        exported += 1;
    }

    let mut ref_state = state.refs.clone();
    let mut written_refs = BTreeMap::new();
    let mut edits = Vec::new();
    for (name, id) in &selected {
        let git = *revisions
            .get(id)
            .ok_or_else(|| export_error(format!("bookmark {name} has no Git commit")))?;
        let full = format!("refs/heads/{name}");
        let found = repo
            .try_find_reference(full.as_str())
            .map_err(export_error)?;
        let reference_name: gix::refs::FullName = full
            .try_into()
            .map_err(|_| export_error(format!("{name:?} is not a valid Git branch name")))?;
        match found {
            Some(found) => {
                let current = found
                    .target()
                    .try_id()
                    .map(|id| id.to_owned())
                    .ok_or_else(|| {
                        export_error(format!(
                            "branch {name} is symbolic; tig export writes direct refs only"
                        ))
                    })?;
                if current == git {
                    written_refs.insert(name.clone(), git);
                    ref_state.insert(name.clone(), git);
                    continue;
                }
                if let Some(previous) = state.refs.get(name) {
                    if *previous != current && !options.force {
                        return Err(export_error(format!(
                            "branch {name} changed in Git after the last export (Git has {current}, tig last exported {previous}); pass --force to overwrite"
                        )));
                    }
                }
                if !options.force && !fast_forward(&repo, current, git)? {
                    return Err(export_error(format!(
                        "branch {name} is not a fast-forward of {current}; pass --force to overwrite"
                    )));
                }
                edits.push(gix::refs::transaction::RefEdit::update(
                    reference_name,
                    git,
                    gix::refs::transaction::PreviousValue::MustExistAndMatch(
                        gix::refs::Target::Object(current),
                    ),
                    "tig export",
                ));
            }
            None => {
                edits.push(gix::refs::transaction::RefEdit::update(
                    reference_name,
                    git,
                    gix::refs::transaction::PreviousValue::MustNotExist,
                    "tig export",
                ));
            }
        }
        written_refs.insert(name.clone(), git);
        ref_state.insert(name.clone(), git);
    }
    // A new repository's HEAD is an unborn symbolic ref, often `master`, so
    // the branch we just wrote would not be the default. Point HEAD at the
    // exported branch without checking out any files.
    let head = repo.head().map_err(export_error)?;
    if head.is_unborn() {
        if let Some(name) = written_refs
            .get("main")
            .map(|_| "main".to_string())
            .or_else(|| written_refs.keys().next().cloned())
        {
            let branch: gix::refs::FullName = format!("refs/heads/{name}")
                .try_into()
                .map_err(|_| export_error(format!("{name:?} is not a valid Git branch name")))?;
            let head_name: gix::refs::FullName = "HEAD"
                .try_into()
                .map_err(|_| export_error("HEAD is not a valid Git ref"))?;
            edits.push(gix::refs::transaction::RefEdit::update(
                head_name,
                gix::refs::Target::Symbolic(branch),
                gix::refs::transaction::PreviousValue::MustExistAndMatch(
                    gix::refs::Target::Symbolic(
                        head.referent_name()
                            .ok_or_else(|| export_error("unborn HEAD has no branch"))?
                            .to_owned(),
                    ),
                ),
                "tig export",
            ));
        }
    }
    if !edits.is_empty() {
        let signature = gix::actor::Signature {
            name: "tig".into(),
            email: "tig@localhost".into(),
            time: gix::date::Time::new(0, 0),
        };
        let mut time_buf = gix::date::parse::TimeBuf::default();
        repo.edit_references_as(edits, Some(signature.to_ref(&mut time_buf)))
            .map_err(export_error)?;
    }
    state.revisions = revisions;
    state.refs = ref_state;
    Ok(ExportReport {
        exported,
        reused,
        omitted_private_paths: omitted_paths.len(),
        omitted_paths,
        warnings,
        bookmarks: written_refs,
    })
}

fn rules_blob_id(store: &dyn Store, root: &ObjectId) -> Result<Option<ObjectId>, ExportError> {
    let path = RepoPath::new(RULES_FILE)?;
    match lookup(store, root, &path)? {
        Some(leaf) if matches!(leaf.kind(), EntryKind::File | EntryKind::Executable) => {
            Ok(Some(leaf.id()))
        }
        Some(_) => Err(tig_core::Error::Invalid(
            ".private is invalid: expected a regular file".into(),
        )
        .into()),
        None => Ok(None),
    }
}

fn rules_for<'a>(
    store: &dyn Store,
    root: &ObjectId,
    key: Option<ObjectId>,
    cache: &'a mut HashMap<Option<ObjectId>, Rules>,
) -> Result<&'a Rules, ExportError> {
    if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(key) {
        entry.insert(rules_of(store, root)?);
    }
    Ok(&cache[&key])
}

fn refuse_pastes(
    store: &dyn Store,
    plans: &BTreeMap<ObjectId, Planned>,
    options: &ExportOptions,
) -> Result<(), ExportError> {
    let empty = hash_object(ObjectKind::Blob, b"");
    let mut private_blobs = BTreeSet::new();
    let mut private_hashes = BTreeSet::new();
    for plan in plans.values() {
        for (_, leaf) in &plan.classified.private_files {
            if leaf.is_file_like() && leaf.id() != empty {
                private_blobs.extend(tig_core::blob::content_ids(store, &leaf.id())?);
                private_hashes.insert(*tig_core::blob::content_hash(store, &leaf.id())?.as_bytes());
            }
        }
    }
    let mut paths = BTreeSet::new();
    for plan in plans.values() {
        for (path, leaf) in &plan.classified.public_files {
            if leaf.kind() == EntryKind::Sealed || !leaf.is_file_like() || leaf.id() == empty {
                continue;
            }
            if !options.declassify.contains(path)
                && (tig_core::blob::content_ids(store, &leaf.id())?.iter().any(|id| private_blobs.contains(id))
                    || private_hashes.contains(tig_core::blob::content_hash(store, &leaf.id())?.as_bytes())) {
                paths.insert(path.clone());
            }
        }
    }
    if paths.is_empty() {
        Ok(())
    } else {
        Err(ExportError::PastedSecret {
            paths: paths.into_iter().collect(),
        })
    }
}

fn mention_warning(
    store: &dyn Store,
    plans: &BTreeMap<ObjectId, Planned>,
) -> Result<Option<String>, ExportError> {
    let mut hidden = BTreeSet::new();
    let mut public_text = String::new();
    for plan in plans.values() {
        let roots = uniform_private_roots(
            &plan.classified.public_files,
            &plan.classified.private_files,
            &plan.classified.readers_of,
        );
        hidden.extend(names_hidden_inside(
            roots.keys(),
            &plan.classified.private_files,
        ));
        public_text.push_str(&plan.revision.description);
        public_text.push('\n');
        for (path, leaf) in &plan.classified.public_files {
            if path.as_str() == RULES_FILE && leaf.is_file_like() {
                public_text.push_str(&String::from_utf8_lossy(&store.get_blob(&leaf.id())?));
                public_text.push('\n');
            }
        }
    }
    Ok(metadata_mention_warning(&hidden, &public_text, "exported"))
}

impl TreeWriter<'_> {
    fn write(
        &mut self,
        tree_id: &ObjectId,
        prefix: &RepoPath,
        depth: usize,
    ) -> Result<gix::ObjectId, ExportError> {
        // Postorder traversal uses a heap stack, like tig-core's tree walks.
        // A valid depth-4096 tree must not exhaust a library caller's stack.
        let mut pending = vec![(*tree_id, prefix.clone(), depth, false)];
        while let Some((tree_id, prefix, depth, entered)) = pending.pop() {
            if depth > MAX_TREE_DEPTH || self.cache.len() >= MAX_ITEMS || pending.len() > MAX_ITEMS
            {
                return Err(export_error(format!(
                    "export tree exceeds depth ({MAX_TREE_DEPTH}) or object limit ({MAX_ITEMS})"
                )));
            }
            let key = (self.rules_blob, prefix.clone(), tree_id);
            if self.cache.contains_key(&key) {
                continue;
            }
            let tree = self.store.get_tree(&tree_id)?;
            if !entered {
                pending.push((tree_id, prefix.clone(), depth, true));
                for entry in tree.entries().iter().rev() {
                    if entry.kind() == EntryKind::Tree {
                        pending.push((entry.id(), prefix.join(entry.name())?, depth + 1, false));
                    }
                }
                continue;
            }
            let mut entries: Vec<gix::objs::tree::Entry> = Vec::new();
            for entry in tree.entries() {
                if entry.kind() == EntryKind::Sealed {
                    continue;
                }
                let path = prefix.join(entry.name())?;
                if entry.kind() == EntryKind::Tree {
                    let child = *self
                        .cache
                        .get(&(self.rules_blob, path.clone(), entry.id()))
                        .ok_or_else(|| export_error("child tree was not exported"))?;
                    if tree_is_empty(self.repo, child)? {
                        continue;
                    }
                    entries.push(gix::objs::tree::Entry {
                        mode: gix::objs::tree::EntryKind::Tree.into(),
                        filename: entry.name().into(),
                        oid: child,
                    });
                    continue;
                }
                match self.rules.classify(&path) {
                    crate::rules::Verdict::Private { .. } => continue,
                    crate::rules::Verdict::Public { .. } => {}
                }
                use gix::objs::Write;
                let mut content = tig_core::blob::ContentReader::new(self.store, &entry.id())?;
                let oid = self.repo.objects.write_stream(gix::objs::Kind::Blob, content.content_len(), &mut content)
                    .map_err(export_error)?;
                let mode = match entry.kind() {
                    EntryKind::File => gix::objs::tree::EntryKind::Blob.into(),
                    EntryKind::Executable => gix::objs::tree::EntryKind::BlobExecutable.into(),
                    EntryKind::Symlink => gix::objs::tree::EntryKind::Link.into(),
                    EntryKind::Tree | EntryKind::Sealed | EntryKind::Conflict => {
                        return Err(export_error(format!("unexpected entry at {path}")))
                    }
                };
                entries.push(gix::objs::tree::Entry {
                    mode,
                    filename: entry.name().into(),
                    oid,
                });
            }
            entries.sort();
            let written = self
                .repo
                .write_object(gix::objs::Tree { entries })
                .map_err(export_error)?
                .detach();
            self.cache.insert(key, written);
        }
        self.cache
            .get(&(self.rules_blob, prefix.clone(), *tree_id))
            .copied()
            .ok_or_else(|| export_error("tree was not exported"))
    }
}

fn tree_is_empty(repo: &gix::Repository, id: gix::ObjectId) -> Result<bool, ExportError> {
    let tree = repo.find_tree(id).map_err(export_error)?;
    Ok(tree.decode().map_err(export_error)?.entries.is_empty())
}

fn write_commit(
    repo: &gix::Repository,
    tree: gix::ObjectId,
    parents: &[gix::ObjectId],
    revision: &Revision,
) -> Result<gix::ObjectId, ExportError> {
    let mut commit = gix::objs::Commit {
        tree,
        parents: Default::default(),
        author: git_signature(&revision.author)?,
        committer: git_signature(&revision.committer)?,
        encoding: None,
        message: revision.description.as_str().into(),
        extra_headers: Vec::new(),
    };
    commit.parents.extend(parents.iter().copied());
    Ok(repo.write_object(&commit).map_err(export_error)?.detach())
}

/// Git commits store whole seconds. Sub-second tig timestamps are truncated
/// toward zero, which is the inverse of import's `seconds * 1000` for the
/// values import records.
fn git_signature(signature: &Signature) -> Result<gix::actor::Signature, ExportError> {
    if signature.name.contains(['\n', '\0', '<'])
        || signature.email.contains(['\n', '\0', '<', '>'])
    {
        return Err(export_error(
            "author or committer identity contains characters Git cannot store unambiguously",
        ));
    }
    let offset = signature
        .tz_offset_min
        .checked_mul(60)
        .ok_or_else(|| export_error("timezone offset overflows Git's seconds"))?;
    Ok(gix::actor::Signature {
        name: signature.name.as_str().into(),
        email: signature.email.as_str().into(),
        time: gix::date::Time::new(signature.timestamp_ms / 1000, offset),
    })
}

fn commit_exists(repo: &gix::Repository, id: gix::ObjectId) -> bool {
    repo.find_commit(id).is_ok()
}

/// Check the union once, sharing work across cached commits and tree DAGs.
/// Missing objects are rebuilt; malformed or corrupt existing objects refuse
/// export rather than claim success over a damaged destination.
fn cached_objects_complete(
    repo: &gix::Repository,
    commits: impl IntoIterator<Item = gix::ObjectId>,
) -> Result<bool, ExportError> {
    use gix::objs::{Kind, ObjectRef};
    let mut pending: Vec<_> = commits.into_iter().map(|id| (id, Kind::Commit)).collect();
    let mut seen = HashMap::new();
    while let Some((id, expected)) = pending.pop() {
        if let Some(kind) = seen.get(&id) {
            if *kind != expected {
                return Err(export_error(format!(
                    "cached Git object {id} has inconsistent types"
                )));
            }
            continue;
        }
        if seen.len() >= MAX_ITEMS || pending.len() > MAX_ITEMS {
            return Err(export_error("cached Git history is too large"));
        }
        let Some(object) = repo.try_find_object(id).map_err(export_error)? else {
            return Ok(false);
        };
        if object.kind != expected
            || gix::objs::compute_hash(repo.object_hash(), object.kind, &object.data)
                .map_err(export_error)?
                != id
        {
            return Err(export_error(format!("cached Git object {id} is corrupt")));
        }
        seen.insert(id, expected);
        match ObjectRef::from_bytes(&object.data, object.kind, repo.object_hash())
            .map_err(export_error)?
        {
            ObjectRef::Commit(commit) => {
                pending.push((commit.tree(), Kind::Tree));
                pending.extend(commit.parents().map(|parent| (parent, Kind::Commit)));
            }
            ObjectRef::Tree(tree) => {
                for entry in tree.entries {
                    let kind = if entry.mode.is_tree() {
                        Kind::Tree
                    } else if entry.mode.is_blob_or_symlink() {
                        Kind::Blob
                    } else {
                        return Err(export_error("cached export contains a Git submodule"));
                    };
                    pending.push((entry.oid.to_owned(), kind));
                }
            }
            ObjectRef::Blob(_) => {}
            ObjectRef::Tag(_) => {
                return Err(export_error("cached export contains an unexpected tag"))
            }
        };
    }
    Ok(true)
}

fn fast_forward(
    repo: &gix::Repository,
    ancestor: gix::ObjectId,
    descendant: gix::ObjectId,
) -> Result<bool, ExportError> {
    if ancestor == descendant {
        return Ok(true);
    }
    let mut seen = BTreeSet::new();
    let mut stack = vec![descendant];
    while let Some(id) = stack.pop() {
        if id == ancestor {
            return Ok(true);
        }
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > MAX_ITEMS {
            return Err(export_error("history is too large"));
        }
        let commit = repo.find_commit(id).map_err(export_error)?;
        let decoded = commit.decode().map_err(export_error)?;
        for parent in decoded.parents() {
            stack.push(parent);
        }
    }
    Ok(false)
}

fn parent_first(store: &dyn Store, tips: &[ObjectId]) -> Result<Vec<ObjectId>, ExportError> {
    let mut colors: BTreeMap<ObjectId, u8> = BTreeMap::new();
    let mut stack: Vec<(ObjectId, bool)> =
        tips.iter().rev().copied().map(|id| (id, false)).collect();
    let mut order = Vec::new();
    while let Some((id, entered)) = stack.pop() {
        if id == root_revision_id() {
            continue;
        }
        if entered {
            colors.insert(id, 2);
            order.push(id);
            continue;
        }
        match colors.get(&id) {
            Some(2) => continue,
            Some(1) => return Err(export_error("revision cycle")),
            _ => {}
        }
        if colors.len() >= MAX_ITEMS || stack.len() > MAX_ITEMS {
            return Err(export_error("history is too large"));
        }
        colors.insert(id, 1);
        stack.push((id, true));
        let revision = store.get_revision(&id)?;
        for parent in revision.parents.iter().rev() {
            stack.push((*parent, false));
        }
    }
    Ok(order)
}

fn valid_branch(name: &str) -> bool {
    let full = format!("refs/heads/{name}");
    gix::validate::reference::branch_name(gix::bstr::BStr::new(full.as_bytes())).is_ok()
}

fn open_destination(path: &Path) -> Result<gix::Repository, ExportError> {
    if path.is_file() {
        return Err(export_error(format!(
            "{} is a file, not a Git repository",
            path.display()
        )));
    }
    if path.exists() {
        if let Ok(repo) = gix::open(path) {
            if repo_owns(&repo, path) {
                return Ok(repo);
            }
        }
        if !is_empty_dir(path)? {
            return Err(export_error(format!(
                "{} is not an empty directory or a Git repository",
                path.display()
            )));
        }
    } else if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent).map_err(export_error)?;
        }
    }
    let opened = if bare_path(path) {
        gix::init_bare(path)
    } else {
        gix::init(path)
    }
    .map_err(export_error)?;
    Ok(opened)
}

fn bare_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.get(name.len().saturating_sub(4)..)
                .is_some_and(|suffix| suffix.eq_ignore_ascii_case(".git"))
        })
}

fn is_empty_dir(path: &Path) -> Result<bool, ExportError> {
    let mut entries = std::fs::read_dir(path).map_err(export_error)?;
    Ok(entries.next().is_none())
}

fn repo_owns(repo: &gix::Repository, path: &Path) -> bool {
    let Ok(want) = std::fs::canonicalize(path) else {
        return false;
    };
    if same_place(repo.git_dir(), &want) {
        return true;
    }
    repo.workdir().is_some_and(|work| same_place(work, &want))
}

fn same_place(left: &Path, canonical: &Path) -> bool {
    std::fs::canonicalize(left).is_ok_and(|path| path == canonical)
}

/// The state path for one destination: `.tig/git-export/<blake3 hex>`.
pub fn state_path(tig_dir: &Path, destination: &Path) -> Result<PathBuf, ExportError> {
    Ok(tig_dir
        .join("git-export")
        .join(destination_key(destination)?))
}
