//! Fetch a directory remote and rebuild local history.
//!
//! The first successful fetch pins the keyring owner's signing key (TOFU).
//! Later fetches refuse a different owner or an older head counter. Refs come
//! only from the signed publish manifest (see `manifest.rs`), which also
//! lists every sealed pack; a member must find each listed pack of an epoch
//! they hold, so a withheld pack is an error, not a quiet sealed gap. Public
//! objects are copied and checked by the remote's store. A member opens the
//! packs for epochs they still hold, then replaces sealed entries whose
//! records they have. An outsider keeps those entries sealed. See DESIGN.md
//! "Publish and fetch".
//!
//! The caller persists [`FetchState`] and turns [`FetchReport::refs`] into
//! `remote/<bookmark>` bookmarks. On `Err`, `state` is unchanged.

use std::collections::{BTreeMap, BTreeSet};

use tig_core::encode::{Reader, Writer};
use tig_core::object::{hash_object, Object, ObjectKind, Revision, Tree};
use tig_core::repo::{root_revision, root_revision_id};
use tig_core::seal::SealedId;
use tig_core::store::{Store, StoreExt};
use tig_core::treeops::{apply_edits, Leaf, MAX_TREE_DEPTH};
use tig_core::{EntryKind, ObjectId, RepoPath};

use crate::keyring::{Keyring, KeyringError, VerifiedKeyring};
use crate::keys::{Identity, KeyError};
use crate::manifest::{pack_id, Manifest, ManifestError};
use crate::pack::{Pack, PackError, SealedRecord};
use crate::project::PRIVATE_GROUP;
use crate::remote::{DirRemote, RemoteError};

const VERSION: u8 = 2;
const MAX_STORED_REVISIONS: usize = 1_000_000;
const MAX_OBJECTS: usize = 1_000_000;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_FETCH_REVISIONS: usize = 100_000;
const MAX_FETCH_BYTES: usize = 512 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FetchError {
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    #[error(transparent)]
    Remote(#[from] RemoteError),
    #[error(transparent)]
    Pack(#[from] PackError),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// The signed manifest lists packs for an epoch this member holds, but
    /// the remote does not serve them (or serves them without their records).
    #[error(
        "the remote is missing {missing} sealed pack(s) of epoch {epoch} that its signed manifest lists; it may be withholding private history"
    )]
    WithheldPack { epoch: u64, missing: usize },
    #[error("remote is too large to fetch")]
    TooLarge,
    #[error("{0}")]
    Invalid(String),
}

/// Per-remote fetch memory. The caller persists [`FetchState::encode`].
///
/// `owner_signing` stays `None` until the first successful fetch. The map is
/// public revision to the internal revision rebuilt on this machine. The root
/// revision is not stored; it always maps to itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchState {
    pub remote_id: [u8; 16],
    pub owner_signing: Option<[u8; 32]>,
    /// Highest keyring counter this state has accepted.
    pub counter: u64,
    pub revisions: BTreeMap<ObjectId, ObjectId>,
    /// Highest publish manifest sequence accepted (rollback floor).
    pub manifest_seq: u64,
}

impl Default for FetchState {
    fn default() -> Self {
        Self::new()
    }
}

impl FetchState {
    /// Empty state for a remote this process has not fetched.
    pub fn new() -> Self {
        FetchState {
            remote_id: [0; 16],
            owner_signing: None,
            counter: 0,
            revisions: BTreeMap::new(),
            manifest_seq: 0,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, FetchError> {
        if self.revisions.len() > MAX_STORED_REVISIONS {
            return Err(FetchError::Invalid("fetch state is too large".into()));
        }
        let mut w = Writer::new();
        w.u8(VERSION);
        w.buf.extend_from_slice(&self.remote_id);
        match self.owner_signing {
            Some(pin) => {
                w.u8(1);
                w.buf.extend_from_slice(&pin);
            }
            None => w.u8(0),
        }
        w.varint(self.counter);
        w.varint(self.revisions.len() as u64);
        for (public, internal) in &self.revisions {
            w.id(public);
            w.id(internal);
        }
        w.varint(self.manifest_seq);
        Ok(w.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FetchError> {
        let mut r = Reader::new(bytes, "fetch state");
        let version = r.u8()?;
        if !(1..=VERSION).contains(&version) {
            return Err(FetchError::Invalid(format!(
                "unsupported fetch state version {version}"
            )));
        }
        let remote_id = read_array(&mut r)?;
        let flag = r.u8()?;
        let owner_signing = match flag {
            0 => None,
            1 => Some(read_array(&mut r)?),
            _ => {
                return Err(FetchError::Invalid(
                    "fetch state pin flag is invalid".into(),
                ))
            }
        };
        let counter = r.varint()?;
        let n = r.count(64)?;
        if n > MAX_STORED_REVISIONS {
            return Err(FetchError::Invalid("too many revisions".into()));
        }
        let mut revisions = BTreeMap::new();
        let mut previous: Option<ObjectId> = None;
        for _ in 0..n {
            let public = r.id()?;
            let internal = r.id()?;
            if previous.is_some_and(|prev| public <= prev) {
                return Err(FetchError::Invalid(
                    "revisions are not in canonical order".into(),
                ));
            }
            previous = Some(public);
            revisions.insert(public, internal);
        }
        // Version 1 predates publish manifests.
        let manifest_seq = if version >= 2 { r.varint()? } else { 0 };
        r.finish()?;
        Ok(FetchState {
            remote_id,
            owner_signing,
            counter,
            revisions,
            manifest_seq,
        })
    }
}

/// What one successful fetch produced.
///
/// `refs` maps each remote bookmark to the internal revision id. `newly_pinned`
/// is the owner's fingerprint when this call set the pin; the caller shows it.
/// `unsealed` and `still_sealed` count sealed entries of revisions rebuilt on
/// this call, not ones already recorded in `state`.
#[derive(Debug)]
pub struct FetchReport {
    pub refs: BTreeMap<String, ObjectId>,
    pub newly_pinned: Option<String>,
    pub unsealed: usize,
    pub still_sealed: usize,
}

struct Budget {
    objects: usize,
    entries: usize,
    bytes: usize,
}

impl Budget {
    fn bytes(&mut self, amount: usize) -> Result<(), FetchError> {
        self.bytes = self
            .bytes
            .checked_add(amount)
            .filter(|used| *used <= MAX_FETCH_BYTES)
            .ok_or(FetchError::TooLarge)?;
        Ok(())
    }
    fn object(&mut self) -> Result<(), FetchError> {
        bump(&mut self.objects, MAX_OBJECTS)
    }

    fn entry(&mut self) -> Result<(), FetchError> {
        bump(&mut self.entries, MAX_ENTRIES)
    }
}

/// Fetches every bookmark on `remote` into `store`.
///
/// An empty `state` pins the keyring owner. A saved pin is checked, and a
/// head older than `state.counter` is refused, before any object is copied.
/// `identity` opens packs for epochs that still grant it; `None`, or an
/// identity with no grant, leaves sealed entries sealed. A pack the signed
/// manifest lists for an epoch the identity holds must be present. Not being
/// a member is not an error.
pub fn fetch(
    remote: &DirRemote,
    store: &dyn Store,
    identity: Option<&Identity>,
    state: &mut FetchState,
) -> Result<FetchReport, FetchError> {
    let keyring = Keyring::decode(&remote.read_keyring()?)?;
    if keyring.remote != remote.remote_id() {
        return Err(FetchError::Invalid(
            "keyring is for a different remote".into(),
        ));
    }
    let (pin, newly_pinned) = resolve_pin(state, remote.remote_id(), &keyring)?;
    let verified = keyring.verify(&pin, state.counter)?;
    let manifest = match remote.read_manifest()? {
        Some(bytes) => Manifest::decode(&bytes)?,
        None => {
            return Err(FetchError::Invalid(
                "the remote has no signed publish manifest; nothing is published yet".into(),
            ))
        }
    };
    manifest.verify(remote.remote_id(), &keyring, state.manifest_seq)?;

    let refs = manifest.refs.clone();
    let tips: Vec<ObjectId> = refs.values().copied().collect();
    let mut budget = Budget {
        objects: 0,
        entries: 0,
        bytes: 0,
    };
    let order = copy_history(remote.public_store(), store, &tips, &mut budget)?;
    let records = open_member_packs(
        remote,
        store,
        &keyring,
        &verified,
        &manifest,
        identity,
        &mut budget,
    )?;

    let mut mapped = state.revisions.clone();
    let mut built = BTreeMap::new();
    let mut unsealed = 0usize;
    let mut still_sealed = 0usize;
    for public_id in order {
        let (internal, opened, closed) =
            rebuild_one(store, public_id, &mapped, &records, &mut budget)?;
        if mapped.get(&public_id) == Some(&internal) {
            continue;
        }
        unsealed += opened;
        still_sealed += closed;
        mapped.insert(public_id, internal);
        built.insert(public_id, internal);
    }
    let reported = map_refs(&refs, &mapped)?;

    state.remote_id = remote.remote_id();
    state.owner_signing = Some(pin);
    state.counter = verified.counter();
    state.manifest_seq = manifest.sequence;
    state.revisions.extend(built);
    Ok(FetchReport {
        refs: reported,
        newly_pinned,
        unsealed,
        still_sealed,
    })
}

fn resolve_pin(
    state: &FetchState,
    remote_id: [u8; 16],
    keyring: &Keyring,
) -> Result<([u8; 32], Option<String>), FetchError> {
    match state.owner_signing {
        Some(pin) => {
            if state.remote_id != remote_id {
                return Err(FetchError::Invalid(
                    "fetch state is for a different remote".into(),
                ));
            }
            Ok((pin, None))
        }
        None => {
            if state.counter != 0 || !state.revisions.is_empty() {
                return Err(FetchError::Invalid(
                    "fetch state is missing its owner pin".into(),
                ));
            }
            Ok((keyring.owner.signing, Some(keyring.owner.fingerprint())))
        }
    }
}

fn member_epochs(keyring: &Keyring, identity: &Identity) -> BTreeSet<u64> {
    let me = identity.public();
    keyring
        .grants
        .iter()
        .filter(|grant| {
            grant.context.remote == keyring.remote
                && grant.context.group == PRIVATE_GROUP
                && grant.recipient == me
        })
        .map(|grant| grant.context.epoch)
        .collect()
}

fn open_member_packs(
    remote: &DirRemote,
    store: &dyn Store,
    keyring: &Keyring,
    verified: &VerifiedKeyring,
    manifest: &Manifest,
    identity: Option<&Identity>,
    budget: &mut Budget,
) -> Result<BTreeMap<SealedId, SealedRecord>, FetchError> {
    let Some(identity) = identity else {
        return Ok(BTreeMap::new());
    };
    let mut records = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for epoch in member_epochs(keyring, identity) {
        let key = match verified.key_for(PRIVATE_GROUP, epoch, identity) {
            Ok(key) => key,
            Err(KeyringError::NotMember) => continue,
            Err(error) => return Err(error.into()),
        };
        // Packs the manifest lists for this epoch, and the sealed records
        // each must carry. Unlisted packs are still read.
        let mut expected: BTreeMap<[u8; 32], &BTreeSet<SealedId>> = manifest
            .packs
            .iter()
            .filter(|(_, entry)| entry.group == PRIVATE_GROUP && entry.epoch == epoch)
            .map(|(id, entry)| (*id, &entry.sealed))
            .collect();
        for bytes in remote.list_packs(PRIVATE_GROUP, epoch)? {
            budget.bytes(bytes.len())?;
            let opened = Pack::open(&bytes, &key)?;
            if let Some(listed) = expected.remove(&pack_id(&bytes)) {
                let carried: BTreeSet<SealedId> =
                    opened.sealed.iter().map(|record| record.sealed_id).collect();
                if !listed.is_subset(&carried) {
                    return Err(FetchError::WithheldPack { epoch, missing: 1 });
                }
            }
            for (kind, id, body) in opened.objects {
                budget.bytes(body.len())?;
                if !matches!(kind, ObjectKind::Blob | ObjectKind::Tree) {
                    return Err(FetchError::Invalid(
                        "pack contains an object that is not a blob or a tree".into(),
                    ));
                }
                if hash_object(kind, &body) != id {
                    return Err(FetchError::Invalid(
                        "pack object does not match its id".into(),
                    ));
                }
                if !seen.insert(id) {
                    continue;
                }
                budget.object()?;
                if !store.has(&id)? {
                    store.put_raw(&id, kind, &body)?;
                }
            }
            for record in opened.sealed {
                remember(budget, &mut records, record)?;
            }
        }
        if !expected.is_empty() {
            return Err(FetchError::WithheldPack { epoch, missing: expected.len() });
        }
    }
    Ok(records)
}

fn remember(
    budget: &mut Budget,
    records: &mut BTreeMap<SealedId, SealedRecord>,
    record: SealedRecord,
) -> Result<(), FetchError> {
    match records.get(&record.sealed_id) {
        Some(existing) if existing == &record => Ok(()),
        Some(_) => Err(FetchError::Invalid(
            "packs disagree about a sealed record".into(),
        )),
        None => {
            budget.entry()?;
            records.insert(record.sealed_id, record);
            Ok(())
        }
    }
}

/// Parents first, root excluded. Copies each revision and its public tree.
fn copy_history(
    remote: &dyn Store,
    local: &dyn Store,
    tips: &[ObjectId],
    budget: &mut Budget,
) -> Result<Vec<ObjectId>, FetchError> {
    const VISITING: u8 = 1;
    const DONE: u8 = 2;
    let mut colors: BTreeMap<ObjectId, u8> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut stack: Vec<(ObjectId, bool)> = tips.iter().rev().map(|id| (*id, false)).collect();
    let mut order = Vec::new();
    while let Some((id, entered)) = stack.pop() {
        if id == root_revision_id() {
            ensure_root(remote, local, budget, &mut seen)?;
            continue;
        }
        if entered {
            colors.insert(id, DONE);
            order.push(id);
            if order.len() > MAX_FETCH_REVISIONS {
                return Err(FetchError::TooLarge);
            }
            continue;
        }
        match colors.get(&id).copied() {
            Some(DONE) => continue,
            Some(VISITING) => {
                return Err(FetchError::Invalid("revision parents form a cycle".into()))
            }
            _ => {}
        }
        colors.insert(id, VISITING);
        stack.push((id, true));
        let revision = copy_revision(remote, local, id, budget, &mut seen)?;
        if revision.parents.len() > MAX_FETCH_REVISIONS {
            return Err(FetchError::TooLarge);
        }
        for parent in revision.parents.iter().rev() {
            match colors.get(parent).copied() {
                Some(DONE) => {}
                Some(VISITING) => {
                    return Err(FetchError::Invalid("revision parents form a cycle".into()))
                }
                _ => stack.push((*parent, false)),
            }
        }
    }
    Ok(order)
}

fn ensure_root(
    remote: &dyn Store,
    local: &dyn Store,
    budget: &mut Budget,
    seen: &mut BTreeSet<ObjectId>,
) -> Result<(), FetchError> {
    let id = root_revision_id();
    if seen.contains(&id) {
        return Ok(());
    }
    if remote.has(&id)? {
        let _ = copy_revision(remote, local, id, budget, seen)?;
        return Ok(());
    }
    seen.insert(id);
    budget.object()?;
    let empty = Object::Tree(Tree::empty());
    let empty_id = empty.id();
    if seen.insert(empty_id) {
        budget.object()?;
    }
    local.put(&empty)?;
    local.put(&Object::Revision(root_revision()))?;
    Ok(())
}

fn copy_revision(
    remote: &dyn Store,
    local: &dyn Store,
    id: ObjectId,
    budget: &mut Budget,
    seen: &mut BTreeSet<ObjectId>,
) -> Result<Revision, FetchError> {
    if !seen.insert(id) {
        let body = local.get_raw(&id)?.ok_or(tig_core::Error::NotFound(id))?.1;
        return Ok(Revision::decode(&body)?);
    }
    budget.object()?;
    let (kind, body) = must_get(remote, &id)?;
    budget.bytes(body.len())?;
    if kind != ObjectKind::Revision {
        return Err(FetchError::Invalid(format!(
            "revision {id} is not a revision"
        )));
    }
    if !local.has(&id)? {
        local.put_raw(&id, kind, &body)?;
    }
    let revision = Revision::decode(&body)?;
    copy_tree(remote, local, revision.tree, budget, seen)?;
    Ok(revision)
}

fn copy_tree(
    remote: &dyn Store,
    local: &dyn Store,
    root: ObjectId,
    budget: &mut Budget,
    seen: &mut BTreeSet<ObjectId>,
) -> Result<(), FetchError> {
    let mut stack = vec![(root, 0usize)];
    while let Some((id, depth)) = stack.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        if !seen.insert(id) {
            continue;
        }
        budget.object()?;
        let (kind, body) = must_get(remote, &id)?;
        budget.bytes(body.len())?;
        if kind != ObjectKind::Tree {
            return Err(FetchError::Invalid(format!("object {id} is not a tree")));
        }
        if !local.has(&id)? {
            local.put_raw(&id, kind, &body)?;
        }
        let tree = Tree::decode(&body)?;
        if !tree.entries().is_empty() && depth + 1 > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        for entry in tree.entries() {
            budget.entry()?;
            match entry.kind() {
                EntryKind::Tree => stack.push((entry.id(), depth + 1)),
                EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                    copy_blob(remote, local, entry.id(), budget, seen)?;
                }
                EntryKind::Sealed => {}
            }
        }
    }
    Ok(())
}

fn copy_blob(
    remote: &dyn Store,
    local: &dyn Store,
    id: ObjectId,
    budget: &mut Budget,
    seen: &mut BTreeSet<ObjectId>,
) -> Result<(), FetchError> {
    if !seen.insert(id) {
        return Ok(());
    }
    budget.object()?;
    let (kind, body) = must_get(remote, &id)?;
    budget.bytes(body.len())?;
    if kind != ObjectKind::Blob {
        return Err(FetchError::Invalid(format!("object {id} is not a blob")));
    }
    if !local.has(&id)? {
        local.put_raw(&id, kind, &body)?;
    }
    Ok(())
}

fn rebuild_one(
    store: &dyn Store,
    public_id: ObjectId,
    mapped: &BTreeMap<ObjectId, ObjectId>,
    records: &BTreeMap<SealedId, SealedRecord>,
    budget: &mut Budget,
) -> Result<(ObjectId, usize, usize), FetchError> {
    let public = store.get_revision(&public_id)?;
    // Keep content already opened locally, while a later grant can open
    // seals left by an earlier fetch. Parent mappings may change too.
    let previous_tree = match mapped.get(&public_id) {
        Some(id) => store.get_revision(id)?.tree,
        None => public.tree,
    };
    let (tree, unsealed, still_sealed) = unseal(store, previous_tree, records, budget)?;
    let mut parents = Vec::with_capacity(public.parents.len());
    for parent in &public.parents {
        parents.push(map_parent(*parent, mapped)?);
    }
    let internal = Revision {
        tree,
        parents,
        change_id: public.change_id,
        predecessors: Vec::new(),
        author: public.author.clone(),
        committer: public.committer.clone(),
        description: public.description.clone(),
    };
    let id = store.put(&Object::Revision(internal))?;
    Ok((id, unsealed, still_sealed))
}

fn unseal(
    store: &dyn Store,
    public_tree: ObjectId,
    records: &BTreeMap<SealedId, SealedRecord>,
    budget: &mut Budget,
) -> Result<(ObjectId, usize, usize), FetchError> {
    let mut edits = BTreeMap::new();
    let mut unsealed = 0usize;
    let mut still_sealed = 0usize;
    for (path, sid) in sealed_leaves(store, public_tree, budget)? {
        let Some(record) = records.get(&sid) else {
            still_sealed += 1;
            continue;
        };
        if record.path != path {
            return Err(FetchError::Invalid(format!(
                "sealed record path {} does not match tree path {path}",
                record.path
            )));
        }
        edits.insert(path, Some(checked_leaf(store, record)?));
        unsealed += 1;
    }
    let tree = if edits.is_empty() {
        public_tree
    } else {
        apply_edits(store, &public_tree, &edits)?
    };
    if tree != public_tree {
        // Decrypted subtrees are subject to the same expansion/depth limits.
        sealed_leaves(store, tree, budget)?;
    }
    Ok((tree, unsealed, still_sealed))
}

fn sealed_leaves(
    store: &dyn Store,
    root: ObjectId,
    budget: &mut Budget,
) -> Result<Vec<(RepoPath, SealedId)>, FetchError> {
    let mut out = Vec::new();
    let mut stack = vec![(root, RepoPath::root(), 0usize)];
    while let Some((id, prefix, depth)) = stack.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        let tree = store.get_tree(&id)?;
        if !tree.entries().is_empty() && depth + 1 > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        let mut nested = Vec::new();
        for entry in tree.entries() {
            budget.entry()?;
            let path = prefix.join(entry.name())?;
            match entry.kind() {
                EntryKind::Tree => nested.push((entry.id(), path, depth + 1)),
                EntryKind::Sealed => {
                    let sid = entry.sealed_id().ok_or_else(|| {
                        FetchError::Invalid("sealed entry is missing its id".into())
                    })?;
                    out.push((path, sid));
                }
                EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                    if store.kind(&entry.id())? != Some(ObjectKind::Blob) {
                        return Err(FetchError::Invalid(format!(
                            "file target {} is missing or is not a blob",
                            entry.id()
                        )));
                    }
                }
            }
        }
        for item in nested.into_iter().rev() {
            stack.push(item);
        }
    }
    Ok(out)
}

fn checked_leaf(store: &dyn Store, record: &SealedRecord) -> Result<Leaf, FetchError> {
    let file_or_tree = record.kind.is_file_like() || record.kind == EntryKind::Tree;
    if !file_or_tree {
        return Err(FetchError::Invalid(
            "sealed record is not a file or a tree".into(),
        ));
    }
    let expected = if record.kind == EntryKind::Tree {
        ObjectKind::Tree
    } else {
        ObjectKind::Blob
    };
    match store.kind(&record.target)? {
        Some(kind) if kind == expected => {}
        Some(kind) => {
            return Err(FetchError::Invalid(format!(
                "sealed target {} is a {}, expected a {}",
                record.target,
                kind.name(),
                expected.name()
            )))
        }
        None => {
            return Err(FetchError::Invalid(format!(
                "sealed target {} is missing",
                record.target
            )))
        }
    }
    Ok(Leaf::new(record.kind, record.target)?)
}

fn map_parent(id: ObjectId, mapped: &BTreeMap<ObjectId, ObjectId>) -> Result<ObjectId, FetchError> {
    if id == root_revision_id() {
        return Ok(id);
    }
    mapped
        .get(&id)
        .copied()
        .ok_or_else(|| FetchError::Invalid(format!("parent {id} was not fetched")))
}

fn map_refs(
    refs: &BTreeMap<String, ObjectId>,
    mapped: &BTreeMap<ObjectId, ObjectId>,
) -> Result<BTreeMap<String, ObjectId>, FetchError> {
    let mut out = BTreeMap::new();
    for (name, public_id) in refs {
        let internal = if *public_id == root_revision_id() {
            root_revision_id()
        } else {
            mapped.get(public_id).copied().ok_or_else(|| {
                FetchError::Invalid(format!("ref {name} points at an unknown revision"))
            })?
        };
        out.insert(name.clone(), internal);
    }
    Ok(out)
}

fn must_get(store: &dyn Store, id: &ObjectId) -> Result<(ObjectKind, Vec<u8>), FetchError> {
    match store.get_raw(id)? {
        Some(found) => Ok(found),
        None => Err(tig_core::Error::NotFound(*id).into()),
    }
}

fn bump(used: &mut usize, cap: usize) -> Result<(), FetchError> {
    if *used >= cap {
        return Err(FetchError::TooLarge);
    }
    *used += 1;
    Ok(())
}

fn too_deep() -> FetchError {
    FetchError::Invalid(format!(
        "tree deeper than MAX_TREE_DEPTH ({MAX_TREE_DEPTH})"
    ))
}

fn read_array<const N: usize>(r: &mut Reader<'_>) -> Result<[u8; N], FetchError> {
    let mut out = [0u8; N];
    out.copy_from_slice(r.take(N)?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_a_private_tree_rejects_missing_file_targets() {
        use tig_core::{MemoryStore, TreeEntry};
        let store = MemoryStore::new();
        let missing = hash_object(ObjectKind::Blob, b"secret");
        let tree = store
            .put(&Object::Tree(
                Tree::new(vec![
                    TreeEntry::new("file", EntryKind::File, missing).unwrap()
                ])
                .unwrap(),
            ))
            .unwrap();
        let sid = SealedId::from_stored([7; 32]);
        let public = store
            .put(&Object::Tree(
                Tree::new(vec![TreeEntry::sealed("secrets", sid).unwrap()]).unwrap(),
            ))
            .unwrap();
        let records = BTreeMap::from([(
            sid,
            SealedRecord {
                sealed_id: sid,
                path: RepoPath::new("secrets").unwrap(),
                kind: EntryKind::Tree,
                target: tree,
            },
        )]);
        let mut budget = Budget {
            objects: 0,
            entries: 0,
            bytes: 0,
        };
        assert!(matches!(unseal(&store, public, &records, &mut budget),
            Err(FetchError::Invalid(ref reason)) if reason.contains("file target")));
        store.put_blob(b"secret").unwrap();
        assert!(unseal(&store, public, &records, &mut budget).is_ok());
    }

    #[test]
    fn shared_subtrees_keep_each_path_and_cannot_bypass_expansion_limit() {
        use tig_core::{MemoryStore, TreeEntry};
        let store = MemoryStore::new();
        let sid = SealedId::from_stored([7; 32]);
        let child = store
            .put(&Object::Tree(
                Tree::new(vec![TreeEntry::sealed("secret", sid).unwrap()]).unwrap(),
            ))
            .unwrap();
        let root = store
            .put(&Object::Tree(
                Tree::new(vec![
                    TreeEntry::new("a", EntryKind::Tree, child).unwrap(),
                    TreeEntry::new("b", EntryKind::Tree, child).unwrap(),
                ])
                .unwrap(),
            ))
            .unwrap();
        let mut budget = Budget {
            objects: 0,
            entries: 0,
            bytes: 0,
        };
        let paths = sealed_leaves(&store, root, &mut budget).unwrap();
        assert_eq!(
            paths,
            vec![
                (RepoPath::new("a/secret").unwrap(), sid),
                (RepoPath::new("b/secret").unwrap(), sid),
            ]
        );

        // Only twenty unique trees, but over a million expanded paths.
        let mut tree = store.put(&Object::Tree(Tree::empty())).unwrap();
        for _ in 0..20 {
            tree = store
                .put(&Object::Tree(
                    Tree::new(vec![
                        TreeEntry::new("a", EntryKind::Tree, tree).unwrap(),
                        TreeEntry::new("b", EntryKind::Tree, tree).unwrap(),
                    ])
                    .unwrap(),
                ))
                .unwrap();
        }
        assert!(matches!(
            sealed_leaves(&store, tree, &mut budget),
            Err(FetchError::TooLarge)
        ));
    }

    #[test]
    fn state_roundtrip_rejects_unsorted_and_trailing_bytes() {
        let mut state = FetchState::new();
        state.remote_id = [1; 16];
        state.owner_signing = Some([2; 32]);
        state.counter = 4;
        state.revisions.insert(ObjectId([3; 32]), ObjectId([7; 32]));
        state.revisions.insert(ObjectId([4; 32]), ObjectId([8; 32]));
        state.manifest_seq = 5;
        let bytes = state.encode().unwrap();
        assert_eq!(FetchState::decode(&bytes).unwrap(), state);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(FetchState::decode(&trailing).is_err());

        let mut bad_version = bytes.clone();
        bad_version[0] = 3;
        assert!(matches!(
            FetchState::decode(&bad_version),
            Err(FetchError::Invalid(ref reason)) if reason.contains("version")
        ));

        let mut unsorted = bytes.clone();
        let start = unsorted
            .windows(32)
            .position(|window| window == [3; 32])
            .unwrap();
        let first: Vec<u8> = unsorted[start..start + 64].to_vec();
        let second: Vec<u8> = unsorted[start + 64..start + 128].to_vec();
        unsorted[start..start + 64].copy_from_slice(&second);
        unsorted[start + 64..start + 128].copy_from_slice(&first);
        assert!(matches!(
            FetchState::decode(&unsorted),
            Err(FetchError::Invalid(ref reason)) if reason.contains("canonical")
        ));

        assert_eq!(
            FetchState::decode(&FetchState::new().encode().unwrap()).unwrap(),
            FetchState::new()
        );
    }
}
