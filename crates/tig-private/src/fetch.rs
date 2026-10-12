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

use std::collections::{BTreeMap, BTreeSet, HashMap};

use tig_core::encode::{Reader, Writer};
use tig_core::object::{hash_object, Object, ObjectKind, Revision, Tree};
use tig_core::repo::{rebase_revision, root_revision, root_revision_id, Transaction};
use tig_core::seal::{SealSalt, SealedId};
use tig_core::store::{Store, StoreExt};
use tig_core::treeops::{apply_edits, Leaf, MAX_TREE_DEPTH};
use tig_core::{EntryKind, ObjectId, RepoPath, TreeEntry};

use crate::keyring::{Keyring, KeyringError, VerifiedKeyring};
use crate::keys::{Identity, KeyError};
use crate::manifest::{pack_id, Manifest, ManifestError};
use crate::pack::{Pack, PackError, SealedRecord};
use crate::project::PRIVATE_GROUP;
use crate::publish::PublishState;
use crate::remote::{Remote, RemoteError};

const VERSION: u8 = 2;
const MAX_STORED_REVISIONS: usize = 1_000_000;
const MAX_OBJECTS: usize = 1_000_000;
const MAX_ENTRIES: usize = 1_000_000;
const MAX_FETCH_REVISIONS: usize = 100_000;
const MAX_FETCH_BYTES: usize = 512 * 1024 * 1024;
/// Ids per `get_batch` request.
const BATCH_IDS: usize = 1000;

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
    /// Internal revisions whose access upgrade did not preserve public bytes.
    pub projection_mismatches: Vec<ObjectId>,
}

struct AuthenticatedSeal {
    record: SealedRecord,
    salt: SealSalt,
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
///
/// `published` is the other half of this remote's correspondence. A public
/// revision this machine already published reuses that internal revision unless
/// newly available access requires a successor. An access successor retains the
/// public id, metadata and predecessor relationship; its correspondence wins
/// over an older publish entry on later fetches and publishes.
pub fn fetch(
    remote: &dyn Remote,
    store: &dyn Store,
    identity: Option<&Identity>,
    state: &mut FetchState,
    published: &PublishState,
) -> Result<FetchReport, FetchError> {
    fetch_inner(remote, store, identity, state, published, None)
}

/// Fetch into a local transaction so bookmarks, workspaces and unpublished
/// descendants follow access upgrades. The caller commits and saves state.
pub fn fetch_into(
    remote: &dyn Remote,
    tx: &mut Transaction,
    identity: Option<&Identity>,
    state: &mut FetchState,
    published: &PublishState,
) -> Result<FetchReport, FetchError> {
    let store = tx.store().clone();
    fetch_inner(remote, store.as_ref(), identity, state, published, Some(tx))
}

fn fetch_inner(
    remote: &dyn Remote,
    store: &dyn Store,
    identity: Option<&Identity>,
    state: &mut FetchState,
    published: &PublishState,
    tx: Option<&mut Transaction>,
) -> Result<FetchReport, FetchError> {
    let head = remote.read_head()?;
    let keyring_bytes = head.keyring.ok_or_else(|| {
        FetchError::Invalid("keyring is missing".into())
    })?;
    let keyring = Keyring::decode(&keyring_bytes)?;
    if keyring.remote != remote.remote_id() {
        return Err(FetchError::Invalid(
            "keyring is for a different remote".into(),
        ));
    }
    let (mut pin, mut newly_pinned) = resolve_pin(state, remote.remote_id(), &keyring)?;
    if let Some(published_pin) = published.owner_signing {
        if published.remote_id != remote.remote_id()
            || state.owner_signing.is_some_and(|pin| pin != published_pin)
        {
            return Err(FetchError::Invalid(
                "fetch and publish state disagree about the remote owner".into(),
            ));
        }
        pin = published_pin;
        newly_pinned = None;
    } else if published.counter != 0 || published.manifest_seq != 0 || !published.revisions.is_empty() {
        return Err(FetchError::Invalid(
            "publish state is missing its owner pin".into(),
        ));
    }
    let verified = keyring.verify(&pin, state.counter.max(published.counter))?;
    let manifest = match head.manifest {
        Some(bytes) => Manifest::decode(&bytes)?,
        None => {
            return Err(FetchError::Invalid(
                "the remote has no signed publish manifest; nothing is published yet".into(),
            ))
        }
    };
    manifest.verify(
        remote.remote_id(),
        &keyring,
        state.manifest_seq.max(published.manifest_seq),
    )?;

    let refs = manifest.refs.clone();
    let tips: Vec<ObjectId> = refs.values().copied().collect();
    let mut budget = Budget {
        objects: 0,
        entries: 0,
        bytes: 0,
    };
    let order = copy_history(remote, store, &tips, &mut budget)?;
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
    let ours = local_of_published(published);
    // Fetch's upgraded correspondence takes precedence over an older publish
    // entry. Publish must also reuse this same public twin.
    for (public, internal) in ours {
        mapped.entry(public).or_insert(internal);
    }
    let original_mapped = mapped.clone();
    let mut rewritten = HashMap::new();
    let mut projection_mismatches = Vec::new();
    let mut unsealed = 0usize;
    let mut still_sealed = 0usize;
    for public_id in order.iter().copied() {
        let previous = mapped.get(&public_id).copied();
        if let Some(old) = previous {
            let before = store.get_revision(&old)?;
            let (tree, opened, closed) = unseal(store, before.tree, &records, &mut budget)?;
            let parents: Vec<_> = before
                .parents
                .iter()
                .map(|p| *rewritten.get(p).unwrap_or(p))
                .collect();
            if tree == before.tree && parents == before.parents {
                continue;
            }
            let mut next = if parents == before.parents {
                let mut next = before.clone();
                next.tree = tree;
                next
            } else {
                rebase_revision(store, &before, parents)?
            };
            // A conflicting rebase is a projection mismatch, not malformed
            // remote content. Check it before scanning for unopened seals.
            if !same_public_revision(store, &next, public_id, &mapped, &records, &mut budget)? {
                projection_mismatches.push(old);
                continue;
            }
            // Replay the local delta first, then open any inherited seals.
            next.tree = unseal(store, next.tree, &records, &mut budget)?.0;
            next.predecessors = vec![old];
            if !same_public_revision(store, &next, public_id, &mapped, &records, &mut budget)? {
                projection_mismatches.push(old);
                continue;
            }
            let new = store.put(&Object::Revision(next))?;
            rewritten.insert(old, new);
            mapped.insert(public_id, new);
            unsealed += opened;
            still_sealed += closed;
            continue;
        }
        let (internal, opened, closed) =
            rebuild_one(store, public_id, &mapped, &records, &mut budget)?;
        if mapped.get(&public_id) == Some(&internal) {
            continue;
        }
        unsealed += opened;
        still_sealed += closed;
        mapped.insert(public_id, internal);
    }
    if let Some(tx) = tx.filter(|_| !rewritten.is_empty() && projection_mismatches.is_empty()) {
        let public_of: BTreeMap<_, _> = mapped.iter().map(|(p, i)| (*i, *p)).collect();
        let upgrades = tx.apply_access_upgrades(rewritten, |old, next| {
            // Unmapped local descendants retain ordinary local conflicts.
            // Their inherited access changes already come from core rebasing.
            if let Some(public) = public_of.get(&old) {
                // A locally published descendant may no longer be reachable
                // from a remote bookmark. Its public twin was uploaded, not
                // necessarily stored locally; retrieve it only for this check.
                if !store.has(public)? {
                    copy_history(remote, store, &[*public], &mut budget)
                        .map_err(|error| tig_core::Error::Invalid(error.to_string()))?;
                }
                if !same_public_revision(store, next, *public, &mapped, &records, &mut budget)
                    .map_err(|error| tig_core::Error::Invalid(error.to_string()))?
                {
                    projection_mismatches.push(old);
                    return Ok(false);
                }
                let (tree, opened, closed) = unseal(store, next.tree, &records, &mut budget)
                    .map_err(|error| tig_core::Error::Invalid(error.to_string()))?;
                next.tree = tree;
                if !same_public_revision(store, next, *public, &mapped, &records, &mut budget)
                    .map_err(|error| tig_core::Error::Invalid(error.to_string()))?
                {
                    projection_mismatches.push(old);
                    return Ok(false);
                }
                mapped.insert(*public, Object::Revision(next.clone()).id());
                unsealed += opened;
                still_sealed += closed;
            }
            Ok(true)
        })?;
        if let Some(upgrades) = upgrades {
            for internal in mapped.values_mut() {
                if let Some(new) = upgrades.get(internal) {
                    *internal = *new;
                }
            }
        }
    }
    if !projection_mismatches.is_empty() {
        // Keeping a rejected descendant on an old parent while moving that
        // parent would show two versions of one change. Defer the upgrade
        // batch, but still fetch new history and advance verified remote floors.
        mapped = original_mapped;
        unsealed = 0;
        still_sealed = 0;
        for public_id in order {
            if mapped.contains_key(&public_id) {
                continue;
            }
            let (internal, opened, closed) =
                rebuild_one(store, public_id, &mapped, &records, &mut budget)?;
            mapped.insert(public_id, internal);
            unsealed += opened;
            still_sealed += closed;
        }
    }
    let reported = map_refs(&refs, &mapped)?;

    state.remote_id = remote.remote_id();
    state.owner_signing = Some(pin);
    state.counter = verified.counter();
    state.manifest_seq = manifest.sequence;
    state.revisions = mapped;
    Ok(FetchReport {
        refs: reported,
        newly_pinned,
        unsealed,
        still_sealed,
        projection_mismatches,
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

fn local_of_published(published: &PublishState) -> BTreeMap<ObjectId, ObjectId> {
    published
        .revisions
        .iter()
        .map(|(internal, public)| (*public, *internal))
        .collect()
}

fn open_member_packs(
    remote: &dyn Remote,
    store: &dyn Store,
    keyring: &Keyring,
    verified: &VerifiedKeyring,
    manifest: &Manifest,
    identity: Option<&Identity>,
    budget: &mut Budget,
) -> Result<BTreeMap<SealedId, AuthenticatedSeal>, FetchError> {
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
                let salt = key.seal_salt(&record.path, record.kind, &record.target);
                remember(budget, &mut records, AuthenticatedSeal { record, salt })?;
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
    records: &mut BTreeMap<SealedId, AuthenticatedSeal>,
    seal: AuthenticatedSeal,
) -> Result<(), FetchError> {
    let record = &seal.record;
    match records.get(&record.sealed_id) {
        Some(existing) if existing.record == *record => Ok(()),
        Some(_) => Err(FetchError::Invalid(
            "packs disagree about a sealed record".into(),
        )),
        None => {
            budget.entry()?;
            records.insert(record.sealed_id, seal);
            Ok(())
        }
    }
}

/// Parents first, root excluded. One `get_batch` per revision level and per
/// tree level (plus the blobs at that level).
fn copy_history(
    remote: &dyn Remote,
    local: &dyn Store,
    tips: &[ObjectId],
    budget: &mut Budget,
) -> Result<Vec<ObjectId>, FetchError> {
    let mut parents_of: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    ensure_root(remote, local, budget, &mut seen)?;
    let mut frontier = dedup_ids(tips);
    frontier.retain(|id| *id != root_revision_id());
    let mut levels: Vec<Vec<ObjectId>> = Vec::new();
    let mut visiting = BTreeSet::new();
    while !frontier.is_empty() {
        if levels.len() + frontier.len() > MAX_FETCH_REVISIONS {
            return Err(FetchError::TooLarge);
        }
        let batch: Vec<ObjectId> = frontier
            .iter()
            .copied()
            .filter(|id| !parents_of.contains_key(id) && *id != root_revision_id())
            .collect();
        if batch.iter().any(|id| !visiting.insert(*id)) {
            return Err(FetchError::Invalid("revision parents form a cycle".into()));
        }
        let got = fetch_objects(remote, &batch)?;
        let mut next = Vec::new();
        let mut trees = Vec::new();
        for id in &batch {
            let (kind, body) = got.get(id).ok_or(tig_core::Error::NotFound(*id))?;
            budget.bytes(body.len())?;
            budget.object()?;
            if *kind != ObjectKind::Revision {
                return Err(FetchError::Invalid(format!(
                    "revision {id} is not a revision"
                )));
            }
            if !local.has(id)? {
                local.put_raw(id, *kind, body)?;
            }
            let revision = Revision::decode(body)?;
            if revision.parents.len() > MAX_FETCH_REVISIONS {
                return Err(FetchError::TooLarge);
            }
            trees.push(revision.tree);
            parents_of.insert(*id, revision.parents.clone());
            for parent in &revision.parents {
                if *parent != root_revision_id() && !parents_of.contains_key(parent) {
                    next.push(*parent);
                }
            }
        }
        copy_tree_levels(remote, local, &trees, budget, &mut seen)?;
        levels.push(batch);
        frontier = dedup_ids(&next);
        if parents_of.len() > MAX_FETCH_REVISIONS {
            return Err(FetchError::TooLarge);
        }
    }
    topo_parents_first(&parents_of)
}

fn dedup_ids(ids: &[ObjectId]) -> Vec<ObjectId> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for id in ids {
        if seen.insert(*id) {
            out.push(*id);
        }
    }
    out
}

fn topo_parents_first(
    parents_of: &BTreeMap<ObjectId, Vec<ObjectId>>,
) -> Result<Vec<ObjectId>, FetchError> {
    let mut pending: BTreeMap<ObjectId, usize> = BTreeMap::new();
    let mut children: BTreeMap<ObjectId, Vec<ObjectId>> = BTreeMap::new();
    for (id, parents) in parents_of {
        let mut waiting = 0usize;
        for parent in parents {
            if parents_of.contains_key(parent) {
                waiting += 1;
                children.entry(*parent).or_default().push(*id);
            }
        }
        pending.insert(*id, waiting);
    }
    let mut ready: Vec<ObjectId> = pending
        .iter()
        .filter(|(_, waiting)| **waiting == 0)
        .map(|(id, _)| *id)
        .collect();
    let mut order = Vec::new();
    while let Some(id) = ready.pop() {
        order.push(id);
        if order.len() > MAX_FETCH_REVISIONS {
            return Err(FetchError::TooLarge);
        }
        for child in children.get(&id).into_iter().flatten() {
            let left = pending.get_mut(child).expect("child is in the graph");
            *left -= 1;
            if *left == 0 {
                ready.push(*child);
            }
        }
    }
    if order.len() != parents_of.len() {
        return Err(FetchError::Invalid("revision parents form a cycle".into()));
    }
    Ok(order)
}

/// Requests `ids` in batches of [`BATCH_IDS`]. The remote is not trusted:
/// an object that was not asked for, arrives twice, or does not hash to its
/// id is refused, and one level may not exceed [`MAX_FETCH_BYTES`].
fn fetch_objects(
    remote: &dyn Remote,
    ids: &[ObjectId],
) -> Result<BTreeMap<ObjectId, (ObjectKind, Vec<u8>)>, FetchError> {
    let mut out = BTreeMap::new();
    let mut bytes = 0usize;
    for chunk in ids.chunks(BATCH_IDS) {
        let asked: BTreeSet<ObjectId> = chunk.iter().copied().collect();
        for (id, kind, body) in remote.get_batch(chunk)? {
            if !asked.contains(&id) || out.contains_key(&id) {
                return Err(FetchError::Invalid(format!(
                    "the remote sent object {id}, which was not requested or was sent twice"
                )));
            }
            bytes = bytes
                .checked_add(body.len())
                .filter(|used| *used <= MAX_FETCH_BYTES)
                .ok_or(FetchError::TooLarge)?;
            if hash_object(kind, &body) != id {
                return Err(FetchError::Invalid(format!(
                    "object {id} does not match its id"
                )));
            }
            out.insert(id, (kind, body));
        }
    }
    Ok(out)
}

fn ensure_root(
    remote: &dyn Remote,
    local: &dyn Store,
    budget: &mut Budget,
    seen: &mut BTreeSet<ObjectId>,
) -> Result<(), FetchError> {
    let id = root_revision_id();
    if !seen.insert(id) {
        return Ok(());
    }
    let got = fetch_objects(remote, &[id])?;
    if let Some((kind, body)) = got.get(&id) {
        budget.bytes(body.len())?;
        budget.object()?;
        if *kind != ObjectKind::Revision {
            return Err(FetchError::Invalid("root object is not a revision".into()));
        }
        if !local.has(&id)? {
            local.put_raw(&id, *kind, body)?;
        }
        let revision = Revision::decode(body)?;
        copy_tree_levels(remote, local, &[revision.tree], budget, seen)?;
        return Ok(());
    }
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

fn copy_tree_levels(
    remote: &dyn Remote,
    local: &dyn Store,
    roots: &[ObjectId],
    budget: &mut Budget,
    seen: &mut BTreeSet<ObjectId>,
) -> Result<(), FetchError> {
    let mut level = dedup_ids(roots);
    level.retain(|id| seen.insert(*id));
    let mut depth = 0usize;
    while !level.is_empty() {
        if depth > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        let got = fetch_objects(remote, &level)?;
        let mut next = Vec::new();
        let mut blobs = Vec::new();
        for id in &level {
            let (kind, body) = got.get(id).ok_or(tig_core::Error::NotFound(*id))?;
            budget.bytes(body.len())?;
            budget.object()?;
            if *kind != ObjectKind::Tree {
                return Err(FetchError::Invalid(format!("object {id} is not a tree")));
            }
            if !local.has(id)? {
                local.put_raw(id, *kind, body)?;
            }
            let tree = Tree::decode(body)?;
            if !tree.entries().is_empty() && depth + 1 > MAX_TREE_DEPTH {
                return Err(too_deep());
            }
            for entry in tree.entries() {
                budget.entry()?;
                match entry.kind() {
                    EntryKind::Tree => {
                        if seen.insert(entry.id()) {
                            next.push(entry.id());
                        }
                    }
                    EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                        if seen.insert(entry.id()) {
                            blobs.push(entry.id());
                        }
                    }
                    EntryKind::Sealed => {}
                    EntryKind::Conflict => {
                        return Err(FetchError::Invalid(
                            "remote contains an unresolved conflict".into(),
                        ))
                    }
                }
            }
        }
        if !blobs.is_empty() {
            let got = fetch_objects(remote, &blobs)?;
            for id in &blobs {
                let (kind, body) = got.get(id).ok_or(tig_core::Error::NotFound(*id))?;
                budget.bytes(body.len())?;
                budget.object()?;
                if *kind != ObjectKind::Blob {
                    return Err(FetchError::Invalid(format!("object {id} is not a blob")));
                }
                if !local.has(id)? {
                    local.put_raw(id, *kind, body)?;
                }
            }
        }
        level = next;
        depth += 1;
    }
    Ok(())
}

fn rebuild_one(
    store: &dyn Store,
    public_id: ObjectId,
    mapped: &BTreeMap<ObjectId, ObjectId>,
    records: &BTreeMap<SealedId, AuthenticatedSeal>,
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

fn same_public_revision(
    store: &dyn Store,
    internal: &Revision,
    public_id: ObjectId,
    mapped: &BTreeMap<ObjectId, ObjectId>,
    records: &BTreeMap<SealedId, AuthenticatedSeal>,
    budget: &mut Budget,
) -> Result<bool, FetchError> {
    let public = store.get_revision(&public_id)?;
    let Some(tree) = project_original_seals(store, internal.tree, public.tree, records, budget)?
    else {
        return Ok(false);
    };
    let public_of: BTreeMap<_, _> = mapped.iter().map(|(p, i)| (*i, *p)).collect();
    let mut projected = internal.clone();
    projected.tree = tree;
    projected.predecessors.clear();
    for parent in &mut projected.parents {
        if *parent != root_revision_id() {
            let Some(public_parent) = public_of.get(parent) else {
                return Ok(false);
            };
            *parent = *public_parent;
        }
    }
    Ok(projected.encode() == public.encode())
}

/// Re-seal at the original public boundaries, including opaque entries inside
/// a decrypted folder. Each record supplies its own original epoch salt.
/// An explicit stack keeps deeply nested remote trees off the call stack.
fn project_original_seals(
    store: &dyn Store,
    internal: ObjectId,
    public: ObjectId,
    records: &BTreeMap<SealedId, AuthenticatedSeal>,
    budget: &mut Budget,
) -> Result<Option<ObjectId>, FetchError> {
    let mut stack = vec![(internal, public, RepoPath::root(), 0usize, false)];
    let mut projected = BTreeMap::new();
    while let Some((internal, template, prefix, depth, finish)) = stack.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        if internal == template {
            projected.insert(prefix, internal);
            continue;
        }
        let original = store.get_tree(&template)?;
        let tree = store.get_tree(&internal)?;
        if !finish {
            stack.push((internal, template, prefix.clone(), depth, true));
            for expected in original.entries() {
                budget.entry()?;
                let Some(entry) = tree.get(expected.name()) else {
                    return Ok(None);
                };
                let path = prefix.join(entry.name())?;
                match expected.kind() {
                    EntryKind::Tree if entry.kind() == EntryKind::Tree => {
                        stack.push((entry.id(), expected.id(), path, depth + 1, false));
                    }
                    EntryKind::Sealed if entry != expected => {
                        let Some(seal) = expected.sealed_id().and_then(|sid| records.get(&sid))
                        else {
                            return Ok(None);
                        };
                        if seal.record.path != path || seal.record.kind != entry.kind() {
                            return Ok(None);
                        }
                        if entry.kind() == EntryKind::Tree {
                            stack.push((entry.id(), seal.record.target, path, depth + 1, false));
                        }
                    }
                    _ => {}
                }
            }
            continue;
        }
        let mut entries = Vec::with_capacity(tree.entries().len());
        for entry in tree.entries() {
            let path = prefix.join(entry.name())?;
            let mut next = entry.clone();
            if let Some(expected) = original.get(entry.name()) {
                match expected.kind() {
                    EntryKind::Tree if entry.kind() == EntryKind::Tree => {
                        let Some(id) = projected.get(&path) else {
                            return Ok(None);
                        };
                        next = TreeEntry::new(entry.name(), EntryKind::Tree, *id)?;
                    }
                    EntryKind::Sealed if entry != expected => {
                        let Some(seal) = expected.sealed_id().and_then(|sid| records.get(&sid))
                        else {
                            return Ok(None);
                        };
                        let target = if entry.kind() == EntryKind::Tree {
                            let Some(id) = projected.get(&path) else {
                                return Ok(None);
                            };
                            *id
                        } else {
                            entry.id()
                        };
                        // Salt is content-bound: only the authenticated target
                        // may be recomputed under this original salt.
                        if target != seal.record.target {
                            return Ok(None);
                        }
                        let sid = SealedId::compute(&seal.salt, entry.kind(), &target);
                        next = TreeEntry::sealed(entry.name(), sid)?;
                    }
                    _ => {}
                }
            }
            entries.push(next);
        }
        let id = store.put(&Object::Tree(Tree::new(entries)?))?;
        projected.insert(prefix, id);
    }
    Ok(projected.get(&RepoPath::root()).copied())
}

fn unseal(
    store: &dyn Store,
    mut tree: ObjectId,
    records: &BTreeMap<SealedId, AuthenticatedSeal>,
    budget: &mut Budget,
) -> Result<(ObjectId, usize, usize), FetchError> {
    let mut unsealed = 0usize;
    loop {
        let mut edits = BTreeMap::new();
        let mut still_sealed = 0usize;
        for (path, sid) in sealed_leaves(store, tree, budget)? {
            let Some(seal) = records.get(&sid) else {
                still_sealed += 1;
                continue;
            };
            let record = &seal.record;
            if record.path != path {
                return Err(FetchError::Invalid(format!(
                    "sealed record path {} does not match tree path {path}",
                    record.path
                )));
            }
            edits.insert(path, Some(checked_leaf(store, record)?));
            unsealed += 1;
        }
        if edits.is_empty() {
            return Ok((tree, unsealed, still_sealed));
        }
        tree = apply_edits(store, &tree, &edits)?;
        // The next pass opens inherited seals inside decrypted subtrees and
        // checks their expansion/depth limits before returning the tree.
    }
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
                EntryKind::Conflict => return Err(FetchError::Invalid("remote contains an unresolved conflict".into())),
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
            AuthenticatedSeal {
                record: SealedRecord {
                    sealed_id: sid,
                    path: RepoPath::new("secrets").unwrap(),
                    kind: EntryKind::Tree,
                    target: tree,
                },
                salt: SealSalt::from_bytes([0; 32]),
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
