//! Publish a revision to a directory remote.
//!
//! Reads the remote keyring, projects each unpublished ancestor, and only
//! then writes. A refusal leaves the remote and `state` unchanged. See
//! DESIGN.md "Publish and fetch".
//!
//! The caller keeps [`PublishState`] and prepares and saves [`OwnerKeys`]
//! before the first publish. The owner passes those keys back on later
//! publishes and never takes an epoch key from the remote.
//!
//! Empty remote, keys already saved: pass `Some(owner_keys)` when the
//! keyring file is absent. Publish builds the keyring from that epoch
//! secret and writes the file only after the refusal checks. The caller
//! must save the keys before calling `publish`, so a crash cannot leave a
//! remote keyring whose secret existed only in a dead process. Passing
//! `None` to an empty remote is refused. Use `Keyring::create` to prepare keys.

use std::collections::{BTreeMap, BTreeSet};

use tig_core::encode::{Reader, Writer};
use tig_core::object::{hash_object, Object, ObjectKind, Tree};
use tig_core::repo::{root_revision, root_revision_id};
use tig_core::store::{Store, StoreExt};
use tig_core::treeops::{Leaf, MAX_TREE_DEPTH};
use tig_core::{EntryKind, ObjectId, RepoPath};

use crate::keyring::{Keyring, KeyringError, OwnerKeys};
use crate::keys::{EpochKey, Identity, KeyError, WireId};
use crate::pack::{PackBuilder, PackError};
use crate::project::{project_tree, public_revision, Projection, SealedRoot, PRIVATE_GROUP};
use crate::remote::{DirRemote, RemoteError};

const VERSION: u8 = 1;
const MAX_REVISIONS: usize = 1_000_000;
const MAX_PATHS: usize = 1_000_000;
const MAX_WIRES: usize = 1_000_000;
const MAX_SENT_GROUPS: usize = 10_000;
const MAX_GROUP: usize = 1024;
const MAX_PATH: usize = 64 * 1024;
const MAX_HISTORY: usize = 100_000;
const MAX_BOOKMARK: usize = 1024;

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error(transparent)]
    Project(#[from] crate::project::ProjectError),
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    #[error(transparent)]
    Remote(#[from] RemoteError),
    #[error(transparent)]
    Pack(#[from] PackError),
    #[error(transparent)]
    Key(#[from] KeyError),
    /// A path published in the clear earlier is private now. Rotate it.
    #[error("already leaked; rotate these paths: {}", join_paths(paths))]
    AlreadyLeaked { paths: Vec<RepoPath> },
    /// A public file has the same bytes as a non-empty private file.
    #[error("public file repeats a private file: {}", join_pastes(pastes))]
    PastedSecret { pastes: Vec<Paste> },
    /// A `!` rule makes a path public that has not been confirmed.
    #[error(
        "a negation makes these paths public; confirm them: {}",
        join_paths(paths)
    )]
    NegationNeedsConfirmation { paths: Vec<RepoPath> },
    #[error("{0}")]
    Invalid(String),
}

/// A public file whose bytes match a private file in the same revision.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Paste {
    pub public_path: RepoPath,
    pub private_path: RepoPath,
}

/// What the caller turns on to get past a refusal.
///
/// Both flags default to off. A leak must be acknowledged on every publish
/// that still hides a previously public path. A negation is remembered in
/// [`PublishState::confirmed_negations`] after the first confirmation.
#[derive(Clone, Debug, Default)]
pub struct PublishOptions {
    /// Seal the path from now on, and report that the old contents leaked.
    pub acknowledge_leaked: bool,
    /// Accept every still-unconfirmed `!` path in this publish.
    pub confirm_negations: bool,
}

/// Per-remote publish memory. The caller persists [`PublishState::encode`].
///
/// `owner_signing` is `None` until the first successful publish. The map is
/// internal revision to public revision. The root revision is not stored; it
/// always projects to itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishState {
    pub remote_id: [u8; 16],
    pub owner_signing: Option<[u8; 32]>,
    /// Highest keyring counter this state has accepted.
    pub counter: u64,
    pub revisions: BTreeMap<ObjectId, ObjectId>,
    /// Every file path published as public to this remote, plus Git exposure
    /// evidence seeded by import before the first publish. This evidence alone
    /// does not bind an otherwise unused state to an owner or remote.
    pub ever_public: BTreeSet<RepoPath>,
    pub confirmed_negations: BTreeSet<RepoPath>,
    /// Wire ids already sent, per group and epoch.
    pub sent: BTreeMap<(String, u64), BTreeSet<WireId>>,
}

impl Default for PublishState {
    fn default() -> Self {
        Self::new()
    }
}

impl PublishState {
    /// Empty state for a remote this process has not published to.
    pub fn new() -> Self {
        PublishState {
            remote_id: [0; 16],
            owner_signing: None,
            counter: 0,
            revisions: BTreeMap::new(),
            ever_public: BTreeSet::new(),
            confirmed_negations: BTreeSet::new(),
            sent: BTreeMap::new(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, PublishError> {
        if self.revisions.len() > MAX_REVISIONS
            || self.ever_public.len() > MAX_PATHS
            || self.confirmed_negations.len() > MAX_PATHS
            || self.sent.len() > MAX_SENT_GROUPS
        {
            return Err(PublishError::Invalid("publish state is too large".into()));
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
        for (internal, public) in &self.revisions {
            w.id(internal);
            w.id(public);
        }
        write_paths(&mut w, &self.ever_public)?;
        write_paths(&mut w, &self.confirmed_negations)?;
        w.varint(self.sent.len() as u64);
        for ((group, epoch), wires) in &self.sent {
            if group.is_empty() || group.len() > MAX_GROUP || wires.len() > MAX_WIRES {
                return Err(PublishError::Invalid("sent set is invalid".into()));
            }
            w.str(group);
            w.varint(*epoch);
            w.varint(wires.len() as u64);
            for wire in wires {
                w.buf.extend_from_slice(&wire.0);
            }
        }
        Ok(w.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PublishError> {
        let mut r = Reader::new(bytes, "publish state");
        let version = r.u8()?;
        if version != VERSION {
            return Err(PublishError::Invalid(format!(
                "unsupported publish state version {version}"
            )));
        }
        let remote_id = read_array(&mut r)?;
        let flag = r.u8()?;
        let owner_signing = match flag {
            0 => None,
            1 => Some(read_array(&mut r)?),
            _ => {
                return Err(PublishError::Invalid(
                    "publish state pin flag is invalid".into(),
                ))
            }
        };
        let counter = r.varint()?;
        let n = r.count(64)?;
        if n > MAX_REVISIONS {
            return Err(PublishError::Invalid("too many revisions".into()));
        }
        let mut revisions = BTreeMap::new();
        let mut previous: Option<ObjectId> = None;
        for _ in 0..n {
            let internal = r.id()?;
            let public = r.id()?;
            if previous.is_some_and(|prev| internal <= prev) {
                return Err(PublishError::Invalid(
                    "revisions are not in canonical order".into(),
                ));
            }
            previous = Some(internal);
            revisions.insert(internal, public);
        }
        let ever_public = read_paths(&mut r)?;
        let confirmed_negations = read_paths(&mut r)?;
        let n_groups = r.count(1)?;
        if n_groups > MAX_SENT_GROUPS {
            return Err(PublishError::Invalid("too many sent groups".into()));
        }
        let mut sent = BTreeMap::new();
        let mut previous_group: Option<(String, u64)> = None;
        for _ in 0..n_groups {
            let group = r.str()?;
            if group.is_empty() || group.len() > MAX_GROUP {
                return Err(PublishError::Invalid("invalid group name".into()));
            }
            let group = group.to_string();
            let epoch = r.varint()?;
            let rank = (group.clone(), epoch);
            if previous_group.as_ref().is_some_and(|prev| rank <= *prev) {
                return Err(PublishError::Invalid(
                    "sent groups are not in canonical order".into(),
                ));
            }
            previous_group = Some(rank.clone());
            let n_wires = r.count(32)?;
            if n_wires > MAX_WIRES {
                return Err(PublishError::Invalid("too many wire ids".into()));
            }
            let mut wires = BTreeSet::new();
            let mut previous_wire: Option<[u8; 32]> = None;
            for _ in 0..n_wires {
                let wire = read_array::<32>(&mut r)?;
                if previous_wire.is_some_and(|prev| wire <= prev) {
                    return Err(PublishError::Invalid(
                        "wire ids are not in canonical order".into(),
                    ));
                }
                previous_wire = Some(wire);
                wires.insert(WireId(wire));
            }
            sent.insert(rank, wires);
        }
        r.finish()?;
        Ok(PublishState {
            remote_id,
            owner_signing,
            counter,
            revisions,
            ever_public,
            confirmed_negations,
            sent,
        })
    }
}

/// Counts for one successful publish.
#[derive(Debug)]
pub struct PublishReport {
    pub revisions_published: usize,
    pub public_objects_written: usize,
    pub private_objects_sealed: usize,
    pub sealed_roots: usize,
    /// Retained for callers of the original API. Always `None`: the first
    /// epoch keys must now be prepared and saved before calling publish.
    pub new_owner_keys: Option<OwnerKeys>,
    pub warnings: Vec<String>,
}

struct Plan {
    internal: ObjectId,
    projection: Projection,
}

struct Session {
    epoch_key: EpochKey,
    counter: u64,
    pin: [u8; 32],
    /// Keyring not yet written. Held until refusal checks have passed.
    fresh: Option<Keyring>,
}

/// Publishes `rev` and its unpublished ancestors to `remote` under `bookmark`.
///
/// The first call on an empty remote (no keyring) makes `identity` the owner
/// and pins that signing key. The caller must pass keys it already saved,
/// whose remote id matches (see the module docs). Later
/// calls check the pinned key and `state.counter`, then encrypt with the
/// owner's local key or, for a member, with
/// [`crate::keyring::VerifiedKeyring::current_key`].
///
/// On `Err`, `state` is unchanged and nothing new has been written. A failure
/// after the remote accepted some objects (a crash, or a disk error) can
/// leave content-addressed objects without moving the bookmark; publishing
/// the same revision again finishes the job.
#[allow(clippy::too_many_arguments)]
pub fn publish(
    store: &dyn Store,
    remote: &DirRemote,
    identity: &Identity,
    owner_keys: Option<&OwnerKeys>,
    state: &mut PublishState,
    bookmark: &str,
    rev: ObjectId,
    options: &PublishOptions,
) -> Result<PublishReport, PublishError> {
    if bookmark.is_empty() || bookmark.len() > MAX_BOOKMARK {
        return Err(PublishError::Invalid("invalid bookmark".into()));
    }
    let session = open_session(remote, identity, owner_keys, state)?;
    let ancestors = parent_first(store, &[rev], |id| {
        id == root_revision_id() || state.revisions.contains_key(&id)
    })?;
    let mut plans = Vec::with_capacity(ancestors.len());
    for internal in ancestors {
        let revision = store.get_revision(&internal)?;
        let projection = project_tree(store, &revision.tree, &session.epoch_key)?;
        plans.push(Plan {
            internal,
            projection,
        });
    }
    let mut ever_public = state.ever_public.clone();
    ever_public.extend(remote_public_paths(remote)?);
    let checked = check_refusals(state, &ever_public, &plans, options)?;

    let mut written = 0usize;
    if let Some(fresh) = &session.fresh {
        remote.write_keyring(&fresh.encode()?)?;
    }
    write_canonical(
        remote.public_store(),
        &Object::Tree(Tree::empty()),
        &mut written,
    )?;
    write_canonical(
        remote.public_store(),
        &Object::Revision(root_revision()),
        &mut written,
    )?;

    let mut public_ids = state.revisions.clone();
    for plan in &plans {
        let revision = store.get_revision(&plan.internal)?;
        let mut parents = Vec::with_capacity(revision.parents.len());
        for parent in &revision.parents {
            parents.push(public_parent(&public_ids, *parent)?);
        }
        let public_rev = public_revision(&revision, plan.projection.public_tree, parents);
        write_public_tree(
            store,
            remote.public_store(),
            &plan.projection.public_tree,
            &mut written,
        )?;
        let obj = Object::Revision(public_rev);
        let public_id = obj.id();
        write_canonical(remote.public_store(), &obj, &mut written)?;
        public_ids.insert(plan.internal, public_id);
    }

    let (sealed_objects, sealed_roots, new_wires) =
        write_pack(store, remote, &session.epoch_key, state, &plans)?;

    let tip = public_parent(&public_ids, rev)?;
    let mut refs = remote.read_refs()?;
    refs.insert(bookmark.to_string(), tip);
    remote.write_refs(&refs)?;

    let epoch = session.epoch_key.context().epoch;
    let group = session.epoch_key.context().group.clone();
    state.remote_id = remote.remote_id();
    state.owner_signing = Some(session.pin);
    state.counter = session.counter;
    for plan in &plans {
        let public_id = public_ids[&plan.internal];
        state.revisions.insert(plan.internal, public_id);
    }
    ever_public.extend(checked.new_public);
    state.ever_public = ever_public;
    state.confirmed_negations.extend(checked.confirmed);
    if !new_wires.is_empty() {
        state
            .sent
            .entry((group, epoch))
            .or_default()
            .extend(new_wires);
    }
    Ok(PublishReport {
        revisions_published: plans.len(),
        public_objects_written: written,
        private_objects_sealed: sealed_objects,
        sealed_roots,
        new_owner_keys: None,
        warnings: checked.warnings,
    })
}

fn open_session(
    remote: &DirRemote,
    identity: &Identity,
    owner_keys: Option<&OwnerKeys>,
    state: &PublishState,
) -> Result<Session, PublishError> {
    let remote_id = remote.remote_id();
    let saved_pin = saved_pin(state, remote_id)?;
    match remote.read_keyring() {
        Err(RemoteError::Invalid(message)) if message == "keyring is missing" => {
            if saved_pin.is_some() {
                return Err(PublishError::Invalid(
                    "this publish state is already bound, but the remote has no keyring".into(),
                ));
            }
            // Saved keys win over minting a new epoch. The caller stored them
            // before this call; the keyring file is written only after the
            // refusal checks, from this same secret.
            let saved = owner_keys.ok_or_else(|| {
                PublishError::Invalid(
                    "save owner keys before the first publish (prepare them with Keyring::create)"
                        .into(),
                )
            })?;
            if saved.remote != remote_id {
                return Err(PublishError::Invalid(
                    "owner keys are for a different remote".into(),
                ));
            }
            let keyring = Keyring::from_saved_owner(identity, saved)?;
            let pin = identity.public().signing;
            keyring.verify(&pin, 0)?;
            let epoch_key = owner_epoch_key(saved, remote_id, 1)?;
            Ok(Session {
                epoch_key,
                counter: keyring.head.counter,
                pin,
                fresh: Some(keyring),
            })
        }
        Err(error) => Err(error.into()),
        Ok(bytes) => {
            let keyring = Keyring::decode(&bytes)?;
            if keyring.remote != remote_id {
                return Err(PublishError::Invalid(
                    "keyring is for a different remote".into(),
                ));
            }
            let pin =
                match saved_pin {
                    Some(pin) => pin,
                    None if keyring.owner == identity.public() => identity.public().signing,
                    None => return Err(PublishError::Invalid(
                        "this remote already has an owner; pin their signing key before publishing"
                            .into(),
                    )),
                };
            let verified = keyring.verify(&pin, state.counter)?;
            let epoch = keyring
                .head
                .epochs
                .get(PRIVATE_GROUP)
                .copied()
                .ok_or_else(|| PublishError::Invalid("keyring has no private epoch".into()))?;
            let epoch_key = if identity.public() == keyring.owner {
                let keys = owner_keys.ok_or_else(|| {
                    PublishError::Invalid(
                        "the owner must pass local epoch keys; they are not read from the remote"
                            .into(),
                    )
                })?;
                owner_epoch_key(keys, remote_id, epoch)?
            } else {
                verified.current_key(PRIVATE_GROUP, identity)?
            };
            Ok(Session {
                epoch_key,
                counter: verified.counter(),
                pin,
                fresh: None,
            })
        }
    }
}

fn saved_pin(state: &PublishState, remote_id: [u8; 16]) -> Result<Option<[u8; 32]>, PublishError> {
    match state.owner_signing {
        Some(pin) => {
            if state.remote_id != remote_id {
                return Err(PublishError::Invalid(
                    "publish state is for a different remote".into(),
                ));
            }
            Ok(Some(pin))
        }
        None => {
            let unused = state.counter == 0
                && state.revisions.is_empty()
                && state.confirmed_negations.is_empty()
                && state.sent.is_empty();
            if unused {
                Ok(None)
            } else {
                Err(PublishError::Invalid(
                    "publish state is missing its owner pin".into(),
                ))
            }
        }
    }
}

fn owner_epoch_key(
    keys: &OwnerKeys,
    remote_id: [u8; 16],
    epoch: u64,
) -> Result<EpochKey, PublishError> {
    if keys.remote != remote_id {
        return Err(PublishError::Invalid(
            "owner keys are for a different remote".into(),
        ));
    }
    let stored = keys
        .keys
        .get(&(PRIVATE_GROUP.to_string(), epoch))
        .ok_or_else(|| PublishError::Invalid("owner has no key for this epoch".into()))?;
    let expect = stored.context();
    if expect.remote != remote_id || expect.group != PRIVATE_GROUP || expect.epoch != epoch {
        return Err(PublishError::Invalid(
            "stored epoch key has the wrong context".into(),
        ));
    }
    Ok(EpochKey::from_bytes(expect.clone(), *stored.to_bytes()))
}

/// Parents first. `skip` drops the root and revisions already published.
fn parent_first(
    store: &dyn Store,
    tips: &[ObjectId],
    skip: impl Fn(ObjectId) -> bool,
) -> Result<Vec<ObjectId>, PublishError> {
    const VISITING: u8 = 1;
    const DONE: u8 = 2;
    let mut colors: BTreeMap<ObjectId, u8> = BTreeMap::new();
    let mut stack: Vec<(ObjectId, bool)> = tips.iter().rev().map(|id| (*id, false)).collect();
    let mut order = Vec::new();
    while let Some((id, entered)) = stack.pop() {
        if skip(id) {
            continue;
        }
        if entered {
            colors.insert(id, DONE);
            order.push(id);
            if order.len() > MAX_HISTORY {
                return Err(PublishError::Invalid(
                    "history is too long to publish".into(),
                ));
            }
            continue;
        }
        match colors.get(&id).copied() {
            Some(DONE) => continue,
            Some(VISITING) => {
                return Err(PublishError::Invalid(
                    "revision parents form a cycle".into(),
                ))
            }
            _ => {}
        }
        colors.insert(id, VISITING);
        stack.push((id, true));
        let revision = store.get_revision(&id)?;
        for parent in revision.parents.iter().rev() {
            if skip(*parent) {
                continue;
            }
            match colors.get(parent).copied() {
                Some(DONE) => {}
                Some(VISITING) => {
                    return Err(PublishError::Invalid(
                        "revision parents form a cycle".into(),
                    ))
                }
                _ => stack.push((*parent, false)),
            }
        }
    }
    Ok(order)
}

struct Checked {
    warnings: Vec<String>,
    new_public: BTreeSet<RepoPath>,
    confirmed: BTreeSet<RepoPath>,
}

/// A different publisher or branch may have exposed a path before this
/// caller's state existed. Include the remote's reachable public history.
fn remote_public_paths(remote: &DirRemote) -> Result<BTreeSet<RepoPath>, PublishError> {
    let tips: Vec<_> = remote.read_refs()?.values().copied().collect();
    let store = remote.public_store();
    let revisions = parent_first(store, &tips, |id| id == root_revision_id())?;
    let mut paths = BTreeSet::new();
    let mut entries = 0usize;
    for id in revisions {
        let mut stack = vec![(store.get_revision(&id)?.tree, RepoPath::root(), 0usize)];
        while let Some((tree, prefix, depth)) = stack.pop() {
            if depth > MAX_TREE_DEPTH {
                return Err(PublishError::Invalid("remote tree is too deep".into()));
            }
            for entry in store.get_tree(&tree)?.entries() {
                entries += 1;
                if entries > MAX_PATHS {
                    return Err(PublishError::Invalid(
                        "remote history has too many paths".into(),
                    ));
                }
                let path = prefix.join(entry.name())?;
                if entry.kind() == EntryKind::Tree {
                    stack.push((entry.id(), path, depth + 1));
                } else if entry.kind().is_file_like() {
                    paths.insert(path);
                }
            }
        }
    }
    Ok(paths)
}

fn check_refusals(
    state: &PublishState,
    ever_public: &BTreeSet<RepoPath>,
    plans: &[Plan],
    options: &PublishOptions,
) -> Result<Checked, PublishError> {
    let empty = empty_blob();
    let mut seen_public = ever_public.clone();
    let mut leaked = BTreeSet::new();
    let mut pastes = BTreeSet::new();
    let mut negations = BTreeSet::new();
    let mut new_public = BTreeSet::new();
    for plan in plans {
        for path in &seen_public {
            if hidden_now(path, &plan.projection) {
                leaked.insert(path.clone());
            }
        }
        pastes.extend(pastes_in(&plan.projection, empty));
        for path in &plan.projection.negated {
            if !seen_public.contains(path) && !state.confirmed_negations.contains(path) {
                negations.insert(path.clone());
            }
        }
        for (path, leaf) in &plan.projection.public_files {
            if leaf.is_file_like() {
                seen_public.insert(path.clone());
                new_public.insert(path.clone());
            }
        }
    }
    let mut warnings = Vec::new();
    if !leaked.is_empty() {
        let paths: Vec<RepoPath> = leaked.into_iter().collect();
        if !options.acknowledge_leaked {
            return Err(PublishError::AlreadyLeaked { paths });
        }
        warnings.push(format!(
            "these paths were already published and cannot be hidden; they are sealed from now on, but the old contents leaked and should be rotated: {}",
            join_paths(&paths)
        ));
    }
    if !pastes.is_empty() {
        return Err(PublishError::PastedSecret {
            pastes: pastes.into_iter().collect(),
        });
    }
    if !negations.is_empty() && !options.confirm_negations {
        return Err(PublishError::NegationNeedsConfirmation {
            paths: negations.into_iter().collect(),
        });
    }
    let confirmed = if options.confirm_negations {
        negations
    } else {
        BTreeSet::new()
    };
    Ok(Checked {
        warnings,
        new_public,
        confirmed,
    })
}

fn hidden_now(path: &RepoPath, projection: &Projection) -> bool {
    projection
        .private_files
        .iter()
        .any(|(private, _)| private == path)
        || projection
            .sealed
            .iter()
            .any(|root| path.starts_with(&root.path))
}

fn pastes_in(projection: &Projection, empty: ObjectId) -> BTreeSet<Paste> {
    let mut private_blobs: BTreeMap<ObjectId, RepoPath> = BTreeMap::new();
    for (path, leaf) in &projection.private_files {
        if leaf.is_file_like() && leaf.id() != empty {
            private_blobs
                .entry(leaf.id())
                .or_insert_with(|| path.clone());
        }
    }
    let mut found = BTreeSet::new();
    for (path, leaf) in &projection.public_files {
        if !leaf.is_file_like() || leaf.id() == empty {
            continue;
        }
        if let Some(private_path) = private_blobs.get(&leaf.id()) {
            found.insert(Paste {
                public_path: path.clone(),
                private_path: private_path.clone(),
            });
        }
    }
    found
}

fn empty_blob() -> ObjectId {
    hash_object(ObjectKind::Blob, b"")
}

fn public_parent(
    public_ids: &BTreeMap<ObjectId, ObjectId>,
    id: ObjectId,
) -> Result<ObjectId, PublishError> {
    if id == root_revision_id() {
        return Ok(root_revision_id());
    }
    public_ids
        .get(&id)
        .copied()
        .ok_or_else(|| PublishError::Invalid(format!("parent {id} has not been published")))
}

fn write_canonical(
    store: &dyn Store,
    obj: &Object,
    written: &mut usize,
) -> Result<(), PublishError> {
    let body = obj.encode_body();
    let id = hash_object(obj.kind(), &body);
    put_missing(store, &id, obj.kind(), &body, written)
}

fn put_missing(
    store: &dyn Store,
    id: &ObjectId,
    kind: ObjectKind,
    body: &[u8],
    written: &mut usize,
) -> Result<(), PublishError> {
    if store.has(id)? {
        return Ok(());
    }
    store.put_raw(id, kind, body)?;
    *written += 1;
    Ok(())
}

/// Copies a public tree. A tree the remote already has is skipped, children
/// included: its id commits to those children. Children are written before
/// the parent. The walk is a heap stack; a deep tree must not grow the
/// thread stack.
fn write_public_tree(
    local: &dyn Store,
    remote: &dyn Store,
    root: &ObjectId,
    written: &mut usize,
) -> Result<(), PublishError> {
    // (id, depth, entered). Entered means the children are already queued
    // above this frame, so they are written before the parent.
    const MAX_STACK: usize = 1_000_000;
    let mut stack = vec![(*root, 0usize, false)];
    let mut seen = BTreeSet::new();
    while let Some((id, depth, entered)) = stack.pop() {
        if entered {
            let (kind, body) = local.get_raw(&id)?.ok_or(tig_core::Error::NotFound(id))?;
            if kind != ObjectKind::Tree {
                return Err(PublishError::Invalid(format!(
                    "public tree {id} is not a tree"
                )));
            }
            put_missing(remote, &id, ObjectKind::Tree, &body, written)?;
            continue;
        }
        if remote.has(&id)? || !seen.insert(id) {
            continue;
        }
        if depth > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        let (kind, body) = local.get_raw(&id)?.ok_or(tig_core::Error::NotFound(id))?;
        if kind != ObjectKind::Tree {
            return Err(PublishError::Invalid(format!(
                "public tree {id} is not a tree"
            )));
        }
        let tree = Tree::decode(&body)?;
        if !tree.entries().is_empty() && depth + 1 > MAX_TREE_DEPTH {
            return Err(too_deep());
        }
        stack.push((id, depth, true));
        let mut children = Vec::new();
        for entry in tree.entries() {
            match entry.kind() {
                EntryKind::Tree => children.push(entry.id()),
                EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                    let blob_id = entry.id();
                    let (blob_kind, blob) = local
                        .get_raw(&blob_id)?
                        .ok_or(tig_core::Error::NotFound(blob_id))?;
                    if blob_kind != ObjectKind::Blob {
                        return Err(PublishError::Invalid(format!(
                            "public file {blob_id} is not a blob"
                        )));
                    }
                    put_missing(remote, &blob_id, ObjectKind::Blob, &blob, written)?;
                }
                EntryKind::Sealed => {}
            }
        }
        if stack.len() > MAX_STACK || children.len() > MAX_STACK - stack.len() {
            return Err(PublishError::Invalid(
                "public tree is too large to publish".into(),
            ));
        }
        for child in children.into_iter().rev() {
            stack.push((child, depth + 1, false));
        }
    }
    Ok(())
}

fn too_deep() -> PublishError {
    PublishError::Core(tig_core::Error::Invalid(format!(
        "tree deeper than MAX_TREE_DEPTH ({MAX_TREE_DEPTH})"
    )))
}

fn write_pack(
    store: &dyn Store,
    remote: &DirRemote,
    key: &EpochKey,
    state: &PublishState,
    plans: &[Plan],
) -> Result<(usize, usize, BTreeSet<WireId>), PublishError> {
    let epoch = key.context().epoch;
    let already = state
        .sent
        .get(&(key.context().group.clone(), epoch))
        .cloned()
        .unwrap_or_default();
    let mut builder = PackBuilder::new(key);
    let mut added: BTreeSet<ObjectId> = BTreeSet::new();
    let mut new_wires = BTreeSet::new();
    let mut sealed_roots = 0usize;
    for plan in plans {
        for root in &plan.projection.sealed {
            seal_root(
                store,
                key,
                root,
                &already,
                &mut added,
                &mut new_wires,
                &mut builder,
            )?;
            sealed_roots += 1;
        }
    }
    let sealed_objects = new_wires.len();
    if sealed_objects == 0 && sealed_roots == 0 {
        return Ok((0, 0, new_wires));
    }
    let bytes = builder.finish()?;
    remote.put_pack(&bytes)?;
    Ok((sealed_objects, sealed_roots, new_wires))
}

fn seal_root(
    store: &dyn Store,
    key: &EpochKey,
    root: &SealedRoot,
    already: &BTreeSet<WireId>,
    added: &mut BTreeSet<ObjectId>,
    new_wires: &mut BTreeSet<WireId>,
    builder: &mut PackBuilder<'_>,
) -> Result<(), PublishError> {
    let sealed_id = key.seal(&root.path, root.leaf.kind(), &root.leaf.id());
    builder.add_sealed(
        sealed_id,
        root.path.clone(),
        root.leaf.kind(),
        root.leaf.id(),
    )?;
    let mut pending = vec![(root.leaf, root.path.components().count())];
    let mut walked = BTreeSet::new();
    while let Some((leaf, depth)) = pending.pop() {
        if depth > MAX_TREE_DEPTH {
            return Err(PublishError::Core(tig_core::Error::Invalid(format!(
                "tree deeper than MAX_TREE_DEPTH ({MAX_TREE_DEPTH})"
            ))));
        }
        if !walked.insert(leaf.id()) {
            continue;
        }
        match leaf.kind() {
            EntryKind::Tree => {
                queue_object(
                    store,
                    key,
                    ObjectKind::Tree,
                    leaf.id(),
                    already,
                    added,
                    new_wires,
                    builder,
                )?;
                let tree = store.get_tree(&leaf.id())?;
                for entry in tree.entries() {
                    if entry.kind() == EntryKind::Sealed {
                        continue;
                    }
                    let child = Leaf::new(entry.kind(), entry.id())?;
                    pending.push((child, depth + 1));
                }
            }
            EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                queue_object(
                    store,
                    key,
                    ObjectKind::Blob,
                    leaf.id(),
                    already,
                    added,
                    new_wires,
                    builder,
                )?;
            }
            EntryKind::Sealed => {}
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn queue_object(
    store: &dyn Store,
    key: &EpochKey,
    kind: ObjectKind,
    id: ObjectId,
    already: &BTreeSet<WireId>,
    added: &mut BTreeSet<ObjectId>,
    new_wires: &mut BTreeSet<WireId>,
    builder: &mut PackBuilder<'_>,
) -> Result<(), PublishError> {
    let wire = key.wire_id(&id);
    if already.contains(&wire) || !added.insert(id) {
        return Ok(());
    }
    let (stored_kind, body) = store.get_raw(&id)?.ok_or(tig_core::Error::NotFound(id))?;
    if stored_kind != kind {
        return Err(PublishError::Invalid(format!(
            "object {id} has kind {} but the tree says {}",
            stored_kind.name(),
            kind.name()
        )));
    }
    builder.add_object(kind, id, &body)?;
    new_wires.insert(wire);
    Ok(())
}

fn write_paths(w: &mut Writer, paths: &BTreeSet<RepoPath>) -> Result<(), PublishError> {
    w.varint(paths.len() as u64);
    for path in paths {
        if path.as_str().len() > MAX_PATH {
            return Err(PublishError::Invalid("path is too long".into()));
        }
        w.str(path.as_str());
    }
    Ok(())
}

fn read_paths(r: &mut Reader<'_>) -> Result<BTreeSet<RepoPath>, PublishError> {
    let n = r.count(1)?;
    if n > MAX_PATHS {
        return Err(PublishError::Invalid("too many paths".into()));
    }
    let mut paths = BTreeSet::new();
    let mut previous: Option<RepoPath> = None;
    for _ in 0..n {
        let text = r.str()?;
        if text.len() > MAX_PATH {
            return Err(PublishError::Invalid("path is too long".into()));
        }
        let path = RepoPath::new(text)?;
        if previous.as_ref().is_some_and(|prev| path <= *prev) {
            return Err(PublishError::Invalid(
                "paths are not in canonical order".into(),
            ));
        }
        previous = Some(path.clone());
        paths.insert(path);
    }
    Ok(paths)
}

fn read_array<const N: usize>(r: &mut Reader<'_>) -> Result<[u8; N], PublishError> {
    let mut out = [0u8; N];
    out.copy_from_slice(r.take(N)?);
    Ok(out)
}

fn join_paths(paths: &[RepoPath]) -> String {
    paths
        .iter()
        .map(RepoPath::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn join_pastes(pastes: &[Paste]) -> String {
    pastes
        .iter()
        .map(|paste| format!("{} copies {}", paste.public_path, paste.private_path))
        .collect::<Vec<_>>()
        .join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_roundtrip_rejects_unsorted_and_trailing_bytes() {
        let mut state = PublishState::new();
        state.remote_id = [1; 16];
        state.owner_signing = Some([2; 32]);
        state.counter = 4;
        state.revisions.insert(ObjectId([1; 32]), ObjectId([9; 32]));
        state.revisions.insert(ObjectId([2; 32]), ObjectId([8; 32]));
        state.ever_public.insert(RepoPath::new(".env").unwrap());
        state
            .confirmed_negations
            .insert(RepoPath::new("secrets/README.md").unwrap());
        state.sent.insert(
            ("private".into(), 1),
            BTreeSet::from([WireId([5; 32]), WireId([6; 32])]),
        );
        let bytes = state.encode().unwrap();
        assert_eq!(PublishState::decode(&bytes).unwrap(), state);

        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PublishState::decode(&trailing).is_err());

        // Swap the two revision records (64 bytes each) so the keys decrease.
        let mut unsorted = bytes.clone();
        let start = unsorted
            .windows(32)
            .position(|window| window == [1; 32])
            .unwrap();
        let first: Vec<u8> = unsorted[start..start + 64].to_vec();
        let second: Vec<u8> = unsorted[start + 64..start + 128].to_vec();
        unsorted[start..start + 64].copy_from_slice(&second);
        unsorted[start + 64..start + 128].copy_from_slice(&first);
        assert!(matches!(
            PublishState::decode(&unsorted),
            Err(PublishError::Invalid(ref reason)) if reason.contains("canonical")
        ));

        assert_eq!(
            PublishState::decode(&PublishState::new().encode().unwrap()).unwrap(),
            PublishState::new()
        );
    }
}
