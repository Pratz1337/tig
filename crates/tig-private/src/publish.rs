//! Publish a revision to a directory remote.
//!
//! Reads the remote keyring, projects each unpublished ancestor, and only
//! then writes. A refusal leaves the remote and `state` unchanged. See
//! DESIGN.md "Publish and fetch".
//!
//! The caller keeps [`PublishState`] and prepares and saves [`OwnerKeys`]
//! before the first publish. The owner passes those keys back on later
//! publishes. The original private epoch is checked against those saved keys;
//! additional role groups may use their verified, authorized grants.
//!
//! Empty remote, keys already saved: pass `Some(owner_keys)` when the
//! keyring file is absent. Publish builds the keyring from that epoch
//! secret and writes the file only after the refusal checks. The caller
//! must save the keys before calling `publish`, so a crash cannot leave a
//! remote keyring whose secret existed only in a dead process. Passing
//! `None` to an empty remote is refused. Use `Keyring::create` to prepare keys.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use tig_core::encode::{Reader, Writer};
use tig_core::object::{hash_object, Object, ObjectKind, Tree};
use tig_core::repo::{rebase_revision, root_revision, root_revision_id};
use tig_core::store::{Store, StoreExt};
use tig_core::treeops::{Leaf, MAX_TREE_DEPTH};
use tig_core::{EntryKind, ObjectId, RepoPath};

use crate::fetch::FetchState;
use crate::keyring::{Keyring, KeyringError, OwnerKeys};
use crate::keys::{EpochKey, Identity, KeyError, WireId};
use crate::manifest::{pack_id, Manifest, ManifestError, PackEntry};
use crate::pack::{Pack, PackBatch, PackError};
use crate::project::{access_group, project_grouped, public_revision, Projection, PRIVATE_GROUP};
use crate::remote::{CommitOutcome, Remote, RemoteError};

const VERSION: u8 = 5;
const MAX_REVISIONS: usize = 1_000_000;
const MAX_PATHS: usize = 1_000_000;
const MAX_WIRES: usize = 1_000_000;
const MAX_SENT_GROUPS: usize = 10_000;
const MAX_GROUP: usize = 1024;
const MAX_PATH: usize = 64 * 1024;
const MAX_HISTORY: usize = 100_000;
const MAX_BOOKMARK: usize = 1024;
const PUBLISH_ATTEMPTS: u32 = 8;
const BATCH_OBJECTS: usize = 1000;
const BATCH_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum PublishError {
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error(transparent)]
    Project(#[from] crate::project::ProjectError),
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    #[error(transparent)]
    Remote(RemoteError),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
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
    /// A public file repeats bytes that were sealed before (the private file
    /// was renamed, deleted, or reclassified). Declassify the path to allow it.
    #[error(
        "these public files contain bytes that were private before; pass --declassify <path> for each one you really mean to publish: {}",
        join_paths(paths)
    )]
    PreviouslyPrivate { paths: Vec<RepoPath> },
    /// A `!` rule makes a path public that has not been confirmed.
    #[error(
        "a negation makes these paths public; confirm them: {}",
        join_paths(paths)
    )]
    NegationNeedsConfirmation { paths: Vec<RepoPath> },
    /// The remote bookmark is not an ancestor of this revision.
    #[error(
        "remote `{bookmark}` has changes you have not fetched; run `tig fetch`, merge, and publish again"
    )]
    NotFastForward { bookmark: String },
    /// Eight head commits in a row lost the race.
    #[error("the remote is busy; another publish landed on every attempt")]
    Busy,
    #[error("{0}")]
    Invalid(String),
}

impl From<RemoteError> for PublishError {
    fn from(error: RemoteError) -> Self {
        match error {
            RemoteError::Busy(_) => Self::Busy,
            other => Self::Remote(other),
        }
    }
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
    /// Publish these paths in the clear even though their bytes were sealed
    /// before (an explicit, per-path declassification).
    pub declassify: BTreeSet<RepoPath>,
    /// Move the bookmark even when it is not a fast-forward.
    pub force: bool,
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
    /// Accepted role-policy prefix; ownership transfer cannot be omitted later.
    pub policy_checkpoint: Option<crate::keyring::PolicyCheckpoint>,
    pub revisions: BTreeMap<ObjectId, ObjectId>,
    /// Every file path published as public to this remote, plus Git exposure
    /// evidence seeded by import before the first publish. This evidence alone
    /// does not bind an otherwise unused state to an owner or remote.
    pub ever_public: BTreeSet<RepoPath>,
    pub confirmed_negations: BTreeSet<RepoPath>,
    /// Wire ids already sent, per group and epoch.
    pub sent: BTreeMap<(String, u64), BTreeSet<WireId>>,
    /// Every non-empty blob ever sealed to this remote (local only). Those
    /// bytes may not reappear in a public file unless declassified, even
    /// after the private file was renamed or deleted.
    pub ever_private: BTreeSet<ObjectId>,
    /// Blobs the user explicitly declassified with `declassify`.
    pub declassified: BTreeSet<ObjectId>,
    /// Highest publish manifest sequence seen or written (rollback floor).
    pub manifest_seq: u64,
    /// Public disclosures cannot be omitted by a later signed head.
    pub revealed: BTreeSet<ObjectId>,
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
            policy_checkpoint: None,
            revisions: BTreeMap::new(),
            ever_public: BTreeSet::new(),
            confirmed_negations: BTreeSet::new(),
            sent: BTreeMap::new(),
            ever_private: BTreeSet::new(),
            declassified: BTreeSet::new(),
            manifest_seq: 0,
            revealed: BTreeSet::new(),
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
        w.u8(if self.policy_checkpoint.is_some() || !self.revealed.is_empty() { VERSION } else { 4 });
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
        write_ids(&mut w, &self.ever_private)?;
        write_ids(&mut w, &self.declassified)?;
        w.varint(self.manifest_seq);
        if self.policy_checkpoint.is_some() || !self.revealed.is_empty() {
            match self.policy_checkpoint {
                Some(checkpoint) => {
                    w.u8(1);
                    w.varint(checkpoint.transitions);
                    w.buf.extend_from_slice(&checkpoint.digest);
                }
                None => w.u8(0),
            }
            write_ids(&mut w, &self.revealed)?;
        }
        Ok(w.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PublishError> {
        let mut r = Reader::new(bytes, "publish state");
        let version = r.u8()?;
        if !(1..=VERSION).contains(&version) {
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
        // Version 1 predates historical private-blob tracking.
        let (ever_private, declassified) = if version >= 2 {
            (read_ids(&mut r)?, read_ids(&mut r)?)
        } else {
            (BTreeSet::new(), BTreeSet::new())
        };
        // Version 3 adds the manifest floor.
        let manifest_seq = if version >= 3 { r.varint()? } else { 0 };
        let (policy_checkpoint, revealed) = if version >= 5 {
            let checkpoint = match r.u8()? {
                0 => None,
                1 => Some(crate::keyring::PolicyCheckpoint { transitions: r.varint()?, digest: read_array(&mut r)? }),
                _ => return Err(PublishError::Invalid("invalid policy checkpoint flag".into())),
            };
            (checkpoint, read_ids(&mut r)?)
        } else { (None, BTreeSet::new()) };
        r.finish()?;
        // Earlier projections used the narrower embedded-** privacy policy.
        // Keep exposure evidence and rollback floors, but reclassify history.
        if version < 4 {
            revisions.clear();
        }
        Ok(PublishState {
            remote_id,
            owner_signing,
            counter,
            policy_checkpoint,
            revisions,
            ever_public,
            confirmed_negations,
            sent,
            ever_private,
            declassified,
            manifest_seq,
            revealed,
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
    /// Public metadata: published as-is with the public revision.
    description: String,
}

struct Session {
    epoch_keys: BTreeMap<String, EpochKey>,
    frozen: BTreeSet<String>,
    edit_rules: bool,
    counter: u64,
    pin: [u8; 32],
    /// Keyring not yet written. Held until refusal checks have passed.
    fresh: Option<Keyring>,
    /// The verified keyring (or `fresh`), for manifest signers.
    keyring: Keyring,
}

/// Publishes `rev` and its unpublished ancestors to `remote` under `bookmark`.
///
/// The first call on an empty remote (no keyring) makes `identity` the owner
/// and pins that signing key. The caller must pass keys it already saved,
/// whose remote id matches (see the module docs). Later
/// calls check the pinned key and `state.counter`, then encrypt with a saved
/// owner key, or a verified role/member grant. Only simple mode requires the
/// original owner's private-group epoch key to remain locally saved. See
/// [`crate::keyring::VerifiedKeyring::current_key`].
///
/// On `Err`, `state` is unchanged. Refusal checks and the fast-forward check
/// run before the first `put_batch` or `put_pack`, so a refusal on the first
/// attempt uploads nothing. A lost `commit_head` race can leave
/// content-addressed objects and a pack that no manifest names, even if a
/// later attempt refuses. The bookmark does not move until `commit_head`
/// returns [`CommitOutcome::Committed`]. Every attempt verifies the head
/// against the highest keyring counter and manifest sequence seen so far, so
/// a remote cannot roll back between attempts.
///
/// A move that is a fast-forward only through predecessors (a rewrite of
/// published history) succeeds with a warning naming each replaced change.
///
/// `fetched` is the other half of this remote's correspondence: an internal
/// revision rebuilt by fetch is already published under that public id.
#[allow(clippy::too_many_arguments)]
pub fn publish(
    store: &dyn Store,
    remote: &dyn Remote,
    identity: &Identity,
    owner_keys: Option<&OwnerKeys>,
    state: &mut PublishState,
    fetched: &FetchState,
    bookmark: &str,
    rev: ObjectId,
    options: &PublishOptions,
) -> Result<PublishReport, PublishError> {
    if bookmark.is_empty() || bookmark.len() > MAX_BOOKMARK {
        return Err(PublishError::Invalid("invalid bookmark".into()));
    }
    let mut pin = saved_pin(state, remote.remote_id())?;
    if let Some(fetched_pin) = fetched.owner_signing {
        if fetched.remote_id != remote.remote_id() || pin.is_some_and(|pin| pin != fetched_pin) {
            return Err(PublishError::Invalid(
                "fetch and publish state disagree about the remote owner".into(),
            ));
        }
        pin = Some(fetched_pin);
    } else if fetched.counter != 0 || fetched.manifest_seq != 0 || !fetched.revisions.is_empty() || fetched.policy_checkpoint.is_some() {
        return Err(PublishError::Invalid(
            "fetch state is missing its owner pin".into(),
        ));
    }
    let mut prep: Option<Prep> = None;
    let mut prep_keyring = None;
    let mut prep_changes = None;
    let mut next_head = None;
    let mut history = PublicHistory::default();
    let mut ever_public = state.ever_public.clone();
    let mut checked = None;
    let local_ids = local_of_public(state, fetched);
    // Rollback floors for this call. Local state moves only after a commit.
    let mut counter_floor = state.counter.max(fetched.counter);
    let mut policy_floor = None;
    let mut revealed_floor: BTreeSet<_> = state.revealed.union(&fetched.revealed).copied().collect();
    let mut sequence_floor = state.manifest_seq.max(fetched.manifest_seq);
    for _ in 0..PUBLISH_ATTEMPTS {
        let head = match next_head.take() {
            Some(head) => head,
            None => remote.read_head()?,
        };
        let session = open_session(
            remote.remote_id(),
            head.keyring.as_deref(),
            identity,
            owner_keys,
            pin,
            counter_floor,
        )?;
        session.keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
        session.keyring.verify_policy_checkpoint(fetched.policy_checkpoint.as_ref())?;
        session.keyring.verify_policy_checkpoint(policy_floor.as_ref())?;
        policy_floor = session.keyring.policy_checkpoint();
        counter_floor = counter_floor.max(session.counter);
        if session.fresh.is_none() {
            pin = Some(session.pin);
        }
        let previous = read_manifest(
            remote.remote_id(),
            head.manifest.as_deref(),
            &session.keyring,
            sequence_floor,
        )?;
        if revealed_floor.iter().any(|id| !previous.as_ref().is_some_and(|manifest| manifest.reveals.contains_key(id))) {
            return Err(PublishError::Invalid("the remote omitted a previously accepted reveal".into()));
        }
        if let Some(manifest) = &previous { revealed_floor.extend(manifest.reveals.keys().copied()); }
        let reuse = prep.as_ref().is_some_and(|prep| {
            prep.counter == session.counter && prep_keyring == head.keyring
                && prep_changes.as_ref().map(|(changes, reveals)| (changes, reveals))
                    == previous.as_ref().map(|manifest| (&manifest.changes, &manifest.reveals))
        });
        if !reuse {
            prep = Some(project(store, remote.public_store(), &session, state, fetched, rev, previous.as_ref())?);
            prep_keyring = head.keyring.clone();
            prep_changes = previous.as_ref().map(|manifest| (manifest.changes.clone(), manifest.reveals.clone()));
        }
        if let Some(manifest) = &previous {
            sequence_floor = sequence_floor.max(manifest.sequence);
        }
        let mut refs = match &previous {
            Some(manifest) => manifest.refs.clone(),
            None => remote.read_legacy_refs()?.unwrap_or_default(),
        };
        let paths_changed = remote_public_paths(remote.public_store(), &refs, &mut history)?;
        let reveal_paths_changed = revealed_public_paths(store, remote, &local_ids, previous.as_ref(),
            &session.keyring.policy_snapshot()?.current_owner.signing, &mut history)?;
        let paths_changed = paths_changed || reveal_paths_changed;
        if paths_changed {
            ever_public.extend(history.paths.iter().cloned());
        }
        if !reuse || checked.is_none() || paths_changed {
            checked = Some(check_refusals(
                store,
                state,
                &ever_public,
                &prep.as_ref().expect("projection was just built").plans,
                options,
            )?);
        }
        let tip = public_parent(
            &prep.as_ref().expect("projection was just built").public_ids,
            rev,
        )?;
        let rewrites = ensure_fast_forward(
            store,
            rev,
            bookmark,
            refs.get(bookmark).copied(),
            tip,
            &local_ids,
            options.force,
        )?;
        {
            let prep = prep.as_mut().expect("projection was just built");
            if !prep.uploaded {
                if let Err(error) = upload(store, remote, prep) {
                    // The remote refuses a pack for an epoch a revoke just
                    // replaced. Start over under the new keyring.
                    if remote.read_head()?.keyring != head.keyring {
                        continue;
                    }
                    return Err(error);
                }
                prep.uploaded = true;
            }
        }
        let prep = prep.as_ref().expect("projection was just built");
        refs.insert(bookmark.to_string(), tip);
        let mut packs = previous.as_ref().map(|m| m.packs.clone()).unwrap_or_default();
        for pack in &prep.packs {
            packs.entry(pack.id).or_insert_with(|| pack.entry.clone());
        }
        let sequence = previous
            .as_ref()
            .map_or(0, |m| m.sequence)
            .max(sequence_floor)
            .checked_add(1)
            .ok_or_else(|| PublishError::Invalid("manifest sequence overflow".into()))?;
        let manifest = Manifest::signed_with_changes(
            remote.remote_id(), sequence, refs, packs,
            previous.as_ref().map(|m| m.changes.clone()).unwrap_or_default(),
            previous.as_ref().map(|m| m.reveals.clone()).unwrap_or_default(),
            identity,
        )?.encode()?;
        let fresh = match &session.fresh {
            Some(keyring) => Some(keyring.encode()?),
            None => None,
        };
        match remote.commit_head(&head.version(), fresh.as_deref(), Some(&manifest))? {
            CommitOutcome::Stale(current) => {
                // The next attempt verifies this head (pin and counter floor).
                // A changed counter restarts projection under the new epoch.
                next_head = Some(current);
                continue;
            }
            CommitOutcome::Committed(_) => {
                let checked = checked.expect("refusal checks passed before upload");
                state.remote_id = remote.remote_id();
                state.owner_signing = Some(session.pin);
                state.counter = session.counter;
                state.policy_checkpoint = session.keyring.policy_checkpoint();
                for plan in &prep.plans {
                    let public_id = prep.public_ids[&plan.internal];
                    state.revisions.insert(plan.internal, public_id);
                }
                ever_public.extend(checked.new_public);
                state.ever_public = ever_public;
                state.confirmed_negations.extend(checked.confirmed);
                state.ever_private.extend(checked.new_private);
                state.declassified.extend(checked.new_declassified);
                state.manifest_seq = sequence;
                state.revealed = revealed_floor;
                for (context, wires) in &prep.new_wires {
                    state.sent.entry(context.clone()).or_default().extend(wires);
                }
                return Ok(PublishReport {
                    revisions_published: prep.plans.len(),
                    public_objects_written: prep.written,
                    private_objects_sealed: prep.sealed_objects,
                    sealed_roots: prep.sealed_roots,
                    new_owner_keys: None,
                    warnings: {
                        let mut warnings = rewrites;
                        warnings.extend(checked.warnings);
                        warnings.extend(prep.metadata_warnings.iter().cloned());
                        let compatibility: BTreeSet<_> = prep
                            .plans
                            .iter()
                            .flat_map(|plan| plan.projection.warnings.iter().cloned())
                            .collect();
                        warnings.extend(compatibility);
                        warnings
                    },
                });
            }
        }
    }
    Err(PublishError::Busy)
}

struct PackUpload {
    id: [u8; 32],
    entry: PackEntry,
    local: ObjectId,
}

struct Prep {
    plans: Vec<Plan>,
    metadata_warnings: Vec<String>,
    public_ids: BTreeMap<ObjectId, ObjectId>,
    packs: Vec<PackUpload>,
    new_wires: BTreeMap<(String, u64), BTreeSet<WireId>>,
    objects: Vec<(ObjectId, ObjectKind, usize)>,
    uploaded: bool,
    written: usize,
    sealed_objects: usize,
    sealed_roots: usize,
    counter: u64,
}

/// Projects and spools locally. Only bounded batches hold transfer bodies.
fn project(
    store: &dyn Store,
    public: &dyn Store,
    session: &Session,
    state: &PublishState,
    fetched: &FetchState,
    rev: ObjectId,
    manifest: Option<&Manifest>,
) -> Result<Prep, PublishError> {
    let known = published_ids(state, fetched);
    let ancestors = parent_first(store, &[rev], |id| {
        id == root_revision_id() || known.contains_key(&id)
    })?;
    let keys = session.epoch_keys.iter().map(|(group, key)| (group.clone(), key)).collect();
    let embargoed = embargoed_content(store, state, fetched, manifest)?;
    let mut plans = Vec::with_capacity(ancestors.len());
    let mut outbox = Outbox::new(store, public);
    write_canonical(&mut outbox, &Object::Tree(Tree::empty()))?;
    write_canonical(&mut outbox, &Object::Revision(root_revision()))?;
    let mut public_ids = known;
    let rules = RepoPath::new(crate::project::RULES_FILE)?;
    for internal in ancestors {
        let revision = store.get_revision(&internal)?;
        if !session.edit_rules {
            let current = tig_core::treeops::lookup(store, &revision.tree, &rules)?;
            if revision.parents.is_empty() && current.is_some() {
                return Err(PublishError::Invalid("changing .private requires EDIT_PRIVATE".into()));
            }
            for parent in &revision.parents {
                let parent = store.get_revision(parent)?;
                if tig_core::treeops::lookup(store, &parent.tree, &rules)? != current {
                    return Err(PublishError::Invalid("changing .private requires EDIT_PRIVATE".into()));
                }
            }
        }
        if manifest.is_some_and(|manifest| manifest.changes.values().any(|entry| entry.change_id == revision.change_id)) {
            return Err(PublishError::Invalid("a sealed change is immutable; start a new change instead of rewriting it".into()));
        }
        let parents = revision.parents.iter().map(|id| public_parent(&public_ids, *id)).collect::<Result<Vec<_>, _>>()?;
        let mut projected_source = revision.clone();
        if revision.parents != parents && has_embargoed_ancestor(store, &revision.parents, &public_ids, manifest)? {
            projected_source = rebase_revision(store, &revision, parents.clone())?;
            let restored = rebase_revision(store, &projected_source, revision.parents.clone())?;
            if restored.tree != revision.tree {
                return Err(PublishError::Invalid("this descendant changes an embargoed fix; seal it separately or reveal its parent first".into()));
            }
            if revision.parents.len() == 1 && manifest.is_some_and(|manifest| manifest.changes.contains_key(&parents[0])) {
                let manifest = manifest.expect("private parent has a manifest");
                let opened = store.get_revision(&revision.parents[0])?;
                let child = public_revision(&revision, projected_source.tree, parents.clone());
                crate::changes::descendant_public_bytes(&crate::changes::DescendantCheck {
                    store, manifest, skeleton_id: parents[0], opened_id: revision.parents[0],
                    opened: &opened, child: &child, upgraded: &revision,
                }).map_err(|error| PublishError::Invalid(format!("private descendant does not preserve its public projection: {error}")))?;
            }
        }
        let projection = project_grouped(store, &projected_source.tree, &keys)?;
        for (path, leaf) in &projection.public_files {
            if leaf.is_file_like() && leak_ids(store, &leaf.id())?.iter().any(|id| embargoed.contains(id)) {
                return Err(PublishError::Invalid(format!("{path} repeats an unrevealed private change; only an owner reveal can release those bytes")));
            }
        }
        for root in &projection.sealed {
            let group = access_group(&root.readers);
            if session.frozen.contains(&group) {
                return Err(PublishError::Invalid(format!("group `{group}` must be rotated after removing readers")));
            }
        }
        let public_rev = public_revision(&revision, projection.public_tree, parents);
        write_public_tree(store, &mut outbox, &projection.public_tree)?;
        let obj = Object::Revision(public_rev);
        let public_id = obj.id();
        write_canonical(&mut outbox, &obj)?;
        public_ids.insert(internal, public_id);
        plans.push(Plan { internal, projection, description: revision.description });
    }
    let mut packs = Vec::new();
    let mut new_wires = BTreeMap::new();
    let mut sealed_objects = 0;
    let mut sealed_roots = 0;
    for (group, key) in &session.epoch_keys {
        let (objects, roots, wires) = build_pack(store, key, state, &plans, &mut packs)?;
        sealed_objects += objects;
        sealed_roots += roots;
        if !wires.is_empty() { new_wires.insert((group.clone(), key.context().epoch), wires); }
    }
    let metadata_warnings = metadata_mentions(store, &plans)?;
    Ok(Prep {
        plans, metadata_warnings, public_ids, packs, new_wires,
        objects: outbox.pending, uploaded: false, written: 0,
        sealed_objects, sealed_roots, counter: session.counter,
    })
}

/// Reuse authenticated local correspondence; ciphertext and keys never enter the outbox.
fn embargoed_content(
    store: &dyn Store,
    state: &PublishState,
    fetched: &FetchState,
    manifest: Option<&Manifest>,
) -> Result<BTreeSet<ObjectId>, PublishError> {
    let Some(manifest) = manifest.filter(|manifest| !manifest.changes.is_empty()) else {
        return Ok(BTreeSet::new());
    };
    let local = local_of_public(state, fetched);
    let mut hidden = BTreeSet::new();
    for (public, _) in manifest.changes.iter().filter(|(id, _)| !manifest.reveals.contains_key(id)) {
        let Some(internal) = local.get(public) else { continue; };
        let revision = store.get_revision(internal)?;
        let baseline = store.get_revision(public)?;
        let mut public_content = BTreeSet::new();
        for (_, leaf) in tig_core::treeops::walk(store, &baseline.tree, &RepoPath::root())? {
            if leaf.is_file_like() { public_content.extend(leak_ids(store, &leaf.id())?); }
        }
        for (_, leaf) in tig_core::treeops::walk(store, &revision.tree, &RepoPath::root())? {
            if leaf.is_file_like() {
                hidden.extend(leak_ids(store, &leaf.id())?.into_iter().filter(|id| !public_content.contains(id)));
            }
        }
    }
    Ok(hidden)
}

fn has_embargoed_ancestor(
    store: &dyn Store,
    parents: &[ObjectId],
    public_ids: &BTreeMap<ObjectId, ObjectId>,
    manifest: Option<&Manifest>,
) -> Result<bool, PublishError> {
    let Some(manifest) = manifest.filter(|manifest| !manifest.changes.is_empty()) else {
        return Ok(false);
    };
    let mut pending = parents.to_vec();
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        let public = public_ids.get(&id).unwrap_or(&id);
        if manifest.changes.contains_key(public) && !manifest.reveals.contains_key(public) { return Ok(true); }
        if id != root_revision_id() && seen.insert(id) {
            if seen.len() > MAX_HISTORY { return Err(PublishError::Invalid("history is too long to publish".into())); }
            pending.extend(store.get_revision(&id)?.parents);
        }
    }
    Ok(false)
}

fn upload(store: &dyn Store, remote: &dyn Remote, prep: &mut Prep) -> Result<(), PublishError> {
    let mut written = 0usize;
    let mut start = 0usize;
    while start < prep.objects.len() {
        let mut end = start;
        let mut bytes = 0usize;
        while end < prep.objects.len() && end - start < BATCH_OBJECTS {
            let next = prep.objects[end].2;
            if end > start && bytes.saturating_add(next) > BATCH_BYTES { break; }
            bytes = bytes.saturating_add(next);
            end += 1;
        }
        let chunk = &prep.objects[start..end];
        let ids: Vec<ObjectId> = chunk.iter().map(|(id, _, _)| *id).collect();
        let asked: BTreeSet<ObjectId> = ids.iter().copied().collect();
        let mut missing = BTreeSet::new();
        for id in remote.missing(&ids)? {
            if !asked.contains(&id) || !missing.insert(id) {
                return Err(PublishError::Invalid(format!("the remote listed {id} as missing, which was not asked or was listed twice")));
            }
        }
        let mut send = Vec::new();
        for (id, kind, _) in chunk {
            if missing.contains(id) {
                let (stored, body) = store.get_raw(id)?.ok_or(tig_core::Error::NotFound(*id))?;
                if stored != *kind { return Err(PublishError::Invalid("spooled public object has the wrong kind".into())); }
                send.push((*id, *kind, body));
            }
        }
        written += send.len();
        if !send.is_empty() { remote.put_batch(&send)?; }
        start = end;
    }
    for pack in &prep.packs {
        let bytes = store.get_kind(&pack.local, ObjectKind::Blob)?;
        remote.put_pack(&bytes)?;
    }
    prep.written = written;
    Ok(())
}

fn published_ids(state: &PublishState, fetched: &FetchState) -> BTreeMap<ObjectId, ObjectId> {
    let mut ids = state.revisions.clone();
    for (public, internal) in &fetched.revisions {
        ids.entry(*internal).or_insert(*public);
    }
    ids
}

fn local_of_public(state: &PublishState, fetched: &FetchState) -> BTreeMap<ObjectId, ObjectId> {
    let mut map = fetched.revisions.clone();
    for (internal, public) in &state.revisions {
        map.entry(*public).or_insert(*internal);
    }
    map
}

/// Checks the move of `bookmark` from the remote's `old` public target to
/// `rev` (DESIGN.md "Collaboration", rule 2) and returns its warnings.
///
/// `old` must map to a local revision this machine published or fetched. A
/// parent ancestor of `rev` is a plain fast-forward. Otherwise the move
/// rewrites published history: every published revision it drops from the
/// bookmark's history (`old` and its parents that `rev` does not reach) must
/// be replaced, that is reachable from the new history through predecessor
/// links only. Rewriting or squashing a published change passes with a
/// warning naming it; dropping an unreplaced published parent, or abandoning
/// anything published, is refused like any other non-fast-forward.
fn ensure_fast_forward(
    store: &dyn Store,
    rev: ObjectId,
    bookmark: &str,
    old: Option<ObjectId>,
    new_public: ObjectId,
    local_of_public: &BTreeMap<ObjectId, ObjectId>,
    force: bool,
) -> Result<Vec<String>, PublishError> {
    let Some(old) = old else {
        return Ok(Vec::new());
    };
    if old == new_public || old == root_revision_id() || force {
        return Ok(Vec::new());
    }
    let refuse = || PublishError::NotFastForward {
        bookmark: bookmark.to_string(),
    };
    let Some(local) = local_of_public.get(&old).copied() else {
        return Err(refuse());
    };
    let (kept, predecessors) = parent_ancestors(store, rev, local)?;
    if kept.contains(&local) {
        return Ok(Vec::new());
    }
    let dropped = dropped_revisions(store, local, &kept)?;
    if !all_replaced(store, predecessors, &dropped)? {
        return Err(refuse());
    }
    let mut changes = BTreeSet::new();
    for id in &dropped {
        changes.insert(store.get_revision(id)?.change_id.short(8));
    }
    Ok(changes
        .into_iter()
        .map(|change| {
            format!(
                "rewrites published change `{change}`; collaborators who built on it must rebase"
            )
        })
        .collect())
}

/// `rev` and its parent ancestors, nearest first, stopping early at `stop`,
/// plus the predecessors those revisions name.
fn parent_ancestors(
    store: &dyn Store,
    rev: ObjectId,
    stop: ObjectId,
) -> Result<(BTreeSet<ObjectId>, Vec<ObjectId>), PublishError> {
    let mut seen = BTreeSet::from([rev]);
    let mut queue = VecDeque::from([rev]);
    let mut predecessors = Vec::new();
    let mut edges = 0usize;
    while let Some(id) = queue.pop_front() {
        if id == stop {
            break;
        }
        let revision = store.get_revision(&id)?;
        edges = edges
            .saturating_add(revision.parents.len())
            .saturating_add(revision.predecessors.len());
        if edges > MAX_HISTORY {
            return Err(PublishError::Invalid(
                "history is too long to publish".into(),
            ));
        }
        predecessors.extend(revision.predecessors.iter().copied());
        for parent in &revision.parents {
            if seen.insert(*parent) {
                queue.push_back(*parent);
            }
        }
        if seen.len() > MAX_HISTORY {
            return Err(PublishError::Invalid(
                "history is too long to publish".into(),
            ));
        }
    }
    Ok((seen, predecessors))
}

/// `old` and its parent ancestors that are not in `kept`.
fn dropped_revisions(
    store: &dyn Store,
    old: ObjectId,
    kept: &BTreeSet<ObjectId>,
) -> Result<BTreeSet<ObjectId>, PublishError> {
    let mut dropped = BTreeSet::new();
    let mut stack = vec![old];
    let mut edges = 0usize;
    while let Some(id) = stack.pop() {
        if kept.contains(&id) || !dropped.insert(id) {
            continue;
        }
        if dropped.len() > MAX_HISTORY {
            return Err(PublishError::Invalid(
                "history is too long to publish".into(),
            ));
        }
        let parents = store.get_revision(&id)?.parents;
        edges = edges.saturating_add(parents.len());
        if edges > MAX_HISTORY {
            return Err(PublishError::Invalid(
                "history is too long to publish".into(),
            ));
        }
        stack.extend(parents);
    }
    Ok(dropped)
}

/// Whether every revision in `dropped` is reached from `start` through
/// predecessor links only. A walk past the history bound proves nothing, so
/// it answers no.
fn all_replaced(
    store: &dyn Store,
    start: Vec<ObjectId>,
    dropped: &BTreeSet<ObjectId>,
) -> Result<bool, PublishError> {
    let mut left = dropped.clone();
    let mut seen = BTreeSet::new();
    // Nearest first: the usual edit replaces the tip's own earlier snapshot.
    let mut stack: Vec<ObjectId> = start.into_iter().rev().collect();
    let mut edges = stack.len();
    while let Some(id) = stack.pop() {
        if left.remove(&id) && left.is_empty() {
            return Ok(true);
        }
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > MAX_HISTORY {
            return Ok(false);
        }
        // A predecessor this store does not have ends that chain.
        if store.has(&id)? {
            let predecessors = store.get_revision(&id)?.predecessors;
            edges = edges.saturating_add(predecessors.len());
            if edges > MAX_HISTORY {
                return Ok(false);
            }
            stack.extend(predecessors);
        }
    }
    Ok(left.is_empty())
}

/// The metadata exception (DESIGN.md "Privacy"): `.private` and change
/// descriptions are public, so they can name what a sealed folder hides.
/// Warns (never refuses) when they mention a name found only inside a
/// sealed root. Names under 4 characters are skipped as noise.
fn metadata_mentions(store: &dyn Store, plans: &[Plan]) -> Result<Vec<String>, PublishError> {
    let mut hidden = BTreeSet::new();
    let mut public_text = String::new();
    for plan in plans {
        hidden.extend(crate::project::names_hidden_inside(
            plan.projection.sealed.iter().map(|root| &root.path),
            &plan.projection.private_files,
        ));
        public_text.push_str(&plan.description);
        public_text.push('\n');
        for (path, leaf) in &plan.projection.public_files {
            if path.as_str() == crate::project::RULES_FILE && leaf.is_file_like() {
                public_text.push_str(&String::from_utf8_lossy(&store.get_blob(&leaf.id())?));
                public_text.push('\n');
            }
        }
    }
    Ok(crate::project::metadata_mention_warning(&hidden, &public_text, "published")
        .into_iter()
        .collect())
}

/// The remote's manifest, verified against `keyring`. Missing is fine only
/// for a state that has never seen one (a new or pre-manifest remote).
fn read_manifest(
    remote_id: [u8; 16],
    bytes: Option<&[u8]>,
    keyring: &Keyring,
    min_sequence: u64,
) -> Result<Option<Manifest>, PublishError> {
    match bytes {
        Some(bytes) => {
            let manifest = Manifest::decode(bytes)?;
            manifest.verify(remote_id, keyring, min_sequence)?;
            Ok(Some(manifest))
        }
        None if min_sequence > 0 => Err(PublishError::Invalid(
            "the remote's publish manifest is missing, but this state has seen one".into(),
        )),
        None => Ok(None),
    }
}

fn open_session(
    remote_id: [u8; 16],
    keyring_bytes: Option<&[u8]>,
    identity: &Identity,
    owner_keys: Option<&OwnerKeys>,
    saved_pin: Option<[u8; 32]>,
    counter_floor: u64,
) -> Result<Session, PublishError> {
    match keyring_bytes {
        None => {
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
            let epoch_key = owner_epoch_key(saved, remote_id, PRIVATE_GROUP, 1)?;
            Ok(Session {
                epoch_keys: BTreeMap::from([(PRIVATE_GROUP.into(), epoch_key)]),
                frozen: BTreeSet::new(),
                edit_rules: true,
                counter: keyring.head.counter,
                pin,
                keyring: keyring.clone(),
                fresh: Some(keyring),
            })
        }
        Some(bytes) => {
            let keyring = Keyring::decode(bytes)?;
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
            let verified = keyring.verify(&pin, counter_floor)?;
            if !crate::manifest::allowed_signers(&keyring).contains(&identity.public().signing) {
                if keyring.policy.is_empty() { return Err(KeyringError::NotMember.into()); }
                return Err(PublishError::Invalid("this identity does not have publish permission".into()));
            }
            let edit_rules = keyring.policy.is_empty() || verified.snapshot().has(&identity.public(), crate::roles::EDIT_PRIVATE);
            let mut epoch_keys = BTreeMap::new();
            let mut frozen = BTreeSet::new();
            for (group, epoch) in &keyring.head.epochs {
                if !verified.reads_now(&identity.public(), group) { continue; }
                if verified.group_frozen(group) { frozen.insert(group.clone()); }
                let local_owner = identity.public() == keyring.owner
                    && verified.snapshot().is_current_owner(&identity.public().signing);
                let saved = owner_keys.filter(|keys| keys.keys.contains_key(&(group.clone(), *epoch)));
                let key = if local_owner && (saved.is_some() || (group == PRIVATE_GROUP && keyring.policy.is_empty())) {
                    let keys = saved.ok_or_else(|| PublishError::Invalid("the owner must pass local epoch keys; they are not read from the remote".into()))?;
                    let key = owner_epoch_key(keys, remote_id, group, *epoch)?;
                    keyring.check_owner_key(&key)?;
                    key
                } else {
                    verified.current_key(group, identity)?
                };
                epoch_keys.insert(group.clone(), key);
            }
            Ok(Session {
                epoch_keys,
                frozen,
                edit_rules,
                counter: verified.counter(),
                pin,
                fresh: None,
                keyring,
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
                && state.sent.is_empty()
                && state.policy_checkpoint.is_none()
                && state.revealed.is_empty();
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
    group: &str,
    epoch: u64,
) -> Result<EpochKey, PublishError> {
    if keys.remote != remote_id {
        return Err(PublishError::Invalid(
            "owner keys are for a different remote".into(),
        ));
    }
    let stored = keys
        .keys
        .get(&(group.to_string(), epoch))
        .ok_or_else(|| PublishError::Invalid("owner has no key for this epoch".into()))?;
    let expect = stored.context();
    if expect.remote != remote_id || expect.group != group || expect.epoch != epoch {
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
        if colors.len() > MAX_HISTORY {
            return Err(PublishError::Invalid(
                "history is too long to publish".into(),
            ));
        }
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
    /// Non-empty private blobs of this publish, to remember.
    new_private: BTreeSet<ObjectId>,
    /// Blobs declassified in this publish.
    new_declassified: BTreeSet<ObjectId>,
}

/// A different publisher or branch may have exposed a path before this
/// caller's state existed. Include the remote's reachable public history.
#[derive(Default)]
struct PublicHistory {
    revisions: BTreeSet<ObjectId>,
    trees: BTreeSet<(ObjectId, RepoPath)>,
    paths: BTreeSet<RepoPath>,
    entries: usize,
    revealed: BTreeSet<ObjectId>,
}

fn revealed_public_paths(
    store: &dyn Store,
    remote: &dyn Remote,
    local_ids: &BTreeMap<ObjectId, ObjectId>,
    manifest: Option<&Manifest>,
    current_owner: &[u8; 32],
    history: &mut PublicHistory,
) -> Result<bool, PublishError> {
    let Some(manifest) = manifest else { return Ok(false); };
    let mut changed = false;
    for id in manifest.reveals.keys().filter(|id| !history.revealed.contains(id)) {
        let local = local_ids.get(id).map(|id| store.get_revision(id)).transpose()?;
        let baseline = remote.public_store().get_revision(id)?;
        let paths = if let Some(local) = local.filter(|local| local.tree != baseline.tree) {
            crate::project::classify_with_roles(store, &local.tree)?.public_files.into_iter()
                .filter(|(_, leaf)| leaf.is_file_like()).map(|(path, _)| path).collect()
        } else {
            crate::changes::revealed_paths(remote, manifest, id, current_owner)
                .map_err(|error| PublishError::Invalid(error.to_string()))?
        };
        for path in paths { changed |= history.paths.insert(path); }
    }
    history.revealed.extend(manifest.reveals.keys().copied());
    Ok(changed)
}

/// Extends this call's exposure evidence, reading only newly reachable history.
/// The prefix is part of the tree cache key: one subtree can appear at several paths.
fn remote_public_paths(
    store: &dyn Store,
    refs: &BTreeMap<String, ObjectId>,
    history: &mut PublicHistory,
) -> Result<bool, PublishError> {
    let tips: Vec<_> = refs.values().copied().collect();
    let revisions = parent_first(store, &tips, |id| {
        id == root_revision_id() || history.revisions.contains(&id)
    })?;
    if history.revisions.len().saturating_add(revisions.len()) > MAX_HISTORY {
        return Err(PublishError::Invalid(
            "history is too long to publish".into(),
        ));
    }
    let mut changed = false;
    for id in revisions {
        let mut stack = vec![(store.get_revision(&id)?.tree, RepoPath::root(), 0usize)];
        while let Some((tree, prefix, depth)) = stack.pop() {
            if depth > MAX_TREE_DEPTH {
                return Err(PublishError::Invalid("remote tree is too deep".into()));
            }
            if !history.trees.insert((tree, prefix.clone())) {
                continue;
            }
            for entry in store.get_tree(&tree)?.entries() {
                history.entries += 1;
                if history.entries > MAX_PATHS {
                    return Err(PublishError::Invalid(
                        "remote history has too many paths".into(),
                    ));
                }
                let path = prefix.join(entry.name())?;
                if entry.kind() == EntryKind::Tree {
                    stack.push((entry.id(), path, depth + 1));
                } else if entry.kind().is_file_like() {
                    changed |= history.paths.insert(path);
                }
            }
        }
        history.revisions.insert(id);
    }
    Ok(changed)
}

fn check_refusals(
    store: &dyn Store,
    state: &PublishState,
    ever_public: &BTreeSet<RepoPath>,
    plans: &[Plan],
    options: &PublishOptions,
) -> Result<Checked, PublishError> {
    let empty = empty_blob();
    // Everything private in this batch plus everything ever sealed to this
    // remote: a rename or delete inside an unpublished window, or after an
    // earlier publish, must not let those bytes out.
    let mut new_private = BTreeSet::new();
    for plan in plans {
        for (_, leaf) in &plan.projection.private_files {
            if leaf.is_file_like() && leaf.id() != empty {
                new_private.extend(leak_ids(store, &leaf.id())?);
            }
        }
    }
    let mut previously_private = BTreeSet::new();
    let mut new_declassified = BTreeSet::new();
    for plan in plans {
        for (path, leaf) in &plan.projection.public_files {
            let id = leaf.id();
            if !leaf.is_file_like() || id == empty { continue; }
            let ids = leak_ids(store, &id)?;
            if ids.iter().any(|id| !state.declassified.contains(id) && (new_private.contains(id) || state.ever_private.contains(id))) {
                if options.declassify.contains(path) {
                    new_declassified.extend(ids);
                } else {
                    previously_private.insert(path.clone());
                }
            }
        }
    }
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
        pastes.extend(pastes_in(store, &plan.projection, empty)?);
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
    // After the rule-level question: confirming a negation makes a path
    // public going forward; it never declassifies bytes that were sealed.
    if !previously_private.is_empty() {
        return Err(PublishError::PreviouslyPrivate {
            paths: previously_private.into_iter().collect(),
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
        new_private,
        new_declassified,
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

fn pastes_in(store: &dyn Store, projection: &Projection, empty: ObjectId) -> Result<BTreeSet<Paste>, PublishError> {
    let mut private_blobs: BTreeMap<ObjectId, RepoPath> = BTreeMap::new();
    for (path, leaf) in &projection.private_files {
        if leaf.is_file_like() && leaf.id() != empty {
            for id in leak_ids(store, &leaf.id())? {
                private_blobs.entry(id).or_insert_with(|| path.clone());
            }
        }
    }
    let mut found = BTreeSet::new();
    for (path, leaf) in &projection.public_files {
        if !leaf.is_file_like() || leaf.id() == empty {
            continue;
        }
        for id in leak_ids(store, &leaf.id())? {
            if let Some(private_path) = private_blobs.get(&id) {
                found.insert(Paste { public_path: path.clone(), private_path: private_path.clone() });
            }
        }
    }
    Ok(found)
}

/// Include the ordinary blob ID of the complete bytes so historical kind-1
/// files and new chunked representations share the same leak evidence.
fn leak_ids(store: &dyn Store, id: &ObjectId) -> Result<Vec<ObjectId>, PublishError> {
    let mut ids = tig_core::blob::content_ids(store, id)?;
    if store.kind(id)? == Some(ObjectKind::ChunkedBlob) {
        struct HashWriter(blake3::Hasher);
        impl std::io::Write for HashWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
        }
        let mut hash = HashWriter(blake3::Hasher::new_derive_key(tig_core::domain::OBJECT_ID));
        hash.0.update(&[ObjectKind::Blob as u8]);
        tig_core::blob::write_content(store, id, &mut hash)?;
        ids.push(ObjectId(*hash.0.finalize().as_bytes()));
    }
    Ok(ids)
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

struct Outbox<'a> {
    local: &'a dyn Store,
    public: &'a dyn Store,
    pending: Vec<(ObjectId, ObjectKind, usize)>,
    seen: BTreeSet<ObjectId>,
}

impl<'a> Outbox<'a> {
    fn new(local: &'a dyn Store, public: &'a dyn Store) -> Self {
        Outbox {
            local,
            public,
            pending: Vec::new(),
            seen: BTreeSet::new(),
        }
    }

    fn push(&mut self, id: ObjectId, kind: ObjectKind, body: Vec<u8>) -> Result<(), PublishError> {
        if !self.seen.insert(id) {
            return Ok(());
        }
        if !self.local.has(&id)? { self.local.put_raw(&id, kind, &body)?; }
        self.pending.push((id, kind, body.len()));
        Ok(())
    }
}

fn write_canonical(out: &mut Outbox<'_>, obj: &Object) -> Result<(), PublishError> {
    let body = obj.encode_body();
    let id = hash_object(obj.kind(), &body);
    out.push(id, obj.kind(), body)
}

/// Copies a public tree. A tree the remote already has is skipped, children
/// included: its id commits to those children. Children are written before
/// the parent. The walk is a heap stack; a deep tree must not grow the
/// thread stack.
fn write_public_tree(
    local: &dyn Store,
    remote: &mut Outbox<'_>,
    root: &ObjectId,
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
            remote.push(id, ObjectKind::Tree, body)?;
            continue;
        }
        if remote.public.has(&id)? || !seen.insert(id) {
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
                    tig_core::blob::for_each_content(local, &entry.id(), |kind, id, body| {
                        remote.push(id, kind, body.to_vec())
                    })?;
                }
                EntryKind::Sealed => {}
                EntryKind::Conflict => return Err(PublishError::Invalid("unresolved conflict in public tree".into())),
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

fn build_pack(
    store: &dyn Store,
    key: &EpochKey,
    state: &PublishState,
    plans: &[Plan],
    packs: &mut Vec<PackUpload>,
) -> Result<(usize, usize, BTreeSet<WireId>), PublishError> {
    let already = state.sent.get(&(key.context().group.clone(), key.context().epoch)).cloned().unwrap_or_default();
    let mut builder = PackBatch::new(key);
    let mut added = BTreeSet::new();
    let mut new_wires = BTreeSet::new();
    let mut roots = 0;
    let mut emit = |bytes: &[u8]| -> Result<(), PackError> {
        let opened = Pack::open(bytes, key)?;
        let entry = PackEntry {
            group: key.context().group.clone(), epoch: key.context().epoch,
            sealed: opened.sealed.iter().map(|record| record.sealed_id).collect(),
        };
        let local = hash_object(ObjectKind::Blob, bytes);
        if !store.has(&local)? { store.put_raw(&local, ObjectKind::Blob, bytes)?; }
        packs.push(PackUpload { id: pack_id(bytes), entry, local });
        Ok(())
    };
    for plan in plans {
        for root in &plan.projection.sealed {
            if access_group(&root.readers) != key.context().group { continue; }
            let sealed = key.seal(&root.path, root.leaf.kind(), &root.leaf.id());
            builder.add_sealed(sealed, root.path.clone(), root.leaf.kind(), root.leaf.id(), &mut emit)?;
            roots += 1;
            let mut pending = vec![(root.leaf, root.path.components().count())];
            let mut walked = BTreeSet::new();
            while let Some((leaf, depth)) = pending.pop() {
                if depth > MAX_TREE_DEPTH { return Err(too_deep()); }
                if !walked.insert(leaf.id()) { continue; }
                match leaf.kind() {
                    EntryKind::Tree => {
                        queue_object(store, key, ObjectKind::Tree, leaf.id(), &already, &mut added, &mut new_wires, &mut builder, &mut emit)?;
                        for entry in store.get_tree(&leaf.id())?.entries() {
                            if entry.kind() != EntryKind::Sealed { pending.push((Leaf::new(entry.kind(), entry.id())?, depth + 1)); }
                        }
                    }
                    EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                        tig_core::blob::for_each_content(store, &leaf.id(), |kind, id, _body| {
                            queue_object(store, key, kind, id, &already, &mut added, &mut new_wires, &mut builder, &mut emit)
                        })?;
                    }
                    EntryKind::Sealed => {}
                    EntryKind::Conflict => return Err(PublishError::Invalid("unresolved conflict in private tree".into())),
                }
            }
        }
    }
    builder.finish(&mut emit)?;
    Ok((new_wires.len(), roots, new_wires))
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
    builder: &mut PackBatch<'_>,
    emit: &mut dyn FnMut(&[u8]) -> Result<(), PackError>,
) -> Result<(), PublishError> {
    let wire = key.wire_id(&id);
    if already.contains(&wire) || !added.insert(id) { return Ok(()); }
    let (stored_kind, body) = store.get_raw(&id)?.ok_or(tig_core::Error::NotFound(id))?;
    if stored_kind != kind {
        return Err(PublishError::Invalid(format!("object {id} has kind {} but the tree says {}", stored_kind.name(), kind.name())));
    }
    builder.add_object(kind, id, &body, emit)?;
    new_wires.insert(wire);
    Ok(())
}

fn write_ids(w: &mut Writer, ids: &BTreeSet<ObjectId>) -> Result<(), PublishError> {
    if ids.len() > MAX_PATHS {
        return Err(PublishError::Invalid("too many blob ids".into()));
    }
    w.varint(ids.len() as u64);
    for id in ids {
        w.id(id);
    }
    Ok(())
}

fn read_ids(r: &mut Reader<'_>) -> Result<BTreeSet<ObjectId>, PublishError> {
    let n = r.count(32)?;
    if n > MAX_PATHS {
        return Err(PublishError::Invalid("too many blob ids".into()));
    }
    let mut ids = BTreeSet::new();
    let mut previous: Option<ObjectId> = None;
    for _ in 0..n {
        let id = r.id()?;
        if previous.is_some_and(|prev| id <= prev) {
            return Err(PublishError::Invalid("blob ids are not in canonical order".into()));
        }
        previous = Some(id);
        ids.insert(id);
    }
    Ok(ids)
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
    fn remote_history_retry_reads_only_new_revisions_and_trees() {
        struct CountingStore {
            inner: tig_core::MemoryStore,
            reads: std::sync::Mutex<BTreeMap<ObjectId, usize>>,
        }
        impl Store for CountingStore {
            fn get_raw(&self, id: &ObjectId) -> tig_core::Result<Option<(ObjectKind, Vec<u8>)>> {
                *self.reads.lock().unwrap().entry(*id).or_default() += 1;
                self.inner.get_raw(id)
            }
            fn put_raw(
                &self,
                id: &ObjectId,
                kind: ObjectKind,
                body: &[u8],
            ) -> tig_core::Result<()> {
                self.inner.put_raw(id, kind, body)
            }
            fn has(&self, id: &ObjectId) -> tig_core::Result<bool> {
                self.inner.has(id)
            }
        }
        let store = CountingStore {
            inner: tig_core::MemoryStore::new(),
            reads: std::sync::Mutex::new(BTreeMap::new()),
        };
        let blob = store.put_blob(b"public").unwrap();
        let subtree = store
            .put(&Object::Tree(
                Tree::new(vec![tig_core::object::TreeEntry::new(
                    "file",
                    EntryKind::File,
                    blob,
                )
                .unwrap()])
                .unwrap(),
            ))
            .unwrap();
        let tree = store
            .put(&Object::Tree(
                Tree::new(vec![tig_core::object::TreeEntry::new(
                    "a",
                    EntryKind::Tree,
                    subtree,
                )
                .unwrap()])
                .unwrap(),
            ))
            .unwrap();
        let mut revision = root_revision();
        revision.tree = tree;
        revision.parents = vec![root_revision_id()];
        let base = store.put(&Object::Revision(revision.clone())).unwrap();
        let mut refs = BTreeMap::from([("main".into(), base)]);
        let mut history = PublicHistory::default();
        assert!(remote_public_paths(&store, &refs, &mut history).unwrap());
        let paths = history.paths.clone();
        assert!(paths.contains(&RepoPath::new("a/file").unwrap()));
        let before = store.reads.lock().unwrap().clone();
        assert!(!remote_public_paths(&store, &refs, &mut history).unwrap());
        assert_eq!(history.paths, paths);
        assert_eq!(
            *store.reads.lock().unwrap(),
            before,
            "unchanged history was read again"
        );

        // A new revision reuses one subtree and mounts it at another prefix.
        revision.tree = store
            .put(&Object::Tree(
                Tree::new(vec![
                    tig_core::object::TreeEntry::new("a", EntryKind::Tree, subtree).unwrap(),
                    tig_core::object::TreeEntry::new("b", EntryKind::Tree, subtree).unwrap(),
                ])
                .unwrap(),
            ))
            .unwrap();
        revision.parents = vec![base];
        let child = store.put(&Object::Revision(revision)).unwrap();
        refs.insert("main".into(), child);
        assert!(remote_public_paths(&store, &refs, &mut history).unwrap());
        assert!(history.paths.contains(&RepoPath::new("b/file").unwrap()));
        let after = store.reads.lock().unwrap();
        assert_eq!(after[&base], before[&base]);
        assert_eq!(after[&tree], before[&tree]);
    }

    #[test]
    fn fast_forward_walk_refuses_excessive_edges() {
        let store = tig_core::MemoryStore::new();
        store.put(&Object::Revision(root_revision())).unwrap();
        let mut revision = root_revision();
        revision.parents = vec![root_revision_id(); MAX_HISTORY + 1];
        let id = store.put(&Object::Revision(revision)).unwrap();
        assert!(parent_ancestors(&store, id, ObjectId([99; 32])).is_err());
    }

    #[test]
    fn state_roundtrip_rejects_unsorted_and_trailing_bytes() {
        let mut state = PublishState::new();
        state.remote_id = [1; 16];
        state.owner_signing = Some([2; 32]);
        state.counter = 4;
        state.manifest_seq = 7;
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

        let mut legacy = bytes.clone();
        legacy[0] = 3;
        let mut migrated = state.clone();
        migrated.revisions.clear();
        assert_eq!(PublishState::decode(&legacy).unwrap(), migrated);

        let mut protected = state.clone();
        protected.revealed.insert(ObjectId([3; 32]));
        let revealed_only = protected.encode().unwrap();
        assert_eq!(revealed_only[0], 5);
        assert_eq!(PublishState::decode(&revealed_only).unwrap(), protected);
        protected.policy_checkpoint = Some(crate::keyring::PolicyCheckpoint {
            transitions: 3, digest: [4; 32],
        });
        let protected_bytes = protected.encode().unwrap();
        assert_eq!(PublishState::decode(&protected_bytes).unwrap(), protected);
        for end in bytes.len()..protected_bytes.len() {
            assert!(PublishState::decode(&protected_bytes[..end]).is_err());
        }

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
