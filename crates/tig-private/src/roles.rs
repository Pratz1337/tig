//! Signed role policy. Visibility (which groups an identity may read) is
//! separate from management permissions and from epoch-key wraps.
//!
//! A manager signs a policy transition. The current owner signs the keyring
//! head that commits it. A cryptographic grant is a second step: only a
//! current reader of that group, or the current owner when they already read
//! it, wraps the epoch key. A manager who cannot read the group never
//! generates or learns that key.
//!
//! Dropping a reader's last visibility freezes new publication of that group
//! until a remaining reader advances the epoch and rewraps only remaining
//! readers. Historical grants stay valid for old epochs.

use std::collections::{BTreeMap, BTreeSet};

use tig_core::encode::{Reader, Writer};

use crate::keys::{Identity, PublicIdentity};

pub const EDIT_PRIVATE: u32 = 1;
pub const MANAGE_ROLES: u32 = 1 << 1;
pub const ASSIGN_ROLES: u32 = 1 << 2;
pub const PUBLISH: u32 = 1 << 4;
pub const ALL_PERMISSIONS: u32 = EDIT_PRIVATE
    | MANAGE_ROLES
    | ASSIGN_ROLES
    | PUBLISH;

const TRANSITION_LABEL: &str = "tig role policy transition v1";
const HEAD_LABEL: &str = "tig role policy head v1";
const MAX_NAME: usize = 64;
const MAX_ITEMS: usize = 10_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoleError {
    #[error("invalid role policy: {0}")]
    Invalid(String),
    #[error("not allowed: {0}")]
    Denied(String),
    #[error("group `{group}` is frozen until a current reader rotates it")]
    Frozen { group: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Role {
    pub rank: u32,
    pub permissions: u32,
    pub groups: BTreeSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransitionBody {
    SetRole { name: String, role: Role },
    RemoveRole { name: String },
    Assign { member: PublicIdentity, role: String },
    Unassign { member: PublicIdentity, role: String },
    Transfer { owner: PublicIdentity },
    /// Binds an already-signed [`crate::keys::Grant`] to the policy snapshot
    /// at `counter_after`. The signer must already read `group`.
    AuthorizeGrant {
        group: String,
        epoch: u64,
        recipient: PublicIdentity,
        grant_signature: [u8; 64],
    },
    /// Remaining reader starts `epoch` (the next one). Does not wrap keys.
    AdvanceEpoch { group: String, epoch: u64 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTransition {
    pub counter_after: u64,
    pub body: TransitionBody,
    pub signer: [u8; 32],
    pub signature: [u8; 64],
}

impl TransitionBody {
    pub fn sign(
        self,
        remote: [u8; 16],
        root_signing: &[u8; 32],
        counter_after: u64,
        actor: &Identity,
    ) -> SignedTransition {
        let signer = actor.public().signing;
        let signature = actor.sign(&signing_message(
            remote,
            root_signing,
            counter_after,
            &signer,
            &self,
        ));
        SignedTransition {
            counter_after,
            body: self,
            signer,
            signature,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyLog {
    /// Grant signatures trusted as root-signed simple-mode history.
    pub baseline: BTreeSet<[u8; 64]>,
    pub transitions: Vec<SignedTransition>,
}

impl PolicyLog {
    pub fn empty() -> Self {
        PolicyLog {
            baseline: BTreeSet::new(),
            transitions: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.baseline.is_empty() && self.transitions.is_empty()
    }

    pub fn digest(&self, remote: [u8; 16], root_signing: &[u8; 32]) -> [u8; 32] {
        blake3::derive_key(HEAD_LABEL, &canonical(remote, root_signing, self))
    }

    pub fn encode_body(&self, remote: [u8; 16], root_signing: &[u8; 32]) -> Vec<u8> {
        canonical(remote, root_signing, self)
    }

    pub fn decode_body(bytes: &[u8]) -> Result<(PolicyLog, [u8; 16], [u8; 32]), RoleError> {
        let mut r = Reader::new(bytes, "role policy");
        let mut remote = [0u8; 16];
        remote.copy_from_slice(r.take(16).map_err(|e| RoleError::Invalid(e.to_string()))?);
        let mut root = [0u8; 32];
        root.copy_from_slice(r.take(32).map_err(|e| RoleError::Invalid(e.to_string()))?);
        let n_base = limited(&mut r)?;
        let mut baseline = BTreeSet::new();
        let mut previous: Option<[u8; 64]> = None;
        for _ in 0..n_base {
            let mut sig = [0u8; 64];
            sig.copy_from_slice(r.take(64).map_err(|e| RoleError::Invalid(e.to_string()))?);
            if previous.is_some_and(|prev| sig <= prev) {
                return Err(RoleError::Invalid(
                    "baseline grant signatures are not in order".into(),
                ));
            }
            previous = Some(sig);
            baseline.insert(sig);
        }
        let n = limited(&mut r)?;
        let mut transitions = Vec::with_capacity(n);
        for _ in 0..n {
            transitions.push(read_transition(&mut r)?);
        }
        r.finish().map_err(|e| RoleError::Invalid(e.to_string()))?;
        Ok((PolicyLog { baseline, transitions }, remote, root))
    }

    /// Replays transitions. Authority is the snapshot from before each batch
    /// of equal `counter_after`, never a later mutable role.
    pub fn replay(&self, root: &PublicIdentity, remote: [u8; 16]) -> Result<Snapshot, RoleError> {
        let mut snap = Snapshot::at_root(root);
        let mut index = 0;
        while index < self.transitions.len() {
            let counter = self.transitions[index].counter_after;
            let start = index;
            while index < self.transitions.len() && self.transitions[index].counter_after == counter
            {
                index += 1;
            }
            let batch = &self.transitions[start..index];
            if start > 0 && counter <= self.transitions[start - 1].counter_after {
                return Err(RoleError::Invalid(
                    "policy counters do not increase".into(),
                ));
            }
            for transition in batch {
                check_signature(remote, &root.signing, transition)?;
                authorize(&snap, &transition.signer, &transition.body)?;
            }
            for transition in batch {
                apply(&mut snap, transition)?;
            }
        }
        if !self.baseline.is_empty() || !self.transitions.is_empty() {
            snap.explicit = true;
        }
        Ok(snap)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct GrantAuth {
    granter: [u8; 32],
    group: String,
    epoch: u64,
    recipient: PublicIdentity,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub root: PublicIdentity,
    pub current_owner: PublicIdentity,
    pub roles: BTreeMap<String, Role>,
    pub assignments: BTreeMap<PublicIdentity, BTreeSet<String>>,
    /// False only for a keyring that has never committed role policy.
    pub explicit: bool,
    authorized: BTreeMap<[u8; 64], GrantAuth>,
    explicit_groups: BTreeSet<String>,
}

impl PartialEq for Snapshot {
    fn eq(&self, other: &Self) -> bool {
        self.root == other.root
            && self.current_owner == other.current_owner
            && self.roles == other.roles
            && self.assignments == other.assignments
            && self.explicit == other.explicit
            && self.explicit_groups == other.explicit_groups
    }
}

impl Snapshot {
    pub fn at_root(root: &PublicIdentity) -> Self {
        Snapshot {
            root: *root,
            current_owner: *root,
            roles: BTreeMap::new(),
            assignments: BTreeMap::new(),
            explicit: false,
            authorized: BTreeMap::new(),
            explicit_groups: BTreeSet::new(),
        }
    }

    pub fn is_current_owner(&self, signing: &[u8; 32]) -> bool {
        self.current_owner.signing == *signing
    }

    pub fn permissions(&self, actor: &PublicIdentity) -> u32 {
        if actor.signing == self.current_owner.signing && actor.encryption == self.current_owner.encryption
        {
            return ALL_PERMISSIONS;
        }
        let mut bits = 0;
        for name in self.assignments.get(actor).into_iter().flatten() {
            if let Some(role) = self.roles.get(name) {
                bits |= role.permissions;
            }
        }
        bits
    }

    pub fn has(&self, actor: &PublicIdentity, permission: u32) -> bool {
        self.permissions(actor) & permission == permission
    }

    pub fn highest_rank(&self, actor: &PublicIdentity) -> Option<u32> {
        self.assignments.get(actor).and_then(|names| {
            names
                .iter()
                .filter_map(|name| self.roles.get(name).map(|role| role.rank))
                .max()
        })
    }

    /// Groups named by at least one role. Other groups stay on the simple
    /// rule: a current grant holder still reads them.
    pub fn group_is_explicit(&self, group: &str) -> bool {
        group.split('+').any(|name| self.explicit_groups.contains(name))
    }

    pub fn assigned_groups(&self, actor: &PublicIdentity) -> BTreeSet<String> {
        let mut groups = BTreeSet::new();
        for name in self.assignments.get(actor).into_iter().flatten() {
            if let Some(role) = self.roles.get(name) {
                groups.extend(role.groups.iter().cloned());
            }
        }
        groups
    }

    /// Visibility right now. A cached epoch key does not count unless the
    /// group is still implicit (no role names it) and the actor holds the
    /// current grant.
    pub fn may_read(
        &self,
        actor: &PublicIdentity,
        group: &str,
        current_holders: &BTreeSet<PublicIdentity>,
    ) -> bool {
        if group.split('+').any(|name| self.assigned_groups(actor).contains(name)) {
            return true;
        }
        let implicit_holder = !self.group_is_explicit(group) && current_holders.contains(actor);
        if implicit_holder {
            return true;
        }
        !self.explicit
            && actor.signing == self.current_owner.signing
            && actor.encryption == self.current_owner.encryption
    }

    pub fn current_holders<'a, I>(grants: I, group: &str, epoch: u64) -> BTreeSet<PublicIdentity>
    where
        I: IntoIterator<Item = &'a crate::keys::Grant>,
    {
        grants
            .into_iter()
            .filter(|grant| grant.context.group == group && grant.context.epoch == epoch)
            .map(|grant| grant.recipient)
            .collect()
    }

    pub fn publication_frozen<'a, I>(&self, grants: I, group: &str, epoch: u64) -> bool
    where
        I: IntoIterator<Item = &'a crate::keys::Grant>,
    {
        if !self.explicit {
            return false;
        }
        let holders = Self::current_holders(grants, group, epoch);
        holders.iter().any(|holder| !self.may_read(holder, group, &holders))
    }

    /// Role mode requires [`PUBLISH`] plus visibility. Simple mode does not
    /// consult this bit (manifest signers stay as they are until wired).
    pub fn may_publish_group<'a, I>(
        &self,
        actor: &PublicIdentity,
        grants: I,
        group: &str,
        epoch: Option<u64>,
    ) -> Result<(), RoleError>
    where
        I: IntoIterator<Item = &'a crate::keys::Grant>,
    {
        let grants: Vec<&crate::keys::Grant> = grants.into_iter().collect();
        if let Some(epoch) = epoch {
            if self.publication_frozen(grants.iter().copied(), group, epoch) {
                return Err(RoleError::Frozen {
                    group: group.to_string(),
                });
            }
        }
        let holders = epoch
            .map(|epoch| Self::current_holders(grants, group, epoch))
            .unwrap_or_default();
        if !self.explicit {
            if self.may_read(actor, group, &holders) {
                return Ok(());
            }
            return Err(RoleError::Denied(
                "simple mode publishes as the owner or a current reader".into(),
            ));
        }
        if !self.has(actor, PUBLISH) {
            return Err(RoleError::Denied(
                "reading a group does not grant publish".into(),
            ));
        }
        if !self.may_read(actor, group, &holders) {
            return Err(RoleError::Denied(format!(
                "publisher cannot read group `{group}`"
            )));
        }
        Ok(())
    }

    /// Publish must refuse to move a path into a reader set the publisher
    /// does not currently read. Call this from publish, per sealed root.
    pub fn require_publisher_reads(
        &self,
        actor: &PublicIdentity,
        readers: &BTreeSet<String>,
        holders_of: &BTreeMap<String, BTreeSet<PublicIdentity>>,
    ) -> Result<(), RoleError> {
        if !self.explicit {
            return Ok(());
        }
        for group in readers {
            let empty = BTreeSet::new();
            let holders = holders_of.get(group).unwrap_or(&empty);
            if !self.may_read(actor, group, holders) {
                return Err(RoleError::Denied(format!(
                    "cannot move a path into group `{group}` without read access"
                )));
            }
        }
        Ok(())
    }

    pub fn grant_trusted(
        &self,
        baseline: &BTreeSet<[u8; 64]>,
        group: &str,
        epoch: u64,
        recipient: &PublicIdentity,
        granter: &[u8; 32],
        signature: &[u8; 64],
    ) -> Result<(), RoleError> {
        if !self.explicit {
            if *granter == self.root.signing {
                return Ok(());
            }
            return Err(RoleError::Denied(
                "simple-mode grants are signed by the root owner".into(),
            ));
        }
        if baseline.contains(signature) {
            if *granter == self.root.signing {
                return Ok(());
            }
            return Err(RoleError::Invalid(
                "baseline grant was not signed by the root owner".into(),
            ));
        }
        let Some(auth) = self.authorized.get(signature) else {
            return Err(RoleError::Denied(
                "grant has no policy authorization at its issuing snapshot".into(),
            ));
        };
        if auth.granter != *granter
            || auth.group != group
            || auth.epoch != epoch
            || auth.recipient != *recipient
        {
            return Err(RoleError::Denied(
                "grant does not match the policy authorization".into(),
            ));
        }
        Ok(())
    }
}

/// What is waiting on a reader who already holds the key. Fingerprints only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAccess {
    pub frozen_groups: Vec<String>,
    pub grants_pending: Vec<(String, String)>,
}

pub fn pending_access<'a, I>(
    snapshot: &Snapshot,
    epochs: &BTreeMap<String, u64>,
    grants: I,
) -> PendingAccess
where
    I: IntoIterator<Item = &'a crate::keys::Grant>,
{
    let grants: Vec<&crate::keys::Grant> = grants.into_iter().collect();
    let mut groups = BTreeSet::new();
    for role in snapshot.roles.values() {
        groups.extend(role.groups.iter().cloned());
    }
    groups.extend(epochs.keys().cloned());
    let mut frozen = Vec::new();
    let mut pending = Vec::new();
    for group in groups {
        let epoch = epochs.get(&group).copied();
        let holders = epoch
            .map(|epoch| Snapshot::current_holders(grants.iter().copied(), &group, epoch))
            .unwrap_or_default();
        if let Some(epoch) = epoch {
            if snapshot.publication_frozen(grants.iter().copied(), &group, epoch) {
                frozen.push(group.clone());
            }
        }
        let mut readers = BTreeSet::new();
        for (member, names) in &snapshot.assignments {
            if names.iter().any(|name| {
                snapshot
                    .roles
                    .get(name)
                    .is_some_and(|role| role.groups.contains(&group))
            }) {
                readers.insert(*member);
            }
        }
        if !snapshot.group_is_explicit(&group) {
            readers.extend(holders.iter().copied());
        }
        for reader in readers {
            if !holders.contains(&reader) {
                pending.push((group.clone(), reader.fingerprint()));
            }
        }
    }
    PendingAccess {
        frozen_groups: frozen,
        grants_pending: pending,
    }
}

pub fn format_pending(pending: &PendingAccess) -> String {
    let mut lines = Vec::new();
    for group in &pending.frozen_groups {
        lines.push(format!(
            "{group}: publication frozen until a current reader rotates the epoch"
        ));
    }
    for (group, fingerprint) in &pending.grants_pending {
        lines.push(format!(
            "{group}: key grant pending for {fingerprint}; a current reader must wrap the epoch key"
        ));
    }
    if lines.is_empty() {
        "no pending role grants or frozen groups".into()
    } else {
        lines.join("\n")
    }
}

fn authorize(snap: &Snapshot, signer: &[u8; 32], body: &TransitionBody) -> Result<(), RoleError> {
    let actor = find_actor(snap, signer)?;
    match body {
        TransitionBody::SetRole { name, role } => {
            check_name(name)?;
            for group in &role.groups {
                check_name(group)?;
            }
            if role.permissions & !ALL_PERMISSIONS != 0 {
                return Err(RoleError::Invalid("unknown permission bit".into()));
            }
            if !snap.has(&actor, MANAGE_ROLES) {
                return Err(RoleError::Denied("missing manage-roles".into()));
            }
            if let Some(existing) = snap.roles.get(name) {
                manageable(snap, &actor, existing.rank)?;
                if !snap.is_current_owner(signer)
                    && snap.assignments.get(&actor).is_some_and(|assigned| assigned.contains(name))
                    && (role.rank > existing.rank || role.permissions & !existing.permissions != 0
                        || !role.groups.is_subset(&existing.groups))
                {
                    return Err(RoleError::Denied("you cannot raise your own assigned role".into()));
                }
            }
            manageable(snap, &actor, role.rank)?;
            if !snap.is_current_owner(signer) && role.permissions & !snap.permissions(&actor) != 0 {
                return Err(RoleError::Denied(
                    "cannot grant a permission you do not hold".into(),
                ));
            }
            Ok(())
        }
        TransitionBody::RemoveRole { name } => {
            let role = snap
                .roles
                .get(name)
                .ok_or_else(|| RoleError::Invalid(format!("unknown role `{name}`")))?;
            if !snap.has(&actor, MANAGE_ROLES) {
                return Err(RoleError::Denied("missing manage-roles".into()));
            }
            manageable(snap, &actor, role.rank)
        }
        TransitionBody::Assign { member, role } => {
            if *member == snap.current_owner {
                // Owner already has every permission. Self-assign is only a
                // visibility change and only the owner may do it to themself.
            }
            assign_ok(snap, &actor, signer, member, role)
        }
        TransitionBody::Unassign { member, role } => {
            if *member == snap.current_owner {
                return Err(RoleError::Denied(
                    "the current owner cannot be removed".into(),
                ));
            }
            let rank = snap
                .roles
                .get(role)
                .map(|role| role.rank)
                .ok_or_else(|| RoleError::Invalid(format!("unknown role `{role}`")))?;
            if !snap.has(&actor, ASSIGN_ROLES) {
                return Err(RoleError::Denied("missing assign-roles".into()));
            }
            manageable(snap, &actor, rank)
        }
        TransitionBody::Transfer { owner } => {
            if !snap.is_current_owner(signer) {
                return Err(RoleError::Denied(
                    "only the current owner can transfer ownership".into(),
                ));
            }
            if owner.signing == snap.current_owner.signing {
                return Err(RoleError::Invalid("owner is unchanged".into()));
            }
            Ok(())
        }
        TransitionBody::AuthorizeGrant {
            group,
            recipient,
            ..
        } => {
            check_group(group)?;
            if !may_read_without_holder_list(snap, &actor, group) {
                return Err(RoleError::Denied(format!(
                    "only a reader of `{group}` can wrap its key"
                )));
            }
            if !may_read_without_holder_list(snap, recipient, group) {
                return Err(RoleError::Denied(
                    "recipient cannot read this group; assign the role first".into(),
                ));
            }
            Ok(())
        }
        TransitionBody::AdvanceEpoch { group, .. } => {
            check_group(group)?;
            if !may_read_without_holder_list(snap, &actor, group) {
                return Err(RoleError::Denied(format!(
                    "only a reader of `{group}` can rotate it"
                )));
            }
            Ok(())
        }
    }
}

/// Reader check that does not treat "holds a key" as visibility, except the
/// simple-mode implicit rule for groups no role has named.
fn may_read_without_holder_list(snap: &Snapshot, actor: &PublicIdentity, group: &str) -> bool {
    if group.split('+').any(|name| snap.assigned_groups(actor).contains(name)) {
        return true;
    }
    // Implicit simple-mode membership is not known here (no grant list).
    // Callers pass current holders into `may_read` for publish and env.
    // Cryptographic steps require an assigned group once any role names it,
    // and refuse a non-assigned manager even for implicit groups: holding a
    // key you were granted is not a management power, but wrapping still
    // requires you already read it. Implicit private readers are those with
    // a grant; the keyring checks that holder set before accepting this
    // transition. Here, assignment is sufficient. Implicit holders are
    // allowed only when the group is not explicit and the actor is the
    // current owner (they hold the owner keystore in simple mode).
    if !snap.group_is_explicit(group) && snap.is_current_owner(&actor.signing)
        && actor.encryption == snap.current_owner.encryption
    {
        return true;
    }
    false
}

fn assign_ok(
    snap: &Snapshot,
    actor: &PublicIdentity,
    signer: &[u8; 32],
    member: &PublicIdentity,
    role_name: &str,
) -> Result<(), RoleError> {
    let role = snap
        .roles
        .get(role_name)
        .ok_or_else(|| RoleError::Invalid(format!("unknown role `{role_name}`")))?;
    if !snap.has(actor, ASSIGN_ROLES) {
        return Err(RoleError::Denied("missing assign-roles".into()));
    }
    manageable(snap, actor, role.rank)?;
    if member.signing == *signer && member.encryption == actor.encryption && !snap.is_current_owner(signer)
    {
        return Err(RoleError::Denied("you cannot raise your own roles".into()));
    }
    if member.signing == *signer && !snap.is_current_owner(signer) {
        return Err(RoleError::Denied("you cannot raise your own roles".into()));
    }
    if role.permissions & !snap.permissions(actor) != 0 {
        return Err(RoleError::Denied("cannot grant a permission you do not hold".into()));
    }
    Ok(())
}

fn find_actor(snap: &Snapshot, signer: &[u8; 32]) -> Result<PublicIdentity, RoleError> {
    if snap.current_owner.signing == *signer {
        return Ok(snap.current_owner);
    }
    snap.assignments
        .keys()
        .find(|member| member.signing == *signer)
        .copied()
        .ok_or_else(|| RoleError::Denied("signer has no role".into()))
}

fn manageable(snap: &Snapshot, actor: &PublicIdentity, rank: u32) -> Result<(), RoleError> {
    if snap.is_current_owner(&actor.signing) && actor.encryption == snap.current_owner.encryption {
        return Ok(());
    }
    match snap.highest_rank(actor) {
        Some(have) if rank < have => Ok(()),
        _ => Err(RoleError::Denied(
            "you can only manage roles ranked below you".into(),
        )),
    }
}

fn apply(snap: &mut Snapshot, transition: &SignedTransition) -> Result<(), RoleError> {
    match &transition.body {
        TransitionBody::SetRole { name, role } => {
            snap.explicit_groups.extend(role.groups.iter().cloned());
            snap.roles.insert(name.clone(), role.clone());
        }
        TransitionBody::RemoveRole { name } => {
            snap.roles.remove(name);
            for assigned in snap.assignments.values_mut() {
                assigned.remove(name);
            }
        }
        TransitionBody::Assign { member, role } => {
            snap.assignments
                .entry(*member)
                .or_default()
                .insert(role.clone());
        }
        TransitionBody::Unassign { member, role } => {
            if let Some(set) = snap.assignments.get_mut(member) {
                set.remove(role);
            }
        }
        TransitionBody::Transfer { owner } => {
            snap.current_owner = *owner;
        }
        TransitionBody::AuthorizeGrant {
            group,
            epoch,
            recipient,
            grant_signature,
        } => {
            snap.authorized.insert(
                *grant_signature,
                GrantAuth {
                    granter: transition.signer,
                    group: group.clone(),
                    epoch: *epoch,
                    recipient: *recipient,
                },
            );
        }
        TransitionBody::AdvanceEpoch { .. } => {}
    }
    Ok(())
}

fn check_signature(
    remote: [u8; 16],
    root_signing: &[u8; 32],
    transition: &SignedTransition,
) -> Result<(), RoleError> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(&transition.signer)
        .map_err(|_| RoleError::Invalid("signer is not an Ed25519 key".into()))?;
    let message = signing_message(
        remote,
        root_signing,
        transition.counter_after,
        &transition.signer,
        &transition.body,
    );
    key.verify_strict(
        &message,
        &ed25519_dalek::Signature::from_bytes(&transition.signature),
    )
    .map_err(|_| RoleError::Invalid("bad role transition signature".into()))
}

fn signing_message(
    remote: [u8; 16],
    root_signing: &[u8; 32],
    counter_after: u64,
    signer: &[u8; 32],
    body: &TransitionBody,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(TRANSITION_LABEL.as_bytes());
    out.extend_from_slice(&remote);
    out.extend_from_slice(root_signing);
    out.extend_from_slice(&counter_after.to_le_bytes());
    out.extend_from_slice(signer);
    out.extend(encode_body(body));
    out
}

fn canonical(remote: [u8; 16], root_signing: &[u8; 32], log: &PolicyLog) -> Vec<u8> {
    let mut w = Writer::new();
    w.buf.extend_from_slice(&remote);
    w.buf.extend_from_slice(root_signing);
    w.varint(log.baseline.len() as u64);
    for sig in &log.baseline {
        w.buf.extend_from_slice(sig);
    }
    w.varint(log.transitions.len() as u64);
    for transition in &log.transitions {
        write_transition(&mut w, transition);
    }
    w.finish()
}

fn encode_body(body: &TransitionBody) -> Vec<u8> {
    let mut w = Writer::new();
    match body {
        TransitionBody::SetRole { name, role } => {
            w.u8(1);
            w.str(name);
            w.varint(u64::from(role.rank));
            w.varint(u64::from(role.permissions));
            w.varint(role.groups.len() as u64);
            for group in &role.groups {
                w.str(group);
            }
        }
        TransitionBody::RemoveRole { name } => {
            w.u8(2);
            w.str(name);
        }
        TransitionBody::Assign { member, role } => {
            w.u8(3);
            write_id(&mut w, member);
            w.str(role);
        }
        TransitionBody::Unassign { member, role } => {
            w.u8(4);
            write_id(&mut w, member);
            w.str(role);
        }
        TransitionBody::Transfer { owner } => {
            w.u8(5);
            write_id(&mut w, owner);
        }
        TransitionBody::AuthorizeGrant {
            group,
            epoch,
            recipient,
            grant_signature,
        } => {
            w.u8(6);
            w.str(group);
            w.varint(*epoch);
            write_id(&mut w, recipient);
            w.buf.extend_from_slice(grant_signature);
        }
        TransitionBody::AdvanceEpoch { group, epoch } => {
            w.u8(7);
            w.str(group);
            w.varint(*epoch);
        }
    }
    w.finish()
}

fn write_id(w: &mut Writer, id: &PublicIdentity) {
    w.buf.extend_from_slice(&id.encryption);
    w.buf.extend_from_slice(&id.signing);
}

fn write_transition(w: &mut Writer, transition: &SignedTransition) {
    w.varint(transition.counter_after);
    w.buf.extend_from_slice(&transition.signer);
    w.buf.extend_from_slice(&transition.signature);
    let body = encode_body(&transition.body);
    w.bytes(&body);
}

fn read_transition(r: &mut Reader<'_>) -> Result<SignedTransition, RoleError> {
    let counter_after = r.varint().map_err(|e| RoleError::Invalid(e.to_string()))?;
    let mut signer = [0u8; 32];
    signer.copy_from_slice(r.take(32).map_err(|e| RoleError::Invalid(e.to_string()))?);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(r.take(64).map_err(|e| RoleError::Invalid(e.to_string()))?);
    let body_bytes = r.bytes().map_err(|e| RoleError::Invalid(e.to_string()))?;
    let body = decode_body_bytes(body_bytes)?;
    Ok(SignedTransition {
        counter_after,
        body,
        signer,
        signature,
    })
}

fn decode_body_bytes(bytes: &[u8]) -> Result<TransitionBody, RoleError> {
    let mut r = Reader::new(bytes, "transition");
    let kind = r.u8().map_err(|e| RoleError::Invalid(e.to_string()))?;
    let body = match kind {
        1 => {
            let name = name_of(&mut r)?;
            let rank = u32_of(&mut r)?;
            let permissions = u32_of(&mut r)?;
            let n = limited(&mut r)?;
            let mut groups = BTreeSet::new();
            for _ in 0..n {
                let group = name_of(&mut r)?;
                if !groups.insert(group) {
                    return Err(RoleError::Invalid("duplicate group".into()));
                }
            }
            TransitionBody::SetRole {
                name,
                role: Role {
                    rank,
                    permissions,
                    groups,
                },
            }
        }
        2 => TransitionBody::RemoveRole { name: name_of(&mut r)? },
        3 => TransitionBody::Assign {
            member: read_id(&mut r)?,
            role: name_of(&mut r)?,
        },
        4 => TransitionBody::Unassign {
            member: read_id(&mut r)?,
            role: name_of(&mut r)?,
        },
        5 => TransitionBody::Transfer {
            owner: read_id(&mut r)?,
        },
        6 => TransitionBody::AuthorizeGrant {
            group: group_of(&mut r)?,
            epoch: r.varint().map_err(|e| RoleError::Invalid(e.to_string()))?,
            recipient: read_id(&mut r)?,
            grant_signature: read_arr(&mut r)?,
        },
        7 => TransitionBody::AdvanceEpoch {
            group: group_of(&mut r)?,
            epoch: r.varint().map_err(|e| RoleError::Invalid(e.to_string()))?,
        },
        _ => return Err(RoleError::Invalid("unknown transition".into())),
    };
    r.finish().map_err(|e| RoleError::Invalid(e.to_string()))?;
    Ok(body)
}

fn name_of(r: &mut Reader<'_>) -> Result<String, RoleError> {
    let name = r.str().map_err(|e| RoleError::Invalid(e.to_string()))?.to_string();
    check_name(&name)?;
    Ok(name)
}

fn group_of(r: &mut Reader<'_>) -> Result<String, RoleError> {
    let group = r.str().map_err(|e| RoleError::Invalid(e.to_string()))?.to_string();
    check_group(&group)?;
    Ok(group)
}

fn check_group(group: &str) -> Result<(), RoleError> {
    let mut previous: Option<&str> = None;
    for name in group.split('+') {
        check_name(name)?;
        if previous.is_some_and(|p| p >= name) {
            return Err(RoleError::Invalid("group readers are not canonical".into()));
        }
        previous = Some(name);
    }
    Ok(())
}

fn check_name(name: &str) -> Result<(), RoleError> {
    if name.is_empty()
        || name.len() > MAX_NAME
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
    {
        return Err(RoleError::Invalid(format!("invalid name `{name}`")));
    }
    Ok(())
}

fn u32_of(r: &mut Reader<'_>) -> Result<u32, RoleError> {
    let value = r.varint().map_err(|e| RoleError::Invalid(e.to_string()))?;
    u32::try_from(value).map_err(|_| RoleError::Invalid("value does not fit".into()))
}

fn limited(r: &mut Reader<'_>) -> Result<usize, RoleError> {
    let n = r.varint().map_err(|e| RoleError::Invalid(e.to_string()))?;
    usize::try_from(n)
        .ok()
        .filter(|n| *n <= MAX_ITEMS)
        .ok_or_else(|| RoleError::Invalid("too many role records".into()))
}

fn read_id(r: &mut Reader<'_>) -> Result<PublicIdentity, RoleError> {
    Ok(PublicIdentity {
        encryption: read_arr(r)?,
        signing: read_arr(r)?,
    })
}

fn read_arr<const N: usize>(r: &mut Reader<'_>) -> Result<[u8; N], RoleError> {
    let mut out = [0u8; N];
    out.copy_from_slice(r.take(N).map_err(|e| RoleError::Invalid(e.to_string()))?);
    Ok(out)
}
