//! The remote keyring: owner identity, owner-signed head, and grants.
//!
//! Phase 1 has one group, `private`. The owner keeps epoch keys in
//! [`OwnerKeys`] and never takes those secrets from the remote. Members
//! pin the owner's signing key and refuse a head whose counter is older
//! than one they have already seen. See DESIGN.md "Keyring".
//!
//! The file encoding uses a version byte and canonical varints. The head
//! signature is over a separate fixed-width encoding under
//! [`tig_core::domain::KEYRING_HEAD_SIGNATURE`].

use std::collections::{BTreeMap, BTreeSet};

use tig_core::domain;
use tig_core::encode::{Reader, Writer};
use zeroize::Zeroize;

use crate::keys::{grant, open_grant, EpochKey, Grant, GroupEpoch, Identity, PublicIdentity};
use crate::project::PRIVATE_GROUP;
use crate::roles::{PolicyLog, SignedTransition, Snapshot, TransitionBody};

const VERSION: u8 = 1;
const VERSION_ROLES: u8 = 2;
const MAX_GROUPS: usize = 10_000;
const MAX_GRANTS: usize = 100_000;
const MAX_GROUP: usize = 1024;
const MAX_WRAP: usize = 4096;
/// Smallest grant this encoder writes: fixed fields plus an empty group and
/// an empty ciphertext. Used only to reject a count the buffer cannot hold.
const MIN_GRANT: usize = 16 + 1 + 1 + 32 + 32 + 32 + 24 + 1 + 32 + 32 + 64;

#[derive(Debug, thiserror::Error)]
pub enum KeyringError {
    #[error(transparent)]
    Key(#[from] crate::keys::KeyError),
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error("you are not a member")]
    NotMember,
    #[error("keyring head rolled back")]
    RolledBack,
    #[error("invalid keyring: {0}")]
    Invalid(String),
}

/// Owner-signed statement of the current epoch of each group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedHead {
    pub remote: [u8; 16],
    pub counter: u64,
    /// Group name to the current epoch. Iteration order is bytewise.
    pub epochs: BTreeMap<String, u64>,
    pub signature: [u8; 64],
}

impl SignedHead {
    /// Bytes covered by [`SignedHead::signature`].
    ///
    /// `KEYRING_HEAD_SIGNATURE || remote_len_u64_le || remote || counter_u64_le
    /// || count_u64_le || (group_len_u64_le || group || epoch_u64_le)*`,
    /// groups in bytewise order.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.epochs.len() * 32);
        out.extend_from_slice(domain::KEYRING_HEAD_SIGNATURE.as_bytes());
        out.extend_from_slice(&(self.remote.len() as u64).to_le_bytes());
        out.extend_from_slice(&self.remote);
        out.extend_from_slice(&self.counter.to_le_bytes());
        out.extend_from_slice(&(self.epochs.len() as u64).to_le_bytes());
        for (group, epoch) in &self.epochs {
            out.extend_from_slice(&(group.len() as u64).to_le_bytes());
            out.extend_from_slice(group.as_bytes());
            out.extend_from_slice(&epoch.to_le_bytes());
        }
        out
    }
}

/// The owner's local epoch keys. The secret bytes never go to the remote.
#[derive(Debug)]
pub struct OwnerKeys {
    pub remote: [u8; 16],
    pub keys: BTreeMap<(String, u64), EpochKey>,
}

impl OwnerKeys {
    pub fn encode(&self) -> Result<Vec<u8>, KeyringError> {
        if self.keys.len() > MAX_GROUPS {
            return Err(KeyringError::Invalid("too many epoch keys".into()));
        }
        let mut w = Writer::new();
        w.u8(VERSION);
        w.buf.extend_from_slice(&self.remote);
        w.varint(self.keys.len() as u64);
        for ((group, epoch), key) in &self.keys {
            if key.context().remote != self.remote
                || &key.context().group != group
                || key.context().epoch != *epoch
            {
                return Err(KeyringError::Invalid(
                    "epoch key context does not match the store".into(),
                ));
            }
            if group.len() > MAX_GROUP {
                return Err(KeyringError::Invalid("group name is too long".into()));
            }
            w.str(group);
            w.varint(*epoch);
            w.buf.extend_from_slice(&key.to_bytes()[..]);
        }
        Ok(w.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KeyringError> {
        let mut r = Reader::new(bytes, "owner keys");
        expect_version(&mut r)?;
        let remote = read_array(&mut r)?;
        let n = r.count(1 + 1 + 32)?;
        if n > MAX_GROUPS {
            return Err(KeyringError::Invalid("too many epoch keys".into()));
        }
        let mut keys = BTreeMap::new();
        let mut previous: Option<(String, u64)> = None;
        for _ in 0..n {
            let group = read_limited_str(&mut r, MAX_GROUP)?;
            let epoch = r.varint()?;
            let mut secret = read_array::<32>(&mut r)?;
            let rank = (group.clone(), epoch);
            if previous.as_ref().is_some_and(|prev| rank <= *prev) {
                secret.zeroize();
                return Err(KeyringError::Invalid(
                    "epoch keys are not in canonical order".into(),
                ));
            }
            previous = Some(rank.clone());
            let key = EpochKey::from_bytes(
                GroupEpoch {
                    remote,
                    group,
                    epoch,
                },
                secret,
            );
            secret.zeroize();
            keys.insert(rank, key);
        }
        r.finish()?;
        Ok(OwnerKeys { remote, keys })
    }
}

/// Accepted signed policy prefix. The root pin alone cannot detect a former
/// owner's alternate history that omits an ownership transfer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PolicyCheckpoint {
    pub transitions: u64,
    pub digest: [u8; 32],
}

/// What a remote stores: who the owner is, the signed head, and every grant
/// the owner has ever issued. Old grants stay so a revoked member can still
/// open packs from before the revocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Keyring {
    pub remote: [u8; 16],
    /// Pinned trust root. Unchanged by ownership transfer.
    pub owner: PublicIdentity,
    pub head: SignedHead,
    pub grants: Vec<Grant>,
    /// Empty in simple mode. Version 1 files have no policy bytes.
    pub policy: PolicyLog,
}

impl Keyring {
    /// Group `private`, epoch 1, the owner granted to themself, head counter 1.
    pub fn create(remote: [u8; 16], owner: &Identity) -> Result<(Self, OwnerKeys), KeyringError> {
        let context = GroupEpoch {
            remote,
            group: PRIVATE_GROUP.to_string(),
            epoch: 1,
        };
        let key = EpochKey::generate(context)?;
        let self_grant = grant(&key, &owner.public(), owner)?;
        let mut head = SignedHead {
            remote,
            counter: 1,
            epochs: BTreeMap::from([(PRIVATE_GROUP.to_string(), 1)]),
            signature: [0; 64],
        };
        head.signature = owner.sign(&head.signing_bytes());
        let mut owner_keys = OwnerKeys {
            remote,
            keys: BTreeMap::new(),
        };
        owner_keys.keys.insert((PRIVATE_GROUP.to_string(), 1), key);
        let keyring = Keyring {
            remote,
            owner: owner.public(),
            head,
            grants: vec![self_grant],
            policy: PolicyLog::empty(),
        };
        Ok((keyring, owner_keys))
    }

    /// Initial keyring whose `private` epoch-1 secret is already in `keys`.
    ///
    /// The wrap is fresh; the epoch secret is not. Publish uses this when the
    /// caller saved [`OwnerKeys`] before any keyring file exists, then writes
    /// the result only after refusal checks. The owner still reads the epoch
    /// from `keys`, not from the new self-grant.
    pub fn from_saved_owner(owner: &Identity, keys: &OwnerKeys) -> Result<Self, KeyringError> {
        if keys.keys.len() != 1 {
            return Err(KeyringError::Invalid(
                "a new remote keyring needs the first epoch key and no later ones".into(),
            ));
        }
        let key = require_epoch_key(keys, keys.remote, 1)?;
        let self_grant = grant(key, &owner.public(), owner)?;
        let mut head = SignedHead {
            remote: keys.remote,
            counter: 1,
            epochs: BTreeMap::from([(PRIVATE_GROUP.to_string(), 1)]),
            signature: [0; 64],
        };
        head.signature = owner.sign(&head.signing_bytes());
        Ok(Keyring {
            remote: keys.remote,
            owner: owner.public(),
            head,
            grants: vec![self_grant],
            policy: PolicyLog::empty(),
        })
    }

    /// Grants `member` the current `private` epoch and advances the head.
    pub fn grant(
        &mut self,
        owner_keys: &OwnerKeys,
        owner: &Identity,
        member: &PublicIdentity,
    ) -> Result<(), KeyringError> {
        if !self.policy.is_empty() {
            return Err(KeyringError::Invalid(
                "this remote uses roles; a current reader must wrap the epoch key".into(),
            ));
        }
        self.require_owner(owner)?;
        let epoch = self.current_epoch()?;
        if self.member_of(epoch, member) {
            return Err(KeyringError::Invalid(
                "already a member of the current epoch".into(),
            ));
        }
        let epoch_key = require_epoch_key(owner_keys, self.remote, epoch)?;
        self.check_owner_key(epoch_key)?;
        let issued = grant(epoch_key, member, owner)?;
        self.push_grant_and_sign(owner, issued)
    }

    /// A losing revoke can save a different secret at the winning epoch.
    /// Compare local provenance with signed commitments before using it.
    pub(crate) fn check_owner_key(&self, key: &EpochKey) -> Result<(), KeyringError> {
        if self.grants.iter().any(|issued| {
            issued.context == *key.context() && !key.matches_commitment(&issued.commitment)
        }) {
            return Err(KeyringError::Invalid(
                "the saved owner key differs from the remote's signed epoch commitments; sync owner keys from the owner client that committed the revoke".into(),
            ));
        }
        Ok(())
    }

    /// Starts a new random epoch for the members who remain. History is kept.
    pub fn revoke(
        &mut self,
        owner_keys: &mut OwnerKeys,
        owner: &Identity,
        member: &PublicIdentity,
    ) -> Result<(), KeyringError> {
        if !self.policy.is_empty() {
            return Err(KeyringError::Invalid(
                "this remote uses roles; a remaining reader must rotate the group".into(),
            ));
        }
        self.require_owner(owner)?;
        if owner_keys.remote != self.remote {
            return Err(KeyringError::Invalid(
                "owner keys are for a different remote".into(),
            ));
        }
        let current = self.current_epoch()?;
        let mut found = false;
        let mut remaining = BTreeSet::new();
        for issued in &self.grants {
            if !self.is_current(issued, current) {
                continue;
            }
            if &issued.recipient == member {
                found = true;
            } else {
                remaining.insert(issued.recipient);
            }
        }
        if !found {
            return Err(KeyringError::NotMember);
        }
        let new_epoch = current
            .checked_add(1)
            .ok_or_else(|| KeyringError::Invalid("epoch overflow".into()))?;
        let map_key = (PRIVATE_GROUP.to_string(), new_epoch);
        // A previous attempt may have saved this key before its remote write
        // failed. Reuse that locally generated secret, never overwrite it.
        let generated = if owner_keys.keys.contains_key(&map_key) {
            let saved = require_epoch_key(owner_keys, self.remote, new_epoch)?;
            EpochKey::from_bytes(saved.context().clone(), *saved.to_bytes())
        } else {
            EpochKey::generate(GroupEpoch {
                remote: self.remote,
                group: PRIVATE_GROUP.to_string(),
                epoch: new_epoch,
            })?
        };
        let mut fresh = Vec::with_capacity(remaining.len());
        for recipient in &remaining {
            fresh.push(grant(&generated, recipient, owner)?);
        }
        // Commit only after every new grant exists, so a failed wrap leaves
        // the head and the owner store unchanged.
        let counter = self
            .head
            .counter
            .checked_add(1)
            .ok_or_else(|| KeyringError::Invalid("counter overflow".into()))?;
        owner_keys.keys.insert(map_key, generated);
        self.grants.extend(fresh);
        self.head
            .epochs
            .insert(PRIVATE_GROUP.to_string(), new_epoch);
        self.head.counter = counter;
        self.head.remote = self.remote;
        self.sign_head(owner);
        Ok(())
    }

    /// Commits manager-signed transitions and optional reader wraps.
    /// The head signer is the current owner or an authorized batch actor.
    /// Ownership transfer additionally requires the successor's head signature.
    /// The root pin does not move. A non-reader cannot put an [`AdvanceEpoch`] or
    /// [`TransitionBody::AuthorizeGrant`] through `authorize`.
    pub fn commit_policy(
        &mut self,
        head_signer: &Identity,
        transitions: Vec<SignedTransition>,
        new_grants: Vec<Grant>,
    ) -> Result<(), KeyringError> {
        if transitions.is_empty() {
            return Err(KeyringError::Invalid("empty role batch".into()));
        }
        let counter = self
            .head
            .counter
            .checked_add(1)
            .ok_or_else(|| KeyringError::Invalid("counter overflow".into()))?;
        if transitions.iter().any(|t| t.counter_after != counter) {
            return Err(KeyringError::Invalid(
                "role batch is not for the next counter".into(),
            ));
        }
        let mut trial = self.policy.clone();
        if self.policy.is_empty() {
            trial.baseline = self.grants.iter().map(|g| g.signature).collect();
        }
        trial.transitions.extend(transitions.iter().cloned());
        let snapshot = trial
            .replay(&self.owner, self.remote)
            .map_err(|e| KeyringError::Invalid(e.to_string()))?;
        if head_signer.public() != snapshot.current_owner
            && (transitions.iter().any(|t| matches!(t.body, TransitionBody::Transfer { .. }))
                || !transitions.iter().any(|t| t.signer == head_signer.public().signing))
        {
            return Err(KeyringError::Invalid("head signer did not authorize this policy batch".into()));
        }
        self.check_epoch_and_grants(&transitions, &new_grants)?;
        let mut next = self.clone();
        next.policy = trial;
        next.grants.extend(new_grants);
        for transition in &transitions {
            if let TransitionBody::AdvanceEpoch { group, epoch } = &transition.body {
                next.head.epochs.insert(group.clone(), *epoch);
            }
        }
        next.head.counter = counter;
        next.head.remote = self.remote;
        next.sign_head(head_signer);
        next.verify(&self.owner.signing, self.head.counter)?;
        *self = next;
        Ok(())
    }

    pub fn policy_checkpoint(&self) -> Option<PolicyCheckpoint> {
        if self.policy.is_empty() { return None; }
        Some(PolicyCheckpoint {
            transitions: self.policy.transitions.len() as u64,
            digest: self.policy.digest(self.remote, &self.owner.signing),
        })
    }

    pub fn verify_policy_checkpoint(&self, checkpoint: Option<&PolicyCheckpoint>) -> Result<(), KeyringError> {
        let Some(checkpoint) = checkpoint else { return Ok(()); };
        let count = usize::try_from(checkpoint.transitions)
            .map_err(|_| KeyringError::Invalid("policy checkpoint is too large".into()))?;
        if count == 0 || self.policy.transitions.len() < count {
            return Err(KeyringError::Invalid("the remote dropped an accepted role policy".into()));
        }
        let prefix = PolicyLog {
            baseline: self.policy.baseline.clone(),
            transitions: self.policy.transitions[..count].to_vec(),
        };
        if prefix.digest(self.remote, &self.owner.signing) != checkpoint.digest {
            return Err(KeyringError::Invalid("the remote rewrote an accepted role policy".into()));
        }
        Ok(())
    }

    pub fn policy_snapshot(&self) -> Result<Snapshot, KeyringError> {
        if self.policy.is_empty() {
            return Ok(Snapshot::at_root(&self.owner));
        }
        self.policy
            .replay(&self.owner, self.remote)
            .map_err(|e| KeyringError::Invalid(e.to_string()))
    }

    fn check_epoch_and_grants(
        &self,
        transitions: &[SignedTransition],
        new_grants: &[Grant],
    ) -> Result<(), KeyringError> {
        let mut expected = std::collections::BTreeMap::<String, u64>::new();
        for transition in transitions {
            if let TransitionBody::AdvanceEpoch { group, epoch } = &transition.body {
                let next = self
                    .head
                    .epochs
                    .get(group)
                    .copied()
                    .map(|current| current.checked_add(1).ok_or_else(|| KeyringError::Invalid("epoch overflow".into())))
                    .transpose()?
                    .unwrap_or(1);
                if *epoch != next || expected.insert(group.clone(), *epoch).is_some() {
                    return Err(KeyringError::Invalid(
                        "epoch advance is not the next epoch".into(),
                    ));
                }
            }
        }
        let mut auths = 0usize;
        for transition in transitions {
            if let TransitionBody::AuthorizeGrant {
                group,
                epoch,
                recipient,
                grant_signature,
            } = &transition.body
            {
                auths += 1;
                let current = expected
                    .get(group)
                    .copied()
                    .or_else(|| self.head.epochs.get(group).copied());
                if current != Some(*epoch) {
                    return Err(KeyringError::Invalid(
                        "grant is not for the current epoch".into(),
                    ));
                }
                let Some(issued) = new_grants.iter().find(|g| g.signature == *grant_signature) else {
                    return Err(KeyringError::Invalid(
                        "authorized grant is missing".into(),
                    ));
                };
                if issued.context.group != *group
                    || issued.context.epoch != *epoch
                    || issued.context.remote != self.remote
                    || issued.recipient != *recipient
                    || issued.granter != transition.signer
                {
                    return Err(KeyringError::Invalid(
                        "grant does not match its authorization".into(),
                    ));
                }
            }
        }
        if new_grants.len() != auths {
            return Err(KeyringError::Invalid(
                "every new grant needs an authorization".into(),
            ));
        }
        Ok(())
    }

    fn sign_head(&mut self, signer: &Identity) {
        let mut message = self.head.signing_bytes();
        if !self.policy.is_empty() {
            message.extend_from_slice(&self.policy.digest(self.remote, &self.owner.signing));
        }
        self.head.signature = signer.sign(&message);
    }

    fn head_message(&self) -> Vec<u8> {
        let mut message = self.head.signing_bytes();
        if !self.policy.is_empty() {
            message.extend_from_slice(&self.policy.digest(self.remote, &self.owner.signing));
        }
        message
    }

    /// Checks the pin, the head signature, the counter, and every grant
    /// signature. Does not unwrap epoch keys.
    pub fn verify(
        &self,
        pinned_owner_signing_key: &[u8; 32],
        min_counter: u64,
    ) -> Result<VerifiedKeyring, KeyringError> {
        if self.owner.signing != *pinned_owner_signing_key {
            return Err(KeyringError::Invalid(
                "owner signing key does not match the pin".into(),
            ));
        }
        if self.head.remote != self.remote {
            return Err(KeyringError::Invalid(
                "head is for a different remote".into(),
            ));
        }
        let snapshot = self.policy_snapshot()?;
        let mut head_keys = BTreeSet::from([snapshot.current_owner.signing]);
        if !self.policy.is_empty() {
            let last = self.policy.transitions.last().ok_or_else(|| {
                KeyringError::Invalid("role policy has no transition".into())
            })?;
            if last.counter_after != self.head.counter {
                return Err(KeyringError::Invalid("head counter does not match its policy batch".into()));
            }
            let batch: Vec<_> = self.policy.transitions.iter()
                .filter(|t| t.counter_after == self.head.counter).collect();
            if !batch.iter().any(|t| matches!(t.body, TransitionBody::Transfer { .. })) {
                head_keys.extend(batch.iter().map(|t| t.signer));
            }
            self.verify_policy_epochs()?;
        }
        let message = self.head_message();
        let signature = ed25519_dalek::Signature::from_bytes(&self.head.signature);
        if !head_keys.into_iter().any(|signing| {
            ed25519_dalek::VerifyingKey::from_bytes(&signing)
                .is_ok_and(|key| key.verify_strict(&message, &signature).is_ok())
        }) {
            return Err(KeyringError::Invalid("bad head signature".into()));
        }
        if self.head.counter < min_counter {
            return Err(KeyringError::RolledBack);
        }
        let mut commitments = BTreeMap::new();
        for issued in &self.grants {
            if issued.context.remote != self.remote {
                return Err(KeyringError::Invalid(
                    "grant is for a different remote".into(),
                ));
            }
            let context = (issued.context.group.clone(), issued.context.epoch);
            if commitments.insert(context, issued.commitment).is_some_and(|old| old != issued.commitment) {
                return Err(KeyringError::Invalid("grants disagree about an epoch key commitment".into()));
            }
            snapshot
                .grant_trusted(
                    &self.policy.baseline,
                    &issued.context.group,
                    issued.context.epoch,
                    &issued.recipient,
                    &issued.granter,
                    &issued.signature,
                )
                .map_err(|e| KeyringError::Invalid(e.to_string()))?;
            issued.verify_signature(&issued.granter)?;
        }
        Ok(VerifiedKeyring {
            remote: self.remote,
            epochs: self.head.epochs.clone(),
            counter: self.head.counter,
            grants: self.grants.clone(),
            owner_signing: *pinned_owner_signing_key,
            snapshot,
            baseline: self.policy.baseline.clone(),
        })
    }

    fn verify_policy_epochs(&self) -> Result<(), KeyringError> {
        let mut epochs = BTreeMap::<String, u64>::new();
        for grant in &self.grants {
            if self.policy.baseline.contains(&grant.signature) {
                let epoch = epochs.entry(grant.context.group.clone()).or_default();
                *epoch = (*epoch).max(grant.context.epoch);
            }
        }
        let has_custody = |group: &str, epoch: u64, signer: &[u8; 32], authorized: &BTreeSet<[u8; 64]>| {
            self.grants.iter().any(|grant| grant.context.group == group
                && grant.context.epoch == epoch && grant.recipient.signing == *signer
                && authorized.contains(&grant.signature))
        };
        let mut authorized = self.policy.baseline.clone();
        let mut index = 0;
        while index < self.policy.transitions.len() {
            let counter = self.policy.transitions[index].counter_after;
            let start = index;
            while index < self.policy.transitions.len() && self.policy.transitions[index].counter_after == counter {
                index += 1;
            }
            let batch = &self.policy.transitions[start..index];
            let prior = epochs.clone();
            let mut advanced = BTreeSet::new();
            for transition in batch {
                if let TransitionBody::AdvanceEpoch { group, epoch } = &transition.body {
                    if !advanced.insert(group) { return Err(KeyringError::Invalid("duplicate group epoch advance".into())); }
                    let previous = prior.get(group).copied();
                    if previous.is_some_and(|old| !has_custody(group, old, &transition.signer, &authorized)) {
                        return Err(KeyringError::Invalid("only an existing key holder may rotate the group".into()));
                    }
                    let next = epochs.get(group).copied().unwrap_or(0).checked_add(1)
                        .ok_or_else(|| KeyringError::Invalid("epoch overflow".into()))?;
                    if *epoch != next {
                        return Err(KeyringError::Invalid("policy epoch is not the next epoch".into()));
                    }
                    epochs.insert(group.clone(), *epoch);
                }
            }
            for transition in batch {
                if let TransitionBody::AuthorizeGrant { group, epoch, grant_signature, .. } = &transition.body {
                    if prior.get(group).copied().is_some_and(|old| !has_custody(group, old, &transition.signer, &authorized)) {
                        return Err(KeyringError::Invalid("only an existing key holder may wrap the group key".into()));
                    }
                    if epochs.get(group) != Some(epoch)
                        || !self.grants.iter().any(|grant| grant.signature == *grant_signature)
                    {
                        return Err(KeyringError::Invalid("policy grant is not at its issuing epoch".into()));
                    }
                }
            }
            for transition in batch {
                if let TransitionBody::AuthorizeGrant { grant_signature, .. } = &transition.body {
                    authorized.insert(*grant_signature);
                }
            }
        }
        if epochs != self.head.epochs {
            return Err(KeyringError::Invalid("head epochs do not match the signed policy".into()));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, KeyringError> {
        if self.grants.len() > MAX_GRANTS || self.head.epochs.len() > MAX_GROUPS {
            return Err(KeyringError::Invalid("keyring is too large".into()));
        }
        let mut grants = self.grants.clone();
        grants.sort_by_key(grant_rank);
        for pair in grants.windows(2) {
            if grant_rank(&pair[0]) == grant_rank(&pair[1]) {
                return Err(KeyringError::Invalid("duplicate grant".into()));
            }
        }
        let mut w = Writer::new();
        w.u8(if self.policy.is_empty() {
            VERSION
        } else {
            VERSION_ROLES
        });
        w.buf.extend_from_slice(&self.remote);
        w.buf.extend_from_slice(&self.owner.encryption);
        w.buf.extend_from_slice(&self.owner.signing);
        w.buf.extend_from_slice(&self.head.remote);
        w.varint(self.head.counter);
        w.varint(self.head.epochs.len() as u64);
        for (group, epoch) in &self.head.epochs {
            if group.len() > MAX_GROUP {
                return Err(KeyringError::Invalid("group name is too long".into()));
            }
            w.str(group);
            w.varint(*epoch);
        }
        w.buf.extend_from_slice(&self.head.signature);
        w.varint(grants.len() as u64);
        for issued in &grants {
            if issued.context.group.len() > MAX_GROUP || issued.wrapped.ciphertext.len() > MAX_WRAP
            {
                return Err(KeyringError::Invalid("grant is too large".into()));
            }
            write_grant(&mut w, issued);
        }
        if !self.policy.is_empty() {
            w.bytes(&self.policy.encode_body(self.remote, &self.owner.signing));
        }
        Ok(w.finish())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KeyringError> {
        let mut r = Reader::new(bytes, "keyring");
        let version = r.u8()?;
        if version != VERSION && version != VERSION_ROLES {
            return Err(KeyringError::Invalid(format!(
                "unsupported version {version}"
            )));
        }
        let remote = read_array(&mut r)?;
        let owner = PublicIdentity {
            encryption: read_array(&mut r)?,
            signing: read_array(&mut r)?,
        };
        let head_remote = read_array(&mut r)?;
        let counter = r.varint()?;
        let n_epochs = r.count(2)?;
        if n_epochs > MAX_GROUPS {
            return Err(KeyringError::Invalid("too many groups".into()));
        }
        let mut epochs = BTreeMap::new();
        let mut previous_group: Option<String> = None;
        for _ in 0..n_epochs {
            let group = read_limited_str(&mut r, MAX_GROUP)?;
            let epoch = r.varint()?;
            if previous_group
                .as_ref()
                .is_some_and(|prev| group.as_str() <= prev.as_str())
            {
                return Err(KeyringError::Invalid(
                    "epochs are not in canonical order".into(),
                ));
            }
            previous_group = Some(group.clone());
            epochs.insert(group, epoch);
        }
        let signature = read_array(&mut r)?;
        let n_grants = r.count(MIN_GRANT)?;
        if n_grants > MAX_GRANTS {
            return Err(KeyringError::Invalid("too many grants".into()));
        }
        let mut grants = Vec::with_capacity(n_grants);
        let mut previous_grant: Option<GrantRank> = None;
        for _ in 0..n_grants {
            let issued = read_grant(&mut r)?;
            let rank = grant_rank(&issued);
            if previous_grant.as_ref().is_some_and(|prev| rank <= *prev) {
                return Err(KeyringError::Invalid(
                    "grants are not in canonical order".into(),
                ));
            }
            previous_grant = Some(rank);
            grants.push(issued);
        }
        let policy = if version == VERSION_ROLES {
            let body = r.bytes()?;
            let (log, got_remote, root) = PolicyLog::decode_body(body)
                .map_err(|e| KeyringError::Invalid(e.to_string()))?;
            if got_remote != remote || root != owner.signing {
                return Err(KeyringError::Invalid(
                    "role policy is for a different remote or root".into(),
                ));
            }
            if log.is_empty() {
                return Err(KeyringError::Invalid(
                    "version 2 keyring is missing role policy".into(),
                ));
            }
            log
        } else {
            PolicyLog::empty()
        };
        r.finish()?;
        Ok(Keyring {
            remote,
            owner,
            head: SignedHead {
                remote: head_remote,
                counter,
                epochs,
                signature,
            },
            grants,
            policy,
        })
    }

    fn require_owner(&self, owner: &Identity) -> Result<(), KeyringError> {
        if owner.public() != self.owner {
            return Err(KeyringError::Invalid(
                "caller is not the keyring owner".into(),
            ));
        }
        Ok(())
    }

    fn current_epoch(&self) -> Result<u64, KeyringError> {
        self.head
            .epochs
            .get(PRIVATE_GROUP)
            .copied()
            .ok_or_else(|| KeyringError::Invalid("no current private epoch".into()))
    }

    fn is_current(&self, issued: &Grant, epoch: u64) -> bool {
        issued.context.remote == self.remote
            && issued.context.group == PRIVATE_GROUP
            && issued.context.epoch == epoch
    }

    fn member_of(&self, epoch: u64, member: &PublicIdentity) -> bool {
        self.grants
            .iter()
            .any(|issued| self.is_current(issued, epoch) && issued.recipient == *member)
    }

    fn push_grant_and_sign(&mut self, owner: &Identity, issued: Grant) -> Result<(), KeyringError> {
        let counter = self
            .head
            .counter
            .checked_add(1)
            .ok_or_else(|| KeyringError::Invalid("counter overflow".into()))?;
        self.grants.push(issued);
        self.head.counter = counter;
        self.head.remote = self.remote;
        self.sign_head(owner);
        Ok(())
    }
}

/// A keyring whose head and grants have been checked against a pinned owner.
pub struct VerifiedKeyring {
    remote: [u8; 16],
    epochs: BTreeMap<String, u64>,
    counter: u64,
    grants: Vec<Grant>,
    /// Pinned root signing key. Not the current owner after a transfer.
    owner_signing: [u8; 32],
    snapshot: Snapshot,
    baseline: std::collections::BTreeSet<[u8; 64]>,
}

impl VerifiedKeyring {
    /// Highest head counter accepted by [`Keyring::verify`]. Callers store
    /// this and pass it as `min_counter` on the next fetch.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Opens this identity's grant for the head's current epoch of `group`.
    pub fn current_key(&self, group: &str, identity: &Identity) -> Result<EpochKey, KeyringError> {
        let epoch = self
            .epochs
            .get(group)
            .copied()
            .ok_or(KeyringError::NotMember)?;
        self.key_for(group, epoch, identity)
    }

    /// Opens this identity's grant for an older epoch, to read an old pack.
    pub fn key_for(
        &self,
        group: &str,
        epoch: u64,
        identity: &Identity,
    ) -> Result<EpochKey, KeyringError> {
        let me = identity.public();
        let issued = self
            .grants
            .iter()
            .rev()
            .find(|issued| {
                issued.context.remote == self.remote
                    && issued.context.group == group
                    && issued.context.epoch == epoch
                    && issued.recipient == me
            })
            .ok_or(KeyringError::NotMember)?;
        self.snapshot
            .grant_trusted(
                &self.baseline,
                group,
                epoch,
                &me,
                &issued.granter,
                &issued.signature,
            )
            .map_err(|e| KeyringError::Invalid(e.to_string()))?;
        Ok(open_grant(issued, identity, &issued.granter)?)
    }

    /// Current epoch named by the signed head for `group`.
    pub fn current_epoch_of(&self, group: &str) -> Option<u64> {
        self.epochs.get(group).copied()
    }

    /// Every `(group, epoch)` this identity has a trusted grant for, including
    /// historical epochs. This does not mean they may read new content.
    pub fn granted_epochs(&self, identity: &Identity) -> Vec<(String, u64)> {
        let me = identity.public();
        let mut out: Vec<(String, u64)> = self
            .grants
            .iter()
            .filter(|issued| {
                issued.recipient == me
                    && self
                        .snapshot
                        .grant_trusted(
                            &self.baseline,
                            &issued.context.group,
                            issued.context.epoch,
                            &me,
                            &issued.granter,
                            &issued.signature,
                        )
                        .is_ok()
            })
            .map(|issued| (issued.context.group.clone(), issued.context.epoch))
            .collect();
        out.sort();
        out.dedup();
        out
    }

    /// Groups this identity may read at the current policy, ignoring cached keys.
    pub fn readable_groups(&self, actor: &PublicIdentity) -> BTreeSet<String> {
        let mut names: BTreeSet<String> = self.epochs.keys().cloned().collect();
        for role in self.snapshot.roles.values() {
            names.extend(role.groups.iter().cloned());
        }
        names
            .into_iter()
            .filter(|group| self.reads_now(actor, group))
            .collect()
    }

    pub fn reads_now(&self, actor: &PublicIdentity, group: &str) -> bool {
        let holders = self
            .current_epoch_of(group)
            .map(|epoch| Snapshot::current_holders(&self.grants, group, epoch))
            .unwrap_or_default();
        self.snapshot.may_read(actor, group, &holders)
    }

    pub fn group_frozen(&self, group: &str) -> bool {
        match self.current_epoch_of(group) {
            Some(epoch) => self.snapshot.publication_frozen(&self.grants, group, epoch),
            None => false,
        }
    }

    pub fn snapshot(&self) -> &Snapshot {
        &self.snapshot
    }

    /// Pinned root signing key. Ownership transfer does not change this.
    pub fn root_signing(&self) -> &[u8; 32] {
        &self.owner_signing
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct GrantRank {
    remote: [u8; 16],
    group: String,
    epoch: u64,
    encryption: [u8; 32],
    signing: [u8; 32],
    signature: [u8; 64],
}

fn grant_rank(issued: &Grant) -> GrantRank {
    GrantRank {
        remote: issued.context.remote,
        group: issued.context.group.clone(),
        epoch: issued.context.epoch,
        encryption: issued.recipient.encryption,
        signing: issued.recipient.signing,
        signature: issued.signature,
    }
}

fn write_grant(w: &mut Writer, issued: &Grant) {
    w.buf.extend_from_slice(&issued.context.remote);
    w.str(&issued.context.group);
    w.varint(issued.context.epoch);
    w.buf.extend_from_slice(&issued.recipient.encryption);
    w.buf.extend_from_slice(&issued.recipient.signing);
    w.buf.extend_from_slice(&issued.wrapped.ephemeral);
    w.buf.extend_from_slice(&issued.wrapped.nonce);
    w.bytes(&issued.wrapped.ciphertext);
    w.buf.extend_from_slice(&issued.commitment);
    w.buf.extend_from_slice(&issued.granter);
    w.buf.extend_from_slice(&issued.signature);
}

fn read_grant(r: &mut Reader<'_>) -> Result<Grant, KeyringError> {
    let remote = read_array(r)?;
    let group = read_limited_str(r, MAX_GROUP)?;
    let epoch = r.varint()?;
    let encryption = read_array(r)?;
    let signing = read_array(r)?;
    let ephemeral = read_array(r)?;
    let nonce = read_array::<24>(r)?;
    let ciphertext = r.bytes()?;
    if ciphertext.len() > MAX_WRAP {
        return Err(KeyringError::Invalid("wrapped key is too large".into()));
    }
    let ciphertext = ciphertext.to_vec();
    Ok(Grant {
        context: GroupEpoch {
            remote,
            group,
            epoch,
        },
        recipient: PublicIdentity {
            encryption,
            signing,
        },
        wrapped: crate::keys::WrappedKey {
            ephemeral,
            nonce,
            ciphertext,
        },
        commitment: read_array(r)?,
        granter: read_array(r)?,
        signature: read_array(r)?,
    })
}

fn expect_version(r: &mut Reader<'_>) -> Result<(), KeyringError> {
    let version = r.u8()?;
    if version != VERSION {
        return Err(KeyringError::Invalid(format!(
            "unsupported version {version}"
        )));
    }
    Ok(())
}

fn read_array<const N: usize>(r: &mut Reader<'_>) -> Result<[u8; N], KeyringError> {
    let mut out = [0u8; N];
    out.copy_from_slice(r.take(N)?);
    Ok(out)
}

fn read_limited_str(r: &mut Reader<'_>, max: usize) -> Result<String, KeyringError> {
    let text = r.str()?;
    if text.len() > max {
        return Err(KeyringError::Invalid("string is too long".into()));
    }
    Ok(text.to_string())
}

fn require_epoch_key(
    keys: &OwnerKeys,
    remote: [u8; 16],
    epoch: u64,
) -> Result<&EpochKey, KeyringError> {
    if keys.remote != remote {
        return Err(KeyringError::Invalid(
            "owner keys are for a different remote".into(),
        ));
    }
    let key = keys
        .keys
        .get(&(PRIVATE_GROUP.to_string(), epoch))
        .ok_or_else(|| KeyringError::Invalid("owner has no key for this epoch".into()))?;
    let expect = GroupEpoch {
        remote,
        group: PRIVATE_GROUP.to_string(),
        epoch,
    };
    if key.context() != &expect {
        return Err(KeyringError::Invalid(
            "stored epoch key has the wrong context".into(),
        ));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saved_owner_keys_rebuild_the_same_epoch_secret() {
        let owner = Identity::generate().unwrap();
        let (created, keys) = Keyring::create([3; 16], &owner).unwrap();
        let rebuilt = Keyring::from_saved_owner(&owner, &keys).unwrap();
        assert_eq!(rebuilt.remote, created.remote);
        assert_eq!(rebuilt.owner, owner.public());
        assert_eq!(rebuilt.head.counter, 1);
        assert_eq!(rebuilt.head.epochs, created.head.epochs);
        let opened = rebuilt
            .verify(&owner.public().signing, 0)
            .unwrap()
            .key_for(PRIVATE_GROUP, 1, &owner)
            .unwrap();
        let original = keys.keys.get(&(PRIVATE_GROUP.to_string(), 1)).unwrap();
        assert_eq!(opened.to_bytes(), original.to_bytes());
        // The self-grant wrap is fresh, so the files differ.
        assert_ne!(rebuilt.encode().unwrap(), created.encode().unwrap());
    }

    #[test]
    fn noncanonical_and_unsorted_epochs_are_refused() {
        let mut bad = vec![VERSION];
        bad.extend_from_slice(&[7; 16]);
        bad.extend_from_slice(&[1; 32]);
        bad.extend_from_slice(&[2; 32]);
        bad.extend_from_slice(&[7; 16]);
        bad.extend_from_slice(&[0x80, 0x00]);
        assert!(Keyring::decode(&bad).is_err());

        let mut unsorted = vec![VERSION];
        unsorted.extend_from_slice(&[0; 16 + 32 + 32 + 16]);
        unsorted.push(1); // counter
        unsorted.push(2); // two groups, "b" then "a"
        unsorted.extend_from_slice(&[1, b'b', 1, 1, b'a', 1]);
        unsorted.extend_from_slice(&[0; 64]);
        unsorted.push(0); // no grants
        assert!(matches!(
            Keyring::decode(&unsorted),
            Err(KeyringError::Invalid(ref reason)) if reason.contains("canonical")
        ));
    }
}
