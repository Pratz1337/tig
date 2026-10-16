//! Grant and revoke through one atomic remote head.
//!
//! Both commands verify the pinned keyring, write the owner's local
//! `pending-keyring` (and, for revoke, the new epoch secrets) before the
//! remote changes, then `commit_head`. A stale head is verified again, never
//! below the counter of the head the last attempt was built on, and the
//! commit is rebuilt, at most eight times. Revoke puts the owner-resigned
//! manifest and the new keyring in the same commit. The rollback floors in
//! `publish-state` move only after a commit lands; until then the pending
//! keyring is the crash record.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use crate::keyring::{Keyring, KeyringError, OwnerKeys};
use crate::keys::{Identity, PublicIdentity};
use crate::manifest::{self, Manifest};
use crate::project::PRIVATE_GROUP;
use crate::publish::PublishState;
use crate::remote::{CommitOutcome, HeadVersion, Remote, RemoteError, RemoteHead};

const ATTEMPTS: u32 = 8;
const PENDING_FILE: &str = "pending-keyring";
const KEYS_FILE: &str = "owner-keys";
const STATE_FILE: &str = "publish-state";

#[derive(Debug, thiserror::Error)]
pub enum AccessError {
    #[error(transparent)]
    Key(#[from] crate::keys::KeyError),
    #[error(transparent)]
    Keyring(#[from] KeyringError),
    #[error(transparent)]
    Remote(#[from] RemoteError),
    #[error(transparent)]
    Manifest(#[from] crate::manifest::ManifestError),
    #[error(transparent)]
    Publish(#[from] crate::publish::PublishError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("the remote is busy; another publish or access change landed on every attempt")]
    Busy,
    #[error("{0}")]
    Invalid(String),
}

struct Base {
    version: HeadVersion,
    keyring: Keyring,
    manifest: Option<Vec<u8>>,
    sequence: u64,
}

/// Grants `member` the current private epoch. `local_dir` holds `owner-keys`,
/// `pending-keyring`, and `publish-state`.
pub fn grant(
    remote: &dyn Remote,
    local_dir: &Path,
    owner: &Identity,
    keys: &OwnerKeys,
    state: &mut PublishState,
    member: &PublicIdentity,
) -> Result<(), AccessError> {
    save_keys(local_dir, keys)?;
    let mut base = loaded(remote, owner, state)?;
    for attempt in 0..ATTEMPTS {
        if attempt > 0 && is_current_member(&base.keyring, member) {
            accept(local_dir, state, &base.keyring, base.manifest.as_deref())?;
            clear_pending(local_dir)?;
            return Ok(());
        }
        let mut next = base.keyring.clone();
        next.grant(keys, owner, member)?;
        stage(local_dir, &next)?;
        if commit(remote, &base, &next, None)? {
            accept(local_dir, state, &next, base.manifest.as_deref())?;
            clear_pending(local_dir)?;
            return Ok(());
        }
        base = reloaded(remote, owner, base.keyring.head.counter, base.sequence)?;
    }
    Err(AccessError::Busy)
}

/// Revokes `member`: a new epoch for everyone else, and the manifest
/// re-signed by the owner, in one head commit.
pub fn revoke(
    remote: &dyn Remote,
    local_dir: &Path,
    owner: &Identity,
    keys: &mut OwnerKeys,
    state: &mut PublishState,
    member: &PublicIdentity,
) -> Result<(), AccessError> {
    let mut base = loaded(remote, owner, state)?;
    for attempt in 0..ATTEMPTS {
        if !is_current_member(&base.keyring, member) {
            if attempt == 0 {
                return Err(KeyringError::NotMember.into());
            }
            accept(local_dir, state, &base.keyring, base.manifest.as_deref())?;
            clear_pending(local_dir)?;
            return Ok(());
        }
        let mut next = base.keyring.clone();
        next.revoke(keys, owner, member)?;
        save_keys(local_dir, keys)?;
        let resigned = manifest::resign_as_owner(
            base.manifest.as_deref(),
            remote.remote_id(),
            owner,
            &base.keyring,
            state.manifest_seq,
        )?;
        stage(local_dir, &next)?;
        if commit(remote, &base, &next, resigned.as_deref())? {
            accept(local_dir, state, &next, resigned.as_deref())?;
            clear_pending(local_dir)?;
            return Ok(());
        }
        base = reloaded(remote, owner, base.keyring.head.counter, base.sequence)?;
    }
    Err(AccessError::Busy)
}

/// Commits a keyring already built by [`crate::keyring::Keyring::commit_policy`].
/// The pin is the root owner in `state`, not necessarily the current owner.
/// `manifest` is installed in the same head when `Some`. Role rotation that
/// removes publish rights must pass a manifest re-signed by someone who still
/// may publish; this function does not choose that signer.
pub fn commit_keyring(
    remote: &dyn Remote,
    local_dir: &Path,
    state: &mut PublishState,
    build: impl FnMut(&Keyring) -> Result<(Keyring, Option<Vec<u8>>), AccessError>,
) -> Result<(), AccessError> {
    let pin = state.owner_signing.ok_or_else(|| {
        AccessError::Invalid("publish to this remote before changing roles".into())
    })?;
    if state.remote_id != remote.remote_id() {
        return Err(AccessError::Invalid(
            "publish state is for a different remote".into(),
        ));
    }
    let mut base = loaded_with_pin(remote, pin, state)?;
    let mut policy_floor = base.keyring.policy_checkpoint();
    let mut reveals_floor = state.revealed.clone();
    let mut build = build;
    for _ in 0..ATTEMPTS {
        base.keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
        base.keyring.verify_policy_checkpoint(policy_floor.as_ref())?;
        policy_floor = base.keyring.policy_checkpoint();
        check_reveals(&base, &reveals_floor)?;
        if let Some(bytes) = base.manifest.as_deref() {
            reveals_floor.extend(Manifest::decode(bytes)?.reveals.keys().copied());
        }
        let (next, manifest) = build(&base.keyring)?;
        next.verify(&pin, base.keyring.head.counter)?;
        next.verify_policy_checkpoint(base.keyring.policy_checkpoint().as_ref())?;
        if let Some(bytes) = manifest.as_deref().or(base.manifest.as_deref()) {
            let proposed = Manifest::decode(bytes)?;
            proposed.verify(remote.remote_id(), &next, base.sequence).map_err(|error| {
                if matches!(error, manifest::ManifestError::BadSignature) {
                    AccessError::Invalid("an authorized publisher must re-sign the current manifest before this role change".into())
                } else {
                    error.into()
                }
            })?;
            if !reveals_floor.iter().all(|id| proposed.reveals.contains_key(id)) {
                return Err(AccessError::Invalid("a previously revealed change was omitted".into()));
            }
        }
        stage(local_dir, &next)?;
        if commit(remote, &base, &next, manifest.as_deref())? {
            accept(local_dir, state, &next, manifest.as_deref().or(base.manifest.as_deref()))?;
            clear_pending(local_dir)?;
            return Ok(());
        }
        base = decode_base(
            remote.remote_id(),
            remote.read_head()?,
            pin,
            base.keyring.head.counter,
            base.sequence,
        )?;
    }
    Err(AccessError::Busy)
}

/// Finishes an owner update that crashed after the local pending keyring was
/// saved. A newer verified remote head is left in place. When the pending
/// keyring moves the epoch, the manifest is re-signed into the same commit.
pub fn finish_pending(
    remote: &dyn Remote,
    local_dir: &Path,
    owner: &Identity,
    state: &mut PublishState,
) -> Result<(), AccessError> {
    let path = local_dir.join(PENDING_FILE);
    let Some(bytes) = read_optional(&path)? else {
        return Ok(());
    };
    let pending = Keyring::decode(&bytes)?;
    let pin = state
        .owner_signing
        .ok_or_else(|| AccessError::Invalid("pending keyring has no owner pin".into()))?;
    if state.remote_id != pending.remote {
        return Err(AccessError::Invalid(
            "pending keyring is for a different remote".into(),
        ));
    }
    let verified = pending.verify(&pin, 0)?;
    if !pending.policy.is_empty() {
        // Role proposals do not store raw epoch custody on the management
        // client. A committed proposal is recoverable without owner-keys;
        // an uncommitted one must be regenerated against the current head.
        let base = decode_base(remote.remote_id(), remote.read_head()?, pin,
            state.counter, state.manifest_seq)?;
        base.keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
        if base.keyring.head.counter >= pending.head.counter {
            let same = base.keyring.head.counter != pending.head.counter
                || base.keyring.encode()? == bytes;
            accept(local_dir, state, &base.keyring, base.manifest.as_deref())?;
            clear_pending(local_dir)?;
            if same { return Ok(()); }
            return Err(AccessError::Invalid("an interrupted role change was superseded; run it again".into()));
        }
        clear_pending(local_dir)?;
        return Err(AccessError::Invalid("an interrupted role change was not committed; run it again".into()));
    }
    let keys = load_keys(local_dir)?;
    if keys.remote != pending.remote || remote.remote_id() != pending.remote {
        return Err(AccessError::Invalid(
            "pending keyring keys are for a different remote".into(),
        ));
    }
    for (group, epoch) in &pending.head.epochs {
        if !keys.keys.contains_key(&(group.clone(), *epoch)) {
            return Err(AccessError::Invalid(
                "pending keyring epoch key is missing".into(),
            ));
        }
    }
    if owner.public() != pending.owner {
        return Err(AccessError::Invalid(
            "pending keyring belongs to a different owner".into(),
        ));
    }
    // The pending counter is not committed; only saved, committed floors apply.
    let mut base = decode_base(
        remote.remote_id(),
        remote.read_head()?,
        pin,
        state.counter,
        state.manifest_seq,
    )?;
    base.keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    check_reveals(&base, &state.revealed)?;
    if base.keyring.head.counter > verified.counter() {
        accept(local_dir, state, &base.keyring, base.manifest.as_deref())?;
        clear_pending(local_dir)?;
        return Ok(());
    }
    let moved = epochs_of(&base.keyring) != epochs_of(&pending);
    for _ in 0..ATTEMPTS {
        base.keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
        check_reveals(&base, &state.revealed)?;
        if base.keyring.head.counter > verified.counter() {
            accept(local_dir, state, &base.keyring, base.manifest.as_deref())?;
            clear_pending(local_dir)?;
            return Ok(());
        }
        if base.keyring.head.counter == verified.counter() {
            // Either this update landed before the crash, or another owner
            // process committed a different head on the same parent. Never
            // replace a committed head with its sibling.
            let landed = base.keyring.encode()? == bytes;
            accept(local_dir, state, &base.keyring, base.manifest.as_deref())?;
            clear_pending(local_dir)?;
            if landed {
                return Ok(());
            }
            return Err(AccessError::Invalid(
                "an interrupted grant or revoke was superseded by another change to the remote; check its members and run it again"
                    .into(),
            ));
        }
        let resigned = if moved {
            manifest::resign_as_owner(
                base.manifest.as_deref(),
                remote.remote_id(),
                owner,
                &base.keyring,
                state.manifest_seq,
            )?
        } else {
            None
        };
        if commit(remote, &base, &pending, resigned.as_deref())? {
            accept(local_dir, state, &pending, resigned.as_deref())?;
            clear_pending(local_dir)?;
            return Ok(());
        }
        base = decode_base(
            remote.remote_id(),
            remote.read_head()?,
            pin,
            base.keyring.head.counter,
            base.sequence,
        )?;
    }
    Err(AccessError::Busy)
}

fn loaded(
    remote: &dyn Remote,
    owner: &Identity,
    state: &PublishState,
) -> Result<Base, AccessError> {
    let pin = state
        .owner_signing
        .ok_or_else(|| AccessError::Invalid("publish to this remote before granting or revoking".into()))?;
    if state.remote_id != remote.remote_id() {
        return Err(AccessError::Invalid(
            "publish state is for a different remote".into(),
        ));
    }
    if owner.public().signing != pin {
        return Err(AccessError::Invalid(
            "only the owner of this remote can grant or revoke".into(),
        ));
    }
    loaded_with_pin(remote, pin, state)
}

fn loaded_with_pin(
    remote: &dyn Remote,
    pin: [u8; 32],
    state: &PublishState,
) -> Result<Base, AccessError> {
    let head = remote.read_head()?;
    let base = decode_base(remote.remote_id(), head, pin, state.counter, state.manifest_seq)?;
    base.keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    check_reveals(&base, &state.revealed)?;
    Ok(base)
}

/// The head after a lost race, never older than `floor`, the counter of the
/// head the previous attempt was built on.
fn reloaded(
    remote: &dyn Remote,
    owner: &Identity,
    floor: u64,
    sequence: u64,
) -> Result<Base, AccessError> {
    let head = remote.read_head()?;
    decode_base(remote.remote_id(), head, owner.public().signing, floor, sequence)
}

fn decode_base(
    remote_id: [u8; 16],
    head: RemoteHead,
    pin: [u8; 32],
    floor: u64,
    sequence_floor: u64,
) -> Result<Base, AccessError> {
    let Some(bytes) = head.keyring.as_deref() else {
        return Err(AccessError::Invalid(
            "this remote has no keyring yet; publish to it first".into(),
        ));
    };
    let keyring = Keyring::decode(bytes)?;
    if keyring.remote != remote_id {
        return Err(AccessError::Invalid(
            "keyring is for a different remote".into(),
        ));
    }
    keyring.verify(&pin, floor)?;
    let sequence = match head.manifest.as_deref() {
        Some(bytes) => {
            let manifest = Manifest::decode(bytes)?;
            manifest.verify(remote_id, &keyring, sequence_floor)?;
            manifest.sequence
        }
        None if sequence_floor > 0 => {
            return Err(AccessError::Invalid(
                "the remote's publish manifest is missing, but this state has seen one".into(),
            ))
        }
        None => 0,
    };
    Ok(Base {
        version: head.version(),
        keyring,
        manifest: head.manifest,
        sequence,
    })
}

fn check_reveals(base: &Base, known: &BTreeSet<tig_core::ObjectId>) -> Result<(), AccessError> {
    if known.is_empty() { return Ok(()); }
    let manifest = base.manifest.as_deref().map(Manifest::decode).transpose()?;
    if !known.iter().all(|id| manifest.as_ref().is_some_and(|m| m.reveals.contains_key(id))) {
        return Err(AccessError::Invalid("the remote dropped a known reveal certificate".into()));
    }
    Ok(())
}

/// `true` when the commit landed.
fn commit(
    remote: &dyn Remote,
    base: &Base,
    next: &Keyring,
    manifest: Option<&[u8]>,
) -> Result<bool, AccessError> {
    let bytes = next.encode()?;
    match remote.commit_head(&base.version, Some(&bytes), manifest)? {
        CommitOutcome::Committed(_) => Ok(true),
        CommitOutcome::Stale(_) => Ok(false),
    }
}

/// Saves the signed head about to be committed, for crash recovery. It is
/// not a rollback floor yet: the commit may lose a race.
fn stage(local_dir: &Path, next: &Keyring) -> Result<(), AccessError> {
    write_file(&local_dir.join(PENDING_FILE), &next.encode()?, false)
}

/// Raises the saved floors to a head that is now on the remote. `manifest`
/// is the manifest bytes this call committed, if any.
fn accept(
    local_dir: &Path,
    state: &mut PublishState,
    keyring: &Keyring,
    manifest: Option<&[u8]>,
) -> Result<(), AccessError> {
    keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    let manifest = manifest.map(Manifest::decode).transpose()?;
    if manifest.as_ref().is_some_and(|m| !state.revealed.iter().all(|id| m.reveals.contains_key(id))) {
        return Err(AccessError::Invalid("the remote dropped a known reveal certificate".into()));
    }
    state.counter = state.counter.max(keyring.head.counter);
    state.policy_checkpoint = keyring.policy_checkpoint();
    if let Some(manifest) = manifest {
        state.manifest_seq = state.manifest_seq.max(manifest.sequence);
        state.revealed.extend(manifest.reveals.keys().copied());
    }
    save_state(local_dir, state)
}

fn is_current_member(keyring: &Keyring, member: &PublicIdentity) -> bool {
    let Some(&epoch) = keyring.head.epochs.get(PRIVATE_GROUP) else {
        return false;
    };
    keyring.grants.iter().any(|grant| {
        grant.context.group == PRIVATE_GROUP
            && grant.context.epoch == epoch
            && grant.recipient == *member
    })
}

fn epochs_of(keyring: &Keyring) -> Vec<(String, u64)> {
    keyring
        .head
        .epochs
        .iter()
        .map(|(group, epoch)| (group.clone(), *epoch))
        .collect()
}

fn save_keys(dir: &Path, keys: &OwnerKeys) -> Result<(), AccessError> {
    write_file(&dir.join(KEYS_FILE), &keys.encode()?, true)
}

fn load_keys(dir: &Path) -> Result<OwnerKeys, AccessError> {
    let bytes = read_optional(&dir.join(KEYS_FILE))?.ok_or_else(|| {
        AccessError::Invalid("pending keyring has no saved owner keys".into())
    })?;
    Ok(OwnerKeys::decode(&bytes)?)
}

fn save_state(dir: &Path, state: &PublishState) -> Result<(), AccessError> {
    write_file(&dir.join(STATE_FILE), &state.encode()?, false)
}

fn clear_pending(dir: &Path) -> Result<(), AccessError> {
    match fs::remove_file(dir.join(PENDING_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, AccessError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn write_file(dest: &Path, bytes: &[u8], secret: bool) -> Result<(), AccessError> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut rnd = [0u8; 8];
    getrandom::getrandom(&mut rnd)
        .map_err(|error| AccessError::Invalid(format!("no randomness: {error}")))?;
    let tmp = dest.with_extension(format!("tmp-{}", hex::encode(rnd)));
    let write = (|| -> Result<(), AccessError> {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
        if secret {
            lock_down(&tmp)?;
        }
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp, dest)?;
        Ok(())
    })();
    if write.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    write
}

fn lock_down(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
