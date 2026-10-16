//! `tig seal` and `tig reveal`.
//!
//! The remote head is the publication boundary; local undo cannot undo disclosure.

use std::path::Path;
use std::collections::BTreeMap;
use tig_core::store::StoreExt;

use tig_private::changes::{self, Correspondence, RevealRequest, SealCommand};
use tig_private::manifest::Manifest;
use tig_private::keyring::Keyring;
use tig_private::keys::EpochKey;

use super::identity;
use super::workspace;
use super::{CliError, Result};

pub(super) fn seal(
    repository: Option<&Path>,
    remote_name: String,
    bookmark: String,
    revision: Option<String>,
    role: String,
) -> Result<()> {
    let (mut session, _) = super::open_ready(repository)?;
    let identity = identity::load_or_create()?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let cfg = super::remote::require(&tig, &remote_name)?;
    let remote = super::remote::connect(&cfg, Some(&identity), true)?;
    let mut state = super::remote::load_publish_state(&cfg.dir)?;
    let fetched = super::remote::load_fetch_state(&cfg.dir)?;
    let known_reveals = state.revealed.union(&fetched.revealed).copied().collect();
    let pin = state.owner_signing.ok_or_else(|| {
        CliError::msg("publish to this remote before sealing a private change")
    })?;
    if state.remote_id != remote.remote_id() {
        return Err(CliError::msg("publish state is for a different remote"));
    }
    let bytes = remote
        .read_head()?
        .keyring
        .ok_or_else(|| CliError::msg("this remote has no keyring yet; publish to it first"))?;
    let keyring = Keyring::decode(&bytes)?;
    let verified = keyring.verify(&pin, state.counter)?;
    keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    super::remote::verify_policy_checkpoints(&cfg.dir, &keyring)?;
    let epoch = keyring
        .head
        .epochs
        .get(&role)
        .copied()
        .ok_or_else(|| CliError::msg(format!("role {role} has no current epoch")))?;
    let owner_keys = super::remote::load_owner_keys(&cfg.dir)?;
    let grant_key = if owner_keys.is_none() {
        Some(verified.current_key(&role, &identity)?)
    } else {
        None
    };
    let role_key: &EpochKey = if let Some(key) = grant_key.as_ref() {
        key
    } else {
        owner_keys
            .as_ref()
            .and_then(|keys| keys.keys.get(&(role.clone(), epoch)))
            .ok_or_else(|| CliError::msg(format!("no local epoch key for role {role}")))?
    };
    let mut projection_keys = BTreeMap::new();
    for (group, current_epoch) in &keyring.head.epochs {
        let available = owner_keys.as_ref().and_then(|keys| keys.keys.get(&(group.clone(), *current_epoch)))
            .map(|key| EpochKey::from_bytes(key.context().clone(), *key.to_bytes()))
            .or_else(|| verified.current_key(group, &identity).ok());
        if let Some(key) = available { projection_keys.insert(group.clone(), key); }
    }
    let privacy_keys = projection_keys.iter().map(|(group, key)| (group.clone(), key)).collect();
    let revision = match revision {
        Some(spec) => session.resolve(&spec)?,
        None => session.working()?,
    };
    let correspondence = Correspondence::from_local_to_public(&state.revisions);
    let report = changes::seal_command(SealCommand {
        repo: &mut session.repo,
        remote: remote.as_ref(),
        identity: &identity,
        keyring: &keyring,
        pinned_owner: &pin,
        min_counter: state.counter,
        min_sequence: state.manifest_seq,
        known_reveals: &known_reveals,
        bookmark: &bookmark,
        revision,
        role: &role,
        role_key,
        privacy_keys: &privacy_keys,
        correspondence: &correspondence,
    })?;
    state.revisions.insert(revision, report.skeleton);
    state.revealed.extend(report.revealed);
    let sealed_tree = session.repo.store().get_revision(&revision)?.tree;
    for (_, leaf) in tig_private::project::classify_with_roles(session.repo.store().as_ref(), &sealed_tree)?.private_files {
        for id in tig_core::blob::content_ids(session.repo.store().as_ref(), &leaf.id())? {
            state.ever_private.insert(id);
        }
    }
    state.counter = state.counter.max(keyring.head.counter);
    state.policy_checkpoint = keyring.policy_checkpoint();
    state.manifest_seq = state.manifest_seq.max(report.sequence);
    super::remote::save_publish_state(&cfg.dir, &state)?;
    println!(
        "sealed {} at {}",
        report.change_id.short(8),
        report.skeleton.short(12)
    );
    Ok(())
}

pub(super) fn reveal(
    repository: Option<&Path>,
    remote_name: String,
    revision: String,
) -> Result<()> {
    let (session, _) = super::open_ready(repository)?;
    let identity = identity::load_or_create()?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let cfg = super::remote::require(&tig, &remote_name)?;
    let remote = super::remote::connect(&cfg, Some(&identity), true)?;
    let mut state = super::remote::load_publish_state(&cfg.dir)?;
    let mut fetched = super::remote::load_fetch_state(&cfg.dir)?;
    let known_reveals = state.revealed.union(&fetched.revealed).copied().collect();
    let pin = state.owner_signing.ok_or_else(|| CliError::msg("fetch or publish before revealing a private change"))?;
    if state.remote_id != remote.remote_id() {
        return Err(CliError::msg("publish state is for a different remote"));
    }
    let head = remote.read_head()?;
    let keyring = Keyring::decode(head.keyring.as_deref().ok_or_else(|| CliError::msg("this remote has no keyring"))?)?;
    let verified = keyring.verify(&pin, state.counter)?;
    keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    super::remote::verify_policy_checkpoints(&cfg.dir, &keyring)?;
    if identity.public() != keyring.policy_snapshot()?.current_owner {
        return Err(CliError::msg("only the current owner can reveal a private change"));
    }
    let local = session.resolve(&revision)?;
    let skeleton = state.revisions.get(&local).copied().unwrap_or(local);
    let manifest = Manifest::decode(head.manifest.as_deref().ok_or_else(|| CliError::msg("this remote has no manifest"))?)?;
    manifest.verify(remote.remote_id(), &keyring, state.manifest_seq)?;
    let entry = manifest.entry(&skeleton).ok_or_else(|| CliError::msg("that revision is not a sealed private change"))?;
    let owner_keys = super::remote::load_owner_keys(&cfg.dir)?;
    let grant_key = verified.key_for(&entry.group, entry.epoch, &identity).ok();
    let role_key = owner_keys.as_ref()
        .and_then(|keys| keys.keys.get(&(entry.group.clone(), entry.epoch)))
        .or(grant_key.as_ref())
        .ok_or_else(|| CliError::msg("no local role key for this private change"))?;
    let report = changes::publish_reveal(&RevealRequest {
        remote: remote.as_ref(), owner: &identity, keyring: &keyring,
        pinned_owner: &pin, min_counter: state.counter, min_sequence: state.manifest_seq,
        skeleton, role_key, expected: &head.version(),
        known_reveals: &known_reveals,
    })?;
    state.counter = state.counter.max(keyring.head.counter);
    state.policy_checkpoint = keyring.policy_checkpoint();
    state.revealed.extend(manifest.reveals.keys().copied());
    state.revealed.insert(skeleton);
    state.ever_public.extend(report.public_paths);
    state.manifest_seq = manifest.sequence.checked_add(1).ok_or_else(|| CliError::msg("manifest sequence overflow"))?;
    fetched.revealed.extend(state.revealed.iter().copied());
    fetched.policy_checkpoint = keyring.policy_checkpoint();
    fetched.counter = fetched.counter.max(keyring.head.counter);
    fetched.manifest_seq = fetched.manifest_seq.max(state.manifest_seq);
    super::remote::save_fetch_state(&cfg.dir, &fetched)?;
    super::remote::save_publish_state(&cfg.dir, &state)?;
    println!("revealed {}", skeleton.short(12));
    Ok(())
}
