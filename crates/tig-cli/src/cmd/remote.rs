//! `tig remote`, and the `.tig/remotes/<name>/` files other commands share.

use std::fs;
use std::path::{Path, PathBuf};

use tig_private::fetch::FetchState;
use tig_private::keyring::{Keyring, OwnerKeys};
use tig_private::keys::Identity;
use tig_private::publish::PublishState;
use tig_private::remote::{DirRemote, Remote, RemoteError};
use tig_remote_http::HttpRemote;

use super::workspace;
use super::{CliError, Result};
use crate::ui;

pub(super) struct RemoteCfg {
    pub name: String,
    pub dir: PathBuf,
    pub location: Location,
}

/// Where a remote lives. A directory remote keeps its path in
/// `.tig/remotes/<name>/path`, as it always has; a server remote keeps its URL
/// in `.tig/remotes/<name>/url` instead.
pub(super) enum Location {
    Dir(PathBuf),
    Url(String),
}

impl Location {
    /// Anything with a scheme is a URL. The HTTP client refuses schemes other
    /// than https, and plain http to anything but loopback.
    fn parse(text: &str) -> Result<Location> {
        if text.contains("://") {
            Ok(Location::Url(text.trim().to_string()))
        } else {
            Ok(Location::Dir(absolute_path(Path::new(text))?))
        }
    }

    fn show(&self) -> String {
        match self {
            Location::Dir(path) => ui::show_path(path),
            Location::Url(url) => url.clone(),
        }
    }
}

/// Owner material for grant and revoke. The identity stays with the caller.
pub(super) struct OwnerBundle {
    pub remote: Box<dyn Remote>,
    #[allow(dead_code)]
    pub keyring: Keyring,
    pub keys: OwnerKeys,
    pub state: PublishState,
}

pub(super) fn run(repository: Option<&Path>, action: super::RemoteAction) -> Result<()> {
    match action {
        super::RemoteAction::Add { name, location } => add(repository, &name, &location),
        super::RemoteAction::List => list(repository),
        super::RemoteAction::Remove { name } => remove(repository, &name),
    }
}

pub(super) fn add(repository: Option<&Path>, name: &str, location: &str) -> Result<()> {
    validate_name(name)?;
    let (mut session, before) = super::open_ready(repository)?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let dir = tig.join("remotes").join(name);
    if dir.try_exists()? {
        return Err(CliError::msg(format!("remote {name} already exists")));
    }
    let cfg = RemoteCfg {
        name: name.to_string(),
        dir,
        location: Location::parse(location)?,
    };
    let (file, text) = match &cfg.location {
        Location::Dir(path) => ("path", path_text(path)?),
        Location::Url(url) => {
            let url = tig_remote_http::check_url(url)?;
            ("url", format!("{url}\n"))
        }
    };
    fs::create_dir_all(&cfg.dir)?;
    if !super::disk::write_new(&cfg.dir.join(file), text.as_bytes(), false)? {
        return Err(CliError::msg(format!("remote {name} already exists")));
    }
    println!("added remote {name} at {}", cfg.location.show());
    super::announce_if_moved(&mut session, before)
}

fn list(repository: Option<&Path>) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let mut rows = Vec::new();
    match fs::read_dir(tig.join("remotes")) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(CliError::msg(format!("cannot read remotes: {err}")));
        }
        Ok(entries) => {
            for entry in entries {
                let entry = entry?;
                if !entry.file_type()?.is_dir() {
                    continue;
                }
                let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                    continue;
                };
                if !valid_name(&name) {
                    continue;
                }
                let cfg = require(&tig, &name)?;
                rows.push((cfg.name, cfg.location.show()));
            }
        }
    }
    rows.sort();
    if rows.is_empty() {
        println!("No remotes.");
    } else {
        for (name, location) in rows {
            println!("{name} {location}");
        }
    }
    super::announce_if_moved(&mut session, before)
}

fn remove(repository: Option<&Path>, name: &str) -> Result<()> {
    validate_name(name)?;
    let (mut session, before) = super::open_ready(repository)?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let dir = tig.join("remotes").join(name);
    if !dir.try_exists()? {
        return Err(CliError::msg(format!("no remote named {name}")));
    }
    fs::remove_dir_all(&dir)?;
    println!("removed remote {name}");
    super::announce_if_moved(&mut session, before)
}

pub(super) fn require(tig: &Path, name: &str) -> Result<RemoteCfg> {
    validate_name(name)?;
    let dir = tig.join("remotes").join(name);
    // A `url` file names a server. Otherwise read the `path` file that
    // every remote had before servers existed.
    let location = match read_optional(&dir.join("url"))? {
        Some(bytes) => Location::Url(config_text(name, bytes)?),
        None => match read_optional(&dir.join("path"))? {
            Some(bytes) => Location::Dir(PathBuf::from(config_text(name, bytes)?)),
            None => return Err(CliError::msg(format!("no remote named {name}"))),
        },
    };
    Ok(RemoteCfg {
        name: name.to_string(),
        dir,
        location,
    })
}

fn config_text(name: &str, bytes: Vec<u8>) -> Result<String> {
    let text = String::from_utf8(bytes)
        .map_err(|_| CliError::msg(format!("remote {name} is not valid text")))?;
    let text = text.trim();
    if text.is_empty() {
        return Err(CliError::msg(format!(
            "remote {name} has an empty location"
        )));
    }
    Ok(text.to_string())
}

/// The one place a remote config becomes a connection. `create` makes a
/// missing directory remote; a server remote is created by `tig-server
/// init`. `identity` signs writes to a server; a directory ignores it.
pub(super) fn connect(
    cfg: &RemoteCfg,
    identity: Option<&Identity>,
    create: bool,
) -> Result<Box<dyn Remote>> {
    match &cfg.location {
        Location::Dir(path) if create => Ok(Box::new(open_or_create(path)?)),
        Location::Dir(path) => Ok(Box::new(open_existing(path)?)),
        Location::Url(url) => {
            // The client keeps its own copy of the identity for signing.
            let identity = identity.map(|id| Identity::from_bytes(*id.to_bytes()));
            match HttpRemote::connect(url, identity) {
                Ok(remote) => Ok(Box::new(remote)),
                Err(RemoteError::Io(err)) => {
                    Err(CliError::msg(format!("cannot reach {url}: {err}")))
                }
                Err(err) => Err(CliError::msg(format!("remote {url}: {err}"))),
            }
        }
    }
}

/// Says what a refused publish means before converting its typed error.
pub(super) fn explain(cfg: &RemoteCfg, err: tig_private::publish::PublishError) -> CliError {
    use tig_private::publish::PublishError;
    let name = &cfg.name;
    let denied = match &err {
        PublishError::Remote(RemoteError::Denied(message)) => Some(message.as_str()),
        PublishError::Keyring(tig_private::keyring::KeyringError::NotMember) => Some("you are not a member"),
        PublishError::Invalid(message) if message == "you are not a member" => Some(message.as_str()),
        _ => None,
    };
    if denied == Some("you are not a member") {
        CliError::msg(format!(
            "you are not a member of remote {name}; ask its owner to grant you access"
        ))
    } else if let Some(message) = denied {
        CliError::msg(format!("remote {name} refused the signed request: {message}"))
    } else {
        err.into()
    }
}

/// Opens a remote, creating the directory layout and a random id when it
/// has none yet. Does not write a keyring.
fn open_or_create(path: &Path) -> Result<DirRemote> {
    match DirRemote::open(path) {
        Ok(remote) => Ok(remote),
        Err(RemoteError::Invalid(message)) if message == "remote-id is missing" => {
            let mut id = [0u8; 16];
            getrandom::getrandom(&mut id)
                .map_err(|err| CliError::msg(format!("no randomness: {err}")))?;
            Ok(DirRemote::create(path, id)?)
        }
        Err(err) => Err(err.into()),
    }
}

fn open_existing(path: &Path) -> Result<DirRemote> {
    match DirRemote::open(path) {
        Ok(remote) => Ok(remote),
        Err(RemoteError::Invalid(message)) if message == "remote-id is missing" => {
            Err(CliError::msg(format!(
                "{} is not a tig remote yet; publish to it first",
                ui::show_path(path)
            )))
        }
        Err(err) => Err(err.into()),
    }
}

pub(super) fn load_publish_state(dir: &Path) -> Result<PublishState> {
    Ok(load_states(dir, true)?.0)
}

/// Fetch, publish, grant and revoke share one owner pin and rollback floor.
/// A head learned through one command must be trusted by the others.
fn load_states(dir: &Path, pending_floor: bool) -> Result<(PublishState, FetchState)> {
    let mut published = match read_optional(&dir.join("publish-state"))? {
        None => Ok(PublishState::new()),
        Some(bytes) => PublishState::decode(&bytes)
            .map_err(|err| CliError::msg(format!("cannot read publish state: {err}"))),
    }?;
    let mut fetched = match read_optional(&dir.join("fetch-state"))? {
        None => Ok(FetchState::new()),
        Some(bytes) => FetchState::decode(&bytes)
            .map_err(|err| CliError::msg(format!("cannot read fetch state: {err}"))),
    }?;
    let observed = match read_optional(&dir.join("observed-policy"))? {
        Some(bytes) => FetchState::decode(&bytes)?,
        None => FetchState::new(),
    };
    if published.owner_signing.is_some()
        && fetched.owner_signing.is_some()
        && (published.owner_signing != fetched.owner_signing
            || published.remote_id != fetched.remote_id)
    {
        return Err(CliError::msg(
            "fetch and publish state disagree about the remote owner",
        ));
    }
    if let Some(pin) = published.owner_signing.or(fetched.owner_signing).or(observed.owner_signing) {
        let remote_id = if published.owner_signing.is_some() {
            published.remote_id
        } else if fetched.owner_signing.is_some() {
            fetched.remote_id
        } else {
            observed.remote_id
        };
        if observed.owner_signing.is_some()
            && (observed.owner_signing != Some(pin) || observed.remote_id != remote_id)
        {
            return Err(CliError::msg("observed role policy disagrees about the remote owner"));
        }
        let mut counter = published.counter.max(fetched.counter).max(observed.counter);
        if let Some(bytes) = read_optional(&dir.join("pending-keyring"))?.filter(|_| pending_floor) {
            let pending = Keyring::decode(&bytes)?;
            if pending.remote != remote_id {
                return Err(CliError::msg("pending keyring is for a different remote"));
            }
            pending.verify(&pin, 0)?;
            pending.verify_policy_checkpoint(published.policy_checkpoint.as_ref())?;
            pending.verify_policy_checkpoint(fetched.policy_checkpoint.as_ref())?;
            pending.verify_policy_checkpoint(observed.policy_checkpoint.as_ref())?;
            counter = counter.max(pending.head.counter);
        }
        published.remote_id = remote_id;
        fetched.remote_id = remote_id;
        published.owner_signing = Some(pin);
        fetched.owner_signing = Some(pin);
        published.counter = counter;
        fetched.counter = counter;
        let mut checkpoint: Option<tig_private::keyring::PolicyCheckpoint> = None;
        for next in [published.policy_checkpoint, fetched.policy_checkpoint, observed.policy_checkpoint].into_iter().flatten() {
            if let Some(previous) = checkpoint {
                if previous.transitions == next.transitions && previous != next {
                    return Err(CliError::msg("local states disagree about the accepted role policy"));
                }
                if previous.transitions > next.transitions { continue; }
            }
            checkpoint = Some(next);
        }
        published.policy_checkpoint = checkpoint;
        fetched.policy_checkpoint = checkpoint;
        let revealed = published.revealed.union(&fetched.revealed).copied().collect();
        published.revealed = revealed;
        fetched.revealed = published.revealed.clone();
        let sequence = published.manifest_seq.max(fetched.manifest_seq);
        published.manifest_seq = sequence;
        fetched.manifest_seq = sequence;
    }
    Ok((published, fetched))
}

/// Check every persisted prefix before a merged state chooses the newer one.
pub(super) fn verify_policy_checkpoints(dir: &Path, keyring: &Keyring) -> Result<()> {
    if let Some(bytes) = read_optional(&dir.join("publish-state"))? {
        let state = PublishState::decode(&bytes)?;
        keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    }
    if let Some(bytes) = read_optional(&dir.join("fetch-state"))? {
        let state = FetchState::decode(&bytes)?;
        keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    }
    if let Some(bytes) = read_optional(&dir.join("observed-policy"))? {
        let state = FetchState::decode(&bytes)?;
        keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    }
    Ok(())
}

/// Read-only role commands must remember observations too. A separate floor
/// survives stale cache saves; the OS lock serializes competing observations.
pub(super) fn remember_policy_head(dir: &Path, keyring: &Keyring) -> Result<PublishState> {
    let lock = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(dir.join("observed-policy.lock"))?;
    lock.lock()?;
    let mut state = load_publish_state(dir)?;
    let pin = state.owner_signing.ok_or_else(|| CliError::msg("fetch this remote before using its role policy"))?;
    if state.remote_id != keyring.remote { return Err(CliError::msg("keyring is for a different remote")); }
    keyring.verify(&pin, state.counter)?;
    verify_policy_checkpoints(dir, keyring)?;
    let mut observed = FetchState::new();
    observed.remote_id = keyring.remote;
    observed.owner_signing = Some(pin);
    observed.counter = keyring.head.counter;
    observed.policy_checkpoint = keyring.policy_checkpoint();
    let bytes = observed.encode()?;
    let path = dir.join("observed-policy");
    if read_optional(&path)?.as_deref() != Some(bytes.as_slice()) {
        super::disk::write_replace(&path, &bytes, false)?;
    }
    state.counter = observed.counter;
    state.policy_checkpoint = observed.policy_checkpoint;
    Ok(state)
}

pub(super) fn save_publish_state(dir: &Path, state: &PublishState) -> Result<()> {
    let bytes = state.encode()?;
    super::disk::write_replace(&dir.join("publish-state"), &bytes, false)
}

pub(super) fn load_fetch_state(dir: &Path) -> Result<FetchState> {
    Ok(load_states(dir, true)?.1)
}

pub(super) fn save_fetch_state(dir: &Path, state: &FetchState) -> Result<()> {
    let bytes = state.encode()?;
    super::disk::write_replace(&dir.join("fetch-state"), &bytes, false)
}

pub(super) fn load_owner_keys(dir: &Path) -> Result<Option<OwnerKeys>> {
    match read_optional(&dir.join("owner-keys"))? {
        None => Ok(None),
        Some(bytes) => Ok(Some(OwnerKeys::decode(&bytes)?)),
    }
}

/// Creates `owner-keys` only when it is absent. Returns whether this call wrote it.
pub(super) fn save_owner_keys_new(dir: &Path, keys: &OwnerKeys) -> Result<bool> {
    let bytes = keys.encode()?;
    super::disk::write_new(&dir.join("owner-keys"), &bytes, true)
}

#[cfg(test)]
pub(super) fn save_owner_keys(dir: &Path, keys: &OwnerKeys) -> Result<()> {
    let bytes = keys.encode()?;
    super::disk::write_replace(&dir.join("owner-keys"), &bytes, true)
}

/// Loads the keyring, owner keys, and publish state, and checks the pin.
pub(super) fn load_owner(cfg: &RemoteCfg, identity: &Identity) -> Result<OwnerBundle> {
    finish_keyring_update(cfg, identity)?;
    let remote = connect(cfg, Some(identity), false)?;
    let keys = load_owner_keys(&cfg.dir)?.ok_or_else(|| {
        CliError::msg("no owner keys for this remote; only the owner can grant or revoke")
    })?;
    if keys.remote != remote.remote_id() {
        return Err(CliError::msg("owner keys are for a different remote"));
    }
    let bytes = remote
        .read_head()?
        .keyring
        .ok_or_else(|| CliError::msg("this remote has no keyring yet; publish to it first"))?;
    let keyring = Keyring::decode(&bytes)?;
    if identity.public() != keyring.owner {
        return Err(CliError::msg(
            "only the owner of this remote can grant or revoke",
        ));
    }
    let state = load_publish_state(&cfg.dir)?;
    let pin = state
        .owner_signing
        .ok_or_else(|| CliError::msg("publish to this remote before granting or revoking"))?;
    if state.remote_id != remote.remote_id() {
        return Err(CliError::msg("publish state is for a different remote"));
    }
    keyring.verify(&pin, state.counter)?;
    keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    verify_policy_checkpoints(&cfg.dir, &keyring)?;
    Ok(OwnerBundle {
        remote,
        keyring,
        keys,
        state,
    })
}

/// Completes an interrupted owner update using only locally saved, signed
/// material. Never roll back a newer verified remote head.
pub(super) fn finish_keyring_update(cfg: &RemoteCfg, owner: &Identity) -> Result<()> {
    if !cfg.dir.join("pending-keyring").try_exists()? {
        return Ok(());
    }
    let remote = connect(cfg, Some(owner), false)?;
    // Recovery checks committed floors; the pending counter has not landed yet.
    let mut state = load_states(&cfg.dir, false)?.0;
    let head = remote.read_head()?;
    if let Some(bytes) = head.keyring.as_deref() {
        let keyring = Keyring::decode(bytes)?;
        let pin = state.owner_signing.ok_or_else(|| CliError::msg("pending keyring has no owner pin"))?;
        if keyring.remote != remote.remote_id() { return Err(CliError::msg("keyring is for a different remote")); }
        keyring.verify(&pin, state.counter)?;
        verify_policy_checkpoints(&cfg.dir, &keyring)?;
    }
    tig_private::access::finish_pending(remote.as_ref(), &cfg.dir, owner, &mut state)?;
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    if valid_name(name) {
        Ok(())
    } else {
        Err(CliError::msg(format!(
            "invalid remote name {name:?}; use [a-z0-9_-]+"
        )))
    }
}

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if let Ok(canonical) = fs::canonicalize(path) {
        return Ok(canonical);
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(std::env::current_dir()?.join(path))
    }
}

/// Pending grants and frozen groups. Fingerprints only; no key material.
pub(super) fn describe_roles(keyring: &tig_private::keyring::Keyring) -> Result<String> {
    let snapshot = keyring.policy_snapshot()?;
    let pending = tig_private::roles::pending_access(&snapshot, &keyring.head.epochs, &keyring.grants);
    Ok(tig_private::roles::format_pending(&pending))
}

fn path_text(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| CliError::msg("remote path is not valid text"))?;
    Ok(format!("{text}\n"))
}

#[cfg(test)]
fn put_keyring(remote: &DirRemote, bytes: &[u8]) {
    use tig_private::remote::CommitOutcome;
    let head = remote.read_head().unwrap();
    assert!(matches!(
        remote
            .commit_head(&head.version(), Some(bytes), None)
            .unwrap(),
        CommitOutcome::Committed(_)
    ));
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(CliError::msg(format!(
            "cannot read {}: {err}",
            ui::show_path(path)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_policy_survives_competing_observers_and_stale_cache_saves() {
        use std::sync::{Arc, Barrier};
        use tig_private::roles::{Role, TransitionBody};
        let dir = tempfile::tempdir().unwrap();
        let owner = Identity::generate().unwrap();
        let (original, _) = Keyring::create([45; 16], &owner).unwrap();
        let mut stale = PublishState::new();
        stale.remote_id = original.remote;
        stale.owner_signing = Some(owner.public().signing);
        stale.counter = original.head.counter;
        save_publish_state(dir.path(), &stale).unwrap();
        let mut current = original.clone();
        for (counter, name) in [(2, "first"), (3, "second")] {
            current.commit_policy(&owner, vec![TransitionBody::SetRole {
                name: name.into(), role: Role { rank: 1, permissions: 0, groups: Default::default() },
            }.sign(current.remote, &owner.public().signing, counter, &owner)], vec![]).unwrap();
            if counter == 2 { remember_policy_head(dir.path(), &current).unwrap(); }
        }
        let barrier = Arc::new(Barrier::new(2));
        let workers: Vec<_> = [original.clone(), current.clone()].into_iter().map(|ring| {
            let barrier = barrier.clone();
            let path = dir.path().to_path_buf();
            std::thread::spawn(move || {
                barrier.wait();
                remember_policy_head(&path, &ring).is_ok()
            })
        }).collect();
        let results: Vec<_> = workers.into_iter().map(|worker| worker.join().unwrap()).collect();
        assert_eq!(results, [false, true]);
        save_publish_state(dir.path(), &stale).unwrap();
        save_fetch_state(dir.path(), &FetchState::new()).unwrap();
        for state in [load_publish_state(dir.path()).unwrap().counter, load_fetch_state(dir.path()).unwrap().counter] {
            assert_eq!(state, current.head.counter);
        }
        assert_eq!(load_publish_state(dir.path()).unwrap().policy_checkpoint, current.policy_checkpoint());
        assert!(remember_policy_head(dir.path(), &original).is_err());
        assert_eq!(load_publish_state(dir.path()).unwrap().counter, current.head.counter);
    }

    #[test]
    fn pending_revoke_is_recovered_before_using_an_older_remote_head() {
        use tig_private::keys::Identity;
        for remote_updated in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("remote");
            let cfg = RemoteCfg {
                name: "origin".into(),
                dir: dir.path().join("cfg"),
                location: Location::Dir(path.clone()),
            };
            let owner = Identity::generate().unwrap();
            let member = Identity::generate().unwrap();
            let remote = DirRemote::create(&path, [41; 16]).unwrap();
            let (mut ring, mut keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
            ring.grant(&keys, &owner, &member.public()).unwrap();
            put_keyring(&remote, &ring.encode().unwrap());
            let mut state = PublishState::new();
            state.remote_id = remote.remote_id();
            state.owner_signing = Some(owner.public().signing);
            state.counter = ring.head.counter;
            save_publish_state(&cfg.dir, &state).unwrap();
            ring.revoke(&mut keys, &owner, &member.public()).unwrap();
            save_owner_keys(&cfg.dir, &keys).unwrap();
            super::super::disk::write_replace(
                &cfg.dir.join("pending-keyring"),
                &ring.encode().unwrap(),
                false,
            )
            .unwrap();
            if remote_updated {
                put_keyring(&remote, &ring.encode().unwrap());
            }
            // Crash before persisting the new counter. Pending local state is
            // already a rollback floor, even before a mutating command retries.
            assert_eq!(
                load_fetch_state(&cfg.dir).unwrap().counter,
                ring.head.counter
            );
            let recovered = load_owner(&cfg, &owner).unwrap();
            assert_eq!(recovered.keyring.head, ring.head);
            assert_eq!(recovered.state.counter, ring.head.counter);
            assert!(!cfg.dir.join("pending-keyring").exists());
        }
    }

    #[test]
    fn pending_update_never_overwrites_a_newer_verified_head() {
        use tig_private::keys::Identity;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remote");
        let cfg = RemoteCfg {
            name: "origin".into(),
            dir: dir.path().join("cfg"),
            location: Location::Dir(path.clone()),
        };
        let owner = Identity::generate().unwrap();
        let remote = DirRemote::create(&path, [42; 16]).unwrap();
        let (mut ring, keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
        save_owner_keys(&cfg.dir, &keys).unwrap();
        super::super::disk::write_replace(
            &cfg.dir.join("pending-keyring"),
            &ring.encode().unwrap(),
            false,
        )
        .unwrap();
        ring.grant(&keys, &owner, &Identity::generate().unwrap().public())
            .unwrap();
        let newest = ring.encode().unwrap();
        put_keyring(&remote, &newest);
        let mut state = PublishState::new();
        state.remote_id = remote.remote_id();
        state.owner_signing = Some(owner.public().signing);
        state.counter = ring.head.counter;
        save_publish_state(&cfg.dir, &state).unwrap();
        finish_keyring_update(&cfg, &owner).unwrap();
        assert_eq!(remote.read_keyring().unwrap(), newest);
        assert_eq!(
            load_fetch_state(&cfg.dir).unwrap().counter,
            ring.head.counter
        );
    }

    #[test]
    fn fetch_and_publish_share_the_pin_and_highest_counter() {
        let dir = tempfile::tempdir().unwrap();
        let mut fetched = FetchState::new();
        fetched.remote_id = [1; 16];
        fetched.owner_signing = Some([2; 32]);
        fetched.counter = 7;
        fetched.manifest_seq = 11;
        save_fetch_state(dir.path(), &fetched).unwrap();
        let mut published = load_publish_state(dir.path()).unwrap();
        assert_eq!(published.owner_signing, fetched.owner_signing);
        assert_eq!(published.remote_id, fetched.remote_id);
        assert_eq!(published.counter, 7);
        assert_eq!(published.manifest_seq, 11);
        published.counter = 9;
        published.manifest_seq = 12;
        save_publish_state(dir.path(), &published).unwrap();
        assert_eq!(load_fetch_state(dir.path()).unwrap().counter, 9);
        assert_eq!(load_fetch_state(dir.path()).unwrap().manifest_seq, 12);
        fetched.owner_signing = Some([3; 32]);
        save_fetch_state(dir.path(), &fetched).unwrap();
        assert!(load_publish_state(dir.path()).is_err());
        assert!(load_fetch_state(dir.path()).is_err());
    }
}
