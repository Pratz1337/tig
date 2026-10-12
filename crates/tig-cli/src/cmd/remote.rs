//! `tig remote`, and the `.tig/remotes/<name>/` files other commands share.

use std::fs;
use std::path::{Path, PathBuf};

use tig_private::fetch::FetchState;
use tig_private::keyring::{Keyring, OwnerKeys};
use tig_private::publish::PublishState;
use tig_private::remote::{DirRemote, RemoteError};

use super::workspace;
use super::{CliError, Result};
use crate::ui;

pub(super) struct RemoteCfg {
    pub name: String,
    pub dir: PathBuf,
    pub path: PathBuf,
}

/// Owner material for grant and revoke. The identity stays with the caller.
pub(super) struct OwnerBundle {
    pub remote: DirRemote,
    pub keyring: Keyring,
    pub keys: OwnerKeys,
    pub state: PublishState,
}

pub(super) fn run(repository: Option<&Path>, action: super::RemoteAction) -> Result<()> {
    match action {
        super::RemoteAction::Add { name, path } => add(repository, &name, &path),
        super::RemoteAction::List => list(repository),
        super::RemoteAction::Remove { name } => remove(repository, &name),
    }
}

pub(super) fn add(repository: Option<&Path>, name: &str, path: &Path) -> Result<()> {
    validate_name(name)?;
    let (mut session, before) = super::open_ready(repository)?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let dir = tig.join("remotes").join(name);
    if dir.try_exists()? {
        return Err(CliError::msg(format!("remote {name} already exists")));
    }
    let absolute = absolute_path(path)?;
    fs::create_dir_all(&dir)?;
    let text = path_text(&absolute)?;
    if !super::disk::write_new(&dir.join("path"), text.as_bytes(), false)? {
        return Err(CliError::msg(format!("remote {name} already exists")));
    }
    println!("added remote {name} at {}", ui::show_path(&absolute));
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
                rows.push((cfg.name, cfg.path));
            }
        }
    }
    rows.sort();
    if rows.is_empty() {
        println!("No remotes.");
    } else {
        for (name, path) in rows {
            println!("{name} {}", ui::show_path(&path));
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
    let text = match fs::read_to_string(dir.join("path")) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Err(CliError::msg(format!("no remote named {name}")));
        }
        Err(err) => {
            return Err(CliError::msg(format!("cannot read remote {name}: {err}")));
        }
    };
    let path = PathBuf::from(text.trim());
    if path.as_os_str().is_empty() {
        return Err(CliError::msg(format!("remote {name} has an empty path")));
    }
    Ok(RemoteCfg {
        name: name.to_string(),
        dir,
        path,
    })
}

/// Opens a remote, creating the directory layout and a random id when it
/// has none yet. Does not write a keyring.
pub(super) fn open_or_create(path: &Path) -> Result<DirRemote> {
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

pub(super) fn open_existing(path: &Path) -> Result<DirRemote> {
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
    Ok(load_states(dir)?.0)
}

/// Fetch, publish, grant and revoke share one owner pin and rollback floor.
/// A head learned through one command must be trusted by the others.
fn load_states(dir: &Path) -> Result<(PublishState, FetchState)> {
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
    if published.owner_signing.is_some()
        && fetched.owner_signing.is_some()
        && (published.owner_signing != fetched.owner_signing
            || published.remote_id != fetched.remote_id)
    {
        return Err(CliError::msg(
            "fetch and publish state disagree about the remote owner",
        ));
    }
    if let Some(pin) = published.owner_signing.or(fetched.owner_signing) {
        let remote_id = if published.owner_signing.is_some() {
            published.remote_id
        } else {
            fetched.remote_id
        };
        let mut counter = published.counter.max(fetched.counter);
        if let Some(bytes) = read_optional(&dir.join("pending-keyring"))? {
            let pending = Keyring::decode(&bytes)?;
            if pending.remote != remote_id {
                return Err(CliError::msg("pending keyring is for a different remote"));
            }
            pending.verify(&pin, 0)?;
            counter = counter.max(pending.head.counter);
        }
        published.remote_id = remote_id;
        fetched.remote_id = remote_id;
        published.owner_signing = Some(pin);
        fetched.owner_signing = Some(pin);
        published.counter = counter;
        fetched.counter = counter;
    }
    Ok((published, fetched))
}

pub(super) fn save_publish_state(dir: &Path, state: &PublishState) -> Result<()> {
    let bytes = state.encode()?;
    super::disk::write_replace(&dir.join("publish-state"), &bytes, false)
}

pub(super) fn load_fetch_state(dir: &Path) -> Result<FetchState> {
    Ok(load_states(dir)?.1)
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

pub(super) fn save_owner_keys(dir: &Path, keys: &OwnerKeys) -> Result<()> {
    let bytes = keys.encode()?;
    super::disk::write_replace(&dir.join("owner-keys"), &bytes, true)
}

/// Loads the keyring, owner keys, and publish state, and checks the pin.
pub(super) fn load_owner(
    cfg: &RemoteCfg,
    identity: &tig_private::keys::Identity,
) -> Result<OwnerBundle> {
    finish_keyring_update(cfg)?;
    let remote = open_existing(&cfg.path)?;
    let keys = load_owner_keys(&cfg.dir)?.ok_or_else(|| {
        CliError::msg("no owner keys for this remote; only the owner can grant or revoke")
    })?;
    if keys.remote != remote.remote_id() {
        return Err(CliError::msg("owner keys are for a different remote"));
    }
    let bytes = match remote.read_keyring() {
        Ok(bytes) => bytes,
        Err(RemoteError::Invalid(message)) if message == "keyring is missing" => {
            return Err(CliError::msg(
                "this remote has no keyring yet; publish to it first",
            ));
        }
        Err(err) => return Err(err.into()),
    };
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
    Ok(OwnerBundle {
        remote,
        keyring,
        keys,
        state,
    })
}

/// Save keys, then a local signed pending head and rollback floor, before
/// exposing the new head remotely. A retry completes a pending write first.
pub(super) fn commit_keyring(cfg: &RemoteCfg, bundle: &mut OwnerBundle) -> Result<()> {
    save_owner_keys(&cfg.dir, &bundle.keys)?;
    let bytes = bundle.keyring.encode()?;
    super::disk::write_replace(&cfg.dir.join("pending-keyring"), &bytes, false)?;
    bundle.state.counter = bundle.keyring.head.counter;
    save_publish_state(&cfg.dir, &bundle.state)?;
    bundle.remote.write_keyring(&bytes)?;
    fs::remove_file(cfg.dir.join("pending-keyring"))?;
    Ok(())
}

/// Completes an interrupted owner update using only locally saved, signed
/// material. Never roll back a newer verified remote head.
pub(super) fn finish_keyring_update(cfg: &RemoteCfg) -> Result<()> {
    let path = cfg.dir.join("pending-keyring");
    let Some(bytes) = read_optional(&path)? else {
        return Ok(());
    };
    let pending = Keyring::decode(&bytes)?;
    let mut state = load_publish_state(&cfg.dir)?;
    let pin = state
        .owner_signing
        .ok_or_else(|| CliError::msg("pending keyring has no owner pin"))?;
    let verified = pending.verify(&pin, 0)?;
    let keys = load_owner_keys(&cfg.dir)?
        .ok_or_else(|| CliError::msg("pending keyring has no saved owner keys"))?;
    if keys.remote != pending.remote {
        return Err(CliError::msg(
            "pending keyring keys are for a different remote",
        ));
    }
    for (group, epoch) in &pending.head.epochs {
        if !keys.keys.contains_key(&(group.clone(), *epoch)) {
            return Err(CliError::msg("pending keyring epoch key is missing"));
        }
    }
    let remote = open_existing(&cfg.path)?;
    if remote.remote_id() != pending.remote {
        return Err(CliError::msg("pending keyring is for a different remote"));
    }
    let current = Keyring::decode(&remote.read_keyring()?)?;
    if current.remote != pending.remote {
        return Err(CliError::msg("remote keyring is for a different remote"));
    }
    current.verify(&pin, 0)?;
    if current.head.counter <= verified.counter() {
        remote.write_keyring(&bytes)?;
    }
    state.counter = state.counter.max(current.head.counter);
    save_publish_state(&cfg.dir, &state)?;
    fs::remove_file(path)?;
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

fn path_text(path: &Path) -> Result<String> {
    let text = path
        .to_str()
        .ok_or_else(|| CliError::msg("remote path is not valid text"))?;
    Ok(format!("{text}\n"))
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
    fn pending_revoke_is_recovered_before_using_an_older_remote_head() {
        use tig_private::keys::Identity;
        for remote_updated in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let cfg = RemoteCfg {
                name: "origin".into(),
                dir: dir.path().join("cfg"),
                path: dir.path().join("remote"),
            };
            let owner = Identity::generate().unwrap();
            let member = Identity::generate().unwrap();
            let remote = DirRemote::create(&cfg.path, [41; 16]).unwrap();
            let (mut ring, mut keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
            ring.grant(&keys, &owner, &member.public()).unwrap();
            remote.write_keyring(&ring.encode().unwrap()).unwrap();
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
                remote.write_keyring(&ring.encode().unwrap()).unwrap();
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
        let cfg = RemoteCfg {
            name: "origin".into(),
            dir: dir.path().join("cfg"),
            path: dir.path().join("remote"),
        };
        let owner = Identity::generate().unwrap();
        let remote = DirRemote::create(&cfg.path, [42; 16]).unwrap();
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
        remote.write_keyring(&newest).unwrap();
        let mut state = PublishState::new();
        state.remote_id = remote.remote_id();
        state.owner_signing = Some(owner.public().signing);
        state.counter = ring.head.counter;
        save_publish_state(&cfg.dir, &state).unwrap();
        finish_keyring_update(&cfg).unwrap();
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
        save_fetch_state(dir.path(), &fetched).unwrap();
        let mut published = load_publish_state(dir.path()).unwrap();
        assert_eq!(published.owner_signing, fetched.owner_signing);
        assert_eq!(published.remote_id, fetched.remote_id);
        assert_eq!(published.counter, 7);
        published.counter = 9;
        save_publish_state(dir.path(), &published).unwrap();
        assert_eq!(load_fetch_state(dir.path()).unwrap().counter, 9);
        fetched.owner_signing = Some([3; 32]);
        save_fetch_state(dir.path(), &fetched).unwrap();
        assert!(load_publish_state(dir.path()).is_err());
        assert!(load_fetch_state(dir.path()).is_err());
    }
}
