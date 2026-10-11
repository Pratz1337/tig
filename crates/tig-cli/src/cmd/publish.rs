//! `tig publish`
//!
//! First publish of an empty remote saves owner keys locally before `publish`
//! runs. The library then builds the keyring from those keys and writes the
//! file only after the refusal checks, so a crash or a refusal cannot leave a
//! remote keyring whose epoch secret was never stored.

use std::path::Path;

use tig_core::store::StoreExt;
use tig_core::treeops::walk;
use tig_core::{EntryKind, ObjectId, RepoPath};
use tig_private::keyring::Keyring;
use tig_private::publish::{self, PublishOptions};
use tig_private::remote::DirRemote;

use super::identity;
use super::workspace;
use super::{CliError, Result};
use crate::ui::RevLabel;

pub(super) fn run(
    repository: Option<&Path>,
    remote_name: String,
    bookmark: String,
    revision: Option<String>,
    acknowledge_leaked: bool,
    confirm_negations: bool,
) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let identity = identity::load_or_create()?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let cfg = super::remote::require(&tig, &remote_name)?;
    let rev = publish_rev(&session, revision)?;
    let dir_remote = super::remote::open_or_create(&cfg.path)?;
    let missing_keyring = !cfg.path.join("keyring").try_exists()?;
    // Keys hit disk before publish can write a keyring. A refusal still
    // leaves the remote keyring absent; the saved keys are what a retry uses.
    if missing_keyring && super::remote::load_owner_keys(&cfg.dir)?.is_none() {
        let (_preview, keys) = Keyring::create(dir_remote.remote_id(), &identity)?;
        super::remote::save_owner_keys_new(&cfg.dir, &keys)?;
    }
    let owner_keys = super::remote::load_owner_keys(&cfg.dir)?;
    if missing_keyring && owner_keys.is_none() {
        return Err(CliError::msg("could not save owner keys before publishing"));
    }
    let mut state = super::remote::load_publish_state(&cfg.dir)?;
    let options = PublishOptions {
        acknowledge_leaked,
        confirm_negations,
    };
    let report = publish::publish(
        session.repo.store().as_ref(),
        &dir_remote,
        &identity,
        owner_keys.as_ref(),
        &mut state,
        &bookmark,
        rev,
        &options,
    )?;
    if let Some(keys) = &report.new_owner_keys {
        // Only the minting path returns keys. Do not overwrite a keystore
        // that was saved before this call.
        if super::remote::load_owner_keys(&cfg.dir)?.is_none() {
            super::remote::save_owner_keys_new(&cfg.dir, keys)?;
        }
    }
    super::remote::save_publish_state(&cfg.dir, &state)?;
    let mut tx = session
        .repo
        .start(format!("publish {remote_name} {bookmark}"));
    tx.set_bookmark(&bookmark, rev)?;
    session.commit(tx)?;

    let sealed = sealed_paths(&dir_remote, &bookmark)?;
    let noun = if report.revisions_published == 1 {
        "revision"
    } else {
        "revisions"
    };
    println!(
        "published {} {noun} to {remote_name} ({bookmark})",
        report.revisions_published
    );
    println!("public objects: {}", report.public_objects_written);
    println!("private objects sealed: {}", report.private_objects_sealed);
    if sealed.is_empty() {
        println!("sealed: (none)");
    } else {
        println!("sealed: {}", sealed.join(", "));
    }
    if missing_keyring {
        println!(
            "you own this remote; your fingerprint: {}",
            identity.public().fingerprint()
        );
    }
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    let stored = session.repo.revision(&rev)?;
    let all = Vec::new();
    let label = RevLabel::from_revision(&session.repo, rev, &stored, &all);
    println!("bookmark {bookmark}: {}", label.line());
    super::announce_if_moved(&mut session, before)
}

/// `@-` when `@` is an empty working change, otherwise `@`.
fn publish_rev(session: &super::Session, revision: Option<String>) -> Result<ObjectId> {
    if let Some(spec) = revision {
        return session.resolve(&spec);
    }
    let at = session.working()?;
    let rev = session.repo.revision(&at)?;
    let empty = match rev.parents.first() {
        Some(parent) => session.repo.revision(parent)?.tree == rev.tree,
        None => false,
    };
    if empty {
        session.resolve("@-")
    } else {
        Ok(at)
    }
}

fn sealed_paths(remote: &DirRemote, bookmark: &str) -> Result<Vec<String>> {
    let refs = remote.read_refs()?;
    let id = refs.get(bookmark).copied().ok_or_else(|| {
        CliError::msg(format!(
            "remote bookmark {bookmark} is missing after publish"
        ))
    })?;
    let rev = remote.public_store().get_revision(&id)?;
    let leaves = walk(remote.public_store(), &rev.tree, &RepoPath::root())?;
    let mut names: Vec<String> = leaves
        .into_iter()
        .filter(|(_, leaf)| leaf.kind() == EntryKind::Sealed)
        .map(|(path, _)| path.to_string())
        .collect();
    names.sort();
    Ok(names)
}
