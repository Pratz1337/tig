//! Role policy and reader-mediated epoch grants.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use clap::{Args as ClapArgs, Subcommand};
use tig_private::keyring::Keyring;
use tig_private::keys::{self, EpochKey, GroupEpoch, PublicIdentity};
use tig_private::manifest::Manifest;
use tig_private::roles::{self, PolicyLog, Role, TransitionBody};

use super::{identity, remote, workspace, CliError, Result};

#[derive(ClapArgs)]
#[command(subcommand_precedence_over_arg = true)]
pub(super) struct Args {
    #[arg(default_value = "origin")]
    pub remote: String,
    #[command(subcommand)]
    pub action: Action,
}

#[derive(Subcommand)]
pub(super) enum Action {
    /// Create a read role; the owner receives initial key custody.
    Create {
        name: String,
        #[arg(long, default_value_t = 1)] rank: u32,
        #[arg(long, value_delimiter = ',')] permissions: Vec<String>,
    },
    /// Remove a role assignment and rotate its keys atomically.
    Revoke { role: String, token: String },
    /// Create or replace a role. Permissions are comma-separated names.
    Set {
        name: String,
        #[arg(long)] rank: u32,
        #[arg(long, value_delimiter = ',')] permissions: Vec<String>,
        #[arg(long, value_delimiter = ',')] groups: Vec<String>,
    },
    Delete { name: String },
    Assign { role: String, token: String },
    Unassign { role: String, token: String },
    /// Show role definitions and assigned identities.
    List,
    /// Show key grants still waiting on a reader and frozen groups.
    Pending,
    /// Wrap an existing group key for a role-authorized recipient.
    Grant { group: String, token: String },
    /// Rotate a group and wrap only its remaining authorized readers.
    Rotate { group: String },
    /// Propose ownership transfer; the successor accepts this public file.
    Transfer { token: String, proposal: PathBuf },
    /// Verify a public transfer proposal and sign as the successor.
    AcceptTransfer { proposal: PathBuf },
}

pub(super) fn run(repository: Option<&Path>, args: Args) -> Result<()> {
    let (session, _) = super::open_ready(repository)?;
    let actor = identity::load_or_create()?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let cfg = remote::require(&tig, &args.remote)?;
    remote::finish_keyring_update(&cfg, &actor)?;
    let transport = remote::connect(&cfg, Some(&actor), false)?;
    let mut state = remote::load_publish_state(&cfg.dir)?;
    let pin = state.owner_signing.ok_or_else(|| CliError::msg("fetch this remote before changing roles"))?;
    if state.remote_id != transport.remote_id() {
        return Err(CliError::msg("remote state belongs to a different remote"));
    }
    let head = transport.read_head()?;
    let keyring = Keyring::decode(head.keyring.as_deref().ok_or_else(|| CliError::msg("remote has no keyring"))?)?;
    let verified = keyring.verify(&pin, state.counter)?;
    keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    remote::verify_policy_checkpoints(&cfg.dir, &keyring)?;
    match &args.action {
        Action::List => {
            let snapshot = verified.snapshot();
            for (name, role) in &snapshot.roles {
                println!("{name}: rank {}, permissions {}, groups {}", role.rank, role.permissions, role.groups.iter().cloned().collect::<Vec<_>>().join(","));
            }
            for (member, roles) in &snapshot.assignments {
                println!("{}: {}", member.fingerprint(), roles.iter().cloned().collect::<Vec<_>>().join(","));
            }
            return Ok(());
        }
        Action::Pending => {
            println!("{}", remote::describe_roles(&keyring)?);
            return Ok(());
        }
        Action::Transfer { token, proposal } => {
            let owner = parse_identity(token)?;
            let counter = keyring.head.counter.checked_add(1).ok_or_else(|| CliError::msg("counter overflow"))?;
            let transition = TransitionBody::Transfer { owner }
                .sign(keyring.remote, &pin, counter, &actor);
            let mut trial = keyring.policy.clone();
            trial.transitions.push(transition.clone());
            trial.replay(&keyring.owner, keyring.remote).map_err(show)?;
            let log = PolicyLog { baseline: BTreeSet::new(), transitions: vec![transition] };
            let mut bytes = head.version().0.to_vec();
            bytes.extend(log.encode_body(keyring.remote, &pin));
            if !super::disk::write_new(proposal, &bytes, false)? {
                return Err(CliError::msg("the transfer proposal file already exists"));
            }
            println!("transfer proposed; the successor must run role accept-transfer");
            return Ok(());
        }
        _ => {}
    }
    let mut proposal_version = None;
    let proposed = if let Action::AcceptTransfer { proposal } = &args.action {
        let bytes = fs::read(proposal)?;
        let version: [u8; 32] = bytes.get(..32).ok_or_else(|| CliError::msg("invalid transfer proposal"))?.try_into().unwrap();
        if version != head.version().0 {
            return Err(CliError::msg("the remote changed after this transfer proposal; request a fresh proposal"));
        }
        let (log, id, root) = PolicyLog::decode_body(&bytes[32..]).map_err(show)?;
        if id != keyring.remote || root != pin || !log.baseline.is_empty()
            || log.transitions.len() != 1
            || !matches!(&log.transitions[0].body, TransitionBody::Transfer { owner } if *owner == actor.public())
        {
            return Err(CliError::msg("transfer proposal is not for this remote and identity"));
        }
        proposal_version = Some(version);
        Some(log.transitions)
    } else { None };
    tig_private::access::commit_keyring(transport.as_ref(), &cfg.dir, &mut state, |current| {
        if proposal_version.is_some() && current.encode()? != keyring.encode()? {
            return Err(tig_private::access::AccessError::Invalid("transfer proposal was superseded".into()));
        }
        let counter = current.head.counter.checked_add(1).ok_or_else(|| tig_private::access::AccessError::Invalid("counter overflow".into()))?;
        let ready = match &args.action {
            Action::Create { name, rank, permissions } => {
                let mut next = current.clone();
                next.create_role(&actor, name, *rank, permission_bits(permissions).map_err(|e| tig_private::access::AccessError::Invalid(e.to_string()))?)?;
                Some(next)
            }
            Action::Revoke { role, token } => {
                let mut next = current.clone();
                next.revoke_role(&actor, role, &parse_identity(token).map_err(|e| tig_private::access::AccessError::Invalid(e.to_string()))?)?;
                Some(next)
            }
            Action::Grant { group, token } if current.policy_snapshot()?.roles.contains_key(group) => {
                let mut next = current.clone();
                next.grant_role(&actor, group, &parse_identity(token).map_err(|e| tig_private::access::AccessError::Invalid(e.to_string()))?)?;
                Some(next)
            }
            _ => None,
        };
        let next = if let Some(next) = ready { next } else {
        let mut bodies = Vec::new();
        let mut grants = Vec::new();
        match &args.action {
            Action::Set { name, rank, permissions, groups } => bodies.push(TransitionBody::SetRole {
                name: name.clone(), role: Role { rank: *rank, permissions: permission_bits(permissions).map_err(|e| tig_private::access::AccessError::Invalid(e.to_string()))?, groups: groups.iter().cloned().collect() },
            }),
            Action::Delete { name } => bodies.push(TransitionBody::RemoveRole { name: name.clone() }),
            Action::Assign { role, token } => bodies.push(TransitionBody::Assign { member: parse_identity(token).map_err(|e| tig_private::access::AccessError::Invalid(e.to_string()))?, role: role.clone() }),
            Action::Unassign { role, token } => bodies.push(TransitionBody::Unassign { member: parse_identity(token).map_err(|e| tig_private::access::AccessError::Invalid(e.to_string()))?, role: role.clone() }),
            Action::Grant { group, .. } | Action::Rotate { group } => {
                let verified = current.verify(&pin, state_floor(&keyring))?;
                if !verified.reads_now(&actor.public(), group) {
                    return Err(tig_private::access::AccessError::Invalid("only a current reader may wrap or rotate this group".into()));
                }
                let old_epoch = verified.current_epoch_of(group);
                let rotating = matches!(&args.action, Action::Rotate { .. }) || old_epoch.is_none();
                if old_epoch.is_some() {
                    // Possession, not a management permission, authorizes custody.
                    let _old_key = verified.current_key(group, &actor)?;
                }
                let epoch = if rotating { old_epoch.unwrap_or(0).checked_add(1).ok_or_else(|| tig_private::access::AccessError::Invalid("epoch overflow".into()))? } else { old_epoch.unwrap() };
                let key = if rotating {
                    bodies.push(TransitionBody::AdvanceEpoch { group: group.clone(), epoch });
                    EpochKey::generate(GroupEpoch { remote: current.remote, group: group.clone(), epoch })?
                } else { verified.current_key(group, &actor)? };
                let recipients: BTreeSet<_> = if let Action::Grant { token, .. } = &args.action {
                    BTreeSet::from([parse_identity(token).map_err(|e| tig_private::access::AccessError::Invalid(e.to_string()))?])
                } else {
                    let mut readers: BTreeSet<_> = verified.snapshot().assignments.keys().copied().filter(|member| verified.reads_now(member, group)).collect();
                    readers.extend(current.grants.iter().map(|g| g.recipient).filter(|member| verified.reads_now(member, group)));
                    readers
                };
                for recipient in recipients {
                    if !verified.reads_now(&recipient, group) {
                        return Err(tig_private::access::AccessError::Invalid("assign the recipient's read role before granting its key".into()));
                    }
                    let grant = keys::grant(&key, &recipient, &actor)?;
                    bodies.push(TransitionBody::AuthorizeGrant { group: group.clone(), epoch, recipient, grant_signature: grant.signature });
                    grants.push(grant);
                }
            }
            Action::AcceptTransfer { .. } => {}
            _ => unreachable!("read-only actions returned above"),
        }
        let transitions = proposed.clone().unwrap_or_else(|| bodies.into_iter().map(|body| body.sign(current.remote, &pin, counter, &actor)).collect());
        let mut next = current.clone();
        next.commit_policy(&actor, transitions, grants)?;
        next
        };
        let raw_manifest = transport.read_head()?.manifest;
        let manifest = if let Some(raw) = raw_manifest {
            let previous = Manifest::decode(&raw)?;
            previous.verify(current.remote, current, 0)?;
            let transferring = matches!(&args.action, Action::AcceptTransfer { .. });
            let signers = tig_private::manifest::allowed_signers(&next);
            if transferring || !signers.contains(&previous.publisher) {
                if !signers.contains(&actor.public().signing) {
                    return Err(tig_private::access::AccessError::Invalid("an authorized publisher must re-sign the current manifest before this role change".into()));
                }
                let mut reveals = previous.reveals.clone();
                if transferring {
                    for (id, cert) in &mut reveals {
                        *cert = tig_private::changes::RevealCertificate::sign(&actor, current.remote, &previous.changes[id], &cert.key, &cert.salt);
                    }
                }
                Some(Manifest::signed_with_changes(current.remote, previous.sequence.checked_add(1).ok_or_else(|| tig_private::access::AccessError::Invalid("manifest sequence overflow".into()))?, previous.refs, previous.packs, previous.changes, reveals, &actor)?.encode()?)
            } else { None }
        } else { None };
        Ok((next, manifest))
    })?;
    println!("role change committed");
    Ok(())
}

fn state_floor(keyring: &Keyring) -> u64 { keyring.head.counter }
fn parse_identity(token: &str) -> Result<PublicIdentity> { crate::ui::parse_identity_token(token).map_err(CliError::msg) }
fn show(error: roles::RoleError) -> CliError { CliError::msg(error.to_string()) }
fn permission_bits(names: &[String]) -> Result<u32> {
    let mut bits = 0;
    for name in names {
        bits |= match name.as_str() {
            "edit-private" => roles::EDIT_PRIVATE,
            "manage-roles" => roles::MANAGE_ROLES,
            "assign-roles" => roles::ASSIGN_ROLES,
            "publish" => roles::PUBLISH,
            _ => return Err(CliError::msg(format!("unknown permission {name}"))),
        };
    }
    Ok(bits)
}
