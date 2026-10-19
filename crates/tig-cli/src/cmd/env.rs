//! Run a literal child command with secrets authorized by the current role policy.

use std::ffi::OsString;
use std::path::Path;

use clap::Args as ClapArgs;
use tig_core::store::StoreExt;
use tig_core::treeops::lookup;
use tig_private::env;
use tig_private::keyring::Keyring;
use tig_private::rules::Verdict;

use super::{identity, remote, workspace, CliError, Result};

#[derive(ClapArgs)]
pub(super) struct Args {
    pub remote: String,
    #[arg(long)]
    pub role: String,
    /// Dotenv source in this revision; defaults to .env.<role>.
    #[arg(long)]
    pub file: Option<String>,
    /// Program and literal arguments, following --.
    #[arg(last = true, required = true, num_args = 1..)]
    pub command: Vec<OsString>,
}

pub(super) fn run(repository: Option<&Path>, args: Args) -> Result<std::process::ExitStatus> {
    let (session, _) = super::open_ready(repository)?;
    let actor = identity::load_or_create()?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let cfg = remote::require(&tig, &args.remote)?;
    remote::finish_keyring_update(&cfg, &actor)?;
    let transport = remote::connect(&cfg, Some(&actor), false)?;
    let state = remote::load_publish_state(&cfg.dir)?;
    let pin = state.owner_signing.ok_or_else(|| CliError::msg("fetch this remote before using its secrets"))?;
    if state.remote_id != transport.remote_id() {
        return Err(CliError::msg("remote state belongs to a different remote"));
    }
    let bytes = transport.read_head()?.keyring.ok_or_else(|| CliError::msg("remote has no keyring"))?;
    let keyring = Keyring::decode(&bytes)?;
    let verified = keyring.verify(&pin, state.counter)?;
    keyring.verify_policy_checkpoint(state.policy_checkpoint.as_ref())?;
    remote::verify_policy_checkpoints(&cfg.dir, &keyring)?;
    remote::remember_policy_head(&cfg.dir, &keyring)?;
    if !verified.reads_now(&actor.public(), &args.role) {
        return Err(CliError::msg("you cannot read this role's secrets"));
    }
    let revision = session.repo.revision(&session.working()?)?;
    let store = session.repo.store();
    let name = args.file.unwrap_or_else(|| format!(".env.{}", args.role));
    let path = super::parse_path(&name)?;
    let rules = tig_private::project::rules_of(store.as_ref(), &revision.tree)?;
    match rules.classify(&path) {
        Verdict::Private { readers, .. } if readers.contains(&args.role) => {}
        _ => return Err(CliError::msg("the env source is not classified private for the requested role")),
    }
    let leaf = lookup(store.as_ref(), &revision.tree, &path)?
        .ok_or_else(|| CliError::msg("the env source is missing or sealed"))?;
    if !leaf.kind().is_file_like() {
        return Err(CliError::msg("the env source is missing or sealed"));
    }
    let bytes = zeroize::Zeroizing::new(store.get_blob(&leaf.id())?);
    let secrets = env::parse_dotenv(&name, &bytes).map_err(|e| CliError::msg(e.to_string()))?;
    let status = env::run(&args.command[0], &args.command[1..], &secrets, true)
        .map_err(|e| CliError::msg(e.to_string()))?;
    drop(secrets);
    drop(bytes);
    Ok(status)
}
