//! `tig grant`

use std::path::Path;

use super::identity;
use super::workspace;
use super::{CliError, Result};
use crate::ui;

pub(super) fn run(repository: Option<&Path>, remote_name: String, token: String) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let identity = identity::load_or_create()?;
    let member = ui::parse_identity_token(&token).map_err(CliError::msg)?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let cfg = super::remote::require(&tig, &remote_name)?;
    let mut bundle = super::remote::load_owner(&cfg, &identity)?;
    bundle.keyring.grant(&bundle.keys, &identity, &member)?;
    super::remote::commit_keyring(&cfg, &mut bundle)?;
    println!("granted {} on {remote_name}", member.fingerprint());
    super::announce_if_moved(&mut session, before)
}
