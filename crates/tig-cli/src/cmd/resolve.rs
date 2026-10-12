//! Select an exact conflict alternative, including modes and structural changes.

use super::{CliError, Result};
use std::path::Path;
use tig_core::store::StoreExt;
use tig_core::treeops::lookup;
use tig_core::workspace::Workspace;
use tig_core::EntryKind;

pub(super) fn run(
    repository: Option<&Path>,
    path: &str,
    side: Option<usize>,
    base: Option<usize>,
) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let path = super::parse_path(path)?;
    let rev = session.repo.revision(&before)?;
    let leaf = lookup(session.repo.store().as_ref(), &rev.tree, &path)?
        .filter(|leaf| leaf.kind() == EntryKind::Conflict)
        .ok_or_else(|| CliError::msg(format!("{path} is not conflicted")))?;
    let conflict = session.repo.store().get_conflict(&leaf.id())?;
    let (index, choices) = match (side, base) {
        (Some(index), None) => (index, conflict.adds()),
        (None, Some(index)) => (index, conflict.removes()),
        _ => return Err(CliError::msg("select either --side or --base")),
    };
    let choice = index
        .checked_sub(1)
        .and_then(|i| choices.get(i))
        .ok_or_else(|| {
            CliError::msg(format!(
                "alternative must be between 1 and {}",
                choices.len()
            ))
        })?;
    let mut ws = Workspace::open(&session.repo, session.name())?;
    ws.resolve(&session.repo, &path, *choice)?;
    ws.snapshot(&mut session.repo)?;
    super::announce_if_moved(&mut session, before)
}
