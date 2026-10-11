//! `tig op log` and `tig op restore`

use std::path::Path;

use tig_core::repo::Repo;
use tig_core::ObjectId;

use super::{CliError, OpAction, Result};
use crate::ui;

pub(super) fn run(repository: Option<&Path>, action: OpAction) -> Result<()> {
    match action {
        OpAction::Log { limit } => log(repository, limit),
        OpAction::Restore { op } => restore(repository, &op),
    }
}

fn log(repository: Option<&Path>, limit: Option<usize>) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let limit = limit.unwrap_or(usize::MAX);
    for (id, op) in session.repo.op_log(limit)? {
        let mark = if op.undo_of.is_some() { " (undo)" } else { "" };
        println!(
            "{} {} {}{mark}",
            id.short(12),
            ui::format_time(op.timestamp_ms),
            op.description
        );
    }
    Ok(())
}

fn restore(repository: Option<&Path>, prefix: &str) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let id = resolve_op(&session.repo, prefix)?;
    session.repo.restore_operation(&id)?;
    println!("restored {}", id.short(12));
    let name = session.name().to_string();
    if !session.repo.view().workspaces.contains_key(&name) {
        println!("this workspace does not exist in that operation");
        return Ok(());
    }
    super::announce_if_moved(&mut session, before)
}

/// Resolves an operation-id prefix by walking [`Repo::op_log`].
pub(super) fn resolve_op(repo: &Repo, prefix: &str) -> Result<ObjectId> {
    let prefix = prefix.trim();
    if prefix.is_empty()
        || prefix.len() > ObjectId::LEN * 2
        || !prefix.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(CliError::msg(format!("unknown operation {prefix:?}")));
    }
    let want = prefix.to_ascii_lowercase();
    let mut matches = Vec::new();
    for (id, _) in repo.op_log(usize::MAX)? {
        if id.to_hex().starts_with(&want) {
            matches.push(id);
        }
    }
    match matches.len() {
        0 => Err(CliError::msg(format!("unknown operation {prefix:?}"))),
        1 => Ok(matches[0]),
        n => Err(CliError::msg(format!(
            "operation {prefix:?} is ambiguous ({n} matches); use a longer prefix"
        ))),
    }
}
