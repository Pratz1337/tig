//! `tig describe`

use std::path::Path;

use super::{CliError, Result};
use crate::ui::RevLabel;

pub(super) fn run(
    repository: Option<&Path>,
    revision: Option<&str>,
    message: Option<String>,
) -> Result<()> {
    let Some(message) = message else {
        return Err(CliError::msg(
            "describe needs -m MSG (no editor in this version)",
        ));
    };
    let (mut session, before) = super::open_ready(repository)?;
    let id = session.resolve(revision.unwrap_or("@"))?;
    let rev = session.repo.revision(&id)?;
    if rev.description == message {
        println!("description unchanged");
        return Ok(());
    }
    let was_working = id == before;
    let mut tx = session.repo.start("describe");
    let new_id = tx.rewrite(id, |rev| rev.description = message)?;
    session.repo.commit(tx)?;
    let moved = super::close_moved(&mut session, before)?;
    if was_working || moved {
        super::announce(&session)?;
    }
    if !was_working {
        let described = session.repo.revision(&new_id)?;
        let all = session.repo.visible_revisions()?;
        let label = RevLabel::from_revision(&session.repo, new_id, &described, &all);
        println!("described {}", label.line());
    }
    Ok(())
}
