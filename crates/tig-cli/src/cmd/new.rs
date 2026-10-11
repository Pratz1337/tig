//! `tig new`

use std::path::Path;

use super::Result;

pub(super) fn run(
    repository: Option<&Path>,
    revs: Vec<String>,
    message: Option<String>,
) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let parents = if revs.is_empty() {
        vec![session.working()?]
    } else {
        let mut ids = Vec::with_capacity(revs.len());
        for spec in &revs {
            ids.push(session.resolve(spec)?);
        }
        ids
    };
    let message = message.unwrap_or_default();
    let name = session.name().to_string();
    let mut tx = session.repo.start("new change");
    let id = tx.new_change(&parents, &message)?;
    tx.set_working(&name, id)?;
    session.repo.commit(tx)?;
    super::announce_if_moved(&mut session, before)
}
