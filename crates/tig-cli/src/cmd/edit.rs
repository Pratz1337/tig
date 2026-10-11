//! `tig edit`

use std::path::Path;

use super::Result;
use crate::ui;

pub(super) fn run(repository: Option<&Path>, revision: &str) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let id = session.resolve(revision)?;
    if session.working()? != id {
        let rev = session.repo.revision(&id)?;
        let all = session.repo.visible_revisions()?;
        let label = ui::change_label(&session.repo, &rev.change_id, &all);
        let name = session.name().to_string();
        let mut tx = session.repo.start(format!("edit {label}"));
        tx.set_working(&name, id)?;
        session.repo.commit(tx)?;
        super::close_moved(&mut session, before)?;
    }
    super::announce(&session)
}
