//! `tig abandon`

use std::path::Path;

use super::Result;
use crate::ui::RevLabel;

pub(super) fn run(repository: Option<&Path>, revision: Option<&str>) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let id = session.resolve(revision.unwrap_or("@"))?;
    let rev = session.repo.revision(&id)?;
    // Labels use a fixed 8-char change id: no history walk on the hot path.
    let all: Vec<(tig_core::ObjectId, tig_core::Revision)> = Vec::new();
    let label = RevLabel::from_revision(&session.repo, id, &rev, &all);
    let mut tx = session.repo.start(format!("abandon {}", label.change_id));
    tx.abandon(id)?;
    session.commit(tx)?;
    println!("abandoned {}", label.change_id);
    super::announce_if_moved(&mut session, before)
}
