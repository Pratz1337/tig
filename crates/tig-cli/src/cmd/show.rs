//! `tig show`

use std::path::Path;

use super::diff;
use super::log;
use super::Result;

pub(super) fn run(repository: Option<&Path>, revision: Option<&str>) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let spec = revision.unwrap_or("@");
    let id = session.resolve(spec)?;
    let rev = session.repo.revision(&id)?;
    let working = session.working()?;
    let all = session.repo.visible_revisions()?;
    log::print_entry(&session, working, id, &rev, &all, true)?;
    println!();
    diff::print_revision_diff(&session.repo, id, false, &if id == session.working()? { session.wc.conflict_paths() } else { Vec::new() })
}
