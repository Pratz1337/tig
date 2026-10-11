//! `tig undo`

use std::path::Path;

use super::Result;

pub(super) fn run(repository: Option<&Path>) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    session.repo.undo()?;
    println!("{}", session.repo.operation().description);
    super::announce_if_moved(&mut session, before)
}
