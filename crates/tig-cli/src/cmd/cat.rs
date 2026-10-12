//! `tig cat`

use std::io::{self, Write};
use std::path::Path;

use tig_core::treeops::lookup;

use super::{CliError, Result};

pub(super) fn run(repository: Option<&Path>, path: &str, revision: Option<&str>) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let id = session.resolve(revision.unwrap_or("@"))?;
    let rev = session.repo.revision(&id)?;
    let path = super::parse_path(path)?;
    let leaf = lookup(session.repo.store().as_ref(), &rev.tree, &path)?;
    match leaf {
        Some(leaf) if leaf.is_file_like() || leaf.kind() == tig_core::EntryKind::Conflict => {
            let bytes = tig_core::conflict::materialize(session.repo.store().as_ref(), leaf)?;
            let mut stdout = io::stdout().lock();
            stdout.write_all(&bytes)?;
            stdout.flush()?;
            Ok(())
        }
        Some(_) => Err(CliError::msg(format!("{path} is not a file"))),
        None => Err(CliError::msg(format!("{path} is not in this revision"))),
    }
}
