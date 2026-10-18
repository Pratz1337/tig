//! `tig export-git`: write bookmarks into a Git repository.
//!
//! The destination worktree is not checked out. Private paths stay in tig.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Instant;

use tig_private::export_git::{export_git, state_path, ExportOptions, ExportState};

use super::Result;

pub(super) fn run(
    repository: Option<&Path>,
    destination: &Path,
    bookmarks: Vec<String>,
    working_copy: bool,
    declassify: Vec<String>,
    force: bool,
    verbose: bool,
) -> Result<()> {
    let started = Instant::now();
    let (session, _before) = super::open_ready(repository)?;
    let tig = super::workspace::main_tig_dir(session.wc.root())?;
    let options = ExportOptions {
        bookmarks: bookmarks.into_iter().collect(),
        declassify: declassify
            .iter()
            .map(|path| super::parse_path(path))
            .collect::<Result<_>>()?,
        force,
        verbose,
    };
    // A new destination does not exist yet, so it has no map. export_git
    // creates the repository; the map is saved after that, under the
    // canonical path.
    let mut state = if destination.exists() {
        read_state(&state_path(&tig, destination)?)?
    } else {
        ExportState::default()
    };
    let working_bookmarks;
    let bookmarks = if working_copy {
        working_bookmarks = BTreeMap::from([("working-copy".into(), session.working()?)]);
        &working_bookmarks
    } else {
        &session.repo.view().bookmarks
    };
    let report = export_git(
        destination,
        session.repo.store().as_ref(),
        bookmarks,
        &mut state,
        &options,
    )?;
    super::disk::write_replace(&state_path(&tig, destination)?, &state.encode(), false)?;
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    if verbose {
        for path in &report.omitted_paths {
            eprintln!("omitted private path: {path}");
        }
    }
    println!(
        "exported {} revisions; reused {}; omitted {} private paths; {} bookmarks; {:.2} s",
        report.exported,
        report.reused,
        report.omitted_private_paths,
        report.bookmarks.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn read_state(path: &Path) -> Result<ExportState> {
    match fs::read(path) {
        Ok(bytes) => Ok(ExportState::decode(&bytes)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(ExportState::default()),
        Err(error) => Err(error.into()),
    }
}
