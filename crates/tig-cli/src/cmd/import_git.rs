//! `tig import-git`: persistence and working-copy adapter for the import API.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::time::Instant;

use tig_core::store::DiskStore;
use tig_private::import_git::{import_git, ImportState};
use zeroize::Zeroizing;

use super::{CliError, Result, Session};
use crate::wc::WorkingCopy;

pub(super) fn load_state(tig: &Path) -> Result<Option<ImportState>> {
    match fs::read(tig.join("git-import")) {
        Ok(bytes) => Ok(Some(ImportState::decode(&Zeroizing::new(bytes))?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn run(repository: Option<&Path>, source: &Path, strip_private: bool) -> Result<()> {
    let started = Instant::now();
    let source = fs::canonicalize(source)?;
    let target = super::start_dir(repository)?;
    // Existing tig repositories may contain work; initialization only accepts
    // a fresh empty destination, never implicitly snapshots a Git worktree.
    let mut session = match fs::read_dir(&target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => initialize(&target)?,
        Ok(mut entries) => {
            if entries.next().is_none() {
                initialize(&target)?
            } else {
                super::open_ready(Some(&target))?.0
            }
        }
        Err(error) => return Err(error.into()),
    };
    let before = session.working()?;
    let tig = super::workspace::main_tig_dir(session.wc.root())?;
    let mut state = match load_state(&tig)? {
        Some(state) => state,
        None => {
            let state = ImportState::new(strip_private)?;
            // Identity is durable before any commit gets a ChangeId. An
            // interrupted import must retry with this exact secret.
            if !super::disk::write_new(&tig.join("git-import"), &state.encode(), true)? {
                return Err(CliError::msg("another import created its state; retry"));
            }
            state
        }
    };
    if state.strip_private != strip_private {
        return Err(CliError::msg("re-import must use the same --strip-private mode; use a separate destination to change it"));
    }
    let previous: BTreeSet<_> = state.revisions.values().copied().collect();
    // State may have been saved just before a crash prevented the view commit.
    // Durable object mappings alone do not mean history was made visible.
    let first = previous.is_empty()
        || !session
            .repo
            .visible_revisions()?
            .iter()
            .any(|(id, _)| previous.contains(id));
    // Bulk objects bypass the journal, so ordinary commands do not inherit
    // import compaction. See the measured comparison in bench/IMPORT.md.
    let bulk = DiskStore::open(tig.join("store"))?;
    let report = import_git(&source, &bulk, &mut state)?;
    for path in &report.matched {
        if strip_private {
            eprintln!("stripped private path: {path}");
        } else {
            eprintln!("{path}: already exposed in git history — rotate these secrets");
        }
    }
    for warning in &report.warnings {
        eprintln!("warning: {warning}");
    }
    for (name, target) in &report.bookmarks {
        if let Some(existing) = session.repo.view().bookmarks.get(name) {
            if existing != target && !previous.contains(existing) {
                return Err(CliError::msg(format!(
                    "bookmark {name:?} has local work; rename it before importing this branch"
                )));
            }
        }
    }
    // Persist leak evidence before making imported history visible. A crash
    // after this write is safe to retry; all objects have already been written.
    super::disk::write_replace(&tig.join("git-import"), &state.encode(), true)?;
    let mut tx = session.repo.start("import Git history");
    tx.import_history(&report.heads, &report.bookmarks)?;
    if first {
        if let Some(head) = report.head {
            let working = tx.new_change(&[head], "")?;
            tx.set_working(session.name(), working)?;
        }
    }
    if tx.view() != session.repo.view() {
        session.commit(tx)?;
    }
    super::announce_if_moved(&mut session, before)?;
    println!(
        "imported {} revisions; reused {}; {} bookmarks; {:.2} s ({:.0} revisions/s)",
        report.imported,
        report.reused,
        report.bookmarks.len(),
        started.elapsed().as_secs_f64(),
        (report.imported + report.reused) as f64 / started.elapsed().as_secs_f64().max(0.001)
    );
    Ok(())
}

fn initialize(target: &Path) -> Result<Session> {
    let (repo, wc) = WorkingCopy::init_for_import(target, super::settings::load()?.settings)?;
    Ok(Session { repo, wc })
}
