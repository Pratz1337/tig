//! Long-lived native watcher with selective snapshots and full reconciliation.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use super::CliError;
use super::Result;
use crate::watcher::{self, FsWatch, WatchConfig, DEFAULT_QUEUE_BOUND, RECONCILE_EVERY};

pub(super) fn run(repository: Option<&Path>) -> Result<()> {
    let mut session = super::open_session(repository)?;
    let meta = session.wc.workspace_meta_dir();
    let root = session.wc.root().to_path_buf();

    let mut watcher = FsWatch::start(WatchConfig {
        root,
        workspace_meta: meta.clone(),
        queue_bound: DEFAULT_QUEUE_BOUND,
    })
    .map_err(io_msg)?;

    // Arm first: events concurrent with the initial authoritative scan
    // remain queued instead of disappearing in the startup gap.
    session.wc.enable_watcher()?;
    let seen = watcher::load_dirty(&meta).map_err(io_msg)?;
    let scanned = apply_scan(&mut session, &[], true, true)?;
    if scanned {
        watcher::consume_dirty_through(&meta, seen.epoch).map_err(io_msg)?;
    }

    let mut last_full = Instant::now();
    loop {
        let batch = watcher.recv(Duration::from_millis(200)).map_err(io_msg)?;
        let reconcile = last_full.elapsed() >= RECONCILE_EVERY;
        let Some(batch) = batch else {
            if reconcile {
                full_and_consume(&mut session, &meta)?;
                last_full = Instant::now();
            }
            continue;
        };
        if batch.baseline && !batch.restart {
            session.repo.reload()?;
            if !session.wc.baseline_is_stale(&session.repo)? {
                continue;
            }
        }
        let epoch = watcher::record_dirty(&meta, &batch).map_err(io_msg)?;
        if batch.restart {
            watcher.restart().map_err(io_msg)?;
        }
        let full = batch.full_scan || reconcile || batch.restart;
        let paths: &[PathBuf] = if full { &[] } else { &batch.paths };
        let scanned = apply_scan(&mut session, paths, full, true)?;
        if scanned {
            watcher::consume_dirty_through(&meta, epoch).map_err(io_msg)?;
        }
        if full {
            last_full = Instant::now();
        }
    }
}

fn full_and_consume(session: &mut super::Session, meta: &Path) -> Result<()> {
    let hints = watcher::load_dirty(meta).map_err(io_msg)?;
    let scanned = apply_scan(session, &[], true, true)?;
    if scanned {
        watcher::consume_dirty_through(meta, hints.epoch).map_err(io_msg)?;
    }
    Ok(())
}

fn apply_scan(
    session: &mut super::Session,
    paths: &[PathBuf],
    mut full: bool,
    rehash: bool,
) -> Result<bool> {
    session.repo.reload()?;
    if session.wc.baseline_is_stale(&session.repo)? {
        *session = super::open_session(Some(session.wc.root()))?;
        full = true;
        if session.wc.baseline_is_stale(&session.repo)? {
            // The other command has committed but is still checking out.
            // Keep durable hints and adopt its state on the next event.
            return Ok(false);
        }
    }
    let stats = match session
        .wc
        .snapshot_paths(&mut session.repo, paths, full, rehash)
    {
        Ok(stats) => stats,
        Err(error) => {
            session.repo.reload()?;
            if session.wc.baseline_is_stale(&session.repo)? {
                return Ok(false);
            }
            return Err(error.into());
        }
    };
    for warning in stats.warnings {
        eprintln!("warning: {warning}");
    }
    super::report_skipped(&session.repo);
    println!(
        "snapshotted {} changed paths ({} files scanned, {} hashed)",
        stats.changed, stats.scanned, stats.hashed
    );
    Ok(true)
}

fn io_msg(err: watcher::WatchError) -> CliError {
    CliError::msg(err.to_string())
}
