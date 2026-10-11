//! `tig snapshot`

use std::path::Path;

use super::Result;

pub(super) fn run(repository: Option<&Path>, rehash: bool) -> Result<()> {
    let mut session = super::open_session(repository)?;
    let stats = session.wc.snapshot_with_rehash(&mut session.repo, rehash)?;
    for warning in stats.warnings {
        eprintln!("warning: {warning}");
    }
    super::report_skipped(&session.repo);
    println!(
        "snapshotted {} changed paths ({} files scanned, {} hashed)",
        stats.changed, stats.scanned, stats.hashed
    );
    Ok(())
}
