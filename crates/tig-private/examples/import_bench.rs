//! Compare bulk storage backends on real Git history, including compaction.
use std::path::Path;
use std::time::Instant;

use tig_core::store::{JournalStore, Store};
use tig_private::import_git::{import_git, ImportState};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3 || !matches!(args[2].as_str(), "loose" | "journal") {
        return Err("usage: import_bench GIT_REPO FRESH_STORE loose|journal".into());
    }
    let target = Path::new(&args[1]);
    if target.exists() {
        return Err("benchmark store must be fresh".into());
    }
    let journal = JournalStore::open(target)?;
    let store: &dyn Store = if args[2] == "journal" {
        &journal
    } else {
        journal.disk()
    };
    let mut state = ImportState::new(false)?;
    let started = Instant::now();
    let report = import_git(Path::new(&args[0]), store, &mut state)?;
    let imported = started.elapsed().as_secs_f64();
    if args[2] == "journal" {
        journal.compact()?;
    }
    let total = started.elapsed().as_secs_f64();
    println!(
        "{}: {} commits, import {:.3} s, compaction {:.3} s, total {:.3} s, {:.1} commits/s",
        args[2],
        report.imported,
        imported,
        total - imported,
        total,
        report.imported as f64 / total
    );
    Ok(())
}
