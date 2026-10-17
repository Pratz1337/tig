//! `tig status`

use std::path::Path;

use tig_core::treeops::diff_trees;

use super::Result;
use crate::ui::RevLabel;

pub(super) fn run(repository: Option<&Path>, short: bool, null: bool) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let id = session.working()?;
    let rev = session.repo.revision(&id)?;
    let short = short || null;
    let end = if null { "\0" } else { "\n" };
    if !short {
        // Labels use a fixed 8-char change id: no history walk on the hot path.
        let all: Vec<(tig_core::ObjectId, tig_core::Revision)> = Vec::new();
        let label = RevLabel::from_revision(&session.repo, id, &rev, &all);
        println!("working change: {}", label.line());

        if rev.parents.is_empty() {
            println!("parent: (none)");
        } else {
            for parent in &rev.parents {
                let parent_rev = session.repo.revision(parent)?;
                let parent_label = RevLabel::from_revision(&session.repo, *parent, &parent_rev, &all);
                println!("parent: {}", parent_label.line());
            }
        }
    }

    let parent_tree = match rev.parents.first() {
        Some(parent) => session.repo.revision(parent)?.tree,
        None => tig_core::store::empty_tree_id(),
    };
    let mut entries = diff_trees(session.repo.store().as_ref(), &parent_tree, &rev.tree)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    let conflicts: std::collections::BTreeSet<_> = session.wc.conflict_paths().into_iter().collect();
    for path in &conflicts {
        if short { print!("C {path}{end}"); }
        else { println!("C {path} (unresolved conflict)"); }
    }
    if entries.is_empty() && conflicts.is_empty() {
        if !short { println!("No changes."); }
        return Ok(());
    }
    for entry in entries {
        if conflicts.contains(&entry.path) { continue; }
        let letter = match (&entry.old, &entry.new) {
            (None, Some(_)) => "A",
            (Some(_), None) => "D",
            _ => "M",
        };
        print!("{letter} {}{end}", entry.path);
    }
    Ok(())
}
