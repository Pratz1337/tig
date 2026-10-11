//! `tig status`

use std::path::Path;

use tig_core::treeops::diff_trees;

use super::Result;
use crate::ui::RevLabel;

pub(super) fn run(repository: Option<&Path>) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let id = session.working()?;
    let rev = session.repo.revision(&id)?;
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

    let parent_tree = match rev.parents.first() {
        Some(parent) => session.repo.revision(parent)?.tree,
        None => tig_core::store::empty_tree_id(),
    };
    let mut entries = diff_trees(session.repo.store().as_ref(), &parent_tree, &rev.tree)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    if entries.is_empty() {
        println!("No changes.");
        return Ok(());
    }
    for entry in entries {
        let letter = match (&entry.old, &entry.new) {
            (None, Some(_)) => "A",
            (Some(_), None) => "D",
            _ => "M",
        };
        println!("{letter} {}", entry.path);
    }
    Ok(())
}
