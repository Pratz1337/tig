//! `tig log`

use std::path::Path;

use tig_core::repo::Repo;
use tig_core::{ObjectId, Revision};

use super::Result;
use crate::ui::{self, RevLabel};

pub(super) fn run(repository: Option<&Path>, limit: Option<usize>) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let working = session.working()?;
    let all = session.repo.visible_revisions()?;
    let limit = limit.unwrap_or(usize::MAX);
    for (id, rev) in all.iter().take(limit) {
        print_entry(&session, working, *id, rev, &all, false)?;
    }
    Ok(())
}

pub(super) fn print_entry(
    session: &super::Session,
    working: ObjectId,
    id: ObjectId,
    rev: &Revision,
    all: &[(ObjectId, Revision)],
    full_description: bool,
) -> Result<()> {
    // The root is the same empty starting point in every repo; its zero
    // change id and 1970 timestamp are noise.
    if id == tig_core::repo::root_revision_id() {
        println!("{} root", ui::marker(id, working));
        return Ok(());
    }
    let label = RevLabel::from_revision(&session.repo, id, rev, all);
    let current = session.name().to_string();
    let mut extras = Vec::new();
    for (name, target) in &session.repo.view().bookmarks {
        if *target == id {
            extras.push(name.clone());
        }
    }
    for (name, target) in &session.repo.view().workspaces {
        if *target == id && name != &current {
            extras.push(format!("{name}@"));
        }
    }
    if is_empty(&session.repo, rev)? {
        extras.push("(empty)".to_string());
    }
    println!(
        "{}",
        ui::format_rev_line(
            ui::marker(id, working),
            &label,
            &rev.author.email,
            &ui::format_time(rev.committer.timestamp_ms),
            &extras,
        )
    );
    if full_description {
        print_full(&rev.description);
    } else {
        println!("  {}", label.summary);
    }
    Ok(())
}

fn print_full(description: &str) {
    if description.trim().is_empty() {
        println!("  (no description)");
        return;
    }
    for line in description.lines() {
        println!("  {line}");
    }
}

fn is_empty(repo: &Repo, rev: &Revision) -> Result<bool> {
    let Some(parent) = rev.parents.first() else {
        return Ok(false);
    };
    Ok(repo.revision(parent)?.tree == rev.tree)
}
