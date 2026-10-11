//! `tig bookmark`

use std::path::Path;

use tig_core::ObjectId;

use super::{BookmarkAction, Result};
use crate::ui::RevLabel;

pub(super) fn run(repository: Option<&Path>, action: BookmarkAction) -> Result<()> {
    match action {
        BookmarkAction::Set { name, revision } => set(repository, name, revision),
        BookmarkAction::List => list(repository),
        BookmarkAction::Delete { name } => delete(repository, name),
    }
}

fn set(repository: Option<&Path>, name: String, revision: Option<String>) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let id = match revision {
        Some(spec) => session.resolve(&spec)?,
        None => session.working()?,
    };
    let mut tx = session.repo.start(format!("set bookmark {name}"));
    tx.set_bookmark(&name, id)?;
    session.commit(tx)?;
    let rev = session.repo.revision(&id)?;
    let all = session.repo.visible_revisions()?;
    let label = RevLabel::from_revision(&session.repo, id, &rev, &all);
    println!("bookmark {name}: {}", label.line());
    super::announce_if_moved(&mut session, before)
}

fn list(repository: Option<&Path>) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let bookmarks: Vec<(String, ObjectId)> = session
        .repo
        .view()
        .bookmarks
        .iter()
        .map(|(name, id)| (name.clone(), *id))
        .collect();
    if bookmarks.is_empty() {
        println!("No bookmarks.");
        return Ok(());
    }
    let all = session.repo.visible_revisions()?;
    for (name, id) in bookmarks {
        let rev = session.repo.revision(&id)?;
        let label = RevLabel::from_revision(&session.repo, id, &rev, &all);
        println!("{name} {}", label.line());
    }
    Ok(())
}

fn delete(repository: Option<&Path>, name: String) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let mut tx = session.repo.start(format!("delete bookmark {name}"));
    tx.delete_bookmark(&name)?;
    session.commit(tx)?;
    println!("deleted bookmark {name}");
    super::announce_if_moved(&mut session, before)
}
