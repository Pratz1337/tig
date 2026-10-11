//! `tig fetch`

use std::path::Path;

use tig_private::fetch;

use super::identity;
use super::workspace;
use super::Result;
use crate::ui::RevLabel;

pub(super) fn run(repository: Option<&Path>, remote_name: String) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    // Outsiders fetch with no identity. A corrupt file is still an error.
    let identity = identity::load_if_present()?;
    let tig = workspace::main_tig_dir(session.wc.root())?;
    let cfg = super::remote::require(&tig, &remote_name)?;
    let dir_remote = super::remote::open_existing(&cfg.path)?;
    let mut state = super::remote::load_fetch_state(&cfg.dir)?;
    let report = fetch::fetch(
        &dir_remote,
        session.repo.store().as_ref(),
        identity.as_ref(),
        &mut state,
    )?;
    if let Some(fingerprint) = &report.newly_pinned {
        println!("pinned owner of {remote_name}: {fingerprint} (verify it with them)");
    }
    let mut tx = session.repo.start(format!("fetch {remote_name}"));
    let mut bookmarks = Vec::new();
    for (name, id) in &report.refs {
        let bookmark = format!("{remote_name}/{name}");
        tx.set_bookmark(&bookmark, *id)?;
        bookmarks.push((bookmark, *id));
    }
    session.commit(tx)?;
    super::remote::save_fetch_state(&cfg.dir, &state)?;
    println!("unsealed: {}", report.unsealed);
    println!("still sealed: {}", report.still_sealed);
    let all = Vec::new();
    for (bookmark, id) in bookmarks {
        let rev = session.repo.revision(&id)?;
        let label = RevLabel::from_revision(&session.repo, id, &rev, &all);
        println!("bookmark {bookmark}: {}", label.line());
    }
    super::announce_if_moved(&mut session, before)
}
