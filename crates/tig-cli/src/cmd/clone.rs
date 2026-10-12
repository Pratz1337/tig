//! `tig clone`
//!
//! `WorkingCopy::init` always writes a template `.private` when that file is
//! absent. Clone should skip it so the file comes from the fetched revision.
//! That needs a `write_private` flag on init, which lives in `wc.rs`. Until
//! then, clone inits normally and checkout replaces `.private` when the
//! published bytes differ.

use std::fs;
use std::path::{Path, PathBuf};

use super::{CliError, Result};
use crate::ui;

pub(super) fn run(_repository: Option<&Path>, source: &str, dir: PathBuf) -> Result<()> {
    ensure_fresh_dir(&dir)?;
    // Ignore global `-R`: the new repo is `dir`, not the caller's checkout.
    super::init::run(None, Some(dir.clone()))?;
    super::remote::add(Some(&dir), "origin", source)?;
    super::fetch::run(Some(&dir), "origin".to_string())?;
    let spec = checkout_spec(&dir)?;
    super::new_change::run(Some(&dir), vec![spec], None)
}

fn ensure_fresh_dir(dir: &Path) -> Result<()> {
    match fs::read_dir(dir) {
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CliError::msg(format!(
            "cannot read {}: {err}",
            ui::show_path(dir)
        ))),
        Ok(mut entries) => {
            if entries.next().is_some() {
                Err(CliError::msg(format!(
                    "{} is not empty",
                    ui::show_path(dir)
                )))
            } else {
                Ok(())
            }
        }
    }
}

fn checkout_spec(dir: &Path) -> Result<String> {
    let (session, _before) = super::open_ready(Some(dir))?;
    let bookmarks = &session.repo.view().bookmarks;
    if bookmarks.contains_key("origin/main") {
        return Ok("origin/main".to_string());
    }
    match bookmarks.keys().find(|name| name.starts_with("origin/")) {
        Some(name) => Ok(name.clone()),
        None => Err(CliError::msg("origin has no bookmarks")),
    }
}
