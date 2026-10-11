//! `tig init`

use std::path::{Path, PathBuf};

use super::settings;
use super::{CliError, Result};
use crate::ui::{self, RevLabel};
use crate::wc::WorkingCopy;

pub(super) fn run(repository: Option<&Path>, dir: Option<PathBuf>) -> Result<()> {
    let dir = match dir {
        Some(dir) => dir,
        None => super::start_dir(repository)?,
    };
    let private_path = dir.join(".private");
    let wrote_private = match std::fs::symlink_metadata(&private_path) {
        Ok(_) => false,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => true,
        Err(err) => {
            return Err(CliError::msg(format!(
                "cannot stat {}: {err}",
                private_path.display()
            )))
        }
    };

    let loaded = settings::load()?;
    let (repo, wc) = WorkingCopy::init(&dir, loaded.settings.clone())?;
    println!("initialized repo in {}", crate::ui::show_path(wc.root()));
    if wrote_private {
        println!("wrote .private");
        println!(
            ".env* (except .env.example, .env.sample, .env.template), *.pem, *.key, \
             *.p12, *.pfx, id_rsa, id_dsa, id_ecdsa, and id_ed25519 are private by default"
        );
    } else {
        println!("kept existing .private");
    }
    if loaded.fell_back {
        eprintln!(
            "hint: author is {} <{}>; set TIG_AUTHOR_NAME and TIG_AUTHOR_EMAIL, or user.name and user.email in ~/.gitconfig",
            loaded.settings.user_name, loaded.settings.user_email
        );
    }
    let id = repo.working_revision(wc.name())?;
    let rev = repo.revision(&id)?;
    let all = repo.visible_revisions()?;
    let label = RevLabel::from_revision(&repo, id, &rev, &all);
    println!("{}", ui::working_change_line(&label));
    Ok(())
}
