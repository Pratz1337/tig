//! `tig workspace`

use std::fs;
use std::path::{Path, PathBuf};

use tig_core::ObjectId;

use super::{CliError, Result, WorkspaceAction};
use crate::ui::RevLabel;
use crate::wc::WorkingCopy;

pub(super) fn run(repository: Option<&Path>, action: WorkspaceAction) -> Result<()> {
    match action {
        WorkspaceAction::Add {
            path,
            name,
            revision,
        } => add(repository, path, name, revision),
        WorkspaceAction::List => list(repository),
        WorkspaceAction::Forget { name } => forget(repository, &name),
        WorkspaceAction::UpdateStale => update_stale(repository),
    }
}

fn update_stale(repository: Option<&Path>) -> Result<()> {
    // Opening normally snapshots first, which correctly refuses a stale
    // workspace. This command must preserve its recorded baseline instead.
    let mut session = super::open_session(repository)?;
    let stats = session.wc.update_stale(&mut session.repo)?;
    for warning in stats.warnings {
        eprintln!("warning: {warning}");
    }
    if let Some(saved) = stats.saved {
        let rev = session.repo.revision(&saved)?;
        let label = RevLabel::from_revision(&session.repo, saved, &rev, &[]);
        println!("saved local edits as {}", label.line());
    }
    println!("workspace updated to its current working revision");
    super::announce(&session)
}

fn add(
    repository: Option<&Path>,
    path: PathBuf,
    name: Option<String>,
    revision: Option<String>,
) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let name = match name {
        Some(name) => name,
        None => directory_name(&path)?,
    };
    let parent = match revision {
        Some(spec) => session.resolve(&spec)?,
        None => session.working()?,
    };
    let created = WorkingCopy::add_workspace(&mut session.repo, &session.wc, &name, &path, parent)?;
    let id = session.repo.working_revision(created.name())?;
    let rev = session.repo.revision(&id)?;
    // Labels use a fixed 8-char change id: no history walk on the hot path.
    let all: Vec<(tig_core::ObjectId, tig_core::Revision)> = Vec::new();
    let label = RevLabel::from_revision(&session.repo, id, &rev, &all);
    println!(
        "added workspace {} at {}",
        created.name(),
        crate::ui::show_path(created.root())
    );
    println!("{}: {}", created.name(), label.line());
    super::announce_if_moved(&mut session, before)
}

fn list(repository: Option<&Path>) -> Result<()> {
    let (session, _before) = super::open_ready(repository)?;
    let tig_dir = main_tig_dir(session.wc.root())?;
    let workspaces: Vec<(String, ObjectId)> = session
        .repo
        .view()
        .workspaces
        .iter()
        .map(|(name, id)| (name.clone(), *id))
        .collect();
    if workspaces.is_empty() {
        println!("No workspaces.");
        return Ok(());
    }
    // Labels use a fixed 8-char change id: no history walk on the hot path.
    let all: Vec<(tig_core::ObjectId, tig_core::Revision)> = Vec::new();
    for (name, id) in workspaces {
        let rev = session.repo.revision(&id)?;
        let label = RevLabel::from_revision(&session.repo, id, &rev, &all);
        let root = workspace_root(&tig_dir, &name);
        println!("{name} {} {} {root}", label.change_id, label.object_id);
    }
    Ok(())
}

fn forget(repository: Option<&Path>, name: &str) -> Result<()> {
    let (mut session, before) = super::open_ready(repository)?;
    let current = session.name().to_string();
    let mut tx = session.repo.start(format!("forget workspace {name}"));
    tx.remove_workspace(name)?;
    session.commit(tx)?;
    println!("forgot workspace {name}");
    if name == current {
        println!("this directory is no longer a workspace");
        return Ok(());
    }
    super::announce_if_moved(&mut session, before)
}

fn directory_name(path: &Path) -> Result<String> {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(CliError::msg(
            "workspace add needs --name (could not use the directory name)",
        ));
    };
    if name.is_empty() || name == "." || name == ".." {
        return Err(CliError::msg(
            "workspace add needs --name (could not use the directory name)",
        ));
    }
    Ok(name.to_string())
}

/// The main `.tig` directory. A secondary workspace's `.tig` is a pointer file.
pub(super) fn main_tig_dir(root: &Path) -> Result<PathBuf> {
    let pointer = root.join(".tig");
    let meta = fs::symlink_metadata(&pointer)
        .map_err(|err| CliError::msg(format!("cannot read {}: {err}", pointer.display())))?;
    if meta.is_dir() {
        return Ok(pointer);
    }
    if meta.is_file() {
        let text = fs::read_to_string(&pointer)?;
        let path = PathBuf::from(text.trim());
        if path.is_dir() {
            return Ok(path);
        }
        return Err(CliError::msg(format!(
            "{} does not point at a tig directory",
            pointer.display()
        )));
    }
    Err(CliError::msg(format!(
        "{} is not a tig directory",
        pointer.display()
    )))
}

fn workspace_root(tig_dir: &Path, name: &str) -> String {
    let path = tig_dir.join("workspaces").join(name).join("root");
    match fs::read_to_string(path) {
        Ok(text) => {
            let text = text.trim();
            if text.is_empty() {
                "(unknown)".to_string()
            } else {
                crate::ui::show_path(Path::new(text))
            }
        }
        Err(_) => "(unknown)".to_string(),
    }
}
