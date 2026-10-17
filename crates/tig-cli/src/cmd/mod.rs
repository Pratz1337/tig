//! Command dispatch. Each command snapshots the working copy, then does its
//! work in one transaction (or one core call that already commits, for undo
//! and restore), then checks the disk back out if the working revision moved.

mod abandon;
mod bookmark;
mod cat;
mod changes;
mod clone;
mod describe;
mod diff;
mod disk;
mod edit;
mod export_git;
mod fetch;
mod grant;
mod identity;
mod import_git;
mod init;
mod log;
#[path = "new.rs"]
mod new_change;
mod op;
mod publish;
mod remote;
mod role;
mod env;
mod resolve;
mod revoke;
mod settings;
mod show;
mod snapshot;
mod status;
mod undo;
mod why;
mod watch;
mod workspace;

use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use tig_core::path::RepoPath;
use tig_core::repo::Repo;
use tig_core::ObjectId;

use crate::ui::{self, RevLabel};
use crate::wc::WorkingCopy;

/// Failures a person caused or a repo can hit. Clap usage errors never become
/// this type: clap prints those itself and exits 2.
#[derive(Debug)]
pub struct CliError {
    message: String,
    child_exit: Option<i32>,
}

impl CliError {
    pub(super) fn msg(message: impl Into<String>) -> Self {
        CliError {
            message: message.into(),
            child_exit: None,
        }
    }

    pub fn child_exit_code(&self) -> Option<i32> {
        self.child_exit
    }
}

impl From<tig_private::changes::ChangeError> for CliError {
    fn from(err: tig_private::changes::ChangeError) -> Self {
        CliError::msg(err.to_string())
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl From<tig_core::Error> for CliError {
    fn from(err: tig_core::Error) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<crate::wc::Error> for CliError {
    fn from(err: crate::wc::Error) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<tig_private::project::ProjectError> for CliError {
    fn from(err: tig_private::project::ProjectError) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<std::io::Error> for CliError {
    fn from(err: std::io::Error) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<tig_private::publish::PublishError> for CliError {
    fn from(err: tig_private::publish::PublishError) -> Self {
        use tig_private::publish::PublishError;
        let message = match &err {
            PublishError::AlreadyLeaked { paths } => format!(
                "already leaked; rotate these paths: {}\npass --acknowledge-leaked to seal them from now on",
                join_repo_paths(paths)
            ),
            PublishError::NegationNeedsConfirmation { paths } => format!(
                "a negation makes these paths public; confirm them: {}\npass --confirm-negations to publish them",
                join_repo_paths(paths)
            ),
            _ => err.to_string(),
        };
        CliError::msg(message)
    }
}

impl From<tig_private::fetch::FetchError> for CliError {
    fn from(err: tig_private::fetch::FetchError) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<tig_private::keyring::KeyringError> for CliError {
    fn from(err: tig_private::keyring::KeyringError) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<tig_private::access::AccessError> for CliError {
    fn from(err: tig_private::access::AccessError) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<tig_private::remote::RemoteError> for CliError {
    fn from(err: tig_private::remote::RemoteError) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<tig_private::manifest::ManifestError> for CliError {
    fn from(err: tig_private::manifest::ManifestError) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<tig_private::keys::KeyError> for CliError {
    fn from(err: tig_private::keys::KeyError) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<tig_private::import_git::ImportError> for CliError {
    fn from(err: tig_private::import_git::ImportError) -> Self {
        CliError::msg(err.to_string())
    }
}

impl From<tig_private::export_git::ExportError> for CliError {
    fn from(err: tig_private::export_git::ExportError) -> Self {
        CliError::msg(err.to_string())
    }
}

fn join_repo_paths(paths: &[RepoPath]) -> String {
    paths
        .iter()
        .map(RepoPath::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

pub type Result<T> = std::result::Result<T, CliError>;

struct Session {
    repo: Repo,
    wc: WorkingCopy,
}

impl Session {
    /// Commits `tx` and reports any descendant left un-rebased.
    fn commit(&mut self, tx: tig_core::repo::Transaction) -> Result<()> {
        self.repo.commit(tx)?;
        report_skipped(&self.repo);
        Ok(())
    }

    fn name(&self) -> &str {
        self.wc.name()
    }

    fn resolve(&self, spec: &str) -> Result<ObjectId> {
        Ok(self.repo.resolve(self.name(), spec)?)
    }

    fn working(&self) -> Result<ObjectId> {
        Ok(self.repo.working_revision(self.name())?)
    }
}

/// Opens the workspace and snapshots the disk before any command work.
fn open_ready(repository: Option<&Path>) -> Result<(Session, ObjectId)> {
    let mut session = open_session(repository)?;
    let stats = session.wc.snapshot(&mut session.repo)?;
    for warning in stats.warnings {
        eprintln!("warning: {warning}");
    }
    report_skipped(&session.repo);
    let before = session.working()?;
    Ok((session, before))
}

/// A rebase that would conflict leaves the descendant on the previous
/// version of its parent; say so, so nothing changes silently.
fn report_skipped(repo: &tig_core::repo::Repo) {
    for skipped in repo.last_skipped_rebases() {
        let paths: Vec<String> = skipped
            .paths
            .iter()
            .take(5)
            .map(|p| p.to_string())
            .collect();
        eprintln!(
            "warning: change {} was not rebased onto this edit because it would conflict in {}; it stays on the previous version (conflict support is coming)",
            skipped.change.short(8),
            paths.join(", ")
        );
    }
}

fn open_session(repository: Option<&Path>) -> Result<Session> {
    let start = start_dir(repository)?;
    let loaded = settings::load()?;
    let (repo, wc) = WorkingCopy::open(&start, loaded.settings)?;
    Ok(Session { repo, wc })
}

fn start_dir(repository: Option<&Path>) -> Result<PathBuf> {
    match repository {
        Some(dir) => Ok(dir.to_path_buf()),
        None => std::env::current_dir()
            .map_err(|err| CliError::msg(format!("current directory: {err}"))),
    }
}

/// Checks out when this workspace's working revision changed.
/// Returns false when the workspace was removed or the revision is unchanged.
fn close_moved(session: &mut Session, before: ObjectId) -> Result<bool> {
    let name = session.name().to_string();
    let Some(&after) = session.repo.view().workspaces.get(&name) else {
        return Ok(false);
    };
    if after == before {
        return Ok(false);
    }
    session.wc.checkout(&session.repo)?;
    Ok(true)
}

fn announce(session: &Session) -> Result<()> {
    let id = session.working()?;
    let rev = session.repo.revision(&id)?;
    // Labels use a fixed 8-char change id: no history walk on the hot path.
    let all: Vec<(tig_core::ObjectId, tig_core::Revision)> = Vec::new();
    let label = RevLabel::from_revision(&session.repo, id, &rev, &all);
    println!("{}", ui::working_change_line(&label));
    Ok(())
}

fn announce_if_moved(session: &mut Session, before: ObjectId) -> Result<()> {
    if close_moved(session, before)? {
        announce(session)?;
    }
    Ok(())
}

fn parse_path(text: &str) -> Result<RepoPath> {
    let text = text.trim_end_matches(['/', '\\']);
    let text = text.strip_prefix("./").unwrap_or(text);
    if text.is_empty() || text == "." {
        return Err(CliError::msg("path is empty"));
    }
    Ok(RepoPath::from_os_relative(text)?)
}

pub fn run() -> Result<()> {
    // Clap prints usage errors itself and exits 2. `--help` exits 0.
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    };
    let repository = cli.repository.as_deref();
    match cli.command {
        Cmd::Init { dir } => init::run(repository, dir)?,
        Cmd::ImportGit {
            path,
            strip_private,
        } => import_git::run(repository, &path, strip_private)?,
        Cmd::ExportGit {
            path,
            bookmark,
            declassify,
            force,
            verbose,
        } => export_git::run(repository, &path, bookmark, declassify, force, verbose)?,
        Cmd::Status { short, null } => status::run(repository, short, null)?,
        Cmd::Watch => watch::run(repository)?,
        Cmd::Snapshot { rehash } => snapshot::run(repository, rehash)?,
        Cmd::Diff { revision, stat } => diff::run(repository, revision.as_deref(), stat)?,
        Cmd::Log { limit } => log::run(repository, limit)?,
        Cmd::Show { revision } => show::run(repository, revision.as_deref())?,
        Cmd::New { revs, message } => new_change::run(repository, revs, message)?,
        Cmd::Describe { revision, message } => {
            describe::run(repository, revision.as_deref(), message)?
        }
        Cmd::Edit { revision } => edit::run(repository, &revision)?,
        Cmd::Abandon { revision } => abandon::run(repository, revision.as_deref())?,
        Cmd::Undo => undo::run(repository)?,
        Cmd::Op { action } => op::run(repository, action)?,
        Cmd::Workspace { action } => workspace::run(repository, action)?,
        Cmd::Bookmark { action } => bookmark::run(repository, action)?,
        Cmd::Cat { path, revision } => cat::run(repository, &path, revision.as_deref())?,
        Cmd::Resolve { path, side, base } => resolve::run(repository, &path, side, base)?,
        Cmd::Why { path } => why::run(repository, &path)?,
        Cmd::Identity { show } => identity::run(show)?,
        Cmd::Remote { action } => remote::run(repository, action)?,
        Cmd::Role(args) => role::run(repository, args)?,
        Cmd::Env(args) => {
            let status = env::run(repository, args)?;
            if !status.success() {
                return Err(CliError {
                    message: String::new(),
                    child_exit: Some(status.code().unwrap_or(1)),
                });
            }
        }
        Cmd::Seal { remote, bookmark, revision, role } => changes::seal(repository, remote, bookmark, revision, role)?,
        Cmd::Reveal { remote, revision } => changes::reveal(repository, remote, revision)?,
        Cmd::Publish {
            remote,
            bookmark,
            revision,
            acknowledge_leaked,
            confirm_negations,
            declassify,
            force,
        } => publish::run(
            repository,
            remote,
            bookmark,
            revision,
            acknowledge_leaked,
            confirm_negations,
            declassify,
            force,
        )?,
        Cmd::Fetch { remote } => fetch::run(repository, remote)?,
        Cmd::Clone { source, dir } => clone::run(repository, &source, dir)?,
        Cmd::Grant { remote, token } => grant::run(repository, remote, token)?,
        Cmd::Revoke { remote, token } => revoke::run(repository, remote, token)?,
    }
    Ok(())
}

#[derive(Parser)]
#[command(
    name = "tig",
    version,
    about = "version control",
    arg_required_else_help = true,
    disable_help_subcommand = true,
    color = clap::ColorChoice::Never
)]
struct Cli {
    /// Repository root, or any directory inside a workspace.
    #[arg(short = 'R', long = "repository", global = true, value_name = "DIR")]
    repository: Option<PathBuf>,

    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Snapshot filesystem changes from native events
    Watch,
    /// Manage ranked roles and their access groups
    Role(role::Args),
    /// Run a command with secrets authorized for a role
    Env(env::Args),
    /// Publish an opaque change that can be opened in place
    Seal {
        remote: String,
        bookmark: String,
        #[arg(short = 'r', long, value_name = "REV")]
        revision: Option<String>,
        #[arg(long)]
        role: String,
    },
    /// Reveal an opaque change without rewriting its public history
    Reveal {
        remote: String,
        #[arg(short = 'r', long, value_name = "REV")]
        revision: String,
    },
    /// Import complete Git history into this repository (creates an empty destination)
    ImportGit {
        /// Source Git working tree or bare repository
        path: PathBuf,
        /// Remove private paths from every imported revision (never-public Git repos)
        #[arg(long)]
        strip_private: bool,
    },
    /// Write bookmarks to a Git repository. Private paths are omitted.
    ExportGit {
        /// Destination Git repository. Created when missing or empty.
        /// A path ending in `.git` is bare; the worktree is never checked out.
        path: PathBuf,
        /// Bookmark to export. Repeat to export several. Defaults to every bookmark.
        #[arg(long, value_name = "NAME")]
        bookmark: Vec<String>,
        /// Export this public path even though its bytes also appear in a private file
        #[arg(long, value_name = "PATH")]
        declassify: Vec<String>,
        /// Overwrite a Git branch that is not a fast-forward of the last export
        #[arg(long)]
        force: bool,
        /// List omitted private paths. The default summary is only a count.
        #[arg(long)]
        verbose: bool,
    },
    /// Record the disk in the working change
    Snapshot {
        /// Re-read every file instead of using the stat cache
        #[arg(long)]
        rehash: bool,
    },
    /// Create a repository
    Init {
        /// Directory to create. Defaults to the current directory.
        dir: Option<PathBuf>,
    },
    /// Show the working change and what differs from its parent
    #[command(alias = "st")]
    Status {
        /// Print only change letters and paths; clean changes produce no output
        #[arg(short, long)]
        short: bool,
        /// End each path with NUL instead of newline; implies --short
        #[arg(short = 'z', long = "null")]
        null: bool,
    },
    /// Show a revision against its first parent
    Diff {
        /// Revision to diff. Defaults to `@`.
        #[arg(short = 'r', long = "revision", value_name = "REV")]
        revision: Option<String>,
        /// Print a summary of added and removed lines
        #[arg(long)]
        stat: bool,
    },
    /// List visible revisions, newest first
    Log {
        /// Show at most N revisions
        #[arg(short = 'n', value_name = "N")]
        limit: Option<usize>,
    },
    /// Show one revision and its diff
    Show {
        /// Revision to show. Defaults to `@`.
        revision: Option<String>,
    },
    /// Start a new change and make it the working change
    New {
        /// Parent revisions. Defaults to `@`.
        revs: Vec<String>,
        /// Description. Empty when omitted.
        #[arg(short = 'm', long = "message", value_name = "MSG")]
        message: Option<String>,
    },
    /// Set a revision's description
    Describe {
        /// Revision to describe. Defaults to `@`.
        #[arg(short = 'r', long = "revision", value_name = "REV")]
        revision: Option<String>,
        /// New description
        #[arg(short = 'm', long = "message", value_name = "MSG")]
        message: Option<String>,
    },
    /// Make a revision the working change
    Edit {
        /// Revision to edit
        revision: String,
    },
    /// Hide a revision
    Abandon {
        /// Revision to abandon. Defaults to `@`.
        revision: Option<String>,
    },
    /// Undo the latest operation
    Undo,
    /// Operation log
    Op {
        #[command(subcommand)]
        action: OpAction,
    },
    /// Extra working copies
    Workspace {
        #[command(subcommand)]
        action: WorkspaceAction,
    },
    /// Named revisions
    Bookmark {
        #[command(subcommand)]
        action: BookmarkAction,
    },
    /// Print a file's bytes
    Cat {
        /// Path inside the revision
        path: String,
        /// Revision to read. Defaults to `@`.
        #[arg(short = 'r', long = "revision", value_name = "REV")]
        revision: Option<String>,
    },
    /// Resolve a conflict by selecting one of its stored alternatives
    Resolve {
        /// Conflicted path. Text files can also be resolved by ordinary editing.
        path: String,
        /// Select a positive alternative (1-based, as shown in conflict markers).
        #[arg(long, required_unless_present = "base", conflicts_with = "base")]
        side: Option<usize>,
        /// Select a base alternative (1-based).
        #[arg(long)]
        base: Option<usize>,
    },
    /// Explain why a path is private or public
    Why {
        /// Path to classify
        path: String,
    },
    /// Show or create your identity
    Identity {
        /// Show the identity without creating one
        #[arg(long)]
        show: bool,
    },
    /// Remotes: directories or tig servers
    Remote {
        #[command(subcommand)]
        action: RemoteAction,
    },
    /// Publish a revision to a remote
    Publish {
        /// Remote name
        remote: String,
        /// Bookmark to publish. Defaults to `main`.
        #[arg(short = 'b', long = "bookmark", default_value = "main")]
        bookmark: String,
        /// Revision to publish. Defaults to `@`, or `@-` when `@` is empty.
        #[arg(short = 'r', long = "revision", value_name = "REV")]
        revision: Option<String>,
        /// Seal paths that were already published in the clear
        #[arg(long)]
        acknowledge_leaked: bool,
        /// Publish paths a `!` rule makes public
        #[arg(long)]
        confirm_negations: bool,
        /// Publish this path in the clear although its bytes were private
        /// before (repeatable)
        #[arg(long, value_name = "PATH")]
        declassify: Vec<String>,
        /// Move the bookmark even when the remote has changes you have not fetched
        #[arg(long)]
        force: bool,
    },
    /// Fetch bookmarks from a remote
    Fetch {
        /// Remote name
        remote: String,
    },
    /// Copy a remote into a new repository
    Clone {
        /// Remote directory or server URL (https://host[:port]/...) to copy
        source: String,
        /// Directory for the new repository
        dir: PathBuf,
    },
    /// Grant a person access to a remote
    Grant {
        /// Remote name
        remote: String,
        /// Their `tig identity` token
        token: String,
    },
    /// Revoke a person's access to a remote
    Revoke {
        /// Remote name
        remote: String,
        /// Their `tig identity` token
        token: String,
    },
}

#[derive(Subcommand)]
enum OpAction {
    /// Verify stored content and recover the newest complete operation
    Recover,
    /// List operations, newest first
    Log {
        /// Show at most N operations
        #[arg(short = 'n', value_name = "N")]
        limit: Option<usize>,
    },
    /// Make the repo look as it did after an operation
    Restore {
        /// Operation id or a unique prefix of one
        op: String,
    },
}

#[derive(Subcommand)]
enum WorkspaceAction {
    /// Update a stale workspace, saving any disk edits as a separate change
    UpdateStale,
    /// Create a workspace at PATH
    Add {
        /// Directory for the new workspace
        path: PathBuf,
        /// Workspace name. Defaults to the directory name.
        #[arg(long, value_name = "NAME")]
        name: Option<String>,
        /// Parent revision. Defaults to `@`.
        #[arg(short = 'r', long = "revision", value_name = "REV")]
        revision: Option<String>,
    },
    /// List workspaces
    List,
    /// Drop a workspace from the repo. Does not delete its files.
    Forget {
        /// Workspace name
        name: String,
    },
}

#[derive(Subcommand)]
enum BookmarkAction {
    /// Point a bookmark at a revision
    Set {
        /// Bookmark name
        name: String,
        /// Revision to mark. Defaults to `@`.
        #[arg(short = 'r', long = "revision", value_name = "REV")]
        revision: Option<String>,
    },
    /// List bookmarks
    List,
    /// Remove a bookmark
    Delete {
        /// Bookmark name
        name: String,
    },
}

#[derive(Subcommand)]
enum RemoteAction {
    /// Remember a remote directory or server
    Add {
        /// Remote name
        name: String,
        /// Directory path, or server URL (https://, or http:// to loopback only)
        location: String,
    },
    /// List remotes
    List,
    /// Forget a remote. Does not delete its files.
    Remove {
        /// Remote name
        name: String,
    },
}
