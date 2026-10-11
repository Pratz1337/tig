//! Filesystem working copy.
//!
//! One client of [`tig_core::workspace::Workspace`]: a directory walk plus a
//! stat cache finds what changed, and the overlay folds that into the working
//! revision. Checkout is the other direction, after `new` / `edit` / `undo`
//! moved the revision. See DESIGN.md "Workspaces" and "Paths".
//!
//! Bytes are stored and restored as-is. Line endings are never converted.
//!
//! The stat cache is marked *racy* (the racy-git rule) for every file whose
//! mtime is within [`RACY_WINDOW`] of the moment the state is saved. Those
//! files are hashed again on the next snapshot, because a filesystem can
//! report the same timestamp for two writes that both landed inside its
//! clock resolution.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ignore::WalkBuilder;
use tig_core::encode::{Reader, Writer};
use tig_core::index::PathIndex;
use tig_core::object::{hash_object, EntryKind, ObjectKind};
use tig_core::ophead::FileOpHead;
use tig_core::path::RepoPath;
use tig_core::repo::{Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::store::{empty_tree_id, DiskStore, StoreExt};
use tig_core::treeops::{diff_trees, walk, DiffEntry, Leaf};
use tig_core::workspace::Workspace;
use tig_core::ObjectId;
use tig_private::rules::DEFAULT_PRIVATE;

/// Files touched this close to a state save are hashed again next time.
const RACY_WINDOW: Duration = Duration::from_secs(2);

const STATE_MAGIC: &[u8; 4] = b"TIGW";
const STATE_VERSION: u8 = 1;
const FLAG_RACY: u8 = 0b01;
const FLAG_STAND_IN: u8 = 0b10;

/// Problems the working copy can run into. Disk and core failures are
/// wrapped; everything else is a sentence a person can act on.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// What one snapshot looked at. `changed == 0` means no operation was written.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotStats {
    /// Files visited. Ignored files and `.tig` are not counted.
    pub scanned: usize,
    /// Files whose bytes were read and hashed. A cache hit is not a hash.
    pub hashed: usize,
    /// Paths that differ from the working revision, deletions included.
    pub changed: usize,
    /// Names that were skipped, and notes such as a corrupt stat cache.
    pub warnings: Vec<String>,
}

/// What one checkout wrote and removed. Directories are not counted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckoutStats {
    pub written: usize,
    pub removed: usize,
}

/// One stat-cache row: what we believe is on disk for a path.
///
/// `mtime` is `(seconds, nanoseconds)` since the Unix epoch. Nanoseconds are
/// in `0..1_000_000_000`. Seconds may be negative.
///
/// On Unix, [`EntryKind::Executable`] mirrors the mode bit. On Windows the
/// bit does not exist, so a file that was executable stays executable for as
/// long as its cache row says so (an edit would otherwise drop the bit).
///
/// `symlink_stand_in` is set when Windows refused to create a symlink and the
/// target text was written as a regular file. Snapshots keep
/// [`EntryKind::Symlink`] while that file is still the stand-in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileState {
    pub size: u64,
    pub mtime: (i64, u32),
    pub kind: EntryKind,
    pub id: ObjectId,
    pub racy: bool,
    pub symlink_stand_in: bool,
}

/// On-disk record of the revision this directory currently reflects.
struct WcState {
    working: ObjectId,
    tree: ObjectId,
    cache: PathIndex<FileState>,
}

impl WcState {
    fn blank() -> Self {
        WcState {
            working: ObjectId([0; 32]),
            tree: empty_tree_id(),
            cache: PathIndex::new(),
        }
    }
}

/// The on-disk working copy rooted at `root`. `tig_dir` is the main
/// `.tig` directory (a secondary workspace's `.tig` is only a pointer file).
pub struct WorkingCopy {
    root: PathBuf,
    tig_dir: PathBuf,
    name: String,
    state: WcState,
    /// `false` when the state file was missing or corrupt. Snapshot then
    /// re-hashes every file. Checkout refuses until that snapshot lands.
    trusted: bool,
    /// Surfaced once, on the next snapshot.
    load_warning: Option<String>,
    /// When set, used instead of [`SystemTime::now`] for the racy window.
    /// Tests move this forward so they do not have to sleep.
    clock: Option<SystemTime>,
}

impl WorkingCopy {
    /// Creates `ROOT/.tig`, a repo, and the default `.private` when `ROOT`
    /// does not already have one, then snapshots whatever is already there.
    pub fn init(root: &Path, settings: Settings) -> Result<(Repo, WorkingCopy)> {
        let root = canonicalize_creating(root)?;
        let tig_dir = root.join(".tig");
        if symlink_metadata_kind(&tig_dir)?.is_some() {
            return Err(Error::Msg(format!(
                "{} already exists; a tig repo is already here",
                tig_dir.display()
            )));
        }
        fs::create_dir_all(tig_dir.join("store"))?;
        fs::create_dir_all(tig_dir.join("workspaces"))?;
        let store = Arc::new(DiskStore::open(tig_dir.join("store"))?);
        let op_head = Arc::new(FileOpHead::new(&tig_dir));
        let mut repo = Repo::init(store, op_head, settings)?;

        let private = root.join(".private");
        if symlink_metadata_kind(&private)?.is_none() {
            atomic_write(&private, DEFAULT_PRIVATE.as_bytes(), false)?;
        }

        let name = DEFAULT_WORKSPACE.to_string();
        write_root_file(&tig_dir, &name, &root)?;
        let working = repo.working_revision(&name)?;
        let tree = repo.revision(&working)?.tree;
        let mut wc = WorkingCopy {
            root,
            tig_dir,
            name,
            state: WcState {
                working,
                tree,
                cache: PathIndex::new(),
            },
            trusted: true,
            load_warning: None,
            clock: None,
        };
        wc.snapshot(&mut repo)?;
        Ok((repo, wc))
    }

    /// Finds `.tig` (a directory, or a file pointing at one) from `start`
    /// upward and opens that workspace.
    pub fn open(start: &Path, settings: Settings) -> Result<(Repo, WorkingCopy)> {
        let start_dir = starting_dir(start)?;
        let (root, tig_dir) = find_tig(&start_dir)?;
        ensure_metadata_dirs(&tig_dir)?;
        let name = workspace_name_for(&tig_dir, &root)?;
        let store = Arc::new(DiskStore::open(tig_dir.join("store"))?);
        let op_head = Arc::new(FileOpHead::new(&tig_dir));
        let repo = Repo::load(store, op_head, settings)?;
        // The view must actually have this workspace. A leftover root file
        // from a half-created workspace is not enough.
        repo.working_revision(&name)?;
        let (state, trusted, load_warning) = load_state_file(&state_path(&tig_dir, &name))?;
        Ok((
            repo,
            WorkingCopy {
                root,
                tig_dir,
                name,
                state,
                trusted,
                load_warning,
                clock: None,
            },
        ))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Overrides the clock used for the racy-git window.
    ///
    /// `None` reads [`SystemTime::now`]. Tests set a clock in the future so
    /// a snapshot can clear racy bits without sleeping for [`RACY_WINDOW`].
    pub fn set_clock(&mut self, now: Option<SystemTime>) {
        self.clock = now;
    }

    /// Scans the disk and folds the difference into the working revision as
    /// one operation. Writes nothing when the disk matches the revision.
    ///
    /// If the repo's working revision for this workspace is not the revision
    /// recorded in the state file, another process moved it. Snapshotting
    /// against the old revision would drop that move, so this returns an
    /// error telling you to run `tig workspace update-stale`.
    pub fn snapshot(&mut self, repo: &mut Repo) -> Result<SnapshotStats> {
        ensure_canonical_directory(&self.root)?;
        ensure_metadata_dirs(&self.tig_dir)?;
        repo.reload()?;
        let current = repo.working_revision(&self.name)?;
        let rev_tree = repo.revision(&current)?.tree;
        let mut warnings = Vec::new();
        if let Some(warning) = &self.load_warning {
            warnings.push(warning.clone());
        }
        if self.trusted && self.state.working != current {
            return Err(Error::Msg(format!(
                "workspace is stale; run `tig workspace update-stale` ({})",
                self.name
            )));
        }
        if self.trusted && self.state.tree != rev_tree {
            // The two ids are written together. A mismatch means the file
            // was edited or truncated in a way decode still accepted.
            self.trusted = false;
            warnings.push(
                "workspace state tree does not match the working revision; re-scanning every file"
                    .into(),
            );
        }

        let mut ws = Workspace::open(repo, &self.name)?;
        let (mut stats, cache) = self.scan(repo, &mut ws, &mut warnings)?;
        stats.changed = ws.pending().len();
        stats.warnings = warnings;
        stats.warnings.sort();
        stats.warnings.dedup();
        // `snapshot` writes one operation, or none when the overlay is empty.
        ws.snapshot(repo)?;
        self.state.working = ws.working_revision();
        self.state.tree = repo.revision(&self.state.working)?.tree;
        self.state.cache = cache;
        let now = self.now();
        mark_racy(&mut self.state.cache, now);
        self.save_state()?;
        self.trusted = true;
        self.load_warning = None;
        Ok(stats)
    }

    /// Makes the disk match the repo's current working revision.
    ///
    /// Refuses before writing when preflight finds an unsafe path or a file
    /// that differs from its snapshot. Re-checks each affected path before
    /// mutation; a concurrent edit or I/O failure can stop a partial checkout.
    pub fn checkout(&mut self, repo: &Repo) -> Result<CheckoutStats> {
        ensure_canonical_directory(&self.root)?;
        ensure_metadata_dirs(&self.tig_dir)?;
        if !self.trusted {
            return Err(Error::Msg(
                "workspace state is unusable (missing or corrupt); snapshot the working copy so tig can re-scan before checkout"
                    .into(),
            ));
        }
        let current = repo.working_revision(&self.name)?;
        let new_tree = repo.revision(&current)?.tree;
        let diff = diff_trees(repo.store().as_ref(), &self.state.tree, &new_tree)?;
        let final_paths = final_tree_paths(&self.state.cache, &diff);
        preflight(self.root(), &final_paths, &diff)?;
        let deleted: BTreeSet<&RepoPath> = diff
            .iter()
            .filter(|change| change.new.is_none())
            .map(|change| &change.path)
            .collect();
        for change in &diff {
            ensure_clean(&self.root, &self.state.cache, change, &deleted)?;
        }

        let mut stats = CheckoutStats {
            written: 0,
            removed: 0,
        };
        let mut cache = self.state.cache.clone();
        let mut removed_dirs: Vec<RepoPath> = Vec::new();

        let (deletes, writes) = split_diff(&diff);
        for change in &deletes {
            ensure_ancestors_safe(&self.root, &change.path, &BTreeSet::new())?;
            ensure_clean(&self.root, &self.state.cache, change, &BTreeSet::new())?;
            let disk = disk_path(&self.root, &change.path);
            remove_leaf(&disk)?;
            cache.remove(&change.path);
            removed_dirs.extend(ancestor_dirs(&change.path));
            stats.removed += 1;
        }
        remove_empty_dirs(&self.root, &removed_dirs);
        for change in &writes {
            let leaf = change.new.expect("writes have a new leaf");
            // Sealed and directory leaves are rejected in preflight.
            let bytes = repo.store().get_blob(&leaf.id())?;
            ensure_ancestors_safe(&self.root, &change.path, &BTreeSet::new())?;
            ensure_clean(&self.root, &self.state.cache, change, &BTreeSet::new())?;
            let dest = disk_path(&self.root, &change.path);
            if symlink_metadata_kind(&dest)? == Some(Shape::Dir) {
                // Preflight allowed only an empty directory. remove_dir
                // refuses if an untracked file appeared since that check.
                fs::remove_dir(&dest)?;
            }
            let stand_in = write_leaf(&self.root, &change.path, leaf, &bytes)?;
            let disk = disk_path(&self.root, &change.path);
            let meta = fs::symlink_metadata(&disk)?;
            let mtime = observed_mtime(&meta, self.now());
            cache.insert(
                change.path.clone(),
                FileState {
                    size: meta.len(),
                    mtime,
                    kind: leaf.kind(),
                    id: leaf.id(),
                    racy: false,
                    symlink_stand_in: stand_in,
                },
            );
            stats.written += 1;
        }
        remove_empty_dirs(&self.root, &removed_dirs);

        self.state.working = current;
        self.state.tree = new_tree;
        self.state.cache = cache;
        let now = self.now();
        mark_racy(&mut self.state.cache, now);
        self.save_state()?;
        Ok(stats)
    }

    /// Creates workspace `name` at `path`: a new empty change on `parent`,
    /// a `.tig` pointer at `path`, and a checkout of that change.
    ///
    /// `path` is the new workspace's directory. It is created when missing.
    /// The workspace shares `main`'s object store.
    pub fn add_workspace(
        repo: &mut Repo,
        main: &WorkingCopy,
        name: &str,
        path: &Path,
        parent: ObjectId,
    ) -> Result<WorkingCopy> {
        validate_workspace_name(name)?;
        ensure_metadata_dirs(&main.tig_dir)?;
        let workspace_dir = main.tig_dir.join("workspaces").join(name);
        if symlink_metadata_kind(&workspace_dir)?.is_some() {
            return Err(Error::Msg(format!(
                "workspace metadata for {name:?} already exists"
            )));
        }
        let path = canonicalize_creating(path)?;
        let pointer = path.join(".tig");
        if symlink_metadata_kind(&pointer)?.is_some() {
            return Err(Error::Msg(format!(
                "{} already exists",
                pointer.display()
            )));
        }
        // Creates the workspace and an empty change on `parent` in one operation.
        let created = Workspace::create(repo, name, parent)?;
        write_root_file(&main.tig_dir, name, &path)?;
        // One line: the absolute path of the main `.tig` directory.
        atomic_write(
            &pointer,
            format!("{}\n", main.tig_dir.display()).as_bytes(),
            true,
        )?;
        let mut wc = WorkingCopy {
            root: path,
            tig_dir: main.tig_dir.clone(),
            name: name.to_string(),
            // Disk is empty. The revision's tree is the parent's; checkout
            // diffs the empty tree onto it.
            state: WcState {
                working: created.working_revision(),
                tree: empty_tree_id(),
                cache: PathIndex::new(),
            },
            trusted: true,
            load_warning: None,
            clock: None,
        };
        wc.checkout(repo)?;
        Ok(wc)
    }

    fn now(&self) -> SystemTime {
        self.clock.unwrap_or_else(SystemTime::now)
    }

    fn save_state(&self) -> Result<()> {
        let dir = self.tig_dir.join("workspaces").join(&self.name);
        ensure_metadata_dirs(&self.tig_dir)?;
        ensure_real_directory(&dir)?;
        atomic_write(&dir.join("state"), &encode_state(&self.state), true)?;
        Ok(())
    }

    /// One directory walk. Hashes a file only when the stat cache cannot
    /// prove it is unchanged.
    fn scan(
        &self,
        repo: &Repo,
        ws: &mut Workspace,
        warnings: &mut Vec<String>,
    ) -> Result<(SnapshotStats, PathIndex<FileState>)> {
        let mut stats = SnapshotStats {
            scanned: 0,
            hashed: 0,
            changed: 0,
            warnings: Vec::new(),
        };
        let mut cache = PathIndex::new();
        let mut seen: BTreeSet<RepoPath> = BTreeSet::new();

        for ent in walk_worktree(&self.root) {
            let ent = ent.map_err(|e| {
                Error::Msg(format!("walking {}: {e}", self.root.display()))
            })?;
            if ent.depth() == 0 {
                continue;
            }
            if let Some(err) = ent.error() {
                warnings.push(format!(
                    "ignore rules near {}: {err}",
                    ent.path().display()
                ));
            }
            let rel = match ent.path().strip_prefix(&self.root) {
                Ok(rel) => rel,
                Err(_) => {
                    return Err(Error::Msg(format!(
                        "working-copy walk left {}: {}",
                        self.root.display(),
                        ent.path().display()
                    )));
                }
            };
            if ent.path_is_symlink() {
                // Recorded below as a symlink. Do not descend: the walker
                // was built with `follow_links(false)`.
            } else if ent.file_type().is_some_and(|t| t.is_dir()) {
                continue;
            } else if !ent.file_type().is_some_and(|t| t.is_file()) {
                warnings.push(format!(
                    "skipping special file {}",
                    ent.path().display()
                ));
                continue;
            }

            stats.scanned += 1;
            let Some(text) = rel_to_string(rel) else {
                warnings.push(format!(
                    "skipping {}: path is not valid UTF-8",
                    ent.path().display()
                ));
                continue;
            };
            let repo_path = match RepoPath::from_os_relative(&text) {
                Ok(path) => path,
                Err(e) => {
                    warnings.push(format!("skipping {text}: {e}"));
                    continue;
                }
            };
            #[cfg(windows)]
            if let Some(why) = path_name_block(&repo_path) {
                // Opening `aux.c` or `TIG~1` can hit a device or `.tig`.
                // Keep a cached row so a later snapshot does not delete it,
                // and do not read the file.
                warnings.push(format!("skipping {repo_path}: {why}"));
                if let Some(prev) = self.state.cache.get(&repo_path) {
                    cache.insert(repo_path.clone(), prev.clone());
                    seen.insert(repo_path);
                }
                continue;
            }

            let meta = ent.metadata().map_err(|e| {
                Error::Msg(format!("stat {}: {e}", ent.path().display()))
            })?;
            let shape = shape_of(&meta);
            if matches!(shape, Shape::Dir | Shape::Other) {
                warnings.push(format!(
                    "skipping special file {}",
                    ent.path().display()
                ));
                continue;
            }
            let size = meta.len();
            let mtime = observed_mtime(&meta, self.now());
            let mtime_known = mtime_parts(&meta).is_some();
            let prev = if self.trusted {
                self.state.cache.get(&repo_path).cloned()
            } else {
                None
            };

            if let Some(prev) = prev.as_ref() {
                if self.trusted
                    && mtime_known
                    && !prev.racy
                    && prev.size == size
                    && prev.mtime == mtime
                    && shape_agrees(prev, shape)
                {
                    let (kind, stand_in) = desired_kind(&meta, shape, Some(prev));
                    let mut row = prev.clone();
                    if kind != row.kind || stand_in != row.symlink_stand_in {
                        ws.set(
                            repo,
                            repo_path.clone(),
                            Some(leaf_of(kind, row.id)?),
                        )?;
                        row.kind = kind;
                        row.symlink_stand_in = stand_in;
                    }
                    cache.insert(repo_path.clone(), row);
                    seen.insert(repo_path);
                    continue;
                }
            }

            let bytes = read_shape(ent.path(), shape)?;
            let id = repo.store().put_blob(&bytes)?;
            stats.hashed += 1;
            let (kind, stand_in) = desired_kind(&meta, shape, prev.as_ref());
            let unchanged = self.trusted
                && prev
                    .as_ref()
                    .is_some_and(|row| row.id == id && row.kind == kind);
            if !unchanged {
                ws.set(repo, repo_path.clone(), Some(leaf_of(kind, id)?))?;
            }
            cache.insert(
                repo_path.clone(),
                FileState {
                    size,
                    mtime,
                    kind,
                    id,
                    racy: !mtime_known,
                    symlink_stand_in: stand_in,
                },
            );
            seen.insert(repo_path);
        }

        // The walker skips ignored paths. A path still on disk is not a
        // deletion: drop it only when it is gone. Tracked ignored files keep
        // their cache row so a later delete is still noticed.
        let mut absent: Vec<RepoPath> = Vec::new();
        if self.trusted {
            absent.extend(
                self.state
                    .cache
                    .iter()
                    .map(|(path, _)| path.clone())
                    .filter(|path| !seen.contains(path)),
            );
        } else {
            let base = repo.revision(&ws.working_revision())?.tree;
            absent.extend(
                walk(repo.store().as_ref(), &base, &RepoPath::root())?
                    .into_iter()
                    .map(|(path, _)| path)
                    .filter(|path| !seen.contains(path)),
            );
        }
        for path in absent {
            let disk = disk_path(&self.root, &path);
            match symlink_metadata_kind(&disk)? {
                None => ws.remove(repo, &path)?,
                Some(_) => {
                    if let Some(prev) = self.state.cache.get(&path) {
                        cache.insert(path, prev.clone());
                    }
                }
            }
        }

        Ok((stats, cache))
    }
}

// --- state file ------------------------------------------------------------

fn state_path(tig_dir: &Path, name: &str) -> PathBuf {
    tig_dir.join("workspaces").join(name).join("state")
}

fn load_state_file(path: &Path) -> Result<(WcState, bool, Option<String>)> {
    match fs::read(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok((
            WcState::blank(),
            false,
            Some("no workspace state file; re-scanning every file".into()),
        )),
        Err(e) => Err(e.into()),
        Ok(bytes) => match decode_state(&bytes) {
            Ok(state) => Ok((state, true, None)),
            Err(reason) => Ok((
                WcState::blank(),
                false,
                Some(format!(
                    "workspace state is corrupt ({reason}); re-scanning every file instead of trusting the stat cache"
                )),
            )),
        },
    }
}

fn encode_state(state: &WcState) -> Vec<u8> {
    let mut body = Writer::new();
    body.u8(STATE_VERSION);
    body.id(&state.working);
    body.id(&state.tree);
    let rows: Vec<_> = state
        .cache
        .iter()
        .map(|(path, row)| (path.clone(), row.clone()))
        .collect();
    body.varint(rows.len() as u64);
    for (path, row) in &rows {
        body.str(path.as_str());
        body.varint(row.size);
        body.ivarint(row.mtime.0);
        body.varint(u64::from(row.mtime.1));
        body.u8(kind_byte(row.kind));
        body.id(&row.id);
        let mut flags = 0u8;
        if row.racy {
            flags |= FLAG_RACY;
        }
        if row.symlink_stand_in {
            flags |= FLAG_STAND_IN;
        }
        body.u8(flags);
    }
    let mut out = Vec::with_capacity(4 + body.buf.len());
    out.extend_from_slice(STATE_MAGIC);
    out.extend_from_slice(&body.finish());
    out
}

fn decode_state(bytes: &[u8]) -> std::result::Result<WcState, String> {
    if bytes.len() < 5 || &bytes[..4] != STATE_MAGIC {
        return Err("bad magic; delete the state file and let tig re-scan".into());
    }
    let mut r = Reader::new(&bytes[4..], "workspace state");
    let version = r.u8().map_err(|e| e.to_string())?;
    if version != STATE_VERSION {
        return Err(format!(
            "unsupported version {version}; delete the state file and let tig re-scan"
        ));
    }
    let working = r.id().map_err(|e| e.to_string())?;
    let tree = r.id().map_err(|e| e.to_string())?;
    // Each row carries a 32-byte id, so a huge count cannot allocate forever.
    let n = r.count(32).map_err(|e| e.to_string())?;
    let mut rows = Vec::with_capacity(n);
    for _ in 0..n {
        let path = RepoPath::from_os_relative(r.str().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        if path.is_root() {
            return Err("cache row names the workspace root".into());
        }
        let size = r.varint().map_err(|e| e.to_string())?;
        let secs = r.ivarint().map_err(|e| e.to_string())?;
        let nanos = r.varint().map_err(|e| e.to_string())?;
        if nanos > 999_999_999 {
            return Err("mtime nanoseconds out of range".into());
        }
        let kind = kind_from_byte(r.u8().map_err(|e| e.to_string())?)?;
        let id = r.id().map_err(|e| e.to_string())?;
        let flags = r.u8().map_err(|e| e.to_string())?;
        if flags & !(FLAG_RACY | FLAG_STAND_IN) != 0 {
            return Err(format!("unknown state flags {flags}"));
        }
        if flags & FLAG_STAND_IN != 0 && kind != EntryKind::Symlink {
            return Err("stand-in flag on a non-symlink row".into());
        }
        rows.push((
            path,
            FileState {
                size,
                mtime: (secs, nanos as u32),
                kind,
                id,
                racy: flags & FLAG_RACY != 0,
                symlink_stand_in: flags & FLAG_STAND_IN != 0,
            },
        ));
    }
    r.finish().map_err(|e| e.to_string())?;
    let cache = PathIndex::from_sorted(rows).map_err(|e| e.to_string())?;
    Ok(WcState {
        working,
        tree,
        cache,
    })
}

fn kind_byte(kind: EntryKind) -> u8 {
    match kind {
        EntryKind::File => 1,
        EntryKind::Executable => 2,
        EntryKind::Symlink => 3,
        // The cache only stores file-like rows. A tree or seal here is a bug.
        EntryKind::Tree | EntryKind::Sealed => 0,
    }
}

fn kind_from_byte(b: u8) -> std::result::Result<EntryKind, String> {
    match b {
        1 => Ok(EntryKind::File),
        2 => Ok(EntryKind::Executable),
        3 => Ok(EntryKind::Symlink),
        _ => Err(format!("unknown file kind {b}")),
    }
}

fn leaf_of(kind: EntryKind, id: ObjectId) -> Result<Leaf> {
    match kind {
        EntryKind::File => Ok(Leaf::file(id)),
        EntryKind::Executable => Ok(Leaf::executable(id)),
        EntryKind::Symlink => Ok(Leaf::symlink(id)),
        EntryKind::Tree | EntryKind::Sealed => Err(Error::Msg(format!(
            "internal error: cache row has kind {kind:?}"
        ))),
    }
}

fn mark_racy(cache: &mut PathIndex<FileState>, now: SystemTime) {
    let cutoff = now.checked_sub(RACY_WINDOW);
    let rows: Vec<_> = cache
        .iter()
        .map(|(path, row)| (path.clone(), row.clone()))
        .collect();
    for (path, mut row) in rows {
        let racy = match system_time_from_parts(row.mtime) {
            Some(mtime) => match cutoff {
                Some(cutoff) => mtime >= cutoff,
                // `now` itself is within the window of the epoch.
                None => true,
            },
            None => true,
        };
        if row.racy != racy {
            row.racy = racy;
            cache.insert(path, row);
        }
    }
}

// --- checkout safety -------------------------------------------------------

fn final_tree_paths(cache: &PathIndex<FileState>, diff: &[DiffEntry]) -> BTreeSet<RepoPath> {
    let mut paths: BTreeSet<RepoPath> = cache.iter().map(|(path, _)| path.clone()).collect();
    for change in diff {
        if change.new.is_none() {
            paths.remove(&change.path);
        } else {
            paths.insert(change.path.clone());
        }
    }
    paths
}

fn split_diff(diff: &[DiffEntry]) -> (Vec<&DiffEntry>, Vec<&DiffEntry>) {
    let mut deletes = Vec::new();
    let mut writes = Vec::new();
    for change in diff {
        if change.new.is_none() {
            deletes.push(change);
        } else {
            writes.push(change);
        }
    }
    // Deeper paths first so a file is removed before its parent directory.
    deletes.sort_by_key(|change| std::cmp::Reverse(change.path.components().count()));
    (deletes, writes)
}

/// Refuses the checkout before any write.
fn preflight(root: &Path, paths: &BTreeSet<RepoPath>, diff: &[DiffEntry]) -> Result<()> {
    for change in diff {
        ensure_file_leaf(change.old.as_ref(), &change.path)?;
        ensure_file_leaf(change.new.as_ref(), &change.path)?;
    }
    #[cfg(windows)]
    {
        for path in paths.iter().chain(diff.iter().map(|change| &change.path)) {
            if let Some(why) = path_name_block(path) {
                return Err(Error::Msg(format!(
                    "refusing to check out {path}: {why}"
                )));
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = paths;
    }
    if volume_is_case_insensitive(root) {
        if let Some((a, b)) = case_collision(paths) {
            return Err(Error::Msg(format!(
                "refusing to check out {a} and {b}: case-insensitive collision"
            )));
        }
    }
    let deleted: BTreeSet<&RepoPath> = diff
        .iter()
        .filter(|change| change.new.is_none())
        .map(|change| &change.path)
        .collect();
    for change in diff {
        if change.new.is_some() {
            ensure_ancestors_safe(root, &change.path, &deleted)?;
        } else {
            ensure_ancestors_safe(root, &change.path, &BTreeSet::new())?;
        }
    }
    Ok(())
}

fn ensure_file_leaf(leaf: Option<&Leaf>, path: &RepoPath) -> Result<()> {
    if let Some(leaf) = leaf {
        if !matches!(
            leaf.kind(),
            EntryKind::File | EntryKind::Executable | EntryKind::Symlink
        ) {
            return Err(Error::Msg(format!(
                "refusing to check out {path}: {:?} entries are not files",
                leaf.kind()
            )));
        }
    }
    Ok(())
}

fn path_name_block(path: &RepoPath) -> Option<&'static str> {
    path.components().find_map(windows_name_block)
}

/// `Some(reason)` when `name` must not be created on Windows.
fn windows_name_block(name: &str) -> Option<&'static str> {
    if name.contains(['<', '>', '"', '|', '?', '*']) {
        Some("invalid Windows filename character")
    } else if name.encode_utf16().count() > 255 {
        Some("Windows filename exceeds 255 UTF-16 units")
    } else if is_windows_device(name) {
        Some("Windows device name")
    } else if is_tig_short_name(name) {
        Some("NTFS 8.3 alias of .tig")
    } else {
        None
    }
}

/// `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`, `LPT1`–`LPT9`, the superscript
/// forms `COM¹`–`COM³` and `LPT¹`–`LPT³`, in any case, with or without an
/// extension (`aux.c`, `NUL.tar.gz`).
fn is_windows_device(name: &str) -> bool {
    let stem = match name.split_once('.') {
        Some((stem, _)) => stem,
        None => name,
    };
    if stem.is_empty() {
        return false;
    }
    let folded = fold_device(stem);
    matches!(folded.as_str(), "con" | "prn" | "aux" | "nul" | "conin$" | "conout$")
        || is_com_or_lpt(&folded)
}

fn is_com_or_lpt(folded: &str) -> bool {
    let rest = folded
        .strip_prefix("com")
        .or_else(|| folded.strip_prefix("lpt"));
    match rest {
        Some(n) if n.len() == 1 => matches!(n.as_bytes(), [b'1'..=b'9']),
        _ => false,
    }
}

/// Maps ASCII case and the superscript digits Windows treats as `1`, `2`, `3`.
fn fold_device(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        let mapped = match c {
            '\u{00B9}' => '1',
            '\u{00B2}' => '2',
            '\u{00B3}' => '3',
            other => other,
        };
        for lower in mapped.to_lowercase() {
            out.push(lower);
        }
    }
    out
}

/// NTFS generates `TIG~1` as the 8.3 short name of `.tig` (git rejects
/// `GIT~1` for the same reason). Also `TIG~2` and longer numeric tails,
/// which NTFS uses once `~1` is taken. Trailing dots and spaces are
/// ignored by NTFS; the path policy already rejects those, and we trim
/// them here so a hand-built tree still cannot sneak one through.
fn is_tig_short_name(name: &str) -> bool {
    let folded = fold_device(name);
    let trimmed = folded.trim_end_matches(&[' ', '.'][..]);
    let Some(rest) = trimmed.strip_prefix("tig~") else {
        return false;
    };
    let bytes = rest.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 6
        && bytes.iter().all(|b| b.is_ascii_digit())
        && bytes[0] != b'0'
}

fn case_collision(paths: &BTreeSet<RepoPath>) -> Option<(String, String)> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for path in paths {
        let mut prefix = String::new();
        for (i, component) in path.components().enumerate() {
            if i > 0 {
                prefix.push('/');
            }
            prefix.push_str(component);
            let key = fold_device(&prefix);
            if let Some(prev) = seen.get(&key) {
                if prev != &prefix {
                    return Some((prev.clone(), prefix));
                }
            } else {
                seen.insert(key, prefix.clone());
            }
        }
    }
    None
}

/// `true` when `root/.tig` and `root/.TIG` are the same file. That is the
/// case-insensitive probe: on a sensitive volume the flipped name is absent.
fn volume_is_case_insensitive(root: &Path) -> bool {
    let orig = root.join(".tig");
    let flipped = root.join(".TIG");
    match (fs::symlink_metadata(&orig), fs::symlink_metadata(&flipped)) {
        (Ok(a), Ok(b)) => same_file(&a, &b),
        _ => false,
    }
}

/// Both names already resolved. On Unix, confirm they are one inode. On
/// Windows the file-id APIs are still unstable; a case-sensitive volume
/// would not have resolved the flipped name, so both hits are enough.
#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(_a: &fs::Metadata, _b: &fs::Metadata) -> bool {
    true
}

/// An ancestor that is a symlink or reparse point would make a later create
/// write outside the workspace. An ancestor we are about to delete is fine:
/// the delete runs first, and the write creates a real directory.
fn ensure_ancestors_safe(
    root: &Path,
    rel: &RepoPath,
    deleted: &BTreeSet<&RepoPath>,
) -> Result<()> {
    ensure_canonical_directory(root)?;
    let mut cur = root.to_path_buf();
    let mut at = RepoPath::root();
    let parts: Vec<&str> = rel.components().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    for name in &parts[..parts.len() - 1] {
        at = at.join(name)?;
        cur.push(name);
        match fs::symlink_metadata(&cur) {
            Ok(meta) if is_link_or_reparse(&meta) => {
                if !deleted.contains(&at) {
                    return Err(Error::Msg(format!(
                        "refusing to write through symlink or reparse point {}",
                        cur.display()
                    )));
                }
            }
            Ok(meta) if meta.is_dir() => ensure_not_metadata_alias(&cur)?,
            Ok(_) => {
                if !deleted.contains(&at) {
                    return Err(Error::Msg(format!(
                        "refusing to check out {}: {} is not a directory",
                        rel,
                        cur.display()
                    )));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

/// Compares the file checkout is about to overwrite or delete with the tree
/// snapshot. Every affected file is hashed: restored mtimes cannot prove its
/// contents are safe to destroy. Content that already equals the blob we
/// would write is allowed, so a checkout that stopped halfway can be retried.
fn ensure_clean(
    root: &Path,
    cache: &PathIndex<FileState>,
    change: &DiffEntry,
    deleted: &BTreeSet<&RepoPath>,
) -> Result<()> {
    let disk = disk_path(root, &change.path);
    let meta = match fs::symlink_metadata(&disk) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if change.old.is_some() && change.new.is_some() {
                return Err(dirty(
                    &change.path,
                    "deleted on disk since the last snapshot",
                ));
            }
            // Already absent, and this checkout deletes it. Or it is a new
            // file and nothing is in the way.
            return Ok(());
        }
        Err(e) => return Err(e.into()),
    };
    let shape = shape_of(&meta);
    if shape != Shape::Symlink {
        ensure_not_metadata_alias(&disk)?;
    }
    if shape == Shape::Dir && change.old.is_none() && change.new.is_some() {
        if directory_is_removed(root, &change.path, deleted)? {
            return Ok(());
        }
    }
    if matches!(shape, Shape::Dir | Shape::Other) {
        return Err(dirty(
            &change.path,
            "changed on disk since the last snapshot",
        ));
    }
    let bytes = read_shape(&disk, shape)?;
    let id = hash_object(ObjectKind::Blob, &bytes);
    if let Some(leaf) = change.old {
        let (kind, _) = desired_kind(&meta, shape, cache.get(&change.path));
        if leaf.id() == id && leaf.kind() == kind && leaf_matches_shape(leaf, shape) {
            return Ok(());
        }
    }
    if let Some(leaf) = change.new {
        if leaf.id() == id && leaf_matches_shape(leaf, shape) {
            return Ok(());
        }
    }
    Err(dirty(
        &change.path,
        "changed on disk since the last snapshot",
    ))
}

/// Every leaf in a directory replacement must be a scheduled deletion.
/// Extra empty subdirectories are also preserved rather than removed.
fn directory_is_removed(
    root: &Path,
    rel: &RepoPath,
    deleted: &BTreeSet<&RepoPath>,
) -> Result<bool> {
    let mut pending = vec![rel.clone()];
    while let Some(dir) = pending.pop() {
        let mut empty = true;
        for ent in fs::read_dir(disk_path(root, &dir))? {
            empty = false;
            let ent = ent?;
            let Some(name) = ent.file_name().to_str().map(str::to_owned) else {
                return Ok(false);
            };
            let child = dir.join(&name)?;
            let meta = fs::symlink_metadata(ent.path())?;
            if meta.is_dir() && !is_link_or_reparse(&meta) {
                pending.push(child);
            } else if !deleted.contains(&child) {
                return Ok(false);
            }
        }
        if empty && dir != *rel {
            return Ok(false);
        }
    }
    Ok(true)
}

fn dirty(path: &RepoPath, why: &str) -> Error {
    Error::Msg(format!("refusing to check out {path}: it {why}"))
}

fn leaf_matches_shape(leaf: Leaf, shape: Shape) -> bool {
    match shape {
        Shape::Symlink => leaf.kind() == EntryKind::Symlink,
        Shape::File => matches!(
            leaf.kind(),
            EntryKind::File | EntryKind::Executable | EntryKind::Symlink
        ),
        Shape::Dir | Shape::Other => false,
    }
}

// --- disk kinds ------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    File,
    Symlink,
    Dir,
    Other,
}

fn shape_of(meta: &fs::Metadata) -> Shape {
    if is_link_or_reparse(meta) {
        Shape::Symlink
    } else if meta.is_dir() {
        Shape::Dir
    } else if meta.is_file() {
        Shape::File
    } else {
        Shape::Other
    }
}

fn shape_agrees(row: &FileState, shape: Shape) -> bool {
    match shape {
        Shape::Symlink => row.kind == EntryKind::Symlink && !row.symlink_stand_in,
        Shape::File => {
            if row.symlink_stand_in {
                row.kind == EntryKind::Symlink
            } else {
                matches!(row.kind, EntryKind::File | EntryKind::Executable)
            }
        }
        Shape::Dir | Shape::Other => false,
    }
}

/// Kind to record for `meta`. On Windows an executable stays executable,
/// and a symlink stand-in stays a symlink, including after the bytes change:
/// the disk has no other way to say which it was.
fn desired_kind(meta: &fs::Metadata, shape: Shape, prev: Option<&FileState>) -> (EntryKind, bool) {
    match shape {
        Shape::Symlink => (EntryKind::Symlink, false),
        Shape::File => {
            if let Some(prev) = prev {
                if prev.symlink_stand_in && prev.kind == EntryKind::Symlink {
                    return (EntryKind::Symlink, true);
                }
            }
            #[cfg(unix)]
            {
                let kind = if unix_executable(meta) {
                    EntryKind::Executable
                } else {
                    EntryKind::File
                };
                (kind, false)
            }
            #[cfg(not(unix))]
            {
                let _ = meta;
                if let Some(prev) = prev {
                    if matches!(prev.kind, EntryKind::File | EntryKind::Executable) {
                        return (prev.kind, false);
                    }
                }
                (EntryKind::File, false)
            }
        }
        Shape::Dir | Shape::Other => (EntryKind::File, false),
    }
}

fn is_link_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(unix)]
fn unix_executable(meta: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o111 != 0
}

fn read_shape(path: &Path, shape: Shape) -> io::Result<Vec<u8>> {
    match shape {
        Shape::Symlink => read_symlink_bytes(path),
        Shape::File => {
            let mut file = OpenOptions::new().read(true).open(path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            Ok(buf)
        }
        Shape::Dir | Shape::Other => Err(io::Error::other(format!(
            "{} is not a file",
            path.display()
        ))),
    }
}

fn read_symlink_bytes(path: &Path) -> io::Result<Vec<u8>> {
    let target = fs::read_link(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(target.as_os_str().as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        // Windows symlink targets are Unicode. Lossy conversion is the
        // stand-in when a target is not valid Unicode; checkout writes the
        // original blob bytes back, so a round trip of a UTF-8 target is exact.
        Ok(target.to_string_lossy().into_owned().into_bytes())
    }
}

/// Writes `leaf` at `rel`. Returns whether the symlink was stored as a
/// regular file (Windows stand-in).
fn write_leaf(root: &Path, rel: &RepoPath, leaf: Leaf, bytes: &[u8]) -> Result<bool> {
    prepare_parent(root, rel)?;
    let dest = disk_path(root, rel);
    // Reduce the race window by re-checking just before writing. Path-based
    // std APIs cannot make this check and the following mutation atomic.
    ensure_ancestors_real(root, rel)?;
    match leaf.kind() {
        EntryKind::Symlink => write_symlink(&dest, bytes),
        EntryKind::File | EntryKind::Executable => {
            atomic_write(&dest, bytes, false)?;
            #[cfg(unix)]
            set_unix_mode(&dest, leaf.kind() == EntryKind::Executable)?;
            Ok(false)
        }
        EntryKind::Tree | EntryKind::Sealed => Err(Error::Msg(format!(
            "refusing to check out {rel}: {:?} is not a file",
            leaf.kind()
        ))),
    }
}

fn write_symlink(dest: &Path, bytes: &[u8]) -> Result<bool> {
    if symlink_metadata_kind(dest)?.is_some() {
        remove_leaf(dest)?;
    }
    match os_symlink(bytes, dest) {
        Ok(()) => Ok(false),
        #[cfg(windows)]
        Err(_) => {
            // No privilege (or the target is not valid Unicode). The file
            // contents are the target text; the stat cache remembers that.
            atomic_write(dest, bytes, false)?;
            Ok(true)
        }
        #[cfg(not(windows))]
        Err(e) => Err(e.into()),
    }
}

#[cfg(unix)]
fn os_symlink(bytes: &[u8], dest: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let target = OsStr::from_bytes(bytes);
    std::os::unix::fs::symlink(target, dest)
}

#[cfg(windows)]
fn os_symlink(bytes: &[u8], dest: &Path) -> io::Result<()> {
    let text = std::str::from_utf8(bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "symlink target is not utf-8",
        )
    })?;
    std::os::windows::fs::symlink_file(text, dest)
}

#[cfg(not(any(unix, windows)))]
fn os_symlink(_bytes: &[u8], dest: &Path) -> io::Result<()> {
    Err(io::Error::other(format!(
        "symlinks are not supported; cannot create {}",
        dest.display()
    )))
}

#[cfg(unix)]
fn set_unix_mode(path: &Path, executable: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = if executable { 0o755 } else { 0o644 };
    let mut perms = fs::symlink_metadata(path)?.permissions();
    perms.set_mode(mode);
    fs::set_permissions(path, perms)
}

/// Creates parent directories one level at a time. `create_dir_all` would
/// follow a symlink ancestor; this checks each level with `symlink_metadata`
/// first.
fn prepare_parent(root: &Path, rel: &RepoPath) -> Result<()> {
    let mut cur = root.to_path_buf();
    let parts: Vec<&str> = rel.components().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    for name in &parts[..parts.len() - 1] {
        cur.push(name);
        match fs::symlink_metadata(&cur) {
            Ok(meta) if is_link_or_reparse(&meta) => {
                return Err(Error::Msg(format!(
                    "refusing to write through symlink or reparse point {}",
                    cur.display()
                )));
            }
            Ok(meta) if meta.is_dir() => ensure_not_metadata_alias(&cur)?,
            Ok(_) => {
                return Err(Error::Msg(format!(
                    "refusing to check out {rel}: {} is not a directory",
                    cur.display()
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                fs::create_dir(&cur)?;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn ensure_ancestors_real(root: &Path, rel: &RepoPath) -> Result<()> {
    let mut cur = root.to_path_buf();
    let parts: Vec<&str> = rel.components().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    for name in &parts[..parts.len() - 1] {
        cur.push(name);
        match fs::symlink_metadata(&cur) {
            Ok(meta) if is_link_or_reparse(&meta) => {
                return Err(Error::Msg(format!(
                    "refusing to write through symlink or reparse point {}",
                    cur.display()
                )));
            }
            Ok(meta) if meta.is_dir() => ensure_not_metadata_alias(&cur)?,
            Ok(_) => {
                return Err(Error::Msg(format!(
                    "refusing to check out {rel}: {} is not a directory",
                    cur.display()
                )));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(Error::Msg(format!(
                    "refusing to check out {rel}: {} disappeared",
                    cur.display()
                )));
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn remove_leaf(path: &Path) -> io::Result<()> {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    if meta.is_dir() && !is_link_or_reparse(&meta) {
        return Err(io::Error::other(format!(
            "refusing to delete directory {} while removing a file",
            path.display()
        )));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileTypeExt;
        if meta.file_type().is_symlink_dir() {
            return fs::remove_dir(path);
        }
    }
    fs::remove_file(path)
}

fn remove_empty_dirs(root: &Path, dirs: &[RepoPath]) {
    let mut dirs = dirs.to_vec();
    dirs.sort();
    dirs.dedup();
    dirs.sort_by_key(|dir| std::cmp::Reverse(dir.components().count()));
    for dir in dirs {
        if dir.is_root() {
            continue;
        }
        if ensure_ancestors_safe(root, &dir, &BTreeSet::new()).is_err() {
            continue;
        }
        let path = disk_path(root, &dir);
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.is_dir() && !is_link_or_reparse(&meta) {
            // Not empty, or not a directory we own: leave it.
            let _ = fs::remove_dir(&path);
        }
    }
}

fn ancestor_dirs(path: &RepoPath) -> Vec<RepoPath> {
    let mut out = Vec::new();
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if dir.is_root() {
            break;
        }
        out.push(dir.clone());
        cur = dir.parent();
    }
    out
}

// --- paths and atomic writes ----------------------------------------------

fn disk_path(root: &Path, rel: &RepoPath) -> PathBuf {
    let mut out = root.to_path_buf();
    for component in rel.components() {
        out.push(component);
    }
    out
}

fn rel_to_string(rel: &Path) -> Option<String> {
    let mut text = String::new();
    for (i, component) in rel.components().enumerate() {
        let std::path::Component::Normal(name) = component else {
            return None;
        };
        let part = name.to_str()?;
        if i > 0 {
            text.push('/');
        }
        text.push_str(part);
    }
    Some(text)
}

fn walk_worktree(root: &Path) -> ignore::Walk {
    // `.tigignore` uses gitignore syntax and outranks `.gitignore`.
    // Global git excludes and `.ignore` files are off. Hidden files stay
    // visible so `.env` is part of the working copy. Symlinks are not followed.
    // `require_git(false)` applies `.gitignore` even though there is no `.git`.
    WalkBuilder::new(root)
        .standard_filters(false)
        .hidden(false)
        .ignore(false)
        .git_global(false)
        .git_exclude(false)
        .git_ignore(true)
        .require_git(false)
        .parents(false)
        .follow_links(false)
        .add_custom_ignore_filename(".tigignore")
        .filter_entry(|ent| {
            let name = ent.file_name();
            name != OsStr::new(".tig") && !is_scratch_name(name)
        })
        .build()
}

fn is_scratch_name(name: &OsStr) -> bool {
    name.to_str()
        .and_then(|text| text.strip_prefix(".tig-tmp-"))
        .is_some_and(|suffix| {
            suffix.len() == 16 && suffix.bytes().all(|b| b.is_ascii_hexdigit())
        })
}

struct RemoveOnDrop(PathBuf);

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Writes `bytes` to `dest` by creating a new temp file in the same directory
/// and renaming it over `dest`. `sync` fsyncs first; working-tree files skip
/// that (one fsync per file would dominate checkout).
fn atomic_write(dest: &Path, bytes: &[u8], sync: bool) -> io::Result<()> {
    let parent = dest.parent().ok_or_else(|| {
        io::Error::other(format!("{} has no parent directory", dest.display()))
    })?;
    let (tmp, mut file) = create_temp(parent)?;
    let guard = RemoveOnDrop(tmp.clone());
    file.write_all(bytes)?;
    if sync {
        file.sync_all()?;
    }
    // Windows will not rename a file that still has an open handle.
    drop(file);
    rename_replacing(&tmp, dest)?;
    drop(guard);
    Ok(())
}

fn create_temp(dir: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..8 {
        let mut rnd = [0u8; 8];
        getrandom::getrandom(&mut rnd)
            .map_err(|e| io::Error::other(format!("no randomness: {e}")))?;
        let path = dir.join(format!(".tig-tmp-{}", hex::encode(rnd)));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("could not create a temp file"))
}

fn rename_replacing(from: &Path, to: &Path) -> io::Result<()> {
    if let Err(e) = fs::rename(from, to) {
        // A just-closed temp can fail the first rename on Windows. Retry,
        // but never unlink the destination: failure must preserve its bytes.
        let mut last = e;
        for attempt in 0..4 {
            match fs::rename(from, to) {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
            std::thread::sleep(Duration::from_millis(1 << attempt));
        }
        return Err(last);
    }
    Ok(())
}

fn symlink_metadata_kind(path: &Path) -> io::Result<Option<Shape>> {
    match fs::symlink_metadata(path) {
        Ok(meta) => Ok(Some(shape_of(&meta))),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn canonicalize_creating(path: &Path) -> Result<PathBuf> {
    fs::create_dir_all(path)?;
    Ok(fs::canonicalize(path)?)
}

fn starting_dir(start: &Path) -> Result<PathBuf> {
    let meta = fs::symlink_metadata(start).map_err(|e| {
        Error::Msg(format!("cannot open {}: {e}", start.display()))
    })?;
    let dir = if meta.is_dir() && !is_link_or_reparse(&meta) {
        start.to_path_buf()
    } else {
        start.parent().map(Path::to_path_buf).ok_or_else(|| {
            Error::Msg(format!("{} has no parent directory", start.display()))
        })?
    };
    Ok(fs::canonicalize(&dir)?)
}

/// `(workspace root, main .tig directory)`.
fn find_tig(start_dir: &Path) -> Result<(PathBuf, PathBuf)> {
    let mut dir = start_dir.to_path_buf();
    loop {
        let candidate = dir.join(".tig");
        match fs::symlink_metadata(&candidate) {
            Ok(meta) if is_link_or_reparse(&meta) => {
                return Err(Error::Msg(format!(
                    "refusing linked metadata {}",
                    candidate.display()
                )));
            }
            Ok(meta) if meta.is_dir() => return Ok((dir, candidate)),
            Ok(meta) if meta.is_file() => {
                let text = fs::read_to_string(&candidate)?;
                let target = PathBuf::from(text.trim());
                if !target.is_absolute() {
                    return Err(Error::Msg(format!(
                        "{} must point at an absolute tig directory",
                        candidate.display()
                    )));
                }
                let tig = fs::canonicalize(&target).map_err(|e| {
                    Error::Msg(format!(
                        "{} points at {}, which cannot be opened: {e}",
                        candidate.display(),
                        target.display()
                    ))
                })?;
                let tig_meta = fs::symlink_metadata(&tig)?;
                if !tig_meta.is_dir() || is_link_or_reparse(&tig_meta) {
                    return Err(Error::Msg(format!(
                        "{} does not point at a tig directory",
                        candidate.display()
                    )));
                }
                return Ok((dir, tig));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        match dir.parent() {
            Some(parent) if parent != dir => dir = parent.to_path_buf(),
            _ => break,
        }
    }
    Err(Error::Msg(format!(
        "no .tig directory found from {}",
        start_dir.display()
    )))
}

fn workspace_name_for(tig_dir: &Path, root: &Path) -> Result<String> {
    let ws_dir = tig_dir.join("workspaces");
    let root = fs::canonicalize(root)?;
    let mut found: Option<String> = None;
    let entries = fs::read_dir(&ws_dir).map_err(|e| {
        Error::Msg(format!("cannot read {}: {e}", ws_dir.display()))
    })?;
    for ent in entries {
        let ent = ent?;
        let file_type = ent.file_type()?;
        if !file_type.is_dir() || file_type.is_symlink() {
            continue;
        }
        ensure_real_directory(&ent.path())?;
        let root_file = ent.path().join("root");
        let Ok(text) = fs::read_to_string(&root_file) else {
            continue;
        };
        let recorded = PathBuf::from(text.trim());
        let Ok(recorded) = fs::canonicalize(&recorded) else {
            continue;
        };
        if recorded == root {
            let name = ent.file_name().into_string().map_err(|_| {
                Error::Msg(format!(
                    "workspace directory {} is not valid UTF-8",
                    ent.path().display()
                ))
            })?;
            validate_workspace_name(&name)?;
            if found.replace(name).is_some() {
                return Err(Error::Msg(format!(
                    "several workspaces claim {}",
                    root.display()
                )));
            }
        }
    }
    found.ok_or_else(|| {
        Error::Msg(format!(
            "no workspace in {} records its root as {}",
            ws_dir.display(),
            root.display()
        ))
    })
}

fn write_root_file(tig_dir: &Path, name: &str, workspace_root: &Path) -> Result<()> {
    let dir = tig_dir.join("workspaces").join(name);
    ensure_real_directory(tig_dir)?;
    ensure_real_directory(&tig_dir.join("workspaces"))?;
    if symlink_metadata_kind(&dir)?.is_none() {
        fs::create_dir(&dir)?;
    }
    ensure_real_directory(&dir)?;
    let body = format!("{}\n", workspace_root.display());
    atomic_write(&dir.join("root"), body.as_bytes(), true)?;
    Ok(())
}

fn validate_workspace_name(name: &str) -> Result<()> {
    tig_core::object::validate_name(name)?;
    if let Some(why) = windows_name_block(name) {
        return Err(Error::Msg(format!(
            "invalid workspace name {name:?}: {why}"
        )));
    }
    Ok(())
}

fn ensure_real_directory(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.is_dir() || is_link_or_reparse(&meta) {
        return Err(Error::Msg(format!(
            "{} is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

fn ensure_canonical_directory(path: &Path) -> Result<()> {
    ensure_real_directory(path)?;
    if fs::canonicalize(path)? != path {
        return Err(Error::Msg(format!(
            "refusing redirected directory {}",
            path.display()
        )));
    }
    Ok(())
}

/// Numeric and hashed 8.3 names can both resolve to repository metadata.
fn ensure_not_metadata_alias(path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        let resolved = fs::canonicalize(path)?;
        if resolved.file_name().and_then(OsStr::to_str)
            .is_some_and(|name| name.eq_ignore_ascii_case(".tig"))
        {
            return Err(Error::Msg(format!(
                "refusing metadata alias {}",
                path.display()
            )));
        }
    }
    #[cfg(not(windows))]
    let _ = path;
    Ok(())
}

fn ensure_metadata_dirs(tig_dir: &Path) -> Result<()> {
    ensure_canonical_directory(tig_dir)?;
    ensure_real_directory(&tig_dir.join("workspaces"))?;
    ensure_real_directory(&tig_dir.join("store"))?;
    ensure_real_directory(&tig_dir.join("store").join("tmp"))
}

fn mtime_parts(meta: &fs::Metadata) -> Option<(i64, u32)> {
    system_time_parts(meta.modified().ok()?)
}

fn observed_mtime(meta: &fs::Metadata, now: SystemTime) -> (i64, u32) {
    mtime_parts(meta)
        .or_else(|| system_time_parts(now))
        .unwrap_or((0, 0))
}

fn system_time_parts(t: SystemTime) -> Option<(i64, u32)> {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => {
            let secs = i64::try_from(d.as_secs()).ok()?;
            Some((secs, d.subsec_nanos()))
        }
        Err(e) => {
            let d = e.duration();
            let secs = i64::try_from(d.as_secs()).ok()?;
            let nanos = d.subsec_nanos();
            if nanos == 0 {
                Some((-secs, 0))
            } else {
                Some((
                    secs.checked_neg()?.checked_sub(1)?,
                    1_000_000_000 - nanos,
                ))
            }
        }
    }
}

fn system_time_from_parts(mtime: (i64, u32)) -> Option<SystemTime> {
    if mtime.1 >= 1_000_000_000 {
        return None;
    }
    if mtime.0 >= 0 {
        UNIX_EPOCH.checked_add(Duration::new(mtime.0 as u64, mtime.1))
    } else if mtime.1 == 0 {
        UNIX_EPOCH.checked_sub(Duration::new(mtime.0.checked_neg()? as u64, 0))
    } else {
        let secs = mtime.0.checked_neg()?.checked_sub(1)?;
        UNIX_EPOCH.checked_sub(Duration::new(secs as u64, 1_000_000_000 - mtime.1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rp(text: &str) -> RepoPath {
        RepoPath::new(text).unwrap()
    }

    #[test]
    fn device_names_cover_extensions_and_superscripts() {
        for name in [
            "aux",
            "AUX",
            "aux.c",
            "AuX.C",
            "NUL.txt",
            "NUL.tar.gz",
            "CON",
            "prn",
            "COM1",
            "com9.txt",
            "lpt1",
            "LPT9.dat",
            "COM\u{00B9}",
            "com\u{00B2}.txt",
            "LPT\u{00B3}",
            "conin$",
            "CONOUT$",
        ] {
            assert!(is_windows_device(name), "{name} should be reserved");
        }
        for name in [".env", "commit", "combo", "COM0", "COM10", "auxillary", "readme"] {
            assert!(!is_windows_device(name), "{name} should be allowed");
        }
    }

    #[test]
    fn short_names_of_tig_are_blocked() {
        for name in ["TIG~1", "tig~1", "Tig~2", "tig~10", "TIG~1.", "tig~1 "] {
            assert!(is_tig_short_name(name), "{name}");
        }
        for name in [".tig", "tig", "TIG~0", "TIG~1.txt", "GIT~1", "not~1"] {
            assert!(!is_tig_short_name(name), "{name}");
        }
    }

    #[test]
    fn case_collision_finds_files_and_prefixes() {
        let mut paths = BTreeSet::new();
        paths.insert(rp("A"));
        paths.insert(rp("a"));
        assert!(case_collision(&paths).is_some());

        let mut paths = BTreeSet::new();
        paths.insert(rp("Foo"));
        paths.insert(rp("foo/bar"));
        assert!(case_collision(&paths).is_some());

        let mut paths = BTreeSet::new();
        paths.insert(rp("a.txt"));
        paths.insert(rp("a/b"));
        paths.insert(rp("readme"));
        assert!(case_collision(&paths).is_none());
    }

    #[test]
    fn state_roundtrip_preserves_rows() {
        let mut cache = PathIndex::new();
        cache.insert(
            rp("dir/a.txt"),
            FileState {
                size: 3,
                mtime: (1_700_000_000, 12),
                kind: EntryKind::Executable,
                id: ObjectId([7; 32]),
                racy: true,
                symlink_stand_in: false,
            },
        );
        cache.insert(
            rp("link"),
            FileState {
                size: 4,
                mtime: (-5, 10),
                kind: EntryKind::Symlink,
                id: ObjectId([9; 32]),
                racy: false,
                symlink_stand_in: true,
            },
        );
        let state = WcState {
            working: ObjectId([1; 32]),
            tree: ObjectId([2; 32]),
            cache,
        };
        let decoded = decode_state(&encode_state(&state)).unwrap();
        assert_eq!(decoded.working, state.working);
        assert_eq!(decoded.tree, state.tree);
        let rows: Vec<_> = decoded
            .cache
            .iter()
            .map(|(p, row)| (p.as_str().to_string(), row.clone()))
            .collect();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].0, "dir/a.txt");
        assert!(rows[0].1.racy);
        assert_eq!(rows[0].1.kind, EntryKind::Executable);
        assert!(rows[1].1.symlink_stand_in);
        assert_eq!(rows[1].1.mtime, (-5, 10));
    }

    #[test]
    fn corrupt_state_is_rejected() {
        assert!(decode_state(b"nope").is_err());
        assert!(decode_state(b"TIGW\x02").is_err());
    }

    #[test]
    fn failed_rename_preserves_destination() {
        let dir = tempfile::tempdir().unwrap();
        let dest = dir.path().join("state");
        fs::write(&dest, b"previous state").unwrap();
        assert!(rename_replacing(&dir.path().join("missing"), &dest).is_err());
        assert_eq!(fs::read(&dest).unwrap(), b"previous state");
    }

    #[test]
    fn extreme_state_timestamp_does_not_panic() {
        assert!(system_time_from_parts((i64::MIN, 0)).is_none());
    }

    #[test]
    #[ignore = "Decision required: the state format has no integrity checksum"]
    fn syntactically_valid_state_corruption_is_rejected() {
        let mut cache = PathIndex::new();
        cache.insert(
            rp("work.txt"),
            FileState {
                size: 5,
                mtime: (1_700_000_000, 0),
                kind: EntryKind::File,
                id: ObjectId([7; 32]),
                racy: true,
                symlink_stand_in: false,
            },
        );
        let state = WcState {
            working: ObjectId([1; 32]),
            tree: ObjectId([2; 32]),
            cache,
        };
        let mut bytes = encode_state(&state);
        // A single flipped racy bit is still a valid encoding.
        *bytes.last_mut().unwrap() ^= FLAG_RACY;
        assert!(decode_state(&bytes).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn preflight_blocks_unsafe_deleted_paths() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join(".tig")).unwrap();
        let diff = vec![DiffEntry {
            path: rp("TIG~1/file"),
            old: Some(Leaf::file(ObjectId([7; 32]))),
            new: None,
        }];
        assert!(preflight(&fs::canonicalize(dir.path()).unwrap(), &BTreeSet::new(), &diff).is_err());
    }

    #[test]
    fn state_rejects_root_rows_and_invalid_stand_ins() {
        for (path, stand_in) in [(RepoPath::root(), false), (rp("work.txt"), true)] {
            let mut cache = PathIndex::new();
            cache.insert(
                path,
                FileState {
                    size: 5,
                    mtime: (0, 0),
                    kind: EntryKind::File,
                    id: ObjectId([7; 32]),
                    racy: true,
                    symlink_stand_in: stand_in,
                },
            );
            let state = WcState {
                working: ObjectId([1; 32]),
                tree: ObjectId([2; 32]),
                cache,
            };
            assert!(decode_state(&encode_state(&state)).is_err());
        }
    }
}
