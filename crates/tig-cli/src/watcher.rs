//! Native filesystem events and durable hints for one workspace.
//! Events select file paths; uncertain structure, overflow and backend loss
//! require a full rehash. Normal commands always retain the full walk.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use notify::event::{CreateKind, DataChange, Flag, ModifyKind, RemoveKind, RenameMode};
use notify::{Event, EventHandler, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

/// Cap on relative paths stored in the durable hint file.
pub const MAX_DIRTY_PATHS: usize = 4096;

/// Default live-event queue length. Overflow becomes a full scan.
pub const DEFAULT_QUEUE_BOUND: usize = 2048;

/// How often a long-lived watch should reconcile even when the queue is quiet.
pub const RECONCILE_EVERY: Duration = Duration::from_secs(15);

const DIRTY_NAME: &str = "dirty";
const LOCK_NAME: &str = "dirty.lock";

/// One coalesced observation from the native watcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WatchBatch {
    /// Workspace-relative paths. Empty when `full_scan` is set.
    pub paths: Vec<PathBuf>,
    /// Walk the whole workspace. Directory structure changes, ignore-rule
    /// changes, nested `.tig` boundaries, overflow, backend errors, and
    /// [`Event::need_rescan`] all set this.
    pub full_scan: bool,
    /// The full scan is only our metadata baseline (`state`, `root`, op head).
    /// The watch loop drops these only when its working baseline still matches.
    pub baseline: bool,
    /// Drop and recreate the native watcher before trusting later events.
    pub restart: bool,
}

impl WatchBatch {
    fn full(baseline: bool, restart: bool) -> Self {
        WatchBatch {
            paths: Vec::new(),
            full_scan: true,
            baseline,
            restart,
        }
    }
}

/// Hint file body. `epoch` starts at 0 when the file is absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirtyHints {
    pub epoch: u64,
    pub full_scan: bool,
    /// Present when the file was missing, unreadable, or the wrong version.
    /// Callers full-walk and rehash; they must not treat this as "clean".
    pub corrupt: bool,
    pub paths: Vec<PathBuf>,
}

impl DirtyHints {
    pub fn clean() -> Self {
        DirtyHints {
            epoch: 0,
            full_scan: false,
            corrupt: false,
            paths: Vec::new(),
        }
    }

    pub fn is_empty(&self) -> bool {
        !self.full_scan && !self.corrupt && self.paths.is_empty()
    }
}

#[derive(Debug)]
pub enum WatchError {
    Io(io::Error),
    Notify(notify::Error),
    Msg(String),
}

impl std::fmt::Display for WatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WatchError::Io(err) => write!(f, "{err}"),
            WatchError::Notify(err) => write!(f, "{err}"),
            WatchError::Msg(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for WatchError {}

impl From<io::Error> for WatchError {
    fn from(err: io::Error) -> Self {
        WatchError::Io(err)
    }
}

impl From<notify::Error> for WatchError {
    fn from(err: notify::Error) -> Self {
        WatchError::Notify(err)
    }
}

pub type Result<T> = std::result::Result<T, WatchError>;

/// Where to watch and where durable hints live.
pub struct WatchConfig {
    /// Workspace root. Events outside this tree are dropped.
    pub root: PathBuf,
    /// `.tig/workspaces/<name>`. Hint and sentinel files live here.
    pub workspace_meta: PathBuf,
    pub queue_bound: usize,
}

/// Live native watcher plus the bounded queue in front of it.
pub struct FsWatch {
    root: PathBuf,
    workspace_meta: PathBuf,
    rx: Receiver<notify::Result<Event>>,
    handler: QueueHandler,
    watcher: Option<RecommendedWatcher>,
    queue_bound: usize,
}

struct QueueHandler {
    tx: SyncSender<notify::Result<Event>>,
    overflow: Arc<AtomicBool>,
}

impl Clone for QueueHandler {
    fn clone(&self) -> Self {
        QueueHandler {
            tx: self.tx.clone(),
            overflow: Arc::clone(&self.overflow),
        }
    }
}

impl EventHandler for QueueHandler {
    fn handle_event(&mut self, event: notify::Result<Event>) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => {
                // The event is gone. The flag is the only record of it.
                self.overflow.store(true, Ordering::SeqCst);
            }
        }
    }
}

impl FsWatch {
    /// Starts [`notify::recommended_watcher`] recursively on `root`.
    pub fn start(config: WatchConfig) -> Result<Self> {
        if config.queue_bound == 0 {
            return Err(WatchError::Msg("queue bound must be at least 1".into()));
        }
        let (tx, rx) = mpsc::sync_channel(config.queue_bound);
        let handler = QueueHandler {
            tx,
            overflow: Arc::new(AtomicBool::new(false)),
        };
        let watcher = spawn_native(&config.root, handler.clone())?;
        Ok(FsWatch {
            root: config.root,
            workspace_meta: config.workspace_meta,
            rx,
            handler,
            watcher: Some(watcher),
            queue_bound: config.queue_bound,
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn workspace_meta(&self) -> &Path {
        &self.workspace_meta
    }

    pub fn recv(&mut self, idle: Duration) -> Result<Option<WatchBatch>> {
        if self.take_overflow() {
            self.drain();
            return Ok(Some(WatchBatch::full(false, true)));
        }
        let first = match self.rx.recv_timeout(idle) {
            Ok(event) => event,
            Err(RecvTimeoutError::Timeout) => return Ok(None),
            Err(RecvTimeoutError::Disconnected) => {
                return Ok(Some(WatchBatch::full(false, true)));
            }
        };
        let mut acc = Accum::new();
        self.fold_one(&mut acc, first);
        let coalesce = Duration::from_millis(50);
        let deadline = Instant::now() + coalesce;
        while !acc.restart || !acc.full {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            match self.rx.recv_timeout(left) {
                Ok(event) => self.fold_one(&mut acc, event),
                Err(RecvTimeoutError::Timeout) => break,
                Err(RecvTimeoutError::Disconnected) => {
                    acc.restart = true;
                    acc.full = true;
                    acc.baseline = false;
                    break;
                }
            }
        }
        if self.take_overflow() {
            self.drain();
            return Ok(Some(WatchBatch::full(false, true)));
        }
        let batch = acc.finish();
        Ok((batch.full_scan || batch.restart || !batch.paths.is_empty()).then_some(batch))
    }

    /// Drops the native watcher and watches `root` again. The next scan must
    /// be a full scan: events during the gap were not delivered.
    pub fn restart(&mut self) -> Result<()> {
        self.watcher.take();
        self.drain();
        self.handler.overflow.store(false, Ordering::SeqCst);
        self.watcher = Some(spawn_native(&self.root, self.handler.clone())?);
        Ok(())
    }

    /// Pushes `extra` events through the same bounded handler the backend uses.
    /// Native watchers coalesce, so a test cannot rely on the OS to fill the queue.
    pub fn saturate_queue(&mut self) {
        let extra = self.queue_bound.saturating_add(8);
        for i in 0..extra {
            let event = Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Any)))
                .add_path(self.root.join(format!("__queue_{i}")));
            self.handler.handle_event(Ok(event));
        }
    }

    /// Feeds a synthetic backend rescan through the live queue.
    pub fn inject_backend_rescan(&mut self) {
        let mut event = Event::new(EventKind::Any);
        event.attrs.set_flag(Flag::Rescan);
        self.handler.handle_event(Ok(event));
    }

    fn take_overflow(&self) -> bool {
        self.handler.overflow.swap(false, Ordering::SeqCst)
    }

    fn drain(&mut self) {
        while self.rx.try_recv().is_ok() {}
    }

    fn fold_one(&mut self, acc: &mut Accum, event: notify::Result<Event>) {
        match event {
            Err(_) => {
                acc.full = true;
                acc.restart = true;
                acc.baseline = false;
            }
            Ok(event) => {
                // `EventKind::Any` is an ordinary imprecise event about `paths`.
                // Only a rescan flag or a watch-level Other means the queue lost events.
                if event.need_rescan()
                    || (matches!(event.kind, EventKind::Other) && event.paths.is_empty())
                {
                    acc.full = true;
                    acc.restart = true;
                    acc.baseline = false;
                }
                if matches!(event.kind, EventKind::Access(_)) || event.paths.is_empty() {
                    return;
                }
                for path in &event.paths {
                    match classify_path(&self.root, &self.workspace_meta, &event.kind, path) {
                        Class::Drop => {}
                        Class::Path(rel) => {
                            acc.paths.insert(rel);
                            acc.baseline = false;
                            acc.non_baseline_full = true;
                        }
                        Class::Full { baseline } => {
                            acc.full = true;
                            if !baseline {
                                acc.baseline = false;
                                acc.non_baseline_full = true;
                            } else if !acc.non_baseline_full {
                                acc.baseline = true;
                            }
                        }
                    }
                }
            }
        }
    }
}

struct Accum {
    paths: BTreeSet<PathBuf>,
    full: bool,
    baseline: bool,
    non_baseline_full: bool,
    restart: bool,
}

impl Accum {
    fn new() -> Self {
        Accum {
            paths: BTreeSet::new(),
            full: false,
            baseline: false,
            non_baseline_full: false,
            restart: false,
        }
    }

    fn finish(self) -> WatchBatch {
        if self.full {
            WatchBatch::full(self.baseline && !self.non_baseline_full, self.restart)
        } else {
            WatchBatch {
                paths: self.paths.into_iter().collect(),
                full_scan: false,
                baseline: false,
                restart: self.restart,
            }
        }
    }
}

enum Class {
    Drop,
    Path(PathBuf),
    Full { baseline: bool },
}

fn classify_path(root: &Path, meta: &Path, kind: &EventKind, path: &Path) -> Class {
    if let Some(rel_meta) = strip_root(meta, path) {
        let name = rel_meta.to_str().unwrap_or("");
        return if name == "state" || name == "root" {
            Class::Full { baseline: true }
        } else {
            Class::Drop
        };
    }
    let Some(rel) = strip_root(root, path) else {
        return Class::Drop;
    };
    // A modify of the workspace root is the parent of a child event, not a
    // structural change of its own. The child path is classified separately.
    if rel.as_os_str().is_empty() {
        return Class::Drop;
    }
    if !rel_is_utf8(&rel) {
        return Class::Full { baseline: false };
    }
    let name = rel.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name == ".gitignore" || name == ".tigignore" {
        return Class::Full { baseline: false };
    }
    let components: Vec<&str> = rel
        .components()
        .filter_map(|c| c.as_os_str().to_str())
        .collect();
    if components.contains(&".tig") {
        if components.first().copied() == Some(".tig") {
            return classify_root_meta(&components);
        }
        // Nested workspace boundary. Contents belong to the other tree.
        if components.last().copied() == Some(".tig") {
            return Class::Full { baseline: false };
        }
        return Class::Drop;
    }
    if directory_structural(kind, path) {
        return Class::Full { baseline: false };
    }
    Class::Path(rel.to_path_buf())
}

fn classify_root_meta(components: &[&str]) -> Class {
    // .tig/op_head and .tig/op_head.light
    if components.len() == 2 && (components[1] == "op_head" || components[1] == "op_head.light") {
        return Class::Full { baseline: true };
    }
    // .tig/workspaces/<name>/{state,root}
    if components.len() == 4
        && components[1] == "workspaces"
        && (components[3] == "state" || components[3] == "root")
    {
        return Class::Full { baseline: true };
    }
    Class::Drop
}

fn directory_structural(kind: &EventKind, path: &Path) -> bool {
    match kind {
        EventKind::Create(CreateKind::Folder) | EventKind::Remove(RemoveKind::Folder) => true,
        EventKind::Modify(ModifyKind::Name(mode)) => {
            // A file rename carries both paths (or one file path). A directory
            // rename is structural: the children may never get their own events.
            matches!(
                mode,
                RenameMode::Both | RenameMode::From | RenameMode::To | RenameMode::Any
            ) && (path.is_dir() || !path.exists())
        }
        EventKind::Create(CreateKind::Any) | EventKind::Create(CreateKind::Other) => path.is_dir(),
        EventKind::Remove(RemoveKind::Any | RemoveKind::Other) => true,
        EventKind::Remove(_) => false,
        _ => false,
    }
}

/// Drops the Windows verbatim prefix so `C:\...` and `\\?\C:\...` compare.
fn plain(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        return PathBuf::from(format!(r"\\{rest}"));
    }
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        return PathBuf::from(rest);
    }
    path.to_path_buf()
}

fn same_component(a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
    #[cfg(windows)]
    {
        a.eq_ignore_ascii_case(b)
    }
    #[cfg(not(windows))]
    {
        a == b
    }
}

fn strip_root(root: &Path, path: &Path) -> Option<PathBuf> {
    let root = plain(root);
    let path = plain(path);
    if let Ok(rel) = path.strip_prefix(&root) {
        return Some(rel.to_path_buf());
    }
    let root_c: Vec<_> = root.components().collect();
    let path_c: Vec<_> = path.components().collect();
    if path_c.len() < root_c.len() {
        return None;
    }
    if !root_c
        .iter()
        .zip(&path_c)
        .all(|(a, b)| same_component(a.as_os_str(), b.as_os_str()))
    {
        return None;
    }
    let mut rel = PathBuf::new();
    for component in path_c.into_iter().skip(root_c.len()) {
        rel.push(component);
    }
    Some(rel)
}

fn rel_is_utf8(path: &Path) -> bool {
    path.components().all(|c| c.as_os_str().to_str().is_some())
}

fn spawn_native(root: &Path, handler: QueueHandler) -> Result<RecommendedWatcher> {
    let mut watcher = notify::recommended_watcher(handler)?;
    watcher.watch(root, RecursiveMode::Recursive)?;
    Ok(watcher)
}

pub fn dirty_path(workspace_meta: &Path) -> PathBuf {
    workspace_meta.join(DIRTY_NAME)
}

/// Reads the hint file. Absence is a clean epoch 0. A torn or unknown body
/// is `corrupt` and `full_scan` so the next command rehashes.
pub fn load_dirty(workspace_meta: &Path) -> Result<DirtyHints> {
    let path = dirty_path(workspace_meta);
    let bytes = match fs::read(&path) {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(DirtyHints::clean()),
        Err(err) => return Err(err.into()),
    };
    Ok(parse_dirty(&bytes).unwrap_or(DirtyHints {
        epoch: 1,
        full_scan: true,
        corrupt: true,
        paths: Vec::new(),
    }))
}

/// Unions `batch` into the hint file and bumps the epoch by one.
/// Returns the epoch just written.
pub fn record_dirty(workspace_meta: &Path, batch: &WatchBatch) -> Result<u64> {
    with_dirty_lock(workspace_meta, || {
        let mut hints = match fs::read(dirty_path(workspace_meta)) {
            Ok(bytes) => parse_dirty(&bytes).unwrap_or(DirtyHints {
                epoch: 0,
                full_scan: true,
                corrupt: true,
                paths: Vec::new(),
            }),
            Err(err) if err.kind() == io::ErrorKind::NotFound => DirtyHints::clean(),
            Err(err) => return Err(err.into()),
        };
        hints.epoch = hints.epoch.saturating_add(1);
        hints.corrupt = false;
        if batch.full_scan
            || hints.full_scan
            || batch
                .paths
                .iter()
                .any(|p| p.to_str().is_none_or(|s| s.contains(['\n', '\r'])))
        {
            hints.full_scan = true;
            hints.paths.clear();
        } else {
            let mut paths: BTreeSet<PathBuf> = hints.paths.drain(..).collect();
            paths.extend(batch.paths.iter().cloned());
            if paths.len() > MAX_DIRTY_PATHS {
                hints.full_scan = true;
                hints.paths.clear();
            } else {
                hints.paths = paths.into_iter().collect();
            }
        }
        write_dirty(workspace_meta, &hints)?;
        Ok(hints.epoch)
    })
}

/// Clear hints only through the observed epoch, retaining the generation
/// counter so an older scan cannot consume a later edit after a clear.
pub fn consume_dirty_through(workspace_meta: &Path, seen_epoch: u64) -> Result<DirtyHints> {
    with_dirty_lock(workspace_meta, || {
        let path = dirty_path(workspace_meta);
        let hints = match fs::read(&path) {
            Ok(bytes) => parse_dirty(&bytes).unwrap_or(DirtyHints {
                epoch: seen_epoch.saturating_add(1),
                full_scan: true,
                corrupt: true,
                paths: Vec::new(),
            }),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(DirtyHints::clean()),
            Err(err) => return Err(err.into()),
        };
        if hints.corrupt || hints.epoch > seen_epoch {
            return Ok(hints);
        }
        let cleared = DirtyHints {
            epoch: hints.epoch,
            ..DirtyHints::clean()
        };
        write_dirty(workspace_meta, &cleared)?;
        Ok(cleared)
    })
}

fn parse_dirty(bytes: &[u8]) -> Option<DirtyHints> {
    let text = std::str::from_utf8(bytes).ok()?;
    let mut lines = text.lines();
    if lines.next()? != "tig-dirty 1" {
        return None;
    }
    let epoch = lines.next()?.strip_prefix("epoch ")?.parse().ok()?;
    let full = match lines.next()? {
        "full 0" => false,
        "full 1" => true,
        _ => return None,
    };
    let mut paths = Vec::new();
    for line in lines {
        let path = line.strip_prefix("path ")?;
        if path.is_empty() || path.contains('\0') || path.starts_with('/') || path.starts_with('\\')
        {
            return None;
        }
        if path.split(['/', '\\']).any(|c| c == ".." || c.is_empty()) {
            return None;
        }
        paths.push(PathBuf::from(path));
    }
    if full {
        paths.clear();
    }
    Some(DirtyHints {
        epoch,
        full_scan: full,
        corrupt: false,
        paths,
    })
}

fn write_dirty(workspace_meta: &Path, hints: &DirtyHints) -> Result<()> {
    fs::create_dir_all(workspace_meta)?;
    let mut body = format!(
        "tig-dirty 1\nepoch {}\nfull {}\n",
        hints.epoch,
        u8::from(hints.full_scan)
    );
    if !hints.full_scan {
        for path in &hints.paths {
            let text = path.to_str().ok_or_else(|| {
                WatchError::Msg(format!("dirty path is not utf-8: {}", path.display()))
            })?;
            body.push_str("path ");
            body.push_str(text);
            body.push('\n');
        }
    }
    let tmp = workspace_meta.join("dirty.tmp");
    {
        let mut file = File::create(&tmp)?;
        file.write_all(body.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&tmp, dirty_path(workspace_meta))?;
    Ok(())
}

fn with_dirty_lock<T>(workspace_meta: &Path, body: impl FnOnce() -> Result<T>) -> Result<T> {
    fs::create_dir_all(workspace_meta)?;
    // The inode stays put. OS locks release on process death; deleting an
    // apparently stale lock could otherwise split concurrent owners.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(workspace_meta.join(LOCK_NAME))?;
    lock.lock()?;
    body()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_batched_with_workspace_metadata_is_never_suppressed_as_self_writes() {
        let dir = tempfile::tempdir().unwrap();
        let meta = dir.path().join(".tig/workspaces/default");
        fs::create_dir_all(&meta).unwrap();
        let mut watch = FsWatch::start(WatchConfig {
            root: dir.path().into(),
            workspace_meta: meta.clone(),
            queue_bound: 8,
        })
        .unwrap();
        for metadata_first in [true, false] {
            let metadata =
                Event::new(EventKind::Modify(ModifyKind::Any)).add_path(meta.join("state"));
            let content = Event::new(EventKind::Modify(ModifyKind::Data(DataChange::Any)))
                .add_path(dir.path().join("file"));
            let mut acc = Accum::new();
            let events = if metadata_first {
                [metadata, content]
            } else {
                [content, metadata]
            };
            for event in events {
                watch.fold_one(&mut acc, Ok(event));
            }
            let batch = acc.finish();
            assert!(batch.full_scan);
            assert!(
                !batch.baseline,
                "content events must survive self-write suppression"
            );
        }
    }
}
