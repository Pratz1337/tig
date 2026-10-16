//! A real long-lived watcher must adopt other commands' checkout state.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use tig_cli::wc::WorkingCopy;
use tig_core::repo::{Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::workspace::Workspace;
use tig_core::RepoPath;

fn command(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tig"));
    command
        .current_dir(root)
        .env("TIG_AUTHOR_NAME", "watch tester")
        .env("TIG_AUTHOR_EMAIL", "watch@example.com");
    command
}

fn ok(root: &Path, args: &[&str]) {
    let output = command(root).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

struct WatchProcess {
    child: Child,
    lines: Receiver<String>,
}

impl WatchProcess {
    fn start(root: &Path) -> Self {
        let mut child = command(root)
            .arg("watch")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                if tx.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        let watch = Self { child, lines };
        assert!(watch
            .lines
            .recv_timeout(Duration::from_secs(10))
            .unwrap()
            .contains("snapshotted"));
        watch
    }

    fn await_repo(&mut self, root: &Path, check: impl Fn(&Repo) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "watcher exited after an external command"
            );
            let (repo, _) = WorkingCopy::open(root, Settings::default()).unwrap();
            if check(&repo) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "watcher did not snapshot the delivered change"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
}

impl Drop for WatchProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn bytes(repo: &Repo, path: &str) -> Option<Vec<u8>> {
    Workspace::open(repo, DEFAULT_WORKSPACE)
        .unwrap()
        .read(repo, &RepoPath::new(path).unwrap())
        .unwrap()
}

#[test]
fn watch_survives_external_describe_new_and_checkout_without_clobbering_history() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    fs::write(root.join("file"), b"base").unwrap();
    WorkingCopy::init(root, Settings::default()).unwrap();
    let mut watch = WatchProcess::start(root);

    ok(root, &["describe", "-m", "external description"]);
    let (repo, _) = WorkingCopy::open(root, Settings::default()).unwrap();
    let described = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    ok(root, &["new", "-m", "external child"]);
    fs::write(root.join("file"), b"changed after new").unwrap();
    watch.await_repo(root, |repo| {
        bytes(repo, "file").as_deref() == Some(&b"changed after new"[..])
    });
    let (repo, _) = WorkingCopy::open(root, Settings::default()).unwrap();
    let working = repo
        .revision(&repo.working_revision(DEFAULT_WORKSPACE).unwrap())
        .unwrap();
    assert_eq!(working.description, "external child");
    assert_eq!(working.parents, vec![described]);

    fs::rename(root.join("file"), root.join("renamed")).unwrap();
    watch.await_repo(root, |repo| {
        bytes(repo, "file").is_none()
            && bytes(repo, "renamed").as_deref() == Some(&b"changed after new"[..])
    });
    fs::remove_file(root.join("renamed")).unwrap();
    watch.await_repo(root, |repo| bytes(repo, "renamed").is_none());

    ok(root, &["edit", &described.to_hex()]);
    assert_eq!(fs::read(root.join("file")).unwrap(), b"base");
    fs::write(root.join("file"), b"changed after checkout").unwrap();
    watch.await_repo(root, |repo| {
        bytes(repo, "file").as_deref() == Some(&b"changed after checkout"[..])
    });
    let (repo, _) = WorkingCopy::open(root, Settings::default()).unwrap();
    assert_eq!(
        repo.revision(&described).unwrap().description,
        "external description"
    );
    let old_tree = repo.revision(&described).unwrap().tree;
    let leaf = tig_core::treeops::lookup(
        repo.store().as_ref(),
        &old_tree,
        &RepoPath::new("file").unwrap(),
    )
    .unwrap()
    .unwrap();
    use tig_core::store::StoreExt;
    assert_eq!(repo.store().get_blob(&leaf.id()).unwrap(), b"base");
}
