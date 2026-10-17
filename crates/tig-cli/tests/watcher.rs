//! Native watcher behavior, durable hints and backend-loss fallbacks.

use tig_cli::watcher;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use watcher::{
    consume_dirty_through, load_dirty, record_dirty, FsWatch, WatchBatch, WatchConfig,
    MAX_DIRTY_PATHS,
};

fn wait_batch(
    watch: &mut FsWatch,
    timeout: Duration,
    pred: impl Fn(&WatchBatch) -> bool,
) -> WatchBatch {
    let deadline = Instant::now() + timeout;
    let mut last = WatchBatch {
        paths: Vec::new(),
        full_scan: false,
        baseline: false,
        restart: false,
    };
    while Instant::now() < deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        let slice = left.min(Duration::from_millis(200));
        if let Some(batch) = watch.recv(slice).expect("recv") {
            if pred(&batch) {
                return batch;
            }
            last = batch;
        }
    }
    panic!("timed out waiting for a batch; last={last:?}");
}

fn setup() -> (tempfile::TempDir, PathBuf, FsWatch) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let meta = root.join(".tig").join("workspaces").join("default");
    fs::create_dir_all(&meta).unwrap();
    let watch = FsWatch::start(WatchConfig {
        root: root.clone(),
        workspace_meta: meta,
        queue_bound: 64,
    })
    .expect("start native watcher");
    // Give the backend a moment to arm before the first write.
    std::thread::sleep(Duration::from_millis(150));
    (dir, root, watch)
}

fn rel_has(batch: &WatchBatch, name: &str) -> bool {
    batch.paths.iter().any(|p| p == Path::new(name))
}

#[test]
fn create_edit_delete_rename_are_delivered() {
    let (_dir, root, mut watch) = setup();
    let file = root.join("note.txt");
    fs::write(&file, b"one").unwrap();
    let created = wait_batch(&mut watch, Duration::from_secs(8), |b| {
        rel_has(b, "note.txt") || b.full_scan
    });
    assert!(
        rel_has(&created, "note.txt"),
        "create must name the file, got {created:?}"
    );

    fs::write(&file, b"two").unwrap();
    let edited = wait_batch(&mut watch, Duration::from_secs(8), |b| {
        rel_has(b, "note.txt")
    });
    assert!(
        rel_has(&edited, "note.txt"),
        "edit must name the file, got {edited:?}"
    );

    let dest = root.join("renamed.txt");
    fs::rename(&file, &dest).unwrap();
    let renamed = wait_batch(&mut watch, Duration::from_secs(8), |b| {
        b.full_scan || rel_has(b, "note.txt") || rel_has(b, "renamed.txt")
    });
    assert!(
        renamed.full_scan || rel_has(&renamed, "note.txt") || rel_has(&renamed, "renamed.txt"),
        "rename must name an endpoint, got {renamed:?}"
    );

    fs::remove_file(&dest).unwrap();
    let removed = wait_batch(&mut watch, Duration::from_secs(8), |b| {
        b.full_scan || rel_has(b, "renamed.txt") || rel_has(b, "note.txt")
    });
    assert!(
        removed.full_scan || rel_has(&removed, "renamed.txt") || rel_has(&removed, "note.txt"),
        "delete must name the file, got {removed:?}"
    );
}

#[test]
fn directory_create_is_a_full_scan() {
    let (_dir, root, mut watch) = setup();
    fs::create_dir(root.join("sub")).unwrap();
    let batch = wait_batch(&mut watch, Duration::from_secs(8), |b| b.full_scan);
    assert!(batch.full_scan);
}

#[test]
fn ignore_rule_changes_force_a_full_scan_even_under_an_ignored_dir() {
    let (_dir, root, mut watch) = setup();
    fs::write(root.join(".tigignore"), b"hidden/\n").unwrap();
    let first = wait_batch(&mut watch, Duration::from_secs(8), |b| b.full_scan);
    assert!(first.full_scan, "root ignore file: {first:?}");

    fs::create_dir_all(root.join("hidden")).unwrap();
    // The directory create is itself a full scan. Drain until quiet so the
    // later ignore write is its own batch.
    let _ = wait_batch(&mut watch, Duration::from_secs(8), |b| b.full_scan);
    let quiet = Instant::now() + Duration::from_millis(400);
    while Instant::now() < quiet {
        let _ = watch.recv(Duration::from_millis(50));
    }

    fs::write(root.join("hidden").join(".gitignore"), b"*.log\n").unwrap();
    let nested = wait_batch(&mut watch, Duration::from_secs(8), |b| b.full_scan);
    assert!(
        nested.full_scan,
        "ignore edit inside an excluded directory must not be dropped: {nested:?}"
    );
}

#[test]
fn overflow_and_backend_rescan_request_a_restart_full_scan() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().to_path_buf();
    let meta = root.join("meta");
    fs::create_dir_all(&meta).unwrap();
    let mut watch = FsWatch::start(WatchConfig {
        root,
        workspace_meta: meta,
        queue_bound: 4,
    })
    .unwrap();
    watch.saturate_queue();
    let batch = watch
        .recv(Duration::from_secs(2))
        .unwrap()
        .expect("overflow batch");
    assert!(batch.full_scan, "{batch:?}");
    assert!(batch.restart, "{batch:?}");
    assert!(batch.paths.is_empty());

    watch.inject_backend_rescan();
    let rescan = wait_batch(&mut watch, Duration::from_secs(2), |b| {
        b.full_scan && b.restart
    });
    assert!(rescan.full_scan && rescan.restart);
}

#[test]
fn durable_epoch_survives_and_does_not_drop_a_newer_generation() {
    let dir = tempfile::tempdir().unwrap();
    let meta = dir.path().join("ws");
    fs::create_dir_all(&meta).unwrap();

    let first = WatchBatch {
        paths: vec![PathBuf::from("a.txt")],
        full_scan: false,
        baseline: false,
        restart: false,
    };
    let epoch = record_dirty(&meta, &first).unwrap();
    assert_eq!(epoch, 1);
    let loaded = load_dirty(&meta).unwrap();
    assert_eq!(loaded.paths, vec![PathBuf::from("a.txt")]);
    assert!(!loaded.full_scan);

    // Consumer observed epoch 1, then the watcher recorded another edit
    // before consume. The newer file must stay.
    let second = WatchBatch {
        paths: vec![PathBuf::from("b.txt")],
        full_scan: false,
        baseline: false,
        restart: false,
    };
    let later = record_dirty(&meta, &second).unwrap();
    assert!(later > epoch);
    let left = consume_dirty_through(&meta, epoch).unwrap();
    assert_eq!(left.epoch, later);
    assert!(left.paths.iter().any(|p| p == Path::new("a.txt")));
    assert!(left.paths.iter().any(|p| p == Path::new("b.txt")));
    assert!(!load_dirty(&meta).unwrap().is_empty());

    let cleared = consume_dirty_through(&meta, later).unwrap();
    assert!(cleared.is_empty());
    assert!(load_dirty(&meta).unwrap().is_empty());

    // A dead process that never consumed leaves the next command dirty.
    let renewed = record_dirty(&meta, &first).unwrap();
    assert!(renewed > later, "epochs must survive consumption");
    consume_dirty_through(&meta, epoch).unwrap();
    let again = load_dirty(&dir.path().join("ws")).unwrap();
    assert_eq!(again.paths, vec![PathBuf::from("a.txt")]);
}

#[test]
fn durable_path_cap_and_corrupt_file_force_a_full_scan() {
    let dir = tempfile::tempdir().unwrap();
    let meta = dir.path().join("ws");
    fs::create_dir_all(&meta).unwrap();
    let mut paths = Vec::new();
    for i in 0..=MAX_DIRTY_PATHS {
        paths.push(PathBuf::from(format!("f{i}")));
    }
    // One record that already exceeds the cap, written as many small records
    // so the union crosses the bound.
    let chunk = 1024;
    for group in paths.chunks(chunk) {
        record_dirty(
            &meta,
            &WatchBatch {
                paths: group.to_vec(),
                full_scan: false,
                baseline: false,
                restart: false,
            },
        )
        .unwrap();
    }
    let hints = load_dirty(&meta).unwrap();
    assert!(hints.full_scan, "{hints:?}");
    assert!(hints.paths.is_empty());

    fs::write(meta.join("dirty"), b"not a hint").unwrap();
    let bad = load_dirty(&meta).unwrap();
    assert!(bad.corrupt && bad.full_scan);
}

#[test]
fn restart_still_delivers_a_later_create() {
    let (_dir, root, mut watch) = setup();
    watch.restart().unwrap();
    // The gap is why the command full-scans around restart. Delivery after
    // the new watcher is armed must still work.
    std::thread::sleep(Duration::from_millis(150));
    fs::write(root.join("after.txt"), b"x").unwrap();
    let batch = wait_batch(&mut watch, Duration::from_secs(8), |b| {
        rel_has(b, "after.txt") || b.full_scan
    });
    assert!(rel_has(&batch, "after.txt") || batch.full_scan, "{batch:?}");
}

#[test]
fn workspace_state_is_a_baseline_event_and_reads_do_not_wake_snapshots() {
    let (_dir, root, mut watch) = setup();
    fs::write(watch.workspace_meta().join("state"), b"baseline").unwrap();
    let batch = wait_batch(&mut watch, Duration::from_secs(8), |b| b.baseline);
    assert!(batch.full_scan);
    fs::write(root.join("read.txt"), b"unchanged").unwrap();
    wait_batch(&mut watch, Duration::from_secs(8), |b| {
        rel_has(b, "read.txt")
    });
    while watch.recv(Duration::from_millis(100)).unwrap().is_some() {}
    for _ in 0..20 {
        fs::read(root.join("read.txt")).unwrap();
    }
    assert!(watch.recv(Duration::from_millis(200)).unwrap().is_none());
}
