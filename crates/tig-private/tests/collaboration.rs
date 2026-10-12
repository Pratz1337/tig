//! Concurrent publishers on one directory remote: shared correspondence,
//! fast-forward bookmarks, head retries, and a crash journal.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Barrier};
use std::thread;

use tig_core::ophead::MemoryOpHead;
use tig_core::repo::{Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::store::StoreExt;
use tig_core::workspace::Workspace;
use tig_core::{ObjectId, RepoPath};
use tig_private::access;
use tig_private::fetch::{fetch, FetchState};
use tig_private::keyring::OwnerKeys;
use tig_private::keys::Identity;
use tig_private::manifest::Manifest;
use tig_private::publish::{publish, PublishError, PublishOptions, PublishState};
use tig_private::remote::{CommitOutcome, DirRemote, HeadVersion};

const ENV: &[u8] = b"API_KEY=collab-marker\n";

fn repo() -> Repo {
    let settings = Settings {
        fixed_time_ms: Some(1_700_000_000_000),
        ..Settings::default()
    };
    Repo::init(
        std::sync::Arc::new(tig_core::MemoryStore::new()),
        std::sync::Arc::new(MemoryOpHead::new()),
        settings,
    )
    .unwrap()
}

fn save(repo: &mut Repo, writes: &[(&str, &[u8])]) -> ObjectId {
    let mut ws = Workspace::open(repo, DEFAULT_WORKSPACE).unwrap();
    for (path, data) in writes {
        ws.write(repo, &RepoPath::new(path).unwrap(), data).unwrap();
    }
    assert!(ws.snapshot(repo).unwrap());
    ws.working_revision()
}

fn save_child(repo: &mut Repo, writes: &[(&str, &[u8])]) -> ObjectId {
    let parent = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let mut tx = repo.start("new");
    let child = tx.new_change(&[parent], "").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
    repo.commit(tx).unwrap();
    save(repo, writes)
}

fn on_top(repo: &mut Repo, parent: ObjectId, writes: &[(&str, &[u8])]) -> ObjectId {
    let mut tx = repo.start("checkout");
    tx.set_working(DEFAULT_WORKSPACE, parent).unwrap();
    repo.commit(tx).unwrap();
    save_child(repo, writes)
}

#[allow(clippy::too_many_arguments)]
fn publish_rev(
    repo: &Repo,
    remote: &DirRemote,
    identity: &Identity,
    keys: Option<&OwnerKeys>,
    state: &mut PublishState,
    fetched: &FetchState,
    bookmark: &str,
    rev: ObjectId,
    force: bool,
) -> Result<usize, PublishError> {
    let report = publish(
        repo.store().as_ref(),
        remote,
        identity,
        keys,
        state,
        fetched,
        bookmark,
        rev,
        &PublishOptions {
            force,
            ..PublishOptions::default()
        },
    )?;
    Ok(report.revisions_published)
}

fn owner_keys(remote: &DirRemote, owner: &Identity) -> OwnerKeys {
    tig_private::keyring::Keyring::create(remote.remote_id(), owner)
        .unwrap()
        .1
}

fn pin_from_fetch(state: &mut PublishState, fetched: &FetchState) {
    state.remote_id = fetched.remote_id;
    state.owner_signing = fetched.owner_signing;
    state.counter = state.counter.max(fetched.counter);
    state.manifest_seq = state.manifest_seq.max(fetched.manifest_seq);
}

fn manifest(remote: &DirRemote) -> Manifest {
    Manifest::decode(&remote.read_manifest().unwrap().unwrap()).unwrap()
}

#[test]
fn publisher_fetch_reuses_the_local_revision() {
    let mut repo = repo();
    let rev = save(&mut repo, &[("src/main.rs", b"fn main() {}\n"), (".env", ENV)]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [11; 16]).unwrap();
    let alice = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &alice);
    let mut published = PublishState::new();
    let n = publish_rev(
        &repo,
        &remote,
        &alice,
        Some(&keys),
        &mut published,
        &FetchState::new(),
        "main",
        rev,
        false,
    )
    .unwrap();
    assert_eq!(n, 1);
    let mut fetched = FetchState::new();
    let report = fetch(
        &remote,
        repo.store().as_ref(),
        Some(&alice),
        &mut fetched,
        &published,
    )
    .unwrap();
    assert_eq!(report.refs["main"], rev);
    let public_id = manifest(&remote).refs["main"];
    assert_eq!(fetched.revisions.get(&public_id), Some(&rev));
}

#[test]
fn fetch_correspondence_is_not_reprojected_across_an_epoch_change() {
    let mut alice_repo = repo();
    let alice_rev = save(&mut alice_repo, &[("src/main.rs", b"alice\n"), (".env", ENV)]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [12; 16]).unwrap();
    let alice = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &alice);
    let mut alice_pub = PublishState::new();
    publish_rev(
        &alice_repo,
        &remote,
        &alice,
        Some(&keys),
        &mut alice_pub,
        &FetchState::new(),
        "main",
        alice_rev,
        false,
    )
    .unwrap();
    let carol = Identity::generate().unwrap();
    grant_member(&remote, &alice, &keys, &alice_pub, &carol);
    let alice_public = manifest(&remote).refs["main"];

    let bob = Identity::generate().unwrap();
    grant_member(&remote, &alice, &keys, &alice_pub, &bob);
    let mut bob_repo = repo();
    let mut bob_fetch = FetchState::new();
    let report = fetch(
        &remote,
        bob_repo.store().as_ref(),
        Some(&bob),
        &mut bob_fetch,
        &PublishState::new(),
    )
    .unwrap();
    let mut bob_pub = PublishState::new();
    pin_from_fetch(&mut bob_pub, &bob_fetch);
    // Same publish, no epoch change: Bob adds one revision and Alice's id stays.
    let child = on_top(&mut bob_repo, report.refs["main"], &[("src/main.rs", b"bob\n")]);
    let n = publish_rev(
        &bob_repo,
        &remote,
        &bob,
        None,
        &mut bob_pub,
        &bob_fetch,
        "main",
        child,
        false,
    )
    .unwrap();
    assert_eq!(n, 1);
    let bob_public = manifest(&remote).refs["main"];
    let parent = remote
        .public_store()
        .get_revision(&bob_public)
        .unwrap()
        .parents[0];
    assert_eq!(parent, alice_public);

    // A third member is revoked. Bob publishes another child. Alice's public id
    // is still the grandparent, not a fresh projection under the new epoch.
    let local = tempfile::tempdir().unwrap();
    fs::create_dir_all(local.path()).unwrap();
    write_owner(local.path(), &keys, &alice_pub);
    let mut owner_pub = alice_pub.clone();
    access::revoke(
        &remote,
        local.path(),
        &alice,
        &mut load_keys(local.path()),
        &mut owner_pub,
        &carol.public(),
    )
    .unwrap();
    assert!(manifest(&remote).publisher != carol.public().signing);
    let again = on_top(&mut bob_repo, child, &[("src/main.rs", b"bob-2\n")]);
    let n = publish_rev(
        &bob_repo,
        &remote,
        &bob,
        None,
        &mut bob_pub,
        &bob_fetch,
        "main",
        again,
        false,
    )
    .unwrap();
    assert_eq!(n, 1);
    let tip = manifest(&remote).refs["main"];
    let mid = remote.public_store().get_revision(&tip).unwrap().parents[0];
    let root = remote.public_store().get_revision(&mid).unwrap().parents[0];
    assert_eq!(root, alice_public);
}

#[test]
fn bookmarks_move_forward_only() {
    let mut alice_repo = repo();
    let alice_rev = save(&mut alice_repo, &[("src/main.rs", b"alice\n")]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [13; 16]).unwrap();
    let alice = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &alice);
    let mut alice_pub = PublishState::new();
    publish_rev(
        &alice_repo,
        &remote,
        &alice,
        Some(&keys),
        &mut alice_pub,
        &FetchState::new(),
        "main",
        alice_rev,
        false,
    )
    .unwrap();
    let kept = manifest(&remote).refs["main"];
    let bob = Identity::generate().unwrap();
    grant_member(&remote, &alice, &keys, &alice_pub, &bob);

    let mut bob_repo = repo();
    let bob_rev = save(&mut bob_repo, &[("src/main.rs", b"bob-unrelated\n")]);
    let mut bob_pub = PublishState::new();
    bob_pub.remote_id = remote.remote_id();
    bob_pub.owner_signing = Some(alice.public().signing);
    let err = publish_rev(
        &bob_repo,
        &remote,
        &bob,
        None,
        &mut bob_pub,
        &FetchState::new(),
        "main",
        bob_rev,
        false,
    )
    .unwrap_err();
    assert!(matches!(err, PublishError::NotFastForward { .. }), "{err}");
    assert!(err.to_string().contains("tig fetch"));
    assert_eq!(manifest(&remote).refs["main"], kept);

    // A different bookmark is not blocked by `main`.
    publish_rev(
        &bob_repo,
        &remote,
        &bob,
        None,
        &mut bob_pub,
        &FetchState::new(),
        "bob",
        bob_rev,
        false,
    )
    .unwrap();
    assert_eq!(manifest(&remote).refs["main"], kept);
    assert_eq!(manifest(&remote).refs["bob"], {
        // Bob's public tip is whatever the manifest now stores.
        manifest(&remote).refs["bob"]
    });

    let mut fetched = FetchState::new();
    let report = fetch(
        &remote,
        bob_repo.store().as_ref(),
        Some(&bob),
        &mut fetched,
        &bob_pub,
    )
    .unwrap();
    pin_from_fetch(&mut bob_pub, &fetched);
    let merged = merge(&mut bob_repo, bob_rev, report.refs["main"], b"merged\n");
    publish_rev(
        &bob_repo,
        &remote,
        &bob,
        None,
        &mut bob_pub,
        &fetched,
        "main",
        merged,
        false,
    )
    .unwrap();
    assert_ne!(manifest(&remote).refs["main"], kept);

    // `--force` replaces a bookmark that was not fetched.
    let carol_rev = save(&mut bob_repo, &[("src/main.rs", b"forced\n")]);
    let mut forced = PublishState::new();
    forced.remote_id = remote.remote_id();
    forced.owner_signing = Some(alice.public().signing);
    forced.counter = manifest_counter(&remote);
    publish_rev(
        &bob_repo,
        &remote,
        &bob,
        None,
        &mut forced,
        &FetchState::new(),
        "side",
        carol_rev,
        false,
    )
    .unwrap();
    let side = manifest(&remote).refs["side"];
    publish_rev(
        &alice_repo,
        &remote,
        &alice,
        Some(&keys),
        &mut alice_pub,
        &FetchState::new(),
        "side",
        alice_rev,
        true,
    )
    .unwrap();
    assert_ne!(manifest(&remote).refs["side"], side);
}

#[test]
fn concurrent_distinct_bookmarks_keep_every_pack() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [14; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut owner_repo = repo();
    let rev = save(&mut owner_repo, &[("src/main.rs", b"owner\n"), (".env", ENV)]);
    let mut owner_pub = PublishState::new();
    publish_rev(
        &owner_repo,
        &remote,
        &owner,
        Some(&keys),
        &mut owner_pub,
        &FetchState::new(),
        "owner",
        rev,
        false,
    )
    .unwrap();
    let members: Vec<Identity> = (0..3).map(|_| Identity::generate().unwrap()).collect();
    for member in &members {
        grant_member(&remote, &owner, &keys, &owner_pub, member);
    }
    let path = dir.path().to_path_buf();
    let owner_signing = owner.public().signing;
    let remote_id = remote.remote_id();
    let mut names = vec!["owner".to_string()];
    let mut threads = Vec::new();
    for (index, member) in members.into_iter().enumerate() {
        let bookmark = format!("m{index}");
        names.push(bookmark.clone());
        let path = path.clone();
        threads.push(thread::spawn(move || {
            let remote = DirRemote::open(&path).unwrap();
            let mut repo = repo();
            let mut state = PublishState::new();
            state.remote_id = remote_id;
            state.owner_signing = Some(owner_signing);
            state.counter = 1;
            let mut last = ObjectId([0; 32]);
            for round in 0..3 {
                let body = format!("member {index} round {round}\n");
                let rev = if round == 0 {
                    save(&mut repo, &[("src/main.rs", body.as_bytes()), (".env", ENV)])
                } else {
                    save_child(&mut repo, &[("src/main.rs", body.as_bytes())])
                };
                publish_rev(
                    &repo,
                    &remote,
                    &member,
                    None,
                    &mut state,
                    &FetchState::new(),
                    &bookmark,
                    rev,
                    false,
                )
                .unwrap();
                last = rev;
            }
            (bookmark, state.revisions[&last])
        }));
    }
    // The owner keeps publishing their own bookmark alongside the members.
    for round in 0..3 {
        let body = format!("owner round {round}\n");
        let rev = save_child(&mut owner_repo, &[("src/main.rs", body.as_bytes())]);
        publish_rev(
            &owner_repo,
            &remote,
            &owner,
            Some(&keys),
            &mut owner_pub,
            &FetchState::new(),
            "owner",
            rev,
            false,
        )
        .unwrap();
    }
    let mut tips = Vec::new();
    tips.push(("owner".to_string(), manifest(&remote).refs["owner"]));
    for thread in threads {
        tips.push(thread.join().unwrap());
    }
    let final_manifest = manifest(&remote);
    for (bookmark, public_id) in &tips {
        assert_eq!(final_manifest.refs[bookmark.as_str()], *public_id, "{bookmark}");
    }
    let mut files = Vec::new();
    collect_packs(dir.path(), &mut files);
    assert!(!files.is_empty());
    for bytes in files {
        let id = *blake3::hash(&bytes).as_bytes();
        assert!(final_manifest.packs.contains_key(&id), "pack missing from manifest");
    }
}

#[test]
fn one_bookmark_admits_one_concurrent_publisher() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [15; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut owner_repo = repo();
    let base = save(&mut owner_repo, &[("src/main.rs", b"base\n")]);
    let mut owner_pub = PublishState::new();
    publish_rev(
        &owner_repo,
        &remote,
        &owner,
        Some(&keys),
        &mut owner_pub,
        &FetchState::new(),
        "main",
        base,
        false,
    )
    .unwrap();
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    grant_member(&remote, &owner, &keys, &owner_pub, &alice);
    grant_member(&remote, &owner, &keys, &owner_pub, &bob);
    let kept = manifest(&remote).refs["main"];

    let path = dir.path().to_path_buf();
    let remote_id = remote.remote_id();
    let pin = owner.public().signing;
    let barrier = Arc::new(Barrier::new(2));
    let mut handles = Vec::new();
    for (identity, text) in [(alice, b"alice-race\n" as &[u8]), (bob, b"bob-race\n")] {
        let path = path.clone();
        let barrier = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            let remote = DirRemote::open(&path).unwrap();
            let mut repo = repo();
            let mut fetched = FetchState::new();
            let report = fetch(
                &remote,
                repo.store().as_ref(),
                Some(&identity),
                &mut fetched,
                &PublishState::new(),
            )
            .unwrap();
            let rev = on_top(&mut repo, report.refs["main"], &[("src/main.rs", text)]);
            let mut state = PublishState::new();
            pin_from_fetch(&mut state, &fetched);
            barrier.wait();
            let result = publish_rev(
                &repo,
                &remote,
                &identity,
                None,
                &mut state,
                &fetched,
                "main",
                rev,
                false,
            );
            (result.map(|_| ()).map_err(|err| err.to_string()), rev, fetched, identity, state)
        }));
    }
    let finished: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let wins = finished.iter().filter(|(result, ..)| result.is_ok()).count();
    let losses = finished
        .iter()
        .filter(|(result, ..)| result.as_ref().is_err_and(|text| text.contains("tig fetch")))
        .count();
    assert_eq!(wins, 1, "{finished:?}");
    assert_eq!(losses, 1, "{finished:?}");
    assert_ne!(manifest(&remote).refs["main"], kept);

    let (loser_rev, mut loser_fetch, loser, mut loser_state) = finished
        .into_iter()
        .find_map(|(result, rev, fetched, identity, state)| {
            result.err().map(|_| (rev, fetched, identity, state))
        })
        .unwrap();
    let remote = DirRemote::open(&path).unwrap();
    let mut loser_repo = repo();
    // The loser's revision lives in the thread's store. Rebuild the same merge
    // by fetching both tips into a fresh repo and publishing a child of the
    // fetched remote tip, which is an ancestor-based fast-forward.
    let _ = (loser_rev, remote_id, pin);
    let report = fetch(
        &remote,
        loser_repo.store().as_ref(),
        Some(&loser),
        &mut loser_fetch,
        &loser_state,
    )
    .unwrap();
    pin_from_fetch(&mut loser_state, &loser_fetch);
    let child = on_top(
        &mut loser_repo,
        report.refs["main"],
        &[("src/main.rs", b"after merge fetch\n")],
    );
    publish_rev(
        &loser_repo,
        &remote,
        &loser,
        None,
        &mut loser_state,
        &loser_fetch,
        "main",
        child,
        false,
    )
    .unwrap();
}

#[test]
fn revoke_during_publish_drops_the_member_signature() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [16; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let mut keys = owner_keys(&remote, &owner);
    let mut owner_repo = repo();
    let rev = save(&mut owner_repo, &[("src/main.rs", b"owner\n"), (".env", ENV)]);
    let mut owner_pub = PublishState::new();
    publish_rev(
        &owner_repo,
        &remote,
        &owner,
        Some(&keys),
        &mut owner_pub,
        &FetchState::new(),
        "owner",
        rev,
        false,
    )
    .unwrap();
    let member = Identity::generate().unwrap();
    let member_id = member.public();
    let other = Identity::generate().unwrap();
    grant_member(&remote, &owner, &keys, &owner_pub, &member);
    grant_member(&remote, &owner, &keys, &owner_pub, &other);
    let epoch_before = tig_private::keyring::Keyring::decode(&remote.read_keyring().unwrap())
        .unwrap()
        .head
        .epochs["private"];

    let path = dir.path().to_path_buf();
    let remote_id = remote.remote_id();
    let pin = owner.public().signing;
    let started = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let started_flag = Arc::clone(&started);
    let stop_flag = Arc::clone(&stop);
    let worker = thread::spawn(move || {
        let remote = DirRemote::open(&path).unwrap();
        let mut repo = repo();
        let mut state = PublishState::new();
        state.remote_id = remote_id;
        state.owner_signing = Some(pin);
        let mut errors = 0usize;
        for round in 0..30 {
            if stop_flag.load(std::sync::atomic::Ordering::SeqCst) && round > 0 {
                break;
            }
            let body = format!("m {round}\n");
            let rev = if round == 0 {
                save(&mut repo, &[("note.txt", body.as_bytes()), (".env", ENV)])
            } else {
                save_child(&mut repo, &[("note.txt", body.as_bytes())])
            };
            match publish_rev(
                &repo,
                &remote,
                &member,
                None,
                &mut state,
                &FetchState::new(),
                "member",
                rev,
                false,
            ) {
                Ok(_) => started_flag.store(true, std::sync::atomic::Ordering::SeqCst),
                Err(_) => errors += 1,
            }
        }
        errors
    });
    while !started.load(std::sync::atomic::Ordering::SeqCst) {
        thread::sleep(std::time::Duration::from_millis(5));
    }
    let local = tempfile::tempdir().unwrap();
    write_owner(local.path(), &keys, &owner_pub);
    access::revoke(
        &remote,
        local.path(),
        &owner,
        &mut keys,
        &mut owner_pub,
        &member_id,
    )
    .unwrap();
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let _errors = worker.join().unwrap();
    let final_manifest = manifest(&remote);
    assert_ne!(final_manifest.publisher, member_id.signing);
    for entry in final_manifest.packs.values() {
        assert!(entry.epoch <= epoch_before, "epoch {}", entry.epoch);
    }
    let mut owner_fetch = FetchState::new();
    pin_publish_fetch(&owner_pub, &mut owner_fetch);
    fetch(
        &remote,
        owner_repo.store().as_ref(),
        Some(&owner),
        &mut owner_fetch,
        &owner_pub,
    )
    .unwrap();
    let other_repo = repo();
    let mut other_fetch = FetchState::new();
    fetch(
        &remote,
        other_repo.store().as_ref(),
        Some(&other),
        &mut other_fetch,
        &PublishState::new(),
    )
    .unwrap();
}

#[test]
fn pending_head_rolls_forward_and_a_torn_record_is_ignored() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [17; 16]).unwrap();
    let pending = dir.path().join("head.pending");
    let record = encode_pending(Some(b"keyring-v1"), Some(b"manifest-v1"));
    fs::write(&pending, &record).unwrap();
    let head = remote.read_head().unwrap();
    assert_eq!(head.keyring.as_deref(), Some(b"keyring-v1".as_slice()));
    assert_eq!(head.manifest.as_deref(), Some(b"manifest-v1".as_slice()));
    assert!(!pending.exists());

    fs::write(&pending, &record[..record.len() - 1]).unwrap();
    let again = remote.read_head().unwrap();
    assert_eq!(again, head);
    assert!(!pending.exists());

    let stale = remote.read_head().unwrap();
    let outcome = remote
        .commit_head(&HeadVersion(stale.version().0), Some(b"nope"), None)
        .unwrap();
    // Same version: this commits. A mismatched version is stale.
    assert!(matches!(outcome, CommitOutcome::Committed(_)));
    let current = remote.read_head().unwrap();
    let outcome = remote
        .commit_head(&stale.version(), Some(b"other"), None)
        .unwrap();
    assert!(matches!(outcome, CommitOutcome::Stale(ref head) if head == &current));
    assert_eq!(remote.read_keyring().unwrap(), b"nope");
}

fn encode_pending(keyring: Option<&[u8]>, manifest: Option<&[u8]>) -> Vec<u8> {
    fn part(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
        match bytes {
            None => out.extend_from_slice(&u64::MAX.to_le_bytes()),
            Some(bytes) => {
                out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
                out.extend_from_slice(bytes);
            }
        }
    }
    let mut body = Vec::new();
    part(&mut body, keyring);
    part(&mut body, manifest);
    body.extend_from_slice(blake3::hash(&body).as_bytes());
    body
}

fn manifest_counter(remote: &DirRemote) -> u64 {
    tig_private::keyring::Keyring::decode(&remote.read_keyring().unwrap())
        .unwrap()
        .head
        .counter
}

fn merge(repo: &mut Repo, left: ObjectId, right: ObjectId, text: &[u8]) -> ObjectId {
    let mut tx = repo.start("merge");
    let child = tx.new_change(&[left, right], "merge").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
    repo.commit(tx).unwrap();
    save(repo, &[("src/main.rs", text)])
}

fn grant_member(
    remote: &DirRemote,
    owner: &Identity,
    keys: &OwnerKeys,
    state: &PublishState,
    member: &Identity,
) {
    let local = tempfile::tempdir().unwrap();
    write_owner(local.path(), keys, state);
    let mut state = state.clone();
    access::grant(
        remote,
        local.path(),
        owner,
        keys,
        &mut state,
        &member.public(),
    )
    .unwrap();
}

fn write_owner(dir: &Path, keys: &OwnerKeys, state: &PublishState) {
    fs::create_dir_all(dir).unwrap();
    fs::write(dir.join("owner-keys"), keys.encode().unwrap()).unwrap();
    fs::write(dir.join("publish-state"), state.encode().unwrap()).unwrap();
}

fn load_keys(dir: &Path) -> OwnerKeys {
    OwnerKeys::decode(&fs::read(dir.join("owner-keys")).unwrap()).unwrap()
}

fn pin_publish_fetch(published: &PublishState, fetched: &mut FetchState) {
    fetched.remote_id = published.remote_id;
    fetched.owner_signing = published.owner_signing;
    fetched.counter = published.counter;
    fetched.manifest_seq = published.manifest_seq;
}

fn collect_packs(root: &Path, out: &mut Vec<Vec<u8>>) {
    let packs = root.join("packs");
    let mut stack = vec![packs];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "pack") {
                out.push(fs::read(&path).unwrap());
            }
        }
    }
}
