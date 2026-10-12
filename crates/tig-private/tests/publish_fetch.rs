//! Publish and fetch against a directory remote: secrecy of the wire
//! bytes, member rebuild, outsider seals, the built-in floor, refusals,
//! incremental republish, revocation, rollback, and a substituted owner.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tig_core::ophead::MemoryOpHead;
use tig_core::repo::{Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::store::StoreExt;
use tig_core::treeops::lookup;
use tig_core::workspace::Workspace;
use tig_core::{EntryKind, MemoryStore, ObjectId, RepoPath};
use tig_private::fetch::{fetch, FetchError, FetchReport, FetchState};
use tig_private::keyring::{Keyring, KeyringError, OwnerKeys};
use tig_private::keys::Identity;
use tig_private::publish::{publish, PublishError, PublishOptions, PublishReport, PublishState};
use tig_private::remote::DirRemote;

const ENV: &[u8] = b"API_KEY=hunter2-unique-marker\n";
const ENV_V2: &[u8] = b"API_KEY=hunter2-unique-marker-v2\n";
const KEY: &[u8] = b"hunter2-key-material\n";
const MAIN: &[u8] = b"fn main() {}\n";
const MAIN_V2: &[u8] = b"fn main() { println!(\"hi\"); }\n";
const RULES: &[u8] = b"secrets/\n";

fn p(path: &str) -> RepoPath {
    RepoPath::new(path).unwrap()
}

fn repo() -> Repo {
    let settings = Settings {
        fixed_time_ms: Some(1_700_000_000_000),
        ..Settings::default()
    };
    Repo::init(
        Arc::new(MemoryStore::new()),
        Arc::new(MemoryOpHead::new()),
        settings,
    )
    .unwrap()
}

fn save(repo: &mut Repo, writes: &[(&str, &[u8])], removes: &[&str]) -> ObjectId {
    let mut ws = Workspace::open(repo, DEFAULT_WORKSPACE).unwrap();
    for path in removes {
        ws.remove(repo, &p(path)).unwrap();
    }
    for (path, data) in writes {
        ws.write(repo, &p(path), data).unwrap();
    }
    assert!(ws.snapshot(repo).unwrap());
    ws.working_revision()
}

fn save_child(repo: &mut Repo, writes: &[(&str, &[u8])], removes: &[&str]) -> ObjectId {
    let parent = repo.working_revision(DEFAULT_WORKSPACE).unwrap();
    let mut tx = repo.start("new");
    let child = tx.new_change(&[parent], "").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
    repo.commit(tx).unwrap();
    save(repo, writes, removes)
}

fn remote_at(id: [u8; 16]) -> (tempfile::TempDir, DirRemote) {
    let dir = tempfile::TempDir::new().unwrap();
    let remote = DirRemote::create(dir.path(), id).unwrap();
    (dir, remote)
}

fn publish_at(
    repo: &Repo,
    remote: &DirRemote,
    identity: &Identity,
    keys: Option<&OwnerKeys>,
    state: &mut PublishState,
    rev: ObjectId,
    options: &PublishOptions,
) -> Result<PublishReport, PublishError> {
    // This fixture is also the in-memory equivalent of saving owner keys
    // before entering publish. Return prepared keys for existing scenarios.
    let prepared = match keys {
        None => Some(Keyring::create(remote.remote_id(), identity)?.1),
        Some(_) => None,
    };
    let mut report = publish(
        repo.store().as_ref(),
        remote,
        identity,
        keys.or(prepared.as_ref()),
        state,
        "main",
        rev,
        options,
    )?;
    report.new_owner_keys = prepared;
    Ok(report)
}

fn fetch_new(
    remote: &DirRemote,
    identity: Option<&Identity>,
    state: &mut FetchState,
) -> Result<(MemoryStore, FetchReport), FetchError> {
    let store = MemoryStore::new();
    let report = fetch(remote, &store, identity, state)?;
    Ok((store, report))
}

fn blob_of(repo: &Repo, rev: ObjectId, path: &str) -> ObjectId {
    let tree = repo.revision(&rev).unwrap().tree;
    lookup(repo.store().as_ref(), &tree, &p(path))
        .unwrap()
        .unwrap_or_else(|| panic!("missing {path}"))
        .id()
}

fn kind_at(store: &dyn tig_core::Store, tree: ObjectId, path: &str) -> Option<EntryKind> {
    lookup(store, &tree, &p(path))
        .unwrap()
        .map(|leaf| leaf.kind())
}

fn file_at(store: &dyn tig_core::Store, tree: ObjectId, path: &str) -> Vec<u8> {
    let id = lookup(store, &tree, &p(path)).unwrap().unwrap().id();
    store.get_blob(&id).unwrap()
}

fn tip(report: &FetchReport) -> ObjectId {
    *report.refs.get("main").expect("bookmark main")
}

fn files_of(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                stack.push(path);
            } else if kind.is_file() {
                let rel = path.strip_prefix(root).unwrap().to_path_buf();
                out.insert(rel, std::fs::read(&path).unwrap());
            }
        }
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|window| window == needle)
}

fn assert_hidden(files: &BTreeMap<PathBuf, Vec<u8>>, needles: &[Vec<u8>]) {
    for needle in needles {
        assert!(!needle.is_empty());
    }
    for (path, bytes) in files {
        let rel = path.to_string_lossy();
        for needle in needles {
            assert!(
                !contains(bytes, needle),
                "{} contains a private needle",
                path.display()
            );
            if let Ok(text) = std::str::from_utf8(needle) {
                assert!(
                    !rel.contains(text),
                    "path {} contains {text}",
                    path.display()
                );
            }
        }
    }
}

fn id_needles(id: ObjectId) -> [Vec<u8>; 2] {
    [id.as_bytes().to_vec(), id.to_hex().into_bytes()]
}

fn under(path: &Path, name: &str) -> bool {
    path.components()
        .next()
        .is_some_and(|component| component.as_os_str() == name)
}

fn public_kind(remote: &DirRemote, path: &str) -> EntryKind {
    let id = remote.read_refs().unwrap()["main"];
    let tree = remote.public_store().get_revision(&id).unwrap().tree;
    kind_at(remote.public_store(), tree, path).unwrap()
}

fn grant(remote: &DirRemote, keys: &OwnerKeys, owner: &Identity, member: &Identity) {
    let mut keyring = Keyring::decode(&remote.read_keyring().unwrap()).unwrap();
    keyring.grant(keys, owner, &member.public()).unwrap();
    remote.write_keyring(&keyring.encode().unwrap()).unwrap();
}

#[test]
fn alice_publishes_secrets_bob_reads_them_carol_does_not() {
    let mut repo = repo();
    let rev = save(
        &mut repo,
        &[
            (".private", RULES),
            (".env", ENV),
            ("secrets/a.key", KEY),
            ("src/main.rs", MAIN),
        ],
        &[],
    );
    let env_id = blob_of(&repo, rev, ".env");
    let key_id = blob_of(&repo, rev, "secrets/a.key");
    let alice_tree = repo.revision(&rev).unwrap().tree;

    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let carol = Identity::generate().unwrap();
    let (_dir, remote) = remote_at([1; 16]);
    let mut state = PublishState::new();
    let report = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    let owner_keys = report
        .new_owner_keys
        .expect("first publish mints owner keys");
    assert_eq!(report.revisions_published, 1);
    assert_eq!(report.sealed_roots, 2);
    assert!(report.private_objects_sealed > 0);
    grant(&remote, &owner_keys, &alice, &bob);

    let mut needles = vec![ENV.to_vec(), KEY.to_vec(), b"a.key".to_vec()];
    needles.extend(id_needles(env_id));
    needles.extend(id_needles(key_id));
    let files = files_of(_dir.path());
    assert!(files.keys().any(|path| under(path, "objects")));
    assert!(files.keys().any(|path| under(path, "packs")));
    assert_hidden(&files, &needles);

    let mut alice_fetch = FetchState::new();
    let (alice_store, alice_report) = fetch_new(&remote, Some(&alice), &mut alice_fetch).unwrap();
    assert_eq!(
        alice_report.newly_pinned.as_deref(),
        Some(alice.public().fingerprint().as_str())
    );
    assert_eq!(alice.public().fingerprint().len(), 16);
    let alice_got = alice_store.get_revision(&tip(&alice_report)).unwrap();
    assert_eq!(alice_got.tree, alice_tree);
    assert_eq!(alice_report.unsealed, 2);
    assert_eq!(alice_report.still_sealed, 0);

    let mut bob_state = FetchState::new();
    let (bob_store, bob_report) = fetch_new(&remote, Some(&bob), &mut bob_state).unwrap();
    assert_eq!(
        bob_report.newly_pinned.as_deref(),
        Some(alice.public().fingerprint().as_str())
    );
    let bob_got = bob_store.get_revision(&tip(&bob_report)).unwrap();
    assert_eq!(bob_got.tree, alice_tree);
    assert_eq!(bob_store.get_blob(&env_id).unwrap(), ENV);
    assert_eq!(bob_store.get_blob(&key_id).unwrap(), KEY);
    assert_eq!(bob_report.unsealed, 2);
    assert_eq!(bob_report.still_sealed, 0);

    let again_report = fetch(&remote, &bob_store, Some(&bob), &mut bob_state).unwrap();
    assert_eq!(again_report.newly_pinned, None);
    assert_eq!(
        bob_store.get_revision(&tip(&again_report)).unwrap().tree,
        alice_tree
    );
    assert_eq!(again_report.unsealed, 0);
    assert_eq!(again_report.still_sealed, 0);

    let mut carol_state = FetchState::new();
    let (carol_store, carol_report) = fetch_new(&remote, Some(&carol), &mut carol_state).unwrap();
    let carol_rev = carol_store.get_revision(&tip(&carol_report)).unwrap();
    assert_eq!(
        kind_at(&carol_store, carol_rev.tree, ".env"),
        Some(EntryKind::Sealed)
    );
    assert_eq!(
        kind_at(&carol_store, carol_rev.tree, "secrets"),
        Some(EntryKind::Sealed)
    );
    assert_eq!(kind_at(&carol_store, carol_rev.tree, "secrets/a.key"), None);
    assert_eq!(file_at(&carol_store, carol_rev.tree, "src/main.rs"), MAIN);
    assert_eq!(file_at(&carol_store, carol_rev.tree, ".private"), RULES);
    assert!(carol_store.get_blob(&env_id).is_err());
    assert!(carol_store.get_blob(&key_id).is_err());
    assert_eq!(carol_report.unsealed, 0);
    assert_eq!(carol_report.still_sealed, 2);
}

#[test]
fn fresh_publisher_still_detects_previously_public_paths() {
    let mut repo = repo();
    let rev = save(&mut repo, &[("src/main.rs", MAIN)], &[]);
    let alice = Identity::generate().unwrap();
    let (_dir, remote) = remote_at([13; 16]);
    let mut state = PublishState::new();
    let keys = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap()
    .new_owner_keys
    .unwrap();
    let mut other = self::repo();
    let rev = save(
        &mut other,
        &[(".private", b"src/\n"), ("src/main.rs", MAIN)],
        &[],
    );
    let before = files_of(_dir.path());
    let result = publish_at(
        &other,
        &remote,
        &alice,
        Some(&keys),
        &mut PublishState::new(),
        rev,
        &PublishOptions::default(),
    );
    assert!(
        matches!(result, Err(PublishError::AlreadyLeaked { ref paths })
        if paths.contains(&p("src/main.rs")))
    );
    assert_eq!(files_of(_dir.path()), before);
}

#[test]
fn later_grant_opens_already_fetched_revisions() {
    let mut repo = repo();
    let rev = save(&mut repo, &[(".env", ENV), ("src/main.rs", MAIN)], &[]);
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let (_dir, remote) = remote_at([12; 16]);
    let mut published = PublishState::new();
    let keys = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut published,
        rev,
        &PublishOptions::default(),
    )
    .unwrap()
    .new_owner_keys
    .unwrap();
    let store = MemoryStore::new();
    let mut state = FetchState::new();
    let first = fetch(&remote, &store, Some(&bob), &mut state).unwrap();
    let first_tree = store.get_revision(&tip(&first)).unwrap().tree;
    assert_eq!(kind_at(&store, first_tree, ".env"), Some(EntryKind::Sealed));
    grant(&remote, &keys, &alice, &bob);
    let opened = fetch(&remote, &store, Some(&bob), &mut state).unwrap();
    let tree = store.get_revision(&tip(&opened)).unwrap().tree;
    assert_eq!(file_at(&store, tree, ".env"), ENV);
    assert_eq!(opened.unsealed, 1);
    let again = fetch(&remote, &store, None, &mut state).unwrap();
    assert_eq!(tip(&again), tip(&opened));
    assert_eq!(again.unsealed, 0);
}

#[test]
fn built_in_floor_keeps_env_private_without_and_after_deleting_private() {
    let mut repo = repo();
    let rev = save(&mut repo, &[(".env", ENV), ("src/main.rs", MAIN)], &[]);
    let env_id = blob_of(&repo, rev, ".env");
    let alice = Identity::generate().unwrap();
    let (dir, remote) = remote_at([2; 16]);
    let mut state = PublishState::new();
    let report = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    let keys = report.new_owner_keys.unwrap();
    assert_eq!(public_kind(&remote, ".env"), EntryKind::Sealed);
    assert_eq!(public_kind(&remote, "src/main.rs"), EntryKind::File);

    let rev = save_child(&mut repo, &[(".private", b"# notes\n")], &[]);
    publish_at(
        &repo,
        &remote,
        &alice,
        Some(&keys),
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    assert_eq!(public_kind(&remote, ".env"), EntryKind::Sealed);

    let rev = save_child(&mut repo, &[], &[".private"]);
    publish_at(
        &repo,
        &remote,
        &alice,
        Some(&keys),
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    assert_eq!(public_kind(&remote, ".env"), EntryKind::Sealed);
    assert_eq!(public_kind(&remote, "src/main.rs"), EntryKind::File);

    let mut needles = vec![ENV.to_vec()];
    needles.extend(id_needles(env_id));
    assert_hidden(&files_of(dir.path()), &needles);

    let mut fetch_state = FetchState::new();
    let (store, report) = fetch_new(&remote, None, &mut fetch_state).unwrap();
    let got = store.get_revision(&tip(&report)).unwrap();
    assert_eq!(kind_at(&store, got.tree, ".env"), Some(EntryKind::Sealed));
    assert_eq!(file_at(&store, got.tree, "src/main.rs"), MAIN);
    assert_eq!(report.unsealed, 0);
    assert!(report.still_sealed >= 1);
}

#[test]
fn already_leaked_path_writes_nothing_until_acknowledged() {
    let mut repo = repo();
    let rev = save(
        &mut repo,
        &[("README.md", b"public notes\n"), ("src/main.rs", MAIN)],
        &[],
    );
    let alice = Identity::generate().unwrap();
    let (dir, remote) = remote_at([3; 16]);
    let mut state = PublishState::new();
    let report = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    let keys = report.new_owner_keys.unwrap();
    let saved = state.clone();
    let before = files_of(dir.path());

    let rev = save_child(&mut repo, &[(".private", b"README.md\n")], &[]);
    let err = publish_at(
        &repo,
        &remote,
        &alice,
        Some(&keys),
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap_err();
    match err {
        PublishError::AlreadyLeaked { paths } => {
            assert_eq!(paths.len(), 1);
            assert_eq!(paths[0].as_str(), "README.md");
        }
        other => panic!("expected a leak refusal, got {other}"),
    }
    assert_eq!(state, saved);
    assert_eq!(files_of(dir.path()), before);

    let report = publish_at(
        &repo,
        &remote,
        &alice,
        Some(&keys),
        &mut state,
        rev,
        &PublishOptions {
            acknowledge_leaked: true,
            ..PublishOptions::default()
        },
    )
    .unwrap();
    assert!(report
        .warnings
        .iter()
        .any(|warning| warning.contains("README.md")));
    assert_eq!(public_kind(&remote, "README.md"), EntryKind::Sealed);
}

#[test]
fn pasted_secret_writes_nothing() {
    let mut repo = repo();
    let rev = save(&mut repo, &[(".env", ENV), ("src/copied.rs", ENV)], &[]);
    let alice = Identity::generate().unwrap();
    let (dir, remote) = remote_at([4; 16]);
    let before = files_of(dir.path());
    let mut state = PublishState::new();
    let saved = state.clone();
    let err = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap_err();
    match err {
        PublishError::PastedSecret { pastes } => {
            assert_eq!(pastes.len(), 1);
            assert_eq!(pastes[0].public_path.as_str(), "src/copied.rs");
            assert_eq!(pastes[0].private_path.as_str(), ".env");
        }
        other => panic!("expected a paste refusal, got {other}"),
    }
    assert_eq!(state, saved);
    assert_eq!(files_of(dir.path()), before);
    assert!(!dir.path().join("keyring").exists());
}

#[test]
fn unconfirmed_negation_writes_nothing_until_confirmed() {
    let mut repo = repo();
    let rev = save(
        &mut repo,
        &[
            (".private", b"!.env\n"),
            (".env", ENV),
            ("src/main.rs", MAIN),
        ],
        &[],
    );
    let alice = Identity::generate().unwrap();
    let (dir, remote) = remote_at([5; 16]);
    let before = files_of(dir.path());
    let mut state = PublishState::new();
    let saved = state.clone();
    let err = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap_err();
    match err {
        PublishError::NegationNeedsConfirmation { paths } => {
            assert_eq!(paths.len(), 1);
            assert_eq!(paths[0].as_str(), ".env");
        }
        other => panic!("expected a negation refusal, got {other}"),
    }
    assert_eq!(state, saved);
    assert_eq!(files_of(dir.path()), before);
    assert!(!dir.path().join("keyring").exists());

    let report = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions {
            confirm_negations: true,
            ..PublishOptions::default()
        },
    )
    .unwrap();
    let keys = report.new_owner_keys.unwrap();
    assert!(state.confirmed_negations.contains(&p(".env")));
    assert_eq!(public_kind(&remote, ".env"), EntryKind::File);
    assert_eq!(
        file_at(
            remote.public_store(),
            remote
                .public_store()
                .get_revision(&remote.read_refs().unwrap()["main"])
                .unwrap()
                .tree,
            ".env"
        ),
        ENV
    );

    let rev = save_child(&mut repo, &[("src/main.rs", MAIN_V2)], &[]);
    publish_at(
        &repo,
        &remote,
        &alice,
        Some(&keys),
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
}

#[test]
fn incremental_republish_writes_only_new_objects() {
    let mut repo = repo();
    let rev = save(
        &mut repo,
        &[
            (".private", RULES),
            (".env", ENV),
            ("secrets/a.key", KEY),
            ("src/main.rs", MAIN),
        ],
        &[],
    );
    let env_id = blob_of(&repo, rev, ".env");
    let key_id = blob_of(&repo, rev, "secrets/a.key");
    let alice = Identity::generate().unwrap();
    let (dir, remote) = remote_at([6; 16]);
    let mut state = PublishState::new();
    let report = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    let keys = report.new_owner_keys.unwrap();
    let before = files_of(dir.path());

    let rev = save_child(&mut repo, &[("src/main.rs", MAIN_V2)], &[]);
    let report = publish_at(
        &repo,
        &remote,
        &alice,
        Some(&keys),
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    assert_eq!(report.revisions_published, 1);
    assert_eq!(report.private_objects_sealed, 0);
    assert!(report.public_objects_written > 0);
    assert!(report.new_owner_keys.is_none());

    let after = files_of(dir.path());
    for (path, bytes) in &before {
        if path == Path::new("refs") {
            continue;
        }
        assert_eq!(after.get(path).unwrap(), bytes, "{}", path.display());
    }
    let mut new_objects = 0usize;
    let mut new_packs = 0usize;
    for path in after.keys() {
        if before.contains_key(path) {
            continue;
        }
        if under(path, "objects") {
            new_objects += 1;
        } else if under(path, "packs") {
            new_packs += 1;
        } else {
            panic!("unexpected new file {}", path.display());
        }
    }
    assert_eq!(new_objects, report.public_objects_written);
    assert_eq!(new_packs, 1);

    let mut needles = vec![ENV.to_vec(), KEY.to_vec(), b"a.key".to_vec()];
    needles.extend(id_needles(env_id));
    needles.extend(id_needles(key_id));
    assert_hidden(&after, &needles);
}

#[test]
fn revoked_member_reads_old_revisions_but_not_the_new_pack() {
    let mut repo = repo();
    let rev1 = save(
        &mut repo,
        &[
            (".private", RULES),
            (".env", ENV),
            ("secrets/a.key", KEY),
            ("src/main.rs", MAIN),
        ],
        &[],
    );
    let old_env = blob_of(&repo, rev1, ".env");
    let alice_tree = repo.revision(&rev1).unwrap().tree;
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let (dir, remote) = remote_at([7; 16]);
    let mut state = PublishState::new();
    let report = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev1,
        &PublishOptions::default(),
    )
    .unwrap();
    let mut owner_keys = report.new_owner_keys.unwrap();
    grant(&remote, &owner_keys, &alice, &bob);

    let mut bob_state = FetchState::new();
    let (bob_store, bob_report) = fetch_new(&remote, Some(&bob), &mut bob_state).unwrap();
    assert_eq!(
        bob_store.get_revision(&tip(&bob_report)).unwrap().tree,
        alice_tree
    );

    let mut keyring = Keyring::decode(&remote.read_keyring().unwrap()).unwrap();
    keyring
        .revoke(&mut owner_keys, &alice, &bob.public())
        .unwrap();
    remote.write_keyring(&keyring.encode().unwrap()).unwrap();

    let rev2 = save_child(&mut repo, &[(".env", ENV_V2)], &[]);
    let new_env = blob_of(&repo, rev2, ".env");
    assert_ne!(old_env, new_env);
    publish_at(
        &repo,
        &remote,
        &alice,
        Some(&owner_keys),
        &mut state,
        rev2,
        &PublishOptions::default(),
    )
    .unwrap();

    let mut needles = vec![
        ENV.to_vec(),
        ENV_V2.to_vec(),
        KEY.to_vec(),
        b"a.key".to_vec(),
    ];
    needles.extend(id_needles(old_env));
    needles.extend(id_needles(new_env));
    assert_hidden(&files_of(dir.path()), &needles);

    let mut later = FetchState::new();
    later.remote_id = bob_state.remote_id;
    later.owner_signing = bob_state.owner_signing;
    later.counter = bob_state.counter;
    let (store, report) = fetch_new(&remote, Some(&bob), &mut later).unwrap();
    let tip_rev = store.get_revision(&tip(&report)).unwrap();
    assert_eq!(tip_rev.parents.len(), 1);
    let parent = store.get_revision(&tip_rev.parents[0]).unwrap();
    assert_eq!(parent.tree, alice_tree);
    assert_eq!(store.get_blob(&old_env).unwrap(), ENV);
    assert!(matches!(
        store.get_blob(&new_env),
        Err(tig_core::Error::NotFound(_))
    ));
    assert_eq!(
        kind_at(&store, tip_rev.tree, ".env"),
        Some(EntryKind::Sealed)
    );
    assert_eq!(
        kind_at(&store, tip_rev.tree, "secrets"),
        Some(EntryKind::Sealed)
    );
    assert_eq!(
        kind_at(&store, parent.tree, "secrets"),
        Some(EntryKind::Tree)
    );
    assert!(report.unsealed > 0);
    assert!(report.still_sealed > 0);
}

#[test]
fn rolled_back_keyring_is_refused() {
    let mut repo = repo();
    let rev = save(&mut repo, &[("src/main.rs", MAIN)], &[]);
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let (_dir, remote) = remote_at([8; 16]);
    let mut state = PublishState::new();
    let report = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    let keys = report.new_owner_keys.unwrap();
    let old_keyring = remote.read_keyring().unwrap();
    grant(&remote, &keys, &alice, &bob);

    let mut bob_state = FetchState::new();
    fetch_new(&remote, Some(&bob), &mut bob_state).unwrap();
    assert!(bob_state.counter > 1);
    remote.write_keyring(&old_keyring).unwrap();

    let saved = bob_state.clone();
    let err = fetch(&remote, &MemoryStore::new(), Some(&bob), &mut bob_state).unwrap_err();
    assert!(matches!(err, FetchError::Keyring(KeyringError::RolledBack)));
    assert_eq!(bob_state, saved);
}

#[test]
fn substituted_owner_is_refused_after_pinning() {
    let mut repo = repo();
    let rev = save(&mut repo, &[("src/main.rs", MAIN)], &[]);
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let mallory = Identity::generate().unwrap();
    let (_dir, remote) = remote_at([9; 16]);
    let mut state = PublishState::new();
    let report = publish_at(
        &repo,
        &remote,
        &alice,
        None,
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    let _keys = report.new_owner_keys.unwrap();

    let mut bob_state = FetchState::new();
    let (_store, bob_report) = fetch_new(&remote, Some(&bob), &mut bob_state).unwrap();
    assert_eq!(
        bob_report.newly_pinned.as_deref(),
        Some(alice.public().fingerprint().as_str())
    );

    let (forged, _) = Keyring::create(remote.remote_id(), &mallory).unwrap();
    remote.write_keyring(&forged.encode().unwrap()).unwrap();
    let saved = bob_state.clone();
    let err = fetch(&remote, &MemoryStore::new(), Some(&bob), &mut bob_state).unwrap_err();
    match err {
        FetchError::Keyring(KeyringError::Invalid(reason)) => {
            let lower = reason.to_lowercase();
            assert!(lower.contains("pin") || lower.contains("owner"), "{reason}");
        }
        other => panic!("expected a pin refusal, got {other}"),
    }
    assert_eq!(bob_state, saved);
    assert_eq!(bob_state.owner_signing, Some(alice.public().signing));
}

#[test]
fn first_publish_requires_keys_the_caller_can_save_before_remote_writes() {
    let mut repo = repo();
    let rev = save(&mut repo, &[(".env", ENV)], &[]);
    let owner = Identity::generate().unwrap();
    let (dir, remote) = remote_at([21; 16]);
    let before = files_of(dir.path());
    let mut state = PublishState::new();
    let result = publish(
        repo.store().as_ref(),
        &remote,
        &owner,
        None,
        &mut state,
        "main",
        rev,
        &PublishOptions::default(),
    );
    assert!(
        result.is_err(),
        "minting inside publish can lose the only epoch key on a crash"
    );
    assert_eq!(files_of(dir.path()), before);
    assert_eq!(state, PublishState::new());
}

#[test]
fn revoke_retries_after_only_owner_keys_reached_disk() {
    let owner = Identity::generate().unwrap();
    let member = Identity::generate().unwrap();
    let (mut ring, mut keys) = Keyring::create([22; 16], &owner).unwrap();
    ring.grant(&keys, &owner, &member.public()).unwrap();
    let old_ring = ring.encode().unwrap();
    ring.revoke(&mut keys, &owner, &member.public()).unwrap();
    let saved_keys = keys.encode().unwrap();
    // Crash after saving keys, before writing the new remote keyring.
    let mut retried = Keyring::decode(&old_ring).unwrap();
    let mut restored = OwnerKeys::decode(&saved_keys).unwrap();
    retried
        .revoke(&mut restored, &owner, &member.public())
        .unwrap();
    assert_eq!(
        restored.encode().unwrap(),
        saved_keys,
        "never replace an existing epoch secret"
    );
    assert_eq!(retried.head.epochs["private"], 2);
    assert!(matches!(
        retried
            .verify(&owner.public().signing, 0)
            .unwrap()
            .current_key("private", &member),
        Err(KeyringError::NotMember)
    ));
}

#[test]
fn all_remote_bytes_hide_multi_branch_rename_delete_readd_history() {
    let mut repo = repo();
    let owner = Identity::generate().unwrap();
    let (dir, remote) = remote_at([23; 16]);
    let (_, keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
    let mut state = PublishState::new();
    let mut needles = vec![
        ENV.to_vec(),
        KEY.to_vec(),
        ENV_V2.to_vec(),
        b"hidden-first-name".to_vec(),
        b"hidden-renamed-name".to_vec(),
    ];
    let first = save(
        &mut repo,
        &[
            (".private", b"secrets/\n"),
            (".env", ENV),
            ("secrets/hidden-first-name", KEY),
            ("public", MAIN),
        ],
        &[],
    );
    let renamed = save_child(
        &mut repo,
        &[("secrets/hidden-renamed-name", KEY)],
        &["secrets/hidden-first-name"],
    );
    let deleted = save_child(&mut repo, &[], &["secrets/hidden-renamed-name", ".env"]);
    let readded = save_child(
        &mut repo,
        &[(".env", ENV_V2), ("secrets/hidden-first-name", KEY)],
        &[],
    );
    for rev in [first, renamed, deleted, readded] {
        needles.extend(id_needles(rev));
        let tree = repo.revision(&rev).unwrap().tree;
        if lookup(repo.store().as_ref(), &tree, &p(".env"))
            .unwrap()
            .is_some()
            || lookup(repo.store().as_ref(), &tree, &p("secrets"))
                .unwrap()
                .is_some()
        {
            needles.extend(id_needles(tree));
        }
        if let Some(leaf) = lookup(repo.store().as_ref(), &tree, &p("secrets")).unwrap() {
            needles.extend(id_needles(leaf.id()));
        }
    }
    needles.extend(id_needles(blob_of(&repo, first, ".env")));
    needles.extend(id_needles(blob_of(
        &repo,
        first,
        "secrets/hidden-first-name",
    )));
    needles.extend(id_needles(blob_of(&repo, readded, ".env")));
    for (id, operation) in repo.op_log(100).unwrap() {
        needles.extend(id_needles(id));
        needles.extend(id_needles(operation.view));
    }
    publish_at(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        readded,
        &PublishOptions::default(),
    )
    .unwrap();
    let mut tx = repo.start("branch from first revision");
    let branch = tx.new_change(&[first], "other branch").unwrap();
    tx.set_working(DEFAULT_WORKSPACE, branch).unwrap();
    repo.commit(tx).unwrap();
    // A negation makes only a README public, so secret child names remain hidden.
    let branch = save(
        &mut repo,
        &[
            (".private", b"secrets/\n!notes/README\n"),
            ("notes/README", b"public notes"),
            (".env", ENV_V2),
        ],
        &[],
    );
    publish(
        repo.store().as_ref(),
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        "other",
        branch,
        &PublishOptions {
            confirm_negations: true,
            ..PublishOptions::default()
        },
    )
    .unwrap();
    // Deleting .private cannot defeat the floor; secrets/ is absent here.
    let floor = save_child(&mut repo, &[("public", MAIN_V2)], &[".private", "secrets"]);
    publish_at(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        floor,
        &PublishOptions::default(),
    )
    .unwrap();
    let files = files_of(dir.path());
    assert_hidden(&files, &needles);
    // Also scan decompressed public bodies: compression cannot hide a leak
    // from this assertion. Packs stay encrypted and get the raw-byte scan.
    for path in files.keys().filter(|path| under(path, "objects")) {
        let hex: String = path.components().skip(1)
            .map(|part| part.as_os_str().to_string_lossy()).collect();
        if let Ok(id) = hex.parse::<ObjectId>() {
            let (_, body) = remote.public_store().get_raw(&id).unwrap().unwrap();
            for needle in &needles {
                assert!(!contains(&body, needle), "public object {id} contains a private needle");
            }
        }
    }
    let (outsider, report) = fetch_new(&remote, None, &mut FetchState::new()).unwrap();
    let tree = outsider.get_revision(&tip(&report)).unwrap().tree;
    assert_eq!(kind_at(&outsider, tree, ".env"), Some(EntryKind::Sealed));
    assert_eq!(report.refs.len(), 2);
}

#[test]
fn revoked_members_cannot_open_new_seals_even_when_blobs_deduplicate() {
    let mut repo = repo();
    let rev = save(&mut repo, &[(".env", ENV)], &[]);
    let owner = Identity::generate().unwrap();
    let member = Identity::generate().unwrap();
    let (_dir, remote) = remote_at([24; 16]);
    let (mut ring, mut keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
    ring.grant(&keys, &owner, &member.public()).unwrap();
    remote.write_keyring(&ring.encode().unwrap()).unwrap();
    let mut state = PublishState::new();
    publish_at(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    ring.revoke(&mut keys, &owner, &member.public()).unwrap();
    remote.write_keyring(&ring.encode().unwrap()).unwrap();
    let next = save_child(&mut repo, &[("copy.key", ENV), ("public", MAIN)], &[]);
    publish_at(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        next,
        &PublishOptions::default(),
    )
    .unwrap();
    let (store, report) = fetch_new(&remote, Some(&member), &mut FetchState::new()).unwrap();
    let tree = store.get_revision(&tip(&report)).unwrap().tree;
    for path in [".env", "copy.key"] {
        assert_eq!(kind_at(&store, tree, path), Some(EntryKind::Sealed));
    }
    let old_key = ring
        .verify(&owner.public().signing, 0)
        .unwrap()
        .key_for("private", 1, &member)
        .unwrap();
    for pack in remote.list_packs("private", 2).unwrap() {
        assert!(tig_private::pack::Pack::open(&pack, &old_key).is_err());
    }
}

#[test]
fn malformed_keyrings_refs_and_portable_path_tricks_leave_fetch_state_unchanged() {
    use tig_core::encode::Writer;
    use tig_core::{Object, ObjectKind};
    let owner = Identity::generate().unwrap();
    let (dir, remote) = remote_at([25; 16]);
    let (ring, _) = Keyring::create(remote.remote_id(), &owner).unwrap();
    let good_ring = ring.encode().unwrap();
    for bytes in [
        vec![],
        vec![255],
        vec![1, 255, 255, 255],
        good_ring[..80].to_vec(),
    ] {
        remote.write_keyring(&bytes).unwrap();
        let mut state = FetchState::new();
        assert!(fetch(&remote, &MemoryStore::new(), None, &mut state).is_err());
        assert_eq!(state, FetchState::new());
    }
    remote.write_keyring(&good_ring).unwrap();
    let mut huge = Writer::new();
    huge.u8(1);
    huge.varint(u64::MAX);
    std::fs::write(dir.path().join("refs"), huge.finish()).unwrap();
    assert!(fetch(&remote, &MemoryStore::new(), None, &mut FetchState::new()).is_err());
    for name in ["../outside", ".TiG", "C:escape", "x\\escape", ".env."] {
        let mut tree = Writer::new();
        tree.u8(1);
        tree.varint(1);
        tree.u8(EntryKind::File as u8);
        tree.str(name);
        tree.id(&tig_core::object::hash_object(ObjectKind::Blob, MAIN));
        let bytes = tree.finish();
        let tree_id = tig_core::object::hash_object(ObjectKind::Tree, &bytes);
        remote
            .public_store()
            .put_raw(&tree_id, ObjectKind::Tree, &bytes)
            .unwrap();
        let mut rev = tig_core::repo::root_revision();
        rev.tree = tree_id;
        let id = remote.public_store().put(&Object::Revision(rev)).unwrap();
        remote
            .write_refs(&BTreeMap::from([("main".into(), id)]))
            .unwrap();
        let mut state = FetchState::new();
        assert!(
            fetch(&remote, &MemoryStore::new(), None, &mut state).is_err(),
            "{name}"
        );
        assert_eq!(state, FetchState::new());
    }
}

#[test]
fn authenticated_seal_with_a_missing_target_is_refused() {
    use tig_core::{Object, ObjectKind, Tree, TreeEntry};
    use tig_private::pack::PackBuilder;
    let owner = Identity::generate().unwrap();
    let (_dir, remote) = remote_at([26; 16]);
    let (ring, keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
    remote.write_keyring(&ring.encode().unwrap()).unwrap();
    let key = &keys.keys[&("private".into(), 1)];
    let missing = tig_core::object::hash_object(ObjectKind::Blob, ENV);
    let sid = key.seal(&p(".env"), EntryKind::File, &missing);
    let mut pack = PackBuilder::new(key);
    pack.add_sealed(sid, p(".env"), EntryKind::File, missing)
        .unwrap();
    remote.put_pack(&pack.finish().unwrap()).unwrap();
    let tree = Tree::new(vec![TreeEntry::sealed(".env", sid).unwrap()]).unwrap();
    let tree_id = remote.public_store().put(&Object::Tree(tree)).unwrap();
    let mut rev = tig_core::repo::root_revision();
    rev.tree = tree_id;
    let id = remote.public_store().put(&Object::Revision(rev)).unwrap();
    remote
        .write_refs(&BTreeMap::from([("main".into(), id)]))
        .unwrap();
    let mut state = FetchState::new();
    assert!(fetch(&remote, &MemoryStore::new(), Some(&owner), &mut state).is_err());
    assert_eq!(state, FetchState::new());
}

#[test]
fn public_rules_can_disclose_a_name_inside_a_sealed_root() {
    let mut repo = repo();
    let rev = save(
        &mut repo,
        &[
            (".private", b"secrets/\nsecrets/named-in-rules\n"),
            ("secrets/named-in-rules", ENV),
        ],
        &[],
    );
    let owner = Identity::generate().unwrap();
    let (dir, remote) = remote_at([27; 16]);
    publish_at(
        &repo,
        &remote,
        &owner,
        None,
        &mut PublishState::new(),
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    assert_eq!(public_kind(&remote, "secrets"), EntryKind::Sealed);
    // Contract requires .private to be public. Name confidentiality therefore
    // excludes names explicitly written in this public metadata.
    assert!(files_of(dir.path())
        .values()
        .any(|bytes| contains(bytes, b"named-in-rules")));
}

#[test]
fn withheld_packs_are_currently_indistinguishable_from_foreign_seals() {
    let mut repo = repo();
    let rev = save(&mut repo, &[(".env", ENV)], &[]);
    let owner = Identity::generate().unwrap();
    let (dir, remote) = remote_at([28; 16]);
    publish_at(
        &repo,
        &remote,
        &owner,
        None,
        &mut PublishState::new(),
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    for entry in std::fs::read_dir(dir.path().join("packs/private/1")).unwrap() {
        std::fs::remove_file(entry.unwrap().path()).unwrap();
    }
    let (_store, report) = fetch_new(&remote, Some(&owner), &mut FetchState::new()).unwrap();
    assert_eq!(report.unsealed, 0);
    assert_eq!(report.still_sealed, 1);
}

#[test]
fn hostile_pack_bytes_and_cross_remote_replay_fail_without_accepting_state() {
    let mut repo = repo();
    let rev = save(&mut repo, &[(".env", ENV)], &[]);
    let owner = Identity::generate().unwrap();
    let (dir, remote) = remote_at([29; 16]);
    publish_at(
        &repo,
        &remote,
        &owner,
        None,
        &mut PublishState::new(),
        rev,
        &PublishOptions::default(),
    )
    .unwrap();
    let pack_path = std::fs::read_dir(dir.path().join("packs/private/1"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let good = std::fs::read(&pack_path).unwrap();
    let mut tampered = good.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 1;
    for bytes in [
        b"TIGP\x01".to_vec(),
        vec![255; 100],
        tampered,
        good[..good.len() / 2].to_vec(),
    ] {
        std::fs::write(&pack_path, bytes).unwrap();
        let mut state = FetchState::new();
        assert!(fetch(&remote, &MemoryStore::new(), Some(&owner), &mut state).is_err());
        assert_eq!(state, FetchState::new());
    }
    let (_other_dir, other) = remote_at([30; 16]);
    other
        .write_keyring(&remote.read_keyring().unwrap())
        .unwrap();
    assert!(fetch(
        &other,
        &MemoryStore::new(),
        Some(&owner),
        &mut FetchState::new()
    )
    .is_err());
    assert!(other.put_pack(&good).is_err());
}

#[test]
fn historical_private_bytes_need_explicit_declassification() {
    let mut repo = repo();
    let owner = Identity::generate().unwrap();
    let (dir, remote) = remote_at([31; 16]);
    let mut state = PublishState::new();
    let first = save(&mut repo, &[(".env", ENV)], &[]);
    let keys = publish_at(&repo, &remote, &owner, None, &mut state, first,
        &PublishOptions::default()).unwrap().new_owner_keys.unwrap();
    // The secret was sealed; deleting `.env` and reusing its bytes in a
    // public file must not let them out.
    let renamed = save_child(&mut repo, &[("public-copy", ENV)], &[".env"]);
    let before = files_of(dir.path());
    let err = publish_at(&repo, &remote, &owner, Some(&keys), &mut state, renamed,
        &PublishOptions::default()).unwrap_err();
    assert!(matches!(err, PublishError::PreviouslyPrivate { ref paths } if paths.len() == 1), "{err}");
    assert_eq!(files_of(dir.path()), before, "a refusal writes nothing");
    assert!(!files_of(dir.path()).values().any(|bytes| contains(bytes, ENV)));
    // Declassifying a different path does not help; naming this one does.
    let wrong = PublishOptions { declassify: [RepoPath::new("other").unwrap()].into(), ..Default::default() };
    assert!(publish_at(&repo, &remote, &owner, Some(&keys), &mut state, renamed, &wrong).is_err());
    let right = PublishOptions { declassify: [RepoPath::new("public-copy").unwrap()].into(), ..Default::default() };
    publish_at(&repo, &remote, &owner, Some(&keys), &mut state, renamed, &right).unwrap();
    assert!(files_of(dir.path()).values().any(|bytes| contains(bytes, ENV)));
}

#[test]
fn rename_inside_an_unpublished_window_is_also_refused() {
    let mut repo = repo();
    let owner = Identity::generate().unwrap();
    let (dir, remote) = remote_at([32; 16]);
    let mut state = PublishState::new();
    // Sealed in one revision, renamed public in the next; neither was
    // published yet, so publish sees both at once.
    save(&mut repo, &[(".env", ENV)], &[]);
    let renamed = save_child(&mut repo, &[("public-copy", ENV)], &[".env"]);
    let err = publish_at(&repo, &remote, &owner, None, &mut state, renamed,
        &PublishOptions::default()).unwrap_err();
    assert!(matches!(err, PublishError::PreviouslyPrivate { .. }), "{err}");
    assert!(!files_of(dir.path()).values().any(|bytes| contains(bytes, ENV)));
}
