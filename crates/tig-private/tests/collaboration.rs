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
use tig_private::fetch::{fetch, fetch_into, FetchState};
use tig_private::keyring::OwnerKeys;
use tig_private::keys::Identity;
use tig_private::manifest::Manifest;
use tig_private::publish::{publish, PublishError, PublishOptions, PublishState};
use tig_private::remote::{CommitOutcome, DirRemote, HeadVersion};

/// Inject a single deterministic race or malformed batch reply.
struct Intercept<'a> {
    remote: &'a DirRemote,
    before_commit: std::sync::Mutex<Option<Box<dyn FnOnce() + Send + 'a>>>,
    reply: u8,
}

impl tig_private::remote::Remote for Intercept<'_> {
    fn remote_id(&self) -> [u8; 16] {
        self.remote.remote_id()
    }
    fn public_store(&self) -> &dyn tig_core::Store {
        self.remote.public_store()
    }
    fn missing(&self, ids: &[ObjectId]) -> Result<Vec<ObjectId>, tig_private::remote::RemoteError> {
        let mut got = self.remote.missing(ids)?;
        if self.reply == 3 {
            got.push(ObjectId([99; 32]));
        }
        if self.reply == 4 && !got.is_empty() {
            got.push(got[0]);
        }
        Ok(got)
    }
    fn put_batch(
        &self,
        objects: &[(ObjectId, tig_core::ObjectKind, Vec<u8>)],
    ) -> Result<(), tig_private::remote::RemoteError> {
        self.remote.put_batch(objects)
    }
    fn get_batch(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<(ObjectId, tig_core::ObjectKind, Vec<u8>)>, tig_private::remote::RemoteError>
    {
        let mut got = self.remote.get_batch(ids)?;
        if self.reply == 1 {
            let obj = tig_core::Object::Blob(b"unsolicited".to_vec());
            got.push((obj.id(), obj.kind(), obj.encode_body()));
        }
        if self.reply == 2 && !got.is_empty() {
            got.push(got[0].clone());
        }
        Ok(got)
    }
    fn put_pack(&self, bytes: &[u8]) -> Result<(), tig_private::remote::RemoteError> {
        if self.reply == 6 {
            if let Some(action) = self.before_commit.lock().unwrap().take() {
                action();
            }
        }
        self.remote.put_pack(bytes)
    }
    fn list_packs(
        &self,
        group: &str,
        epoch: u64,
    ) -> Result<Vec<Vec<u8>>, tig_private::remote::RemoteError> {
        self.remote.list_packs(group, epoch)
    }
    fn read_head(
        &self,
    ) -> Result<tig_private::remote::RemoteHead, tig_private::remote::RemoteError> {
        self.remote.read_head()
    }
    fn commit_head(
        &self,
        expected: &HeadVersion,
        keyring: Option<&[u8]>,
        manifest: Option<&[u8]>,
    ) -> Result<CommitOutcome, tig_private::remote::RemoteError> {
        if self.reply == 5 {
            return Ok(CommitOutcome::Stale(self.remote.read_head()?));
        }
        if let Some(action) = self.before_commit.lock().unwrap().take() {
            action();
        }
        self.remote.commit_head(expected, keyring, manifest)
    }
}

fn intercept(remote: &DirRemote, reply: u8) -> Intercept<'_> {
    Intercept {
        remote,
        before_commit: std::sync::Mutex::new(None),
        reply,
    }
}

#[test]
fn access_retries_a_publish_without_advancing_uncommitted_floors() {
    for revoke in [false, true] {
        let mut repo = repo();
        let rev = save(&mut repo, &[("public", b"base")]);
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::create(dir.path(), [71; 16]).unwrap();
        let owner = Identity::generate().unwrap();
        let mut keys = owner_keys(&remote, &owner);
        let mut state = PublishState::new();
        publish_rev(
            &repo,
            &remote,
            &owner,
            Some(&keys),
            &mut state,
            &FetchState::new(),
            "main",
            rev,
            false,
        )
        .unwrap();
        let member = Identity::generate().unwrap();
        if revoke {
            grant_member(&remote, &owner, &keys, &state, &member);
        }
        let race = Intercept {
            remote: &remote,
            reply: 0,
            before_commit: std::sync::Mutex::new(Some(Box::new(|| {
                let head = remote.read_head().unwrap();
                let old = Manifest::decode(head.manifest.as_ref().unwrap()).unwrap();
                let next = Manifest::signed(
                    remote.remote_id(),
                    old.sequence + 1,
                    old.refs,
                    old.packs,
                    &owner,
                )
                .unwrap()
                .encode()
                .unwrap();
                assert!(matches!(
                    remote
                        .commit_head(&head.version(), None, Some(&next))
                        .unwrap(),
                    CommitOutcome::Committed(_)
                ));
            }))),
        };
        let local = tempfile::tempdir().unwrap();
        let result = if revoke {
            access::revoke(
                &race,
                local.path(),
                &owner,
                &mut keys,
                &mut state,
                &member.public(),
            )
        } else {
            access::grant(
                &race,
                local.path(),
                &owner,
                &keys,
                &mut state,
                &member.public(),
            )
        };
        result.unwrap();
        assert_eq!(state.counter, manifest_counter(&remote));
        assert_eq!(state.manifest_seq, manifest(&remote).sequence);
        assert!(!local.path().join("pending-keyring").exists());
    }
}

#[test]
fn pending_revoke_cannot_replace_a_competing_revoke_at_the_same_counter() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [72; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let (mut ring, mut keys) =
        tig_private::keyring::Keyring::create(remote.remote_id(), &owner).unwrap();
    ring.grant(&keys, &owner, &alice.public()).unwrap();
    ring.grant(&keys, &owner, &bob.public()).unwrap();
    let mut pending = ring.clone();
    pending.revoke(&mut keys, &owner, &alice.public()).unwrap();
    let mut competing_keys = OwnerKeys::decode(&keys.encode().unwrap()).unwrap();
    ring.revoke(&mut competing_keys, &owner, &bob.public())
        .unwrap();
    let head = remote.read_head().unwrap();
    remote
        .commit_head(&head.version(), Some(&ring.encode().unwrap()), None)
        .unwrap();
    let local = tempfile::tempdir().unwrap();
    let mut state = PublishState::new();
    state.remote_id = remote.remote_id();
    state.owner_signing = Some(owner.public().signing);
    state.counter = ring.head.counter;
    write_owner(local.path(), &keys, &state);
    fs::write(
        local.path().join("pending-keyring"),
        pending.encode().unwrap(),
    )
    .unwrap();
    let error = access::finish_pending(&remote, local.path(), &owner, &mut state).unwrap_err();
    assert!(error.to_string().contains("superseded"), "{error}");
    assert_eq!(remote.read_keyring().unwrap(), ring.encode().unwrap());
    assert!(!local.path().join("pending-keyring").exists());
}

#[test]
fn fetch_rejects_unrequested_and_duplicate_batch_objects() {
    let mut repo = repo();
    let rev = save(&mut repo, &[("public", b"base")]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [73; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut published = PublishState::new();
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut published,
        &FetchState::new(),
        "main",
        rev,
        false,
    )
    .unwrap();
    for reply in [1, 2] {
        let mut state = FetchState::new();
        assert!(fetch(
            &intercept(&remote, reply),
            &tig_core::MemoryStore::new(),
            None,
            &mut state,
            &PublishState::new()
        )
        .is_err());
        assert_eq!(state, FetchState::new());
    }
}

#[test]
fn publish_rejects_unrequested_and_duplicate_missing_ids() {
    for reply in [3, 4] {
        let mut repo = repo();
        let rev = save(&mut repo, &[("public", b"base")]);
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::create(dir.path(), [74; 16]).unwrap();
        let owner = Identity::generate().unwrap();
        let keys = owner_keys(&remote, &owner);
        let mut state = PublishState::new();
        assert!(publish(
            repo.store().as_ref(),
            &intercept(&remote, reply),
            &owner,
            Some(&keys),
            &mut state,
            &FetchState::new(),
            "main",
            rev,
            &PublishOptions::default()
        )
        .is_err());
        assert_eq!(state, PublishState::new());
        assert!(!remote
            .public_store()
            .has(&tig_core::repo::root_revision_id())
            .unwrap());
    }
}

#[test]
fn predecessor_rewrite_cannot_drop_a_published_parent() {
    let mut repo = repo();
    let base = save(&mut repo, &[("public", b"base")]);
    let child = save_child(&mut repo, &[("public", b"child")]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [75; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut state = PublishState::new();
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        &FetchState::new(),
        "main",
        base,
        false,
    )
    .unwrap();
    let mut rewritten = repo.store().get_revision(&child).unwrap();
    rewritten.parents = vec![tig_core::repo::root_revision_id()];
    rewritten.predecessors = vec![child];
    let rewritten = repo
        .store()
        .put(&tig_core::Object::Revision(rewritten))
        .unwrap();
    let before = remote.read_head().unwrap();
    assert!(matches!(
        publish_rev(
            &repo,
            &remote,
            &owner,
            Some(&keys),
            &mut state,
            &FetchState::new(),
            "main",
            rewritten,
            false
        ),
        Err(PublishError::NotFastForward { .. })
    ));
    assert_eq!(remote.read_head().unwrap(), before);
}

#[test]
fn predecessor_publish_warns_for_every_replaced_published_change() {
    let mut repo = repo();
    let base = save(&mut repo, &[("public", b"base")]);
    let child = save_child(&mut repo, &[("public", b"child")]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [76; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut state = PublishState::new();
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        &FetchState::new(),
        "main",
        child,
        false,
    )
    .unwrap();
    let mut rewritten_base = repo.store().get_revision(&base).unwrap();
    rewritten_base.description = "rewritten base".into();
    rewritten_base.predecessors = vec![base];
    let base_change = rewritten_base.change_id.short(8);
    let new_base = repo
        .store()
        .put(&tig_core::Object::Revision(rewritten_base))
        .unwrap();
    let mut rewritten_child = repo.store().get_revision(&child).unwrap();
    rewritten_child.parents = vec![new_base];
    rewritten_child.predecessors = vec![child];
    let child_change = rewritten_child.change_id.short(8);
    let new_child = repo
        .store()
        .put(&tig_core::Object::Revision(rewritten_child))
        .unwrap();
    let report = publish(
        repo.store().as_ref(),
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        &FetchState::new(),
        "main",
        new_child,
        &PublishOptions::default(),
    )
    .unwrap();
    for change in [base_change, child_change] {
        assert!(
            report.warnings.iter().any(|warning| warning
                .contains(&format!("rewrites published change `{change}`"))
                && warning.contains("collaborators who built on it must rebase")),
            "{:?}",
            report.warnings
        );
    }
}

#[test]
fn fetch_uses_the_publish_manifest_rollback_floor() {
    let mut repo = repo();
    let base = save(&mut repo, &[("public", b"base")]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [77; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut published = PublishState::new();
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut published,
        &FetchState::new(),
        "main",
        base,
        false,
    )
    .unwrap();
    let old = remote.read_manifest().unwrap().unwrap();
    let child = save_child(&mut repo, &[("public", b"child")]);
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut published,
        &FetchState::new(),
        "main",
        child,
        false,
    )
    .unwrap();
    let head = remote.read_head().unwrap();
    remote
        .commit_head(&head.version(), None, Some(&old))
        .unwrap();
    let mut fetched = FetchState::new();
    assert!(fetch(
        &remote,
        repo.store().as_ref(),
        None,
        &mut fetched,
        &published
    )
    .is_err());
    assert_eq!(fetched, FetchState::new());
}

#[test]
fn publish_uses_the_fetch_manifest_rollback_floor() {
    let mut repo = repo();
    let base = save(&mut repo, &[("public", b"base")]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [79; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut published = PublishState::new();
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut published,
        &FetchState::new(),
        "main",
        base,
        false,
    )
    .unwrap();
    let old = remote.read_head().unwrap();
    let child = save_child(&mut repo, &[("public", b"child")]);
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut published,
        &FetchState::new(),
        "main",
        child,
        false,
    )
    .unwrap();
    let mut fetched = FetchState::new();
    fetch(
        &remote,
        repo.store().as_ref(),
        Some(&owner),
        &mut fetched,
        &published,
    )
    .unwrap();
    let head = remote.read_head().unwrap();
    remote
        .commit_head(&head.version(), None, old.manifest.as_deref())
        .unwrap();
    let mut fresh = PublishState::new();
    assert!(publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut fresh,
        &fetched,
        "side",
        child,
        false
    )
    .is_err());
    assert_eq!(fresh, PublishState::new());
}

#[test]
fn pending_recovery_respects_the_committed_counter_floor() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [80; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let (mut ring, keys) =
        tig_private::keyring::Keyring::create(remote.remote_id(), &owner).unwrap();
    let old = ring.encode().unwrap();
    ring.grant(&keys, &owner, &Identity::generate().unwrap().public())
        .unwrap();
    let pending = ring.encode().unwrap();
    ring.grant(&keys, &owner, &Identity::generate().unwrap().public())
        .unwrap();
    let mut state = PublishState::new();
    state.remote_id = remote.remote_id();
    state.owner_signing = Some(owner.public().signing);
    state.counter = ring.head.counter;
    let local = tempfile::tempdir().unwrap();
    write_owner(local.path(), &keys, &state);
    fs::write(local.path().join("pending-keyring"), pending).unwrap();
    let head = remote.read_head().unwrap();
    remote
        .commit_head(&head.version(), Some(&old), None)
        .unwrap();
    let before = remote.read_head().unwrap();
    assert!(access::finish_pending(&remote, local.path(), &owner, &mut state).is_err());
    assert_eq!(remote.read_head().unwrap(), before);
}

#[test]
fn directory_remote_refuses_oversized_batch_counts() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [81; 16]).unwrap();
    let ids = vec![ObjectId([0; 32]); 1001];
    assert!(remote.get_batch(&ids).is_err());
    assert!(remote.missing(&ids).is_err());
    let blob = tig_core::Object::Blob(b"batch".to_vec());
    let objects = vec![(blob.id(), blob.kind(), blob.encode_body()); 1001];
    assert!(remote.put_batch(&objects).is_err());
    assert!(!remote.public_store().has(&blob.id()).unwrap());
}

#[test]
fn publish_retry_rechecks_the_new_bookmark_and_keeps_local_state() {
    let mut repo = repo();
    let base = save(&mut repo, &[("public", b"base")]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [82; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut state = PublishState::new();
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        &FetchState::new(),
        "main",
        base,
        false,
    )
    .unwrap();
    let ours = save_child(&mut repo, &[("public", b"ours")]);
    let theirs = on_top(&mut repo, base, &[("public", b"theirs")]);
    let before = state.clone();
    let race = Intercept {
        remote: &remote,
        reply: 0,
        before_commit: std::sync::Mutex::new(Some(Box::new(|| {
            let mut competing = before.clone();
            publish_rev(
                &repo,
                &remote,
                &owner,
                Some(&keys),
                &mut competing,
                &FetchState::new(),
                "main",
                theirs,
                false,
            )
            .unwrap();
        }))),
    };
    let result = publish(
        repo.store().as_ref(),
        &race,
        &owner,
        Some(&keys),
        &mut state,
        &FetchState::new(),
        "main",
        ours,
        &PublishOptions::default(),
    );
    assert!(matches!(result, Err(PublishError::NotFastForward { .. })));
    assert_eq!(state, before);
    let tip = manifest(&remote).refs["main"];
    assert_eq!(
        remote.public_store().get_revision(&tip).unwrap().change_id,
        repo.store().get_revision(&theirs).unwrap().change_id
    );
}

#[test]
fn publish_retry_rechecks_new_public_paths() {
    for acknowledge_leaked in [false, true] {
        let mut repo = repo();
        let base = save(&mut repo, &[("public", b"base")]);
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::create(dir.path(), [90; 16]).unwrap();
        let owner = Identity::generate().unwrap();
        let keys = owner_keys(&remote, &owner);
        let mut state = PublishState::new();
        publish_rev(
            &repo,
            &remote,
            &owner,
            Some(&keys),
            &mut state,
            &FetchState::new(),
            "main",
            base,
            false,
        )
        .unwrap();
        let ours = save_child(
            &mut repo,
            &[(".private", b"secrets/\n"), ("secrets/token", b"ours")],
        );
        let theirs = on_top(&mut repo, base, &[("secrets/token", b"exposed")]);
        let before = state.clone();
        let race = Intercept {
            remote: &remote,
            reply: 0,
            before_commit: std::sync::Mutex::new(Some(Box::new(|| {
                let mut competing = before.clone();
                publish_rev(
                    &repo,
                    &remote,
                    &owner,
                    Some(&keys),
                    &mut competing,
                    &FetchState::new(),
                    "side",
                    theirs,
                    false,
                )
                .unwrap();
            }))),
        };
        let result = publish(
            repo.store().as_ref(),
            &race,
            &owner,
            Some(&keys),
            &mut state,
            &FetchState::new(),
            "main",
            ours,
            &PublishOptions {
                acknowledge_leaked,
                ..PublishOptions::default()
            },
        );
        let path = RepoPath::new("secrets/token").unwrap();
        if acknowledge_leaked {
            let report = result.unwrap();
            assert!(report
                .warnings
                .iter()
                .any(|warning| warning.contains("secrets/token")));
            assert!(state.ever_public.contains(&path));
            assert_eq!(manifest(&remote).refs["main"], state.revisions[&ours]);
        } else {
            assert!(
                matches!(result, Err(PublishError::AlreadyLeaked { paths }) if paths == vec![path])
            );
            assert_eq!(state, before);
            assert_eq!(manifest(&remote).refs["main"], before.revisions[&base]);
        }
        assert!(manifest(&remote).refs.contains_key("side"));
    }
}

#[test]
fn busy_publish_keeps_local_state_unchanged() {
    let mut repo = repo();
    let rev = save(&mut repo, &[("public", b"base")]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [83; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut state = PublishState::new();
    let result = publish(
        repo.store().as_ref(),
        &intercept(&remote, 5),
        &owner,
        Some(&keys),
        &mut state,
        &FetchState::new(),
        "main",
        rev,
        &PublishOptions::default(),
    );
    assert!(matches!(result, Err(PublishError::Busy)), "{result:?}");
    assert_eq!(state, PublishState::new());
    assert!(remote.read_head().unwrap().manifest.is_none());
}

#[test]
fn cross_command_owner_pins_refuse_substitution() {
    let mut repo = repo();
    let rev = save(&mut repo, &[("public", b"base")]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [85; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut published = PublishState::new();
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut published,
        &FetchState::new(),
        "main",
        rev,
        false,
    )
    .unwrap();
    let mut fetched = FetchState::new();
    fetch(
        &remote,
        repo.store().as_ref(),
        Some(&owner),
        &mut fetched,
        &published,
    )
    .unwrap();
    let attacker = Identity::generate().unwrap();
    let (ring, attacker_keys) =
        tig_private::keyring::Keyring::create(remote.remote_id(), &attacker).unwrap();
    let old = manifest(&remote);
    let forged = Manifest::signed(
        remote.remote_id(),
        old.sequence,
        old.refs,
        old.packs,
        &attacker,
    )
    .unwrap()
    .encode()
    .unwrap();
    let head = remote.read_head().unwrap();
    remote
        .commit_head(
            &head.version(),
            Some(&ring.encode().unwrap()),
            Some(&forged),
        )
        .unwrap();
    assert!(fetch(
        &remote,
        repo.store().as_ref(),
        None,
        &mut FetchState::new(),
        &published
    )
    .is_err());
    assert!(publish(
        repo.store().as_ref(),
        &remote,
        &attacker,
        Some(&attacker_keys),
        &mut PublishState::new(),
        &fetched,
        "side",
        rev,
        &PublishOptions::default()
    )
    .is_err());
}

#[test]
fn retries_refuse_keyring_and_manifest_rollback() {
    for roll_back_keyring in [false, true] {
        let mut repo = repo();
        let base = save(&mut repo, &[("public", b"base")]);
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::create(dir.path(), [88; 16]).unwrap();
        let owner = Identity::generate().unwrap();
        let keys = owner_keys(&remote, &owner);
        let mut state = PublishState::new();
        publish_rev(
            &repo,
            &remote,
            &owner,
            Some(&keys),
            &mut state,
            &FetchState::new(),
            "main",
            base,
            false,
        )
        .unwrap();
        let old = remote.read_head().unwrap();
        if roll_back_keyring {
            grant_member(
                &remote,
                &owner,
                &keys,
                &state,
                &Identity::generate().unwrap(),
            );
        } else {
            let mut competing = state.clone();
            publish_rev(
                &repo,
                &remote,
                &owner,
                Some(&keys),
                &mut competing,
                &FetchState::new(),
                "side",
                base,
                false,
            )
            .unwrap();
        }
        let before = state.clone();
        let race = Intercept {
            remote: &remote,
            reply: 0,
            before_commit: std::sync::Mutex::new(Some(Box::new(|| {
                let head = remote.read_head().unwrap();
                let (keyring, manifest) = if roll_back_keyring {
                    (old.keyring.as_deref(), None)
                } else {
                    (None, old.manifest.as_deref())
                };
                remote
                    .commit_head(&head.version(), keyring, manifest)
                    .unwrap();
            }))),
        };
        let result = publish(
            repo.store().as_ref(),
            &race,
            &owner,
            Some(&keys),
            &mut state,
            &FetchState::new(),
            "ours",
            base,
            &PublishOptions::default(),
        );
        assert!(result.is_err(), "{result:?}");
        assert_eq!(state, before);
    }
}

#[test]
fn competing_revoke_secret_cannot_be_used_for_publish_or_grant() {
    let mut repo = repo();
    let base = save(&mut repo, &[("public", b"base"), (".env", ENV)]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [86; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let mut keys = owner_keys(&remote, &owner);
    let mut state = PublishState::new();
    publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        &FetchState::new(),
        "main",
        base,
        false,
    )
    .unwrap();
    let member = Identity::generate().unwrap();
    grant_member(&remote, &owner, &keys, &state, &member);
    let mut competing_keys = OwnerKeys::decode(&keys.encode().unwrap()).unwrap();
    let mut competing_state = state.clone();
    let competing_local = tempfile::tempdir().unwrap();
    let remote_ref = &remote;
    let owner_ref = &owner;
    let member_id = member.public();
    let race = Intercept {
        remote: &remote,
        reply: 0,
        before_commit: std::sync::Mutex::new(Some(Box::new(move || {
            access::revoke(
                remote_ref,
                competing_local.path(),
                owner_ref,
                &mut competing_keys,
                &mut competing_state,
                &member_id,
            )
            .unwrap();
        }))),
    };
    let local = tempfile::tempdir().unwrap();
    access::revoke(
        &race,
        local.path(),
        &owner,
        &mut keys,
        &mut state,
        &member.public(),
    )
    .unwrap();
    let child = save_child(
        &mut repo,
        &[(".env", b"unreadable if the losing key is used")],
    );
    let before = remote.read_head().unwrap();
    assert!(publish_rev(
        &repo,
        &remote,
        &owner,
        Some(&keys),
        &mut state,
        &FetchState::new(),
        "main",
        child,
        false
    )
    .is_err());
    assert!(access::grant(
        &remote,
        local.path(),
        &owner,
        &keys,
        &mut state,
        &Identity::generate().unwrap().public()
    )
    .is_err());
    assert_eq!(remote.read_head().unwrap(), before);
}

#[test]
fn publish_retry_reprojects_new_work_after_revoke() {
    for reply in [0, 6] {
        let mut repo = repo();
        let base = save(&mut repo, &[("public", b"base"), (".env", ENV)]);
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::create(dir.path(), [84; 16]).unwrap();
        let owner = Identity::generate().unwrap();
        let keys = owner_keys(&remote, &owner);
        let mut owner_state = PublishState::new();
        publish_rev(
            &repo,
            &remote,
            &owner,
            Some(&keys),
            &mut owner_state,
            &FetchState::new(),
            "main",
            base,
            false,
        )
        .unwrap();
        let member = Identity::generate().unwrap();
        let removed = Identity::generate().unwrap();
        grant_member(&remote, &owner, &keys, &owner_state, &member);
        grant_member(&remote, &owner, &keys, &owner_state, &removed);
        let mut fetched = FetchState::new();
        fetch(
            &remote,
            repo.store().as_ref(),
            Some(&member),
            &mut fetched,
            &owner_state,
        )
        .unwrap();
        let child = save_child(&mut repo, &[(".env", b"new secret after revoke")]);
        let local = tempfile::tempdir().unwrap();
        let mut retry_keys = OwnerKeys::decode(&keys.encode().unwrap()).unwrap();
        let remote_ref = &remote;
        let old_packs = remote.list_packs("private", 1).unwrap().len();
        let race = Intercept {
            remote: &remote,
            reply,
            before_commit: std::sync::Mutex::new(Some(Box::new(move || {
                access::revoke(
                    remote_ref,
                    local.path(),
                    &owner,
                    &mut retry_keys,
                    &mut owner_state,
                    &removed.public(),
                )
                .unwrap();
            }))),
        };
        let mut state = PublishState::new();
        publish(
            repo.store().as_ref(),
            &race,
            &member,
            None,
            &mut state,
            &fetched,
            "main",
            child,
            &PublishOptions::default(),
        )
        .unwrap();
        assert_eq!(state.counter, manifest_counter(race.remote));
        assert!(state.sent.contains_key(&("private".into(), 2)));
        assert!(!state.sent.contains_key(&("private".into(), 1)));
        let final_manifest = manifest(race.remote);
        assert!(final_manifest.packs.values().any(|pack| pack.epoch == 2));
        if reply == 6 {
            assert_eq!(remote.list_packs("private", 1).unwrap().len(), old_packs);
        }
    }
}

#[test]
fn dead_process_head_lock_does_not_block_roll_forward() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [78; 16]).unwrap();
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "head_lock_process_exits_without_drop",
            "--nocapture",
        ])
        .env("TIG_TEST_HEAD_LOCK", dir.path())
        .status()
        .unwrap();
    assert!(child.success());
    let head = remote.read_head().unwrap();
    assert_eq!(head.keyring.as_deref(), Some(b"recovered".as_slice()));
    assert!(!dir.path().join("head.pending").exists());
}

#[test]
fn head_lock_process_exits_without_drop() {
    let Some(path) = std::env::var_os("TIG_TEST_HEAD_LOCK") else {
        return;
    };
    let path = std::path::PathBuf::from(path);
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path.join("head.lock"))
        .unwrap();
    file.lock().unwrap();
    fs::write(
        path.join("head.pending"),
        encode_pending(Some(b"recovered"), None),
    )
    .unwrap();
    std::process::exit(0);
}

const ENV: &[u8] = b"API_KEY=collab-marker\n";

#[test]
fn later_fetch_opens_opaque_seals_in_a_locally_published_child() {
    let mut owner_repo = repo();
    let base = save(&mut owner_repo, &[("public", b"base"), (".env", ENV)]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [87; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut owner_state = PublishState::new();
    publish_rev(
        &owner_repo,
        &remote,
        &owner,
        Some(&keys),
        &mut owner_state,
        &FetchState::new(),
        "main",
        base,
        false,
    )
    .unwrap();
    let member = Identity::generate().unwrap();
    let mut member_repo = repo();
    let mut fetched = FetchState::new();
    let first = fetch(
        &remote,
        member_repo.store().as_ref(),
        Some(&member),
        &mut fetched,
        &PublishState::new(),
    )
    .unwrap();
    grant_member(&remote, &owner, &keys, &owner_state, &member);
    let child = on_top(
        &mut member_repo,
        first.refs["main"],
        &[("public", b"child")],
    );
    let mut published = PublishState::new();
    publish_rev(
        &member_repo,
        &remote,
        &member,
        None,
        &mut published,
        &fetched,
        "main",
        child,
        false,
    )
    .unwrap();
    let opened = fetch(
        &remote,
        member_repo.store().as_ref(),
        Some(&member),
        &mut fetched,
        &published,
    )
    .unwrap();
    let tree = member_repo
        .store()
        .get_revision(&opened.refs["main"])
        .unwrap()
        .tree;
    let leaves =
        tig_core::treeops::walk(member_repo.store().as_ref(), &tree, &RepoPath::root()).unwrap();
    let leaf = leaves
        .iter()
        .find(|(path, _)| path.as_str() == ".env")
        .unwrap()
        .1;
    assert_eq!(leaf.kind(), tig_core::EntryKind::File);
    let public = published.revisions[&child];
    let upgraded = opened.refs["main"];
    assert_ne!(upgraded, child);
    assert_eq!(fetched.revisions[&public], upgraded);
    assert_eq!(manifest(&remote).refs["main"], public);
    let original = member_repo.store().get_revision(&child).unwrap();
    let successor = member_repo.store().get_revision(&upgraded).unwrap();
    assert_eq!(successor.change_id, original.change_id);
    assert_eq!(successor.committer, original.committer);
    assert_eq!(successor.predecessors, vec![child]);

    let saved = fetched.clone();
    let again = fetch(
        &remote,
        member_repo.store().as_ref(),
        None,
        &mut fetched,
        &published,
    )
    .unwrap();
    assert_eq!(again.refs, opened.refs);
    assert_eq!(fetched, saved);
    assert_eq!(again.unsealed, 0);
    assert_eq!(
        publish_rev(
            &member_repo,
            &remote,
            &member,
            None,
            &mut published,
            &fetched,
            "main",
            upgraded,
            false,
        )
        .unwrap(),
        0,
    );
    assert_eq!(manifest(&remote).refs["main"], public);
}

#[test]
fn access_upgrade_rebases_published_and_local_descendants_without_duplicates() {
    let mut owner_repo = repo();
    let base = save(&mut owner_repo, &[("public", b"base"), (".env", ENV)]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [88; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut owner_state = PublishState::new();
    publish_rev(
        &owner_repo,
        &remote,
        &owner,
        Some(&keys),
        &mut owner_state,
        &FetchState::new(),
        "main",
        base,
        false,
    )
    .unwrap();
    let member = Identity::generate().unwrap();
    let mut local = repo();
    let mut fetched = FetchState::new();
    let first = fetch(
        &remote,
        local.store().as_ref(),
        Some(&member),
        &mut fetched,
        &PublishState::new(),
    )
    .unwrap();
    let old_base = first.refs["main"];
    grant_member(&remote, &owner, &keys, &owner_state, &member);
    let child = on_top(&mut local, old_base, &[("public", b"child")]);
    let mut published = PublishState::new();
    publish_rev(
        &local,
        &remote,
        &member,
        None,
        &mut published,
        &fetched,
        "main",
        child,
        false,
    )
    .unwrap();
    let grandchild = save_child(&mut local, &[("local", b"grandchild")]);
    publish_rev(
        &local,
        &remote,
        &member,
        None,
        &mut published,
        &fetched,
        "side",
        grandchild,
        false,
    )
    .unwrap();
    // Still visible locally, but its public twin is now off the remote tips.
    publish_rev(
        &owner_repo,
        &remote,
        &owner,
        Some(&keys),
        &mut owner_state,
        &FetchState::new(),
        "side",
        base,
        true,
    )
    .unwrap();
    let tip = save_child(&mut local, &[("local", b"tip")]);
    let mut tx = local.start("bookmarks");
    tx.set_bookmark("base", old_base).unwrap();
    tx.set_bookmark("main", child).unwrap();
    tx.set_bookmark("local", tip).unwrap();
    local.commit(tx).unwrap();
    let before = local.visible_revisions().unwrap();
    let mut tx = local.start("fetch");
    let report = fetch_into(&remote, &mut tx, Some(&member), &mut fetched, &published).unwrap();
    assert!(report.projection_mismatches.is_empty());
    tx.set_bookmark("remote/main", report.refs["main"]).unwrap();
    local.commit(tx).unwrap();
    let new_tip = local.working_revision(DEFAULT_WORKSPACE).unwrap();
    assert_ne!(new_tip, tip);
    assert_eq!(local.view().bookmarks["local"], new_tip);
    assert_eq!(local.view().bookmarks["main"], report.refs["main"]);
    assert_eq!(
        local.view().bookmarks["base"],
        fetched.revisions[&owner_state.revisions[&base]]
    );
    let after = local.visible_revisions().unwrap();
    assert_eq!(after.len(), before.len());
    let changes: std::collections::BTreeSet<_> = after.iter().map(|(_, r)| r.change_id).collect();
    assert_eq!(changes.len(), after.len(), "one log revision per change");
    for old in [old_base, child, grandchild, tip] {
        assert!(!after.iter().any(|(id, _)| *id == old));
        let (_, rewritten) = after.iter().find(|(_, r)| r.predecessors == [old]).unwrap();
        assert_eq!(
            rewritten.committer,
            local.store().get_revision(&old).unwrap().committer
        );
        let env = tig_core::treeops::lookup(
            local.store().as_ref(),
            &rewritten.tree,
            &RepoPath::new(".env").unwrap(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(env.kind(), tig_core::EntryKind::File);
        assert_eq!(local.store().get_blob(&env.id()).unwrap(), ENV);
    }
    assert_eq!(
        fetched.revisions[&published.revisions[&child]],
        report.refs["main"]
    );
    assert!(after.iter().any(|(id, r)| r.predecessors == [grandchild]
        && fetched.revisions[&published.revisions[&grandchild]] == *id));
    let saved = fetched.clone();
    let view = local.view().clone();
    let mut tx = local.start("fetch again");
    let again = fetch_into(&remote, &mut tx, Some(&member), &mut fetched, &published).unwrap();
    assert_eq!(again.unsealed, 0);
    assert!(again.projection_mismatches.is_empty());
    assert_eq!(fetched, saved);
    assert_eq!(tx.view(), &view);
    assert_eq!(again.refs, report.refs);
    // Republishing the upgraded child must reuse its original public twin.
    assert_eq!(
        publish_rev(
            &local,
            &remote,
            &member,
            None,
            &mut published,
            &fetched,
            "main",
            report.refs["main"],
            false
        )
        .unwrap(),
        0
    );
}

#[test]
fn access_upgrade_keeps_and_reports_a_projection_mismatch() {
    for case in 0..7 {
        let mut owner_repo = repo();
        let base = save(&mut owner_repo, &[("public", b"base"), (".env", ENV)]);
        let dir = tempfile::tempdir().unwrap();
        let remote = DirRemote::create(dir.path(), [89; 16]).unwrap();
        let owner = Identity::generate().unwrap();
        let keys = owner_keys(&remote, &owner);
        let mut published = PublishState::new();
        publish_rev(
            &owner_repo,
            &remote,
            &owner,
            Some(&keys),
            &mut published,
            &FetchState::new(),
            "main",
            base,
            false,
        )
        .unwrap();
        let ancestor = base;
        let ancestor_public = published.revisions[&ancestor];
        let base = if matches!(case, 2 | 3) {
            let child = save_child(&mut owner_repo, &[("public", b"child")]);
            publish_rev(
                &owner_repo,
                &remote,
                &owner,
                Some(&keys),
                &mut published,
                &FetchState::new(),
                "main",
                child,
                false,
            )
            .unwrap();
            child
        } else {
            base
        };
        let member = Identity::generate().unwrap();
        let mut local = repo();
        let mut fetched = FetchState::new();
        let first = fetch(
            &remote,
            local.store().as_ref(),
            Some(&member),
            &mut fetched,
            &PublishState::new(),
        )
        .unwrap();
        let public = published.revisions[&base];
        let mut wrong = local.store().get_revision(&first.refs["main"]).unwrap();
        if case == 4 {
            wrong.parents = vec![local.working_revision(DEFAULT_WORKSPACE).unwrap()];
        } else if case == 5 {
            wrong.author.name = "different author".into();
        } else if case == 6 {
            wrong.committer.timestamp_ms += 1;
        } else if case != 1 {
            wrong.description = "different metadata".into();
        } else {
            let blob = local.store().put_blob(b"different public bytes").unwrap();
            wrong.tree = tig_core::treeops::apply_edits(
                local.store().as_ref(),
                &wrong.tree,
                &std::collections::BTreeMap::from([(
                    RepoPath::new("public").unwrap(),
                    Some(tig_core::treeops::Leaf::file(blob)),
                )]),
            )
            .unwrap();
        }
        let wrong = local
            .store()
            .put(&tig_core::Object::Revision(wrong))
            .unwrap();
        fetched.revisions.insert(public, wrong);
        let mut tx = local.start("checkout mismatch");
        tx.set_working(DEFAULT_WORKSPACE, wrong).unwrap();
        tx.set_bookmark("main", wrong).unwrap();
        local.commit(tx).unwrap();
        grant_member(&remote, &owner, &keys, &published, &member);
        if case == 3 {
            // Exercise rejection by the core descendant rebase callback,
            // after the ancestor's upgrade has already passed projection.
            publish_rev(
                &owner_repo,
                &remote,
                &owner,
                Some(&keys),
                &mut published,
                &FetchState::new(),
                "main",
                ancestor,
                true,
            )
            .unwrap();
        }
        let view = local.view().clone();
        let mappings = fetched.revisions.clone();
        let mut tx = local.start("fetch");
        let report = fetch_into(
            &remote,
            &mut tx,
            Some(&member),
            &mut fetched,
            &PublishState::new(),
        )
        .unwrap();
        assert_eq!(report.projection_mismatches, vec![wrong]);
        assert_eq!(
            report.refs["main"],
            if case == 3 {
                mappings[&ancestor_public]
            } else {
                wrong
            }
        );
        assert_eq!(fetched.revisions, mappings);
        assert_eq!(tx.view(), &view);
        assert_eq!(report.unsealed, 0);
    }
}

#[test]
fn access_upgrade_uses_each_seals_epoch_after_revoke_and_regrant() {
    let mut owner_repo = repo();
    let base = save(&mut owner_repo, &[("public", b"base"), (".env", ENV)]);
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [90; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let mut keys = owner_keys(&remote, &owner);
    let mut owner_state = PublishState::new();
    publish_rev(
        &owner_repo,
        &remote,
        &owner,
        Some(&keys),
        &mut owner_state,
        &FetchState::new(),
        "main",
        base,
        false,
    )
    .unwrap();
    let member = Identity::generate().unwrap();
    let mut local = repo();
    let mut fetched = FetchState::new();
    let first = fetch(
        &remote,
        local.store().as_ref(),
        Some(&member),
        &mut fetched,
        &PublishState::new(),
    )
    .unwrap();
    grant_member(&remote, &owner, &keys, &owner_state, &member);
    let owner_dir = tempfile::tempdir().unwrap();
    write_owner(owner_dir.path(), &keys, &owner_state);
    access::revoke(
        &remote,
        owner_dir.path(),
        &owner,
        &mut keys,
        &mut owner_state,
        &member.public(),
    )
    .unwrap();
    grant_member(&remote, &owner, &keys, &owner_state, &member);
    let child = on_top(
        &mut local,
        first.refs["main"],
        &[("extra.key", b"epoch two")],
    );
    let mut published = PublishState::new();
    publish_rev(
        &local,
        &remote,
        &member,
        None,
        &mut published,
        &fetched,
        "main",
        child,
        false,
    )
    .unwrap();
    let epochs: std::collections::BTreeSet<_> = manifest(&remote)
        .packs
        .values()
        .filter(|p| !p.sealed.is_empty())
        .map(|p| p.epoch)
        .collect();
    assert_eq!(epochs.len(), 2);
    let mut tx = local.start("fetch");
    let opened = fetch_into(&remote, &mut tx, Some(&member), &mut fetched, &published).unwrap();
    assert!(opened.projection_mismatches.is_empty());
    local.commit(tx).unwrap();
    let tree = local
        .store()
        .get_revision(&opened.refs["main"])
        .unwrap()
        .tree;
    for (path, bytes) in [(".env", ENV), ("extra.key", b"epoch two".as_slice())] {
        let leaf =
            tig_core::treeops::lookup(local.store().as_ref(), &tree, &RepoPath::new(path).unwrap())
                .unwrap()
                .unwrap();
        assert_eq!(leaf.kind(), tig_core::EntryKind::File);
        assert_eq!(local.store().get_blob(&leaf.id()).unwrap(), bytes);
    }
    assert_eq!(
        fetched.revisions[&published.revisions[&child]],
        opened.refs["main"]
    );
    let saved = fetched.clone();
    let mut tx = local.start("fetch again");
    let again = fetch_into(&remote, &mut tx, Some(&member), &mut fetched, &published).unwrap();
    assert_eq!(again.unsealed, 0);
    assert_eq!(fetched, saved);
    assert_eq!(tx.view(), local.view());
}

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

/// Four writers publish three times each, so one call can lose to nine
/// competing commits. Retry a bounded Busy once, preserving its local state.
#[allow(clippy::too_many_arguments)]
fn publish_contended(
    repo: &Repo,
    remote: &DirRemote,
    identity: &Identity,
    keys: Option<&OwnerKeys>,
    state: &mut PublishState,
    fetched: &FetchState,
    bookmark: &str,
    rev: ObjectId,
) -> Result<usize, PublishError> {
    let before = state.clone();
    let result = publish_rev(
        repo, remote, identity, keys, state, fetched, bookmark, rev, false,
    );
    if matches!(result, Err(PublishError::Busy)) {
        assert_eq!(*state, before);
        publish_rev(
            repo, remote, identity, keys, state, fetched, bookmark, rev, false,
        )
    } else {
        result
    }
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
    // Scoped threads finish before the temporary remote can be removed,
    // including when a writer or a join reports a failure.
    let tips = thread::scope(|scope| {
        let mut threads = Vec::new();
        for (index, member) in members.into_iter().enumerate() {
            let bookmark = format!("m{index}");
            names.push(bookmark.clone());
            let path = path.clone();
            threads.push(scope.spawn(move || {
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
                        save(
                            &mut repo,
                            &[("src/main.rs", body.as_bytes()), (".env", ENV)],
                        )
                    } else {
                        save_child(&mut repo, &[("src/main.rs", body.as_bytes())])
                    };
                    publish_contended(
                        &repo,
                        &remote,
                        &member,
                        None,
                        &mut state,
                        &FetchState::new(),
                        &bookmark,
                        rev,
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
            publish_contended(
                &owner_repo,
                &remote,
                &owner,
                Some(&keys),
                &mut owner_pub,
                &FetchState::new(),
                "owner",
                rev,
            )
            .unwrap();
        }
        let mut tips = Vec::new();
        tips.push(("owner".to_string(), manifest(&remote).refs["owner"]));
        for thread in threads {
            tips.push(thread.join().unwrap());
        }
        tips
    });
    let final_manifest = manifest(&remote);
    for (bookmark, public_id) in &tips {
        assert_eq!(final_manifest.refs[bookmark.as_str()], *public_id, "{bookmark}");
    }
    let mut files = Vec::new();
    collect_packs(dir.path(), &mut files);
    assert!(!files.is_empty());
    let stored: std::collections::BTreeSet<_> = files
        .iter()
        .map(|bytes| *blake3::hash(bytes).as_bytes())
        .collect();
    for id in final_manifest.packs.keys() {
        assert!(stored.contains(id), "committed pack missing from remote");
    }
    // A fresh fetch must read every referenced revision, tree, blob and pack.
    // Checking just bookmark ids would miss an incomplete concurrent upload.
    let store = tig_core::MemoryStore::new();
    let mut fetched = FetchState::new();
    let report = fetch(
        &remote,
        &store,
        Some(&owner),
        &mut fetched,
        &PublishState::new(),
    )
    .unwrap();
    assert_eq!(report.refs.len(), tips.len());
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


#[test]
fn role_initialization_rebuilds_ciphertext_after_a_public_only_head_race() {
    let mut repo = repo();
    let base = save(&mut repo, &[("public", b"base")]);
    let temp = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(temp.path(), [74; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let keys = owner_keys(&remote, &owner);
    let mut state = PublishState::new();
    publish_rev(&repo, &remote, &owner, Some(&keys), &mut state, &FetchState::new(), "main", base, false).unwrap();
    let tip = save_child(&mut repo, &[(".private", b"billing/ @billing\n"), ("billing/report", b"secret after role initialization")]);
    let race = Intercept {
        remote: &remote, reply: 0,
        before_commit: std::sync::Mutex::new(Some(Box::new(|| {
            let head = remote.read_head().unwrap();
            let old = Manifest::decode(head.manifest.as_deref().unwrap()).unwrap();
            let next = Manifest::signed(remote.remote_id(), old.sequence + 1, old.refs, old.packs, &owner).unwrap().encode().unwrap();
            assert!(matches!(remote.commit_head(&head.version(), None, Some(&next)).unwrap(), CommitOutcome::Committed(_)));
        }))),
    };
    publish(repo.store().as_ref(), &race, &owner, Some(&keys), &mut state, &FetchState::new(), "main", tip, &PublishOptions::default()).unwrap();
    let fresh = tig_core::MemoryStore::new();
    let report = fetch(&remote, &fresh, Some(&owner), &mut FetchState::new(), &PublishState::new()).unwrap();
    let revision = fresh.get_revision(&report.refs["main"]).unwrap();
    let leaf = tig_core::treeops::lookup(&fresh, &revision.tree, &RepoPath::new("billing/report").unwrap()).unwrap().unwrap();
    assert_eq!(fresh.get_blob(&leaf.id()).unwrap(), b"secret after role initialization");
}
