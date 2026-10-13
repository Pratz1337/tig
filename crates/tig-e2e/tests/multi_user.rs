//! The multi-user workflow end to end, over the `Remote` trait: every
//! scenario runs against a directory remote and against a real `tig-server`
//! on 127.0.0.1. See DESIGN.md "Collaboration: many contributors, one
//! remote", rules 1-8, and "Publish and fetch".

mod support;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use tig_core::object::hash_object;
use tig_core::store::StoreExt;
use tig_core::{EntryKind, ObjectKind};
use tig_private::keyring::{Keyring, KeyringError};
use tig_private::keys::Identity;
use tig_private::project::PRIVATE_GROUP;
use tig_private::publish::PublishError;
use tig_private::remote::{RemoteError, RemoteHead};

use support::http::{self as server, HttpBackend};
use support::*;

/// Upper bound on publish attempts in a loop that must eventually land.
const ROUNDS: usize = 40;

fn on_dir(scenario: fn(&dyn Backend, Identity)) {
    scenario(&DirBackend::new(), Identity::generate().unwrap());
}

fn on_http(scenario: fn(&dyn Backend, Identity)) {
    let owner = Identity::generate().unwrap();
    let backend = HttpBackend::new(&owner);
    scenario(&backend, owner);
}

fn epoch(head: &RemoteHead) -> u64 {
    Keyring::decode(head.keyring.as_deref().expect("no keyring"))
        .unwrap()
        .head
        .epochs[PRIVATE_GROUP]
}

fn work(i: usize) -> String {
    format!("contributor {i} was here\n")
}

fn secret(i: usize) -> String {
    format!("TOKEN=contributor-{i}-secret\n")
}

// ---------------------------------------------------------------------------
// 1. Owner plus three members publish at once, to one shared bookmark and to
//    their own bookmarks.

fn concurrent_publishers(backend: &dyn Backend, owner: Identity) {
    let team = team(backend, owner, &["ann", "ben", "cat"]);
    let n = team.len();
    let barrier = Arc::new(Barrier::new(n));
    let handles: Vec<_> = team
        .into_iter()
        .enumerate()
        .map(|(i, mut me)| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let base = me.refs["main"];
                let mine = on_top(
                    &mut me.repo,
                    base,
                    &[
                        (&format!("c{i}/work.txt"), work(i).as_bytes()),
                        (&format!("c{i}/.env"), secret(i).as_bytes()),
                    ],
                );
                let mut log = Vec::new();
                barrier.wait();
                // Everyone races for `main`. A loser fetches, merges and
                // publishes again, as DESIGN rule 2 tells the user to.
                let mut head = mine;
                let mut landed = false;
                for _ in 0..ROUNDS {
                    match me.publish("main", head) {
                        Ok(_) => {
                            log.push("main: ok".to_string());
                            landed = true;
                            break;
                        }
                        Err(PublishError::Busy) => log.push("main: busy".into()),
                        Err(PublishError::NotFastForward { bookmark }) => {
                            assert_eq!(bookmark, "main");
                            log.push("main: not fast-forward".into());
                            me.fetch().unwrap();
                            let theirs = me.refs["main"];
                            head = new_change(&mut me.repo, &[head, theirs], "merge main");
                        }
                        Err(other) => panic!("{}: publish main: {other}", me.name),
                    }
                }
                assert!(landed, "{}: main never landed: {log:?}", me.name);
                // Then each one's own bookmark, while the others still merge.
                let own = format!("m{i}");
                let mut landed = false;
                for _ in 0..ROUNDS {
                    match me.publish(&own, mine) {
                        Ok(_) => {
                            log.push(format!("{own}: ok"));
                            landed = true;
                            break;
                        }
                        Err(PublishError::Busy) => log.push(format!("{own}: busy")),
                        Err(other) => panic!("{}: publish {own}: {other}", me.name),
                    }
                }
                assert!(landed, "{}: {own} never landed: {log:?}", me.name);
                (me, mine, log)
            })
        })
        .collect();
    let mut done: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

    let changes: Vec<_> = done
        .iter()
        .map(|(me, mine, _)| me.store().get_revision(mine).unwrap().change_id)
        .collect();
    let mut versions = Vec::new();
    for (me, _, _) in &mut done {
        me.fetch().unwrap();
        versions.push(me.head().version());
    }
    assert!(
        versions.windows(2).all(|pair| pair[0] == pair[1]),
        "everyone must see the same remote head"
    );
    let seqs: BTreeSet<u64> = done.iter().map(|(me, ..)| me.fetched.manifest_seq).collect();
    assert_eq!(seqs.len(), 1, "{seqs:?}");
    let expected: BTreeSet<String> = std::iter::once("main".to_string())
        .chain((0..n).map(|j| format!("m{j}")))
        .collect();
    let refs: BTreeSet<String> = done[0].0.manifest().refs.keys().cloned().collect();
    assert_eq!(refs, expected);

    for (i, (me, mine, log)) in done.iter().enumerate() {
        let main = me.refs["main"];
        for (j, change) in changes.iter().enumerate() {
            // No update lost: every contributor's work, public and private,
            // is in `main` for every member.
            assert_eq!(file(me.store(), main, &format!("c{j}/work.txt")), work(j).as_bytes(), "{} c{j} {log:?}", me.name);
            assert_eq!(file(me.store(), main, &format!("c{j}/.env")), secret(j).as_bytes(), "{} c{j}", me.name);
            let tip = me.refs[&format!("m{j}")];
            assert_eq!(file(me.store(), tip, &format!("c{j}/work.txt")), work(j).as_bytes());
            // Each change has exactly one revision in history: no duplicates.
            let found = revisions_of(me.store(), main, *change);
            assert_eq!(found.len(), 1, "{} sees change c{j} {} times", me.name, found.len());
            assert!(found.contains(&tip), "{}: m{j} and main disagree on c{j}", me.name);
        }
        // Their own change is their own revision, never a rebuilt copy.
        assert_eq!(me.refs[&format!("m{i}")], *mine, "{}", me.name);
    }
}

#[test]
fn concurrent_publishers_dir() {
    on_dir(concurrent_publishers);
}

#[test]
fn concurrent_publishers_http() {
    on_http(concurrent_publishers);
}

// ---------------------------------------------------------------------------
// 2. Divergence: a refused publish, a fetched merge with a recorded
//    conflict, a local resolution, and everyone converging on it.

const RESOLVED: &[u8] = b"ann's line\nben's line\n";

fn divergence(backend: &dyn Backend, owner: Identity) {
    let mut team = team(backend, owner, &["ann", "ben"]);
    let [owner, ann, ben] = team.as_mut_slice() else {
        unreachable!()
    };
    let ann_rev = on_top(&mut ann.repo, ann.refs["main"], &[("shared.txt", b"ann's line\n")]);
    let ben_rev = on_top(&mut ben.repo, ben.refs["main"], &[("shared.txt", b"ben's line\n")]);
    let ann_change = ann.store().get_revision(&ann_rev).unwrap().change_id;
    let ben_change = ben.store().get_revision(&ben_rev).unwrap().change_id;

    ann.publish("main", ann_rev).unwrap();
    let before = ann.head().version();
    let err = ben.publish("main", ben_rev).unwrap_err();
    assert!(
        matches!(err, PublishError::NotFastForward { ref bookmark } if bookmark == "main"),
        "{err}"
    );
    assert!(err.to_string().contains("tig fetch"), "{err}");
    assert_eq!(ben.head().version(), before, "a refused publish moved the head");

    ben.fetch().unwrap();
    let theirs = ben.refs["main"];
    assert_eq!(file(ben.store(), theirs, "shared.txt"), b"ann's line\n");
    let merged = new_change(&mut ben.repo, &[ben_rev, theirs], "merge main");
    let conflicted = leaf(ben.store(), merged, "shared.txt").unwrap();
    assert_eq!(conflicted.kind(), EntryKind::Conflict, "the merge must record the conflict");
    let sides = ben.store().get_conflict(&conflicted.id()).unwrap();
    assert_eq!(sides.adds().len(), 2);

    // Unresolved conflicts are local-only in this phase.
    let err = ben.publish("main", merged).unwrap_err();
    assert!(err.to_string().contains("conflict"), "{err}");
    assert_eq!(ben.head().version(), before);

    let resolved = save(&mut ben.repo, &[("shared.txt", RESOLVED)]);
    assert_eq!(
        ben.store().get_revision(&resolved).unwrap().predecessors,
        vec![merged],
        "resolving rewrites the merge change"
    );
    ben.publish("main", resolved).unwrap();
    assert_ne!(ben.head().version(), before);

    for me in [&mut *owner, &mut *ann, &mut *ben] {
        me.fetch().unwrap();
        let main = me.refs["main"];
        assert_eq!(file(me.store(), main, "shared.txt"), RESOLVED, "{}", me.name);
        assert_eq!(file(me.store(), main, ".env"), BASE_ENV, "{}", me.name);
        assert_eq!(revisions_of(me.store(), main, ann_change).len(), 1, "{}", me.name);
        assert_eq!(revisions_of(me.store(), main, ben_change).len(), 1, "{}", me.name);
    }
    // Nobody gets a rebuilt duplicate of what they published themselves.
    assert_eq!(revisions_of(ann.store(), ann.refs["main"], ann_change), BTreeSet::from([ann_rev]));
    assert_eq!(ben.refs["main"], resolved);
    assert_eq!(revisions_of(ben.store(), resolved, ben_change), BTreeSet::from([ben_rev]));
}

#[test]
fn divergence_dir() {
    on_dir(divergence);
}

#[test]
fn divergence_http() {
    on_http(divergence);
}

// ---------------------------------------------------------------------------
// 3. Rewriting a published change (describe, then amend) fast-forwards
//    through the predecessor step and names the replaced change.

fn predecessor_rewrite(backend: &dyn Backend, owner: Identity) {
    let mut team = team(backend, owner, &["ann", "ben"]);
    let [owner, ann, ben] = team.as_mut_slice() else {
        unreachable!()
    };
    let first = on_top(&mut ann.repo, ann.refs["main"], &[("feature.txt", b"v1\n")]);
    ann.publish("main", first).unwrap();
    ben.fetch().unwrap();
    let ben_work = on_top(&mut ben.repo, ben.refs["main"], &[("ben.txt", b"built on v1\n")]);

    let change = ann.store().get_revision(&first).unwrap().change_id;
    let warning = format!("rewrites published change `{}`", change.short(8));
    let names_it = |warnings: &[String]| warnings.iter().any(|w| w.contains(&warning));

    let described = describe(&mut ann.repo, first, "feature, described");
    let report = ann.publish("main", described).unwrap();
    assert!(names_it(&report.warnings), "describe: {:?}", report.warnings);

    let amended = save(&mut ann.repo, &[("feature.txt", b"v2\n")]);
    assert_eq!(ann.store().get_revision(&amended).unwrap().predecessors, vec![described]);
    let report = ann.publish("main", amended).unwrap();
    assert!(names_it(&report.warnings), "amend: {:?}", report.warnings);

    // A plain descendant replaces nothing.
    let child = on_top(&mut ann.repo, amended, &[("more.txt", b"more\n")]);
    let report = ann.publish("main", child).unwrap();
    assert!(
        !report.warnings.iter().any(|w| w.contains("rewrites published change")),
        "{:?}",
        report.warnings
    );

    // Ben built on the replaced version; the lease refuses him until he fetches.
    let before = ben.head().version();
    let err = ben.publish("main", ben_work).unwrap_err();
    assert!(matches!(err, PublishError::NotFastForward { .. }), "{err}");
    assert_eq!(ben.head().version(), before);

    for me in [&mut *owner, &mut *ben] {
        me.fetch().unwrap();
        let main = me.refs["main"];
        assert_eq!(file(me.store(), main, "feature.txt"), b"v2\n", "{}", me.name);
        let found = revisions_of(me.store(), main, change);
        assert_eq!(found.len(), 1, "{}: one revision of the rewritten change", me.name);
        let rewritten = me.store().get_revision(found.iter().next().unwrap()).unwrap();
        assert_eq!(rewritten.description, "feature, described");
    }
    ann.fetch().unwrap();
    assert_eq!(ann.refs["main"], child, "ann's own revision is reused");
}

#[test]
fn predecessor_rewrite_dir() {
    on_dir(predecessor_rewrite);
}

#[test]
fn predecessor_rewrite_http() {
    on_http(predecessor_rewrite);
}

// ---------------------------------------------------------------------------
// 4. A publish that uploaded and then died before `commit_head`, and one
//    whose commit landed but whose reply was lost.

fn interrupted_upload(backend: &dyn Backend, owner: Identity) {
    let mut team = team(backend, owner, &["ann", "ben"]);
    let [owner, ann, ben] = team.as_mut_slice() else {
        unreachable!()
    };
    let ann_rev = on_top(
        &mut ann.repo,
        ann.refs["main"],
        &[("ann.txt", b"ann 1\n"), ("ann/.env", b"ANN=1\n")],
    );
    let before = ann.head();
    let saved = ann.published.clone();
    let dying = Wrapped::faulty(backend.connect(Some(&ann.identity)), Fault::DieBeforeCommit);
    let err = ann.publish_via(&dying, "main", ann_rev).unwrap_err();
    assert!(err.to_string().contains("injected"), "{err}");
    assert!(!dying.fault_pending(), "publish never reached commit_head");
    assert!(dying.uploads.load(Ordering::SeqCst) > 0, "nothing was uploaded first");
    assert_eq!(ann.head(), before, "the head moved without a commit");
    assert_eq!(ann.published, saved, "local publish state moved without a commit");

    // The orphaned uploads block nobody.
    ben.fetch().unwrap();
    assert_eq!(file(ben.store(), ben.refs["main"], "shared.txt"), b"base\n");
    let ben_rev = on_top(&mut ben.repo, ben.refs["main"], &[("ben.txt", b"ben\n")]);
    ben.publish("ben", ben_rev).unwrap();
    owner.fetch().unwrap();
    assert!(leaf(owner.store(), owner.refs["main"], "ann.txt").is_none());

    // The interrupted member simply publishes again.
    ann.publish("main", ann_rev).unwrap();

    // Now the commit lands but the reply is lost. Local state stays put, and
    // the retry finds its own tip on the remote.
    let next = on_top(&mut ann.repo, ann_rev, &[("ann.txt", b"ann 2\n"), ("ann/.env", b"ANN=2\n")]);
    let landed_before = ann.head().version();
    let saved = ann.published.clone();
    let lossy = Wrapped::faulty(backend.connect(Some(&ann.identity)), Fault::LoseCommitReply);
    let err = ann.publish_via(&lossy, "main", next).unwrap_err();
    assert!(err.to_string().contains("injected"), "{err}");
    assert_ne!(ann.head().version(), landed_before, "the commit should have landed");
    assert_eq!(ann.published, saved);
    ann.publish("main", next).unwrap();

    for me in [&mut *owner, &mut *ann, &mut *ben] {
        me.fetch().unwrap();
        let main = me.refs["main"];
        assert_eq!(file(me.store(), main, "ann.txt"), b"ann 2\n", "{}", me.name);
        assert_eq!(file(me.store(), main, "ann/.env"), b"ANN=2\n", "{}", me.name);
        assert_eq!(file(me.store(), me.refs["ben"], "ben.txt"), b"ben\n", "{}", me.name);
    }
    assert_eq!(ann.refs["main"], next, "ann's own revision is reused");
    assert_eq!(ben.refs["ben"], ben_rev);
}

#[test]
fn interrupted_upload_dir() {
    on_dir(interrupted_upload);
}

#[test]
fn interrupted_upload_http() {
    on_http(interrupted_upload);
}

// ---------------------------------------------------------------------------
// 5. Server restart (HTTP only): committed state survives, nonces do not.

#[test]
fn server_restart_http() {
    let owner_identity = Identity::generate().unwrap();
    let mut http = HttpBackend::new(&owner_identity);
    let mut team = team(&http, owner_identity, &["ann"]);
    let [owner, ann] = team.as_mut_slice() else {
        unreachable!()
    };
    let ann_rev = on_top(
        &mut ann.repo,
        ann.refs["main"],
        &[("ann.txt", b"before restart\n"), ("ann/.env", b"ANN=before\n")],
    );
    ann.publish("main", ann_rev).unwrap();
    let committed = ann.head();

    let addr = http.addr();
    let outstanding = server::nonce(addr);
    // Control: the running server accepts its own nonce and gets as far as
    // the signature check.
    let (status, body) = server::write_with_nonce(addr, &ann.public(), &server::nonce(addr));
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("signature"), "{body}");

    http.restart();

    assert_eq!(ann.head(), committed, "committed head lost across restart");
    let (status, body) = server::write_with_nonce(addr, &ann.public(), &outstanding);
    assert_eq!(status, 401, "{body}");
    assert!(body.contains("nonce"), "a pre-restart nonce must be refused as a nonce: {body}");

    // The same connections fetch and publish; each write asks the new
    // server for a fresh nonce.
    owner.fetch().unwrap();
    let main = owner.refs["main"];
    assert_eq!(file(owner.store(), main, "ann.txt"), b"before restart\n");
    assert_eq!(file(owner.store(), main, "ann/.env"), b"ANN=before\n");
    let next = on_top(&mut owner.repo, main, &[("owner.txt", b"after restart\n")]);
    owner.publish("main", next).unwrap();
    let after = on_top(&mut ann.repo, ann_rev, &[("ann.txt", b"after restart too\n")]);
    let err = ann.publish("main", after).unwrap_err();
    assert!(matches!(err, PublishError::NotFastForward { .. }), "{err}");
    ann.fetch().unwrap();
    let merged = new_change(&mut ann.repo, &[after, ann.refs["main"]], "merge");
    ann.publish("main", merged).unwrap();

    // Restart again with nothing outstanding; a brand-new reader sees it all.
    http.restart();
    let reader = http.connect(None);
    assert_eq!(reader.read_head().unwrap(), ann.head());
    owner.fetch().unwrap();
    let main = owner.refs["main"];
    assert_eq!(file(owner.store(), main, "owner.txt"), b"after restart\n");
    assert_eq!(file(owner.store(), main, "ann.txt"), b"after restart too\n");
}

// ---------------------------------------------------------------------------
// 6a. Revocation: the revoked member is locked out, new content is sealed
//     against them, and everyone else carries on.

fn revoked_member_is_locked_out(backend: &dyn Backend, owner: Identity) {
    let mut team = team(backend, owner, &["ann", "ben", "cat"]);
    let [owner, ann, ben, cat] = team.as_mut_slice() else {
        unreachable!()
    };
    let cat_rev = on_top(&mut cat.repo, cat.refs["main"], &[("cat.txt", b"cat\n")]);
    cat.publish("cat", cat_rev).unwrap();
    owner.fetch().unwrap();
    let epoch_before = epoch(&owner.head());
    owner.revoke(&cat.public()).unwrap();
    let epoch_after = epoch(&owner.head());
    assert!(epoch_after > epoch_before);
    assert_ne!(
        owner.manifest().publisher,
        cat.public().signing,
        "revoke re-signs the manifest as the owner"
    );

    // The remaining members keep publishing.
    ann.fetch().unwrap();
    let ann_rev = on_top(
        &mut ann.repo,
        ann.refs["main"],
        &[("ann.txt", b"after revoke\n"), ("ann/.env", b"ANN=after-revoke\n")],
    );
    ann.publish("main", ann_rev).unwrap();

    // The revoked member's publish is refused, and nothing moves.
    let head = cat.head();
    let cat_next = on_top(&mut cat.repo, cat_rev, &[("cat.txt", b"cat 2\n")]);
    let err = cat.publish("cat", cat_next).unwrap_err();
    assert!(
        matches!(err, PublishError::Keyring(KeyringError::NotMember)),
        "revoked publish: {err}"
    );
    assert_eq!(cat.head(), head);
    if backend.name() == "http" {
        // The server itself refuses the revoked member's signed writes.
        let body = b"revoked".to_vec();
        let blob = (hash_object(ObjectKind::Blob, &body), ObjectKind::Blob, body);
        let err = cat.remote.put_batch(&[blob]).unwrap_err();
        assert!(matches!(err, RemoteError::Denied(_)), "put_batch: {err}");
        let err = cat
            .remote
            .commit_head(&head.version(), None, head.manifest.as_deref())
            .unwrap_err();
        assert!(matches!(err, RemoteError::Denied(_)), "commit_head: {err}");
        assert_eq!(cat.head(), head);
    }

    // Reads stay open, but content published after the revoke is sealed
    // against the revoked member's keys.
    cat.fetch().unwrap();
    let main = cat.refs["main"];
    assert_eq!(file(cat.store(), main, "ann.txt"), b"after revoke\n");
    assert!(
        sealed(cat.store(), main, "ann/.env"),
        "a revoked member decrypted post-revoke content"
    );
    let keyring = Keyring::decode(&cat.head().keyring.unwrap()).unwrap();
    let verified = keyring.verify(&owner.public().signing, 0).unwrap();
    assert!(verified.key_for(PRIVATE_GROUP, epoch_after, &cat.identity).is_err());
    assert!(verified.current_key(PRIVATE_GROUP, &cat.identity).is_err());
    // What already left stays readable; tig does not pretend otherwise.
    assert!(verified.key_for(PRIVATE_GROUP, epoch_before, &cat.identity).is_ok());

    for me in [&mut *owner, &mut *ben] {
        me.fetch().unwrap();
        assert_eq!(file(me.store(), me.refs["main"], "ann/.env"), b"ANN=after-revoke\n", "{}", me.name);
    }
    let ben_rev = on_top(&mut ben.repo, ben.refs["main"], &[("ben.txt", b"ben\n"), ("ben/.env", b"BEN=1\n")]);
    ben.publish("main", ben_rev).unwrap();
    for me in [&mut *owner, &mut *ann] {
        me.fetch().unwrap();
        assert_eq!(file(me.store(), me.refs["main"], "ben/.env"), b"BEN=1\n", "{}", me.name);
    }
}

#[test]
fn revoked_member_is_locked_out_dir() {
    on_dir(revoked_member_is_locked_out);
}

#[test]
fn revoked_member_is_locked_out_http() {
    on_http(revoked_member_is_locked_out);
}

// ---------------------------------------------------------------------------
// 6b. A revoke racing publishes by the member being revoked and by another
//     member: either outcome is consistent, and no manifest signed by the
//     revoked member lands after the revoke.

/// Publish rounds each racer runs at most; it stops after three rounds that
/// started once the revoke had committed.
const RACE_ROUNDS: usize = 200;

fn revoke_races_publishers(backend: &dyn Backend, owner: Identity) {
    let team = team(backend, owner, &["ann", "cat"]);
    let mut people = team.into_iter();
    let mut owner = people.next().unwrap();
    let racers: Vec<Contributor> = people.collect();
    let cat_public = racers[1].public();
    let epoch_before = epoch(&owner.head());

    let log: CommitLog = Arc::new(Mutex::new(Vec::new()));
    let revoked = Arc::new(AtomicBool::new(false));
    let barrier = Arc::new(Barrier::new(racers.len() + 1));
    let handles: Vec<_> = racers
        .into_iter()
        .map(|mut me| {
            let remote = Wrapped::logged(backend.connect(Some(&me.identity)), &me.name, Arc::clone(&log));
            let revoked = Arc::clone(&revoked);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                let name = me.name.clone();
                let mut head = me.refs["main"];
                let mut results = Vec::new();
                let mut after = 0;
                for round in 0..RACE_ROUNDS {
                    let started_after = revoked.load(Ordering::SeqCst);
                    head = on_top(
                        &mut me.repo,
                        head,
                        &[
                            (&format!("{name}.txt"), format!("{name} {round}\n").as_bytes()),
                            (&format!("{name}/.env"), format!("SECRET={name}-{round}\n").as_bytes()),
                        ],
                    );
                    let result = me.publish_via(&remote, &name, head).map(|_| ()).map_err(|e| e.to_string());
                    if round == 0 {
                        // Wait even on failure, so the others never hang.
                        barrier.wait();
                        assert!(result.is_ok(), "{name} round 0: {result:?}");
                    }
                    results.push((round, started_after, result));
                    if started_after {
                        after += 1;
                        if after == 3 {
                            break;
                        }
                    }
                }
                (me, head, results)
            })
        })
        .collect();

    barrier.wait();
    let owner_remote = Wrapped::logged(backend.connect(Some(&owner.identity)), "owner", Arc::clone(&log));
    owner.revoke_via(&owner_remote, &cat_public).unwrap();
    revoked.store(true, Ordering::SeqCst);
    let mut done: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let epoch_after = epoch(&owner.head());
    assert!(epoch_after > epoch_before);

    let (ann, ann_tip, ann_results) = &done[0];
    for (round, _, result) in ann_results {
        assert!(result.is_ok(), "ann round {round}: {result:?}");
    }
    let ann_change = ann.store().get_revision(ann_tip).unwrap().change_id;
    let ann_last = ann_results.len() - 1;
    let (_, _, cat_results) = &done[1];
    assert_eq!(cat_results.iter().filter(|(_, after, _)| *after).count(), 3, "{cat_results:?}");
    for (round, after, result) in cat_results {
        if *after {
            assert!(result.is_err(), "cat published after the revoke (round {round})");
        }
    }

    // Commit order: nothing signed by the revoked member after the revoke.
    let log = log.lock().unwrap().clone();
    let revoke_at = log
        .iter()
        .rposition(|r| r.who == "owner" && r.committed && r.keyring_changed)
        .expect("the revoke never committed");
    for record in &log[revoke_at + 1..] {
        if record.committed {
            assert_ne!(record.who, "cat", "cat committed after the revoke: {log:?}");
            assert_ne!(record.publisher, Some(cat_public.signing), "{log:?}");
        }
    }
    assert_ne!(owner.manifest().publisher, cat_public.signing);
    assert!(log[revoke_at + 1..].iter().any(|r| r.committed && r.who == "ann"));

    // Ann's last revision was published under the new epoch: sealed for cat,
    // readable for the owner.
    let cat = &mut done[1].0;
    cat.fetch().unwrap();
    let ann_on_cat = cat.refs["ann"];
    assert_eq!(cat.store().get_revision(&ann_on_cat).unwrap().change_id, ann_change);
    assert!(sealed(cat.store(), ann_on_cat, "ann/.env"), "cat decrypted post-revoke content");
    owner.fetch().unwrap();
    let ann_on_owner = owner.refs["ann"];
    assert_eq!(
        file(owner.store(), ann_on_owner, "ann/.env"),
        format!("SECRET=ann-{ann_last}\n").as_bytes()
    );
    // Whatever cat managed before the revoke is still fetchable and intact.
    if owner.refs.contains_key("cat") {
        let cat_tip = owner.refs["cat"];
        assert!(file(owner.store(), cat_tip, "cat.txt").starts_with(b"cat "));
    }
}

#[test]
fn revoke_races_publishers_dir() {
    on_dir(revoke_races_publishers);
}

#[test]
fn revoke_races_publishers_http() {
    on_http(revoke_races_publishers);
}
