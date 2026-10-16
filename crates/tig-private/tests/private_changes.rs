//! Private-change seal, open, and owner reveal.

use std::collections::BTreeMap;
use std::sync::Arc;

use tig_core::blob::CHUNK_LEN;
use tig_core::repo::{Repo, Settings};
use tig_core::store::{empty_tree_id, StoreExt};
use tig_core::treeops::{apply_edits, lookup, Leaf};
use tig_core::{
    ChangeId, EntryKind, MemoryStore, Object, ObjectId, ObjectKind, RepoPath, Revision, Signature,
    Store,
};
use tig_private::changes::{
    authorize_seal, descendant_public_bytes, open_change, open_descendant,
    publish_reveal, publish_seal, seal_command, ChangeError, ChangeManifest, Correspondence,
    DescendantCheck, DescendantInput, OpenInput, OpenOutcome, RevealCertificate, RevealRequest,
    SealCommand, SealRequest,
};
use tig_private::keys::{EpochKey, Identity};
use tig_private::manifest::Manifest;
use tig_private::pack::Pack;
use tig_private::remote::{DirRemote, HeadVersion};

fn sign(name: &str) -> Signature {
    Signature {
        name: name.into(),
        email: format!("{name}@example"),
        timestamp_ms: 10,
        tz_offset_min: 0,
    }
}

fn p(path: &str) -> RepoPath {
    RepoPath::new(path).unwrap()
}

fn parent_revision(store: &MemoryStore) -> ObjectId {
    let tree = apply_edits(
        store,
        &empty_tree_id(),
        &BTreeMap::from([(p("readme"), Some(Leaf::file(store.put_blob(b"visible history").unwrap())))]),
    )
    .unwrap();
    store
        .put(&Object::Revision(Revision {
            tree,
            parents: vec![tig_core::repo::root_revision_id()],
            change_id: ChangeId::random().unwrap(),
            predecessors: vec![],
            author: sign("ada"),
            committer: sign("ada"),
            description: "visible parent".into(),
        }))
        .unwrap()
}

fn secret_revision(store: &MemoryStore, parent: ObjectId, extra: &[(&str, Vec<u8>)]) -> (ObjectId, ChangeId) {
    let mut files = vec![
        (p("fix.txt"), Some(Leaf::file(store.put_blob(b"public fix body").unwrap()))),
        (p(".env"), Some(Leaf::file(store.put_blob(b"SUPER_SECRET_ENV").unwrap()))),
    ];
    for (path, bytes) in extra {
        files.push((p(path), Some(Leaf::file(store.put_blob(bytes).unwrap()))));
    }
    let tree = apply_edits(store, &empty_tree_id(), &files.into_iter().collect()).unwrap();
    let change_id = ChangeId::random().unwrap();
    let id = store
        .put(&Object::Revision(Revision {
            tree,
            parents: vec![parent],
            change_id,
            predecessors: vec![],
            author: sign("Secret Author"),
            committer: sign("Secret Committer"),
            description: "SEALED-FIX-DESCRIPTION-9f3a".into(),
        }))
        .unwrap();
    (id, change_id)
}

struct World {
    store: MemoryStore,
    remote: DirRemote,
    owner: Identity,
    owner_keys: tig_private::keyring::OwnerKeys,
    keyring: tig_private::keyring::Keyring,
    parent: ObjectId,
}

fn world() -> World {
    let remote_id = [9u8; 16];
    let owner = Identity::generate().unwrap();
    let (keyring, owner_keys) = tig_private::keyring::Keyring::create(remote_id, &owner).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.keep();
    let remote = DirRemote::create(&path, remote_id).unwrap();
    let head = remote.read_head().unwrap();
    remote.commit_head(&head.version(), Some(&keyring.encode().unwrap()), None).unwrap();
    let store = MemoryStore::new();
    let parent = parent_revision(&store);
    let (kind, body) = store.get_raw(&parent).unwrap().unwrap();
    remote.put_batch(&[(parent, kind, body)]).unwrap();
    let tree = store.get_revision(&parent).unwrap().tree;
    let (kind, body) = store.get_raw(&tree).unwrap().unwrap();
    remote.put_batch(&[(tree, kind, body)]).unwrap();
    let readme = lookup(&store, &tree, &p("readme")).unwrap().unwrap().id();
    let (kind, body) = store.get_raw(&readme).unwrap().unwrap();
    remote.put_batch(&[(readme, kind, body)]).unwrap();
    World {
        store,
        remote,
        owner,
        owner_keys,
        keyring,
        parent,
    }
}

fn role_key(world: &World) -> &EpochKey {
    world.owner_keys.keys.get(&("private".into(), 1)).unwrap()
}

fn seal(world: &World, revision: ObjectId) -> tig_private::changes::SealReport {
    let head = world.remote.read_head().unwrap();
    world.remote.commit_head(&head.version(), Some(&world.keyring.encode().unwrap()), None).unwrap();
    publish_seal(&SealRequest {
        known_reveals: &Default::default(),
        store: &world.store,
        remote: &world.remote,
        identity: &world.owner,
        keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing,
        min_counter: 0,
        min_sequence: 0,
        bookmark: "main",
        revision,
        public_parents: &[world.parent],
        role: "private",
        role_key: role_key(world),
        privacy_keys: &BTreeMap::from([("private".into(), role_key(world))]),
    })
    .unwrap()
}

fn manifest(world: &World) -> ChangeManifest {
    let bytes = world.remote.read_head().unwrap().manifest.unwrap();
    let manifest = ChangeManifest::decode(&bytes).unwrap();
    manifest
        .verify(world.remote.remote_id(), &world.keyring, 0)
        .unwrap();
    manifest
}

fn copy_public(world: &World, id: ObjectId) {
    let (kind, body) = world.remote.public_store().get_raw(&id).unwrap().unwrap();
    world.store.put_raw(&id, kind, &body).unwrap();
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn version1_manifest_still_decodes() {
    let owner = Identity::generate().unwrap();
    let (keyring, _) = tig_private::keyring::Keyring::create([3; 16], &owner).unwrap();
    let manifest = Manifest::signed(
        [3; 16],
        4,
        BTreeMap::from([("main".into(), ObjectId([1; 32]))]),
        BTreeMap::new(),
        &owner,
    )
    .unwrap();
    let bytes = manifest.encode().unwrap();
    let decoded = ChangeManifest::decode(&bytes).unwrap();
    decoded.verify([3; 16], &keyring, 4).unwrap();
    assert_eq!(decoded.encode().unwrap(), bytes);
    assert!(decoded.changes.is_empty());
    assert!(decoded.reveals.is_empty());
}

#[test]
fn seal_hides_plaintext_and_keeps_public_history() {
    let world = world();
    let (revision, change_id) = secret_revision(&world.store, world.parent, &[]);
    let internal = world.store.get_revision(&revision).unwrap();
    let report = seal(&world, revision);
    assert_eq!(report.change_id, change_id);
    let skeleton = world.remote.public_store().get_revision(&report.skeleton).unwrap();
    assert_eq!(skeleton.change_id, change_id);
    assert_eq!(skeleton.parents, vec![world.parent]);
    assert_eq!(skeleton.description, "");
    assert_eq!(skeleton.author.name, "");
    assert!(skeleton.predecessors.is_empty());
    let tree = world.remote.public_store().get(&skeleton.tree).unwrap();
    let tig_core::Object::Tree(tree) = tree else { panic!("tree") };
    assert_eq!(tree.entries().len(), 2);
    let marker = tree.get("tig-private-change").unwrap();
    assert_eq!(marker.kind(), EntryKind::Sealed);
    assert_ne!(marker.sealed_id().unwrap().as_bytes(), internal.tree.as_bytes());
    assert_eq!(tree.get("readme").unwrap().kind(), EntryKind::File);

    let mut public = Vec::new();
    for id in [report.skeleton, skeleton.tree, report.capsule, world.parent] {
        public.extend(world.remote.public_store().get_raw(&id).unwrap().unwrap().1);
    }
    let packs = world.remote.list_packs("private", 1).unwrap();
    assert_eq!(packs.len(), 2);
    public.extend(packs[0].clone());
    for needle in [
        b"SEALED-FIX-DESCRIPTION-9f3a".as_slice(),
        b"Secret Author",
        b"SUPER_SECRET_ENV",
        b"public fix body",
        internal.tree.as_bytes().as_slice(),
        revision.as_bytes(),
    ] {
        assert!(!contains(&public, needle), "leaked {}", String::from_utf8_lossy(needle));
    }
    let parent = world.remote.public_store().get_revision(&world.parent).unwrap();
    assert_eq!(parent.description, "visible parent");

    let edit = world.store.put_blob(b"child edit").unwrap();
    let child_tree = apply_edits(
        &world.store,
        &skeleton.tree,
        &BTreeMap::from([(p("edit.txt"), Some(Leaf::file(edit)))]),
    )
    .unwrap();
    copy_public(&world, skeleton.tree);
    copy_public(&world, report.skeleton);
    let child = world.store.put(&Object::Revision(Revision {
        tree: child_tree,
        parents: vec![report.skeleton],
        change_id: ChangeId::random().unwrap(),
        predecessors: vec![],
        author: sign("bea"),
        committer: sign("bea"),
        description: "child stays public".into(),
    })).unwrap();
    for id in [edit, child_tree, child] {
        let (kind, body) = world.store.get_raw(&id).unwrap().unwrap();
        world.remote.put_batch(&[(id, kind, body)]).unwrap();
    }
    let loaded = world.remote.public_store().get_revision(&child).unwrap();
    assert_eq!(loaded.parents, vec![report.skeleton]);
    assert_eq!(
        world.remote.public_store().get_blob(&edit).unwrap(),
        b"child edit"
    );

    let member_store = MemoryStore::new();
    for id in [report.skeleton, skeleton.tree, report.capsule] {
        let (kind, body) = world.remote.public_store().get_raw(&id).unwrap().unwrap();
        member_store.put_raw(&id, kind, &body).unwrap();
        if kind == ObjectKind::ChunkedBlob {
            tig_core::blob::for_each_content(world.remote.public_store(), &id, |kind, cid, body| member_store.put_raw(&cid, kind, body)).unwrap();
        }
    }
    let mut correspondence = Correspondence::default();
    let opened = open_change(&mut OpenInput {
        store: &member_store,
        manifest: &manifest(&world),
        skeleton_id: report.skeleton,
        packs: &packs,
        role_key: Some(role_key(&world)),
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut correspondence,
        expects_access: true,
    })
    .unwrap();
    let OpenOutcome::Opened { local_id, public_id, .. } = opened else { panic!("opened") };
    assert_eq!(public_id, report.skeleton);
    let local = member_store.get_revision(&local_id).unwrap();
    assert_eq!(local.description, "SEALED-FIX-DESCRIPTION-9f3a");
    assert_eq!(local.author.name, "Secret Author");
    assert_eq!(local.change_id, change_id);
    assert_eq!(local.parents, vec![world.parent]);
    let fix = lookup(&member_store, &local.tree, &p("fix.txt")).unwrap().unwrap();
    assert_eq!(member_store.get_blob(&fix.id()).unwrap(), b"public fix body");
    let env = lookup(&member_store, &local.tree, &p(".env")).unwrap().unwrap();
    assert_eq!(env.kind(), EntryKind::Sealed);
    assert!(member_store
        .get_blob(&tig_core::object::hash_object(ObjectKind::Blob, b"SUPER_SECRET_ENV"))
        .is_err());

    let mut outsider = Correspondence::default();
    let outcome = open_change(&mut OpenInput {
        store: &member_store,
        manifest: &manifest(&world),
        skeleton_id: report.skeleton,
        packs: &[],
        role_key: None,
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut outsider,
        expects_access: false,
    })
    .unwrap();
    assert!(matches!(outcome, OpenOutcome::Opaque { .. }));

    let head_before = world.remote.read_head().unwrap();
    let version = publish_reveal(&RevealRequest {
        known_reveals: &Default::default(),
        remote: &world.remote,
        owner: &world.owner,
        keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing,
        min_counter: 0,
        min_sequence: 0,
        skeleton: report.skeleton,
        role_key: role_key(&world),
        expected: &head_before.version(),
    })
    .unwrap();
    assert_ne!(version.head, head_before.version());
    let after = world.remote.public_store().get_raw(&report.skeleton).unwrap().unwrap().1;
    assert_eq!(after, world.store.get_raw(&report.skeleton).unwrap().unwrap().1);
    assert_eq!(
        world.remote.public_store().get_revision(&child).unwrap().encode(),
        loaded.encode()
    );
    let revealed = manifest(&world);
    assert!(revealed.reveals.contains_key(&report.skeleton));
    let fresh = MemoryStore::new();
    for id in [report.skeleton, skeleton.tree, report.capsule] {
        let (kind, body) = world.remote.public_store().get_raw(&id).unwrap().unwrap();
        fresh.put_raw(&id, kind, &body).unwrap();
        if kind == ObjectKind::ChunkedBlob {
            tig_core::blob::for_each_content(world.remote.public_store(), &id, |kind, cid, body| fresh.put_raw(&cid, kind, body)).unwrap();
        }
    }
    let mut fresh_map = Correspondence::default();
    let again = open_change(&mut OpenInput {
        store: &fresh,
        manifest: &revealed,
        skeleton_id: report.skeleton,
        packs: &[],
        role_key: None,
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut fresh_map,
        expects_access: false,
    })
    .unwrap();
    let OpenOutcome::Opened { local_id: outsider_local, .. } = again else { panic!("outsider") };
    assert_eq!(
        fresh.get_revision(&outsider_local).unwrap().encode(),
        local.encode()
    );

    for id in [child_tree, edit, child] {
        let (kind, body) = world.store.get_raw(&id).unwrap().unwrap();
        member_store.put_raw(&id, kind, &body).unwrap();
        if kind == ObjectKind::ChunkedBlob {
            tig_core::blob::for_each_content(world.remote.public_store(), &id, |kind, cid, body| member_store.put_raw(&cid, kind, body)).unwrap();
        }
    }
    let upgraded = open_descendant(&DescendantInput {
        store: &member_store,
        manifest: &manifest(&world),
        skeleton_id: report.skeleton,
        opened_id: local_id,
        opened: &local,
        child: &loaded,
    })
    .unwrap();
    let bytes = descendant_public_bytes(&DescendantCheck {
        store: &member_store,
        manifest: &manifest(&world),
        skeleton_id: report.skeleton,
        opened_id: local_id,
        opened: &local,
        child: &loaded,
        upgraded: &upgraded,
    })
    .unwrap();
    assert_eq!(bytes, loaded.encode());
    let edit_on_opened = lookup(&member_store, &upgraded.tree, &p("edit.txt")).unwrap().unwrap();
    assert_eq!(member_store.get_blob(&edit_on_opened.id()).unwrap(), b"child edit");
    let fix_on_opened = lookup(&member_store, &upgraded.tree, &p("fix.txt")).unwrap().unwrap();
    assert_eq!(member_store.get_blob(&fix_on_opened.id()).unwrap(), b"public fix body");
}



#[test]
fn tamper_and_swap_are_rejected() {
    let world = world();
    let (first, _) = secret_revision(&world.store, world.parent, &[]);
    let first_report = seal(&world, first);
    let (second, _) = secret_revision(&world.store, world.parent, &[("other.txt", b"other".to_vec())]);
    // Second seal needs the bookmark to move from a parent. The first bookmark is the skeleton,
    // which is not a parent of the second change. Publish the second under another bookmark.
    publish_seal(&SealRequest {
        known_reveals: &Default::default(),
        store: &world.store,
        remote: &world.remote,
        identity: &world.owner,
        keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing,
        min_counter: 0,
        min_sequence: 0,
        bookmark: "other",
        revision: second,
        public_parents: &[world.parent],
        role: "private",
        role_key: role_key(&world),
        privacy_keys: &BTreeMap::from([("private".into(), role_key(&world))]),
    })
    .unwrap();
    let manifest = manifest(&world);
    let entry = manifest.entry(&first_report.skeleton).unwrap();
    let packs = world.remote.list_packs("private", 1).unwrap();
    let pack = packs
        .iter()
        .find(|pack| tig_private::manifest::pack_id(pack) == entry.wrapper_pack)
        .unwrap();
    let capsule_key_bytes = {
        let opened = Pack::open(pack, role_key(&world)).unwrap();
        // Opening the role pack with a capsule key must fail. Recover the capsule key from the record.
        let body = &opened.objects[0].2;
        let mut raw = [0u8; 32];
        raw.copy_from_slice(&body[1..33]);
        let capsule = EpochKey::from_bytes(role_key(&world).context().clone(), raw);
        assert!(Pack::open(pack, &capsule).is_err());
        let other = EpochKey::from_bytes(
            tig_private::keys::GroupEpoch {
                remote: [1; 16],
                group: "private".into(),
                epoch: 1,
            },
            raw,
        );
        assert!(Pack::open(pack, &other).is_err());
        raw
    };
    let store = MemoryStore::new();
    let (kind, body) = world
        .remote
        .public_store()
        .get_raw(&first_report.skeleton)
        .unwrap()
        .unwrap();
    store.put_raw(&first_report.skeleton, kind, &body).unwrap();
    let tree = store.get_revision(&first_report.skeleton).unwrap().tree;
    let (kind, body) = world.remote.public_store().get_raw(&tree).unwrap().unwrap();
    store.put_raw(&tree, kind, &body).unwrap();

    // put_raw is insert-only. The tampered body must be the first write under this id.
    let mut flipped = world.remote.public_store().get_blob(&entry.capsule).unwrap();
    let last = flipped.len() - 1;
    flipped[last] ^= 0x01;
    store.put_raw(&entry.capsule, ObjectKind::Blob, &flipped).unwrap();
    let mut map = Correspondence::default();
    let err = open_change(&mut OpenInput {
        store: &store,
        manifest: &manifest,
        skeleton_id: first_report.skeleton,
        packs: &packs,
        role_key: Some(role_key(&world)),
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut map,
        expects_access: true,
    })
    .unwrap_err();
    assert!(matches!(err, ChangeError::Tamper | ChangeError::Withheld), "{err}");

    // A second store holds the genuine capsule. The signed entry then points at the other blob.
    let store = MemoryStore::new();
    for id in [first_report.skeleton, entry.capsule] {
        let (kind, body) = world.remote.public_store().get_raw(&id).unwrap().unwrap();
        store.put_raw(&id, kind, &body).unwrap();
        if kind == ObjectKind::ChunkedBlob {
            tig_core::blob::for_each_content(world.remote.public_store(), &id, |kind, cid, body| store.put_raw(&cid, kind, body)).unwrap();
        }
    }
    let tree = store.get_revision(&first_report.skeleton).unwrap().tree;
    let (kind, body) = world.remote.public_store().get_raw(&tree).unwrap().unwrap();
    store.put_raw(&tree, kind, &body).unwrap();
    let other = manifest.changes.values().find(|item| item.skeleton != first_report.skeleton).unwrap();
    let mut forged = manifest.clone();
    forged.changes.get_mut(&first_report.skeleton).unwrap().capsule = other.capsule;
    let signed = ChangeManifest::signed_with_changes(
        forged.remote,
        forged.sequence,
        forged.refs,
        forged.packs,
        forged.changes,
        forged.reveals,
        &world.owner,
    )
    .unwrap();
    let (kind, body) = world.remote.public_store().get_raw(&other.capsule).unwrap().unwrap();
    store.put_raw(&other.capsule, kind, &body).unwrap();
    let err = open_change(&mut OpenInput {
        store: &store,
        manifest: &signed,
        skeleton_id: first_report.skeleton,
        packs: &packs,
        role_key: Some(role_key(&world)),
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut map,
        expects_access: true,
    })
    .unwrap_err();
    assert!(matches!(err, ChangeError::Tamper | ChangeError::Withheld), "{err}");

    let mut world = world;
    let member = Identity::generate().unwrap();
    world
        .keyring
        .grant(&world.owner_keys, &world.owner, &member.public())
        .unwrap();
    let mut fake = RevealCertificate::sign(
        &member,
        world.remote.remote_id(),
        entry,
        &capsule_key_bytes,
        &[7; 32],
    );
    fake.signature = member.sign(&[0; 8]);
    let mut nested = manifest.clone();
    nested.reveals.insert(entry.skeleton, fake);
    let nested = ChangeManifest::signed_with_changes(
        nested.remote,
        nested.sequence + 1,
        nested.refs,
        nested.packs,
        nested.changes,
        nested.reveals,
        &member,
    )
    .unwrap();
    assert!(matches!(
        nested.verify(world.remote.remote_id(), &world.keyring, 0),
        Err(tig_private::manifest::ManifestError::BadSignature)
    ));
}

#[test]
fn denied_before_upload_and_stale_reveal_writes_nothing() {
    let mut world = world();
    let stranger = Identity::generate().unwrap();
    let err = authorize_seal(
        &world.keyring,
        &stranger,
        &world.owner.public().signing,
        0,
        "private",
        role_key(&world),
    )
    .unwrap_err();
    assert!(matches!(err, ChangeError::Denied));
    let (revision, _) = secret_revision(&world.store, world.parent, &[]);
    let err = publish_seal(&SealRequest {
        known_reveals: &Default::default(),
        store: &world.store,
        remote: &world.remote,
        identity: &stranger,
        keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing,
        min_counter: 0,
        min_sequence: 0,
        bookmark: "main",
        revision,
        public_parents: &[world.parent],
        role: "private",
        role_key: role_key(&world),
        privacy_keys: &BTreeMap::from([("private".into(), role_key(&world))]),
    })
    .unwrap_err();
    assert!(matches!(err, ChangeError::Denied));
    assert!(world.remote.read_head().unwrap().manifest.is_none());

    let member = Identity::generate().unwrap();
    world.keyring.grant(&world.owner_keys, &world.owner, &member.public()).unwrap();
    let report = seal(&world, revision);
    let member_key = world.keyring.verify(&world.owner.public().signing, 0).unwrap().current_key("private", &member).unwrap();
    world.keyring.revoke(&mut world.owner_keys, &world.owner, &member.public()).unwrap();
    let err = authorize_seal(
        &world.keyring,
        &member,
        &world.owner.public().signing,
        0,
        "private",
        &member_key,
    )
    .unwrap_err();
    assert!(matches!(err, ChangeError::Denied));

    let err = publish_reveal(&RevealRequest {
        known_reveals: &Default::default(),
        remote: &world.remote,
        owner: &member,
        keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing,
        min_counter: 0,
        min_sequence: 0,
        skeleton: report.skeleton,
        role_key: role_key(&world),
        expected: &world.remote.read_head().unwrap().version(),
    })
    .unwrap_err();
    assert!(matches!(err, ChangeError::NotOwner));
    assert!(manifest(&world).reveals.is_empty());

    let err = publish_reveal(&RevealRequest {
        known_reveals: &Default::default(),
        remote: &world.remote,
        owner: &world.owner,
        keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing,
        min_counter: 0,
        min_sequence: 0,
        skeleton: report.skeleton,
        role_key: role_key(&world),
        expected: &HeadVersion::of(None, None),
    })
    .unwrap_err();
    assert!(matches!(err, ChangeError::StaleHead));
    assert!(manifest(&world).reveals.is_empty());
    let capsule = world.remote.public_store().get_blob(&report.capsule).unwrap();
    assert!(!contains(&capsule, b"SEALED-FIX-DESCRIPTION-9f3a"));
    assert!(!contains(&capsule, b"SUPER_SECRET_ENV"));
}

#[test]
fn withheld_pack_does_not_move_correspondence_and_rotation_keeps_it() {
    let world = world();
    let (revision, _) = secret_revision(&world.store, world.parent, &[]);
    let report = seal(&world, revision);
    let manifest = manifest(&world);
    let tree = world.remote.public_store().get_revision(&report.skeleton).unwrap().tree;
    for id in [report.skeleton, report.capsule, tree] {
        let (kind, body) = world.remote.public_store().get_raw(&id).unwrap().unwrap();
        world.store.put_raw(&id, kind, &body).unwrap();
    }
    let mut correspondence = Correspondence::default();
    let bookmark = report.skeleton;
    let err = open_change(&mut OpenInput {
        store: &world.store,
        manifest: &manifest,
        skeleton_id: report.skeleton,
        packs: &[],
        role_key: Some(role_key(&world)),
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut correspondence,
        expects_access: true,
    })
    .unwrap_err();
    assert!(matches!(err, ChangeError::Withheld));
    assert!(correspondence.get(&report.skeleton).is_none());
    assert_eq!(bookmark, report.skeleton);

    let packs = world.remote.list_packs("private", 1).unwrap();
    let opened = open_change(&mut OpenInput {
        store: &world.store,
        manifest: &manifest,
        skeleton_id: report.skeleton,
        packs: &packs,
        role_key: Some(role_key(&world)),
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut correspondence,
        expects_access: true,
    })
    .unwrap();
    let OpenOutcome::Opened { local_id, .. } = opened else { panic!("open") };
    let rotated = EpochKey::generate(role_key(&world).context().clone()).unwrap();
    let again = open_change(&mut OpenInput {
        store: &world.store,
        manifest: &manifest,
        skeleton_id: report.skeleton,
        packs: &[],
        role_key: Some(&rotated),
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut correspondence,
        expects_access: true,
    })
    .unwrap();
    let OpenOutcome::Already { local_id: kept, .. } = again else { panic!("kept") };
    assert_eq!(kept, local_id);
}

#[test]
fn filename_alone_is_not_a_private_change() {
    let world = world();
    let (revision, _) = secret_revision(&world.store, world.parent, &[]);
    let report = seal(&world, revision);
    let mut manifest = manifest(&world);
    manifest.changes.clear();
    manifest.reveals.clear();
    let manifest = ChangeManifest::signed_with_changes(
        manifest.remote,
        manifest.sequence,
        manifest.refs,
        manifest.packs,
        manifest.changes,
        manifest.reveals,
        &world.owner,
    )
    .unwrap();
    let mut correspondence = Correspondence::default();
    let outcome = open_change(&mut OpenInput {
        store: &world.store,
        manifest: &manifest,
        skeleton_id: report.skeleton,
        packs: &[],
        role_key: None,
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut correspondence,
        expects_access: false,
    })
    .unwrap();
    assert!(matches!(outcome, OpenOutcome::NotAssociated { .. }));
}

#[test]
fn chunked_public_file_is_inside_the_capsule() {
    let world = world();
    let mut big = vec![7u8; CHUNK_LEN + 1];
    big[0] = 9;
    let (revision, _) = secret_revision(&world.store, world.parent, &[("big.bin", big.clone())]);
    let report = seal(&world, revision);
    let packs = world.remote.list_packs("private", 1).unwrap();
    let tree = world.remote.public_store().get_revision(&report.skeleton).unwrap().tree;
    let store = MemoryStore::new();
    for id in [report.skeleton, report.capsule, tree] {
        let (kind, body) = world.remote.public_store().get_raw(&id).unwrap().unwrap();
        store.put_raw(&id, kind, &body).unwrap();
        if kind == ObjectKind::ChunkedBlob {
            tig_core::blob::for_each_content(world.remote.public_store(), &id, |kind, cid, body| store.put_raw(&cid, kind, body)).unwrap();
        }
    }
    let mut correspondence = Correspondence::default();
    let opened = open_change(&mut OpenInput {
        store: &store,
        manifest: &manifest(&world),
        skeleton_id: report.skeleton,
        packs: &packs,
        role_key: Some(role_key(&world)),
        pinned_owner: &world.owner.public().signing,
        correspondence: &mut correspondence,
        expects_access: true,
    })
    .unwrap();
    let OpenOutcome::Opened { local_id, .. } = opened else { panic!("open") };
    let local = store.get_revision(&local_id).unwrap();
    let file = lookup(&store, &local.tree, &p("big.bin")).unwrap().unwrap();
    assert_eq!(store.kind(&file.id()).unwrap(), Some(ObjectKind::ChunkedBlob));
    let out = tig_core::blob::materialize(&store, &file.id()).unwrap();
    assert_eq!(out, big);
    let public = world.remote.public_store().get_blob(&report.capsule).unwrap();
    assert!(!contains(&public, &big[..64]));
}

#[test]
fn seal_command_does_not_add_public_designation_history() {
    let remote_id = [4u8; 16];
    let owner = Identity::generate().unwrap();
    let (keyring, owner_keys) = tig_private::keyring::Keyring::create(remote_id, &owner).unwrap();
    let path = tempfile::tempdir().unwrap().keep();
    let remote = DirRemote::create(&path, remote_id).unwrap();
    let head = remote.read_head().unwrap();
    remote.commit_head(&head.version(), Some(&keyring.encode().unwrap()), None).unwrap();
    let store = MemoryStore::new();
    let parent = parent_revision(&store);
    let parent_rev = store.get_revision(&parent).unwrap();
    let leaf = lookup(&store, &parent_rev.tree, &p("readme")).unwrap().unwrap();
    for id in [parent, parent_rev.tree, leaf.id()] {
        let (kind, body) = store.get_raw(&id).unwrap().unwrap();
        remote.put_batch(&[(id, kind, body)]).unwrap();
    }
    let (revision, change) = secret_revision(&store, parent, &[]);
    let store: Arc<dyn Store> = Arc::new(store);
    let mut repo = Repo::init(
        store,
        Arc::new(tig_core::ophead::MemoryOpHead::new()),
        Settings {
            fixed_time_ms: Some(1),
            ..Settings::default()
        },
    )
    .unwrap();
    let role_key = owner_keys.keys.get(&("private".into(), 1)).unwrap();
    let report = seal_command(SealCommand {
        known_reveals: &Default::default(),
        repo: &mut repo,
        remote: &remote,
        identity: &owner,
        keyring: &keyring,
        pinned_owner: &owner.public().signing,
        min_counter: 0,
        min_sequence: 0,
        bookmark: "main",
        revision,
        role: "private",
        role_key,
        privacy_keys: &BTreeMap::from([("private".into(), role_key)]),
        correspondence: &Correspondence::default(),
    })
    .unwrap();
    assert_eq!(report.change_id, change);
    assert!(repo.view().bookmarks.is_empty());
    let sealed = remote.read_head().unwrap().manifest.unwrap();
    assert_eq!(remote.read_head().unwrap().manifest.unwrap(), sealed);
    let manifest = ChangeManifest::decode(&sealed).unwrap();
    assert!(manifest.entry(&report.skeleton).is_some());
    assert!(manifest.reveals.is_empty());
}

#[test]
fn stale_keyring_cannot_reveal_after_the_head_changes() {
    let world = world();
    let (revision, _) = secret_revision(&world.store, world.parent, &[]);
    let report = seal(&world, revision);
    let head = world.remote.read_head().unwrap();
    let mut changed = world.keyring.clone();
    let recipient = Identity::generate().unwrap();
    changed.grant(&world.owner_keys, &world.owner, &recipient.public()).unwrap();
    world.remote.commit_head(&head.version(), Some(&changed.encode().unwrap()), None).unwrap();
    let expected = world.remote.read_head().unwrap().version();
    let result = publish_reveal(&RevealRequest {
        known_reveals: &Default::default(),
        remote: &world.remote, owner: &world.owner, keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing, min_counter: 0, min_sequence: 0,
        skeleton: report.skeleton, role_key: role_key(&world), expected: &expected,
    });
    assert!(result.is_err(), "a caller's stale keyring authorized a reveal against a different remote head");
    assert_eq!(world.remote.read_head().unwrap().version(), expected);
}

#[test]
fn former_root_owner_cannot_reveal_after_a_signed_transfer() {
    let world = world();
    let (revision, _) = secret_revision(&world.store, world.parent, &[]);
    let report = seal(&world, revision);
    let successor = Identity::generate().unwrap();
    let mut transferred = world.keyring.clone();
    let transition = tig_private::roles::TransitionBody::Transfer { owner: successor.public() }
        .sign(world.remote.remote_id(), &world.owner.public().signing, transferred.head.counter + 1, &world.owner);
    transferred.commit_policy(&successor, vec![transition], vec![]).unwrap();
    let previous = manifest(&world);
    let next = Manifest::signed_with_changes(previous.remote, previous.sequence + 1, previous.refs,
        previous.packs, previous.changes, previous.reveals, &successor).unwrap();
    next.verify(world.remote.remote_id(), &transferred, 0).unwrap();
    let head = world.remote.read_head().unwrap();
    world.remote.commit_head(&head.version(), Some(&transferred.encode().unwrap()), Some(&next.encode().unwrap())).unwrap();
    let expected = world.remote.read_head().unwrap().version();
    let result = publish_reveal(&RevealRequest {
        known_reveals: &Default::default(),
        remote: &world.remote, owner: &world.owner, keyring: &transferred,
        pinned_owner: &world.owner.public().signing, min_counter: 0, min_sequence: 0,
        skeleton: report.skeleton, role_key: role_key(&world), expected: &expected,
    });
    assert!(matches!(result, Err(ChangeError::NotOwner)), "{result:?}");
    assert_eq!(world.remote.read_head().unwrap().version(), expected);
}

#[test]
fn owner_manifest_resigning_preserves_private_changes_and_reveals() {
    let world = world();
    let (revision, _) = secret_revision(&world.store, world.parent, &[]);
    let report = seal(&world, revision);
    let expected = world.remote.read_head().unwrap().version();
    publish_reveal(&RevealRequest {
        known_reveals: &Default::default(),
        remote: &world.remote, owner: &world.owner, keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing, min_counter: 0, min_sequence: 0,
        skeleton: report.skeleton, role_key: role_key(&world), expected: &expected,
    }).unwrap();
    let bytes = world.remote.read_head().unwrap().manifest.unwrap();
    let previous = Manifest::decode(&bytes).unwrap();
    let resigned = tig_private::manifest::resign_as_owner(Some(&bytes), world.remote.remote_id(),
        &world.owner, &world.keyring, previous.sequence).unwrap().unwrap();
    let next = Manifest::decode(&resigned).unwrap();
    next.verify(world.remote.remote_id(), &world.keyring, previous.sequence + 1).unwrap();
    assert_eq!(next.changes, previous.changes);
    assert_eq!(next.reveals, previous.reveals);
    assert_eq!(next.refs, previous.refs);
}

#[test]
fn private_bytes_pasted_into_revealable_files_are_refused_before_upload() {
    let world = world();
    let (revision, _) = secret_revision(&world.store, world.parent, &[("copied.env.txt", b"SUPER_SECRET_ENV".to_vec())]);
    let expected = world.remote.read_head().unwrap().version();
    let result = publish_seal(&SealRequest {
        known_reveals: &Default::default(),
        store: &world.store, remote: &world.remote, identity: &world.owner, keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing, min_counter: 0, min_sequence: 0,
        bookmark: "main", revision, public_parents: &[world.parent], role: "private", role_key: role_key(&world),
        privacy_keys: &BTreeMap::from([("private".into(), role_key(&world))]),
    });
    assert!(matches!(result, Err(ChangeError::Invalid(_))));
    assert_eq!(world.remote.read_head().unwrap().version(), expected);
    assert!(world.remote.list_packs("private", 1).unwrap().is_empty());
}

#[test]
fn sealing_cannot_hide_a_role_publishers_unauthorized_private_rules_edit() {
    let mut world = world();
    let member = Identity::generate().unwrap();
    world.keyring.grant(&world.owner_keys, &world.owner, &member.public()).unwrap();
    let role = tig_private::roles::Role {
        rank: 1, permissions: tig_private::roles::PUBLISH,
        groups: std::collections::BTreeSet::from(["private".into()]),
    };
    let define = tig_private::roles::TransitionBody::SetRole { name: "publisher".into(), role }
        .sign(world.remote.remote_id(), &world.owner.public().signing, world.keyring.head.counter + 1, &world.owner);
    world.keyring.commit_policy(&world.owner, vec![define], vec![]).unwrap();
    let assign = [world.owner.public(), member.public()].into_iter().map(|identity| {
        tig_private::roles::TransitionBody::Assign { member: identity, role: "publisher".into() }
            .sign(world.remote.remote_id(), &world.owner.public().signing, world.keyring.head.counter + 1, &world.owner)
    }).collect();
    world.keyring.commit_policy(&world.owner, assign, vec![]).unwrap();
    let head = world.remote.read_head().unwrap();
    world.remote.commit_head(&head.version(), Some(&world.keyring.encode().unwrap()), None).unwrap();
    let key = world.keyring.verify(&world.owner.public().signing, 0).unwrap().current_key("private", &member).unwrap();
    let (revision, _) = secret_revision(&world.store, world.parent, &[(".private", b"hidden/\n".to_vec())]);
    let expected = world.remote.read_head().unwrap().version();
    let result = publish_seal(&SealRequest {
        known_reveals: &Default::default(),
        store: &world.store, remote: &world.remote, identity: &member, keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing, min_counter: 0, min_sequence: 0,
        bookmark: "main", revision, public_parents: &[world.parent], role: "private", role_key: &key,
        privacy_keys: &BTreeMap::from([("private".into(), &key)]),
    });
    assert!(matches!(result, Err(ChangeError::Denied)), "{result:?}");
    assert_eq!(world.remote.read_head().unwrap().version(), expected);
    assert!(world.remote.list_packs("private", 1).unwrap().is_empty());
}

#[test]
fn both_seal_and_reveal_refuse_a_newer_head_that_drops_an_accepted_certificate() {
    let world = world();
    let (revision, _) = secret_revision(&world.store, world.parent, &[]);
    let report = seal(&world, revision);
    publish_reveal(&RevealRequest {
        known_reveals: &Default::default(), remote: &world.remote, owner: &world.owner, keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing, min_counter: 0, min_sequence: 0,
        skeleton: report.skeleton, role_key: role_key(&world), expected: &world.remote.read_head().unwrap().version(),
    }).unwrap();
    let previous = manifest(&world);
    let known = previous.reveals.keys().copied().collect();
    let dropped = Manifest::signed_with_changes(previous.remote, previous.sequence + 1, previous.refs,
        previous.packs, previous.changes, Default::default(), &world.owner).unwrap();
    let head = world.remote.read_head().unwrap();
    world.remote.commit_head(&head.version(), None, Some(&dropped.encode().unwrap())).unwrap();
    let expected = world.remote.read_head().unwrap().version();
    let result = publish_reveal(&RevealRequest {
        known_reveals: &known, remote: &world.remote, owner: &world.owner, keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing, min_counter: 0, min_sequence: 0,
        skeleton: report.skeleton, role_key: role_key(&world), expected: &expected,
    });
    assert!(matches!(result, Err(ChangeError::RevealDropped)));
    let result = publish_seal(&SealRequest {
        known_reveals: &known, store: &world.store, remote: &world.remote, identity: &world.owner, keyring: &world.keyring,
        pinned_owner: &world.owner.public().signing, min_counter: 0, min_sequence: 0,
        bookmark: "other", revision, public_parents: &[world.parent], role: "private", role_key: role_key(&world),
        privacy_keys: &BTreeMap::from([("private".into(), role_key(&world))]),
    });
    assert!(matches!(result, Err(ChangeError::RevealDropped)));
    assert_eq!(world.remote.read_head().unwrap().version(), expected);
}
