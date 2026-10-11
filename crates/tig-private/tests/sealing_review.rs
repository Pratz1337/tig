use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};

use tig_core::object::hash_object;
use tig_core::store::{empty_tree_id, StoreExt};
use tig_core::treeops::{apply_edits, lookup, walk, Leaf};
use tig_core::{
    ChangeId, EntryKind, MemoryStore, ObjectId, ObjectKind, RepoPath, Revision, Signature, Store,
};
use tig_private::keys::{
    grant, open_grant, unwrap_unverified, wrap, EpochKey, GroupEpoch, Identity, KeyError,
    PublicIdentity, WrappedKey,
};
use tig_private::project::{project_tree, public_revision, ProjectError};

fn p(path: &str) -> RepoPath {
    RepoPath::new(path).unwrap()
}

fn tree(store: &MemoryStore, files: &[(&str, &[u8])]) -> ObjectId {
    let edits = files
        .iter()
        .map(|(path, body)| (p(path), Some(Leaf::file(store.put_blob(body).unwrap()))))
        .collect();
    apply_edits(store, &empty_tree_id(), &edits).unwrap()
}

fn group(name: &str, epoch: u64) -> GroupEpoch {
    GroupEpoch {
        remote: [0; 16],
        group: name.into(),
        epoch,
    }
}

#[test]
fn invalid_utf8_rules_refuse_projection() {
    let store = MemoryStore::new();
    let root = tree(
        &store,
        &[(".private", b"secr\xffet\n"), ("secret", b"TOKEN=1")],
    );
    assert!(project_tree(
        &store,
        &root,
        &EpochKey::generate(group("private", 1)).unwrap()
    )
    .is_err());
}

#[test]
fn present_non_file_rules_refuse_projection() {
    let store = MemoryStore::new();
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let base = tree(&store, &[("secret", b"TOKEN=1")]);
    let target = store.put_blob(b"rules.txt").unwrap();
    for rules in [
        Leaf::tree(tree(&store, &[("policy", b"secret\n")])),
        Leaf::symlink(target),
        Leaf::sealed(key.seal(&p(".private"), EntryKind::File, &target)),
    ] {
        let edits = BTreeMap::from([(p(".private"), Some(rules))]);
        let root = apply_edits(&store, &base, &edits).unwrap();
        assert!(
            project_tree(&store, &root, &key).is_err(),
            "rules kind {:?}",
            rules.kind()
        );
    }
}

#[test]
fn wrap_labels_are_frozen_in_the_domain_module() {
    assert_eq!(tig_core::domain::WRAP_KEY, "tig wrap key v1");
    assert_eq!(tig_core::domain::WRAP_AAD, b"tig wrapped epoch key v1");
    assert_eq!(tig_core::domain::OBJECT_AAD, b"tig sealed object v1");
    assert_eq!(tig_core::domain::OBJECT_ID, "tig object v1");
    assert_eq!(tig_core::domain::SEALED_ENTRY, "tig sealed entry v1");
    assert_eq!(tig_core::domain::SEAL_SALT_KEY, "tig seal salt key v1");
    assert_eq!(tig_core::domain::CONTENT_KEY, "tig content key v1");
    assert_eq!(tig_core::domain::NONCE_KEY, "tig nonce key v1");
    assert_eq!(tig_core::domain::WIRE_ID_KEY, "tig wire id key v1");
    assert_eq!(
        tig_core::domain::IDENTITY_FINGERPRINT,
        "tig identity fingerprint v1"
    );
    assert_eq!(
        tig_core::domain::EPOCH_KEY_COMMITMENT,
        "tig epoch key commitment v1"
    );
    assert_eq!(
        tig_core::domain::GRANT_SIGNATURE,
        "tig epoch grant signature v1"
    );
    assert_eq!(tig_core::domain::PACK_INDEX_AAD, b"tig pack index v1");
    assert_eq!(
        tig_core::domain::KEYRING_HEAD_SIGNATURE,
        "tig keyring head signature v1"
    );
}

#[test]
fn synthetic_nonce_must_not_accept_two_plaintexts_for_one_id() {
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let first = b"SECRET=1";
    let second = b"SECRET=2";
    let id = hash_object(ObjectKind::Blob, first);
    assert!(key.encrypt_object(ObjectKind::Blob, &id, first).is_ok());
    assert!(matches!(
        key.encrypt_object(ObjectKind::Blob, &id, second),
        Err(KeyError::ObjectMismatch)
    ));
    assert!(matches!(
        key.encrypt_object(ObjectKind::Tree, &id, first),
        Err(KeyError::ObjectMismatch)
    ));
}

#[test]
fn reused_epoch_key_must_separate_group_and_epoch_nonce_domains() {
    let key = EpochKey::from_bytes(group("private", 1), [7; 32]);
    let body = b"SECRET=1";
    let id = hash_object(ObjectKind::Blob, body);
    let a = key.encrypt_object(ObjectKind::Blob, &id, body).unwrap();
    let mut other_remote = group("private", 1);
    other_remote.remote = [1; 16];
    for context in [
        group("billing", 1),
        group("private", 2),
        group("private\0", 1),
        group("", 1),
        other_remote,
    ] {
        let other = EpochKey::from_bytes(context.clone(), [7; 32]);
        let b = other.encrypt_object(ObjectKind::Blob, &id, body).unwrap();
        assert_ne!(
            &a[..body.len()],
            &b[..body.len()],
            "same keystream across {context:?}"
        );
        assert!(other.decrypt_object(ObjectKind::Blob, &id, &a).is_err());
        assert_ne!(key.wire_id(&id), other.wire_id(&id));
        assert_ne!(
            key.seal(&p("a.key"), EntryKind::File, &id),
            other.seal(&p("a.key"), EntryKind::File, &id)
        );
    }
}

#[test]
fn server_chosen_key_and_wrap_are_rejected_without_owner_signature() {
    let owner = Identity::generate().unwrap();
    let member = Identity::generate().unwrap();
    let server = Identity::generate().unwrap();
    let context = group("private", 2);
    let server_key = EpochKey::generate(context).unwrap();
    // Public recipient keys suffice to create an entirely new epoch grant.
    let mut substituted = grant(&server_key, &member.public(), &server).unwrap();
    assert!(open_grant(&substituted, &member, &owner.public().signing).is_err());
    // Claiming the pinned owner while keeping a server signature also fails.
    substituted.granter = owner.public().signing;
    assert!(open_grant(&substituted, &member, &owner.public().signing).is_err());
    // Even replacing the wrap in a real owner grant is refused.
    let key = EpochKey::generate(group("private", 2)).unwrap();
    let mut legitimate = grant(&key, &member.public(), &owner).unwrap();
    legitimate.wrapped = wrap(&server_key, &member.public()).unwrap();
    assert!(open_grant(&legitimate, &member, &owner.public().signing).is_err());
}

#[test]
fn private_folder_with_existing_seal_hides_child_names() {
    let store = MemoryStore::new();
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let base = tree(
        &store,
        &[
            (".private", b"secrets/\n"),
            ("secrets/hidden-name", b"TOKEN=1"),
        ],
    );
    let foreign_key = EpochKey::generate(group("foreign", 9)).unwrap();
    let sid = foreign_key.seal(
        &p("secrets/old"),
        EntryKind::File,
        &store.put_blob(b"old secret").unwrap(),
    );
    let root = apply_edits(
        &store,
        &base,
        &BTreeMap::from([(p("secrets/old"), Some(Leaf::sealed(sid)))]),
    )
    .unwrap();
    let projection = project_tree(&store, &root, &key).unwrap();
    assert_eq!(
        projection
            .sealed
            .iter()
            .map(|s| s.path.as_str())
            .collect::<Vec<_>>(),
        vec!["secrets"]
    );
    assert!(
        lookup(&store, &projection.public_tree, &p("secrets/hidden-name"))
            .unwrap()
            .is_none()
    );
    assert!(lookup(&store, &projection.public_tree, &p("secrets/old"))
        .unwrap()
        .is_none());
    assert!(projection
        .public_files
        .iter()
        .all(|(path, _)| !path.starts_with(&p("secrets"))));
    assert_eq!(
        projection.sealed[0].readers,
        std::collections::BTreeSet::from(["private".into()])
    );
    // The original private subtree keeps the opaque foreign entry intact.
    assert_eq!(
        lookup(&store, &projection.sealed[0].leaf.id(), &p("old")).unwrap(),
        Some(Leaf::sealed(sid))
    );
}

#[test]
fn foreign_seals_with_public_files_or_alone_stay_public() {
    let store = MemoryStore::new();
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let foreign_key = EpochKey::generate(group("foreign", 9)).unwrap();
    let target = store.put_blob(b"foreign secret").unwrap();
    let sid = foreign_key.seal(&p("folder/old"), EntryKind::File, &target);
    for files in [vec![("folder/README", &b"public"[..])], vec![]] {
        let base = tree(&store, &files);
        let root = apply_edits(
            &store,
            &base,
            &BTreeMap::from([(p("folder/old"), Some(Leaf::sealed(sid)))]),
        )
        .unwrap();
        let projection = project_tree(&store, &root, &key).unwrap();
        assert_eq!(projection.public_tree, root);
        assert!(projection.sealed.is_empty());
        assert!(projection.private_files.is_empty());
        assert!(projection
            .public_files
            .contains(&(p("folder/old"), Leaf::sealed(sid))));
    }
}

#[test]
fn mixed_directories_seal_only_the_highest_uniform_roots() {
    let store = MemoryStore::new();
    let root = tree(
        &store,
        &[
            (".private", b"mixed/\n!mixed/deep/README\n*.key\n"),
            ("mixed/a", b"A"),
            ("mixed/private/deep/a", b"A"),
            ("mixed/private/b", b"B"),
            ("mixed/deep/README", b"public"),
            ("mixed/deep/token", b"secret"),
            ("other/deep/a.key", b"key"),
            ("other/deep/public", b"public"),
            ("root.key", b"key"),
        ],
    );
    let projection = project_tree(
        &store,
        &root,
        &EpochKey::generate(group("private", 1)).unwrap(),
    )
    .unwrap();
    assert_eq!(
        projection
            .sealed
            .iter()
            .map(|s| s.path.as_str())
            .collect::<Vec<_>>(),
        vec![
            "mixed/a",
            "mixed/deep/token",
            "mixed/private",
            "other/deep/a.key",
            "root.key"
        ]
    );
    assert_eq!(projection.negated, vec![p("mixed/deep/README")]);
    assert!(
        lookup(&store, &projection.public_tree, &p("mixed/private/deep/a"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn projection_does_not_expose_private_ids_in_public_ancestor_encodings() {
    let store = MemoryStore::new();
    let root = tree(
        &store,
        &[
            (".private", b"*.key\n"),
            ("mixed/nested/a.key", b"GUESSABLE"),
            ("mixed/nested/README", b"public"),
            ("src/main", b"source"),
        ],
    );
    let private_ids = [
        root,
        lookup(&store, &root, &p("mixed")).unwrap().unwrap().id(),
        lookup(&store, &root, &p("mixed/nested"))
            .unwrap()
            .unwrap()
            .id(),
        lookup(&store, &root, &p("mixed/nested/a.key"))
            .unwrap()
            .unwrap()
            .id(),
    ];
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let projection = project_tree(&store, &root, &key).unwrap();
    let mut pending = vec![projection.public_tree];
    while let Some(id) = pending.pop() {
        assert!(!private_ids.contains(&id));
        let tree = store.get_tree(&id).unwrap();
        for private_id in private_ids {
            assert!(!tree
                .encode()
                .windows(32)
                .any(|bytes| bytes == private_id.as_bytes()));
        }
        pending.extend(
            tree.entries()
                .iter()
                .filter(|e| e.kind() == EntryKind::Tree)
                .map(|e| e.id()),
        );
    }
    // Untouched, wholly public subtrees can keep their internal ID.
    assert_eq!(
        lookup(&store, &root, &p("src")).unwrap(),
        lookup(&store, &projection.public_tree, &p("src")).unwrap()
    );
    let guessed = tree(&store, &[("a.key", b"GUESSABLE"), ("README", b"public")]);
    assert_ne!(
        lookup(&store, &projection.public_tree, &p("mixed/nested"))
            .unwrap()
            .unwrap()
            .id(),
        guessed
    );
    assert_eq!(
        project_tree(&store, &root, &key).unwrap().public_tree,
        projection.public_tree
    );
}

#[test]
fn empty_deduplicated_symlink_and_executable_private_files_are_sealed() {
    let store = MemoryStore::new();
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let root = tree(
        &store,
        &[
            (".private", b".env\n*.key\nsecrets/\n"),
            (".env", b""),
            ("public-empty", b""),
            ("a.key", b"same bytes"),
            ("public-copy", b"same bytes"),
            ("secrets/deep/hidden-name", b"hidden"),
        ],
    );
    let root = apply_edits(
        &store,
        &root,
        &BTreeMap::from([
            (
                p("secrets/link"),
                Some(Leaf::symlink(store.put_blob(b"../../outside").unwrap())),
            ),
            (
                p("secrets/run"),
                Some(Leaf::executable(store.put_blob(b"execute").unwrap())),
            ),
        ]),
    )
    .unwrap();
    let projection = project_tree(&store, &root, &key).unwrap();
    let paths: Vec<_> = walk(&store, &projection.public_tree, &RepoPath::root())
        .unwrap()
        .into_iter()
        .map(|(path, _)| path.to_string())
        .collect();
    assert_eq!(
        paths,
        vec![
            ".env",
            ".private",
            "a.key",
            "public-copy",
            "public-empty",
            "secrets"
        ]
    );
    for path in [".env", "a.key", "secrets"] {
        let public = lookup(&store, &projection.public_tree, &p(path))
            .unwrap()
            .unwrap();
        let private = lookup(&store, &root, &p(path)).unwrap().unwrap();
        assert_eq!(public.kind(), EntryKind::Sealed);
        assert_ne!(public.id(), private.id());
    }
    // Projection reports the non-empty dedup collision; publish must refuse it.
    let private = projection
        .private_files
        .iter()
        .find(|(path, _)| path == &p("a.key"))
        .unwrap()
        .1;
    assert!(projection
        .public_files
        .iter()
        .any(|(_, leaf)| leaf.id() == private.id()));
}

#[test]
fn absent_invalid_and_executable_rules_are_distinguished() {
    let store = MemoryStore::new();
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let absent = tree(&store, &[("a.key", b"key")]);
    assert_eq!(
        project_tree(&store, &absent, &key).unwrap().public_tree,
        absent
    );
    let invalid = tree(&store, &[(".private", b"[\n"), ("a.key", b"key")]);
    assert!(matches!(
        project_tree(&store, &invalid, &key),
        Err(ProjectError::Rules(_))
    ));
    let executable = apply_edits(
        &store,
        &absent,
        &BTreeMap::from([(
            p(".private"),
            Some(Leaf::executable(store.put_blob(b"*.key\n").unwrap())),
        )]),
    )
    .unwrap();
    assert_eq!(
        project_tree(&store, &executable, &key).unwrap().sealed[0].path,
        p("a.key")
    );
}

#[test]
fn unicode_and_case_folded_paths_are_classified_but_salts_bind_exact_paths() {
    let store = MemoryStore::new();
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let root = tree(
        &store,
        &[
            (".private", "CAFÉ.key\n".as_bytes()),
            ("cafe\u{301}.KEY", b"key"),
            ("CAFÉ.key", b"key"),
        ],
    );
    let projection = project_tree(&store, &root, &key).unwrap();
    assert_eq!(projection.private_files.len(), 2);
    assert!(projection
        .public_files
        .iter()
        .all(|(path, _)| path == &p(".private")));
    let a = lookup(&store, &projection.public_tree, &p("cafe\u{301}.KEY"))
        .unwrap()
        .unwrap();
    let b = lookup(&store, &projection.public_tree, &p("CAFÉ.key"))
        .unwrap()
        .unwrap();
    assert_ne!(a.sealed_id(), b.sealed_id());
}

#[test]
fn deep_private_paths_collapse_without_recursion_in_projection() {
    let store = MemoryStore::new();
    let deep = format!("secrets/{}key", "d/".repeat(128));
    let root = tree(&store, &[(".private", b"secrets/\n"), (&deep, b"key")]);
    assert_eq!(
        project_tree(
            &store,
            &root,
            &EpochKey::generate(group("private", 1)).unwrap()
        )
        .unwrap()
        .sealed[0]
            .path,
        p("secrets")
    );
}

struct FailingRootLookup {
    store: MemoryStore,
    root: ObjectId,
    reads: AtomicUsize,
    writes: AtomicUsize,
    missing: bool,
}

impl Store for FailingRootLookup {
    fn get_raw(&self, id: &ObjectId) -> tig_core::Result<Option<(ObjectKind, Vec<u8>)>> {
        if id == &self.root && self.reads.fetch_add(1, Ordering::Relaxed) == 2 {
            if self.missing {
                let empty = tig_core::Tree::empty().encode();
                return Ok(Some((ObjectKind::Tree, empty)));
            }
            return Err(tig_core::Error::NotFound(*id));
        }
        self.store.get_raw(id)
    }

    fn put_raw(&self, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> tig_core::Result<()> {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.store.put_raw(id, kind, body)
    }

    fn has(&self, id: &ObjectId) -> tig_core::Result<bool> {
        self.store.has(id)
    }
}

#[test]
fn failing_or_vanished_sealed_root_aborts_without_public_tree_writes() {
    for missing in [false, true] {
        let store = MemoryStore::new();
        let root = tree(&store, &[(".private", b".env\n"), (".env", b"key")]);
        let faulty = FailingRootLookup {
            store,
            root,
            reads: AtomicUsize::new(0),
            writes: AtomicUsize::new(0),
            missing,
        };
        let error = project_tree(
            &faulty,
            &root,
            &EpochKey::generate(group("private", 1)).unwrap(),
        )
        .unwrap_err();
        if missing {
            assert!(error.to_string().contains("vanished"));
        } else {
            assert!(matches!(
                error,
                ProjectError::Core(tig_core::Error::NotFound(_))
            ));
        }
        assert_eq!(faulty.writes.load(Ordering::Relaxed), 0);
    }
}

#[test]
fn public_revision_replaces_tree_parents_and_drops_predecessors() {
    let signature = Signature {
        name: "author".into(),
        email: "a@example.com".into(),
        timestamp_ms: 1,
        tz_offset_min: 0,
    };
    let internal = Revision {
        tree: ObjectId([1; 32]),
        parents: vec![ObjectId([2; 32])],
        change_id: ChangeId([3; 16]),
        predecessors: vec![ObjectId([4; 32])],
        author: signature.clone(),
        committer: signature,
        description: "description".into(),
    };
    let public = public_revision(&internal, ObjectId([5; 32]), vec![ObjectId([6; 32])]);
    assert_eq!(public.tree, ObjectId([5; 32]));
    assert_eq!(public.parents, vec![ObjectId([6; 32])]);
    assert!(public.predecessors.is_empty());
    assert_eq!(public.change_id, internal.change_id);
    assert_eq!(public.author, internal.author);
    assert_eq!(public.committer, internal.committer);
    assert_eq!(public.description, internal.description);
    for id in [internal.tree, internal.parents[0], internal.predecessors[0]] {
        assert!(!public
            .encode()
            .windows(32)
            .any(|bytes| bytes == id.as_bytes()));
    }
}

#[test]
fn wrap_checks_low_order_points_and_binds_the_ephemeral_key() {
    let identity = Identity::generate().unwrap();
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let context = group("private", 1);
    for point in [
        "00".repeat(32),
        format!("01{}", "00".repeat(31)),
        format!("ec{}7f", "ff".repeat(30)),
    ] {
        let point: [u8; 32] = hex::decode(point).unwrap().try_into().unwrap();
        assert!(matches!(
            wrap(
                &key,
                &PublicIdentity {
                    encryption: point,
                    signing: identity.public().signing
                }
            ),
            Err(KeyError::WeakKey)
        ));
        let bad = WrappedKey {
            ephemeral: point,
            nonce: [0; 24],
            ciphertext: vec![0; 48],
        };
        assert!(matches!(
            unwrap_unverified(&bad, &context, &identity),
            Err(KeyError::WeakKey)
        ));
    }
    let wrapped = wrap(&key, &identity.public()).unwrap();
    let mut alias = wrapped.clone();
    // X25519 ignores this high bit; the KDF must still bind the transmitted bytes.
    alias.ephemeral[31] ^= 0x80;
    assert!(unwrap_unverified(&alias, &context, &identity).is_err());
    let mut tampered = wrapped.clone();
    tampered.nonce[0] ^= 1;
    assert!(unwrap_unverified(&tampered, &context, &identity).is_err());
    assert!(unwrap_unverified(&wrapped, &group("private\0", 1), &identity).is_err());
    assert!(unwrap_unverified(&wrapped, &context, &Identity::generate().unwrap()).is_err());
}

#[test]
fn objects_are_deterministic_and_bind_all_aad_fields() {
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let body = b"secret";
    let id = hash_object(ObjectKind::Blob, body);
    let ciphertext = key.encrypt_object(ObjectKind::Blob, &id, body).unwrap();
    assert_eq!(
        key.encrypt_object(ObjectKind::Blob, &id, body).unwrap(),
        ciphertext
    );
    for context in [group("private\0", 1), group("private", 2), group("", 1)] {
        let other = EpochKey::from_bytes(context, *key.to_bytes());
        assert!(other
            .decrypt_object(ObjectKind::Blob, &id, &ciphertext)
            .is_err());
    }
    assert!(key
        .decrypt_object(ObjectKind::Tree, &id, &ciphertext)
        .is_err());
    assert!(key
        .decrypt_object(ObjectKind::Blob, &ObjectId([7; 32]), &ciphertext)
        .is_err());
    for end in [0, 15, ciphertext.len() - 1] {
        assert!(key
            .decrypt_object(ObjectKind::Blob, &id, &ciphertext[..end])
            .is_err());
    }
    let mut bad = ciphertext.clone();
    bad[0] ^= 1;
    assert!(key.decrypt_object(ObjectKind::Blob, &id, &bad).is_err());
}

#[test]
fn salt_domains_bind_path_length_kind_content_and_epoch_key() {
    let key = EpochKey::generate(group("private", 1)).unwrap();
    let other = EpochKey::generate(group("private", 1)).unwrap();
    let id = hash_object(ObjectKind::Blob, b"secret");
    let sealed = key.seal(&p("a.key"), EntryKind::File, &id);
    assert_eq!(sealed, key.seal(&p("a.key"), EntryKind::File, &id));
    for kind in [EntryKind::Executable, EntryKind::Symlink, EntryKind::Tree] {
        assert_ne!(sealed, key.seal(&p("a.key"), kind, &id));
    }
    assert_ne!(sealed, key.seal(&p("a.key/b"), EntryKind::File, &id));
    assert_ne!(sealed, other.seal(&p("a.key"), EntryKind::File, &id));
    let salt = key.seal_salt(&p("a.key"), EntryKind::File, &id);
    assert!(sealed.verify(&salt, EntryKind::File, &id));
    assert!(!sealed.verify(&salt, EntryKind::Executable, &id));
    assert!(!sealed.verify(&salt, EntryKind::File, &ObjectId([9; 32])));
    assert_ne!(key.wire_id(&id).0, id.0);
    assert_ne!(key.wire_id(&id).0, *sealed.as_bytes());
    assert_ne!(key.wire_id(&id), other.wire_id(&id));
    assert_eq!(format!("{key:?}"), "EpochKey(..)");
    assert_eq!(format!("{salt:?}"), "SealSalt(..)");
    let identity = Identity::from_bytes([0xaa; 64]);
    assert!(!format!("{identity:?}").contains(&hex::encode(*identity.to_bytes())));
}
