//! Publish and fetch formats: sealed packs, the keyring, and a directory remote.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::Path;

use tig_core::object::hash_object;
use tig_core::seal::{SealSalt, SealedId};
use tig_core::store::StoreExt;
use tig_core::{EntryKind, ObjectId, ObjectKind, RepoPath};
use tig_private::keyring::{Keyring, KeyringError, OwnerKeys};
use tig_private::keys::{self, EpochKey, GroupEpoch, Identity, KeyError};
use tig_private::pack::{Pack, PackBuilder, PackError};
use tig_private::project::PRIVATE_GROUP;
use tig_private::remote::{DirRemote, RemoteError};

fn blob(body: &[u8]) -> (ObjectId, &[u8]) {
    (hash_object(ObjectKind::Blob, body), body)
}

fn context(remote: [u8; 16], group: &str, epoch: u64) -> GroupEpoch {
    GroupEpoch {
        remote,
        group: group.to_string(),
        epoch,
    }
}

fn path(name: &str) -> RepoPath {
    RepoPath::new(name).unwrap()
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn err_text<T, E: std::fmt::Display>(result: Result<T, E>) -> String {
    match result {
        Err(err) => err.to_string(),
        Ok(_) => panic!("expected an error"),
    }
}

/// Walks a pack the same way `Pack::peek_header` does, and records the
/// ranges tests need to edit. A one-object pack's count is one byte.
struct Parts {
    count_at: usize,
    index_ct: Range<usize>,
    /// Each object entry: wire id, then its length-prefixed ciphertext.
    objects: Vec<Range<usize>>,
}

fn parts(bytes: &[u8]) -> Parts {
    let mut cursor = Cursor { buf: bytes, pos: 0 };
    assert_eq!(cursor.take(4), b"TIGP");
    assert_eq!(cursor.u8(), 1);
    let _remote = cursor.take(16);
    let group_len = cursor.varint() as usize;
    let _group = cursor.take(group_len);
    let _epoch = cursor.varint();
    let _nonce = cursor.take(24);
    let index_len = cursor.varint() as usize;
    let index_start = cursor.pos;
    let _index = cursor.take(index_len);
    let count_at = cursor.pos;
    let count = cursor.varint();
    assert_eq!(
        cursor.pos - count_at,
        1,
        "surgery below assumes a one-byte count"
    );
    let mut objects = Vec::new();
    for _ in 0..count {
        let start = cursor.pos;
        let _wire = cursor.take(32);
        let cipher_len = cursor.varint() as usize;
        let _cipher = cursor.take(cipher_len);
        objects.push(start..cursor.pos);
    }
    assert_eq!(cursor.pos, bytes.len());
    Parts {
        count_at,
        index_ct: index_start..index_start + index_len,
        objects,
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> u8 {
        let byte = self.buf[self.pos];
        self.pos += 1;
        byte
    }

    fn take(&mut self, n: usize) -> &'a [u8] {
        let start = self.pos;
        self.pos += n;
        &self.buf[start..self.pos]
    }

    fn varint(&mut self) -> u64 {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let byte = self.u8();
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return value;
            }
        }
        panic!("varint does not fit");
    }
}

fn one_object(key: &EpochKey, body: &[u8]) -> (Vec<u8>, ObjectId) {
    let (id, body) = blob(body);
    let mut builder = PackBuilder::new(key);
    builder.add_object(ObjectKind::Blob, id, body).unwrap();
    (builder.finish().unwrap(), id)
}

#[test]
fn pack_round_trip_dedups_and_hides_plain_ids() {
    let remote = [7u8; 16];
    let key = EpochKey::generate(context(remote, "private", 1)).unwrap();
    let (id_a, body_a) = blob(b"alpha-secret-one");
    let (id_b, body_b) = blob(b"beta-secret-two");
    let sealed_path = path(".env");
    let sealed = key.seal(&sealed_path, EntryKind::File, &id_a);

    let mut builder = PackBuilder::new(&key);
    builder.add_object(ObjectKind::Blob, id_a, body_a).unwrap();
    builder.add_object(ObjectKind::Blob, id_a, body_a).unwrap();
    assert!(matches!(
        builder.add_object(ObjectKind::Blob, id_a, b"not-the-body"),
        Err(PackError::Key(KeyError::ObjectMismatch))
    ));
    builder.add_object(ObjectKind::Blob, id_b, body_b).unwrap();
    builder
        .add_sealed(sealed, sealed_path.clone(), EntryKind::File, id_a)
        .unwrap();
    let bytes = builder.finish().unwrap();

    let header = Pack::peek_header(&bytes).unwrap();
    assert_eq!(header.remote, remote);
    assert_eq!(header.group, "private");
    assert_eq!(header.epoch, 1);
    assert_eq!(header.wire_ids.len(), 2);
    assert!(header.wire_ids.contains(&key.wire_id(&id_a)));
    assert!(header.wire_ids.contains(&key.wire_id(&id_b)));
    assert!(!contains(&bytes, id_a.as_bytes()));
    assert!(!contains(&bytes, id_b.as_bytes()));
    assert!(!contains(&bytes, body_a));
    assert!(!contains(&bytes, body_b));
    assert!(!contains(&bytes, sealed_path.as_str().as_bytes()));

    let opened = Pack::open(&bytes, &key).unwrap();
    assert_eq!(opened.objects.len(), 2);
    let mut found = BTreeMap::new();
    for (kind, id, body) in &opened.objects {
        assert_eq!(*kind, ObjectKind::Blob);
        found.insert(*id, body.clone());
    }
    assert_eq!(&found[&id_a][..], body_a);
    assert_eq!(&found[&id_b][..], body_b);
    assert_eq!(opened.sealed.len(), 1);
    assert_eq!(opened.sealed[0].sealed_id, sealed);
    assert_eq!(opened.sealed[0].path, sealed_path);
    assert_eq!(opened.sealed[0].kind, EntryKind::File);
    assert_eq!(opened.sealed[0].target, id_a);
}

#[test]
fn pack_rejects_a_key_from_another_context() {
    let remote = [7u8; 16];
    let key = EpochKey::generate(context(remote, "private", 1)).unwrap();
    let (bytes, _) = one_object(&key, b"alpha-secret-one");
    let secret = *key.to_bytes();

    for other in [
        context([1; 16], "private", 1),
        context(remote, "billing", 1),
        context(remote, "private", 2),
    ] {
        let rebound = EpochKey::from_bytes(other, secret);
        assert!(matches!(
            Pack::open(&bytes, &rebound),
            Err(PackError::ContextMismatch)
        ));
    }

    let same_context = EpochKey::generate(context(remote, "private", 1)).unwrap();
    assert!(matches!(
        Pack::open(&bytes, &same_context),
        Err(PackError::Key(KeyError::Decrypt))
    ));
}

#[test]
fn pack_rejects_tampered_bytes() {
    let key = EpochKey::generate(context([7; 16], "private", 1)).unwrap();
    let (bytes, _) = one_object(&key, b"alpha-secret-one");
    let layout = parts(&bytes);

    let mut magic = bytes.clone();
    magic[0] ^= 1;
    assert!(Pack::peek_header(&magic).is_err());

    let mut index = bytes.clone();
    let flipped = layout.index_ct.end - 1;
    index[flipped] ^= 0xff;
    assert!(Pack::peek_header(&index).is_ok());
    assert!(matches!(
        Pack::open(&index, &key),
        Err(PackError::Key(KeyError::Decrypt))
    ));

    let mut object = bytes.clone();
    let flipped = layout.objects[0].end - 1;
    object[flipped] ^= 0xff;
    assert!(Pack::peek_header(&object).is_ok());
    assert!(matches!(
        Pack::open(&object, &key),
        Err(PackError::Key(KeyError::Decrypt))
    ));

    let mut remote = bytes.clone();
    remote[5] ^= 1;
    let header = Pack::peek_header(&remote).unwrap();
    assert_ne!(header.remote, key.context().remote);
    assert!(matches!(
        Pack::open(&remote, &key),
        Err(PackError::ContextMismatch)
    ));

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(Pack::peek_header(&trailing)
        .unwrap_err()
        .to_string()
        .contains("trailing"));

    let mut nonminimal = Vec::from(&b"TIGP"[..]);
    nonminimal.push(1);
    nonminimal.extend_from_slice(&[7; 16]);
    nonminimal.extend_from_slice(&[0x80, 0x00]);
    assert!(Pack::peek_header(&nonminimal)
        .unwrap_err()
        .to_string()
        .contains("non-minimal"));
}

#[test]
fn pack_rejects_missing_extra_and_duplicate_wire_ids() {
    let key = EpochKey::generate(context([7; 16], "private", 1)).unwrap();
    let (bytes, _) = one_object(&key, b"alpha-secret-one");
    let layout = parts(&bytes);
    assert_eq!(bytes[layout.count_at], 1);

    let mut duplicate = bytes.clone();
    duplicate[layout.count_at] = 2;
    duplicate.extend_from_slice(&bytes[layout.objects[0].clone()]);
    assert!(Pack::peek_header(&duplicate)
        .unwrap_err()
        .to_string()
        .contains("duplicate"));
    assert!(Pack::open(&duplicate, &key)
        .unwrap_err()
        .to_string()
        .contains("duplicate"));

    let mut missing = bytes[..layout.count_at].to_vec();
    missing.push(0);
    assert!(Pack::peek_header(&missing).unwrap().wire_ids.is_empty());
    assert!(Pack::open(&missing, &key)
        .unwrap_err()
        .to_string()
        .contains("missing"));

    let mut extra = bytes.clone();
    extra[layout.count_at] = 2;
    extra.extend_from_slice(&[0xab; 32]);
    extra.push(0);
    assert_eq!(Pack::peek_header(&extra).unwrap().wire_ids.len(), 2);
    assert!(Pack::open(&extra, &key)
        .unwrap_err()
        .to_string()
        .contains("extra"));
}

#[test]
fn pack_rejects_a_sealed_record_that_does_not_verify() {
    let key = EpochKey::generate(context([7; 16], "private", 1)).unwrap();
    let (id, body) = blob(b"alpha-secret-one");
    let sealed_path = path(".env");
    let wrong = SealedId::compute(&SealSalt::from_bytes([9; 32]), EntryKind::File, &id);
    let mut builder = PackBuilder::new(&key);
    builder.add_object(ObjectKind::Blob, id, body).unwrap();
    builder
        .add_sealed(wrong, sealed_path, EntryKind::File, id)
        .unwrap();
    let bytes = builder.finish().unwrap();
    assert!(Pack::open(&bytes, &key)
        .unwrap_err()
        .to_string()
        .contains("sealed"));
}

#[test]
fn keyring_grant_revoke_keeps_old_epoch_and_refuses_rollback() {
    let remote = [3u8; 16];
    let owner = Identity::generate().unwrap();
    let alice = Identity::generate().unwrap();
    let pin = owner.public().signing;
    let (mut keyring, mut owner_keys) = Keyring::create(remote, &owner).unwrap();
    assert_eq!(keyring.head.counter, 1);
    assert_eq!(keyring.head.epochs.get(PRIVATE_GROUP), Some(&1));

    let encoded = keyring.encode().unwrap();
    assert_eq!(
        Keyring::decode(&encoded).unwrap().encode().unwrap(),
        encoded
    );
    let stored = owner_keys.encode().unwrap();
    let restored = OwnerKeys::decode(&stored).unwrap();
    assert_eq!(restored.encode().unwrap(), stored);
    assert_eq!(
        *restored
            .keys
            .get(&(PRIVATE_GROUP.to_string(), 1))
            .unwrap()
            .to_bytes(),
        *owner_keys
            .keys
            .get(&(PRIVATE_GROUP.to_string(), 1))
            .unwrap()
            .to_bytes()
    );

    keyring.grant(&owner_keys, &owner, &alice.public()).unwrap();
    assert_eq!(keyring.head.counter, 2);
    let epoch1 = {
        let key = owner_keys
            .keys
            .get(&(PRIVATE_GROUP.to_string(), 1))
            .unwrap();
        EpochKey::from_bytes(key.context().clone(), *key.to_bytes())
    };
    let (pack, id) = one_object(&epoch1, b"still-readable");
    let before_revoke = keyring.encode().unwrap();
    assert_eq!(
        Keyring::decode(&before_revoke).unwrap().encode().unwrap(),
        before_revoke
    );

    keyring
        .revoke(&mut owner_keys, &owner, &alice.public())
        .unwrap();
    assert_eq!(keyring.head.counter, 3);
    assert_eq!(keyring.head.epochs.get(PRIVATE_GROUP), Some(&2));
    let after = keyring.encode().unwrap();
    assert_eq!(Keyring::decode(&after).unwrap().encode().unwrap(), after);

    let verified = keyring.verify(&pin, 2).unwrap();
    assert_eq!(verified.counter(), 3);
    let alice_old = verified.key_for(PRIVATE_GROUP, 1, &alice).unwrap();
    assert_eq!(*alice_old.to_bytes(), *epoch1.to_bytes());
    assert_eq!(alice_old.context().epoch, 1);
    let opened = Pack::open(&pack, &alice_old).unwrap();
    assert_eq!(&opened.objects[0].2[..], b"still-readable");
    assert_eq!(opened.objects[0].1, id);

    for err in [
        verified.current_key(PRIVATE_GROUP, &alice).unwrap_err(),
        verified.key_for(PRIVATE_GROUP, 2, &alice).unwrap_err(),
    ] {
        assert!(matches!(err, KeyringError::NotMember));
        assert_eq!(err.to_string(), "you are not a member");
    }

    let owner_now = verified.current_key(PRIVATE_GROUP, &owner).unwrap();
    assert_eq!(owner_now.context().epoch, 2);
    assert_ne!(*owner_now.to_bytes(), *epoch1.to_bytes());
    assert!(matches!(
        Pack::open(&pack, &owner_now),
        Err(PackError::ContextMismatch)
    ));

    let rolled = Keyring::decode(&before_revoke).unwrap();
    assert_eq!(err_text(rolled.verify(&pin, 3)), "keyring head rolled back");
    assert!(rolled.verify(&pin, 2).is_ok());
    assert!(keyring.verify(&pin, 2).is_ok());
}

#[test]
fn keyring_refuses_a_head_signed_by_someone_else() {
    let owner = Identity::generate().unwrap();
    let eve = Identity::generate().unwrap();
    let (mut keyring, _) = Keyring::create([3; 16], &owner).unwrap();
    keyring.head.signature = eve.sign(&keyring.head.signing_bytes());
    assert!(err_text(keyring.verify(&owner.public().signing, 1)).contains("bad head signature"));
    assert!(err_text(keyring.verify(&eve.public().signing, 1)).contains("does not match the pin"));
}

#[test]
fn keyring_refuses_a_grant_from_another_remote() {
    let owner = Identity::generate().unwrap();
    let pin = owner.public().signing;
    let (keyring, _) = Keyring::create([3; 16], &owner).unwrap();
    let (other, _) = Keyring::create([4; 16], &owner).unwrap();
    let foreign = other.grants[0].clone();
    assert!(foreign.verify_signature(&pin).is_ok());
    assert_ne!(foreign.context.remote, keyring.remote);

    let mut spliced = keyring.clone();
    spliced.grants.push(foreign);
    assert!(err_text(spliced.verify(&pin, 1)).contains("different remote"));
}

#[test]
fn keyring_refuses_a_server_substituted_grant() {
    let owner = Identity::generate().unwrap();
    let eve = Identity::generate().unwrap();
    let bob = Identity::generate().unwrap();
    let pin = owner.public().signing;
    let (keyring, owner_keys) = Keyring::create([3; 16], &owner).unwrap();
    let epoch_key = owner_keys
        .keys
        .get(&(PRIVATE_GROUP.to_string(), 1))
        .unwrap();
    let fake = keys::grant(epoch_key, &bob.public(), &eve).unwrap();
    assert!(fake.verify_signature(&eve.public().signing).is_ok());
    assert!(fake.verify_signature(&pin).is_err());

    let mut substituted = keyring.clone();
    substituted.grants.push(fake);
    assert!(substituted.verify(&pin, 1).is_err());
}

#[test]
fn directory_remote_stores_packs_refs_and_public_objects() {
    let dir = tempfile::tempdir().unwrap();
    let remote_id = [9u8; 16];
    let remote = DirRemote::create(dir.path(), remote_id).unwrap();
    assert_eq!(remote.remote_id(), remote_id);
    assert!(remote
        .read_keyring()
        .unwrap_err()
        .to_string()
        .contains("missing"));

    let reopened = DirRemote::open(dir.path()).unwrap();
    assert_eq!(reopened.remote_id(), remote_id);
    let blob_id = remote.public_store().put_blob(b"public-readme").unwrap();
    assert_eq!(
        reopened.public_store().get_blob(&blob_id).unwrap(),
        b"public-readme"
    );

    let key = EpochKey::generate(context(remote_id, PRIVATE_GROUP, 1)).unwrap();
    let (pack, _) = one_object(&key, b"alpha-secret-one");
    remote.put_pack(&pack).unwrap();
    remote.put_pack(&pack).unwrap();
    let listed = remote.list_packs(PRIVATE_GROUP, 1).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0], pack);
    assert!(remote.list_packs(PRIVATE_GROUP, 9).unwrap().is_empty());

    let (other_pack, _) = one_object(&key, b"beta-secret-two");
    remote.put_pack(&other_pack).unwrap();
    assert_eq!(remote.list_packs(PRIVATE_GROUP, 1).unwrap().len(), 2);

    let refs = BTreeMap::from([
        ("main".to_string(), blob_id),
        ("topic".to_string(), ObjectId([2; 32])),
    ]);
    // Legacy unsigned refs are not part of the head. A pre-manifest remote
    // still has the file; new remotes do not create it.
    let mut refs_bytes = tig_core::encode::Writer::new();
    refs_bytes.u8(1);
    refs_bytes.varint(refs.len() as u64);
    for (name, id) in &refs {
        refs_bytes.str(name);
        refs_bytes.id(id);
    }
    std::fs::write(dir.path().join("refs"), refs_bytes.finish()).unwrap();
    assert_eq!(remote.read_refs().unwrap(), refs);

    let head = remote.read_head().unwrap();
    assert!(matches!(
        remote
            .commit_head(&head.version(), Some(b"keyring-bytes"), None)
            .unwrap(),
        tig_private::remote::CommitOutcome::Committed(_)
    ));
    assert_eq!(remote.read_keyring().unwrap(), b"keyring-bytes");

    let again = DirRemote::create(dir.path(), remote_id).unwrap();
    assert_eq!(again.read_refs().unwrap(), refs);
    assert_eq!(again.read_keyring().unwrap(), b"keyring-bytes");
    assert_eq!(
        DirRemote::open(dir.path()).unwrap().read_refs().unwrap(),
        refs
    );
    assert!(err_text(DirRemote::create(dir.path(), [1; 16])).contains("does not match"));
}

#[test]
fn directory_remote_refuses_group_names_that_escape() {
    let dir = tempfile::tempdir().unwrap();
    let remote_id = [9u8; 16];
    let remote = DirRemote::create(dir.path(), remote_id).unwrap();

    for group in ["..", "a/b", ""] {
        let key = EpochKey::from_bytes(context(remote_id, group, 1), [1; 32]);
        let bytes = PackBuilder::new(&key).finish().unwrap();
        assert!(
            matches!(remote.put_pack(&bytes), Err(RemoteError::BadGroup(_))),
            "{group:?}"
        );
        assert!(matches!(
            remote.list_packs(group, 1),
            Err(RemoteError::BadGroup(_))
        ));
    }

    assert!(
        !dir.path().join("1").exists(),
        "packs/../1 must not be created"
    );
    assert!(!dir.path().join("packs").join("a").exists());
    assert_empty_dir(&dir.path().join("packs"));

    let key = EpochKey::generate(context(remote_id, PRIVATE_GROUP, 1)).unwrap();
    let (pack, _) = one_object(&key, b"alpha-secret-one");
    remote.put_pack(&pack).unwrap();
    assert_eq!(remote.list_packs(PRIVATE_GROUP, 1).unwrap().len(), 1);
}

fn assert_empty_dir(path: &Path) {
    let mut entries = std::fs::read_dir(path).unwrap();
    assert!(entries.next().is_none());
}
