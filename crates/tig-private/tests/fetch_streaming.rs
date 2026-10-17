//! Chunk closure and manifest-directed pack downloads at the fetch boundary.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use tig_core::blob::{for_each_content, CHUNK_LEN};
use tig_core::repo::{root_revision, root_revision_id};
use tig_core::store::{Store, StoreExt};
use tig_core::{ChangeId, EntryKind, MemoryStore, Object, ObjectId, ObjectKind, RepoPath, Tree, TreeEntry};
use tig_private::fetch::{fetch, FetchState};
use tig_private::keyring::Keyring;
use tig_private::keys::Identity;
use tig_private::manifest::{pack_id, Manifest, PackEntry};
use tig_private::pack::PackBuilder;
use tig_private::publish::PublishState;
use tig_private::remote::{CommitOutcome, DirRemote, HeadVersion, Remote, RemoteError, RemoteHead};

fn tip(remote: &DirRemote, tree: ObjectId) -> ObjectId {
    let public = remote.public_store();
    public.put(&Object::Tree(Tree::empty())).unwrap();
    public.put(&Object::Revision(root_revision())).unwrap();
    let mut revision = root_revision();
    revision.change_id = ChangeId([181; 16]);
    revision.parents = vec![root_revision_id()];
    revision.tree = tree;
    public.put(&Object::Revision(revision)).unwrap()
}

fn commit(remote: &DirRemote, owner: &Identity, keyring: &Keyring, tip: ObjectId, packs: BTreeMap<[u8; 32], PackEntry>) {
    let manifest = Manifest::signed(remote.remote_id(), 1, BTreeMap::from([("main".into(), tip)]), packs, owner).unwrap();
    let version = remote.read_head().unwrap().version();
    assert!(matches!(remote.commit_head(&version, Some(&keyring.encode().unwrap()), Some(&manifest.encode().unwrap())).unwrap(), CommitOutcome::Committed(_)));
}

#[test]
fn public_chunked_file_fetches_and_validates_its_complete_closure() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [180; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let (keyring, _) = Keyring::create(remote.remote_id(), &owner).unwrap();
    let source = MemoryStore::new();
    let mut data = vec![19; CHUNK_LEN + 31];
    data[CHUNK_LEN..].fill(37);
    let file = source.put_blob(&data).unwrap();
    for_each_content::<_, tig_core::Error>(&source, &file, |kind, id, body| remote.public_store().put_raw(&id, kind, body)).unwrap();
    let tree = remote.public_store().put(&Object::Tree(Tree::new(vec![TreeEntry::new("large.bin", EntryKind::File, file).unwrap()]).unwrap())).unwrap();
    commit(&remote, &owner, &keyring, tip(&remote, tree), BTreeMap::new());

    let local = MemoryStore::new();
    let mut state = FetchState::new();
    let report = fetch(&remote, &local, None, &mut state, &PublishState::new()).unwrap();
    assert_eq!(local.get_blob(&file).unwrap(), data);
    assert_eq!(local.get_revision(&report.refs["main"]).unwrap().tree, tree);
    assert_eq!(state.manifest_seq, 1);
}

#[test]
fn missing_chunk_does_not_advance_correspondence_or_rollback_floors() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [182; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let (keyring, _) = Keyring::create(remote.remote_id(), &owner).unwrap();
    let source = MemoryStore::new();
    let file = source.put_blob(&vec![41; CHUNK_LEN + 1]).unwrap();
    let (kind, body) = source.get_raw(&file).unwrap().unwrap();
    remote.public_store().put_raw(&file, kind, &body).unwrap();
    let tree = remote.public_store().put(&Object::Tree(Tree::new(vec![TreeEntry::new("large.bin", EntryKind::File, file).unwrap()]).unwrap())).unwrap();
    commit(&remote, &owner, &keyring, tip(&remote, tree), BTreeMap::new());
    let mut state = FetchState::new();
    let before = state.clone();
    assert!(fetch(&remote, &MemoryStore::new(), None, &mut state, &PublishState::new()).is_err());
    assert_eq!(state, before);
}

/// A fetch transport that supports bounded pack reads and refuses the old
/// epoch-wide ciphertext buffer. It also records which packs were downloaded.
struct BoundedPacks {
    remote: DirRemote,
    downloaded: Mutex<Vec<[u8; 32]>>,
}

impl Remote for BoundedPacks {
    fn remote_id(&self) -> [u8; 16] { self.remote.remote_id() }
    fn public_store(&self) -> &dyn Store { self.remote.public_store() }
    fn missing(&self, ids: &[ObjectId]) -> Result<Vec<ObjectId>, RemoteError> { self.remote.missing(ids) }
    fn put_batch(&self, objects: &[(ObjectId, ObjectKind, Vec<u8>)]) -> Result<(), RemoteError> { self.remote.put_batch(objects) }
    fn get_batch(&self, ids: &[ObjectId]) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, RemoteError> { self.remote.get_batch(ids) }
    fn put_pack(&self, bytes: &[u8]) -> Result<(), RemoteError> { self.remote.put_pack(bytes) }
    fn list_packs(&self, _: &str, _: u64) -> Result<Vec<Vec<u8>>, RemoteError> {
        Err(RemoteError::Invalid("fetch requested an epoch-wide ciphertext buffer".into()))
    }
    fn list_pack_ids(&self, group: &str, epoch: u64) -> Result<Vec<[u8; 32]>, RemoteError> { self.remote.list_pack_ids(group, epoch) }
    fn get_pack(&self, group: &str, epoch: u64, id: &[u8; 32]) -> Result<Option<Vec<u8>>, RemoteError> {
        self.downloaded.lock().unwrap().push(*id);
        self.remote.get_pack(group, epoch, id)
    }
    fn read_head(&self) -> Result<RemoteHead, RemoteError> { self.remote.read_head() }
    fn commit_head(&self, expected: &HeadVersion, keyring: Option<&[u8]>, manifest: Option<&[u8]>) -> Result<CommitOutcome, RemoteError> { self.remote.commit_head(expected, keyring, manifest) }
}

#[test]
fn private_chunk_closure_can_span_packs_and_orphans_are_not_downloaded() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [183; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let (keyring, keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
    let key = &keys.keys[&("private".into(), 1)];
    let source = MemoryStore::new();
    let mut data = vec![51; CHUNK_LEN + 29];
    data[CHUNK_LEN..].fill(73);
    let file = source.put_blob(&data).unwrap();
    let path = RepoPath::new(".env").unwrap();
    let sealed = key.seal(&path, EntryKind::File, &file);
    let objects = tig_core::blob::content_objects(&source, &file).unwrap();
    let mut packs = BTreeMap::new();
    let mut required = BTreeSet::new();
    for (number, part) in objects.chunks(2).enumerate() {
        let mut builder = PackBuilder::new(key);
        for (kind, id) in part {
            builder.add_object(*kind, *id, &source.get_raw(id).unwrap().unwrap().1).unwrap();
        }
        let seals = if number == 1 {
            builder.add_sealed(sealed, path.clone(), EntryKind::File, file).unwrap();
            BTreeSet::from([sealed])
        } else { BTreeSet::new() };
        let bytes = builder.finish().unwrap();
        remote.put_pack(&bytes).unwrap();
        let id = pack_id(&bytes);
        required.insert(id);
        packs.insert(id, PackEntry { group: "private".into(), epoch: 1, sealed: seals });
    }
    let mut orphan = PackBuilder::new(key);
    let orphan_body = b"uncommitted private content";
    orphan.add_object(ObjectKind::Blob, tig_core::object::hash_object(ObjectKind::Blob, orphan_body), orphan_body).unwrap();
    remote.put_pack(&orphan.finish().unwrap()).unwrap();
    let tree = remote.public_store().put(&Object::Tree(Tree::new(vec![TreeEntry::sealed(".env", sealed).unwrap()]).unwrap())).unwrap();
    commit(&remote, &owner, &keyring, tip(&remote, tree), packs);

    let transport = BoundedPacks { remote, downloaded: Mutex::new(Vec::new()) };
    let local = MemoryStore::new();
    let mut state = FetchState::new();
    let report = fetch(&transport, &local, Some(&owner), &mut state, &PublishState::new()).unwrap();
    assert_eq!(report.unsealed, 1);
    assert_eq!(local.get_blob(&file).unwrap(), data);
    assert_eq!(transport.downloaded.lock().unwrap().iter().copied().collect::<BTreeSet<_>>(), required);
}

#[test]
fn legacy_pack_above_batch_target_fetches_and_tampering_preserves_state() {
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [179; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let (keyring, keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
    let key = &keys.keys[&("private".into(), 1)];
    let bytes = vec![89; 17 * 1024 * 1024];
    let file = tig_core::object::hash_object(ObjectKind::Blob, &bytes);
    let path = RepoPath::new(".env").unwrap();
    let sealed = key.seal(&path, EntryKind::File, &file);
    let mut builder = PackBuilder::new(key);
    builder.add_object(ObjectKind::Blob, file, &bytes).unwrap();
    builder.add_sealed(sealed, path, EntryKind::File, file).unwrap();
    let mut pack = builder.finish().unwrap();
    assert!(pack.len() > tig_private::pack::PACK_BATCH_MAX);
    remote.put_pack(&pack).unwrap();
    let id = pack_id(&pack);
    let tree = remote.public_store().put(&Object::Tree(Tree::new(vec![TreeEntry::sealed(".env", sealed).unwrap()]).unwrap())).unwrap();
    commit(&remote, &owner, &keyring, tip(&remote, tree), BTreeMap::from([
        (id, PackEntry { group: "private".into(), epoch: 1, sealed: BTreeSet::from([sealed]) }),
    ]));
    let transport = BoundedPacks { remote, downloaded: Mutex::new(Vec::new()) };
    let local = MemoryStore::new();
    let mut state = FetchState::new();
    let report = fetch(&transport, &local, Some(&owner), &mut state, &PublishState::new()).unwrap();
    assert_eq!(report.unsealed, 1);
    assert_eq!(local.get_blob(&file).unwrap(), bytes);
    assert_eq!(*transport.downloaded.lock().unwrap(), vec![id]);
    *pack.last_mut().unwrap() ^= 1;
    std::fs::write(dir.path().join("packs/private/1").join(format!("{}.pack", hex::encode(id))), pack).unwrap();
    let before = state.clone();
    assert!(fetch(&transport, &MemoryStore::new(), Some(&owner), &mut state, &PublishState::new()).is_err());
    assert_eq!(state, before);
}

#[test]
fn ordinary_fetch_opens_capsules_later_in_place_and_remembers_reveals() {
    use tig_core::treeops::{apply_edits, lookup, Leaf};
    use tig_core::store::empty_tree_id;
    use tig_private::changes::{publish_seal, publish_reveal, SealRequest, RevealRequest};
    let dir = tempfile::tempdir().unwrap();
    let remote = DirRemote::create(dir.path(), [191; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let (keyring, keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
    let head = remote.read_head().unwrap();
    remote.commit_head(&head.version(), Some(&keyring.encode().unwrap()), None).unwrap();
    let source = MemoryStore::new();
    source.put(&Object::Tree(Tree::empty())).unwrap();
    source.put(&Object::Revision(root_revision())).unwrap();
    let tree = apply_edits(&source, &empty_tree_id(), &BTreeMap::from([
        (RepoPath::new("fix.txt").unwrap(), Some(Leaf::file(source.put_blob(b"security fix").unwrap()))),
        (RepoPath::new(".env").unwrap(), Some(Leaf::file(source.put_blob(b"TOKEN=independent-private-value").unwrap()))),
    ])).unwrap();
    let mut revision = root_revision();
    revision.tree = tree;
    revision.change_id = ChangeId([192; 16]);
    revision.parents = vec![root_revision_id()];
    revision.description = "embargoed security details".into();
    let internal = source.put(&Object::Revision(revision)).unwrap();
    let key = &keys.keys[&("private".into(), 1)];
    let sealed = publish_seal(&SealRequest {
        store: &source, remote: &remote, identity: &owner, keyring: &keyring,
        pinned_owner: &owner.public().signing, min_counter: 0, min_sequence: 0,
        bookmark: "main", revision: internal, public_parents: &[root_revision_id()],
        known_reveals: &BTreeSet::new(),
        role: "private", role_key: key, privacy_keys: &BTreeMap::from([("private".into(), key)]),
    }).unwrap();
    // A contributor can add an ordinary public child while its parent is
    // opaque. Opening the parent must replay this child's delta in place.
    let skeleton = remote.public_store().get_revision(&sealed.skeleton).unwrap();
    let child_tree = apply_edits(remote.public_store(), &skeleton.tree, &BTreeMap::from([
        (RepoPath::new("notes.txt").unwrap(), Some(Leaf::file(remote.public_store().put_blob(b"public child edit").unwrap()))),
    ])).unwrap();
    let mut child = root_revision();
    child.tree = child_tree;
    child.change_id = ChangeId([193; 16]);
    child.description = "public child".into();
    child.parents = vec![sealed.skeleton];
    let child_public = remote.public_store().put(&Object::Revision(child)).unwrap();
    let head = remote.read_head().unwrap();
    let old_manifest = Manifest::decode(head.manifest.as_ref().unwrap()).unwrap();
    let with_child = Manifest::signed_with_changes(remote.remote_id(), old_manifest.sequence + 1,
        BTreeMap::from([("main".into(), child_public)]), old_manifest.packs,
        old_manifest.changes, old_manifest.reveals, &owner).unwrap();
    remote.commit_head(&head.version(), None, Some(&with_child.encode().unwrap())).unwrap();
    let local = MemoryStore::new();
    let mut state = FetchState::new();
    let opaque = fetch(&remote, &local, None, &mut state, &PublishState::new()).unwrap().refs["main"];
    assert_eq!(local.get_revision(&opaque).unwrap().description, "public child");
    let opaque_parent = local.get_revision(&opaque).unwrap().parents[0];
    assert_eq!(local.get_revision(&opaque_parent).unwrap().description, "");
    let member = MemoryStore::new();
    let mut member_state = FetchState::new();
    let opened = fetch(&remote, &member, Some(&owner), &mut member_state, &PublishState::new()).unwrap().refs["main"];
    let member_tree = member.get_revision(&opened).unwrap().tree;
    let member_child = member.get_revision(&opened).unwrap();
    assert_eq!(member_child.description, "public child");
    assert_eq!(member.get_revision(&member_child.parents[0]).unwrap().description, "embargoed security details");
    assert!(lookup(&member, &member_tree, &RepoPath::new("fix.txt").unwrap()).unwrap().is_some());
    assert!(lookup(&member, &member_tree, &RepoPath::new("notes.txt").unwrap()).unwrap().is_some());
    assert!(lookup(&member, &member_tree, &RepoPath::new(".env").unwrap()).unwrap().unwrap().kind().is_file_like());
    publish_reveal(&RevealRequest {
        remote: &remote, owner: &owner, keyring: &keyring, pinned_owner: &owner.public().signing,
        min_counter: 0, min_sequence: 2, skeleton: sealed.skeleton, role_key: key,
        expected: &remote.read_head().unwrap().version(),
        known_reveals: &BTreeSet::new(),
    }).unwrap();
    let revealed = fetch(&remote, &local, None, &mut state, &PublishState::new()).unwrap().refs["main"];
    let revision = local.get_revision(&revealed).unwrap();
    assert_eq!(revision.change_id, ChangeId([193; 16]));
    assert!(revision.predecessors.contains(&opaque));
    assert_eq!(revision.description, "public child");
    assert_eq!(local.get_revision(&revision.parents[0]).unwrap().description, "embargoed security details");
    assert_eq!(lookup(&local, &revision.tree, &RepoPath::new(".env").unwrap()).unwrap().unwrap().kind(), EntryKind::Sealed);
    assert!(lookup(&local, &revision.tree, &RepoPath::new("fix.txt").unwrap()).unwrap().is_some());
    assert_eq!(state.revealed, BTreeSet::from([sealed.skeleton]));
    assert_eq!(FetchState::decode(&state.encode().unwrap()).unwrap(), state);
    let head = remote.read_head().unwrap();
    let previous = Manifest::decode(head.manifest.as_ref().unwrap()).unwrap();
    let dropped = Manifest::signed_with_changes(remote.remote_id(), previous.sequence + 1,
        previous.refs, previous.packs, previous.changes, BTreeMap::new(), &owner).unwrap();
    remote.commit_head(&head.version(), None, Some(&dropped.encode().unwrap())).unwrap();
    let before = state.clone();
    assert!(fetch(&remote, &local, None, &mut state, &PublishState::new()).unwrap_err().to_string().contains("dropped"));
    assert_eq!(state, before);
}
