//! Large-file transfer and secrecy at the publish/fetch boundary.

use std::io::{self, Read, Write};
use std::sync::Arc;

use tig_core::ophead::MemoryOpHead;
use tig_core::repo::{Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::store::StoreExt;
use tig_core::treeops::{lookup, Leaf};
use tig_core::workspace::Workspace;
use tig_core::{EntryKind, MemoryStore, RepoPath};
use tig_private::fetch::{fetch, FetchError, FetchState};
use tig_private::keyring::Keyring;
use tig_private::keys::Identity;
use tig_private::manifest::Manifest;
use tig_private::publish::{publish, PublishError, PublishOptions, PublishState};
use tig_private::remote::DirRemote;

const MIB: u64 = 1024 * 1024;

/// Each 4 MiB region has different bytes, so the large-file test cannot
/// accidentally exercise only one deduplicated chunk.
struct Pattern {
    position: u64,
    length: u64,
    salt: u8,
}

impl Read for Pattern {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let region = tig_core::blob::CHUNK_LEN as u64;
        let n = (out.len() as u64).min(self.length - self.position)
            .min(region - self.position % region) as usize;
        out[..n].fill(self.salt.wrapping_add((self.position / region) as u8));
        self.position += n as u64;
        Ok(n)
    }
}

impl Write for Pattern {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let written = bytes.len();
        let region = tig_core::blob::CHUNK_LEN as u64;
        while !bytes.is_empty() {
            let n = bytes.len().min((region - self.position % region) as usize);
            let expected = self.salt.wrapping_add((self.position / region) as u8);
            if self.position + n as u64 > self.length || bytes[..n].iter().any(|byte| *byte != expected) {
                return Err(io::Error::other("large-file bytes differ"));
            }
            self.position += n as u64;
            bytes = &bytes[n..];
        }
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

#[test]
fn private_file_above_256_mib_transfers_in_bounded_packs() {
    let source_dir = tempfile::TempDir::new().unwrap();
    let mut repo = Repo::init(
        Arc::new(tig_core::store::DiskStore::open(source_dir.path()).unwrap()),
        Arc::new(MemoryOpHead::new()), Settings::default(),
    ).unwrap();
    let public_len = 9 * MIB;
    let private_len = 270 * MIB;
    let public_id = tig_core::blob::put_reader(repo.store().as_ref(), Pattern { position: 0, length: public_len, salt: 190 }).unwrap();
    let private_id = tig_core::blob::put_reader(repo.store().as_ref(), Pattern { position: 0, length: private_len, salt: 7 }).unwrap();
    let mut workspace = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    workspace.write(&repo, &RepoPath::new(".private").unwrap(), b"secrets/\n").unwrap();
    workspace.set(&repo, RepoPath::new("public.bin").unwrap(), Some(Leaf::file(public_id))).unwrap();
    workspace.set(&repo, RepoPath::new("secrets/fix.bin").unwrap(), Some(Leaf::file(private_id))).unwrap();
    workspace.snapshot(&mut repo).unwrap();
    let remote_dir = tempfile::TempDir::new().unwrap();
    let remote = DirRemote::create(remote_dir.path(), [177; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let (_, keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
    publish(repo.store().as_ref(), &remote, &owner, Some(&keys), &mut PublishState::new(),
        &FetchState::new(), "main", workspace.working_revision(), &PublishOptions::default()).unwrap();

    let manifest = Manifest::decode(&remote.read_head().unwrap().manifest.unwrap()).unwrap();
    assert!(manifest.packs.len() > 1);
    for (id, entry) in &manifest.packs {
        let path = remote_dir.path().join("packs").join(&entry.group).join(entry.epoch.to_string())
            .join(format!("{}.pack", hex::encode(id)));
        assert!(std::fs::metadata(path).unwrap().len() <= tig_private::pack::PACK_BATCH_MAX as u64);
    }
    for id in tig_core::blob::content_ids(repo.store().as_ref(), &private_id).unwrap() {
        assert!(!remote.public_store().has(&id).unwrap(), "private object appeared in clear: {id}");
    }

    let dest_dir = tempfile::TempDir::new().unwrap();
    let dest = tig_core::store::DiskStore::open(dest_dir.path()).unwrap();
    let report = fetch(&remote, &dest, Some(&owner), &mut FetchState::new(), &PublishState::new()).unwrap();
    let tree = dest.get_revision(&report.refs["main"]).unwrap().tree;
    for (path, id, length, salt) in [("public.bin", public_id, public_len, 190), ("secrets/fix.bin", private_id, private_len, 7)] {
        let leaf = lookup(&dest, &tree, &RepoPath::new(path).unwrap()).unwrap().unwrap();
        assert_eq!(leaf.id(), id);
        let mut check = Pattern { position: 0, length, salt };
        assert_eq!(tig_core::blob::write_content(&dest, &id, &mut check).unwrap(), length);
        assert_eq!(check.position, length);
    }
    let outsider = MemoryStore::new();
    let report = fetch(&remote, &outsider, None, &mut FetchState::new(), &PublishState::new()).unwrap();
    let tree = outsider.get_revision(&report.refs["main"]).unwrap().tree;
    assert_eq!(lookup(&outsider, &tree, &RepoPath::new("secrets").unwrap()).unwrap().unwrap().kind(), EntryKind::Sealed);

    let (id, entry) = manifest.packs.iter().next_back().unwrap();
    let missing_pack = remote_dir.path().join("packs").join(&entry.group).join(entry.epoch.to_string())
        .join(format!("{}.pack", hex::encode(id)));
    std::fs::remove_file(missing_pack).unwrap();
    let mut state = FetchState::new();
    let before = state.clone();
    let error = fetch(&remote, &MemoryStore::new(), Some(&owner), &mut state, &PublishState::new()).unwrap_err();
    assert!(matches!(error, FetchError::WithheldPack { .. }), "{error}");
    assert_eq!(state, before);

    let (_, body) = repo.store().get_raw(&public_id).unwrap().unwrap();
    let manifest = tig_core::blob::parse_manifest(&body).unwrap();
    let missing_chunk = manifest.chunks()[0].id.to_hex();
    let path = remote_dir.path().join("objects").join(&missing_chunk[..2]).join(&missing_chunk[2..]);
    std::fs::remove_file(path).unwrap();
    let mut state = FetchState::new();
    let before = state.clone();
    assert!(fetch(&remote, &MemoryStore::new(), None, &mut state, &PublishState::new()).is_err());
    assert_eq!(state, before);
}

#[test]
fn private_chunk_copied_to_public_file_is_refused_before_upload() {
    let mut repo = Repo::init(
        Arc::new(MemoryStore::new()),
        Arc::new(MemoryOpHead::new()),
        Settings::default(),
    ).unwrap();
    let mut secret = vec![0u8; 9 * 1024 * 1024];
    for (i, byte) in secret.iter_mut().enumerate() {
        *byte = (i / (1024 * 1024) + 23) as u8;
    }
    let private_id = repo.store().put_blob(&secret).unwrap();
    let public_id = repo.store().put_blob(&secret[..4 * 1024 * 1024]).unwrap();
    let mut workspace = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
    workspace.write(&repo, &RepoPath::new(".private").unwrap(), b"secrets/\n").unwrap();
    workspace.set(&repo, RepoPath::new("secrets/fix.bin").unwrap(), Some(Leaf::file(private_id))).unwrap();
    workspace.set(&repo, RepoPath::new("public.bin").unwrap(), Some(Leaf::file(public_id))).unwrap();
    workspace.snapshot(&mut repo).unwrap();

    let dir = tempfile::TempDir::new().unwrap();
    let remote = DirRemote::create(dir.path(), [176; 16]).unwrap();
    let owner = Identity::generate().unwrap();
    let (_, keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
    let mut state = PublishState::new();
    let before = state.clone();
    let error = publish(
        repo.store().as_ref(), &remote, &owner, Some(&keys), &mut state,
        &FetchState::new(), "main", workspace.working_revision(), &PublishOptions::default(),
    ).unwrap_err();

    assert!(matches!(error, PublishError::PastedSecret { .. } | PublishError::PreviouslyPrivate { .. }), "{error}");
    assert_eq!(state, before);
    let head = remote.read_head().unwrap();
    assert!(head.keyring.is_none() && head.manifest.is_none());
    assert!(!remote.public_store().has(&public_id).unwrap());
    assert!(remote.list_packs("private", 1).unwrap().is_empty());
}

#[test]
fn deleted_private_file_copied_with_other_blob_encoding_is_refused_before_upload() {
    for private_chunked in [true, false] {
        let mut repo = Repo::init(Arc::new(MemoryStore::new()), Arc::new(MemoryOpHead::new()), Settings::default()).unwrap();
        let bytes = vec![41; tig_core::blob::CHUNK_LEN + 17];
        let chunked = repo.store().put_blob(&bytes).unwrap();
        let legacy = repo.store().put(&tig_core::Object::Blob(bytes)).unwrap();
        assert_ne!(chunked, legacy);
        let (private_id, public_id) = if private_chunked { (chunked, legacy) } else { (legacy, chunked) };
        let secret_path = RepoPath::new("secrets/old.bin").unwrap();
        let mut workspace = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
        workspace.write(&repo, &RepoPath::new(".private").unwrap(), b"secrets/\n").unwrap();
        workspace.set(&repo, secret_path.clone(), Some(Leaf::file(private_id))).unwrap();
        workspace.snapshot(&mut repo).unwrap();
        let parent = workspace.working_revision();
        let mut tx = repo.start("copy historically private content");
        let child = tx.new_change(&[parent], "remove private file and copy its bytes").unwrap();
        tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
        repo.commit(tx).unwrap();
        let mut workspace = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
        workspace.remove(&repo, &secret_path).unwrap();
        workspace.set(&repo, RepoPath::new("renamed-public.bin").unwrap(), Some(Leaf::file(public_id))).unwrap();
        workspace.snapshot(&mut repo).unwrap();

        let dir = tempfile::TempDir::new().unwrap();
        let remote = DirRemote::create(dir.path(), [175; 16]).unwrap();
        let owner = Identity::generate().unwrap();
        let (_, keys) = Keyring::create(remote.remote_id(), &owner).unwrap();
        let mut state = PublishState::new();
        let before = state.clone();
        let error = publish(repo.store().as_ref(), &remote, &owner, Some(&keys), &mut state,
            &FetchState::new(), "main", workspace.working_revision(), &PublishOptions::default()).unwrap_err();
        assert!(matches!(error, PublishError::PastedSecret { .. } | PublishError::PreviouslyPrivate { .. }), "{error}");
        assert_eq!(state, before);
        let head = remote.read_head().unwrap();
        assert!(head.keyring.is_none() && head.manifest.is_none());
        for id in tig_core::blob::content_ids(repo.store().as_ref(), &public_id).unwrap() {
            assert!(!remote.public_store().has(&id).unwrap());
        }
        assert!(remote.list_packs("private", 1).unwrap().is_empty());
    }
}
