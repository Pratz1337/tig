//! Private changes: one immutable public revision, opened in place.
//!
//! See `docs/guide.md#private-changes` for the capsule and public-history contract.
//! Crypto is `EpochKey` (XChaCha20-Poly1305, frozen subkeys). The per-change
//! secret is not a role epoch key.

use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::VerifyingKey;
use tig_core::blob::{content_objects, for_each_content};
use tig_core::domain::EPOCH_KEY_COMMITMENT;
use tig_core::encode::{Reader, Writer};
use tig_core::merge::{merge_trees, MergeOutcome};
use tig_core::object::hash_object;
use tig_core::repo::Repo;
use tig_core::seal::{SealSalt, SealedId};
use tig_core::store::{Store, StoreExt};
use tig_core::{
    ChangeId, EntryKind, Object, ObjectId, ObjectKind, RepoPath, Revision, Signature, Tree,
    TreeEntry,
};
use zeroize::{Zeroize, Zeroizing};

use crate::keys::{EpochKey, Identity};
use crate::keyring::Keyring;
use crate::manifest::{self, Manifest};
use crate::pack::{Pack, PackBatch, PackBuilder, PackError};
use crate::project::{access_group, project_grouped, SealedRoot};
use crate::remote::{CommitOutcome, HeadVersion, Remote};

/// Frozen label root adds to `tig_core::domain` under this exact spelling.
pub use tig_core::domain::PRIVATE_CHANGE_REVEAL_SIGNATURE;

/// Opaque entry added to the public baseline. Its name alone authenticates nothing.
pub const MARKER_NAME: &str = "tig-private-change";

const TIGC_MAGIC: &[u8; 4] = b"TIGC";
const TIGC_VERSION: u8 = 1;
const DESCRIPTOR_VERSION: u8 = 1;
const KEY_RECORD_VERSION: u8 = 1;

type CapsuleObjects = BTreeMap<ObjectId, (ObjectKind, Vec<u8>)>;

#[derive(Debug, thiserror::Error)]
pub enum ChangeError {
    #[error("not allowed to seal or reveal this change")]
    Denied,
    #[error("only the owner can reveal a private change")]
    NotOwner,
    #[error("withheld private-change pack or capsule; refs were not moved")]
    Withheld,
    #[error("remote head changed; nothing was committed")]
    StaleHead,
    #[error("a newer manifest dropped an owner reveal certificate")]
    RevealDropped,
    #[error("private-change authentication failed")]
    Tamper,
    #[error("{0}")]
    Invalid(String),
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error(transparent)]
    Key(#[from] crate::keys::KeyError),
    #[error(transparent)]
    Pack(#[from] crate::pack::PackError),
    #[error(transparent)]
    Project(#[from] crate::project::ProjectError),
    #[error(transparent)]
    Manifest(#[from] crate::manifest::ManifestError),
    #[error(transparent)]
    Remote(#[from] crate::remote::RemoteError),
    #[error(transparent)]
    Keyring(#[from] crate::keyring::KeyringError),
}

/// Empty author, committer, and description on the public skeleton.
pub fn redacted_signature() -> Signature {
    Signature {
        name: String::new(),
        email: String::new(),
        timestamp_ms: 0,
        tz_offset_min: 0,
    }
}

pub fn marker_path() -> RepoPath {
    RepoPath::new(MARKER_NAME).expect("marker name is a single path component")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChangeEntry {
    pub skeleton: ObjectId,
    pub change_id: ChangeId,
    pub capsule: ObjectId,
    pub marker: SealedId,
    pub commitment: [u8; 32],
    pub group: String,
    pub epoch: u64,
    pub wrapper_pack: [u8; 32],
}

/// Owner-signed reveal. A member-signed manifest may nest it and still cannot forge one.
#[derive(Clone, PartialEq, Eq)]
pub struct RevealCertificate {
    pub remote: [u8; 16],
    pub skeleton: ObjectId,
    pub change_id: ChangeId,
    pub capsule: ObjectId,
    pub marker: SealedId,
    pub group: String,
    pub epoch: u64,
    pub commitment: [u8; 32],
    pub key: [u8; 32],
    pub salt: [u8; 32],
    pub signature: [u8; 64],
}

impl std::fmt::Debug for RevealCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevealCertificate")
            .field("skeleton", &self.skeleton)
            .field("group", &self.group)
            .field("epoch", &self.epoch)
            .finish()
    }
}

impl RevealCertificate {
    pub fn sign(
        owner: &Identity,
        remote: [u8; 16],
        entry: &ChangeEntry,
        key: &[u8; 32],
        salt: &[u8; 32],
    ) -> Self {
        let mut cert = RevealCertificate {
            remote,
            skeleton: entry.skeleton,
            change_id: entry.change_id,
            capsule: entry.capsule,
            marker: entry.marker,
            group: entry.group.clone(),
            epoch: entry.epoch,
            commitment: entry.commitment,
            key: *key,
            salt: *salt,
            signature: [0; 64],
        };
        cert.signature = owner.sign(&cert.signing_bytes());
        cert
    }

    pub fn verify(&self, pinned_owner: &[u8; 32]) -> Result<(), ChangeError> {
        let key = VerifyingKey::from_bytes(pinned_owner).map_err(|_| ChangeError::Tamper)?;
        key.verify_strict(&self.signing_bytes(), &ed25519_dalek::Signature::from_bytes(&self.signature))
            .map_err(|_| ChangeError::Tamper)?;
        Ok(())
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = self.body();
        w.buf.extend_from_slice(&self.signature);
        w.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ChangeError> {
        let mut r = Reader::new(bytes, "reveal certificate");
        let cert = read_cert_body(&mut r)?;
        let signature: [u8; 64] = r.take(64)?.try_into().expect("64");
        r.finish()?;
        let cert = RevealCertificate { signature, ..cert };
        let again = cert.encode();
        if again.as_slice() != bytes {
            return Err(ChangeError::Tamper);
        }
        Ok(cert)
    }

    fn body(&self) -> Writer {
        let mut w = Writer::new();
        w.buf.extend_from_slice(PRIVATE_CHANGE_REVEAL_SIGNATURE.as_bytes());
        w.buf.extend_from_slice(&self.remote);
        w.id(&self.skeleton);
        w.change_id(&self.change_id);
        w.id(&self.capsule);
        w.buf.extend_from_slice(self.marker.as_bytes());
        w.str(&self.group);
        w.varint(self.epoch);
        w.buf.extend_from_slice(&self.commitment);
        w.buf.extend_from_slice(&self.key);
        w.buf.extend_from_slice(&self.salt);
        w
    }

    fn signing_bytes(&self) -> Vec<u8> {
        self.body().finish()
    }
}

fn read_cert_body(r: &mut Reader<'_>) -> Result<RevealCertificate, ChangeError> {
    let label = PRIVATE_CHANGE_REVEAL_SIGNATURE.as_bytes();
    if r.take(label.len())? != label {
        return Err(ChangeError::Tamper);
    }
    let remote: [u8; 16] = r.take(16)?.try_into().expect("16");
    Ok(RevealCertificate {
        remote,
        skeleton: r.id()?,
        change_id: r.change_id()?,
        capsule: r.id()?,
        marker: SealedId::from_stored(r.take(32)?.try_into().expect("32")),
        group: r.str()?.to_string(),
        epoch: r.varint()?,
        commitment: r.take(32)?.try_into().expect("32"),
        key: r.take(32)?.try_into().expect("32"),
        salt: r.take(32)?.try_into().expect("32"),
        signature: [0; 64],
    })
}

/// Private changes use the canonical publish manifest.
pub type ChangeManifest = Manifest;

pub(crate) fn cert_matches(entry: &ChangeEntry, cert: &RevealCertificate) -> bool {
    entry.skeleton == cert.skeleton
        && entry.change_id == cert.change_id
        && entry.capsule == cert.capsule
        && entry.marker == cert.marker
        && entry.commitment == cert.commitment
        && entry.group == cert.group
        && entry.epoch == cert.epoch
}

pub(crate) fn write_entry(w: &mut Writer, entry: &ChangeEntry) {
    w.id(&entry.skeleton);
    w.change_id(&entry.change_id);
    w.id(&entry.capsule);
    w.buf.extend_from_slice(entry.marker.as_bytes());
    w.buf.extend_from_slice(&entry.commitment);
    w.str(&entry.group);
    w.varint(entry.epoch);
    w.buf.extend_from_slice(&entry.wrapper_pack);
}

/// Copies owner certificates forward. Fails closed if one would disappear.
pub fn carry_reveals(previous: &ChangeManifest, next: &mut ChangeManifest) -> Result<(), ChangeError> {
    for (id, cert) in &previous.reveals {
        match next.reveals.get(id) {
            Some(kept) if kept == cert => {}
            Some(_) => return Err(ChangeError::Tamper),
            None => {
                next.reveals.insert(*id, cert.clone());
            }
        }
    }
    if previous.reveals.len() > next.reveals.len() {
        return Err(ChangeError::RevealDropped);
    }
    Ok(())
}

/// Public skeleton id to local decoded revision. Insert refuses a second local id.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Correspondence {
    pub_to_local: BTreeMap<ObjectId, ObjectId>,
    local_to_public: BTreeMap<ObjectId, ObjectId>,
}

impl Correspondence {
    pub fn get(&self, public_id: &ObjectId) -> Option<ObjectId> {
        self.pub_to_local.get(public_id).copied()
    }

    pub fn public_id(&self, id: ObjectId) -> ObjectId {
        self.local_to_public.get(&id).copied().unwrap_or(id)
    }

    /// Historical local aliases can share one public revision after access upgrades.
    pub fn from_local_to_public(revisions: &BTreeMap<ObjectId, ObjectId>) -> Self {
        Self {
            pub_to_local: revisions.iter().map(|(local, public)| (*public, *local)).collect(),
            local_to_public: revisions.clone(),
        }
    }

    pub fn insert_new(&mut self, public_id: ObjectId, local_id: ObjectId) -> Result<(), ChangeError> {
        if let Some(existing) = self.pub_to_local.get(&public_id) {
            if *existing != local_id {
                return Err(ChangeError::Tamper);
            }
            return Ok(());
        }
        self.pub_to_local.insert(public_id, local_id);
        self.local_to_public.insert(local_id, public_id);
        Ok(())
    }
}

fn commitment_of(key: &EpochKey) -> [u8; 32] {
    let ctx = key.context();
    let mut material = Vec::new();
    material.extend_from_slice(&*key.to_bytes());
    material.extend_from_slice(&(ctx.remote.len() as u64).to_le_bytes());
    material.extend_from_slice(&ctx.remote);
    material.extend_from_slice(&(ctx.group.len() as u64).to_le_bytes());
    material.extend_from_slice(ctx.group.as_bytes());
    material.extend_from_slice(&ctx.epoch.to_le_bytes());
    let commitment = blake3::derive_key(EPOCH_KEY_COMMITMENT, &material);
    material.zeroize();
    debug_assert!(key.matches_commitment(&commitment));
    commitment
}

fn random32() -> Result<[u8; 32], ChangeError> {
    let mut raw = [0u8; 32];
    getrandom::getrandom(&mut raw).map_err(|e| ChangeError::Invalid(e.to_string()))?;
    Ok(raw)
}

/// Current publishing right, plus read access to `role` at the keyring's current epoch.
pub fn authorize_seal(
    keyring: &Keyring,
    identity: &Identity,
    pinned_owner: &[u8; 32],
    min_counter: u64,
    role: &str,
    role_key: &EpochKey,
) -> Result<(), ChangeError> {
    keyring.verify(pinned_owner, min_counter)?;
    if keyring.owner.signing != *pinned_owner {
        return Err(ChangeError::Denied);
    }
    if !manifest::allowed_signers(keyring).contains(&identity.public().signing) {
        return Err(ChangeError::Denied);
    }
    let epoch = keyring
        .head
        .epochs
        .get(role)
        .copied()
        .ok_or(ChangeError::Denied)?;
    keyring.policy_snapshot()?.may_publish_group(
        &identity.public(), &keyring.grants, role, Some(epoch),
    ).map_err(|e| ChangeError::Invalid(e.to_string()))?;
    let ctx = role_key.context();
    if ctx.remote != keyring.remote || ctx.group != role || ctx.epoch != epoch {
        return Err(ChangeError::Denied);
    }
    let me = identity.public();
    let grant = keyring
        .grants
        .iter()
        .find(|grant| {
            grant.context.remote == keyring.remote
                && grant.context.group == role
                && grant.context.epoch == epoch
                && grant.recipient == me
        })
        .ok_or(ChangeError::Denied)?;
    if !role_key.matches_commitment(&grant.commitment) {
        return Err(ChangeError::Denied);
    }
    Ok(())
}

fn authorize_owner(
    keyring: &Keyring,
    owner: &Identity,
    pinned_owner: &[u8; 32],
    min_counter: u64,
) -> Result<(), ChangeError> {
    keyring.verify(pinned_owner, min_counter)?;
    if owner.public() != keyring.policy_snapshot()?.current_owner {
        return Err(ChangeError::NotOwner);
    }
    Ok(())
}

struct BuiltSeal {
    entry: ChangeEntry,
    objects: Vec<(ObjectId, ObjectKind, Vec<u8>)>,
    pack: Vec<u8>,
    private_roots: Vec<SealedRoot>,
}

fn build_seal(
    store: &dyn Store,
    remote_id: [u8; 16],
    revision: ObjectId,
    public_parents: &[ObjectId],
    role_key: &EpochKey,
    privacy_keys: &BTreeMap<String, &EpochKey>,
    baseline: &Tree,
) -> Result<BuiltSeal, ChangeError> {
    let internal = store.get_revision(&revision)?;
    if public_parents.is_empty() {
        return Err(ChangeError::Invalid("a private change needs a public parent".into()));
    }
    let projection = project_grouped(store, &internal.tree, privacy_keys)?;
    let mut closure = BTreeMap::new();
    collect_tree(store, &projection.public_tree, &mut closure)?;
    for (_, leaf) in &projection.private_files {
        for (kind, id) in content_objects(store, &leaf.id())? {
            if closure.contains_key(&id) && !(kind == ObjectKind::Blob && store.get_blob(&id)?.is_empty()) {
                return Err(ChangeError::Invalid("private file bytes also occur in the revealable change".into()));
            }
        }
    }
    let projected = Revision {
        tree: projection.public_tree,
        parents: public_parents.to_vec(),
        change_id: internal.change_id,
        predecessors: Vec::new(),
        author: internal.author,
        committer: internal.committer,
        description: internal.description,
    };
    let mut descriptor = encode_descriptor(&projected, &closure)?;
    if descriptor.len() as u64 > tig_core::blob::MAX_MATERIALIZE {
        descriptor.zeroize();
        return Err(ChangeError::Invalid("private-change descriptor exceeds the 256 MiB materialization limit".into()));
    }
    let descriptor_id = hash_object(ObjectKind::Blob, &descriptor);
    let mut secret = random32()?;
    let capsule_key = EpochKey::from_bytes(role_key.context().clone(), secret);
    secret.zeroize();
    let commitment = commitment_of(&capsule_key);
    if !capsule_key.matches_commitment(&commitment) {
        return Err(ChangeError::Tamper);
    }
    let salt = SealSalt::from_bytes(random32()?);
    let marker = SealedId::compute(&salt, EntryKind::File, &descriptor_id);
    let mut entries: BTreeMap<_, _> = baseline.entries().iter().map(|entry| (entry.name().to_string(), entry.clone())).collect();
    if entries.get(MARKER_NAME).is_some_and(|entry| entry.kind() != EntryKind::Sealed) {
        return Err(ChangeError::Invalid("the private-change marker path already contains a public file".into()));
    }
    entries.insert(MARKER_NAME.into(), TreeEntry::sealed(MARKER_NAME, marker)?);
    let skeleton_tree = Tree::new(entries.into_values().collect())?;
    let skeleton_tree_id = store.put(&Object::Tree(skeleton_tree.clone()))?;
    let skeleton = Revision {
        tree: skeleton_tree_id,
        parents: public_parents.to_vec(),
        change_id: internal.change_id,
        predecessors: Vec::new(),
        author: redacted_signature(),
        committer: redacted_signature(),
        description: String::new(),
    };
    let skeleton_id = hash_object(ObjectKind::Revision, &skeleton.encode());
    let header = tigc_header(
        remote_id,
        role_key.context(),
        &skeleton_id,
        &internal.change_id,
        &marker,
        &commitment,
    );
    let (nonce, ciphertext) = capsule_key.encrypt_index(&descriptor, &header)?;
    descriptor.zeroize();
    let mut capsule = header;
    capsule.extend_from_slice(&nonce);
    let mut rest = Writer::new();
    rest.bytes(&ciphertext);
    capsule.extend_from_slice(&rest.finish());
    if capsule.len() as u64 > tig_core::blob::MAX_MATERIALIZE {
        return Err(ChangeError::Invalid("private-change capsule exceeds the 256 MiB materialization limit".into()));
    }
    let capsule_id = store.put_blob(&capsule)?;
    let pack = wrapper_pack(role_key, &capsule_key, salt.as_bytes(), &skeleton_id, &capsule_id, &marker, &commitment)?;
    let pack_id = manifest::pack_id(&pack);
    let tree_body = skeleton_tree.encode();
    let rev_body = skeleton.encode();
    Ok(BuiltSeal {
        entry: ChangeEntry {
            skeleton: skeleton_id,
            change_id: internal.change_id,
            capsule: capsule_id,
            marker,
            commitment,
            group: role_key.context().group.clone(),
            epoch: role_key.context().epoch,
            wrapper_pack: pack_id,
        },
        objects: vec![
            (skeleton_tree_id, ObjectKind::Tree, tree_body),
            (skeleton_id, ObjectKind::Revision, rev_body),
        ],
        pack,
        private_roots: projection.sealed,
    })
}

fn tigc_header(
    remote: [u8; 16],
    ctx: &crate::keys::GroupEpoch,
    skeleton: &ObjectId,
    change: &ChangeId,
    marker: &SealedId,
    commitment: &[u8; 32],
) -> Vec<u8> {
    let mut w = Writer::new();
    w.buf.extend_from_slice(TIGC_MAGIC);
    w.u8(TIGC_VERSION);
    w.buf.extend_from_slice(&remote);
    w.str(&ctx.group);
    w.varint(ctx.epoch);
    w.id(skeleton);
    w.change_id(change);
    w.buf.extend_from_slice(marker.as_bytes());
    w.buf.extend_from_slice(commitment);
    w.finish()
}

fn wrapper_pack(
    role_key: &EpochKey,
    capsule_key: &EpochKey,
    salt: &[u8; 32],
    skeleton: &ObjectId,
    capsule: &ObjectId,
    marker: &SealedId,
    commitment: &[u8; 32],
) -> Result<Vec<u8>, ChangeError> {
    let mut body = Vec::new();
    body.push(KEY_RECORD_VERSION);
    body.extend_from_slice(&*capsule_key.to_bytes());
    body.extend_from_slice(salt);
    body.extend_from_slice(skeleton.as_bytes());
    body.extend_from_slice(capsule.as_bytes());
    body.extend_from_slice(marker.as_bytes());
    body.extend_from_slice(commitment);
    let id = hash_object(ObjectKind::Blob, &body);
    let mut builder = PackBuilder::new(role_key);
    builder.add_object(ObjectKind::Blob, id, &body)?;
    body.zeroize();
    Ok(builder.finish()?)
}

fn collect_tree(
    store: &dyn Store,
    id: &ObjectId,
    out: &mut CapsuleObjects,
) -> Result<(), ChangeError> {
    if out.contains_key(id) {
        return Ok(());
    }
    let object = store.get(id)?;
    let Object::Tree(tree) = object else {
        return Err(ChangeError::Invalid("projected tree is not a tree".into()));
    };
    out.insert(*id, (ObjectKind::Tree, tree.encode()));
    for entry in tree.entries() {
        match entry.kind() {
            EntryKind::Sealed => {}
            EntryKind::Tree => collect_tree(store, &entry.id(), out)?,
            EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                collect_file(store, &entry.id(), out)?;
            }
            EntryKind::Conflict => {
                return Err(ChangeError::Invalid("unresolved conflict in a private change".into()));
            }
        }
    }
    Ok(())
}

fn collect_file(
    store: &dyn Store,
    id: &ObjectId,
    out: &mut CapsuleObjects,
) -> Result<(), ChangeError> {
    let listed = content_objects(store, id)?;
    for_each_content(store, id, |kind, cid, body| {
        if !matches!(kind, ObjectKind::Blob | ObjectKind::ChunkedBlob) {
            return Err(ChangeError::Invalid("private change closure holds a non-content object".into()));
        }
        if hash_object(kind, body) != cid {
            return Err(ChangeError::Tamper);
        }
        let current: usize = out.values().map(|(_, bytes)| bytes.len()).sum();
        if !out.contains_key(&cid) && current.saturating_add(body.len()) as u64 > tig_core::blob::MAX_MATERIALIZE {
            return Err(ChangeError::Invalid("private-change descriptor exceeds the 256 MiB materialization limit".into()));
        }
        out.insert(cid, (kind, body.to_vec()));
        Ok(())
    })?;
    for (kind, cid) in listed {
        if !out.contains_key(&cid) || out[&cid].0 != kind {
            return Err(ChangeError::Withheld);
        }
    }
    Ok(())
}

fn encode_descriptor(
    rev: &Revision,
    objects: &CapsuleObjects,
) -> Result<Vec<u8>, ChangeError> {
    if !rev.predecessors.is_empty() {
        return Err(ChangeError::Invalid("descriptor must not name ancestors".into()));
    }
    let mut w = Writer::new();
    w.u8(DESCRIPTOR_VERSION);
    w.bytes(&rev.encode());
    w.varint(objects.len() as u64);
    for (id, (kind, body)) in objects {
        if matches!(
            kind,
            ObjectKind::Revision | ObjectKind::Operation | ObjectKind::View | ObjectKind::Conflict
        ) {
            return Err(ChangeError::Invalid("descriptor closure holds a private id".into()));
        }
        w.u8(*kind as u8);
        w.id(id);
        w.bytes(body);
    }
    Ok(w.finish())
}

fn decode_descriptor(bytes: &[u8]) -> Result<(Revision, CapsuleObjects), ChangeError> {
    let mut r = Reader::new(bytes, "change descriptor");
    if r.u8()? != DESCRIPTOR_VERSION {
        return Err(ChangeError::Tamper);
    }
    let rev = Revision::decode(r.bytes()?)?;
    if !rev.predecessors.is_empty() {
        return Err(ChangeError::Tamper);
    }
    let n = r.count(1)?;
    let mut objects = BTreeMap::new();
    let mut last = ObjectId([0; 32]);
    let mut any = false;
    for _ in 0..n {
        let kind = ObjectKind::from_u8(r.u8()?)?;
        let id = r.id()?;
        if any && id <= last {
            return Err(ChangeError::Tamper);
        }
        any = true;
        last = id;
        let body = r.bytes()?.to_vec();
        if hash_object(kind, &body) != id {
            return Err(ChangeError::Tamper);
        }
        if matches!(
            kind,
            ObjectKind::Revision | ObjectKind::Operation | ObjectKind::View | ObjectKind::Conflict
        ) {
            return Err(ChangeError::Tamper);
        }
        objects.insert(id, (kind, body));
    }
    r.finish()?;
    assert_closure(&rev, &objects)?;
    Ok((rev, objects))
}

fn assert_closure(
    rev: &Revision,
    objects: &CapsuleObjects,
) -> Result<(), ChangeError> {
    fn walk(
        id: &ObjectId,
        objects: &CapsuleObjects,
    ) -> Result<(), ChangeError> {
        let Some((kind, body)) = objects.get(id) else {
            return Err(ChangeError::Tamper);
        };
        match kind {
            ObjectKind::Tree => {
                let tree = Tree::decode(body)?;
                for entry in tree.entries() {
                    match entry.kind() {
                        EntryKind::Sealed => {}
                        EntryKind::Tree => walk(&entry.id(), objects)?,
                        EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                            walk_file(&entry.id(), objects)?;
                        }
                        EntryKind::Conflict => return Err(ChangeError::Tamper),
                    }
                }
                Ok(())
            }
            _ => Err(ChangeError::Tamper),
        }
    }
    fn walk_file(
        id: &ObjectId,
        objects: &CapsuleObjects,
    ) -> Result<(), ChangeError> {
        let Some((kind, body)) = objects.get(id) else {
            return Err(ChangeError::Tamper);
        };
        match kind {
            ObjectKind::Blob => Ok(()),
            ObjectKind::ChunkedBlob => {
                let manifest = tig_core::blob::parse_manifest(body)?;
                for chunk in manifest.chunks() {
                    let Some((ObjectKind::Blob, bytes)) = objects.get(&chunk.id) else {
                        return Err(ChangeError::Tamper);
                    };
                    if bytes.len() != chunk.len as usize || hash_object(ObjectKind::Blob, bytes) != chunk.id {
                        return Err(ChangeError::Tamper);
                    }
                }
                Ok(())
            }
            _ => Err(ChangeError::Tamper),
        }
    }
    walk(&rev.tree, objects)
}

struct OpenedCapsule {
    projected: Revision,
    objects: CapsuleObjects,
    salt: [u8; 32],
}

fn decrypt_capsule(
    bytes: &[u8],
    key_bytes: &[u8; 32],
    salt: &[u8; 32],
    entry: &ChangeEntry,
    remote: [u8; 16],
) -> Result<OpenedCapsule, ChangeError> {
    let header = tigc_header(
        remote,
        &crate::keys::GroupEpoch {
            remote,
            group: entry.group.clone(),
            epoch: entry.epoch,
        },
        &entry.skeleton,
        &entry.change_id,
        &entry.marker,
        &entry.commitment,
    );
    if bytes.len() < header.len() + 24 || &bytes[..header.len()] != header.as_slice() {
        return Err(ChangeError::Tamper);
    }
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&bytes[header.len()..header.len() + 24]);
    let mut r = Reader::new(&bytes[header.len() + 24..], "capsule");
    let ciphertext = r.bytes()?.to_vec();
    r.finish()?;
    let key = EpochKey::from_bytes(
        crate::keys::GroupEpoch {
            remote,
            group: entry.group.clone(),
            epoch: entry.epoch,
        },
        *key_bytes,
    );
    if !key.matches_commitment(&entry.commitment) {
        return Err(ChangeError::Tamper);
    }
    let plain = Zeroizing::new(key.decrypt_index(&nonce, &ciphertext, &header)?);
    let (projected, objects) = decode_descriptor(&plain)?;
    let descriptor_id = hash_object(ObjectKind::Blob, &plain);
    let seal_salt = SealSalt::from_bytes(*salt);
    if !entry.marker.verify(&seal_salt, EntryKind::File, &descriptor_id) {
        return Err(ChangeError::Tamper);
    }
    if projected.change_id != entry.change_id {
        return Err(ChangeError::Tamper);
    }
    Ok(OpenedCapsule {
        projected,
        objects,
        salt: *salt,
    })
}

fn key_from_pack(pack: &[u8], role_key: &EpochKey, entry: &ChangeEntry) -> Result<([u8; 32], [u8; 32]), ChangeError> {
    if manifest::pack_id(pack) != entry.wrapper_pack {
        return Err(ChangeError::Tamper);
    }
    let opened = Pack::open(pack, role_key)?;
    for (kind, _id, body) in &opened.objects {
        if *kind != ObjectKind::Blob || body.first().copied() != Some(KEY_RECORD_VERSION) {
            continue;
        }
        if body.len() != 1 + 32 + 32 + 32 + 32 + 32 + 32 {
            return Err(ChangeError::Tamper);
        }
        let key: [u8; 32] = body[1..33].try_into().unwrap();
        let salt: [u8; 32] = body[33..65].try_into().unwrap();
        let skeleton = ObjectId(body[65..97].try_into().unwrap());
        let capsule = ObjectId(body[97..129].try_into().unwrap());
        let marker = SealedId::from_stored(body[129..161].try_into().unwrap());
        let commitment: [u8; 32] = body[161..193].try_into().unwrap();
        if skeleton != entry.skeleton
            || capsule != entry.capsule
            || marker != entry.marker
            || commitment != entry.commitment
        {
            return Err(ChangeError::Tamper);
        }
        return Ok((key, salt));
    }
    Err(ChangeError::Withheld)
}

fn materialize(
    store: &dyn Store,
    opened: &OpenedCapsule,
    skeleton: &Revision,
) -> Result<ObjectId, ChangeError> {
    if opened.projected.parents != skeleton.parents || opened.projected.change_id != skeleton.change_id {
        return Err(ChangeError::Tamper);
    }
    let public = store.get_revision(&hash_object(ObjectKind::Revision, &skeleton.encode()))?;
    if public.encode() != skeleton.encode() {
        return Err(ChangeError::Tamper);
    }
    let tree = store.get(&skeleton.tree)?;
    let Object::Tree(tree) = tree else {
        return Err(ChangeError::Tamper);
    };
    let marker = tree
        .get(MARKER_NAME)
        .and_then(|entry| entry.sealed_id())
        .ok_or(ChangeError::Tamper)?;
    if marker != opened_marker(opened) {
        return Err(ChangeError::Tamper);
    }
    for (id, (kind, body)) in &opened.objects {
        store.put_raw(id, *kind, body)?;
    }
    let local = store.put(&Object::Revision(opened.projected.clone()))?;
    Ok(local)
}

fn opened_marker(opened: &OpenedCapsule) -> SealedId {
    let descriptor = encode_descriptor(&opened.projected, &opened.objects).expect("descriptor re-encodes");
    let id = hash_object(ObjectKind::Blob, &descriptor);
    SealedId::compute(&SealSalt::from_bytes(opened.salt), EntryKind::File, &id)
}

pub struct SealRequest<'a> {
    pub store: &'a dyn Store,
    pub remote: &'a dyn Remote,
    pub identity: &'a Identity,
    pub keyring: &'a Keyring,
    pub pinned_owner: &'a [u8; 32],
    pub min_counter: u64,
    pub min_sequence: u64,
    pub known_reveals: &'a BTreeSet<ObjectId>,
    pub bookmark: &'a str,
    pub revision: ObjectId,
    pub public_parents: &'a [ObjectId],
    pub role: &'a str,
    pub role_key: &'a EpochKey,
    /// Current keys for the tree's independently private groups. They are never revealed.
    pub privacy_keys: &'a BTreeMap<String, &'a EpochKey>,
}

#[derive(Debug)]
pub struct SealReport {
    pub skeleton: ObjectId,
    pub change_id: ChangeId,
    pub capsule: ObjectId,
    pub head: HeadVersion,
    pub sequence: u64,
    pub revealed: BTreeSet<ObjectId>,
}

/// Uploads the skeleton, the capsule ciphertext, and the role wrapper. No descriptor plaintext.
pub fn publish_seal(request: &SealRequest<'_>) -> Result<SealReport, ChangeError> {
    authorize_seal(
        request.keyring,
        request.identity,
        request.pinned_owner,
        request.min_counter,
        request.role,
        request.role_key,
    )?;
    if request.bookmark.is_empty() || request.role.is_empty() {
        return Err(ChangeError::Invalid("bookmark and role are required".into()));
    }
    if request.role_key.context().group != request.role {
        return Err(ChangeError::Denied);
    }
    let head = request.remote.read_head()?;
    require_head_keyring(&head, request.remote.remote_id(), request.keyring)?;
    let source = request.store.get_revision(&request.revision)?;
    if source.parents.len() != request.public_parents.len() {
        return Err(ChangeError::Invalid("private-change parents do not match its public ancestry".into()));
    }
    let rules = RepoPath::new(".private")?;
    let rules_leaf = tig_core::treeops::lookup(request.store, &source.tree, &rules)?;
    let snapshot = request.keyring.policy_snapshot()?;
    let mut baseline = Tree::empty();
    for (index, (internal, public)) in source.parents.iter().zip(request.public_parents).enumerate() {
        let local_parent = request.store.get_revision(internal)?;
        let public_parent = if *public == tig_core::repo::root_revision_id() {
            tig_core::repo::root_revision()
        } else {
            request.remote.public_store().get_revision(public)?
        };
        if local_parent.change_id != public_parent.change_id {
            return Err(ChangeError::Invalid("private-change parent is not its published counterpart".into()));
        }
        if index == 0 && *public != tig_core::repo::root_revision_id() {
            baseline = request.remote.public_store().get_tree(&public_parent.tree)?;
        }
        if !request.keyring.policy.is_empty()
            && !snapshot.has(&request.identity.public(), crate::roles::EDIT_PRIVATE)
            && tig_core::treeops::lookup(request.store, &local_parent.tree, &rules)? != rules_leaf {
            return Err(ChangeError::Denied);
        }
    }
    let built = build_seal(
        request.store,
        request.remote.remote_id(),
        request.revision,
        request.public_parents,
        request.role_key,
        request.privacy_keys,
        &baseline,
    )?;
    let expected = head.version();
    let mut manifest = match &head.manifest {
        Some(bytes) => ChangeManifest::decode(bytes)?,
        None => ChangeManifest::signed_with_changes(
            request.remote.remote_id(),
            0,
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            BTreeMap::new(),
            request.identity,
        )?,
    };
    if manifest.remote != request.remote.remote_id() {
        return Err(ChangeError::Tamper);
    }
    manifest.verify(request.remote.remote_id(), request.keyring, request.min_sequence)?;
    if !request.known_reveals.iter().all(|id| manifest.reveals.contains_key(id)) {
        return Err(ChangeError::RevealDropped);
    }
    if manifest.changes.values().any(|entry| entry.change_id == built.entry.change_id) {
        return Err(ChangeError::Invalid("this change is already sealed".into()));
    }
    if let Some(current) = manifest.refs.get(request.bookmark) {
        if !request.public_parents.contains(current) && *current != built.entry.skeleton {
            return Err(ChangeError::Invalid(
                "remote bookmark is not a parent of this private change".into(),
            ));
        }
    }
    for root in &built.private_roots {
        let group = access_group(&root.readers);
        let key = request.privacy_keys.get(&group).ok_or(ChangeError::Denied)?;
        authorize_seal(request.keyring, request.identity, request.pinned_owner, request.min_counter, &group, key)?;
    }
    // Refusal checks are done. Uploads are ciphertext and redacted skeleton bytes only.
    for (id, kind, body) in &built.objects {
        request.store.put_raw(id, *kind, body)?;
    }
    request.remote.put_batch(&built.objects)?;
    for_each_content(request.store, &built.entry.capsule, |kind, id, body| {
        request.remote.put_batch(&[(id, kind, body.to_vec())])
    })?;
    publish_inner_private(request, &built.private_roots, &mut manifest)?;
    request.remote.put_pack(&built.pack)?;
    let sequence = manifest.sequence.checked_add(1).ok_or_else(|| {
        ChangeError::Invalid("manifest sequence overflow".into())
    })?;
    manifest.refs.insert(request.bookmark.to_string(), built.entry.skeleton);
    manifest.packs.insert(
        built.entry.wrapper_pack,
        crate::manifest::PackEntry {
            group: request.role.to_string(),
            epoch: request.role_key.context().epoch,
            sealed: std::collections::BTreeSet::new(),
        },
    );
    manifest.changes.insert(built.entry.skeleton, built.entry.clone());
    let revealed = manifest.reveals.keys().copied().collect();
    let signed = ChangeManifest::signed_with_changes(
        manifest.remote,
        sequence,
        manifest.refs,
        manifest.packs,
        manifest.changes,
        manifest.reveals,
        request.identity,
    )?;
    let bytes = signed.encode()?;
    match request.remote.commit_head(&expected, None, Some(&bytes))? {
        CommitOutcome::Committed(head) => Ok(SealReport {
            skeleton: built.entry.skeleton,
            change_id: built.entry.change_id,
            capsule: built.entry.capsule,
            head,
            sequence,
            revealed,
        }),
        CommitOutcome::Stale(_) => Err(ChangeError::StaleHead),
    }
}

/// Inner privacy seals keep their own epoch encryption after the change is revealed.
fn publish_inner_private(
    request: &SealRequest<'_>,
    roots: &[SealedRoot],
    manifest: &mut Manifest,
) -> Result<(), ChangeError> {
    let groups: std::collections::BTreeSet<_> = roots.iter().map(|root| access_group(&root.readers)).collect();
    for group in groups {
        let key = request.privacy_keys.get(&group).ok_or(ChangeError::Denied)?;
        authorize_seal(request.keyring, request.identity, request.pinned_owner, request.min_counter, &group, key)?;
        let mut builder = PackBatch::new(key);
        let mut emit = |bytes: &[u8]| -> Result<(), PackError> {
            request.remote.put_pack(bytes).map_err(|e| PackError::Invalid(e.to_string()))?;
            let opened = Pack::open(bytes, key)?;
            manifest.packs.insert(manifest::pack_id(bytes), crate::manifest::PackEntry {
                group: group.clone(), epoch: key.context().epoch,
                sealed: opened.sealed.iter().map(|record| record.sealed_id).collect(),
            });
            Ok(())
        };
        let mut added = std::collections::BTreeSet::new();
        for root in roots.iter().filter(|root| access_group(&root.readers) == group) {
            builder.add_sealed(key.seal(&root.path, root.leaf.kind(), &root.leaf.id()), root.path.clone(), root.leaf.kind(), root.leaf.id(), &mut emit)?;
            let mut pending = vec![(root.leaf.kind(), root.leaf.id())];
            while let Some((kind, id)) = pending.pop() {
                if !added.insert(id) { continue; }
                match kind {
                    EntryKind::Tree => {
                        let tree = request.store.get_tree(&id)?;
                        builder.add_object(ObjectKind::Tree, id, &tree.encode(), &mut emit)?;
                        pending.extend(tree.entries().iter().filter(|entry| entry.kind() != EntryKind::Sealed).map(|entry| (entry.kind(), entry.id())));
                    }
                    EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                        for_each_content(request.store, &id, |kind, cid, body| builder.add_object(kind, cid, body, &mut emit))?;
                    }
                    _ => return Err(ChangeError::Invalid("invalid private-change content".into())),
                }
            }
        }
        builder.finish(&mut emit)?;
    }
    Ok(())
}

pub struct RevealRequest<'a> {
    pub remote: &'a dyn Remote,
    pub owner: &'a Identity,
    pub keyring: &'a Keyring,
    pub pinned_owner: &'a [u8; 32],
    pub min_counter: u64,
    pub min_sequence: u64,
    pub known_reveals: &'a BTreeSet<ObjectId>,
    pub skeleton: ObjectId,
    pub role_key: &'a EpochKey,
    /// Head the caller verified. A stale value commits nothing and uploads nothing.
    pub expected: &'a HeadVersion,
}

#[derive(Debug)]
pub struct RevealReport {
    pub head: HeadVersion,
    pub public_paths: BTreeSet<RepoPath>,
}

pub fn publish_reveal(request: &RevealRequest<'_>) -> Result<RevealReport, ChangeError> {
    authorize_owner(
        request.keyring,
        request.owner,
        request.pinned_owner,
        request.min_counter,
    )?;
    let head = request.remote.read_head()?;
    if head.version() != *request.expected {
        return Err(ChangeError::StaleHead);
    }
    require_head_keyring(&head, request.remote.remote_id(), request.keyring)?;
    let bytes = head.manifest.ok_or(ChangeError::Withheld)?;
    let manifest = ChangeManifest::decode(&bytes)?;
    manifest.verify(request.remote.remote_id(), request.keyring, request.min_sequence)?;
    if !request.known_reveals.iter().all(|id| manifest.reveals.contains_key(id)) {
        return Err(ChangeError::RevealDropped);
    }
    let entry = manifest.entry(&request.skeleton).ok_or(ChangeError::Withheld)?.clone();
    if request.role_key.context().group != entry.group || request.role_key.context().epoch != entry.epoch
    {
        return Err(ChangeError::Denied);
    }
    let pack = request
        .remote
        .get_pack(&entry.group, entry.epoch, &entry.wrapper_pack)?
        .ok_or(ChangeError::Withheld)?;
    let (key, salt) = key_from_pack(&pack, request.role_key, &entry)?;
    let capsule = request
        .remote
        .public_store()
        .get_blob(&entry.capsule)
        .map_err(|_| ChangeError::Withheld)?;
    let opened = decrypt_capsule(&capsule, &key, &salt, &entry, request.remote.remote_id())?;
    let public_paths = capsule_public_paths(&opened)?;
    if manifest.reveals.contains_key(&entry.skeleton) {
        return Err(ChangeError::Invalid("this change is already revealed".into()));
    }
    let cert = RevealCertificate::sign(request.owner, request.remote.remote_id(), &entry, &key, &salt);
    cert.verify(&request.keyring.policy_snapshot()?.current_owner.signing)?;
    let sequence = manifest.sequence.checked_add(1).ok_or_else(|| {
        ChangeError::Invalid("manifest sequence overflow".into())
    })?;
    let mut reveals = manifest.reveals;
    reveals.insert(entry.skeleton, cert);
    let signed = ChangeManifest::signed_with_changes(
        manifest.remote,
        sequence,
        manifest.refs,
        manifest.packs,
        manifest.changes,
        reveals,
        request.owner,
    )?;
    // No put_batch and no put_pack. The ciphertext is already public.
    match request.remote.commit_head(request.expected, None, Some(&signed.encode()?))? {
        CommitOutcome::Committed(head) => Ok(RevealReport { head, public_paths }),
        CommitOutcome::Stale(_) => Err(ChangeError::StaleHead),
    }
}

/// Public certificates expose these paths even while the stored skeleton stays unchanged.
pub fn revealed_paths(
    remote: &dyn Remote,
    manifest: &Manifest,
    skeleton: &ObjectId,
    current_owner: &[u8; 32],
) -> Result<BTreeSet<RepoPath>, ChangeError> {
    let entry = manifest.entry(skeleton).ok_or(ChangeError::Tamper)?;
    let cert = manifest.reveals.get(skeleton).ok_or(ChangeError::Withheld)?;
    cert.verify(current_owner)?;
    if !cert_matches(entry, cert) || cert.remote != remote.remote_id() || manifest.remote != remote.remote_id() {
        return Err(ChangeError::Tamper);
    }
    let capsule = remote.public_store().get_blob(&entry.capsule)?;
    capsule_public_paths(&decrypt_capsule(&capsule, &cert.key, &cert.salt, entry, manifest.remote)?)
}

fn capsule_public_paths(opened: &OpenedCapsule) -> Result<BTreeSet<RepoPath>, ChangeError> {
    let mut pending = vec![(opened.projected.tree, RepoPath::root(), 0usize)];
    let mut paths = BTreeSet::new();
    let mut entries = 0usize;
    let mut path_bytes = 0usize;
    while let Some((id, prefix, depth)) = pending.pop() {
        if depth > tig_core::treeops::MAX_TREE_DEPTH {
            return Err(ChangeError::Invalid("private-change tree is too deep".into()));
        }
        let (kind, body) = opened.objects.get(&id).ok_or(ChangeError::Tamper)?;
        if *kind != ObjectKind::Tree { return Err(ChangeError::Tamper); }
        for entry in Tree::decode(body)?.entries() {
            let path = prefix.join(entry.name())?;
            entries = entries.saturating_add(1);
            path_bytes = path_bytes.saturating_add(path.as_str().len());
            if entries > 1_000_000 || path_bytes as u64 > tig_core::blob::MAX_MATERIALIZE {
                return Err(ChangeError::Invalid("private-change path evidence is too large".into()));
            }
            match entry.kind() {
                EntryKind::Tree => pending.push((entry.id(), path, depth + 1)),
                EntryKind::File | EntryKind::Executable | EntryKind::Symlink => { paths.insert(path); }
                EntryKind::Sealed => {}
                EntryKind::Conflict => return Err(ChangeError::Tamper),
            }
        }
    }
    Ok(paths)
}

fn require_head_keyring(
    head: &crate::remote::RemoteHead,
    remote: [u8; 16],
    keyring: &Keyring,
) -> Result<(), ChangeError> {
    if keyring.remote != remote {
        return Err(ChangeError::Tamper);
    }
    let bytes = head.keyring.as_ref().ok_or(ChangeError::Withheld)?;
    if Keyring::decode(bytes)?.encode()? != keyring.encode()? {
        return Err(ChangeError::StaleHead);
    }
    Ok(())
}

pub struct OpenInput<'a> {
    pub store: &'a dyn Store,
    pub manifest: &'a ChangeManifest,
    pub skeleton_id: ObjectId,
    pub packs: &'a [Vec<u8>],
    pub role_key: Option<&'a EpochKey>,
    pub pinned_owner: &'a [u8; 32],
    pub correspondence: &'a mut Correspondence,
    /// True when this identity holds the entry's role epoch. A missing pack is `Withheld`.
    pub expects_access: bool,
}

#[derive(Debug)]
pub enum OpenOutcome {
    /// Manifest has no change entry. The filename marker is not enough.
    NotAssociated { public_id: ObjectId },
    Opaque { public_id: ObjectId },
    Already { public_id: ObjectId, local_id: ObjectId },
    Opened { public_id: ObjectId, local_id: ObjectId },
}

/// Opens a skeleton in place. An id already in `correspondence` is returned unchanged.
pub fn open_change(input: &mut OpenInput<'_>) -> Result<OpenOutcome, ChangeError> {
    if let Some(local) = input.correspondence.get(&input.skeleton_id) {
        return Ok(OpenOutcome::Already {
            public_id: input.skeleton_id,
            local_id: local,
        });
    }
    let Some(entry) = input.manifest.entry(&input.skeleton_id).cloned() else {
        return Ok(OpenOutcome::NotAssociated { public_id: input.skeleton_id });
    };
    let skeleton = input.store.get_revision(&input.skeleton_id)?;
    if skeleton.change_id != entry.change_id || skeleton.parents.is_empty()
        || !skeleton.predecessors.is_empty() || !skeleton.description.is_empty()
        || skeleton.author != redacted_signature() || skeleton.committer != redacted_signature() {
        return Err(ChangeError::Tamper);
    }
    let capsule = input.store.get_blob(&entry.capsule).map_err(|_| ChangeError::Withheld)?;
    let opened = if let Some(cert) = input.manifest.reveals.get(&entry.skeleton) {
        cert.verify(input.pinned_owner)?;
        if !cert_matches(&entry, cert) || cert.remote != input.manifest.remote {
            return Err(ChangeError::Tamper);
        }
        decrypt_capsule(&capsule, &cert.key, &cert.salt, &entry, input.manifest.remote)?
    } else if let Some(role_key) = input.role_key {
        if role_key.context().remote != input.manifest.remote
            || role_key.context().group != entry.group
            || role_key.context().epoch != entry.epoch
        {
            return Err(ChangeError::Tamper);
        }
        let pack = input
            .packs
            .iter()
            .find(|pack| manifest::pack_id(pack) == entry.wrapper_pack)
            .ok_or(ChangeError::Withheld)?;
        let (key, salt) = key_from_pack(pack, role_key, &entry)?;
        decrypt_capsule(&capsule, &key, &salt, &entry, input.manifest.remote)?
    } else if input.expects_access {
        return Err(ChangeError::Withheld);
    } else {
        return Ok(OpenOutcome::Opaque { public_id: input.skeleton_id });
    };
    if opened.projected.parents != skeleton.parents {
        return Err(ChangeError::Tamper);
    }
    let local = materialize(input.store, &opened, &skeleton)?;
    input.correspondence.insert_new(input.skeleton_id, local)?;
    Ok(OpenOutcome::Opened {
        public_id: input.skeleton_id,
        local_id: local,
    })
}

pub struct DescendantInput<'a> {
    pub store: &'a dyn Store,
    pub manifest: &'a ChangeManifest,
    pub skeleton_id: ObjectId,
    pub opened_id: ObjectId,
    pub opened: &'a Revision,
    pub child: &'a Revision,
}

/// `merge_trees(store, S.tree, D.tree, C.tree)`: the child's delta from the opaque parent, on `D`.
pub fn open_descendant(input: &DescendantInput<'_>) -> Result<Revision, ChangeError> {
    let entry = input.manifest.entry(&input.skeleton_id).ok_or(ChangeError::Invalid(
        "no signed manifest association for this parent".into(),
    ))?;
    let skeleton = input.store.get_revision(&input.skeleton_id)?;
    if skeleton.change_id != entry.change_id || !input.child.parents.contains(&input.skeleton_id) {
        return Err(ChangeError::Tamper);
    }
    if input.opened.change_id != skeleton.change_id {
        return Err(ChangeError::Tamper);
    }
    let tree = match merge_trees(input.store, &skeleton.tree, &input.opened.tree, &input.child.tree)? {
        MergeOutcome::Clean(tree) => tree,
        MergeOutcome::Conflict { .. } => {
            return Err(ChangeError::Invalid("opening the parent conflicts with the child".into()));
        }
    };
    let mut next = input.child.clone();
    next.tree = tree;
    next.parents = input
        .child
        .parents
        .iter()
        .map(|parent| {
            if *parent == input.skeleton_id {
                input.opened_id
            } else {
                *parent
            }
        })
        .collect();
    Ok(next)
}

pub struct DescendantCheck<'a> {
    pub store: &'a dyn Store,
    pub manifest: &'a ChangeManifest,
    pub skeleton_id: ObjectId,
    pub opened_id: ObjectId,
    pub opened: &'a Revision,
    pub child: &'a Revision,
    pub upgraded: &'a Revision,
}

/// Inverts the descendant merge and maps the opened parent back to the public skeleton.
pub fn descendant_public_bytes(input: &DescendantCheck<'_>) -> Result<Vec<u8>, ChangeError> {
    if input.manifest.entry(&input.skeleton_id).is_none() {
        return Err(ChangeError::Invalid("no signed manifest association for this parent".into()));
    }
    let skeleton = input.store.get_revision(&input.skeleton_id)?;
    if input.upgraded.change_id != input.child.change_id
        || input.upgraded.description != input.child.description
        || input.upgraded.author != input.child.author
        || input.upgraded.committer != input.child.committer
    {
        return Err(ChangeError::Tamper);
    }
    let tree = match merge_trees(
        input.store,
        &input.opened.tree,
        &skeleton.tree,
        &input.upgraded.tree,
    )? {
        MergeOutcome::Clean(tree) => tree,
        MergeOutcome::Conflict { .. } => return Err(ChangeError::Tamper),
    };
    let mut projected = input.child.clone();
    projected.tree = tree;
    projected.parents = input
        .upgraded
        .parents
        .iter()
        .map(|parent| {
            if *parent == input.opened_id {
                input.skeleton_id
            } else {
                *parent
            }
        })
        .collect();
    if projected.parents != input.child.parents || projected.tree != input.child.tree {
        return Err(ChangeError::Tamper);
    }
    Ok(projected.encode())
}

pub struct SealCommand<'a> {
    pub repo: &'a mut Repo,
    pub remote: &'a dyn Remote,
    pub identity: &'a Identity,
    pub keyring: &'a Keyring,
    pub pinned_owner: &'a [u8; 32],
    pub min_counter: u64,
    pub min_sequence: u64,
    pub known_reveals: &'a BTreeSet<ObjectId>,
    pub bookmark: &'a str,
    pub revision: ObjectId,
    pub role: &'a str,
    pub role_key: &'a EpochKey,
    pub privacy_keys: &'a BTreeMap<String, &'a EpochKey>,
    pub correspondence: &'a Correspondence,
}

pub fn seal_command(command: SealCommand<'_>) -> Result<SealReport, ChangeError> {
    let parents: Vec<ObjectId> = {
        let revision = command.repo.store().get_revision(&command.revision)?;
        revision
            .parents
            .into_iter()
            .map(|parent| command.correspondence.public_id(parent))
            .collect()
    };
    let report = {
        let store = command.repo.store().clone();
        publish_seal(&SealRequest {
            store: store.as_ref(),
            remote: command.remote,
            identity: command.identity,
            keyring: command.keyring,
            pinned_owner: command.pinned_owner,
            min_counter: command.min_counter,
            min_sequence: command.min_sequence,
            known_reveals: command.known_reveals,
            bookmark: command.bookmark,
            revision: command.revision,
            public_parents: &parents,
            role: command.role,
            role_key: command.role_key,
            privacy_keys: command.privacy_keys,
        })?
    };
    Ok(report)
}
