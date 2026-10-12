//! Shared setup for the multi-user scenarios: in-memory repos, contributors
//! that each hold their own repo and remote connection, the two backends,
//! and a `Remote` wrapper that injects faults and logs head commits.

#![allow(dead_code)]

pub mod http;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tig_core::ophead::MemoryOpHead;
use tig_core::repo::{Repo, Settings, DEFAULT_WORKSPACE};
use tig_core::store::{Store, StoreExt};
use tig_core::treeops::{lookup, Leaf};
use tig_core::workspace::Workspace;
use tig_core::{ChangeId, EntryKind, ObjectId, ObjectKind, RepoPath};
use tig_private::access;
use tig_private::fetch::{fetch, FetchError, FetchReport, FetchState};
use tig_private::keyring::{Keyring, OwnerKeys};
use tig_private::keys::{Identity, PublicIdentity};
use tig_private::manifest::Manifest;
use tig_private::publish::{publish, PublishError, PublishOptions, PublishReport, PublishState};
use tig_private::remote::{CommitOutcome, DirRemote, HeadVersion, Remote, RemoteError, RemoteHead};

// ---------------------------------------------------------------------------
// Backends

/// Where the shared remote lives. `connect` returns one contributor's own
/// connection; `None` is an anonymous reader.
pub trait Backend: Send + Sync {
    fn name(&self) -> &'static str;
    fn connect(&self, identity: Option<&Identity>) -> Box<dyn Remote>;
}

pub struct DirBackend {
    _dir: tempfile::TempDir,
    path: PathBuf,
}

impl DirBackend {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("remote");
        let mut id = [0u8; 16];
        id.copy_from_slice(&ChangeId::random().unwrap().0);
        DirRemote::create(&path, id).unwrap();
        DirBackend { _dir: dir, path }
    }
}

impl Backend for DirBackend {
    fn name(&self) -> &'static str {
        "dir"
    }

    fn connect(&self, _identity: Option<&Identity>) -> Box<dyn Remote> {
        Box::new(DirRemote::open(&self.path).unwrap())
    }
}

pub fn copy_identity(identity: &Identity) -> Identity {
    Identity::from_bytes(*identity.to_bytes())
}

// ---------------------------------------------------------------------------
// Repos

pub fn path(text: &str) -> RepoPath {
    RepoPath::new(text).unwrap()
}

pub fn repo() -> Repo {
    let settings = Settings {
        fixed_time_ms: Some(1_700_000_000_000),
        ..Settings::default()
    };
    Repo::init(
        Arc::new(tig_core::MemoryStore::new()),
        Arc::new(MemoryOpHead::new()),
        settings,
    )
    .unwrap()
}

/// Writes files into the working change and snapshots it.
pub fn save(repo: &mut Repo, writes: &[(&str, &[u8])]) -> ObjectId {
    let mut ws = Workspace::open(repo, DEFAULT_WORKSPACE).unwrap();
    for (name, data) in writes {
        ws.write(repo, &path(name), data).unwrap();
    }
    assert!(ws.snapshot(repo).unwrap(), "snapshot recorded nothing");
    ws.working_revision()
}

/// A new change on `parents` (a merge when there are several), made the
/// working change. Conflicts are stored, not refused.
pub fn new_change(repo: &mut Repo, parents: &[ObjectId], description: &str) -> ObjectId {
    let mut tx = repo.start("new");
    let child = tx.new_change(parents, description).unwrap();
    tx.set_working(DEFAULT_WORKSPACE, child).unwrap();
    repo.commit(tx).unwrap();
    child
}

/// A new change on `parent` holding `writes`.
pub fn on_top(repo: &mut Repo, parent: ObjectId, writes: &[(&str, &[u8])]) -> ObjectId {
    new_change(repo, &[parent], "");
    save(repo, writes)
}

pub fn describe(repo: &mut Repo, rev: ObjectId, text: &str) -> ObjectId {
    let mut tx = repo.start("describe");
    let new = tx
        .rewrite(rev, |revision| revision.description = text.to_string())
        .unwrap();
    repo.commit(tx).unwrap();
    new
}

pub fn leaf(store: &dyn Store, rev: ObjectId, name: &str) -> Option<Leaf> {
    let tree = store.get_revision(&rev).unwrap().tree;
    lookup(store, &tree, &path(name)).unwrap()
}

/// File bytes at `name` in `rev`; panics unless it is a plain file.
pub fn file(store: &dyn Store, rev: ObjectId, name: &str) -> Vec<u8> {
    let found = leaf(store, rev, name).unwrap_or_else(|| panic!("{name} is missing"));
    assert_eq!(found.kind(), EntryKind::File, "{name}");
    store.get_blob(&found.id()).unwrap()
}

/// Whether `name` in `rev` is hidden behind a sealed entry: the path itself,
/// or a folder above it that was sealed whole.
pub fn sealed(store: &dyn Store, rev: ObjectId, name: &str) -> bool {
    let mut prefix = String::new();
    for part in name.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(part);
        match leaf(store, rev, &prefix) {
            Some(found) if found.kind() == EntryKind::Sealed => return true,
            Some(found) if found.kind() == EntryKind::Tree => continue,
            _ => return false,
        }
    }
    false
}

/// Revisions reachable from `tip` through parents whose change is `change`.
pub fn revisions_of(store: &dyn Store, tip: ObjectId, change: ChangeId) -> BTreeSet<ObjectId> {
    tig_core::merge::ancestors(store, &tip)
        .unwrap()
        .into_iter()
        .filter(|id| store.get_revision(id).unwrap().change_id == change)
        .collect()
}

// ---------------------------------------------------------------------------
// Contributors

/// One person: their identity, their own repo, their own remote connection,
/// and their per-remote publish and fetch memory.
pub struct Contributor {
    pub name: String,
    pub identity: Identity,
    /// Only the owner holds epoch keys.
    pub keys: Option<OwnerKeys>,
    /// The owner's `owner-keys` / `pending-keyring` / `publish-state` dir.
    pub local: tempfile::TempDir,
    pub repo: Repo,
    pub remote: Box<dyn Remote>,
    pub published: PublishState,
    pub fetched: FetchState,
    /// Local revision of each remote bookmark at the last fetch.
    pub refs: BTreeMap<String, ObjectId>,
}

impl Contributor {
    pub fn new(name: &str, identity: Identity, backend: &dyn Backend) -> Self {
        let remote = backend.connect(Some(&identity));
        Contributor {
            name: name.to_string(),
            identity,
            keys: None,
            local: tempfile::tempdir().unwrap(),
            repo: repo(),
            remote,
            published: PublishState::new(),
            fetched: FetchState::new(),
            refs: BTreeMap::new(),
        }
    }

    /// The remote's owner, with epoch keys prepared and saved before the
    /// first publish (as `tig publish` does).
    pub fn owner_with(identity: Identity, backend: &dyn Backend) -> Self {
        let mut owner = Contributor::new("owner", identity, backend);
        let keys = Keyring::create(owner.remote.remote_id(), &owner.identity)
            .unwrap()
            .1;
        std::fs::write(owner.local.path().join("owner-keys"), keys.encode().unwrap()).unwrap();
        owner.keys = Some(keys);
        owner
    }

    pub fn public(&self) -> PublicIdentity {
        self.identity.public()
    }

    pub fn publish(&mut self, bookmark: &str, rev: ObjectId) -> Result<PublishReport, PublishError> {
        publish(
            self.repo.store().as_ref(),
            self.remote.as_ref(),
            &self.identity,
            self.keys.as_ref(),
            &mut self.published,
            &self.fetched,
            bookmark,
            rev,
            &PublishOptions::default(),
        )
    }

    /// Publishes through `remote` instead of this contributor's connection.
    pub fn publish_via(
        &mut self,
        remote: &dyn Remote,
        bookmark: &str,
        rev: ObjectId,
    ) -> Result<PublishReport, PublishError> {
        publish(
            self.repo.store().as_ref(),
            remote,
            &self.identity,
            self.keys.as_ref(),
            &mut self.published,
            &self.fetched,
            bookmark,
            rev,
            &PublishOptions::default(),
        )
    }

    /// Fetches every bookmark and raises the publish floors to what fetch
    /// accepted (the CLI keeps both states for one remote).
    pub fn fetch(&mut self) -> Result<FetchReport, FetchError> {
        let report = fetch(
            self.remote.as_ref(),
            self.repo.store().as_ref(),
            Some(&self.identity),
            &mut self.fetched,
            &self.published,
        )?;
        self.published.remote_id = self.fetched.remote_id;
        self.published.owner_signing = self.fetched.owner_signing;
        self.published.counter = self.published.counter.max(self.fetched.counter);
        self.published.manifest_seq = self.published.manifest_seq.max(self.fetched.manifest_seq);
        self.refs = report.refs.clone();
        Ok(report)
    }

    pub fn grant(&mut self, member: &PublicIdentity) {
        access::grant(
            self.remote.as_ref(),
            self.local.path(),
            &self.identity,
            self.keys.as_ref().expect("only the owner grants"),
            &mut self.published,
            member,
        )
        .unwrap();
    }

    /// Revokes through `remote` (the owner's own connection, or a wrapper).
    pub fn revoke_via(
        &mut self,
        remote: &dyn Remote,
        member: &PublicIdentity,
    ) -> Result<(), access::AccessError> {
        std::fs::write(
            self.local.path().join("publish-state"),
            self.published.encode().unwrap(),
        )
        .unwrap();
        access::revoke(
            remote,
            self.local.path(),
            &self.identity,
            self.keys.as_mut().expect("only the owner revokes"),
            &mut self.published,
            member,
        )
    }

    pub fn revoke(&mut self, member: &PublicIdentity) -> Result<(), access::AccessError> {
        std::fs::write(
            self.local.path().join("publish-state"),
            self.published.encode().unwrap(),
        )
        .unwrap();
        access::revoke(
            self.remote.as_ref(),
            self.local.path(),
            &self.identity,
            self.keys.as_mut().expect("only the owner revokes"),
            &mut self.published,
            member,
        )
    }

    pub fn store(&self) -> &dyn Store {
        self.repo.store().as_ref()
    }

    pub fn head(&self) -> RemoteHead {
        self.remote.read_head().unwrap()
    }

    pub fn manifest(&self) -> Manifest {
        Manifest::decode(&self.head().manifest.expect("no manifest")).unwrap()
    }
}

pub const BASE_ENV: &[u8] = b"API_KEY=base-secret\n";

/// `owner` publishes `main` (a public README and a private `.env`), grants
/// every member, and every member fetches. Index 0 is the owner.
pub fn team(backend: &dyn Backend, owner: Identity, names: &[&str]) -> Vec<Contributor> {
    let mut owner = Contributor::owner_with(owner, backend);
    let base = save(
        &mut owner.repo,
        &[("README.md", b"shared project\n"), ("shared.txt", b"base\n"), (".env", BASE_ENV)],
    );
    owner.publish("main", base).unwrap();
    let mut members: Vec<Contributor> = names
        .iter()
        .map(|name| Contributor::new(name, Identity::generate().unwrap(), backend))
        .collect();
    for member in &members {
        owner.grant(&member.public());
    }
    owner.fetch().unwrap();
    assert_eq!(owner.refs["main"], base, "the owner's fetch must reuse its own revision");
    for member in &mut members {
        member.fetch().unwrap();
        let main = member.refs["main"];
        assert_eq!(file(member.store(), main, ".env"), BASE_ENV, "{}", member.name);
    }
    let mut all = vec![owner];
    all.extend(members);
    all
}

// ---------------------------------------------------------------------------
// A wrapper remote: fault injection and a commit log

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// `commit_head` fails before reaching the remote: the publisher died
    /// after uploading objects and packs.
    DieBeforeCommit,
    /// `commit_head` lands, then the reply is lost.
    LoseCommitReply,
}

#[derive(Clone, Debug)]
pub struct CommitRecord {
    pub who: String,
    pub committed: bool,
    pub keyring_changed: bool,
    pub publisher: Option<[u8; 32]>,
}

pub type CommitLog = Arc<Mutex<Vec<CommitRecord>>>;

pub struct Wrapped {
    inner: Box<dyn Remote>,
    fault: Mutex<Option<Fault>>,
    pub uploads: AtomicUsize,
    log: Option<(String, CommitLog)>,
}

impl Wrapped {
    pub fn faulty(inner: Box<dyn Remote>, fault: Fault) -> Self {
        Wrapped {
            inner,
            fault: Mutex::new(Some(fault)),
            uploads: AtomicUsize::new(0),
            log: None,
        }
    }

    /// Records every `commit_head` in `log`, in the order the remote
    /// applied them (the log lock is held across the call).
    pub fn logged(inner: Box<dyn Remote>, who: &str, log: CommitLog) -> Self {
        Wrapped {
            inner,
            fault: Mutex::new(None),
            uploads: AtomicUsize::new(0),
            log: Some((who.to_string(), log)),
        }
    }

    pub fn fault_pending(&self) -> bool {
        self.fault.lock().unwrap().is_some()
    }
}

impl Remote for Wrapped {
    fn remote_id(&self) -> [u8; 16] {
        self.inner.remote_id()
    }
    fn public_store(&self) -> &dyn Store {
        self.inner.public_store()
    }
    fn missing(&self, ids: &[ObjectId]) -> Result<Vec<ObjectId>, RemoteError> {
        self.inner.missing(ids)
    }
    fn put_batch(&self, objects: &[(ObjectId, ObjectKind, Vec<u8>)]) -> Result<(), RemoteError> {
        self.uploads.fetch_add(1, Ordering::SeqCst);
        self.inner.put_batch(objects)
    }
    fn get_batch(&self, ids: &[ObjectId]) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, RemoteError> {
        self.inner.get_batch(ids)
    }
    fn put_pack(&self, bytes: &[u8]) -> Result<(), RemoteError> {
        self.uploads.fetch_add(1, Ordering::SeqCst);
        self.inner.put_pack(bytes)
    }
    fn list_packs(&self, group: &str, epoch: u64) -> Result<Vec<Vec<u8>>, RemoteError> {
        self.inner.list_packs(group, epoch)
    }
    fn read_head(&self) -> Result<RemoteHead, RemoteError> {
        self.inner.read_head()
    }
    fn commit_head(
        &self,
        expected: &HeadVersion,
        keyring: Option<&[u8]>,
        manifest: Option<&[u8]>,
    ) -> Result<CommitOutcome, RemoteError> {
        let fault = self.fault.lock().unwrap().take();
        if fault == Some(Fault::DieBeforeCommit) {
            return Err(RemoteError::Invalid("injected: publisher died before commit_head".into()));
        }
        let outcome = match &self.log {
            None => self.inner.commit_head(expected, keyring, manifest)?,
            Some((who, log)) => {
                let mut log = log.lock().unwrap();
                let outcome = self.inner.commit_head(expected, keyring, manifest)?;
                log.push(CommitRecord {
                    who: who.clone(),
                    committed: matches!(outcome, CommitOutcome::Committed(_)),
                    keyring_changed: keyring.is_some(),
                    publisher: manifest.map(|bytes| Manifest::decode(bytes).unwrap().publisher),
                });
                outcome
            }
        };
        if fault == Some(Fault::LoseCommitReply) {
            return Err(RemoteError::Invalid("injected: commit_head reply lost".into()));
        }
        Ok(outcome)
    }
    fn read_legacy_refs(&self) -> Result<Option<BTreeMap<String, ObjectId>>, RemoteError> {
        self.inner.read_legacy_refs()
    }
}
