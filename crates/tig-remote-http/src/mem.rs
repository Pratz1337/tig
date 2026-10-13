//! In-memory `Remote` for tests and for running the server without a directory.

use std::collections::BTreeMap;
use std::sync::Mutex;

use tig_core::object::hash_object;
use tig_core::store::Store;
use tig_core::{ObjectId, ObjectKind};
use tig_private::pack::Pack;
use tig_private::remote::{CommitOutcome, HeadVersion, Remote, RemoteError, RemoteHead};

use crate::limits::{MAX_LISTED_PACKS, MAX_OBJECT_BODY, MAX_PACK_FILE};
use crate::wire::check_group;

type Packs = BTreeMap<(String, u64), BTreeMap<[u8; 32], Vec<u8>>>;

#[derive(Default)]
struct Objects {
    map: Mutex<BTreeMap<ObjectId, (ObjectKind, Vec<u8>)>>,
}

impl Store for Objects {
    fn get_raw(&self, id: &ObjectId) -> tig_core::Result<Option<(ObjectKind, Vec<u8>)>> {
        let map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        Ok(map.get(id).cloned())
    }

    fn put_raw(&self, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> tig_core::Result<()> {
        if hash_object(kind, body) != *id {
            return Err(tig_core::Error::Invalid(
                "object id does not match its bytes".into(),
            ));
        }
        if body.len() > MAX_OBJECT_BODY {
            return Err(tig_core::Error::Invalid("object is too large".into()));
        }
        let mut map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        map.insert(*id, (kind, body.to_vec()));
        Ok(())
    }

    fn has(&self, id: &ObjectId) -> tig_core::Result<bool> {
        let map = self.map.lock().unwrap_or_else(|p| p.into_inner());
        Ok(map.contains_key(id))
    }
}

/// Process-local remote. Packs are real sealed packs (`Pack::peek_header`).
pub struct MemRemote {
    id: [u8; 16],
    objects: Objects,
    packs: Mutex<Packs>,
    head: Mutex<RemoteHead>,
}

impl MemRemote {
    pub fn new(id: [u8; 16]) -> Self {
        MemRemote {
            id,
            objects: Objects::default(),
            packs: Mutex::new(BTreeMap::new()),
            head: Mutex::new(RemoteHead {
                keyring: None,
                manifest: None,
            }),
        }
    }
}

impl Remote for MemRemote {
    fn remote_id(&self) -> [u8; 16] {
        self.id
    }

    fn public_store(&self) -> &dyn Store {
        &self.objects
    }

    fn missing(&self, ids: &[ObjectId]) -> Result<Vec<ObjectId>, RemoteError> {
        let map = self.objects.map.lock().unwrap_or_else(|p| p.into_inner());
        Ok(ids
            .iter()
            .copied()
            .filter(|id| !map.contains_key(id))
            .collect())
    }

    fn put_batch(&self, objects: &[(ObjectId, ObjectKind, Vec<u8>)]) -> Result<(), RemoteError> {
        for (id, kind, body) in objects {
            self.objects.put_raw(id, *kind, body)?;
        }
        Ok(())
    }

    fn get_batch(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, RemoteError> {
        let map = self.objects.map.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = Vec::new();
        for id in ids {
            if let Some((kind, body)) = map.get(id) {
                if hash_object(*kind, body) != *id {
                    return Err(RemoteError::Invalid(
                        "stored object does not match its id".into(),
                    ));
                }
                out.push((*id, *kind, body.clone()));
            }
        }
        Ok(out)
    }

    fn put_pack(&self, bytes: &[u8]) -> Result<(), RemoteError> {
        if bytes.len() > MAX_PACK_FILE {
            return Err(RemoteError::Invalid("pack is too large".into()));
        }
        let header = Pack::peek_header(bytes)?;
        check_group(&header.group).map_err(RemoteError::Invalid)?;
        if header.remote != self.id {
            return Err(RemoteError::RemoteMismatch);
        }
        let id = *blake3::hash(bytes).as_bytes();
        let mut packs = self.packs.lock().unwrap_or_else(|p| p.into_inner());
        let epoch = packs.entry((header.group, header.epoch)).or_default();
        if epoch.len() >= MAX_LISTED_PACKS && !epoch.contains_key(&id) {
            return Err(RemoteError::Invalid("too many packs".into()));
        }
        if let Some(existing) = epoch.get(&id) {
            if existing != bytes {
                return Err(RemoteError::Invalid(
                    "pack path exists with different bytes".into(),
                ));
            }
            return Ok(());
        }
        epoch.insert(id, bytes.to_vec());
        Ok(())
    }

    fn list_packs(&self, group: &str, epoch: u64) -> Result<Vec<Vec<u8>>, RemoteError> {
        check_group(group).map_err(RemoteError::Invalid)?;
        let packs = self.packs.lock().unwrap_or_else(|p| p.into_inner());
        let Some(epoch) = packs.get(&(group.to_string(), epoch)) else {
            return Ok(Vec::new());
        };
        if epoch.len() > MAX_LISTED_PACKS {
            return Err(RemoteError::Invalid("too many packs".into()));
        }
        let mut remaining = MAX_PACK_FILE;
        for bytes in epoch.values() {
            remaining = remaining
                .checked_sub(bytes.len())
                .ok_or_else(|| RemoteError::Invalid("pack listing is too large".into()))?;
        }
        Ok(epoch.values().cloned().collect())
    }

    fn read_head(&self) -> Result<RemoteHead, RemoteError> {
        Ok(self.head.lock().unwrap_or_else(|p| p.into_inner()).clone())
    }

    fn commit_head(
        &self,
        expected: &HeadVersion,
        keyring: Option<&[u8]>,
        manifest: Option<&[u8]>,
    ) -> Result<CommitOutcome, RemoteError> {
        let mut head = self.head.lock().unwrap_or_else(|p| p.into_inner());
        if head.version() != *expected {
            return Ok(CommitOutcome::Stale(head.clone()));
        }
        if let Some(bytes) = keyring {
            if bytes.len() as u64 > crate::limits::MAX_KEYRING_FILE {
                return Err(RemoteError::Invalid("keyring is too large".into()));
            }
            head.keyring = Some(bytes.to_vec());
        }
        if let Some(bytes) = manifest {
            if bytes.len() as u64 > crate::limits::MAX_MANIFEST_FILE {
                return Err(RemoteError::Invalid("manifest is too large".into()));
            }
            head.manifest = Some(bytes.to_vec());
        }
        Ok(CommitOutcome::Committed(head.version()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_listing_cap_is_checked_before_copying() {
        let remote = MemRemote::new([1; 16]);
        remote.packs.lock().unwrap().insert(
            ("private".into(), 1),
            BTreeMap::from([([0; 32], vec![0; MAX_PACK_FILE]), ([1; 32], vec![0])]),
        );
        assert!(remote.list_packs("private", 1).is_err());
    }
}
