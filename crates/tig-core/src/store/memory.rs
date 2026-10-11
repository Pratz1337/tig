use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::Result;
use crate::id::ObjectId;
use crate::object::ObjectKind;
use crate::store::Store;

/// In-memory store: the fastest backend, used by agents and tests.
#[derive(Default)]
pub struct MemoryStore {
    objects: RwLock<HashMap<ObjectId, (ObjectKind, Vec<u8>)>>,
}

impl MemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.objects.read().expect("lock poisoned").len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Store for MemoryStore {
    fn get_raw(&self, id: &ObjectId) -> Result<Option<(ObjectKind, Vec<u8>)>> {
        Ok(self.objects.read().expect("lock poisoned").get(id).cloned())
    }

    fn put_raw(&self, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> Result<()> {
        self.objects.write().expect("lock poisoned").entry(*id).or_insert_with(|| (kind, body.to_vec()));
        Ok(())
    }

    fn has(&self, id: &ObjectId) -> Result<bool> {
        Ok(self.objects.read().expect("lock poisoned").contains_key(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::StoreExt;

    #[test]
    fn put_get_blob() {
        let s = MemoryStore::new();
        let id = s.put_blob(b"hi").unwrap();
        assert_eq!(s.get_blob(&id).unwrap(), b"hi");
        assert!(s.get_tree(&id).is_err());
        assert_eq!(s.put_blob(b"hi").unwrap(), id);
        assert_eq!(s.len(), 1);
    }
}
