//! Object stores. A store maps `ObjectId` to `(kind, body)`. It never interprets
//! bodies; typed helpers live on `StoreExt`.

mod disk;
mod journal;
mod memory;

pub use disk::DiskStore;
pub use journal::JournalStore;
pub use memory::MemoryStore;

use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::{hash_object, Object, ObjectKind, Operation, Revision, Tree, View};

/// Storage backend. Implementations must be safe to share across threads.
///
/// `put_raw` is given the precomputed id; backends may trust it (callers in this
/// crate always compute it with `hash_object`). `get_raw` must return exactly
/// what was put.
pub trait Store: Send + Sync {
    fn get_raw(&self, id: &ObjectId) -> Result<Option<(ObjectKind, Vec<u8>)>>;
    /// A fast type check, not an integrity check: this need not verify the
    /// body hash. Use `get_raw` to read and verify the body. The default reads
    /// the whole object; backends can look up just its kind.
    fn kind(&self, id: &ObjectId) -> Result<Option<ObjectKind>> {
        Ok(self.get_raw(id)?.map(|(kind, _)| kind))
    }

    fn put_raw(&self, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> Result<()>;
    fn has(&self, id: &ObjectId) -> Result<bool>;
}

/// Typed helpers available on every store.
pub trait StoreExt: Store {
    fn put(&self, obj: &Object) -> Result<ObjectId> {
        let body = obj.encode_body();
        let id = hash_object(obj.kind(), &body);
        if !self.has(&id)? {
            self.put_raw(&id, obj.kind(), &body)?;
        }
        Ok(id)
    }

    fn put_blob(&self, data: &[u8]) -> Result<ObjectId> {
        let id = hash_object(ObjectKind::Blob, data);
        if !self.has(&id)? {
            self.put_raw(&id, ObjectKind::Blob, data)?;
        }
        Ok(id)
    }

    fn get(&self, id: &ObjectId) -> Result<Object> {
        let (kind, body) = self.get_raw(id)?.ok_or(Error::NotFound(*id))?;
        Object::decode(kind, &body)
    }

    fn get_kind(&self, id: &ObjectId, expected: ObjectKind) -> Result<Vec<u8>> {
        let (kind, body) = self.get_raw(id)?.ok_or(Error::NotFound(*id))?;
        if kind != expected {
            return Err(Error::WrongKind {
                expected: expected.name(),
                found: kind.name(),
            });
        }
        Ok(body)
    }

    fn get_blob(&self, id: &ObjectId) -> Result<Vec<u8>> {
        self.get_kind(id, ObjectKind::Blob)
    }

    fn get_tree(&self, id: &ObjectId) -> Result<Tree> {
        Tree::decode(&self.get_kind(id, ObjectKind::Tree)?)
    }

    fn get_revision(&self, id: &ObjectId) -> Result<Revision> {
        Revision::decode(&self.get_kind(id, ObjectKind::Revision)?)
    }

    fn get_operation(&self, id: &ObjectId) -> Result<Operation> {
        Operation::decode(&self.get_kind(id, ObjectKind::Operation)?)
    }

    fn get_view(&self, id: &ObjectId) -> Result<View> {
        View::decode(&self.get_kind(id, ObjectKind::View)?)
    }
}

impl<S: Store + ?Sized> StoreExt for S {}

/// The empty tree's id, which every new repo's root revision points at.
pub fn empty_tree_id() -> ObjectId {
    Object::Tree(Tree::empty()).id()
}
