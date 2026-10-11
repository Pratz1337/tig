//! tig-core: objects, stores, path index, trees, revisions, operation log,
//! and workspaces. Nothing here needs a filesystem except `store::disk`.
//!
//! Read DESIGN.md at the repo root before changing anything here.

pub mod encode;
pub mod error;
pub mod id;
pub mod object;
pub mod store;

pub use error::{Error, Result};
pub use id::{ChangeId, ObjectId};
pub use object::{EntryKind, Object, ObjectKind, Operation, Revision, Signature, Tree, TreeEntry, View};
pub use store::{MemoryStore, Store};
