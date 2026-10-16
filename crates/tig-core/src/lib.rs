//! tig-core: objects, stores, path index, trees, revisions, operation log,
//! and workspaces. Nothing here needs a filesystem except `store::disk`.
//!
//! Read DESIGN.md at the repo root before changing anything here.

pub mod blob;
pub mod domain;
pub mod durability;
pub mod conflict;
pub mod encode;
pub mod error;
pub mod id;
pub mod index;
pub mod merge;
pub mod object;
pub mod ophead;
pub mod path;
mod recovery;
pub mod repo;
pub mod seal;
pub mod store;
pub mod treeops;
pub mod workspace;

pub use blob::{ChunkManifest, ChunkRef, CHUNK_LEN};
pub use error::{Error, Result};
pub use id::{ChangeId, ObjectId};
pub use object::{
    EntryKind, Object, ObjectKind, Operation, Revision, Signature, Tree, TreeEntry, View,
};
pub use path::RepoPath;
pub use store::{MemoryStore, Store};
