//! Full integrity checks run only during explicit or exceptional recovery.

use std::collections::{HashMap, HashSet, VecDeque};

use crate::blob::{self, ChunkRef};
use crate::object::{hash_object, EntryKind, ObjectKind, Operation, Revision, Tree, View};
use crate::ophead::OpHeadStore;
use crate::store::Store;
use crate::{Error, ObjectId, Result};

pub(crate) fn damaged(error: &Error) -> bool {
    matches!(
        error,
        Error::NotFound(_)
            | Error::Corrupt { .. }
            | Error::Decode { .. }
            | Error::WrongKind { .. }
            | Error::InvalidPath { .. }
    )
}

pub(crate) fn recover(
    store: &dyn Store,
    head: &dyn OpHeadStore,
    current: ObjectId,
) -> Result<(ObjectId, Operation, View)> {
    let mut pending = VecDeque::from([current]);
    pending.extend(head.recovery_heads()?);
    let mut seen = HashSet::new();
    while let Some(id) = pending.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        if seen.len() > 100_000 {
            return Err(Error::Invalid(
                "recovery history is too large; operation head unchanged".into(),
            ));
        }
        let op = match checked_raw(store, id, ObjectKind::Operation)
            .and_then(|body| Operation::decode(&body))
        {
            Ok(op) => op,
            Err(error) if damaged(&error) => continue,
            Err(error) => return Err(error),
        };
        pending.extend(op.parents.iter().copied());
        let checked = checked_raw(store, op.view, ObjectKind::View)
            .and_then(|body| View::decode(&body))
            .and_then(|view| {
                verify_view(store, &view)?;
                Ok(view)
            });
        match checked {
            Ok(view) => {
                let unchanged = if id == current {
                    head.get()? == Some(current)
                } else {
                    head.compare_and_set(Some(current), id)?
                };
                if !unchanged {
                    return Err(Error::Invalid(
                        "operation head moved during recovery; retry".into(),
                    ));
                }
                return Ok((id, op, view));
            }
            Err(error) if damaged(&error) => {}
            Err(error) => return Err(error),
        }
    }
    Err(Error::Invalid(
        "no complete operation found; operation head unchanged".into(),
    ))
}

fn checked_raw(store: &dyn Store, id: ObjectId, expected: ObjectKind) -> Result<Vec<u8>> {
    let (kind, body) = store.get_raw(&id)?.ok_or(Error::NotFound(id))?;
    if kind != expected {
        return Err(Error::WrongKind {
            expected: expected.name(),
            found: kind.name(),
        });
    }
    if hash_object(kind, &body) != id {
        return Err(Error::Corrupt {
            id,
            reason: "content hash does not match id".into(),
        });
    }
    Ok(body)
}

/// Current visible history and its content, excluding opaque sealed entries
/// and predecessor/operation history which is not needed for this view.
fn verify_view(store: &dyn Store, view: &View) -> Result<()> {
    let mut pending: Vec<_> = view
        .heads
        .iter()
        .chain(view.workspaces.values())
        .chain(view.bookmarks.values())
        .map(|id| (*id, ObjectKind::Revision))
        .collect();
    let mut seen: HashMap<ObjectId, (ObjectKind, usize)> = HashMap::new();
    let mut chunk_len: HashMap<ObjectId, u32> = HashMap::new();
    while let Some((id, expected)) = pending.pop() {
        if let Some((kind, len)) = seen.get(&id) {
            if *kind != expected {
                return Err(Error::WrongKind {
                    expected: expected.name(),
                    found: kind.name(),
                });
            }
            if expected == ObjectKind::Blob && chunk_len.get(&id).is_some_and(|want| *want as usize != *len) {
                return Err(Error::Corrupt { id, reason: "previously verified blob has the wrong chunk length".into() });
            }
            continue;
        }
        if seen.len() >= 1_000_000 || pending.len() > 1_000_000 {
            return Err(Error::Invalid(
                "recovery view is too large; operation head unchanged".into(),
            ));
        }
        let body = checked_raw(store, id, expected)?;
        seen.insert(id, (expected, body.len()));
        match expected {
            ObjectKind::Revision => {
                let rev = Revision::decode(&body)?;
                pending.push((rev.tree, ObjectKind::Tree));
                pending.extend(rev.parents.into_iter().map(|id| (id, ObjectKind::Revision)));
            }
            ObjectKind::Tree => {
                for entry in Tree::decode(&body)?.entries() {
                    let kind = match entry.kind() {
                        EntryKind::Tree => ObjectKind::Tree,
                        EntryKind::File | EntryKind::Executable | EntryKind::Symlink => {
                            file_kind(store, &entry.id())?
                        }
                        EntryKind::Sealed => continue,
                        EntryKind::Conflict => ObjectKind::Conflict,
                    };
                    pending.push((entry.id(), kind));
                }
            }
            ObjectKind::Blob => {
                if let Some(len) = chunk_len.get(&id) {
                    if body.len() != *len as usize {
                        return Err(Error::Corrupt {
                            id,
                            reason: format!("chunk is {} bytes; the manifest says {len}", body.len()),
                        });
                    }
                }
            }
            ObjectKind::ChunkedBlob => {
                let manifest = blob::parse_manifest(&body)?;
                for chunk in manifest.chunks() {
                    remember_chunk(&mut chunk_len, chunk)?;
                    pending.push((chunk.id, ObjectKind::Blob));
                }
            }
            ObjectKind::Conflict => {
                let conflict = crate::conflict::Conflict::decode(&body)?;
                if let Some(draft) = conflict.draft() { pending.push((draft, file_kind(store, &draft)?)); }
                for leaf in conflict.adds().iter().chain(conflict.removes()).flatten() {
                    let kind = match leaf.kind() {
                        EntryKind::Tree => ObjectKind::Tree,
                        EntryKind::Conflict => ObjectKind::Conflict,
                        EntryKind::Sealed => continue,
                        _ => file_kind(store, &leaf.id())?,
                    };
                    pending.push((leaf.id(), kind));
                }
            }
            ObjectKind::Operation | ObjectKind::View => unreachable!(),
        }
    }
    Ok(())
}

fn file_kind(store: &dyn Store, id: &ObjectId) -> Result<ObjectKind> {
    match store.kind(id)? {
        Some(kind @ (ObjectKind::Blob | ObjectKind::ChunkedBlob)) => Ok(kind),
        Some(kind) => Err(Error::WrongKind {
            expected: "blob",
            found: kind.name(),
        }),
        None => Err(Error::NotFound(*id)),
    }
}

fn remember_chunk(lens: &mut HashMap<ObjectId, u32>, chunk: &ChunkRef) -> Result<()> {
    if let Some(previous) = lens.insert(chunk.id, chunk.len) {
        if previous != chunk.len {
            return Err(Error::Corrupt {
                id: chunk.id,
                reason: "chunk length disagrees across manifests".into(),
            });
        }
    }
    Ok(())
}
