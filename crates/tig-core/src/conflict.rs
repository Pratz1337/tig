//! Local merge expressions. Alternatives are objects, never marker-file blobs.

use crate::encode::{Reader, Writer};
use crate::seal::SealedId;
use crate::store::{Store, StoreExt};
use crate::treeops::Leaf;
use crate::{EntryKind, Error, Object, ObjectId, Result};

const MAX_TERMS: usize = 4096;

/// `adds - removes`, with one more positive term than negative terms.
/// None represents deletion. A draft records partially edited marker bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Conflict {
    removes: Vec<Option<Leaf>>,
    adds: Vec<Option<Leaf>>,
    draft: Option<ObjectId>,
}

impl Conflict {
    pub fn removes(&self) -> &[Option<Leaf>] {
        &self.removes
    }
    pub fn adds(&self) -> &[Option<Leaf>] {
        &self.adds
    }
    pub fn draft(&self) -> Option<ObjectId> {
        self.draft
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(1);
        for terms in [&self.removes, &self.adds] {
            w.varint(terms.len() as u64);
            for leaf in terms {
                match leaf {
                    None => w.u8(0),
                    Some(leaf) => {
                        w.u8(leaf.kind() as u8);
                        w.id(&leaf.id());
                    }
                }
            }
        }
        w.u8(u8::from(self.draft.is_some()));
        if let Some(id) = self.draft {
            w.id(&id);
        }
        w.finish()
    }

    pub fn decode(body: &[u8]) -> Result<Self> {
        let mut r = Reader::new(body, "conflict");
        if r.u8()? != 1 {
            return Err(Error::decode("conflict", "unsupported version"));
        }
        let mut read_terms = || -> Result<Vec<Option<Leaf>>> {
            let n = r.count(1)?;
            if n > MAX_TERMS {
                return Err(Error::decode("conflict", "too many terms"));
            }
            let mut terms = Vec::with_capacity(n);
            for _ in 0..n {
                let kind = r.u8()?;
                terms.push(if kind == 0 {
                    None
                } else {
                    let kind = EntryKind::from_u8(kind)?;
                    let id = r.id()?;
                    Some(if kind == EntryKind::Sealed {
                        Leaf::sealed(SealedId::from_stored(id.0))
                    } else {
                        Leaf::new(kind, id)?
                    })
                });
            }
            Ok(terms)
        };
        let removes = read_terms()?;
        let adds = read_terms()?;
        let draft = match r.u8()? {
            0 => None,
            1 => Some(r.id()?),
            _ => return Err(Error::decode("conflict", "invalid draft flag")),
        };
        r.finish()?;
        if removes.is_empty()
            || adds.len() != removes.len() + 1
            || !removes.windows(2).all(|w| key(w[0]) <= key(w[1]))
            || !adds.windows(2).all(|w| key(w[0]) <= key(w[1]))
            || removes.iter().any(|leaf| {
                adds.binary_search_by_key(&key(*leaf), |term| key(*term))
                    .is_ok()
            })
            || adds.iter().all(|leaf| *leaf == adds[0])
        {
            return Err(Error::decode("conflict", "non-canonical expression"));
        }
        Ok(Self {
            removes,
            adds,
            draft,
        })
    }
}

fn key(leaf: Option<Leaf>) -> (u8, [u8; 32]) {
    leaf.map(|leaf| (leaf.kind() as u8, leaf.id().0))
        .unwrap_or((0, [0; 32]))
}

/// Flatten earlier expressions and cancel identical positive/negative terms.
/// A conflict with a draft is kept as an alternative so later merges retain
/// resolution work. Limits bound malformed or adversarial nested expressions.
pub fn merge(
    store: &dyn Store,
    base: Option<Leaf>,
    ours: Option<Leaf>,
    theirs: Option<Leaf>,
) -> Result<Option<Leaf>> {
    if ours == theirs || base == theirs {
        return Ok(ours);
    }
    if base == ours {
        return Ok(theirs);
    }
    let mut pending = vec![(base, false), (ours, true), (theirs, true)];
    let (mut removes, mut adds) = (Vec::new(), Vec::new());
    let mut visited = 0;
    while let Some((leaf, positive)) = pending.pop() {
        visited += 1;
        if visited > MAX_TERMS || pending.len() > MAX_TERMS {
            return Err(Error::Invalid("conflict expression is too large".into()));
        }
        if let Some(leaf) = leaf.filter(|leaf| leaf.kind() == EntryKind::Conflict) {
            let conflict = store.get_conflict(&leaf.id())?;
            if conflict.draft.is_none() {
                pending.extend(conflict.adds.into_iter().map(|leaf| (leaf, positive)));
                pending.extend(conflict.removes.into_iter().map(|leaf| (leaf, !positive)));
                continue;
            }
        }
        if positive {
            adds.push(leaf);
        } else {
            removes.push(leaf);
        }
    }
    removes.sort_by_key(|leaf| key(*leaf));
    adds.sort_by_key(|leaf| key(*leaf));
    let (mut negative, mut positive) = (Vec::new(), Vec::new());
    let (mut a, mut b) = (0, 0);
    while a < removes.len() && b < adds.len() {
        match key(removes[a]).cmp(&key(adds[b])) {
            std::cmp::Ordering::Equal => {
                a += 1;
                b += 1;
            }
            std::cmp::Ordering::Less => {
                negative.push(removes[a]);
                a += 1;
            }
            std::cmp::Ordering::Greater => {
                positive.push(adds[b]);
                b += 1;
            }
        }
    }
    negative.extend_from_slice(&removes[a..]);
    positive.extend_from_slice(&adds[b..]);
    if positive.iter().all(|leaf| *leaf == positive[0]) {
        return Ok(positive[0]);
    }
    let conflict = Conflict {
        removes: negative,
        adds: positive,
        draft: None,
    };
    Ok(Some(Leaf::new(
        EntryKind::Conflict,
        store.put(&Object::Conflict(conflict))?,
    )?))
}

/// Materializes file conflicts as regular files. Structural alternatives are
/// described by kind; internal hashes must not become accidental file contents.
pub fn materialize(store: &dyn Store, leaf: Leaf) -> Result<Vec<u8>> {
    if leaf.kind() != EntryKind::Conflict {
        return store.get_blob(&leaf.id());
    }
    let conflict = store.get_conflict(&leaf.id())?;
    if let Some(id) = conflict.draft {
        return store.get_blob(&id);
    }
    let width = marker_width(store, &conflict)?;
    let mut bytes = format!("{} tig conflict\n", "<".repeat(width)).into_bytes();
    for (label, terms) in [("base", &conflict.removes), ("side", &conflict.adds)] {
        for (i, leaf) in terms.iter().enumerate() {
            bytes.extend_from_slice(
                format!(
                    "{} tig {label} {}\n",
                    if label == "base" {
                        "-".repeat(width)
                    } else {
                        "+".repeat(width)
                    },
                    i + 1
                )
                .as_bytes(),
            );
            match leaf {
                None => bytes.extend_from_slice(b"[deleted]\n"),
                Some(leaf) if leaf.is_file_like() => {
                    bytes.extend_from_slice(format!("[{:?}]\n", leaf.kind()).as_bytes());
                    let content = store.get_blob(&leaf.id())?;
                    if !is_text(&content) {
                        bytes.extend_from_slice(
                            format!("[binary: select with tig resolve --{label} {}]\n", i + 1)
                                .as_bytes(),
                        );
                        continue;
                    }
                    bytes.extend_from_slice(&content);
                    if !content.ends_with(b"\n") {
                        bytes.push(b'\n');
                    }
                }
                Some(leaf) => {
                    let expected = match leaf.kind() {
                        EntryKind::Tree => Some(crate::ObjectKind::Tree),
                        EntryKind::Conflict => Some(crate::ObjectKind::Conflict),
                        EntryKind::Sealed => None,
                        _ => unreachable!(),
                    };
                    if let Some(kind) = expected {
                        store.get_kind(&leaf.id(), kind)?;
                    }
                    bytes.extend_from_slice(
                        format!(
                            "[{:?}: select with tig resolve --{label} {}]\n",
                            leaf.kind(),
                            i + 1
                        )
                        .as_bytes(),
                    );
                }
            }
        }
    }
    bytes.extend_from_slice(format!("{} tig conflict\n", ">".repeat(width)).as_bytes());
    Ok(bytes)
}

/// Unchanged markers keep the original object, edited markers save a draft,
/// and removing all generated markers resolves to ordinary file bytes.
pub fn snapshot_file(
    store: &dyn Store,
    previous: Leaf,
    bytes: &[u8],
    kind: EntryKind,
) -> Result<Leaf> {
    let mut conflict = store.get_conflict(&previous.id())?;
    if bytes == materialize(store, previous)? {
        return Ok(previous);
    }
    let width = marker_width(store, &conflict)?;
    let has_markers = bytes.split(|byte| *byte == b'\n').any(|line| {
        let Some(first) = line.first().filter(|byte| b"<>-+".contains(byte)) else {
            return false;
        };
        let count = line.iter().take_while(|byte| *byte == first).count();
        count >= width && line[count..].starts_with(b" tig ")
    });
    let id = store.put_blob(bytes)?;
    if !has_markers {
        return Leaf::new(kind, id);
    }
    conflict.draft = Some(id);
    Leaf::new(EntryKind::Conflict, store.put(&Object::Conflict(conflict))?)
}

fn is_text(bytes: &[u8]) -> bool {
    !bytes.contains(&0) && std::str::from_utf8(bytes).is_ok()
}

/// Every generated marker is longer than any literal marker run in its sides.
fn marker_width(store: &dyn Store, conflict: &Conflict) -> Result<usize> {
    let mut width = 7;
    for leaf in conflict
        .adds
        .iter()
        .chain(&conflict.removes)
        .flatten()
        .filter(|leaf| leaf.is_file_like())
    {
        let bytes = store.get_blob(&leaf.id())?;
        if !is_text(&bytes) {
            continue;
        }
        for line in bytes.split(|byte| *byte == b'\n') {
            if let Some(first) = line.first().filter(|byte| b"<>-+".contains(byte)) {
                width = width.max(line.iter().take_while(|byte| *byte == first).count() + 1);
            }
        }
    }
    Ok(width)
}
