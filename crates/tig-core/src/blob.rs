//! Fixed-size chunked blobs.
//!
//! A file of at most [`CHUNK_LEN`] bytes is an ordinary `Blob` (kind 1). Its
//! id is `hash_object(Blob, bytes)`, the same id those bytes have always had.
//! A longer file is a `ChunkedBlob` (kind 7): a version-1 manifest that names
//! ordered `Blob` chunks. Every chunk except the last is exactly [`CHUNK_LEN`]
//! bytes. The split depends only on the byte stream, not on how `Read`
//! fragmented it.
//!
//! Tree entries keep `EntryKind::File`, `Executable`, and `Symlink`. The entry
//! id is either a blob or a chunked manifest.

use std::io::{Read, Write};

use crate::encode::{Reader, Writer};
use crate::error::{Error, Result};
use crate::id::ObjectId;
use crate::object::{hash_object, ObjectKind};
use crate::store::Store;

/// On-disk and in-memory chunk size. Also the largest ordinary blob.
pub const CHUNK_LEN: usize = 4 * 1024 * 1024;
/// 64 GiB. Manifests and `put` refuse anything larger.
pub const MAX_CHUNKS: usize = 16_384;
pub const MAX_CONTENT: u64 = CHUNK_LEN as u64 * MAX_CHUNKS as u64;
/// `get_blob` and other whole-buffer callers stop here. Stream past this.
pub const MAX_MATERIALIZE: u64 = 256 * 1024 * 1024;
const MANIFEST_VERSION: u8 = 1;

/// One chunk: the blob id and the length the manifest claims for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChunkRef {
    pub id: ObjectId,
    pub len: u32,
}

/// Version-1 chunk manifest. Lengths are the canonical split of `total`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChunkManifest {
    total: u64,
    chunks: Vec<ChunkRef>,
}

impl ChunkManifest {
    pub fn total(&self) -> u64 {
        self.total
    }

    pub fn chunks(&self) -> &[ChunkRef] {
        &self.chunks
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u8(MANIFEST_VERSION);
        w.varint(self.total);
        w.varint(self.chunks.len() as u64);
        for chunk in &self.chunks {
            w.id(&chunk.id);
            w.varint(u64::from(chunk.len));
        }
        w.finish()
    }

    pub fn id(&self) -> ObjectId {
        hash_object(ObjectKind::ChunkedBlob, &self.encode())
    }
}

/// Length of each chunk for `total` bytes. Refuses a size an ordinary blob
/// can represent (`total <= CHUNK_LEN`) and anything above [`MAX_CONTENT`].
pub fn canonical_lengths(total: u64) -> Result<Vec<u32>> {
    if total <= CHUNK_LEN as u64 {
        return Err(Error::Invalid(
            "file fits in one blob; a chunk manifest would be non-canonical".into(),
        ));
    }
    if total > MAX_CONTENT {
        return Err(Error::Invalid(format!(
            "file is {total} bytes; the limit is {MAX_CONTENT}"
        )));
    }
    let chunk = CHUNK_LEN as u64;
    let mut left = total;
    let mut lens = Vec::new();
    while left > 0 {
        let n = left.min(chunk) as u32;
        lens.push(n);
        left -= u64::from(n);
        if lens.len() > MAX_CHUNKS {
            return Err(Error::Invalid("too many chunks".into()));
        }
    }
    if lens.len() < 2 {
        return Err(Error::Invalid(
            "a chunk manifest needs at least two chunks".into(),
        ));
    }
    Ok(lens)
}

pub fn parse_manifest(body: &[u8]) -> Result<ChunkManifest> {
    let mut r = Reader::new(body, "chunk manifest");
    let version = r.u8()?;
    if version != MANIFEST_VERSION {
        return Err(Error::decode(
            "chunk manifest",
            format!("unsupported version {version}"),
        ));
    }
    let total = r.varint()?;
    let expected = canonical_lengths(total)?;
    let n = r.count(32)?;
    if n != expected.len() || n > MAX_CHUNKS {
        return Err(Error::decode(
            "chunk manifest",
            format!("chunk count {n} does not match the canonical split"),
        ));
    }
    let mut chunks = Vec::with_capacity(n);
    for want in expected {
        let id = r.id()?;
        let len = r.varint()?;
        if len != u64::from(want) || len == 0 || len > CHUNK_LEN as u64 {
            return Err(Error::decode(
                "chunk manifest",
                format!("chunk length {len} is not the canonical {want}"),
            ));
        }
        chunks.push(ChunkRef { id, len: want });
    }
    r.finish()?;
    let sum: u64 = chunks.iter().map(|chunk| u64::from(chunk.len)).sum();
    if sum != total {
        return Err(Error::decode(
            "chunk manifest",
            "chunk lengths do not add up to the total",
        ));
    }
    Ok(ChunkManifest { total, chunks })
}

fn manifest_of(chunks: Vec<ChunkRef>, total: u64) -> Result<ChunkManifest> {
    let manifest = ChunkManifest { total, chunks };
    // Re-parse so a builder cannot store a shape `parse_manifest` would reject.
    parse_manifest(&manifest.encode())
}

/// Stores `data`. At most [`CHUNK_LEN`] bytes stay a kind-1 blob.
pub fn put_bytes<S: Store + ?Sized>(store: &S, data: &[u8]) -> Result<ObjectId> {
    if data.len() as u64 <= CHUNK_LEN as u64 {
        return put_plain(store, data);
    }
    if data.len() as u64 > MAX_CONTENT {
        return Err(Error::Invalid(format!(
            "file is {} bytes; the limit is {MAX_CONTENT}",
            data.len()
        )));
    }
    let mut chunks = Vec::new();
    let mut offset = 0usize;
    while offset < data.len() {
        let end = (offset + CHUNK_LEN).min(data.len());
        let slice = &data[offset..end];
        chunks.push(ChunkRef {
            id: put_plain(store, slice)?,
            len: slice.len() as u32,
        });
        offset = end;
    }
    store_manifest(store, chunks, data.len() as u64)
}

/// Reads `reader` to completion and stores it. A read of 1 byte and a read of
/// the whole buffer produce the same id.
pub fn put_reader<S: Store + ?Sized>(store: &S, mut reader: impl Read) -> Result<ObjectId> {
    let mut buf = Vec::new();
    let mut chunks: Vec<ChunkRef> = Vec::new();
    // A file of exactly one chunk is a plain blob. Hold that id until another
    // byte arrives so the manifest is never written for it.
    let mut held: Option<ObjectId> = None;
    let mut total: u64 = 0;
    loop {
        fill_chunk(&mut reader, &mut buf)?;
        if buf.is_empty() {
            break;
        }
        let full = buf.len() == CHUNK_LEN;
        let len = buf.len() as u32;
        total = total
            .checked_add(u64::from(len))
            .filter(|total| *total <= MAX_CONTENT)
            .ok_or_else(|| Error::Invalid(format!("file is larger than {MAX_CONTENT} bytes")))?;
        if held.is_none() && !full {
            return put_plain(store, &buf);
        }
        let id = put_plain(store, &buf)?;
        buf.clear();
        if held.is_none() {
            held = Some(id);
            continue;
        }
        if chunks.is_empty() {
            chunks.push(ChunkRef {
                id: held.expect("held chunk"),
                len: CHUNK_LEN as u32,
            });
        }
        chunks.push(ChunkRef { id, len });
        if !full {
            break;
        }
    }
    if chunks.is_empty() {
        return match held {
            Some(id) => Ok(id),
            None => put_plain(store, b""),
        };
    }
    store_manifest(store, chunks, total)
}

fn fill_chunk(reader: &mut impl Read, buf: &mut Vec<u8>) -> Result<()> {
    buf.resize(CHUNK_LEN, 0);
    let mut filled = 0;
    while filled < CHUNK_LEN {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                buf.truncate(filled);
                return Ok(());
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn put_plain<S: Store + ?Sized>(store: &S, data: &[u8]) -> Result<ObjectId> {
    let id = hash_object(ObjectKind::Blob, data);
    if !store.has(&id)? {
        store.put_raw(&id, ObjectKind::Blob, data)?;
    }
    Ok(id)
}

fn store_manifest<S: Store + ?Sized>(
    store: &S,
    chunks: Vec<ChunkRef>,
    total: u64,
) -> Result<ObjectId> {
    let manifest = manifest_of(chunks, total)?;
    let body = manifest.encode();
    let id = hash_object(ObjectKind::ChunkedBlob, &body);
    if !store.has(&id)? {
        store.put_raw(&id, ObjectKind::ChunkedBlob, &body)?;
    }
    Ok(id)
}

/// Whole bytes for callers that already hold a buffer. Refuses content above
/// [`MAX_MATERIALIZE`].
pub fn materialize<S: Store + ?Sized>(store: &S, id: &ObjectId) -> Result<Vec<u8>> {
    let len = content_len(store, id)?;
    if len > MAX_MATERIALIZE {
        return Err(Error::Invalid(format!(
            "object {id} is {len} bytes; stream it instead of loading it"
        )));
    }
    let mut out = Vec::with_capacity(len as usize);
    write_content(store, id, &mut out)?;
    Ok(out)
}

pub fn content_len<S: Store + ?Sized>(store: &S, id: &ObjectId) -> Result<u64> {
    let (kind, body) = load(store, id)?;
    match kind {
        ObjectKind::Blob => Ok(body.len() as u64),
        ObjectKind::ChunkedBlob => Ok(parse_manifest(&body)?.total()),
        other => Err(Error::WrongKind {
            expected: "blob",
            found: other.name(),
        }),
    }
}

/// Writes the file bytes of a blob or a chunked blob. One chunk is in memory
/// at a time.
pub fn write_content<S: Store + ?Sized>(
    store: &S,
    id: &ObjectId,
    mut out: impl Write,
) -> Result<u64> {
    let (kind, body) = load(store, id)?;
    match kind {
        ObjectKind::Blob => {
            out.write_all(&body)?;
            Ok(body.len() as u64)
        }
        ObjectKind::ChunkedBlob => {
            let manifest = parse_manifest(&body)?;
            let mut written = 0u64;
            for chunk in manifest.chunks() {
                let bytes = load_chunk(store, id, chunk)?;
                out.write_all(&bytes)?;
                written += bytes.len() as u64;
            }
            if written != manifest.total() {
                return Err(corrupt(
                    *id,
                    "chunk lengths do not add up to the manifest total",
                ));
            }
            Ok(written)
        }
        other => Err(Error::WrongKind {
            expected: "blob",
            found: other.name(),
        }),
    }
}

/// A content reader that holds at most one chunk for chunked files.
pub struct ContentReader<'a, S: Store + ?Sized> {
    store: &'a S,
    id: ObjectId,
    chunks: std::vec::IntoIter<ChunkRef>,
    current: std::io::Cursor<Vec<u8>>,
    len: u64,
}

impl<'a, S: Store + ?Sized> ContentReader<'a, S> {
    pub fn new(store: &'a S, id: &ObjectId) -> Result<Self> {
        let (kind, body) = load(store, id)?;
        let (len, chunks, current) = match kind {
            ObjectKind::Blob => (body.len() as u64, Vec::new(), body),
            ObjectKind::ChunkedBlob => {
                let manifest = parse_manifest(&body)?;
                (manifest.total, manifest.chunks, Vec::new())
            }
            other => {
                return Err(Error::WrongKind {
                    expected: "blob",
                    found: other.name(),
                })
            }
        };
        Ok(Self {
            store,
            id: *id,
            chunks: chunks.into_iter(),
            current: std::io::Cursor::new(current),
            len,
        })
    }

    pub fn content_len(&self) -> u64 {
        self.len
    }
}

impl<S: Store + ?Sized> Read for ContentReader<'_, S> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        loop {
            let n = self.current.read(out)?;
            if n != 0 {
                return Ok(n);
            }
            let Some(chunk) = self.chunks.next() else {
                return Ok(0);
            };
            // Release the old chunk before allocating its successor.
            self.current = std::io::Cursor::new(Vec::new());
            let bytes = load_chunk(self.store, &self.id, &chunk).map_err(std::io::Error::other)?;
            self.current = std::io::Cursor::new(bytes);
        }
    }
}

/// True when `reader` is exactly the stored file. The reader is consumed.
/// BLAKE3 of the file bytes, not the object id. Two different object ids can
/// name the same bytes when one is a legacy single blob and the other is chunked.
pub fn content_hash<S: Store + ?Sized>(store: &S, id: &ObjectId) -> Result<blake3::Hash> {
    let mut hasher = blake3::Hasher::new();
    write_content(store, id, HashSink(&mut hasher))?;
    Ok(hasher.finalize())
}

struct HashSink<'a>(&'a mut blake3::Hasher);

impl Write for HashSink<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// True when `reader` is exactly the stored file. The reader is consumed.
pub fn matches_reader<S: Store + ?Sized>(
    store: &S,
    id: &ObjectId,
    mut reader: impl Read,
) -> Result<bool> {
    let (kind, body) = match store.get_raw(id)? {
        Some(found) => found,
        None => return Ok(false),
    };
    if hash_object(kind, &body) != *id {
        return Err(corrupt(*id, "body hash does not match id"));
    }
    match kind {
        ObjectKind::Blob => Ok(hash_reader(ObjectKind::Blob, &mut reader)? == *id
            && hash_object(ObjectKind::Blob, &body) == *id),
        ObjectKind::ChunkedBlob => {
            let manifest = parse_manifest(&body)?;
            let mut scratch = Vec::new();
            for chunk in manifest.chunks() {
                scratch.clear();
                take_exact(&mut reader, chunk.len as usize, &mut scratch)?;
                if scratch.len() != chunk.len as usize {
                    return Ok(false);
                }
                if hash_object(ObjectKind::Blob, &scratch) != chunk.id {
                    return Ok(false);
                }
                let stored = load_chunk(store, id, chunk)?;
                if stored.as_slice() != scratch.as_slice() {
                    return Ok(false);
                }
            }
            let mut extra = [0u8; 1];
            Ok(reader.read(&mut extra)? == 0)
        }
        _ => Ok(false),
    }
}

fn take_exact(reader: &mut impl Read, n: usize, out: &mut Vec<u8>) -> Result<()> {
    out.resize(n, 0);
    let mut filled = 0;
    while filled < n {
        match reader.read(&mut out[filled..]) {
            Ok(0) => {
                out.truncate(filled);
                return Ok(());
            }
            Ok(got) => filled += got,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn hash_reader(kind: ObjectKind, reader: &mut impl Read) -> Result<ObjectId> {
    let mut hasher = blake3::Hasher::new_derive_key(crate::domain::OBJECT_ID);
    hasher.update(&[kind as u8]);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut buf) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(ObjectId(*hasher.finalize().as_bytes()))
}

fn load_chunk<S: Store + ?Sized>(
    store: &S,
    manifest_id: &ObjectId,
    chunk: &ChunkRef,
) -> Result<Vec<u8>> {
    let (kind, body) = store.get_raw(&chunk.id)?.ok_or(Error::NotFound(chunk.id))?;
    if kind != ObjectKind::Blob {
        return Err(corrupt(
            *manifest_id,
            format!("chunk {} is a {}, not a blob", chunk.id, kind.name()),
        ));
    }
    if body.len() != chunk.len as usize || hash_object(ObjectKind::Blob, &body) != chunk.id {
        return Err(corrupt(
            *manifest_id,
            format!(
                "chunk {} is {} bytes; the manifest says {}",
                chunk.id,
                body.len(),
                chunk.len
            ),
        ));
    }
    Ok(body)
}

fn load<S: Store + ?Sized>(store: &S, id: &ObjectId) -> Result<(ObjectKind, Vec<u8>)> {
    let (kind, body) = store.get_raw(id)?.ok_or(Error::NotFound(*id))?;
    if kind == ObjectKind::ChunkedBlob {
        parse_manifest(&body)?;
    }
    if hash_object(kind, &body) != *id {
        return Err(corrupt(*id, "body hash does not match id"));
    }
    Ok((kind, body))
}

fn corrupt(id: ObjectId, reason: impl Into<String>) -> Error {
    Error::Corrupt {
        id,
        reason: reason.into(),
    }
}

/// Blob id, or each chunk id and then the manifest id. Children come first
/// so a publisher can store them before the manifest that names them.
pub fn content_objects<S: Store + ?Sized>(
    store: &S,
    id: &ObjectId,
) -> Result<Vec<(ObjectKind, ObjectId)>> {
    let (kind, body) = load(store, id)?;
    match kind {
        ObjectKind::Blob => Ok(vec![(ObjectKind::Blob, *id)]),
        ObjectKind::ChunkedBlob => {
            let manifest = parse_manifest(&body)?;
            for chunk in manifest.chunks() {
                let _ = load_chunk(store, id, chunk)?;
            }
            let mut out: Vec<_> = manifest
                .chunks()
                .iter()
                .map(|chunk| (ObjectKind::Blob, chunk.id))
                .collect();
            out.push((ObjectKind::ChunkedBlob, *id));
            Ok(out)
        }
        other => Err(Error::WrongKind {
            expected: "blob",
            found: other.name(),
        }),
    }
}

/// Same ids as [`content_objects`], without the kinds.
pub fn content_ids<S: Store + ?Sized>(store: &S, id: &ObjectId) -> Result<Vec<ObjectId>> {
    Ok(content_objects(store, id)?
        .into_iter()
        .map(|(_, id)| id)
        .collect())
}

/// Chunk ids named by a manifest body. Empty for a plain blob. Used when the
/// object has been fetched but its chunks have not.
pub fn linked_ids(kind: ObjectKind, body: &[u8]) -> Result<Vec<ObjectId>> {
    match kind {
        ObjectKind::Blob => Ok(Vec::new()),
        ObjectKind::ChunkedBlob => Ok(parse_manifest(body)?
            .chunks()
            .iter()
            .map(|chunk| chunk.id)
            .collect()),
        other => Err(Error::WrongKind {
            expected: "blob",
            found: other.name(),
        }),
    }
}

/// Pushes every object in the content closure. `push` receives borrowed
/// bodies and may map the error with `?` via `From<Error>` at the call site.
pub fn for_each_content<S, E>(
    store: &S,
    id: &ObjectId,
    mut push: impl FnMut(ObjectKind, ObjectId, &[u8]) -> std::result::Result<(), E>,
) -> std::result::Result<(), E>
where
    S: Store + ?Sized,
    E: From<Error>,
{
    let (kind, body) = load(store, id)?;
    match kind {
        ObjectKind::Blob => push(ObjectKind::Blob, *id, &body),
        ObjectKind::ChunkedBlob => {
            let manifest = parse_manifest(&body)?;
            for chunk in manifest.chunks() {
                let bytes = load_chunk(store, id, chunk)?;
                push(ObjectKind::Blob, chunk.id, &bytes)?;
            }
            push(ObjectKind::ChunkedBlob, *id, &body)
        }
        other => Err(Error::WrongKind {
            expected: "blob",
            found: other.name(),
        }
        .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::Object;
    use crate::store::MemoryStore;
    use std::io::Cursor;

    struct Pieces<'a> {
        data: &'a [u8],
        step: usize,
        flip: bool,
    }

    impl Read for Pieces<'_> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if self.data.is_empty() || buf.is_empty() {
                return Ok(0);
            }
            self.flip = !self.flip;
            let n = if self.flip {
                1
            } else {
                self.step.clamp(1, 3)
            };
            let n = n.min(buf.len()).min(self.data.len());
            buf[..n].copy_from_slice(&self.data[..n]);
            self.data = &self.data[n..];
            Ok(n)
        }
    }

    #[test]
    fn small_files_keep_blob_ids() {
        let store = MemoryStore::new();
        let id = put_bytes(&store, b"hello\n").unwrap();
        assert_eq!(id, hash_object(ObjectKind::Blob, b"hello\n"));
        assert_eq!(store.kind(&id).unwrap(), Some(ObjectKind::Blob));
        assert_eq!(materialize(&store, &id).unwrap(), b"hello\n");
        let empty = put_reader(&store, Cursor::new([])).unwrap();
        assert_eq!(empty, hash_object(ObjectKind::Blob, b""));
    }

    #[test]
    fn exact_chunk_is_still_one_blob() {
        let data = vec![7u8; CHUNK_LEN];
        let store = MemoryStore::new();
        let id = put_bytes(&store, &data).unwrap();
        assert_eq!(id, hash_object(ObjectKind::Blob, &data));
        assert_eq!(
            put_reader(
                &store,
                Pieces {
                    data: &data,
                    step: 2,
                    flip: false
                }
            )
            .unwrap(),
            id
        );
    }

    #[test]
    fn fragmented_reader_matches_contiguous_bytes() {
        let mut data = vec![9u8; CHUNK_LEN + 17];
        data[CHUNK_LEN] = 1;
        data[CHUNK_LEN + 16] = 2;
        let store = MemoryStore::new();
        let from_slice = put_bytes(&store, &data).unwrap();
        let from_reader = put_reader(
            &store,
            Pieces {
                data: &data,
                step: 2,
                flip: true,
            },
        )
        .unwrap();
        assert_eq!(from_slice, from_reader);
        assert_eq!(
            store.kind(&from_slice).unwrap(),
            Some(ObjectKind::ChunkedBlob)
        );
        let manifest = parse_manifest(&store.get_raw(&from_slice).unwrap().unwrap().1).unwrap();
        assert_eq!(manifest.total(), data.len() as u64);
        assert_eq!(
            manifest
                .chunks()
                .iter()
                .map(|chunk| chunk.len)
                .collect::<Vec<_>>(),
            vec![CHUNK_LEN as u32, 17]
        );
        assert_eq!(materialize(&store, &from_slice).unwrap(), data);
        assert!(matches_reader(&store, &from_slice, Cursor::new(data.clone())).unwrap());
        assert!(
            !matches_reader(&store, &from_slice, Cursor::new(&data[..data.len() - 1])).unwrap()
        );
    }

    #[test]
    fn corrupt_manifests_are_rejected() {
        let id = ObjectId([4; 32]);
        let mut empty = Writer::new();
        empty.u8(1);
        empty.varint(CHUNK_LEN as u64 + 1);
        empty.varint(0);
        assert!(parse_manifest(&empty.finish()).is_err());

        let mut one = Writer::new();
        one.u8(1);
        one.varint(CHUNK_LEN as u64);
        one.varint(1);
        one.id(&id);
        one.varint(CHUNK_LEN as u64);
        assert!(parse_manifest(&one.finish()).is_err());

        let mut bad_len = Writer::new();
        bad_len.u8(1);
        bad_len.varint(CHUNK_LEN as u64 + 1);
        bad_len.varint(2);
        bad_len.id(&id);
        bad_len.varint(CHUNK_LEN as u64 - 1);
        bad_len.id(&id);
        bad_len.varint(2);
        assert!(parse_manifest(&bad_len.finish()).is_err());

        let mut version = Writer::new();
        version.u8(2);
        version.varint(1);
        assert!(parse_manifest(&version.finish()).is_err());

        let good = parse_manifest(&{
            let mut w = Writer::new();
            w.u8(1);
            w.varint(CHUNK_LEN as u64 + 1);
            w.varint(2);
            w.id(&id);
            w.varint(CHUNK_LEN as u64);
            w.id(&ObjectId([5; 32]));
            w.varint(1);
            w.finish()
        })
        .unwrap();
        let mut trailed = good.encode();
        trailed.push(0);
        assert!(parse_manifest(&trailed).is_err());

        assert!(canonical_lengths(MAX_CONTENT + 1).is_err());
        assert_eq!(
            Object::decode(ObjectKind::ChunkedBlob, &good.encode())
                .unwrap()
                .encode_body(),
            good.encode()
        );
    }

    #[test]
    fn missing_wrong_kind_and_short_chunks_fail() {
        let store = MemoryStore::new();
        let full = vec![3u8; CHUNK_LEN];
        let chunk = put_plain(&store, &full).unwrap();
        let missing = ObjectId([8; 32]);
        let manifest = manifest_of(
            vec![
                ChunkRef {
                    id: chunk,
                    len: CHUNK_LEN as u32,
                },
                ChunkRef {
                    id: missing,
                    len: 1,
                },
            ],
            CHUNK_LEN as u64 + 1,
        )
        .unwrap();
        let id = manifest.id();
        store
            .put_raw(&id, ObjectKind::ChunkedBlob, &manifest.encode())
            .unwrap();
        assert!(matches!(materialize(&store, &id), Err(Error::NotFound(got)) if got == missing));

        let tree = crate::object::Tree::empty().encode();
        let tree_id = hash_object(ObjectKind::Tree, &tree);
        store.put_raw(&tree_id, ObjectKind::Tree, &tree).unwrap();
        let bad_kind = manifest_of(
            vec![
                ChunkRef {
                    id: chunk,
                    len: CHUNK_LEN as u32,
                },
                ChunkRef {
                    id: tree_id,
                    len: 1,
                },
            ],
            CHUNK_LEN as u64 + 1,
        )
        .unwrap();
        let bad_id = bad_kind.id();
        store
            .put_raw(&bad_id, ObjectKind::ChunkedBlob, &bad_kind.encode())
            .unwrap();
        assert!(matches!(
            materialize(&store, &bad_id),
            Err(Error::Corrupt { .. })
        ));

        let lie = manifest_of(
            vec![
                ChunkRef {
                    id: chunk,
                    len: CHUNK_LEN as u32,
                },
                ChunkRef { id: chunk, len: 1 },
            ],
            CHUNK_LEN as u64 + 1,
        )
        .unwrap();
        let lie_id = lie.id();
        store
            .put_raw(&lie_id, ObjectKind::ChunkedBlob, &lie.encode())
            .unwrap();
        assert!(matches!(
            materialize(&store, &lie_id),
            Err(Error::Corrupt { .. })
        ));
    }
}
