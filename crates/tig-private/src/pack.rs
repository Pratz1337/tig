//! One sealed pack for a single remote, group, epoch and publish.
//!
//! The file is magic `TIGP`, version 1, the remote id, a length-prefixed
//! group, the epoch, a random 24-byte index nonce, the length-prefixed index
//! ciphertext, then each object as `wire_id || length-prefixed ciphertext`.
//! The index plaintext is encrypted by [`EpochKey::encrypt_index`]. Plain
//! object ids and names stay inside that ciphertext. See DESIGN.md
//! "Sealed packs".
//!
//! Decoders bound every length and count by the bytes still unread, and
//! reject a non-canonical varint or trailing bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use tig_core::encode::{Reader, Writer};
use tig_core::seal::SealedId;
use tig_core::{EntryKind, ObjectId, ObjectKind, RepoPath};

use crate::keys::{EpochKey, KeyError, WireId};

const MAGIC: &[u8; 4] = b"TIGP";
const PACK_VERSION: u8 = 1;
const INDEX_VERSION: u8 = 1;
/// One object's ciphertext, or the index ciphertext.
const MAX_BYTES: usize = 256 * 1024 * 1024;
const MAX_OBJECTS: usize = 1_000_000;
const MAX_GROUP: usize = 1024;
const MAX_PATH: usize = 64 * 1024;
/// `wire_id || kind || object_id`.
const MIN_INDEX_OBJECT: usize = 32 + 1 + 32;
/// One row of the pack index: wire id, kind, and the plain object id.
type IndexObject = (WireId, ObjectKind, ObjectId);
/// `sealed_id || empty path || kind || target`.
const MIN_SEALED: usize = 32 + 1 + 1 + 32;
/// `wire_id || empty ciphertext length`.
const MIN_FILE_OBJECT: usize = 32 + 1;

#[derive(Debug, thiserror::Error)]
pub enum PackError {
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Core(#[from] tig_core::Error),
    #[error("pack was sealed for a different remote, group, or epoch")]
    ContextMismatch,
    #[error("pack is invalid: {0}")]
    Invalid(String),
}

/// A sealed root carried in the pack index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRecord {
    pub sealed_id: SealedId,
    pub path: RepoPath,
    pub kind: EntryKind,
    /// Internal id the sealed entry stands in for.
    pub target: ObjectId,
}

/// What [`Pack::peek_header`] can see without a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackHeader {
    pub remote: [u8; 16],
    pub group: String,
    pub epoch: u64,
    pub wire_ids: Vec<WireId>,
}

/// Objects and sealed roots from a pack opened with the right epoch key.
pub struct OpenedPack {
    pub objects: Vec<(ObjectKind, ObjectId, zeroize::Zeroizing<Vec<u8>>)>,
    pub sealed: Vec<SealedRecord>,
}

impl fmt::Debug for OpenedPack {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Plaintext bodies are secrets. Lengths are enough to tell records apart.
        let objects: Vec<_> = self
            .objects
            .iter()
            .map(|(kind, id, body)| (*kind, *id, body.len()))
            .collect();
        f.debug_struct("OpenedPack")
            .field("objects", &objects)
            .field("sealed", &self.sealed)
            .finish()
    }
}

/// Builds one pack under a single epoch key.
pub struct PackBuilder<'a> {
    key: &'a EpochKey,
    objects: BTreeMap<WireId, StoredObject>,
    sealed: Vec<SealedRecord>,
}

struct StoredObject {
    kind: ObjectKind,
    id: ObjectId,
    ciphertext: Vec<u8>,
}

impl<'a> PackBuilder<'a> {
    pub fn new(key: &'a EpochKey) -> Self {
        PackBuilder {
            key,
            objects: BTreeMap::new(),
            sealed: Vec::new(),
        }
    }

    /// Adds an object. The same `(kind, id, body)` again is ignored. A
    /// different object that lands on the same wire id is refused.
    pub fn add_object(
        &mut self,
        kind: ObjectKind,
        id: ObjectId,
        body: &[u8],
    ) -> Result<(), PackError> {
        if body.len() > MAX_BYTES {
            return Err(PackError::Invalid("object is too large".into()));
        }
        let ciphertext = self.key.encrypt_object(kind, &id, body)?;
        let wire = self.key.wire_id(&id);
        if let Some(existing) = self.objects.get(&wire) {
            if existing.kind == kind && existing.id == id {
                return Ok(());
            }
            return Err(PackError::Invalid("wire id collision".into()));
        }
        if self.objects.len() >= MAX_OBJECTS {
            return Err(PackError::Invalid("too many objects".into()));
        }
        self.objects.insert(
            wire,
            StoredObject {
                kind,
                id,
                ciphertext,
            },
        );
        Ok(())
    }

    /// Records one sealed root. Checked when the pack is opened, not here,
    /// so a bad record is a pack the reader refuses.
    pub fn add_sealed(
        &mut self,
        sealed_id: SealedId,
        path: RepoPath,
        kind: EntryKind,
        target: ObjectId,
    ) -> Result<(), PackError> {
        if path.as_str().len() > MAX_PATH {
            return Err(PackError::Invalid("sealed path is too long".into()));
        }
        if self.sealed.len() >= MAX_OBJECTS {
            return Err(PackError::Invalid("too many sealed records".into()));
        }
        self.sealed.push(SealedRecord {
            sealed_id,
            path,
            kind,
            target,
        });
        Ok(())
    }

    pub fn finish(self) -> Result<Vec<u8>, PackError> {
        let ctx = self.key.context();
        if ctx.group.len() > MAX_GROUP {
            return Err(PackError::Invalid("group name is too long".into()));
        }
        let listed: Vec<IndexObject> = self
            .objects
            .iter()
            .map(|(wire, object)| (*wire, object.kind, object.id))
            .collect();
        let index = encode_index(&listed, &self.sealed)?;
        if index.len() > MAX_BYTES {
            return Err(PackError::Invalid("index is too large".into()));
        }
        let mut header = Vec::with_capacity(4 + 1 + 16 + ctx.group.len() + 16);
        header.extend_from_slice(MAGIC);
        header.push(PACK_VERSION);
        header.extend_from_slice(&ctx.remote);
        let mut group_epoch = Writer::new();
        group_epoch.str(&ctx.group);
        group_epoch.varint(ctx.epoch);
        header.extend_from_slice(&group_epoch.finish());

        let (nonce, index_ct) = self.key.encrypt_index(&index, &header)?;
        let mut out = header;
        out.extend_from_slice(&nonce);
        let mut rest = Writer::new();
        rest.bytes(&index_ct);
        rest.varint(self.objects.len() as u64);
        // Same BTree order as the index, so the two lists name the same objects.
        for (wire, object) in &self.objects {
            rest.buf.extend_from_slice(&wire.0);
            rest.bytes(&object.ciphertext);
        }
        out.extend_from_slice(&rest.finish());
        Ok(out)
    }
}

/// Opening and inspecting a sealed pack.
pub struct Pack;

impl Pack {
    /// Remote, group, epoch and wire ids. Does not decrypt.
    pub fn peek_header(bytes: &[u8]) -> Result<PackHeader, PackError> {
        let parsed = parse(bytes)?;
        Ok(PackHeader {
            remote: parsed.remote,
            group: parsed.group,
            epoch: parsed.epoch,
            wire_ids: parsed.objects.into_iter().map(|(wire, _)| wire).collect(),
        })
    }

    /// Decrypts the index and every object, and checks each sealed record.
    pub fn open(bytes: &[u8], key: &EpochKey) -> Result<OpenedPack, PackError> {
        let parsed = parse(bytes)?;
        let ctx = key.context();
        if parsed.remote != ctx.remote || parsed.group != ctx.group || parsed.epoch != ctx.epoch {
            return Err(PackError::ContextMismatch);
        }
        let header = &bytes[..parsed.prefix_end];
        let index_ct = &bytes[parsed.index_ct.0..parsed.index_ct.1];
        let plain = key.decrypt_index(&parsed.nonce, index_ct, header)?;
        let (index_objects, sealed) = decode_index(&plain)?;

        let mut file: BTreeMap<WireId, (usize, usize)> = BTreeMap::new();
        for (wire, range) in parsed.objects {
            // `parse` already rejected a repeated wire id.
            file.insert(wire, range);
        }
        let index_wires: BTreeSet<WireId> =
            index_objects.iter().map(|(wire, _, _)| *wire).collect();
        let extra = file.keys().any(|wire| !index_wires.contains(wire));
        let missing = index_wires.iter().any(|wire| !file.contains_key(wire));
        if extra {
            return Err(PackError::Invalid("extra wire id".into()));
        }
        if missing {
            return Err(PackError::Invalid("missing wire id".into()));
        }

        let mut objects = Vec::with_capacity(index_objects.len());
        for (wire, kind, id) in index_objects {
            if key.wire_id(&id) != wire {
                return Err(PackError::Invalid(
                    "wire id does not match object id".into(),
                ));
            }
            let range = file[&wire];
            let body = key.decrypt_object(kind, &id, &bytes[range.0..range.1])?;
            objects.push((kind, id, body));
        }
        for record in &sealed {
            let salt = key.seal_salt(&record.path, record.kind, &record.target);
            if !record.sealed_id.verify(&salt, record.kind, &record.target) {
                return Err(PackError::Invalid("sealed record does not verify".into()));
            }
        }
        Ok(OpenedPack { objects, sealed })
    }
}

struct Parsed {
    remote: [u8; 16],
    group: String,
    epoch: u64,
    /// Index of the first nonce byte. `bytes[..prefix_end]` is the header
    /// prefix [`EpochKey::encrypt_index`] binds, before the nonce.
    prefix_end: usize,
    nonce: [u8; 24],
    index_ct: (usize, usize),
    objects: Vec<(WireId, (usize, usize))>,
}

fn parse(bytes: &[u8]) -> Result<Parsed, PackError> {
    let mut c = Cursor::new(bytes);
    let magic = c.array::<4>()?;
    if &magic != MAGIC {
        return Err(c.err("bad magic"));
    }
    let version = c.u8()?;
    if version != PACK_VERSION {
        return Err(PackError::Invalid(format!(
            "unsupported pack version {version}"
        )));
    }
    let remote = c.array::<16>()?;
    let group = c.str_limited(MAX_GROUP)?;
    let epoch = c.varint()?;
    let prefix_end = c.pos;
    let nonce = c.array::<24>()?;
    let index_ct = c.bytes_range(MAX_BYTES)?;
    let n = c.count(MIN_FILE_OBJECT, MAX_OBJECTS)?;
    let mut objects = Vec::with_capacity(n);
    let mut seen = BTreeSet::new();
    for _ in 0..n {
        let wire = c.array::<32>()?;
        if !seen.insert(wire) {
            return Err(PackError::Invalid("duplicate wire id".into()));
        }
        let ct = c.bytes_range(MAX_BYTES)?;
        objects.push((WireId(wire), ct));
    }
    c.finish()?;
    Ok(Parsed {
        remote,
        group,
        epoch,
        prefix_end,
        nonce,
        index_ct,
        objects,
    })
}

fn encode_index(objects: &[IndexObject], sealed: &[SealedRecord]) -> Result<Vec<u8>, PackError> {
    let mut w = Writer::new();
    w.u8(INDEX_VERSION);
    w.varint(objects.len() as u64);
    for (wire, kind, id) in objects {
        w.buf.extend_from_slice(&wire.0);
        w.u8(*kind as u8);
        w.id(id);
    }
    w.varint(sealed.len() as u64);
    for record in sealed {
        w.buf.extend_from_slice(record.sealed_id.as_bytes());
        w.str(record.path.as_str());
        w.u8(record.kind as u8);
        w.id(&record.target);
    }
    Ok(w.finish())
}

fn decode_index(bytes: &[u8]) -> Result<(Vec<IndexObject>, Vec<SealedRecord>), PackError> {
    let mut r = Reader::new(bytes, "pack index");
    let version = r.u8()?;
    if version != INDEX_VERSION {
        return Err(PackError::Invalid(format!(
            "unsupported index version {version}"
        )));
    }
    let n = r.count(MIN_INDEX_OBJECT)?;
    if n > MAX_OBJECTS {
        return Err(PackError::Invalid("too many objects in the index".into()));
    }
    let mut objects = Vec::with_capacity(n);
    let mut seen = BTreeSet::new();
    for _ in 0..n {
        let mut wire = [0u8; 32];
        wire.copy_from_slice(r.take(32)?);
        if !seen.insert(wire) {
            return Err(PackError::Invalid("duplicate wire id in the index".into()));
        }
        let kind = ObjectKind::from_u8(r.u8()?)?;
        let id = r.id()?;
        objects.push((WireId(wire), kind, id));
    }
    let n = r.count(MIN_SEALED)?;
    if n > MAX_OBJECTS {
        return Err(PackError::Invalid("too many sealed records".into()));
    }
    let mut sealed = Vec::with_capacity(n);
    for _ in 0..n {
        let mut sid = [0u8; 32];
        sid.copy_from_slice(r.take(32)?);
        let path_str = r.str()?;
        if path_str.len() > MAX_PATH {
            return Err(PackError::Invalid("sealed path is too long".into()));
        }
        let path = RepoPath::new(path_str)?;
        let kind = entry_kind(r.u8()?)?;
        let target = r.id()?;
        sealed.push(SealedRecord {
            sealed_id: load_sealed_id(&sid)?,
            path,
            kind,
            target,
        });
    }
    r.finish()?;
    Ok((objects, sealed))
}

fn entry_kind(byte: u8) -> Result<EntryKind, PackError> {
    EntryKind::from_u8(byte).map_err(|_| PackError::Invalid(format!("unknown entry kind {byte}")))
}

fn load_sealed_id(bytes: &[u8; 32]) -> Result<SealedId, PackError> {
    Ok(SealedId::from_stored(*bytes))
}

/// Byte cursor with the same varint rules as [`Reader`]: minimal encodings
/// only, and a length that does not fit in the unread bytes is an error
/// before any allocation.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn err(&self, reason: &str) -> PackError {
        PackError::Invalid(format!("{reason} at byte {}", self.pos))
    }

    fn u8(&mut self) -> Result<u8, PackError> {
        if self.pos >= self.buf.len() {
            return Err(self.err("unexpected end"));
        }
        let byte = self.buf[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    fn take(&mut self, n: usize) -> Result<(), PackError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| self.err("unexpected end"))?;
        if end > self.buf.len() {
            return Err(self.err("unexpected end"));
        }
        self.pos = end;
        Ok(())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], PackError> {
        let start = self.pos;
        self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[start..self.pos]);
        Ok(out)
    }

    fn varint(&mut self) -> Result<u64, PackError> {
        let mut v: u64 = 0;
        for shift in (0..64).step_by(7) {
            let byte = self.u8()?;
            let part = (byte & 0x7f) as u64;
            if shift == 63 && part > 1 {
                return Err(self.err("varint overflow"));
            }
            v |= part << shift;
            if byte & 0x80 == 0 {
                if byte == 0 && shift != 0 {
                    return Err(self.err("non-minimal varint"));
                }
                return Ok(v);
            }
        }
        Err(self.err("varint too long"))
    }

    fn bytes_range(&mut self, max: usize) -> Result<(usize, usize), PackError> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| self.err("length too large"))?;
        if n > max {
            return Err(self.err("length exceeds limit"));
        }
        let start = self.pos;
        self.take(n)?;
        Ok((start, self.pos))
    }

    fn str_limited(&mut self, max: usize) -> Result<String, PackError> {
        let (start, end) = self.bytes_range(max)?;
        let text =
            std::str::from_utf8(&self.buf[start..end]).map_err(|_| self.err("invalid utf-8"))?;
        Ok(text.to_string())
    }

    fn count(&mut self, min_item: usize, max_count: usize) -> Result<usize, PackError> {
        let n = self.varint()?;
        let n = usize::try_from(n).map_err(|_| self.err("count too large"))?;
        if n > max_count {
            return Err(self.err("count exceeds limit"));
        }
        let unread = self.buf.len() - self.pos;
        if n.saturating_mul(min_item) > unread {
            return Err(self.err("list longer than input"));
        }
        Ok(n)
    }

    fn finish(&self) -> Result<(), PackError> {
        if self.pos != self.buf.len() {
            return Err(self.err("trailing bytes"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_kind_bytes_match_tig_core() {
        assert_eq!(EntryKind::File as u8, 1);
        assert_eq!(EntryKind::Executable as u8, 2);
        assert_eq!(EntryKind::Symlink as u8, 3);
        assert_eq!(EntryKind::Tree as u8, 4);
        assert_eq!(EntryKind::Sealed as u8, 5);
    }

    #[test]
    fn bad_magic_noncanonical_length_and_huge_count_are_refused() {
        assert!(Pack::peek_header(b"TIGX").is_err());
        let mut bad = Vec::from(&b"TIGP"[..]);
        bad.push(1);
        bad.extend_from_slice(&[7; 16]);
        bad.extend_from_slice(&[0x80, 0x00]);
        assert!(
            matches!(Pack::peek_header(&bad), Err(PackError::Invalid(ref reason)) if reason.contains("non-minimal"))
        );

        let mut huge = Vec::from(&b"TIGP"[..]);
        huge.push(1);
        huge.extend_from_slice(&[7; 16]);
        huge.push(1); // group length 1
        huge.push(b'a');
        huge.push(1); // epoch 1
        huge.extend_from_slice(&[0; 24]); // nonce
        huge.push(0); // empty index ciphertext
                      // count = 1_000_000, with no object bytes after it.
        let mut count = Writer::new();
        count.varint(1_000_000);
        huge.extend_from_slice(&count.finish());
        assert!(
            matches!(Pack::peek_header(&huge), Err(PackError::Invalid(ref reason)) if reason.contains("longer than input"))
        );
    }

    #[test]
    fn load_sealed_id_roundtrips_through_verify() {
        let salt = tig_core::seal::SealSalt::from_bytes([4; 32]);
        let target = ObjectId([6; 32]);
        let sid = SealedId::compute(&salt, EntryKind::File, &target);
        let loaded = load_sealed_id(sid.as_bytes()).unwrap();
        assert!(loaded.verify(&salt, EntryKind::File, &target));
        assert!(!loaded.verify(&salt, EntryKind::Tree, &target));
    }
}
