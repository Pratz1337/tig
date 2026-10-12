//! Binary bodies for `/v1/...`. Every body is `tig_core::encode` (varints and
//! length-prefixed bytes) except pack downloads and pack uploads, which are
//! the pack file itself, and the nonce, which is 56 raw bytes (see auth.rs).
//!
//! Only public object kinds (blob, tree, revision) cross the wire, in either
//! direction. A `get` response is `varint answered || objects`: it covers the
//! first `answered` requested ids (at least one), so the client asks again for
//! the rest. That keeps each response near `OBJECTS_RESPONSE_TARGET`.
//!
//! Head bodies use a flag byte per file: `0` means absent on read and
//! "leave unchanged" on write. `1` is followed by length-prefixed bytes.
//! There is no delete.

use tig_core::encode::{Reader, Writer};
use tig_core::{ObjectId, ObjectKind};

use crate::limits::{
    MAX_HEAD_HTTP, MAX_ID_BATCH, MAX_KEYRING_FILE, MAX_MANIFEST_FILE, MAX_OBJECTS_HTTP,
    MAX_OBJECT_BATCH, MAX_OBJECT_BODY,
};

// Version 2 adds authenticated stateless nonces, signed If-Match and the
// answered-prefix framing for object downloads.
pub(crate) const PROTOCOL_VERSION: u8 = 2;

pub(crate) fn encode_info(remote_id: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    out.push(PROTOCOL_VERSION);
    out.extend_from_slice(remote_id);
    out
}

pub(crate) fn decode_info(bytes: &[u8]) -> Result<[u8; 16], String> {
    if bytes.len() != 17 {
        return Err("info body must be 17 bytes".into());
    }
    if bytes[0] != PROTOCOL_VERSION {
        return Err(format!("unsupported protocol version {}", bytes[0]));
    }
    let mut id = [0u8; 16];
    id.copy_from_slice(&bytes[1..]);
    Ok(id)
}

pub(crate) fn encode_ids(ids: &[ObjectId]) -> Result<Vec<u8>, String> {
    if ids.len() > MAX_ID_BATCH {
        return Err("too many ids".into());
    }
    let mut w = Writer::new();
    w.varint(ids.len() as u64);
    for id in ids {
        w.id(id);
    }
    Ok(w.finish())
}

pub(crate) fn decode_ids(bytes: &[u8], max: usize) -> Result<Vec<ObjectId>, String> {
    let mut r = Reader::new(bytes, "id list");
    let n = r.count(32).map_err(|e| e.to_string())?;
    if n > max {
        return Err("too many ids".into());
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(r.id().map_err(|e| e.to_string())?);
    }
    r.finish().map_err(|e| e.to_string())?;
    Ok(out)
}

pub(crate) fn encode_objects(objects: &[(ObjectId, ObjectKind, &[u8])]) -> Result<Vec<u8>, String> {
    let mut w = Writer::new();
    write_objects(&mut w, objects)?;
    Ok(w.finish())
}

fn write_objects(w: &mut Writer, objects: &[(ObjectId, ObjectKind, &[u8])]) -> Result<(), String> {
    if objects.len() > MAX_OBJECT_BATCH {
        return Err("too many objects".into());
    }
    let mut size = varint_len(objects.len());
    for (_, kind, body) in objects {
        check_public_kind(*kind)?;
        if body.len() > MAX_OBJECT_BODY {
            return Err("object is too large".into());
        }
        size = size
            .checked_add(object_len(body.len()))
            .filter(|size| *size <= MAX_OBJECTS_HTTP)
            .ok_or_else(|| "object batch is too large".to_string())?;
    }
    w.buf.reserve_exact(size);
    w.varint(objects.len() as u64);
    for (id, kind, body) in objects {
        w.id(id);
        w.u8(*kind as u8);
        w.bytes(body);
    }
    Ok(())
}

pub(crate) fn decode_objects(bytes: &[u8]) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, String> {
    if bytes.len() > MAX_OBJECTS_HTTP {
        return Err("object batch is too large".into());
    }
    let mut r = Reader::new(bytes, "objects");
    let objects = read_objects(&mut r)?;
    r.finish().map_err(|e| e.to_string())?;
    Ok(objects)
}

/// `get` response: how many requested ids it covers, then the objects.
pub(crate) fn encode_get_response(
    answered: usize,
    objects: &[(ObjectId, ObjectKind, &[u8])],
) -> Result<Vec<u8>, String> {
    let mut w = Writer::new();
    w.varint(answered as u64);
    write_objects(&mut w, objects)?;
    Ok(w.finish())
}

pub(crate) type GetResponse = (usize, Vec<(ObjectId, ObjectKind, Vec<u8>)>);

pub(crate) fn decode_get_response(bytes: &[u8]) -> Result<GetResponse, String> {
    if bytes.len() > MAX_OBJECTS_HTTP + 16 {
        return Err("object batch is too large".into());
    }
    let mut r = Reader::new(bytes, "objects");
    let answered = r.varint().map_err(|e| e.to_string())?;
    let answered = usize::try_from(answered).map_err(|_| "bad answered count".to_string())?;
    let objects = read_objects(&mut r)?;
    r.finish().map_err(|e| e.to_string())?;
    Ok((answered, objects))
}

/// Encoded size of one object in a batch.
pub(crate) fn object_len(body_len: usize) -> usize {
    32usize
        .saturating_add(1)
        .saturating_add(varint_len(body_len))
        .saturating_add(body_len)
}

pub(crate) fn varint_len(mut value: usize) -> usize {
    let mut len = 1;
    while value >= 0x80 {
        value >>= 7;
        len += 1;
    }
    len
}

/// Operations, views and conflicts never leave the machine (DESIGN.md,
/// "Crypto and wire rules" 2, and unresolved conflicts stay local).
pub(crate) fn check_public_kind(kind: ObjectKind) -> Result<(), String> {
    match kind {
        ObjectKind::Blob | ObjectKind::Tree | ObjectKind::Revision => Ok(()),
        _ => Err(format!("object kind {kind:?} cannot cross the wire")),
    }
}

fn read_objects(r: &mut Reader<'_>) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, String> {
    // id + kind + empty body length. The count is still bounded by the HTTP cap.
    let n = r.count(32 + 1 + 1).map_err(|e| e.to_string())?;
    if n > MAX_OBJECT_BATCH {
        return Err("too many objects".into());
    }
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let id = r.id().map_err(|e| e.to_string())?;
        let kind =
            ObjectKind::from_u8(r.u8().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        check_public_kind(kind)?;
        let body = r.bytes().map_err(|e| e.to_string())?;
        if body.len() > MAX_OBJECT_BODY {
            return Err("object is too large".into());
        }
        out.push((id, kind, body.to_vec()));
    }
    Ok(out)
}

pub(crate) fn encode_head(
    keyring: Option<&[u8]>,
    manifest: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    if keyring.is_some_and(|b| b.len() as u64 > MAX_KEYRING_FILE) {
        return Err("keyring is too large".into());
    }
    if manifest.is_some_and(|b| b.len() as u64 > MAX_MANIFEST_FILE) {
        return Err("manifest is too large".into());
    }
    let mut w = Writer::new();
    write_optional(&mut w, keyring);
    write_optional(&mut w, manifest);
    let bytes = w.finish();
    if bytes.len() > MAX_HEAD_HTTP {
        return Err("head is too large".into());
    }
    Ok(bytes)
}

pub(crate) type HeadParts = (Option<Vec<u8>>, Option<Vec<u8>>);

pub(crate) fn decode_head(bytes: &[u8]) -> Result<HeadParts, String> {
    if bytes.len() > MAX_HEAD_HTTP {
        return Err("head is too large".into());
    }
    let mut r = Reader::new(bytes, "head");
    let keyring = read_optional(&mut r, MAX_KEYRING_FILE, "keyring")?;
    let manifest = read_optional(&mut r, MAX_MANIFEST_FILE, "manifest")?;
    r.finish().map_err(|e| e.to_string())?;
    Ok((keyring, manifest))
}

fn write_optional(w: &mut Writer, bytes: Option<&[u8]>) {
    match bytes {
        None => w.u8(0),
        Some(bytes) => {
            w.u8(1);
            w.bytes(bytes);
        }
    }
}

fn read_optional(r: &mut Reader<'_>, max: u64, what: &str) -> Result<Option<Vec<u8>>, String> {
    match r.u8().map_err(|e| e.to_string())? {
        0 => Ok(None),
        1 => {
            let bytes = r.bytes().map_err(|e| e.to_string())?;
            if bytes.len() as u64 > max {
                return Err(format!("{what} is too large"));
            }
            Ok(Some(bytes.to_vec()))
        }
        other => Err(format!("bad {what} flag {other}")),
    }
}

/// `ETag` and `If-Match` value, including the quotes: `"<64 hex>"`.
pub(crate) fn etag_value(version: &tig_private::remote::HeadVersion) -> String {
    format!("\"{}\"", version.to_hex())
}

pub(crate) fn parse_etag(header: &str) -> Option<tig_private::remote::HeadVersion> {
    let header = header.trim();
    let hex = header.strip_prefix('"')?.strip_suffix('"')?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let bytes = hex::decode(hex).ok()?;
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    Some(tig_private::remote::HeadVersion(bytes))
}

pub(crate) fn check_group(group: &str) -> Result<(), String> {
    let ok = !group.is_empty()
        && group.len() <= crate::limits::MAX_GROUP_LEN
        && group
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'));
    if ok {
        Ok(())
    } else {
        Err(format!("invalid group name {group:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostile_counts_lengths_flags_and_local_kinds_are_refused() {
        let mut huge = Writer::new();
        huge.varint(u64::MAX);
        let huge = huge.finish();
        assert!(decode_ids(&huge, MAX_ID_BATCH).is_err());
        assert!(decode_objects(&huge).is_err());
        let mut head = vec![1];
        head.extend_from_slice(&huge);
        assert!(decode_head(&head).is_err());
        assert!(decode_head(&[2, 0]).is_err());
        assert!(decode_head(&[0, 0, 0]).is_err());
        for kind in [
            ObjectKind::Operation,
            ObjectKind::View,
            ObjectKind::Conflict,
        ] {
            assert!(encode_objects(&[(ObjectId([0; 32]), kind, &[])]).is_err());
            let mut w = Writer::new();
            w.varint(1);
            w.id(&ObjectId([0; 32]));
            w.u8(kind as u8);
            w.bytes(&[]);
            assert!(decode_objects(&w.finish()).is_err());
        }
        let mut w = Writer::new();
        w.varint(1);
        w.id(&ObjectId([0; 32]));
        w.u8(ObjectKind::Blob as u8);
        w.varint(u64::MAX);
        assert!(decode_objects(&w.finish()).is_err());
    }

    #[test]
    fn version_one_is_not_silently_accepted_as_version_two() {
        let mut info = encode_info(&[1; 16]);
        info[0] = 1;
        assert!(decode_info(&info).is_err());
    }
}
