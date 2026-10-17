//! `HttpRemote`: the `Remote` trait over HTTP. Reads need no identity.
//! Writes sign each request with a fresh server nonce.
//!
//! The server is not trusted for content: every object is hash-checked and
//! must have been requested, pack bytes must match their pack id, the head
//! must match its ETag, and every response is size-bounded before it is read.

use std::collections::BTreeSet;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use tig_core::object::hash_object;
use tig_core::store::Store;
use tig_core::{ObjectId, ObjectKind};
use tig_private::keys::Identity;
use tig_private::pack::Pack;
use tig_private::remote::{CommitOutcome, HeadVersion, Remote, RemoteError, RemoteHead};

use crate::auth::{format_identity, signing_message, Nonce, NONCE_LEN};
use crate::limits::{
    HEADER_DEADLINE, MAX_HEAD_HTTP, MAX_ID_BATCH, MAX_ID_HTTP, MAX_LISTED_PACKS, MAX_OBJECTS_HTTP,
    MAX_OBJECT_BATCH, MAX_PACK_FILE, MIN_RATE, OBJECTS_REQUEST_TARGET, TRANSFER_GRACE,
};
use crate::wire::{
    check_group, check_public_kind, decode_get_response, decode_head, decode_ids, decode_info,
    encode_head, encode_ids, encode_objects, etag_value, object_len, parse_etag, varint_len,
};

const REQUEST_ATTEMPTS: usize = 4;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(3);

struct Inner {
    agent: ureq::Agent,
    base: String,
    remote_id: [u8; 16],
    identity: Option<Identity>,
}

pub struct HttpRemote {
    inner: Arc<Inner>,
    store: HttpStore,
}

struct HttpStore {
    inner: Arc<Inner>,
}

impl HttpRemote {
    /// `url` is the server root (`https://host:port` or `https://host:port/prefix`).
    /// Plain `http://` is refused unless the host is loopback.
    pub fn connect(url: &str, identity: Option<Identity>) -> Result<Self, RemoteError> {
        let base = check_url(url)?;
        // No redirects: one could leave https, or carry a signed write elsewhere.
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .timeout_connect(Duration::from_secs(10))
            .timeout_read(Duration::from_secs(60))
            .timeout_write(Duration::from_secs(60))
            .build();
        let probe = Inner {
            agent: agent.clone(),
            base: base.clone(),
            remote_id: [0; 16],
            identity: None,
        };
        let info = expect_ok(
            call(&probe, "GET", "/v1/info", &[], false, None, 64)?,
            "/v1/info",
        )?;
        let remote_id = decode_info(&info.body).map_err(RemoteError::Invalid)?;
        let inner = Arc::new(Inner {
            agent,
            base,
            remote_id,
            identity,
        });
        let store = HttpStore {
            inner: Arc::clone(&inner),
        };
        Ok(HttpRemote { inner, store })
    }

    fn from_inner(inner: &Arc<Inner>) -> Self {
        HttpRemote {
            inner: Arc::clone(inner),
            store: HttpStore {
                inner: Arc::clone(inner),
            },
        }
    }
}

impl Inner {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

struct Call {
    status: u16,
    etag: Option<String>,
    retry_after: Option<Duration>,
    body: Vec<u8>,
}

fn call(
    inner: &Inner,
    method: &str,
    path: &str,
    body: &[u8],
    auth: bool,
    if_match: Option<&str>,
    max_body: usize,
) -> Result<Call, RemoteError> {
    // Only these routes are safe to repeat. Each signed attempt gets a new nonce.
    let safe = method == "GET"
        || matches!(
            (method, path),
            (
                "POST",
                "/v1/nonce" | "/v1/objects/missing" | "/v1/objects/get" | "/v1/objects/put"
            ) | ("PUT", "/v1/packs")
        )
        || (method == "PUT" && path == "/v1/head" && if_match.is_some());
    let attempts = if safe { REQUEST_ATTEMPTS } else { 1 };
    for attempt in 0..attempts {
        match call_once(inner, method, path, body, auth, if_match, max_body) {
            Ok(response) if response.status == 503 => {
                if attempt + 1 == attempts {
                    return Err(status_error(&response, path));
                }
                std::thread::sleep(retry_delay(attempt, response.retry_after));
            }
            Ok(response) => return Ok(response),
            Err(RemoteError::Io(error))
                if method == "GET"
                    && matches!(
                        error.kind(),
                        std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::UnexpectedEof
                    )
                    && attempt + 1 < attempts =>
            {
                std::thread::sleep(retry_delay(attempt, None))
            }
            Err(other) => return Err(other),
        }
    }
    unreachable!("every final attempt returns")
}

fn retry_delay(attempt: usize, retry_after: Option<Duration>) -> Duration {
    let mut random = [0; 2];
    let _ = getrandom::getrandom(&mut random);
    let backoff =
        Duration::from_millis((50 << attempt.min(5)) + u16::from_le_bytes(random) as u64 % 100);
    backoff
        .max(retry_after.unwrap_or_default())
        .min(MAX_RETRY_AFTER)
}

fn retry_after(value: &str) -> Option<Duration> {
    let delay = if let Ok(seconds) = value.parse::<u64>() {
        Duration::from_secs(seconds)
    } else {
        httpdate::parse_http_date(value)
            .ok()?
            .duration_since(std::time::SystemTime::now())
            .unwrap_or_default()
    };
    Some(delay.min(MAX_RETRY_AFTER))
}

fn transport_error(error: ureq::Transport) -> RemoteError {
    use std::error::Error;
    let kind = error
        .source()
        .and_then(|source| source.downcast_ref::<std::io::Error>())
        .map_or(std::io::ErrorKind::Other, std::io::Error::kind);
    RemoteError::Io(std::io::Error::new(kind, error.to_string()))
}

fn call_once(
    inner: &Inner,
    method: &str,
    path: &str,
    body: &[u8],
    auth: bool,
    if_match: Option<&str>,
    max_body: usize,
) -> Result<Call, RemoteError> {
    let url = inner.url(path);
    let mut request = inner
        .agent
        .request(method, &url)
        .timeout(request_timeout(body.len().saturating_add(max_body)));
    request = request.set("Content-Type", "application/octet-stream");
    if let Some(expected) = if_match {
        request = request.set("If-Match", expected);
    }
    if auth {
        let identity = inner
            .identity
            .as_ref()
            .ok_or_else(|| RemoteError::Invalid("write requires an identity".into()))?;
        let nonce: Nonce = post_nonce(inner)?
            .try_into()
            .map_err(|_| RemoteError::Invalid(format!("nonce must be {NONCE_LEN} bytes")))?;
        let message = signing_message(&inner.remote_id, method, path, body, &nonce, if_match);
        let signature = identity.sign(&message);
        request = request
            .set("Tig-Identity", &format_identity(&identity.public()))
            .set("Tig-Nonce", &hex::encode(nonce))
            .set("Tig-Signature", &hex::encode(signature));
    }
    let sent = if method == "GET" || method == "HEAD" {
        request.call()
    } else {
        request.send_bytes(body)
    };
    let response = match sent {
        Ok(response) => response,
        Err(ureq::Error::Status(_code, response)) => response,
        Err(ureq::Error::Transport(error)) => {
            return Err(transport_error(error));
        }
    };
    let status = response.status();
    let etag = response.header("ETag").map(str::to_string);
    let retry_after = response.header("Retry-After").and_then(retry_after);
    if matches!(status, 401 | 403 | 503) {
        // Refusals may come from a proxy with an HTML body. Their status is
        // authoritative even if that body is oversized or truncated.
        let mut detail = Vec::new();
        let _ = response.into_reader().take(200).read_to_end(&mut detail);
        return Ok(Call {
            status,
            etag,
            retry_after,
            body: detail,
        });
    }
    if let Some(len) = response.header("Content-Length") {
        let len: u64 = len
            .parse()
            .map_err(|_| RemoteError::Invalid("bad content-length".into()))?;
        if len > max_body as u64 {
            return Err(RemoteError::Invalid("response is too large".into()));
        }
    }
    let mut buf = Vec::new();
    response
        .into_reader()
        .take(max_body as u64 + 1)
        .read_to_end(&mut buf)
        // Once response headers arrived, a reset must not replay the request.
        .map_err(|error| RemoteError::Io(std::io::Error::other(error)))?;
    if buf.len() > max_body {
        return Err(RemoteError::Invalid("response is too large".into()));
    }
    Ok(Call {
        status,
        etag,
        retry_after,
        body: buf,
    })
}

fn post_nonce(inner: &Inner) -> Result<Vec<u8>, RemoteError> {
    Ok(expect_ok(
        call(inner, "POST", "/v1/nonce", &[], false, None, NONCE_LEN)?,
        "/v1/nonce",
    )?
    .body)
}

/// A size-derived total deadline in addition to per-socket timeouts. A peer
/// cannot keep a request alive indefinitely by trickling headers or bytes.
fn request_timeout(bytes: usize) -> Duration {
    HEADER_DEADLINE + TRANSFER_GRACE + Duration::from_secs_f64(bytes as f64 / MIN_RATE as f64)
}

fn expect_ok(call: Call, what: &str) -> Result<Call, RemoteError> {
    if call.status == 200 {
        Ok(call)
    } else {
        Err(status_error(&call, what))
    }
}

fn status_error(call: &Call, what: &str) -> RemoteError {
    let detail: String = String::from_utf8_lossy(&call.body)
        .chars()
        .take(200)
        .filter(|c| !c.is_control())
        .collect();
    let message = format!("server returned {} for {what}: {detail}", call.status);
    match call.status {
        503 => RemoteError::Busy(message),
        403 => RemoteError::Denied("you are not a member".into()),
        401 => RemoteError::Denied(message),
        _ => RemoteError::Invalid(message),
    }
}

impl Remote for HttpRemote {
    fn remote_id(&self) -> [u8; 16] {
        self.inner.remote_id
    }

    fn public_store(&self) -> &dyn Store {
        &self.store
    }

    fn missing(&self, ids: &[ObjectId]) -> Result<Vec<ObjectId>, RemoteError> {
        let mut requested = BTreeSet::new();
        let wanted: Vec<ObjectId> = ids
            .iter()
            .copied()
            .filter(|id| requested.insert(*id))
            .collect();
        let mut out = Vec::new();
        for chunk in wanted.chunks(MAX_ID_BATCH) {
            let body = encode_ids(chunk).map_err(RemoteError::Invalid)?;
            let response = expect_ok(
                call(
                    &self.inner,
                    "POST",
                    "/v1/objects/missing",
                    &body,
                    false,
                    None,
                    MAX_ID_HTTP,
                )?,
                "/v1/objects/missing",
            )?;
            let missing = decode_ids(&response.body, chunk.len()).map_err(RemoteError::Invalid)?;
            let asked: BTreeSet<&ObjectId> = chunk.iter().collect();
            let mut seen = BTreeSet::new();
            for id in &missing {
                if !asked.contains(id) {
                    return Err(RemoteError::Invalid(
                        "server listed an id that was not requested".into(),
                    ));
                }
                if !seen.insert(*id) {
                    return Err(RemoteError::Invalid("server repeated a missing id".into()));
                }
            }
            out.extend(missing);
        }
        Ok(out)
    }

    /// Splits into signed requests of at most `MAX_OBJECT_BATCH` objects and
    /// about `OBJECTS_REQUEST_TARGET` bytes. Refuses local-only kinds.
    fn put_batch(&self, objects: &[(ObjectId, ObjectKind, Vec<u8>)]) -> Result<(), RemoteError> {
        let mut seen = BTreeSet::new();
        let mut view: Vec<(ObjectId, ObjectKind, &[u8])> = Vec::with_capacity(objects.len());
        for (id, kind, body) in objects {
            check_public_kind(*kind).map_err(RemoteError::Invalid)?;
            if hash_object(*kind, body) != *id {
                return Err(RemoteError::Invalid(
                    "refusing to upload an object whose id does not match".into(),
                ));
            }
            if seen.insert(*id) {
                view.push((*id, *kind, body.as_slice()));
            }
        }
        let mut start = 0;
        while start < view.len() {
            let mut end = start;
            let mut size = varint_len(MAX_OBJECT_BATCH);
            while end < view.len() && end - start < MAX_OBJECT_BATCH {
                let next = size.saturating_add(object_len(view[end].2.len()));
                if end > start && next > OBJECTS_REQUEST_TARGET {
                    break;
                }
                size = next;
                end += 1;
            }
            let body = encode_objects(&view[start..end]).map_err(RemoteError::Invalid)?;
            expect_ok(
                call(
                    &self.inner,
                    "POST",
                    "/v1/objects/put",
                    &body,
                    true,
                    None,
                    1024,
                )?,
                "/v1/objects/put",
            )?;
            start = end;
        }
        Ok(())
    }

    /// The server answers a prefix of each request; ask again for the rest.
    /// Every object must be one that was asked for in that prefix, once, with
    /// a public kind (checked while decoding) and a matching hash.
    fn get_batch(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, RemoteError> {
        let mut seen = BTreeSet::new();
        let wanted: Vec<ObjectId> = ids.iter().copied().filter(|id| seen.insert(*id)).collect();
        let mut out = Vec::new();
        let mut start = 0;
        while start < wanted.len() {
            let chunk = &wanted[start..wanted.len().min(start + MAX_ID_BATCH)];
            let body = encode_ids(chunk).map_err(RemoteError::Invalid)?;
            let response = expect_ok(
                call(
                    &self.inner,
                    "POST",
                    "/v1/objects/get",
                    &body,
                    false,
                    None,
                    MAX_OBJECTS_HTTP + 16,
                )?,
                "/v1/objects/get",
            )?;
            let (answered, objects) =
                decode_get_response(&response.body).map_err(RemoteError::Invalid)?;
            if answered == 0 || answered > chunk.len() {
                return Err(RemoteError::Invalid(
                    "server answered an impossible number of ids".into(),
                ));
            }
            let asked: BTreeSet<&ObjectId> = chunk[..answered].iter().collect();
            let mut returned = BTreeSet::new();
            for (id, kind, body) in &objects {
                if !asked.contains(id) {
                    return Err(RemoteError::Invalid(
                        "server returned an object that was not requested".into(),
                    ));
                }
                if !returned.insert(*id) {
                    return Err(RemoteError::Invalid("server repeated an object id".into()));
                }
                if hash_object(*kind, body) != *id {
                    return Err(RemoteError::Invalid(
                        "server returned an object whose id does not match".into(),
                    ));
                }
            }
            out.extend(objects);
            start += answered;
        }
        Ok(out)
    }

    fn put_pack(&self, bytes: &[u8]) -> Result<(), RemoteError> {
        if bytes.len() > MAX_PACK_FILE {
            return Err(RemoteError::Invalid("pack is too large".into()));
        }
        expect_ok(
            call(&self.inner, "PUT", "/v1/packs", bytes, true, None, 1024)?,
            "/v1/packs",
        )?;
        Ok(())
    }

    /// Same aggregate cap as `DirRemote`: one epoch's packs total at most
    /// `MAX_PACK_FILE` bytes.
    fn list_packs(&self, group: &str, epoch: u64) -> Result<Vec<Vec<u8>>, RemoteError> {
        let ids = self.list_pack_ids(group, epoch)?;
        let mut out = Vec::with_capacity(ids.len());
        let mut remaining = MAX_PACK_FILE;
        for id in ids {
            let bytes = self.read_pack(group, epoch, &id, remaining)?
                .ok_or_else(|| RemoteError::Invalid("listed pack is missing".into()))?;
            remaining = remaining.checked_sub(bytes.len())
                .ok_or_else(|| RemoteError::Invalid("pack listing is too large".into()))?;
            out.push(bytes);
        }
        Ok(out)
    }

    fn list_pack_ids(&self, group: &str, epoch: u64) -> Result<Vec<[u8; 32]>, RemoteError> {
        check_group(group).map_err(RemoteError::Invalid)?;
        let path = format!("/v1/packs/{group}/{epoch}");
        let response = expect_ok(
            call(&self.inner, "GET", &path, &[], false, None, MAX_ID_HTTP)?,
            "/v1/packs",
        )?;
        let ids = decode_ids(&response.body, MAX_LISTED_PACKS).map_err(RemoteError::Invalid)?;
        if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(RemoteError::Invalid("pack list is not ordered".into()));
        }
        Ok(ids.into_iter().map(|id| id.0).collect())
    }

    fn get_pack(&self, group: &str, epoch: u64, id: &[u8; 32]) -> Result<Option<Vec<u8>>, RemoteError> {
        self.read_pack(group, epoch, id, MAX_PACK_FILE)
    }

    fn read_head(&self) -> Result<RemoteHead, RemoteError> {
        let response = expect_ok(
            call(
                &self.inner,
                "GET",
                "/v1/head",
                &[],
                false,
                None,
                MAX_HEAD_HTTP,
            )?,
            "/v1/head",
        )?;
        let (keyring, manifest) = decode_head(&response.body).map_err(RemoteError::Invalid)?;
        let head = RemoteHead { keyring, manifest };
        let etag = response
            .etag
            .ok_or_else(|| RemoteError::Invalid("head response has no ETag".into()))?;
        let advertised = parse_etag(&etag)
            .ok_or_else(|| RemoteError::Invalid("head ETag is not a version".into()))?;
        if advertised != head.version() {
            return Err(RemoteError::Invalid(
                "head ETag does not match the body".into(),
            ));
        }
        Ok(head)
    }

    fn commit_head(
        &self,
        expected: &HeadVersion,
        keyring: Option<&[u8]>,
        manifest: Option<&[u8]>,
    ) -> Result<CommitOutcome, RemoteError> {
        let body = encode_head(keyring, manifest).map_err(RemoteError::Invalid)?;
        let response = call(
            &self.inner,
            "PUT",
            "/v1/head",
            &body,
            true,
            Some(&etag_value(expected)),
            MAX_HEAD_HTTP,
        )?;
        if response.status == 412 {
            let (keyring, manifest) = decode_head(&response.body).map_err(RemoteError::Invalid)?;
            let head = RemoteHead { keyring, manifest };
            let advertised = response
                .etag
                .as_deref()
                .and_then(parse_etag)
                .ok_or_else(|| RemoteError::Invalid("412 has no version ETag".into()))?;
            if advertised != head.version() {
                return Err(RemoteError::Invalid(
                    "412 ETag does not match the body".into(),
                ));
            }
            return Ok(CommitOutcome::Stale(head));
        }
        let response = expect_ok(response, "/v1/head")?;
        let (saved_keyring, saved_manifest) =
            decode_head(&response.body).map_err(RemoteError::Invalid)?;
        let head = RemoteHead {
            keyring: saved_keyring,
            manifest: saved_manifest,
        };
        let version = response
            .etag
            .as_deref()
            .and_then(parse_etag)
            .ok_or_else(|| RemoteError::Invalid("commit response has no version ETag".into()))?;
        if version != head.version() {
            return Err(RemoteError::Invalid(
                "commit ETag does not match the body".into(),
            ));
        }
        if keyring.is_some_and(|sent| head.keyring.as_deref() != Some(sent))
            || manifest.is_some_and(|sent| head.manifest.as_deref() != Some(sent))
            || (keyring.is_none() && manifest.is_none() && version != *expected)
        {
            return Err(RemoteError::Invalid(
                "committed head does not match what was sent".into(),
            ));
        }
        Ok(CommitOutcome::Committed(version))
    }
}

impl HttpRemote {
    fn read_pack(&self, group: &str, epoch: u64, id: &[u8; 32], limit: usize) -> Result<Option<Vec<u8>>, RemoteError> {
        check_group(group).map_err(RemoteError::Invalid)?;
        let path = format!("/v1/packs/{group}/{epoch}/{}", hex::encode(id));
        let file = call(&self.inner, "GET", &path, &[], false, None, limit)?;
        if file.status == 404 {
            return Ok(None);
        }
        let file = expect_ok(file, "/v1/packs")?;
            if blake3::hash(&file.body).as_bytes() != id {
                return Err(RemoteError::Invalid(
                    "pack bytes do not match the pack id".into(),
                ));
            }
            let header = Pack::peek_header(&file.body)?;
            if header.remote != self.inner.remote_id
                || header.group != group
                || header.epoch != epoch
            {
                return Err(RemoteError::Invalid(
                    "pack context does not match the request".into(),
                ));
            }
        Ok(Some(file.body))
    }

}

impl Store for HttpStore {
    fn get_raw(&self, id: &ObjectId) -> tig_core::Result<Option<(ObjectKind, Vec<u8>)>> {
        let batch = HttpRemote::from_inner(&self.inner)
            .get_batch(std::slice::from_ref(id))
            .map_err(|e| tig_core::Error::Invalid(e.to_string()))?;
        Ok(batch.into_iter().next().map(|(_, kind, body)| (kind, body)))
    }

    fn put_raw(&self, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> tig_core::Result<()> {
        HttpRemote::from_inner(&self.inner)
            .put_batch(&[(*id, kind, body.to_vec())])
            .map_err(|e| tig_core::Error::Invalid(e.to_string()))
    }

    fn has(&self, id: &ObjectId) -> tig_core::Result<bool> {
        let missing = HttpRemote::from_inner(&self.inner)
            .missing(std::slice::from_ref(id))
            .map_err(|e| tig_core::Error::Invalid(e.to_string()))?;
        Ok(missing.is_empty())
    }
}

/// Validates and normalizes a server root without contacting it.
pub fn check_url(url: &str) -> Result<String, RemoteError> {
    normalize_base(url)
}

pub(crate) fn normalize_base(url: &str) -> Result<String, RemoteError> {
    let url = url.trim().trim_end_matches('/');
    let (scheme, rest) = if let Some(rest) = url.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err(RemoteError::Invalid(
            "remote URL must start with https:// or http://".into(),
        ));
    };
    // No userinfo, query, fragment, backslash, space or control characters:
    // each is a way to make the host mean something else to someone else.
    if rest.is_empty()
        || rest
            .bytes()
            .any(|b| !b.is_ascii_graphic() || matches!(b, b'@' | b'#' | b'?' | b'\\'))
    {
        return Err(RemoteError::Invalid(
            "remote URL is not a server root".into(),
        ));
    }
    let (hostport, prefix) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, ""),
    };
    if hostport.is_empty() {
        return Err(RemoteError::Invalid("remote URL has no host".into()));
    }
    let host = host_of(hostport)?;
    if scheme == "http" && !is_loopback(&host) {
        return Err(RemoteError::Invalid(
            "plain http is only allowed for loopback".into(),
        ));
    }
    if prefix.split('/').any(|part| part == "." || part == "..") {
        return Err(RemoteError::Invalid(
            "remote URL path is not allowed".into(),
        ));
    }
    Ok(format!("{scheme}://{hostport}{prefix}"))
}

fn host_of(hostport: &str) -> Result<String, RemoteError> {
    let digits = |port: &str| !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit());
    if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| RemoteError::Invalid("bad IPv6 host".into()))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if !(after.is_empty() || after.strip_prefix(':').is_some_and(digits)) {
            return Err(RemoteError::Invalid("bad IPv6 host".into()));
        }
        if host.is_empty() {
            return Err(RemoteError::Invalid("remote URL has no host".into()));
        }
        return Ok(host.to_string());
    }
    let host = match hostport.split_once(':') {
        Some((host, port)) if digits(port) => host,
        Some(_) => return Err(RemoteError::Invalid("bad port".into())),
        None => hostport,
    };
    if host.is_empty() {
        return Err(RemoteError::Invalid("remote URL has no host".into()));
    }
    Ok(host.to_string())
}

/// `localhost` exactly, `127.0.0.0/8` in dotted-quad form, or IPv6 `::1`
/// in any spelling. Not `localhost.`, `0.0.0.0`, `127.1`, IPv4-mapped
/// addresses or zone ids: plain http to those is refused.
fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if let Ok(addr) = host.parse::<Ipv4Addr>() {
        return addr.is_loopback();
    }
    host.parse::<Ipv6Addr>()
        .is_ok_and(|addr| addr.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_after_accepts_seconds_and_dates_with_a_cap() {
        assert_eq!(retry_after("1"), Some(Duration::from_secs(1)));
        assert_eq!(retry_after("999999"), Some(MAX_RETRY_AFTER));
        let future =
            httpdate::fmt_http_date(std::time::SystemTime::now() + Duration::from_secs(30));
        assert_eq!(retry_after(&future), Some(MAX_RETRY_AFTER));
        assert_eq!(
            retry_after("Sun, 06 Nov 1994 08:49:37 GMT"),
            Some(Duration::ZERO)
        );
        assert_eq!(retry_after("invalid"), None);
        assert!(retry_delay(0, Some(Duration::from_secs(1))) >= Duration::from_secs(1));
    }

    #[test]
    fn http_is_loopback_only() {
        assert!(normalize_base("http://127.0.0.1:8470").is_ok());
        assert!(normalize_base("http://127.1.2.3:1").is_ok());
        assert!(normalize_base("http://localhost:9").is_ok());
        assert!(normalize_base("http://LOCALHOST").is_ok());
        assert!(normalize_base("http://[::1]:9").is_ok());
        assert!(normalize_base("http://[0:0:0:0:0:0:0:1]:9").is_ok());
        assert!(normalize_base("https://example.com").is_ok());
        assert_eq!(
            normalize_base("https://example.com/tig/").unwrap(),
            "https://example.com/tig"
        );
        for refused in [
            "http://example.com",
            "http://127.0.0.1.example",
            "http://localhost.:9",
            "http://localhost.example",
            "http://0.0.0.0:9",
            "http://127.1:9",
            "http://127.0.0.1@example.com",
            "http://example.com#@127.0.0.1",
            "http://127.0.0.1\\@example.com",
            "http://[::ffff:127.0.0.1]:9",
            "http://[::1%25lo]:9",
            "http://[::1]x",
            "http://[::]:9",
            "http://127.0.0.1:9:9",
            "http://127.0.0.1:x",
            "http://127.0.0.1 .example.com",
            "ftp://127.0.0.1",
            "HTTP://127.0.0.1",
            "https://example.com/../x",
        ] {
            assert!(normalize_base(refused).is_err(), "{refused}");
        }
    }

    #[test]
    fn slow_response_obeys_total_deadline() {
        use std::io::Write;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Instant;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let _ = stream.read(&mut [0; 2048]);
            stream.write_all(b"HTTP/1.1 200 OK\r\nX: ").unwrap();
            let begin = Instant::now();
            // Always faster than the per-read timeout, but never finish headers.
            while begin.elapsed() < Duration::from_secs(25) && !flag.load(Ordering::Relaxed) {
                if stream.write_all(b"a").is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        });
        let inner = Inner {
            agent: ureq::AgentBuilder::new()
                .timeout_read(Duration::from_secs(1))
                .build(),
            base,
            remote_id: [0; 16],
            identity: None,
        };
        let begin = Instant::now();
        assert!(call_once(&inner, "GET", "/v1/info", &[], false, None, 64).is_err());
        stop.store(true, Ordering::Relaxed);
        peer.join().unwrap();
        assert!(
            begin.elapsed() < Duration::from_secs(23),
            "trickled response outlived total deadline"
        );
    }
}
