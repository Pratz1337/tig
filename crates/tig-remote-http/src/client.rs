//! `HttpRemote`: the `Remote` trait over HTTP. Reads need no identity.
//! Writes sign each request with a fresh server nonce.

use std::collections::BTreeMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;

use tig_core::object::hash_object;
use tig_core::store::Store;
use tig_core::{ObjectId, ObjectKind};
use tig_private::keys::Identity;
use tig_private::remote::{CommitOutcome, HeadVersion, Remote, RemoteError, RemoteHead};

use crate::auth::{format_identity, signing_message};
use crate::limits::{
    MAX_HEAD_HTTP, MAX_ID_HTTP, MAX_OBJECTS_HTTP, MAX_PACK_FILE,
};
use crate::wire::{
    check_group, decode_head, decode_ids, decode_info, decode_objects, encode_head, encode_ids,
    encode_objects, etag_value, parse_etag,
};

const GET_ATTEMPTS: usize = 3;

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
        let base = normalize_base(url)?;
        let agent = ureq::AgentBuilder::new()
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
        let info = call(&probe, "GET", "/v1/info", &[], false, None, 64)?;
        if info.status != 200 {
            return Err(RemoteError::Invalid(format!(
                "server returned {} for /v1/info",
                info.status
            )));
        }
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
}

impl Inner {
    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }
}

struct Call {
    status: u16,
    etag: Option<String>,
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
    let attempts = if method == "GET" { GET_ATTEMPTS } else { 1 };
    let mut last = None;
    for attempt in 0..attempts {
        match call_once(inner, method, path, body, auth, if_match, max_body) {
            Ok(response) => return Ok(response),
            Err(RemoteError::Io(error)) if attempt + 1 < attempts => {
                last = Some(RemoteError::Io(error));
            }
            Err(other) => return Err(other),
        }
    }
    Err(last.unwrap_or_else(|| RemoteError::Invalid("request failed".into())))
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
    let mut request = inner.agent.request(method, &url);
    request = request.set("Content-Type", "application/octet-stream");
    if let Some(expected) = if_match {
        request = request.set("If-Match", expected);
    }
    if auth {
        let identity = inner.identity.as_ref().ok_or_else(|| {
            RemoteError::Invalid("write requires an identity".into())
        })?;
        let nonce_resp = post_nonce(inner)?;
        if nonce_resp.len() != 32 {
            return Err(RemoteError::Invalid("nonce must be 32 bytes".into()));
        }
        let mut nonce = [0u8; 32];
        nonce.copy_from_slice(&nonce_resp);
        let message = signing_message(&inner.remote_id, method, path, body, &nonce);
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
            return Err(RemoteError::Io(std::io::Error::other(error.to_string())));
        }
    };
    let status = response.status();
    let etag = response.header("ETag").map(str::to_string);
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
        .map_err(RemoteError::Io)?;
    if buf.len() > max_body {
        return Err(RemoteError::Invalid("response is too large".into()));
    }
    Ok(Call {
        status,
        etag,
        body: buf,
    })
}

fn post_nonce(inner: &Inner) -> Result<Vec<u8>, RemoteError> {
    let url = inner.url("/v1/nonce");
    let sent = inner
        .agent
        .request("POST", &url)
        .set("Content-Type", "application/octet-stream")
        .send_bytes(&[]);
    let response = match sent {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(ureq::Error::Transport(error)) => {
            return Err(RemoteError::Io(std::io::Error::other(error.to_string())));
        }
    };
    if response.status() != 200 {
        return Err(RemoteError::Invalid(format!(
            "server returned {} for /v1/nonce",
            response.status()
        )));
    }
    let mut buf = Vec::new();
    response
        .into_reader()
        .take(33)
        .read_to_end(&mut buf)
        .map_err(RemoteError::Io)?;
    Ok(buf)
}

fn expect_ok(call: Call, what: &str) -> Result<Call, RemoteError> {
    if call.status == 200 {
        Ok(call)
    } else {
        Err(RemoteError::Invalid(format!(
            "server returned {} for {what}",
            call.status
        )))
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
        let body = encode_ids(ids).map_err(RemoteError::Invalid)?;
        let response = expect_ok(
            call(&self.inner, "POST", "/v1/objects/missing", &body, false, None, MAX_ID_HTTP)?,
            "/v1/objects/missing",
        )?;
        let missing = decode_ids(&response.body, ids.len()).map_err(RemoteError::Invalid)?;
        if missing.iter().any(|id| !ids.contains(id)) {
            return Err(RemoteError::Invalid(
                "server listed an id that was not requested".into(),
            ));
        }
        Ok(missing)
    }

    fn put_batch(&self, objects: &[(ObjectId, ObjectKind, Vec<u8>)]) -> Result<(), RemoteError> {
        let view: Vec<(ObjectId, ObjectKind, &[u8])> = objects
            .iter()
            .map(|(id, kind, body)| (*id, *kind, body.as_slice()))
            .collect();
        for (id, kind, body) in &view {
            if hash_object(*kind, body) != *id {
                return Err(RemoteError::Invalid(
                    "refusing to upload an object whose id does not match".into(),
                ));
            }
        }
        let body = encode_objects(&view).map_err(RemoteError::Invalid)?;
        expect_ok(
            call(&self.inner, "POST", "/v1/objects/put", &body, true, None, 64)?,
            "/v1/objects/put",
        )?;
        Ok(())
    }

    fn get_batch(
        &self,
        ids: &[ObjectId],
    ) -> Result<Vec<(ObjectId, ObjectKind, Vec<u8>)>, RemoteError> {
        let body = encode_ids(ids).map_err(RemoteError::Invalid)?;
        let response = expect_ok(
            call(&self.inner, "POST", "/v1/objects/get", &body, false, None, MAX_OBJECTS_HTTP)?,
            "/v1/objects/get",
        )?;
        let objects = decode_objects(&response.body).map_err(RemoteError::Invalid)?;
        let mut seen = BTreeMap::new();
        for (id, kind, body) in &objects {
            if !ids.contains(id) {
                return Err(RemoteError::Invalid(
                    "server returned an object that was not requested".into(),
                ));
            }
            if hash_object(*kind, body) != *id {
                return Err(RemoteError::Invalid(
                    "server returned an object whose id does not match".into(),
                ));
            }
            if seen.insert(*id, ()).is_some() {
                return Err(RemoteError::Invalid("server repeated an object id".into()));
            }
        }
        Ok(objects)
    }

    fn put_pack(&self, bytes: &[u8]) -> Result<(), RemoteError> {
        if bytes.len() > MAX_PACK_FILE {
            return Err(RemoteError::Invalid("pack is too large".into()));
        }
        expect_ok(
            call(&self.inner, "PUT", "/v1/packs", bytes, true, None, 64)?,
            "/v1/packs",
        )?;
        Ok(())
    }

    fn list_packs(&self, group: &str, epoch: u64) -> Result<Vec<Vec<u8>>, RemoteError> {
        check_group(group).map_err(RemoteError::Invalid)?;
        let path = format!("/v1/packs/{group}/{epoch}");
        let response = expect_ok(
            call(&self.inner, "GET", &path, &[], false, None, MAX_ID_HTTP)?,
            "/v1/packs",
        )?;
        let ids = decode_ids(&response.body, crate::limits::MAX_LISTED_PACKS)
            .map_err(RemoteError::Invalid)?;
        let mut out = Vec::with_capacity(ids.len());
        let mut previous: Option<ObjectId> = None;
        for id in ids {
            if previous.is_some_and(|prev| prev >= id) {
                return Err(RemoteError::Invalid("pack list is not ordered".into()));
            }
            previous = Some(id);
            let one = format!("/v1/packs/{group}/{epoch}/{}", hex::encode(id.0));
            let file = expect_ok(
                call(&self.inner, "GET", &one, &[], false, None, MAX_PACK_FILE)?,
                "/v1/packs",
            )?;
            if *blake3::hash(&file.body).as_bytes() != id.0 {
                return Err(RemoteError::Invalid(
                    "pack bytes do not match the pack id".into(),
                ));
            }
            out.push(file.body);
        }
        Ok(out)
    }

    fn read_head(&self) -> Result<RemoteHead, RemoteError> {
        let response = expect_ok(
            call(&self.inner, "GET", "/v1/head", &[], false, None, MAX_HEAD_HTTP)?,
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
            if let Some(etag) = &response.etag {
                let advertised = parse_etag(etag)
                    .ok_or_else(|| RemoteError::Invalid("412 ETag is not a version".into()))?;
                if advertised != head.version() {
                    return Err(RemoteError::Invalid(
                        "412 ETag does not match the body".into(),
                    ));
                }
            }
            return Ok(CommitOutcome::Stale(head));
        }
        if response.status != 200 {
            return Err(RemoteError::Invalid(format!(
                "server returned {} for /v1/head",
                response.status
            )));
        }
        let etag = response
            .etag
            .ok_or_else(|| RemoteError::Invalid("commit response has no ETag".into()))?;
        let version = parse_etag(&etag)
            .ok_or_else(|| RemoteError::Invalid("commit ETag is not a version".into()))?;
        Ok(CommitOutcome::Committed(version))
    }
}

impl Store for HttpStore {
    fn get_raw(&self, id: &ObjectId) -> tig_core::Result<Option<(ObjectKind, Vec<u8>)>> {
        let batch = HttpRemote {
            inner: Arc::clone(&self.inner),
            store: HttpStore {
                inner: Arc::clone(&self.inner),
            },
        }
        .get_batch(std::slice::from_ref(id))
        .map_err(|e| tig_core::Error::Invalid(e.to_string()))?;
        Ok(batch.into_iter().next().map(|(_, kind, body)| (kind, body)))
    }

    fn put_raw(&self, id: &ObjectId, kind: ObjectKind, body: &[u8]) -> tig_core::Result<()> {
        let remote = HttpRemote {
            inner: Arc::clone(&self.inner),
            store: HttpStore {
                inner: Arc::clone(&self.inner),
            },
        };
        remote
            .put_batch(&[(*id, kind, body.to_vec())])
            .map_err(|e| tig_core::Error::Invalid(e.to_string()))
    }

    fn has(&self, id: &ObjectId) -> tig_core::Result<bool> {
        let remote = HttpRemote {
            inner: Arc::clone(&self.inner),
            store: HttpStore {
                inner: Arc::clone(&self.inner),
            },
        };
        let missing = remote
            .missing(std::slice::from_ref(id))
            .map_err(|e| tig_core::Error::Invalid(e.to_string()))?;
        Ok(missing.is_empty())
    }
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
    if rest.is_empty() || rest.contains('@') || rest.contains('#') || rest.contains('?') {
        return Err(RemoteError::Invalid("remote URL is not a server root".into()));
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
        return Err(RemoteError::Invalid("remote URL path is not allowed".into()));
    }
    Ok(format!("{scheme}://{hostport}{prefix}"))
}

fn host_of(hostport: &str) -> Result<String, RemoteError> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let end = rest
            .find(']')
            .ok_or_else(|| RemoteError::Invalid("bad IPv6 host".into()))?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        if !(after.is_empty() || after.starts_with(':')) {
            return Err(RemoteError::Invalid("bad IPv6 host".into()));
        }
        if host.is_empty() {
            return Err(RemoteError::Invalid("remote URL has no host".into()));
        }
        return Ok(host.to_string());
    }
    let host = match hostport.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => hostport,
    };
    if host.is_empty() {
        return Err(RemoteError::Invalid("remote URL has no host".into()));
    }
    Ok(host.to_string())
}

fn is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host == "::1" {
        return true;
    }
    match host.parse::<Ipv4Addr>() {
        Ok(addr) => addr.is_loopback(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_is_loopback_only() {
        assert!(normalize_base("http://127.0.0.1:8470").is_ok());
        assert!(normalize_base("http://127.1.2.3:1").is_ok());
        assert!(normalize_base("http://localhost:9").is_ok());
        assert!(normalize_base("http://[::1]:9").is_ok());
        assert!(normalize_base("https://example.com").is_ok());
        assert!(normalize_base("http://example.com").is_err());
        assert!(normalize_base("http://127.0.0.1.example").is_err());
    }
}
