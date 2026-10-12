//! Small HTTP/1.1 server. One request per connection. Writes are signed;
//! reads are not. `PUT /v1/head` is serialized in this process; the backend
//! still compare-and-swaps.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustls::ServerConfig;
use rustls::ServerConnection;
use rustls::StreamOwned;
use tig_core::object::hash_object;
use tig_private::keyring::Keyring;
use tig_private::keys::PublicIdentity;
use tig_private::manifest::allowed_signers;
use tig_private::project::PRIVATE_GROUP;
use tig_private::remote::{CommitOutcome, DirRemote, Remote, RemoteError, RemoteHead};

use crate::auth::{
    parse_fixed_hex, parse_identity, signing_message, verify_signature, NonceTable,
};
use crate::limits::{
    MAX_HEADERS, MAX_HEAD_HTTP, MAX_ID_HTTP, MAX_OBJECTS_HTTP, MAX_PACK_FILE,
};
use crate::wire::{
    self, decode_head, decode_ids, decode_objects, encode_head, encode_ids, encode_info,
    encode_objects, etag_value, parse_etag,
};

const MAX_WORKERS: usize = 64;

struct State {
    remote: Arc<dyn Remote>,
    owner: PublicIdentity,
    nonces: Mutex<NonceTable>,
    head_lock: Mutex<()>,
}

/// PEM certificate and private key for terminating TLS in-process.
pub struct TlsConfig {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

pub struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Server {
    pub fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn shutdown(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
        let workers = std::mem::take(&mut *self.workers.lock().unwrap_or_else(|p| p.into_inner()));
        for worker in workers {
            let _ = worker.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Creates `dir` with a random remote id and records `owner` in `server-owner`.
pub fn init_server_dir(
    dir: &std::path::Path,
    owner: &PublicIdentity,
) -> Result<[u8; 16], RemoteError> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id)
        .map_err(|error| RemoteError::Invalid(format!("no randomness: {error}")))?;
    DirRemote::create(dir, id)?;
    let mut raw = [0u8; 64];
    raw[..32].copy_from_slice(&owner.encryption);
    raw[32..].copy_from_slice(&owner.signing);
    std::fs::write(dir.join("server-owner"), raw)?;
    Ok(id)
}

pub fn read_server_owner(dir: &std::path::Path) -> Result<PublicIdentity, RemoteError> {
    let raw = std::fs::read(dir.join("server-owner"))?;
    if raw.len() != 64 {
        return Err(RemoteError::Invalid(
            "server-owner must be 64 bytes".into(),
        ));
    }
    let mut encryption = [0u8; 32];
    let mut signing = [0u8; 32];
    encryption.copy_from_slice(&raw[..32]);
    signing.copy_from_slice(&raw[32..]);
    Ok(PublicIdentity {
        encryption,
        signing,
    })
}

pub fn serve(
    remote: Arc<dyn Remote>,
    owner: PublicIdentity,
    listen: SocketAddr,
    tls: Option<TlsConfig>,
) -> Result<Server, RemoteError> {
    let tls = tls
        .map(load_tls)
        .transpose()
        .map_err(RemoteError::Invalid)?;
    let listener = TcpListener::bind(listen)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let workers = Arc::new(Mutex::new(Vec::new()));
    let state = Arc::new(State {
        remote,
        owner,
        nonces: Mutex::new(NonceTable::default()),
        head_lock: Mutex::new(()),
    });
    let stop_flag = Arc::clone(&stop);
    let worker_list = Arc::clone(&workers);
    let accept = thread::spawn(move || accept_loop(listener, state, tls, stop_flag, worker_list));
    Ok(Server {
        addr,
        stop,
        accept: Some(accept),
        workers,
    })
}

fn load_tls(tls: TlsConfig) -> Result<Arc<ServerConfig>, String> {
    let mut cert_reader = std::io::Cursor::new(tls.cert_pem);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("tls certificate: {e}"))?;
    if certs.is_empty() {
        return Err("tls certificate is empty".into());
    }
    let mut key_reader = std::io::Cursor::new(tls.key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| format!("tls key: {e}"))?
        .ok_or_else(|| "tls key is empty".to_string())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|e| format!("tls: {e}"))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("tls: {e}"))?;
    Ok(Arc::new(config))
}

fn accept_loop(
    listener: TcpListener,
    state: Arc<State>,
    tls: Option<Arc<ServerConfig>>,
    stop: Arc<AtomicBool>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    let inflight = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                if inflight.load(Ordering::Relaxed) >= MAX_WORKERS {
                    let _ = write_response(&mut &stream, 503, "unavailable", &[], b"busy");
                    continue;
                }
                inflight.fetch_add(1, Ordering::Relaxed);
                let state = Arc::clone(&state);
                let tls = tls.clone();
                let inflight = Arc::clone(&inflight);
                let handle = thread::spawn(move || {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
                    let _ = stream.set_nodelay(true);
                    if let Some(config) = tls {
                        match ServerConnection::new(config) {
                            Ok(conn) => {
                                let mut tls_stream = StreamOwned::new(conn, stream);
                                serve_stream(&mut tls_stream, &state);
                            }
                            Err(error) => {
                                eprintln!("tig-server tls handshake failed: {error}");
                            }
                        }
                    } else {
                        let mut stream = stream;
                        serve_stream(&mut stream, &state);
                    }
                    inflight.fetch_sub(1, Ordering::Relaxed);
                });
                workers
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .push(handle);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => {
                eprintln!("tig-server accept error: {error}");
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn serve_stream<S: Read + Write>(stream: &mut S, state: &State) {
    let response = match read_request(stream) {
        Ok(request) => dispatch(state, &request),
        Err(error) => {
            let too_large = error == "body is too large";
            Response {
                status: if too_large { 413 } else { 400 },
                reason: if too_large {
                    "payload too large"
                } else {
                    "bad request"
                },
                etag: None,
                body: error.into_bytes(),
                logged_method: "-".into(),
                logged_path: "-".into(),
            }
        }
    };
    eprintln!(
        "tig-server {} {} {}",
        response.logged_method, response.logged_path, response.status
    );
    let headers: Vec<(&str, String)> = response
        .etag
        .as_ref()
        .map(|etag| vec![("ETag", etag.clone())])
        .unwrap_or_default();
    let _ = write_response(
        stream,
        response.status,
        response.reason,
        &headers,
        &response.body,
    );
}

struct Incoming {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

struct Response {
    status: u16,
    reason: &'static str,
    etag: Option<String>,
    body: Vec<u8>,
    logged_method: String,
    logged_path: String,
}

fn response(
    status: u16,
    reason: &'static str,
    body: impl Into<Vec<u8>>,
    method: &str,
    path: &str,
) -> Response {
    Response {
        status,
        reason,
        etag: None,
        body: body.into(),
        logged_method: method.to_string(),
        logged_path: path.to_string(),
    }
}

fn dispatch(state: &State, request: &Incoming) -> Response {
    let method = request.method.as_str();
    let path = request.path.as_str();
    let outcome = (|| {
        if request.method.bytes().any(|b| !b.is_ascii_uppercase()) {
            return Ok(response(400, "bad request", b"method".to_vec(), method, path));
        }
        match (method, path) {
            ("GET", "/v1/info") => Ok(response(
                200,
                "ok",
                encode_info(&state.remote.remote_id()),
                method,
                path,
            )),
            ("POST", "/v1/nonce") => issue_nonce(state, method, path),
            ("POST", "/v1/objects/missing") => {
                let ids = decode_ids(&request.body, crate::limits::MAX_ID_BATCH)
                    .map_err(|e| response(400, "bad request", e.into_bytes(), method, path))?;
                let missing = state.remote.missing(&ids).map_err(backend)?;
                let body = encode_ids(&missing).map_err(|e| {
                    response(400, "bad request", e.into_bytes(), method, path)
                })?;
                Ok(response(200, "ok", body, method, path))
            }
            ("POST", "/v1/objects/get") => get_objects(state, request),
            ("POST", "/v1/objects/put") => put_objects(state, request),
            ("PUT", "/v1/packs") => put_pack(state, request),
            ("GET", "/v1/head") => get_head(state, method, path),
            ("PUT", "/v1/head") => put_head(state, request),
            ("GET", path) if path.starts_with("/v1/packs/") => get_packs(state, path),
            _ => Ok(response(404, "not found", b"not found".to_vec(), method, path)),
        }
    })();
    match outcome {
        Ok(response) => response,
        Err(response) => response,
    }
}

fn backend(error: RemoteError) -> Response {
    response(400, "bad request", error.to_string().into_bytes(), "-", "-")
}

fn issue_nonce(state: &State, method: &str, path: &str) -> Result<Response, Response> {
    let mut table = state.nonces.lock().unwrap_or_else(|p| p.into_inner());
    match table.issue(Instant::now()) {
        Ok(nonce) => Ok(response(200, "ok", nonce.to_vec(), method, path)),
        Err(()) => Ok(response(503, "unavailable", b"too many nonces".to_vec(), method, path)),
    }
}

fn get_objects(state: &State, request: &Incoming) -> Result<Response, Response> {
    let method = request.method.as_str();
    let path = request.path.as_str();
    let ids = decode_ids(&request.body, crate::limits::MAX_ID_BATCH)
        .map_err(|e| response(400, "bad request", e.into_bytes(), method, path))?;
    let found = state.remote.get_batch(&ids).map_err(backend)?;
    let view: Vec<(tig_core::ObjectId, tig_core::ObjectKind, &[u8])> = found
        .iter()
        .map(|(id, kind, body)| (*id, *kind, body.as_slice()))
        .collect();
    for (id, kind, body) in &view {
        if hash_object(*kind, body) != *id {
            return Ok(response(
                500,
                "error",
                b"stored object failed its hash".to_vec(),
                method,
                path,
            ));
        }
    }
    let body = encode_objects(&view)
        .map_err(|e| response(400, "bad request", e.into_bytes(), method, path))?;
    Ok(response(200, "ok", body, method, path))
}

fn put_objects(state: &State, request: &Incoming) -> Result<Response, Response> {
    authenticate(state, request)?;
    let objects = decode_objects(&request.body).map_err(|e| {
        response(
            400,
            "bad request",
            e.into_bytes(),
            &request.method,
            &request.path,
        )
    })?;
    let mut seen = BTreeMap::new();
    for (id, kind, body) in &objects {
        if hash_object(*kind, body) != *id {
            return Ok(response(
                400,
                "bad request",
                b"object id does not match".to_vec(),
                &request.method,
                &request.path,
            ));
        }
        if seen.insert(*id, ()).is_some() {
            return Ok(response(
                400,
                "bad request",
                b"duplicate object".to_vec(),
                &request.method,
                &request.path,
            ));
        }
    }
    state.remote.put_batch(&objects).map_err(backend)?;
    Ok(response(200, "ok", Vec::new(), &request.method, &request.path))
}

fn put_pack(state: &State, request: &Incoming) -> Result<Response, Response> {
    authenticate(state, request)?;
    state.remote.put_pack(&request.body).map_err(backend)?;
    Ok(response(200, "ok", Vec::new(), &request.method, &request.path))
}

fn get_packs(state: &State, path: &str) -> Result<Response, Response> {
    let rest = &path["/v1/packs/".len()..];
    let mut parts = rest.split('/');
    let group = parts.next().unwrap_or("");
    let epoch = parts.next().unwrap_or("");
    let pack = parts.next();
    if parts.next().is_some() || group.is_empty() || epoch.is_empty() {
        return Ok(response(400, "bad request", b"bad pack path".to_vec(), "GET", path));
    }
    wire::check_group(group)
        .map_err(|e| response(400, "bad request", e.into_bytes(), "GET", path))?;
    if !epoch.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(response(400, "bad request", b"bad epoch".to_vec(), "GET", path));
    }
    let epoch: u64 = epoch
        .parse()
        .map_err(|_| response(400, "bad request", b"bad epoch".to_vec(), "GET", path))?;
    let packs = state.remote.list_packs(group, epoch).map_err(backend)?;
    match pack {
        None => {
            let mut ids = Vec::with_capacity(packs.len());
            for bytes in &packs {
                ids.push(tig_core::ObjectId(*blake3::hash(bytes).as_bytes()));
            }
            let body = encode_ids(&ids)
                .map_err(|e| response(400, "bad request", e.into_bytes(), "GET", path))?;
            Ok(response(200, "ok", body, "GET", path))
        }
        Some(hex_id) => {
            let id: [u8; 32] = parse_fixed_hex(hex_id).ok_or_else(|| {
                response(400, "bad request", b"bad pack id".to_vec(), "GET", path)
            })?;
            for bytes in &packs {
                if *blake3::hash(bytes).as_bytes() == id {
                    return Ok(response(200, "ok", bytes.clone(), "GET", path));
                }
            }
            Ok(response(404, "not found", b"missing pack".to_vec(), "GET", path))
        }
    }
}

fn get_head(state: &State, method: &str, path: &str) -> Result<Response, Response> {
    let head = state.remote.read_head().map_err(backend)?;
    let body = encode_head(head.keyring.as_deref(), head.manifest.as_deref())
        .map_err(|e| response(500, "error", e.into_bytes(), method, path))?;
    let mut response = response(200, "ok", body, method, path);
    response.etag = Some(etag_value(&head.version()));
    Ok(response)
}

fn put_head(state: &State, request: &Incoming) -> Result<Response, Response> {
    authenticate(state, request)?;
    let expected = request
        .headers
        .get("if-match")
        .and_then(|value| parse_etag(value))
        .ok_or_else(|| {
            response(
                400,
                "bad request",
                b"If-Match required".to_vec(),
                &request.method,
                &request.path,
            )
        })?;
    let (keyring, manifest) = decode_head(&request.body).map_err(|e| {
        response(
            400,
            "bad request",
            e.into_bytes(),
            &request.method,
            &request.path,
        )
    })?;
    let _guard = state.head_lock.lock().unwrap_or_else(|p| p.into_inner());
    match state
        .remote
        .commit_head(&expected, keyring.as_deref(), manifest.as_deref())
        .map_err(backend)?
    {
        CommitOutcome::Committed(version) => {
            let mut response = response(200, "ok", Vec::new(), &request.method, &request.path);
            response.etag = Some(etag_value(&version));
            Ok(response)
        }
        CommitOutcome::Stale(head) => Ok(stale_response(&head, &request.method, &request.path)?),
    }
}

fn stale_response(head: &RemoteHead, method: &str, path: &str) -> Result<Response, Response> {
    let body = encode_head(head.keyring.as_deref(), head.manifest.as_deref())
        .map_err(|e| response(500, "error", e.into_bytes(), method, path))?;
    let mut response = response(412, "precondition failed", body, method, path);
    response.etag = Some(etag_value(&head.version()));
    Ok(response)
}

fn authenticate(state: &State, request: &Incoming) -> Result<(), Response> {
    let method = request.method.as_str();
    let path = request.path.as_str();
    let identity = request
        .headers
        .get("tig-identity")
        .and_then(|value| parse_identity(value))
        .ok_or_else(|| response(401, "unauthorized", b"identity".to_vec(), method, path))?;
    let nonce: [u8; 32] = request
        .headers
        .get("tig-nonce")
        .and_then(|value| parse_fixed_hex(value))
        .ok_or_else(|| response(401, "unauthorized", b"nonce".to_vec(), method, path))?;
    let signature: [u8; 64] = request
        .headers
        .get("tig-signature")
        .and_then(|value| parse_fixed_hex(value))
        .ok_or_else(|| response(401, "unauthorized", b"signature".to_vec(), method, path))?;
    let message = signing_message(
        &state.remote.remote_id(),
        method,
        path,
        &request.body,
        &nonce,
    );
    if verify_signature(&identity.signing, &message, &signature).is_err() {
        return Err(response(
            401,
            "unauthorized",
            b"bad signature".to_vec(),
            method,
            path,
        ));
    }
    if state
        .nonces
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .consume(&nonce, Instant::now())
        .is_err()
    {
        return Err(response(
            401,
            "unauthorized",
            b"nonce".to_vec(),
            method,
            path,
        ));
    }
    if !writer_allowed(state, &identity) {
        return Err(response(
            403,
            "forbidden",
            b"not a current member".to_vec(),
            method,
            path,
        ));
    }
    Ok(())
}

fn writer_allowed(state: &State, who: &PublicIdentity) -> bool {
    let head = match state.remote.read_head() {
        Ok(head) => head,
        Err(_) => return false,
    };
    let Some(bytes) = head.keyring else {
        return who == &state.owner;
    };
    let keyring = match Keyring::decode(&bytes) {
        Ok(keyring) => keyring,
        Err(_) => return false,
    };
    if keyring.remote != state.remote.remote_id() {
        return false;
    }
    if keyring.verify(&state.owner.signing, 0).is_err() {
        return false;
    }
    if !allowed_signers(&keyring).contains(&who.signing) {
        return false;
    }
    if who == &keyring.owner {
        return true;
    }
    let Some(&epoch) = keyring.head.epochs.get(PRIVATE_GROUP) else {
        return false;
    };
    keyring.grants.iter().any(|grant| {
        grant.context.group == PRIVATE_GROUP
            && grant.context.epoch == epoch
            && grant.recipient == *who
    })
}

fn read_request<S: Read>(stream: &mut S) -> Result<Incoming, String> {
    let (head, mut body) = read_headers(stream)?;
    let text = std::str::from_utf8(&head).map_err(|_| "headers are not utf-8".to_string())?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or_else(|| "empty request".to_string())?;
    let mut parts = request_line.split(' ');
    let method = parts
        .next()
        .ok_or_else(|| "bad request line".to_string())?
        .to_string();
    let target = parts.next().ok_or_else(|| "bad request line".to_string())?;
    let version = parts.next().ok_or_else(|| "bad request line".to_string())?;
    if parts.next().is_some() || (version != "HTTP/1.1" && version != "HTTP/1.0") {
        return Err("bad request line".into());
    }
    if target.contains('?') || !target.starts_with('/') {
        return Err("bad target".into());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "bad header".to_string())?;
        if name.is_empty() || name.bytes().any(|b| b.is_ascii_whitespace()) {
            return Err("bad header name".into());
        }
        let name = name.to_ascii_lowercase();
        if headers.insert(name, value.trim().to_string()).is_some() {
            return Err("duplicate header".into());
        }
    }
    if headers.contains_key("transfer-encoding") {
        return Err("chunked bodies are not accepted".into());
    }
    let length = match headers.get("content-length") {
        None => 0usize,
        Some(value) => {
            let length: u64 = value.parse().map_err(|_| "bad content-length".to_string())?;
            usize::try_from(length).map_err(|_| "bad content-length".to_string())?
        }
    };
    let max = max_body(&method, target);
    if length > max {
        return Err("body is too large".into());
    }
    if body.len() > length {
        return Err("body longer than content-length".into());
    }
    while body.len() < length {
        let mut buf = [0u8; 8192];
        let want = (length - body.len()).min(buf.len());
        let n = stream
            .read(&mut buf[..want])
            .map_err(|e| format!("body: {e}"))?;
        if n == 0 {
            return Err("body ended early".into());
        }
        body.extend_from_slice(&buf[..n]);
    }
    Ok(Incoming {
        method,
        path: target.to_string(),
        headers,
        body,
    })
}

fn max_body(method: &str, path: &str) -> usize {
    if method == "POST" && (path == "/v1/objects/missing" || path == "/v1/objects/get") {
        return MAX_ID_HTTP;
    }
    if method == "POST" && path == "/v1/objects/put" {
        return MAX_OBJECTS_HTTP;
    }
    if method == "PUT" && path == "/v1/packs" {
        return MAX_PACK_FILE;
    }
    // `/v1/packs/<group>/<epoch>/<id>` is five slashes; the list has four.
    if method == "GET" && path.starts_with("/v1/packs/") && path.matches('/').count() >= 5 {
        return MAX_PACK_FILE;
    }
    if path == "/v1/head" {
        return MAX_HEAD_HTTP;
    }
    if path.starts_with("/v1/packs/") {
        return MAX_ID_HTTP;
    }
    1024
}

fn read_headers<S: Read>(stream: &mut S) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).map_err(|e| format!("headers: {e}"))?;
        if n == 0 {
            return Err("connection closed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = find_header_end(&buf) {
            let body = buf[end..].to_vec();
            buf.truncate(end);
            return Ok((buf, body));
        }
        if buf.len() > MAX_HEADERS {
            return Err("headers are too large".into());
        }
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

fn write_response<S: Write>(
    stream: &mut S,
    status: u16,
    reason: &str,
    headers: &[(&str, String)],
    body: &[u8],
) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in headers {
        if value.bytes().any(|b| b == b'\r' || b == b'\n') {
            continue;
        }
        head.push_str(name);
        head.push_str(": ");
        head.push_str(value);
        head.push_str("\r\n");
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}
