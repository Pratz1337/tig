//! Small HTTP/1.1 server. One request per connection, one thread per
//! connection. Writes are signed; reads are not. `PUT /v1/head` is serialized
//! in this process; the backend still compare-and-swaps.
//!
//! Every byte from the network is hostile. A connection gets
//! `HEADER_DEADLINE` for the TLS handshake and headers. Size caps are checked
//! from `Content-Length` before any body is read, and a body is buffered only
//! if its request and response working set fits the shared memory budget.
//! The reservation lasts through the response write. Bodies and responses
//! must keep up `MIN_RATE` after `TRANSFER_GRACE`, and no single read or write
//! may stall longer than `IO_TIMEOUT`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustls::{ServerConfig, ServerConnection, StreamOwned};
use tig_core::object::hash_object;
use tig_core::{ObjectId, ObjectKind};
use tig_private::keyring::Keyring;
use tig_private::keys::PublicIdentity;
use tig_private::remote::{CommitOutcome, DirRemote, Remote, RemoteError, RemoteHead};

use crate::auth::{
    parse_fixed_hex, parse_identity, signing_message, verify_signature, ConsumeError,
    ConsumedNonces, Nonce, NonceKey,
};
use crate::limits::{
    HEADER_DEADLINE, IO_TIMEOUT, MAX_BUFFERED_BODIES, MAX_HEADERS, MAX_HEADER_COUNT, MAX_HEAD_HTTP,
    MAX_ID_BATCH, MAX_ID_HTTP, MAX_LISTED_PACKS, MAX_OBJECTS_HTTP, MAX_OBJECT_BATCH,
    MAX_OBJECT_BODY, MAX_PACK_FILE, MAX_WORKERS, MIN_RATE, NONCE_TTL, OBJECTS_RESPONSE_TARGET,
    TRANSFER_GRACE,
};
use crate::wire::{
    self, check_public_kind, decode_head, decode_ids, decode_objects, encode_get_response,
    encode_head, encode_ids, encode_info, etag_value, object_len, parse_etag, varint_len,
};

/// A pack listing younger than this is reused rather than read from disk again.
const PACK_CACHE_FRESH: Duration = Duration::from_secs(2);

struct State {
    remote: Arc<dyn Remote>,
    owner: PublicIdentity,
    nonce_key: NonceKey,
    consumed: Mutex<ConsumedNonces>,
    head_lock: Mutex<()>,
    head_dir: Option<std::path::PathBuf>,
    bodies: Budget,
    packs: Mutex<PackCache>,
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
        let workers = std::mem::take(&mut *lock(&self.workers));
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

/// A poisoned lock only means another request panicked; the data is still whole.
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|p| p.into_inner())
}

/// Creates `dir` with a random remote id and records `owner` in `server-owner`.
pub fn init_server_dir(
    dir: &std::path::Path,
    owner: &PublicIdentity,
) -> Result<[u8; 16], RemoteError> {
    check_owner_key(owner)?;
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
        return Err(RemoteError::Invalid("server-owner must be 64 bytes".into()));
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

fn check_owner_key(owner: &PublicIdentity) -> Result<(), RemoteError> {
    ed25519_dalek::VerifyingKey::from_bytes(&owner.signing)
        .map(|_| ())
        .map_err(|_| RemoteError::Invalid("owner signing key is not an Ed25519 key".into()))
}

/// Serves `remote` on `listen`. Refuses to start if the stored keyring does
/// not verify against `owner`, the identity pinned when the remote was created.
pub fn serve(
    remote: Arc<dyn Remote>,
    owner: PublicIdentity,
    listen: SocketAddr,
    tls: Option<TlsConfig>,
) -> Result<Server, RemoteError> {
    serve_storage(remote, owner, listen, tls, None)
}

/// Serves directory storage, reserving head reads from the actual file sizes.
pub fn serve_dir(
    dir: &std::path::Path,
    owner: PublicIdentity,
    listen: SocketAddr,
    tls: Option<TlsConfig>,
) -> Result<Server, RemoteError> {
    serve_storage(
        Arc::new(DirRemote::open(dir)?),
        owner,
        listen,
        tls,
        Some(dir.to_path_buf()),
    )
}

fn serve_storage(
    remote: Arc<dyn Remote>,
    owner: PublicIdentity,
    listen: SocketAddr,
    tls: Option<TlsConfig>,
    head_dir: Option<std::path::PathBuf>,
) -> Result<Server, RemoteError> {
    check_owner_key(&owner)?;
    if let Some(bytes) = remote.read_head()?.keyring {
        verified_keyring(&bytes, &owner, remote.remote_id(), 0).map_err(RemoteError::Invalid)?;
    }
    let nonce_key =
        NonceKey::generate().map_err(|_| RemoteError::Invalid("no randomness".into()))?;
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
        nonce_key,
        consumed: Mutex::new(ConsumedNonces::default()),
        head_lock: Mutex::new(()),
        head_dir,
        bodies: Budget {
            used: Mutex::new(0),
            cap: MAX_BUFFERED_BODIES,
        },
        packs: Mutex::new(PackCache::default()),
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

/// rustls defaults: TLS 1.3 and 1.2 with the ring provider's safe suites,
/// no client authentication.
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

struct InflightGuard(Arc<AtomicUsize>);

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Never reads, writes or handshakes: a slow peer can only hold its own worker.
fn accept_loop(
    listener: TcpListener,
    state: Arc<State>,
    tls: Option<Arc<ServerConfig>>,
    stop: Arc<AtomicBool>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    let inflight = Arc::new(AtomicUsize::new(0));
    while !stop.load(Ordering::Relaxed) {
        lock(&workers).retain(|worker| !worker.is_finished());
        match listener.accept() {
            Ok((stream, _)) => {
                if inflight.load(Ordering::Relaxed) >= MAX_WORKERS {
                    // Dropping closes it. No reply: a reply could block, and
                    // would be plaintext on a TLS port.
                    continue;
                }
                inflight.fetch_add(1, Ordering::Relaxed);
                let guard = InflightGuard(Arc::clone(&inflight));
                let state = Arc::clone(&state);
                let tls = tls.clone();
                let spawned =
                    thread::Builder::new()
                        .name("tig-server-conn".into())
                        .spawn(move || {
                            let _guard = guard;
                            serve_connection(stream, &state, tls);
                        });
                match spawned {
                    Ok(handle) => lock(&workers).push(handle),
                    Err(error) => eprintln!("tig-server cannot start a worker: {error}"),
                }
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

fn serve_connection(stream: TcpStream, state: &State, tls: Option<Arc<ServerConfig>>) {
    // Windows hands out accepted sockets in the listener's non-blocking mode.
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let _ = stream.set_nodelay(true);
    let conn = Conn {
        socket: stream,
        deadline: Instant::now() + HEADER_DEADLINE,
    };
    match tls {
        Some(config) => match ServerConnection::new(config) {
            // The handshake runs inside the first read, under the header deadline.
            Ok(session) => serve_stream(&mut StreamOwned::new(session, conn), state),
            Err(error) => eprintln!("tig-server tls: {error}"),
        },
        None => serve_stream(&mut { conn }, state),
    }
}

/// A socket whose every read and write must finish before `deadline`.
struct Conn {
    socket: TcpStream,
    deadline: Instant,
}

impl Conn {
    fn timeout(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .map(|left| left.min(IO_TIMEOUT))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "deadline"))
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.socket.set_read_timeout(Some(self.timeout()?))?;
        self.socket.read(buf)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.socket.set_write_timeout(Some(self.timeout()?))?;
        self.socket.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.socket.flush()
    }
}

trait Transport: Read + Write {
    fn conn(&mut self) -> &mut Conn;
    fn finish(&mut self) {
        let _ = self.flush();
    }
}

impl Transport for Conn {
    fn conn(&mut self) -> &mut Conn {
        self
    }
}

impl Transport for StreamOwned<ServerConnection, Conn> {
    fn conn(&mut self) -> &mut Conn {
        &mut self.sock
    }

    fn finish(&mut self) {
        self.conn.send_close_notify();
        let _ = self.flush();
    }
}

/// Time by which `done` bytes of a transfer that began at `start` must have moved.
fn transfer_deadline(start: Instant, done: usize) -> Instant {
    start + TRANSFER_GRACE + Duration::from_secs_f64(done as f64 / MIN_RATE as f64)
}

fn serve_stream<T: Transport>(stream: &mut T, state: &State) {
    let (response, _reservation) = match handle(stream, state) {
        Ok((response, reservation)) => (response, Some(reservation)),
        Err(response) => (response, None),
    };
    eprintln!(
        "tig-server {} {} {}",
        response.logged_method, response.logged_path, response.status
    );
    let _ = write_response(stream, &response);
    stream.finish();
}

struct Incoming {
    method: String,
    path: String,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

impl Incoming {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

struct Response {
    status: u16,
    reason: &'static str,
    etag: Option<String>,
    body: Arc<Vec<u8>>,
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
        body: Arc::new(body.into()),
        logged_method: method.to_string(),
        logged_path: path.to_string(),
    }
}

fn refuse(status: u16, message: &str) -> Response {
    let reason = match status {
        400 => "bad request",
        401 => "unauthorized",
        403 => "forbidden",
        404 => "not found",
        408 => "request timeout",
        411 => "length required",
        412 => "precondition failed",
        413 => "payload too large",
        417 => "expectation failed",
        428 => "precondition required",
        431 => "request header fields too large",
        500 => "internal server error",
        501 => "not implemented",
        503 => "service unavailable",
        _ => "error",
    };
    response(status, reason, message.as_bytes().to_vec(), "-", "-")
}

fn refuse_for(status: u16, message: &str, request: &Incoming) -> Response {
    let mut out = refuse(status, message);
    out.logged_method = request.method.clone();
    out.logged_path = request.path.clone();
    out
}

/// Storage failures are logged here and reported without detail: they can
/// name server paths.
fn backend(error: RemoteError) -> Response {
    match error {
        RemoteError::Busy(_) => refuse(503, "server is busy"),
        RemoteError::Denied(_) => refuse(403, "access refused"),
        RemoteError::Io(_) | RemoteError::Core(_) => {
            eprintln!("tig-server storage error: {error}");
            refuse(500, "storage error")
        }
        other => refuse(400, &other.to_string()),
    }
}

/// Reads and checks one request. Every refusal before the body is read
/// leaves the body unread.
fn handle<'a, T: Transport>(
    stream: &mut T,
    state: &'a State,
) -> Result<(Response, Reservation<'a>), Response> {
    let (head, early) = read_head(stream)?;
    let mut request = parse_head(&head)?;
    let length = body_length(&request)?;
    if early.len() > length {
        return Err(refuse_for(400, "bytes after the body", &request));
    }
    let signed = needs_signature(&request.method, &request.path);
    let mut request_deadline = stream.conn().deadline
        + TRANSFER_GRACE
        + Duration::from_secs_f64(length as f64 / MIN_RATE as f64);
    if signed {
        // Cheap and stateless: no body is buffered for a stale or replayed nonce.
        let auth = parse_auth(state, &request).map_err(|r| relabel(r, &request))?;
        // A signed upload can never succeed after its nonce expires. Do not
        // let a fake signature plus a genuine nonce hold a worker for a much
        // longer, size-derived transfer deadline before checking the signature.
        let age_ms = state.nonce_key.now_ms().saturating_sub(auth.issued);
        let remaining_ms = (NONCE_TTL.as_millis() as u64).saturating_sub(age_ms);
        request_deadline =
            request_deadline.min(Instant::now() + Duration::from_millis(remaining_ms));
        if lock(&state.consumed).contains(auth.issued, &auth.nonce) {
            return Err(refuse_for(401, "nonce already used", &request));
        }
        if request.method == "PUT"
            && request.path == "/v1/head"
            && request.header("if-match").and_then(parse_etag).is_none()
        {
            return Err(refuse_for(428, "If-Match required", &request));
        }
    }
    // Actual declared bytes, including Vec growth and decoded/storage copies.
    let mut reservation = state
        .bodies
        .reserve(length.saturating_mul(4))
        .ok_or_else(|| refuse_for(503, "server is busy", &request))?;
    match request.header("expect") {
        None => {}
        Some(value) if value.eq_ignore_ascii_case("100-continue") => {
            stream
                .write_all(b"HTTP/1.1 100 Continue\r\n\r\n")
                .and_then(|()| stream.flush())
                .map_err(|_| refuse_for(400, "connection failed", &request))?;
        }
        Some(_) => return Err(refuse_for(417, "unsupported expectation", &request)),
    }
    request.body =
        read_body(stream, early, length, request_deadline).map_err(|r| relabel(r, &request))?;
    let out = dispatch(state, &request, &mut reservation);
    // Even small control replies stay charged until the socket write finishes.
    if request.path != "/v1/objects/get" && !reservation.grow(out.body.len()) {
        return Ok((refuse_for(503, "server is busy", &request), reservation));
    }
    Ok((out, reservation))
}

fn relabel(mut out: Response, request: &Incoming) -> Response {
    out.logged_method = request.method.clone();
    out.logged_path = request.path.clone();
    out
}

fn needs_signature(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("POST", "/v1/objects/put") | ("PUT", "/v1/packs") | ("PUT", "/v1/head")
    )
}

/// Largest body each route accepts. Anything else must have none.
fn max_body(method: &str, path: &str) -> usize {
    match (method, path) {
        ("POST", "/v1/objects/missing") | ("POST", "/v1/objects/get") => MAX_ID_HTTP,
        ("POST", "/v1/objects/put") => MAX_OBJECTS_HTTP,
        ("PUT", "/v1/packs") => MAX_PACK_FILE,
        ("PUT", "/v1/head") => MAX_HEAD_HTTP,
        _ => 0,
    }
}

/// Request line and headers, plus whatever body bytes arrived with them.
fn read_head<T: Transport>(stream: &mut T) -> Result<(Vec<u8>, Vec<u8>), Response> {
    stream.conn().deadline = Instant::now() + HEADER_DEADLINE;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 2048];
    loop {
        let n = match stream.read(&mut chunk) {
            Ok(0) => return Err(refuse(400, "connection closed")),
            Ok(n) => n,
            Err(error) if is_timeout(&error) => return Err(refuse(408, "headers took too long")),
            Err(_) => return Err(refuse(400, "connection failed")),
        };
        let from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk[..n]);
        if let Some(at) = buf[from..].windows(4).position(|w| w == b"\r\n\r\n") {
            let end = from + at + 4;
            if end > MAX_HEADERS {
                return Err(refuse(431, "headers are too large"));
            }
            let early = buf.split_off(end);
            return Ok((buf, early));
        }
        if buf.len() > MAX_HEADERS {
            return Err(refuse(431, "headers are too large"));
        }
    }
}

fn is_timeout(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    )
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// Strict HTTP/1.x: no folded lines, no bare CR or LF, no duplicate headers,
/// no percent-encoding or query in the target.
fn parse_head(head: &[u8]) -> Result<Incoming, Response> {
    let text = std::str::from_utf8(head).map_err(|_| refuse(400, "headers are not utf-8"))?;
    let text = text
        .strip_suffix("\r\n\r\n")
        .ok_or_else(|| refuse(400, "bad request"))?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(refuse(400, "bad request line"));
    };
    if method.is_empty() || method.len() > 16 || !method.bytes().all(|b| b.is_ascii_uppercase()) {
        return Err(refuse(400, "bad method"));
    }
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(refuse(400, "bad http version"));
    }
    let target_ok = target.starts_with('/')
        && target
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'?' | b'#' | b'%' | b'\\'));
    if !target_ok {
        return Err(refuse(400, "bad target"));
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(refuse(431, "too many headers"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| refuse(400, "bad header"))?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return Err(refuse(400, "bad header name"));
        }
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(refuse(400, "bad header value"));
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if headers
            .insert(name.to_ascii_lowercase(), value.to_string())
            .is_some()
        {
            return Err(refuse(400, "duplicate header"));
        }
    }
    let request = Incoming {
        method: method.to_string(),
        path: target.to_string(),
        headers,
        body: Vec::new(),
    };
    if version == "HTTP/1.1" && request.header("host").is_none_or(str::is_empty) {
        return Err(refuse_for(400, "host required", &request));
    }
    Ok(request)
}

/// Declared body length, checked against the route's cap before any body
/// byte is read. Chunked bodies are refused.
fn body_length(request: &Incoming) -> Result<usize, Response> {
    if request.headers.contains_key("transfer-encoding") {
        if request.headers.contains_key("content-length") {
            return Err(refuse_for(400, "conflicting body framing", request));
        }
        return Err(refuse_for(501, "chunked bodies are not accepted", request));
    }
    let length = match request.header("content-length") {
        None if request.method == "POST" || request.method == "PUT" => {
            return Err(refuse_for(411, "content-length required", request));
        }
        None => 0,
        Some(value) => {
            if value.is_empty() || value.len() > 20 || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(refuse_for(400, "bad content-length", request));
            }
            value
                .parse::<u64>()
                .ok()
                .and_then(|n| usize::try_from(n).ok())
                .ok_or_else(|| refuse_for(413, "body is too large", request))?
        }
    };
    if length > max_body(&request.method, &request.path) {
        return Err(refuse_for(413, "body is too large", request));
    }
    Ok(length)
}

fn read_body<T: Transport>(
    stream: &mut T,
    mut body: Vec<u8>,
    length: usize,
    deadline: Instant,
) -> Result<Vec<u8>, Response> {
    let start = Instant::now();
    // Grows with what arrives, never with what was promised.
    let mut buf = vec![0u8; 64 * 1024];
    while body.len() < length {
        stream.conn().deadline = transfer_deadline(start, body.len()).min(deadline);
        let want = (length - body.len()).min(buf.len());
        match stream.read(&mut buf[..want]) {
            Ok(0) => return Err(refuse(400, "body ended early")),
            Ok(n) => body.extend_from_slice(&buf[..n]),
            Err(error) if is_timeout(&error) => return Err(refuse(408, "body is too slow")),
            Err(_) => return Err(refuse(400, "connection failed")),
        }
    }
    Ok(body)
}

fn write_response<T: Transport>(stream: &mut T, response: &Response) -> std::io::Result<()> {
    let mut head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
        response.status,
        response.reason,
        response.body.len()
    );
    if let Some(etag) = &response.etag {
        if !etag.bytes().any(|b| b == b'\r' || b == b'\n') {
            head.push_str("ETag: ");
            head.push_str(etag);
            head.push_str("\r\n");
        }
    }
    head.push_str("\r\n");
    let start = Instant::now();
    let mut written = 0usize;
    for part in [head.as_bytes(), response.body.as_slice()] {
        for piece in part.chunks(64 * 1024) {
            stream.conn().deadline = transfer_deadline(start, written);
            stream.write_all(piece)?;
            written += piece.len();
        }
    }
    stream.conn().deadline = transfer_deadline(start, written);
    stream.flush()
}

/// Reserved working sets across all connections, including unsent responses.
struct Budget {
    used: Mutex<usize>,
    cap: usize,
}

struct Reservation<'a> {
    budget: &'a Budget,
    bytes: usize,
}

impl Budget {
    fn reserve(&self, bytes: usize) -> Option<Reservation<'_>> {
        let mut used = lock(&self.used);
        let next = used.checked_add(bytes).filter(|next| *next <= self.cap)?;
        *used = next;
        Some(Reservation {
            budget: self,
            bytes,
        })
    }
}

impl Reservation<'_> {
    fn grow(&mut self, bytes: usize) -> bool {
        let mut used = lock(&self.budget.used);
        let Some(next) = used
            .checked_add(bytes)
            .filter(|next| *next <= self.budget.cap)
        else {
            return false;
        };
        *used = next;
        self.bytes += bytes;
        true
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        let mut used = lock(&self.budget.used);
        *used = used.saturating_sub(self.bytes);
    }
}

fn dispatch(state: &State, request: &Incoming, reservation: &mut Reservation<'_>) -> Response {
    let method = request.method.as_str();
    let path = request.path.as_str();
    // Size checks and head reads/commits use the same lock, so another HTTP
    // writer cannot grow the files between the reservation and storage read.
    let uses_head = path == "/v1/head" || needs_signature(method, path);
    let _head_guard = uses_head.then(|| lock(&state.head_lock));
    if uses_head {
        if let Some(dir) = &state.head_dir {
            let size = ["keyring", "manifest", "head.pending"]
                .into_iter()
                .try_fold(0usize, |total, name| {
                    match std::fs::metadata(dir.join(name)) {
                        Ok(meta) => usize::try_from(meta.len())
                            .ok()
                            .and_then(|size| total.checked_add(size))
                            .ok_or_else(|| refuse(500, "stored head is too large")),
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(total),
                        Err(error) => Err(backend(error.into())),
                    }
                });
            match size {
                Ok(bytes) if reservation.grow(bytes.saturating_mul(4).saturating_add(64)) => {}
                Ok(_) => return refuse_for(503, "server is busy", request),
                Err(out) => return relabel(out, request),
            }
        }
    }
    let outcome = match (method, path) {
        ("GET", "/v1/info") => Ok(response(
            200,
            "ok",
            encode_info(&state.remote.remote_id()),
            method,
            path,
        )),
        ("POST", "/v1/nonce") => issue_nonce(state),
        ("POST", "/v1/objects/missing") => missing(state, request),
        ("POST", "/v1/objects/get") => get_objects(state, request, reservation),
        ("POST", "/v1/objects/put") => put_objects(state, request, reservation),
        ("PUT", "/v1/packs") => put_pack(state, request, reservation),
        ("GET", "/v1/head") => get_head(state, reservation),
        ("PUT", "/v1/head") => put_head(state, request, reservation),
        ("GET", _) if path.starts_with("/v1/packs/") => get_packs(state, path, reservation),
        _ => Err(refuse(404, "not found")),
    };
    match outcome {
        Ok(out) | Err(out) => relabel(out, request),
    }
}

fn issue_nonce(state: &State) -> Result<Response, Response> {
    let nonce = state
        .nonce_key
        .issue()
        .map_err(|()| refuse(503, "no randomness"))?;
    Ok(response(200, "ok", nonce.to_vec(), "-", "-"))
}

fn missing(state: &State, request: &Incoming) -> Result<Response, Response> {
    let ids = decode_ids(&request.body, MAX_ID_BATCH).map_err(|e| refuse(400, &e))?;
    let missing = state.remote.missing(&ids).map_err(backend)?;
    let body = encode_ids(&missing).map_err(|e| refuse(500, &e))?;
    Ok(response(200, "ok", body, "-", "-"))
}

/// Answers a prefix of the requested ids, reading one object at a time and
/// stopping near `OBJECTS_RESPONSE_TARGET`. Always answers at least one id.
fn get_objects(
    state: &State,
    request: &Incoming,
    reservation: &mut Reservation<'_>,
) -> Result<Response, Response> {
    let ids = decode_ids(&request.body, MAX_ID_BATCH).map_err(|e| refuse(400, &e))?;
    let store = state.remote.public_store();
    let mut seen = BTreeSet::new();
    let mut found: Vec<(ObjectId, ObjectKind, Vec<u8>)> = Vec::new();
    let mut size = varint_len(ids.len()) + varint_len(MAX_OBJECT_BATCH);
    if !reservation.grow(size) {
        return Err(refuse(503, "server is busy"));
    }
    let mut answered = 0;
    for id in &ids {
        if !seen.insert(*id) {
            answered += 1;
            continue;
        }
        if found.len() == MAX_OBJECT_BATCH {
            break;
        }
        let disk_size = state
            .head_dir
            .as_ref()
            .map(|dir| object_working_set(dir, id))
            .transpose()?;
        if disk_size == Some(None) {
            // A missing id is answered now, even if an upload installs it
            // before the next request. Do not read a new, unreserved file.
            answered += 1;
            continue;
        }
        if let Some(Some(bytes)) = disk_size {
            if !reservation.grow(bytes) {
                if answered == 0 {
                    return Err(refuse(503, "server is busy"));
                }
                break;
            }
        }
        let Some((kind, body)) = store
            .get_raw(id)
            .map_err(|e| backend(RemoteError::Core(e)))?
        else {
            answered += 1;
            continue;
        };
        if hash_object(kind, &body) != *id || check_public_kind(kind).is_err() {
            eprintln!(
                "tig-server stored object {} is corrupt or not public",
                id.to_hex()
            );
            return Err(refuse(500, "stored object failed its check"));
        }
        let next = size.saturating_add(object_len(body.len()));
        if !found.is_empty() && next > OBJECTS_RESPONSE_TARGET {
            break;
        }
        // Account for the stored bytes, encoded response and Vec growth.
        if disk_size.is_none() && !reservation.grow(object_len(body.len()).saturating_mul(3)) {
            if answered == 0 {
                return Err(refuse(503, "server is busy"));
            }
            break;
        }
        size = next;
        found.push((*id, kind, body));
        answered += 1;
    }
    let view: Vec<(ObjectId, ObjectKind, &[u8])> = found
        .iter()
        .map(|(id, kind, body)| (*id, *kind, body.as_slice()))
        .collect();
    let body = encode_get_response(answered, &view).map_err(|e| refuse(500, &e))?;
    Ok(response(200, "ok", body, "-", "-"))
}

/// Loose files name their decoded length in the ten-byte header. Charge both
/// compressed input and decoded/encoded copies before the backend allocates.
fn object_working_set(dir: &std::path::Path, id: &ObjectId) -> Result<Option<usize>, Response> {
    let hex = id.to_hex();
    let path = dir.join("objects").join(&hex[..2]).join(&hex[2..]);
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(backend(error.into())),
    };
    let meta = file.metadata().map_err(|error| backend(error.into()))?;
    if !meta.is_file() || meta.len() > MAX_OBJECTS_HTTP as u64 || meta.len() < 6 {
        return Err(refuse(500, "stored object failed its check"));
    }
    let mut header = [0; 6];
    file.read_exact(&mut header)
        .map_err(|error| backend(error.into()))?;
    if &header[..4] != b"TIG1" {
        return Err(refuse(500, "stored object failed its check"));
    }
    let body = match header[5] {
        0 => meta.len() as usize - 6,
        1 => {
            let mut size = [0; 4];
            file.read_exact(&mut size)
                .map_err(|error| backend(error.into()))?;
            u32::from_le_bytes(size) as usize
        }
        _ => return Err(refuse(500, "stored object failed its check")),
    };
    if body > MAX_OBJECT_BODY {
        return Err(refuse(500, "stored object failed its check"));
    }
    Ok(Some(
        (meta.len() as usize).saturating_mul(2) + object_len(body).saturating_mul(3),
    ))
}

fn put_objects(
    state: &State,
    request: &Incoming,
    reservation: &mut Reservation<'_>,
) -> Result<Response, Response> {
    authenticate(state, request, reservation)?;
    let objects = decode_objects(&request.body).map_err(|e| refuse(400, &e))?;
    let mut seen = BTreeSet::new();
    for (id, kind, body) in &objects {
        if hash_object(*kind, body) != *id {
            return Err(refuse(400, "object id does not match"));
        }
        if !seen.insert(*id) {
            return Err(refuse(400, "duplicate object"));
        }
    }
    state.remote.put_batch(&objects).map_err(backend)?;
    Ok(response(200, "ok", Vec::new(), "-", "-"))
}

fn put_pack(
    state: &State,
    request: &Incoming,
    reservation: &mut Reservation<'_>,
) -> Result<Response, Response> {
    authenticate(state, request, reservation)?;
    state.remote.put_pack(&request.body).map_err(backend)?;
    lock(&state.packs).loaded = None;
    Ok(response(200, "ok", Vec::new(), "-", "-"))
}

/// One group and epoch of pack ids. Ciphertext is read one pack at a time.
#[derive(Default)]
struct PackCache {
    key: Option<(String, u64)>,
    loaded: Option<Instant>,
    ids: Vec<[u8; 32]>,
}

fn load_pack_ids(
    state: &State,
    group: &str,
    epoch: u64,
) -> Result<Vec<[u8; 32]>, Response> {
    let mut cache = lock(&state.packs);
    let same = cache
        .key
        .as_ref()
        .is_some_and(|(g, e)| g == group && *e == epoch);
    let fresh = same
        && cache
            .loaded
            .is_some_and(|at| at.elapsed() < PACK_CACHE_FRESH);
    if !fresh {
        cache.key = None;
        cache.ids.clear();
        let ids = state.remote.list_pack_ids(group, epoch).map_err(backend)?;
        if ids.len() > MAX_LISTED_PACKS || ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(refuse(500, "stored pack listing is too large"));
        }
        cache.key = Some((group.to_string(), epoch));
        cache.loaded = Some(Instant::now());
        cache.ids = ids;
    }
    Ok(cache.ids.clone())
}

/// `/v1/packs/<group>/<epoch>` lists pack ids; `.../<pack id>` is one pack.
fn get_packs(state: &State, path: &str, reservation: &mut Reservation<'_>) -> Result<Response, Response> {
    let rest = path.strip_prefix("/v1/packs/").unwrap_or("");
    let parts: Vec<&str> = rest.split('/').collect();
    let (group, epoch, pack) = match parts.as_slice() {
        [group, epoch] => (*group, *epoch, None),
        [group, epoch, pack] => (*group, *epoch, Some(*pack)),
        _ => return Err(refuse(400, "bad pack path")),
    };
    wire::check_group(group).map_err(|e| refuse(400, &e))?;
    let canonical = !epoch.is_empty()
        && epoch.len() <= 20
        && epoch.bytes().all(|b| b.is_ascii_digit())
        && (epoch == "0" || !epoch.starts_with('0'));
    let epoch: u64 = epoch
        .parse()
        .ok()
        .filter(|_| canonical)
        .ok_or_else(|| refuse(400, "bad epoch"))?;
    match pack {
        None => {
            if !reservation.grow(MAX_ID_HTTP.saturating_mul(2)) {
                return Err(refuse(503, "server is busy"));
            }
            let ids: Vec<ObjectId> = load_pack_ids(state, group, epoch)?.into_iter().map(ObjectId).collect();
            let body = encode_ids(&ids).map_err(|e| refuse(500, &e))?;
            Ok(response(200, "ok", body, "-", "-"))
        }
        Some(hex_id) => {
            let id: [u8; 32] = parse_fixed_hex(hex_id).ok_or_else(|| refuse(400, "bad pack id"))?;
            let size = state.remote.pack_size(group, epoch, &id).map_err(backend)?.unwrap_or(MAX_PACK_FILE);
            // Loose reads can double their vector capacity; parsing also builds
            // wire-id sets and ranges, including for malformed stored packs.
            if size > MAX_PACK_FILE || !reservation.grow(size.saturating_mul(6)) {
                return Err(refuse(503, "server is busy"));
            }
            match state.remote.get_pack(group, epoch, &id).map_err(backend)? {
                Some(bytes) => {
                    if bytes.len() > size {
                        return Err(refuse(500, "stored pack changed while reading"));
                    }
                    Ok(response(200, "ok", bytes, "-", "-"))
                }
                None => Err(refuse(404, "missing pack")),
            }
        }
    }
}

fn get_head(state: &State, reservation: &mut Reservation<'_>) -> Result<Response, Response> {
    let head = read_remote_head(state, reservation)?;
    head_response(200, "ok", &head)
}

fn read_remote_head(
    state: &State,
    reservation: &mut Reservation<'_>,
) -> Result<RemoteHead, Response> {
    let head = state.remote.read_head().map_err(backend)?;
    if state.head_dir.is_none() && !reservation.grow(head_bytes(&head).saturating_mul(3)) {
        return Err(refuse(503, "server is busy"));
    }
    Ok(head)
}

fn head_bytes(head: &RemoteHead) -> usize {
    head.keyring.as_ref().map_or(0, Vec::len) + head.manifest.as_ref().map_or(0, Vec::len) + 64
}

fn head_response(
    status: u16,
    reason: &'static str,
    head: &RemoteHead,
) -> Result<Response, Response> {
    let body = encode_head(head.keyring.as_deref(), head.manifest.as_deref())
        .map_err(|e| refuse(500, &e))?;
    let mut out = response(status, reason, body, "-", "-");
    out.etag = Some(etag_value(&head.version()));
    Ok(out)
}

/// Signer authorized, then `If-Match`, then keyring rules, then the commit,
/// all under `head_lock`, so a revoke that lands first is always seen.
fn put_head(
    state: &State,
    request: &Incoming,
    reservation: &mut Reservation<'_>,
) -> Result<Response, Response> {
    let signer = authenticate(state, request, reservation)?;
    let expected = request
        .header("if-match")
        .and_then(parse_etag)
        .ok_or_else(|| refuse(428, "If-Match required"))?;
    let (keyring, manifest) = decode_head(&request.body).map_err(|e| refuse(400, &e))?;
    let current = read_remote_head(state, reservation)?;
    if current.version() != expected {
        return head_response(412, "precondition failed", &current);
    }
    if let Some(next) = keyring.as_deref() {
        if current.keyring.as_deref() != Some(next) {
            check_keyring_change(state, &signer, current.keyring.as_deref(), next)?;
        }
    }
    match state
        .remote
        .commit_head(&expected, keyring.as_deref(), manifest.as_deref())
        .map_err(backend)?
    {
        CommitOutcome::Committed(version) => {
            let head = RemoteHead {
                keyring: keyring.or(current.keyring),
                manifest: manifest.or(current.manifest),
            };
            if head.version() != version {
                return Err(refuse(500, "committed version does not match the head"));
            }
            head_response(200, "ok", &head)
        }
        CommitOutcome::Stale(head) => head_response(412, "precondition failed", &head),
    }
}

/// Accept only an authenticated extension of the current policy and grants.
/// Administrative batch actors may move a role head; transfer acceptance
/// requires the successor's signature while the root trust pin stays fixed.
fn check_keyring_change(
    state: &State,
    signer: &PublicIdentity,
    current: Option<&[u8]>,
    next: &[u8],
) -> Result<(), Response> {
    let previous = current.map(|bytes| verified_keyring(bytes, &state.owner, state.remote.remote_id(), 0))
        .transpose().map_err(|_| refuse(500, "stored keyring does not verify"))?;
    let floor = previous.as_ref().map_or(Ok(0), |ring| ring.head.counter.checked_add(1)
        .ok_or_else(|| refuse(400, "keyring counter overflow")))?;
    let proposed = verified_keyring(next, &state.owner, state.remote.remote_id(), floor)
        .map_err(|e| refuse(400, &format!("keyring refused: {e}")))?;
    let Some(previous) = previous else {
        return if signer == &state.owner && proposed.policy.is_empty() { Ok(()) }
            else { Err(refuse(403, "only the configured owner may initialize the keyring")) };
    };
    let before = previous.policy_snapshot().map_err(|_| refuse(500, "stored role policy is invalid"))?;
    let after = proposed.policy_snapshot().map_err(|_| refuse(400, "proposed role policy is invalid"))?;
    if proposed.policy.is_empty() {
        return if previous.policy.is_empty() && signer == &before.current_owner { Ok(()) }
            else { Err(refuse(403, "role policy cannot be removed")) };
    }
    if !proposed.policy.transitions.starts_with(&previous.policy.transitions)
        || proposed.policy.transitions.len() == previous.policy.transitions.len()
        || !previous.grants.iter().all(|grant| proposed.grants.contains(grant))
    {
        return Err(refuse(403, "keyring change does not extend current policy and grants"));
    }
    let baseline = if previous.policy.is_empty() {
        previous.grants.iter().map(|grant| grant.signature).collect()
    } else { previous.policy.baseline.clone() };
    if proposed.policy.baseline != baseline {
        return Err(refuse(403, "historical grant baseline cannot be changed"));
    }
    let batch = &proposed.policy.transitions[previous.policy.transitions.len()..];
    if batch.first().map(|transition| transition.counter_after) != Some(floor)
        || batch.windows(2).any(|pair| pair[1].counter_after != pair[0].counter_after
            && pair[0].counter_after.checked_add(1) != Some(pair[1].counter_after))
    {
        return Err(refuse(403, "policy batch has an unexpected counter"));
    }
    if signer == &before.current_owner || signer == &after.current_owner
        || batch.iter().any(|transition| transition.signer == signer.signing)
    { Ok(()) } else { Err(refuse(403, "request signer did not authorize this keyring change")) }

}

fn verified_keyring(
    bytes: &[u8],
    owner: &PublicIdentity,
    remote: [u8; 16],
    min_counter: u64,
) -> Result<Keyring, String> {
    let keyring = Keyring::decode(bytes).map_err(|e| e.to_string())?;
    if keyring.remote != remote {
        return Err("keyring is for a different remote".into());
    }
    if keyring.owner != *owner {
        return Err("keyring owner is not the server's owner".into());
    }
    keyring
        .verify(&owner.signing, min_counter)
        .map_err(|e| e.to_string())?;
    Ok(keyring)
}

struct Auth {
    identity: PublicIdentity,
    nonce: Nonce,
    issued: u64,
    signature: [u8; 64],
}

/// Parses the auth headers and checks the nonce's MAC and age. Signature
/// not yet checked; nothing consumed.
fn parse_auth(state: &State, request: &Incoming) -> Result<Auth, Response> {
    let identity = request
        .header("tig-identity")
        .and_then(parse_identity)
        .ok_or_else(|| refuse(401, "Tig-Identity required"))?;
    let nonce: Nonce = request
        .header("tig-nonce")
        .and_then(parse_fixed_hex)
        .ok_or_else(|| refuse(401, "Tig-Nonce required"))?;
    let signature: [u8; 64] = request
        .header("tig-signature")
        .and_then(parse_fixed_hex)
        .ok_or_else(|| refuse(401, "Tig-Signature required"))?;
    let issued = state
        .nonce_key
        .check(&nonce)
        .map_err(|()| refuse(401, "nonce is invalid or expired"))?;
    Ok(Auth {
        identity,
        nonce,
        issued,
        signature,
    })
}

/// Authenticate (signature), then authorize (owner or current member), then
/// consume the nonce. A forged request never burns a real client's nonce.
fn authenticate(
    state: &State,
    request: &Incoming,
    reservation: &mut Reservation<'_>,
) -> Result<PublicIdentity, Response> {
    let auth = parse_auth(state, request)?;
    let message = signing_message(
        &state.remote.remote_id(),
        &request.method,
        &request.path,
        &request.body,
        &auth.nonce,
        request.header("if-match"),
    );
    verify_signature(&auth.identity.signing, &message, &auth.signature)
        .map_err(|()| refuse(401, "bad signature"))?;
    let allowed = if request.path == "/v1/head" {
        head_writer_allowed(state, request, &auth.identity, reservation)?
    } else { writer_allowed(state, &auth.identity, reservation)? };
    if !allowed { return Err(refuse(403, "request signer is not authorized for this operation")); }
    lock(&state.consumed)
        .consume(auth.issued, &auth.nonce, state.nonce_key.now_ms())
        .map_err(|error| match error {
            ConsumeError::Expired => refuse(401, "nonce expired"),
            ConsumeError::Replayed => refuse(401, "nonce already used"),
            ConsumeError::Full => refuse(503, "server is busy"),
        })?;
    Ok(auth.identity)
}

/// Administrative heads may carry a valid policy transition without upload
/// permission. Transfer acceptance is signed by the new owner and conditional
/// on the exact prior head; it grants no separate object-upload permission.
fn head_writer_allowed(
    state: &State, request: &Incoming, who: &PublicIdentity,
    reservation: &mut Reservation<'_>,
) -> Result<bool, Response> {
    if writer_allowed(state, who, reservation)? { return Ok(true); }
    let current = read_remote_head(state, reservation)?;
    let (keyring, manifest) = decode_head(&request.body).map_err(|e| refuse(400, &e))?;
    let Some(next) = keyring.as_deref() else { return Ok(false); };
    if request.header("if-match").and_then(parse_etag) != Some(current.version()) { return Ok(false); }
    check_keyring_change(state, who, current.keyring.as_deref(), next)?;
    if let Some(bytes) = manifest.as_deref() {
        if current.manifest.as_deref() != Some(bytes) {
            let next = Keyring::decode(next).map_err(|_| refuse(400, "invalid keyring"))?;
            let policy = next.policy_snapshot().map_err(|_| refuse(400, "invalid role policy"))?;
            if !policy.has(who, tig_private::roles::PUBLISH) { return Ok(false); }
        }
    }
    Ok(true)
}

/// The configured owner initializes simple mode. Current grant holders can
/// publish in simple mode; role mode requires the current PUBLISH permission.
/// A former root owner receives no authority merely from the trust pin.
fn writer_allowed(
    state: &State,
    who: &PublicIdentity,
    reservation: &mut Reservation<'_>,
) -> Result<bool, Response> {
    let head = read_remote_head(state, reservation)?;
    let Some(bytes) = head.keyring else {
        return Ok(who == &state.owner);
    };
    let keyring =
        verified_keyring(&bytes, &state.owner, state.remote.remote_id(), 0).map_err(|e| {
            eprintln!("tig-server stored keyring does not verify: {e}");
            refuse(500, "stored keyring does not verify")
        })?;
    let policy = keyring.policy_snapshot().map_err(|_| refuse(500, "stored role policy is invalid"))?;
    if policy.explicit { return Ok(policy.has(who, tig_private::roles::PUBLISH)); }
    if who == &policy.current_owner { return Ok(true); }
    Ok(keyring.grants.iter().any(|grant| {
        keyring.head.epochs.get(&grant.context.group) == Some(&grant.context.epoch)
            && grant.recipient == *who
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sixteen_small_head_requests_fit_together() {
        let owner = tig_private::keys::Identity::generate().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let remote = Arc::new(DirRemote::create(dir.path(), [1; 16]).unwrap());
        let version = remote.read_head().unwrap().version();
        let state = State {
            remote,
            owner: owner.public(),
            nonce_key: NonceKey::generate().unwrap(),
            consumed: Mutex::new(ConsumedNonces::default()),
            head_lock: Mutex::new(()),
            head_dir: Some(dir.path().to_path_buf()),
            bodies: Budget {
                used: Mutex::new(0),
                cap: MAX_BUFFERED_BODIES,
            },
            packs: Mutex::new(PackCache::default()),
        };
        let barrier = std::sync::Barrier::new(16);
        thread::scope(|scope| {
            let mut workers = Vec::new();
            for i in 0..16 {
                let request = if i % 2 == 0 {
                    b"GET /v1/head HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec()
                } else {
                    let body = encode_head(None, Some(b"small")).unwrap();
                    let nonce = state.nonce_key.issue().unwrap();
                    let tag = etag_value(&version);
                    let signature = owner.sign(&signing_message(
                        &[1; 16],
                        "PUT",
                        "/v1/head",
                        &body,
                        &nonce,
                        Some(&tag),
                    ));
                    let mut request = format!("PUT /v1/head HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nIf-Match: {tag}\r\nTig-Identity: {}\r\nTig-Nonce: {}\r\nTig-Signature: {}\r\n\r\n", body.len(), crate::auth::format_identity(&owner.public()), hex::encode(nonce), hex::encode(signature)).into_bytes();
                    request.extend(body);
                    request
                };
                let state = &state;
                let barrier = &barrier;
                workers.push(scope.spawn(move || {
                    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                    let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
                    peer.write_all(&request).unwrap();
                    let mut conn = Conn {
                        socket: listener.accept().unwrap().0,
                        deadline: Instant::now() + HEADER_DEADLINE,
                    };
                    barrier.wait();
                    let result = handle(&mut conn, state);
                    // Keep all responses and their reservations alive together.
                    barrier.wait();
                    let status = match &result {
                        Ok((out, _)) | Err(out) => out.status,
                    };
                    assert!(
                        matches!(status, 200 | 412),
                        "small head request returned {status}"
                    );
                }));
            }
            for worker in workers {
                worker.join().unwrap();
            }
        });
        assert_eq!(*lock(&state.bodies.used), 0);
    }

    #[test]
    fn object_download_returns_prefix_when_budget_is_short() {
        let dir = tempfile::tempdir().unwrap();
        let remote = Arc::new(DirRemote::create(dir.path(), [1; 16]).unwrap());
        let objects: Vec<_> = [b"first".as_slice(), b"second".as_slice()]
            .into_iter()
            .map(|body| {
                (
                    hash_object(ObjectKind::Blob, body),
                    ObjectKind::Blob,
                    body.to_vec(),
                )
            })
            .collect();
        remote.put_batch(&objects).unwrap();
        let ids: Vec<_> = objects.iter().map(|(id, _, _)| *id).collect();
        let owner = tig_private::keys::Identity::generate().unwrap();
        let cap = object_working_set(dir.path(), &ids[0])
            .unwrap_or_else(|_| panic!("cannot size stored object"))
            .unwrap()
            + 16;
        let state = State {
            remote,
            owner: owner.public(),
            nonce_key: NonceKey::generate().unwrap(),
            consumed: Mutex::new(ConsumedNonces::default()),
            head_lock: Mutex::new(()),
            head_dir: Some(dir.path().to_path_buf()),
            bodies: Budget {
                used: Mutex::new(0),
                cap,
            },
            packs: Mutex::new(PackCache::default()),
        };
        let request = Incoming {
            method: "POST".into(),
            path: "/v1/objects/get".into(),
            headers: BTreeMap::new(),
            body: encode_ids(&ids).unwrap(),
        };
        let mut held = state.bodies.reserve(0).unwrap();
        let out = get_objects(&state, &request, &mut held)
            .unwrap_or_else(|out| panic!("returned {}", out.status));
        let (answered, found) = wire::decode_get_response(&out.body).unwrap();
        assert_eq!(answered, 1);
        assert_eq!(found, vec![objects[0].clone()]);
        assert!(*lock(&state.bodies.used) <= cap);
        drop(out);
        drop(held);
        assert_eq!(*lock(&state.bodies.used), 0);
    }

    #[test]
    fn response_memory_is_reserved_until_sent() {
        let owner = tig_private::keys::Identity::generate().unwrap();
        let state = State {
            remote: Arc::new(crate::MemRemote::new([1; 16])),
            owner: owner.public(),
            nonce_key: NonceKey::generate().unwrap(),
            consumed: Mutex::new(ConsumedNonces::default()),
            head_lock: Mutex::new(()),
            head_dir: None,
            bodies: Budget {
                used: Mutex::new(0),
                cap: MAX_BUFFERED_BODIES,
            },
            packs: Mutex::new(PackCache::default()),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        peer.write_all(b"GET /v1/info HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let mut conn = Conn {
            socket: listener.accept().unwrap().0,
            deadline: Instant::now() + HEADER_DEADLINE,
        };
        let held = handle(&mut conn, &state).unwrap_or_else(|_| panic!("request refused"));
        assert!(
            *lock(&state.bodies.used) > 0,
            "response lost its memory reservation"
        );
        drop(held);
        assert_eq!(*lock(&state.bodies.used), 0);
    }

    #[test]
    fn legacy_pack_reserves_memory_before_reading_ciphertext() {
        use std::fs;

        let dir = tempfile::tempdir().unwrap();
        let remote = tig_private::remote::DirRemote::create(dir.path(), [94; 16]).unwrap();
        let pack_dir = dir.path().join("packs/private/1");
        fs::create_dir_all(&pack_dir).unwrap();
        let id = [8; 32];
        let size = 17 * 1024 * 1024;
        let file = fs::File::create(pack_dir.join(format!("{}.pack", hex::encode(id)))).unwrap();
        file.set_len(size as u64).unwrap();
        drop(file);
        let owner = tig_private::keys::Identity::generate().unwrap();
        let state = State {
            remote: Arc::new(remote), owner: owner.public(),
            nonce_key: NonceKey::generate().unwrap(), consumed: Mutex::new(ConsumedNonces::default()),
            head_lock: Mutex::new(()), head_dir: Some(dir.path().to_path_buf()),
            bodies: Budget { used: Mutex::new(0), cap: size * 6 - 1 },
            packs: Mutex::new(PackCache::default()),
        };
        let mut held = state.bodies.reserve(0).unwrap();
        // Reading the deliberately invalid body would produce a backend error.
        let response = get_packs(&state, &format!("/v1/packs/private/1/{}", hex::encode(id)), &mut held)
            .err().unwrap();
        assert_eq!(response.status, 503);
        assert_eq!(*lock(&state.bodies.used), 0);
    }

    #[test]
    fn body_deadline_is_absolute_even_when_peer_keeps_sending() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let socket = listener.accept().unwrap().0;
        let sending = thread::spawn(move || {
            for _ in 0..10 {
                if peer.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(40));
            }
        });
        let begin = Instant::now();
        let mut conn = Conn {
            socket,
            deadline: begin + HEADER_DEADLINE,
        };
        let result = read_body(
            &mut conn,
            Vec::new(),
            4096,
            begin + Duration::from_millis(150),
        );
        assert_eq!(result.err().map(|r| r.status), Some(408));
        assert!(begin.elapsed() < Duration::from_secs(1));
        drop(conn);
        sending.join().unwrap();
    }

    #[test]
    fn budget_refuses_overflow_and_releases_on_drop() {
        let budget = Budget {
            used: Mutex::new(0),
            cap: 10,
        };
        let held = budget.reserve(7).unwrap();
        assert!(budget.reserve(4).is_none());
        assert!(budget.reserve(usize::MAX).is_none());
        drop(held);
        assert!(budget.reserve(10).is_some());
    }
}
