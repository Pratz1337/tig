//! Everything that touches the `tig-remote-http` API lives here, so a change
//! to the server start call or the `HttpRemote` constructor touches one spot.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::time::Duration;

use tig_private::keys::{Identity, PublicIdentity};
use tig_private::remote::Remote;
use tig_remote_http::{init_server_dir, serve_dir, HttpRemote, Server};

use super::{copy_identity, Backend};

/// A real `tig-server` on 127.0.0.1, storing into a temp directory.
pub struct HttpBackend {
    // Fields drop in order: the server stops before its storage is deleted.
    server: Option<Server>,
    owner: PublicIdentity,
    addr: SocketAddr,
    dir: tempfile::TempDir,
}

impl HttpBackend {
    /// `tig-server init --owner` then `serve` on an ephemeral port.
    pub fn new(owner: &Identity) -> Self {
        let dir = tempfile::tempdir().unwrap();
        init_server_dir(dir.path(), &owner.public()).unwrap();
        let server = start(dir.path(), &owner.public(), "127.0.0.1:0".parse().unwrap());
        HttpBackend {
            addr: server.local_addr(),
            dir,
            owner: owner.public(),
            server: Some(server),
        }
    }

    /// Stops the server and joins its threads. Committed state stays on disk.
    pub fn stop(&mut self) {
        if let Some(mut server) = self.server.take() {
            server.shutdown();
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Starts a new server (fresh nonce key, empty caches) on the same storage
    /// directory and port, so existing `HttpRemote`s point at it.
    pub fn restart(&mut self) {
        self.stop();
        self.server = Some(start(self.dir.path(), &self.owner, self.addr));
    }
}

fn start(dir: &Path, owner: &PublicIdentity, listen: SocketAddr) -> Server {
    serve_dir(dir, *owner, listen, None).unwrap()
}

impl Backend for HttpBackend {
    fn name(&self) -> &'static str {
        "http"
    }

    fn connect(&self, identity: Option<&Identity>) -> Box<dyn Remote> {
        Box::new(HttpRemote::connect(&self.url(), identity.map(copy_identity)).unwrap())
    }
}

/// One raw HTTP/1.1 exchange: status and body.
pub fn raw(addr: SocketAddr, method: &str, path: &str, headers: &[(&str, String)]) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("not an HTTP response: {text:?}"));
    let body = text.split_once("\r\n\r\n").map_or("", |(_, body)| body);
    (status, body.to_string())
}

/// A write nonce issued by the server now running on `addr`.
pub fn nonce(addr: SocketAddr) -> Vec<u8> {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let request =
        format!("POST /v1/nonce HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    let split = response
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("nonce response has headers");
    assert!(response.starts_with(b"HTTP/1.1 200"), "nonce request failed");
    response[split + 4..].to_vec()
}

/// A signed-write request carrying `nonce` and a junk signature. The server
/// checks the nonce before the signature, so the refusal names which failed.
pub fn write_with_nonce(addr: SocketAddr, who: &PublicIdentity, nonce: &[u8]) -> (u16, String) {
    let mut identity = Vec::with_capacity(64);
    identity.extend_from_slice(&who.encryption);
    identity.extend_from_slice(&who.signing);
    raw(
        addr,
        "POST",
        "/v1/objects/put",
        &[
            ("Content-Type", "application/octet-stream".to_string()),
            ("Tig-Identity", hex(&identity)),
            ("Tig-Nonce", hex(nonce)),
            ("Tig-Signature", hex(&[0u8; 64])),
        ],
    )
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
