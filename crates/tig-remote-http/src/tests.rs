use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use tig_core::object::hash_object;
use tig_core::{ObjectId, ObjectKind};
use tig_private::keyring::Keyring;
use tig_private::keys::{EpochKey, GroupEpoch, Identity};
use tig_private::pack::PackBuilder;
use tig_private::remote::{CommitOutcome, DirRemote, Remote};

use crate::auth::signing_message;
use crate::limits::MAX_OBJECTS_HTTP;
use crate::wire::encode_objects;
use crate::{serve, HttpRemote, MemRemote};

fn start(id: [u8; 16], owner: &Identity) -> (crate::Server, String) {
    let server = serve(
        Arc::new(MemRemote::new(id)),
        owner.public(),
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .unwrap();
    let url = format!("http://{}", server.local_addr());
    (server, url)
}

fn copy_identity(identity: &Identity) -> Identity {
    Identity::from_bytes(*identity.to_bytes())
}

fn blob(bytes: &[u8]) -> (ObjectId, ObjectKind, Vec<u8>) {
    (
        hash_object(ObjectKind::Blob, bytes),
        ObjectKind::Blob,
        bytes.to_vec(),
    )
}

#[test]
fn info_round_trip() {
    let owner = Identity::generate().unwrap();
    let id = [7u8; 16];
    let (_server, url) = start(id, &owner);
    let remote = HttpRemote::connect(&url, None).unwrap();
    assert_eq!(remote.remote_id(), id);
}

#[test]
fn objects_round_trip() {
    let owner = Identity::generate().unwrap();
    let (_server, url) = start([1u8; 16], &owner);
    let writer = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    let reader = HttpRemote::connect(&url, None).unwrap();
    let object = blob(b"hello");
    assert_eq!(writer.missing(&[object.0]).unwrap(), vec![object.0]);
    writer.put_batch(std::slice::from_ref(&object)).unwrap();
    assert!(writer.missing(&[object.0]).unwrap().is_empty());
    assert_eq!(reader.get_batch(&[object.0]).unwrap(), vec![object.clone()]);
    assert!(reader.public_store().has(&object.0).unwrap());
    assert_eq!(
        reader.public_store().get_raw(&object.0).unwrap().unwrap().1,
        b"hello"
    );
    reader
        .public_store()
        .put_raw(&object.0, object.1, &object.2)
        .unwrap_err();
}

#[test]
fn packs_round_trip() {
    let owner = Identity::generate().unwrap();
    let id = [4u8; 16];
    let (_server, url) = start(id, &owner);
    let remote = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    let key = EpochKey::generate(GroupEpoch {
        remote: id,
        group: "private".into(),
        epoch: 1,
    })
    .unwrap();
    let pack = PackBuilder::new(&key).finish().unwrap();
    remote.put_pack(&pack).unwrap();
    remote.put_pack(&pack).unwrap();
    assert_eq!(remote.list_packs("private", 1).unwrap(), vec![pack]);
    assert!(remote.list_packs("private", 2).unwrap().is_empty());
}

#[test]
fn head_auth_caps_and_interrupted_upload() {
    let id = [8u8; 16];
    let owner = Identity::generate().unwrap();
    let member = Identity::generate().unwrap();
    let stranger = Identity::generate().unwrap();
    let (server, url) = start(id, &owner);
    let remote = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();

    assert!(HttpRemote::connect(&url, None)
        .unwrap()
        .put_batch(&[blob(b"x")])
        .is_err());

    let empty = remote.read_head().unwrap();
    let (mut keyring, owner_keys) = Keyring::create(id, &owner).unwrap();
    keyring
        .grant(&owner_keys, &owner, &member.public())
        .unwrap();
    let keyring_bytes = keyring.encode().unwrap();
    let committed = remote
        .commit_head(&empty.version(), Some(&keyring_bytes), Some(b"manifest-1"))
        .unwrap();
    let CommitOutcome::Committed(version) = committed else {
        panic!("expected commit");
    };
    let head = remote.read_head().unwrap();
    assert_eq!(head.version(), version);
    assert_eq!(head.manifest.as_deref(), Some(b"manifest-1".as_slice()));

    match remote
        .commit_head(&empty.version(), None, Some(b"manifest-2"))
        .unwrap()
    {
        CommitOutcome::Stale(current) => {
            assert_eq!(current.manifest.as_deref(), Some(b"manifest-1".as_slice()));
        }
        CommitOutcome::Committed(_) => panic!("stale write must not commit"),
    }

    let object = blob(b"member-bytes");
    HttpRemote::connect(&url, Some(copy_identity(&member)))
        .unwrap()
        .put_batch(std::slice::from_ref(&object))
        .unwrap();
    assert_eq!(remote.get_batch(&[object.0]).unwrap()[0].2, b"member-bytes");

    let bad = encode_objects(&[(object.0, ObjectKind::Blob, b"tampered".as_slice())]).unwrap();
    assert_eq!(
        signed_status(&url, &owner, "POST", "/v1/objects/put", &bad),
        400
    );
    assert_eq!(
        raw_status(
            &url,
            "POST",
            "/v1/objects/put",
            &encode_objects(&[(object.0, object.1, object.2.as_slice())]).unwrap()
        ),
        401
    );
    assert_eq!(
        signed_status(
            &url,
            &stranger,
            "POST",
            "/v1/objects/put",
            &encode_objects(&[(object.0, object.1, object.2.as_slice())]).unwrap()
        ),
        403
    );
    assert_eq!(replayed_nonce_status(&url, &owner), 401);

    let too_big = format!(
        "POST /v1/objects/put HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        MAX_OBJECTS_HTTP + 1
    );
    assert_eq!(raw_bytes(&url, too_big.as_bytes()), 413);

    let head_body = crate::wire::encode_head(Some(&keyring_bytes), Some(b"nope")).unwrap();
    let mut prefix = format!(
        "PUT /v1/head HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        head_body.len()
    )
    .into_bytes();
    prefix.extend_from_slice(&head_body[..head_body.len() / 2]);
    let mut stream = TcpStream::connect(server.local_addr()).unwrap();
    stream.write_all(&prefix).unwrap();
    drop(stream);
    assert_eq!(
        remote.read_head().unwrap().manifest.as_deref(),
        Some(b"manifest-1".as_slice())
    );
    assert_eq!(remote.remote_id(), id);
}

#[test]
fn restart_keeps_the_head() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Identity::generate().unwrap();
    let id = crate::init_server_dir(dir.path(), &owner.public()).unwrap();
    let server = serve(
        Arc::new(DirRemote::open(dir.path()).unwrap()),
        owner.public(),
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .unwrap();
    let url = format!("http://{}", server.local_addr());
    let client = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    let head = client.read_head().unwrap();
    let (keyring, _) = Keyring::create(id, &owner).unwrap();
    let bytes = keyring.encode().unwrap();
    client
        .commit_head(&head.version(), Some(&bytes), Some(b"kept"))
        .unwrap();
    drop(server);

    let server = serve(
        Arc::new(DirRemote::open(dir.path()).unwrap()),
        owner.public(),
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .unwrap();
    let url = format!("http://{}", server.local_addr());
    let client = HttpRemote::connect(&url, None).unwrap();
    let head = client.read_head().unwrap();
    assert_eq!(head.keyring.as_deref(), Some(bytes.as_slice()));
    assert_eq!(head.manifest.as_deref(), Some(b"kept".as_slice()));
    assert_eq!(client.remote_id(), id);
}

#[test]
fn etag_mismatch_is_refused() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let info = crate::wire::encode_info(&[3u8; 16]);
    let head = crate::wire::encode_head(None, None).unwrap();
    std::thread::spawn(move || {
        for _ in 0..2 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let text = String::from_utf8_lossy(&buf[..n]);
            let (body, etag): (Vec<u8>, Option<String>) = if text.starts_with("GET /v1/info") {
                (info.clone(), None)
            } else {
                (head.clone(), Some(format!("\"{}\"", "ab".repeat(32))))
            };
            let mut response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n",
                body.len()
            );
            if let Some(etag) = etag {
                response.push_str("ETag: ");
                response.push_str(&etag);
                response.push_str("\r\n");
            }
            response.push_str("\r\n");
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    let remote = HttpRemote::connect(&format!("http://{addr}"), None).unwrap();
    let message = remote.read_head().unwrap_err().to_string();
    assert!(message.contains("ETag"), "{message}");
}

fn signed_status(url: &str, identity: &Identity, method: &str, path: &str, body: &[u8]) -> u16 {
    let id = HttpRemote::connect(url, None).unwrap().remote_id();
    let addr = url.trim_start_matches("http://");
    let nonce = post_nonce(addr);
    let message = signing_message(&id, method, path, body, &nonce);
    let signature = identity.sign(&message);
    let identity_header = crate::auth::format_identity(&identity.public());
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nTig-Identity: {identity_header}\r\nTig-Nonce: {}\r\nTig-Signature: {}\r\nConnection: close\r\n\r\n",
        body.len(),
        hex::encode(nonce),
        hex::encode(signature)
    );
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    raw_bytes(url, &bytes)
}

fn replayed_nonce_status(url: &str, identity: &Identity) -> u16 {
    let id = HttpRemote::connect(url, None).unwrap().remote_id();
    let addr = url.trim_start_matches("http://");
    let object = blob(b"replay");
    let body = encode_objects(&[(object.0, object.1, object.2.as_slice())]).unwrap();
    let path = "/v1/objects/put";
    let nonce = post_nonce(addr);
    let message = signing_message(&id, "POST", path, &body, &nonce);
    let signature = identity.sign(&message);
    let identity_header = crate::auth::format_identity(&identity.public());
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nTig-Identity: {identity_header}\r\nTig-Nonce: {}\r\nTig-Signature: {}\r\nConnection: close\r\n\r\n",
        body.len(),
        hex::encode(nonce),
        hex::encode(signature)
    );
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(&body);
    assert_eq!(raw_bytes(url, &bytes), 200);
    raw_bytes(url, &bytes)
}

fn post_nonce(addr: &str) -> [u8; 32] {
    let request = format!(
        "POST /v1/nonce HTTP/1.1\r\nHost: {addr}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    );
    let (status, body) = exchange(addr, request.as_bytes());
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    body.as_slice().try_into().expect("nonce length")
}

fn raw_status(url: &str, method: &str, path: &str, body: &[u8]) -> u16 {
    let addr = url.trim_start_matches("http://");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    raw_bytes(url, &bytes)
}

fn raw_bytes(url: &str, bytes: &[u8]) -> u16 {
    exchange(url.trim_start_matches("http://"), bytes).0
}

fn exchange(addr: &str, bytes: &[u8]) -> (u16, Vec<u8>) {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream.write_all(bytes).unwrap();
    let mut buf = Vec::new();
    let _ = stream.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf);
    let status = text.split_whitespace().nth(1).unwrap().parse().unwrap();
    let body = buf
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| buf[index + 4..].to_vec())
        .unwrap_or_default();
    (status, body)
}
