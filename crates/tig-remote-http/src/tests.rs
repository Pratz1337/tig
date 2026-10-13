use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use tig_core::object::hash_object;
use tig_core::{ObjectId, ObjectKind};
use tig_private::keyring::Keyring;
use tig_private::keys::{EpochKey, GroupEpoch, Identity};
use tig_private::pack::PackBuilder;
use tig_private::remote::{CommitOutcome, Remote};

use crate::auth::signing_message;
use crate::limits::MAX_OBJECTS_HTTP;
use crate::wire::encode_objects;
use crate::{serve, serve_dir, HttpRemote, MemRemote};

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
    let server = serve_dir(
        dir.path(),
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

    let server = serve_dir(
        dir.path(),
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
    let message = signing_message(&id, method, path, body, &nonce, None);
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
    let message = signing_message(&id, "POST", path, &body, &nonce, None);
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

fn post_nonce(addr: &str) -> crate::auth::Nonce {
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

fn signed_request(
    id: [u8; 16],
    identity: &Identity,
    method: &str,
    path: &str,
    body: &[u8],
    nonce: &crate::auth::Nonce,
    if_match: Option<&str>,
) -> Vec<u8> {
    let message = signing_message(&id, method, path, body, nonce, if_match);
    let mut request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\nTig-Identity: {}\r\nTig-Nonce: {}\r\nTig-Signature: {}\r\n",
        body.len(), crate::auth::format_identity(&identity.public()),
        hex::encode(nonce), hex::encode(identity.sign(&message)),
    );
    if let Some(value) = if_match {
        request.push_str(&format!("If-Match: {value}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    let mut bytes = request.into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

#[test]
fn forged_signature_cannot_burn_nonce_and_replay_is_atomic() {
    let owner = Identity::generate().unwrap();
    let id = [11; 16];
    let (_server, url) = start(id, &owner);
    let object = blob(b"authenticated bytes");
    let body = encode_objects(&[(object.0, object.1, object.2.as_slice())]).unwrap();
    let nonce = post_nonce(url.trim_start_matches("http://"));
    let valid = signed_request(id, &owner, "POST", "/v1/objects/put", &body, &nonce, None);
    let mut forged = valid.clone();
    *forged.last_mut().unwrap() ^= 1; // Signature still covers the original bytes.
    assert_eq!(raw_bytes(&url, &forged), 401);
    let tasks: Vec<_> = (0..2)
        .map(|_| {
            let url = url.clone();
            let valid = valid.clone();
            std::thread::spawn(move || raw_bytes(&url, &valid))
        })
        .collect();
    let mut statuses: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
    statuses.sort();
    assert_eq!(statuses, [200, 401]);
}

#[test]
fn unauthorized_valid_signature_cannot_burn_owner_nonce() {
    let owner = Identity::generate().unwrap();
    let outsider = Identity::generate().unwrap();
    let id = [24; 16];
    let (_server, url) = start(id, &owner);
    let object = blob(b"owner write");
    let body = encode_objects(&[(object.0, object.1, object.2.as_slice())]).unwrap();
    let nonce = post_nonce(url.trim_start_matches("http://"));
    let refused = signed_request(
        id,
        &outsider,
        "POST",
        "/v1/objects/put",
        &body,
        &nonce,
        None,
    );
    assert_eq!(raw_bytes(&url, &refused), 403);
    let allowed = signed_request(id, &owner, "POST", "/v1/objects/put", &body, &nonce, None);
    assert_eq!(raw_bytes(&url, &allowed), 200);
}

#[test]
fn first_commit_owner_pin_and_member_revocation() {
    let owner = Identity::generate().unwrap();
    let member = Identity::generate().unwrap();
    let id = [12; 16];
    let (_server, url) = start(id, &owner);
    let writer = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    let empty = writer.read_head().unwrap();
    let nonce = post_nonce(url.trim_start_matches("http://"));
    let first = crate::wire::encode_head(None, Some(b"takeover")).unwrap();
    assert_eq!(
        raw_bytes(
            &url,
            &signed_request(
                id,
                &member,
                "PUT",
                "/v1/head",
                &first,
                &nonce,
                Some(&crate::wire::etag_value(&empty.version()))
            )
        ),
        403
    );
    assert_eq!(writer.read_head().unwrap(), empty);

    let (mut ring, mut keys) = Keyring::create(id, &owner).unwrap();
    ring.grant(&keys, &owner, &member.public()).unwrap();
    writer
        .commit_head(
            &empty.version(),
            Some(&ring.encode().unwrap()),
            Some(b"owner"),
        )
        .unwrap();
    let contributor = HttpRemote::connect(&url, Some(copy_identity(&member))).unwrap();
    contributor.put_batch(&[blob(b"before revoke")]).unwrap();
    let before = contributor.read_head().unwrap();
    contributor
        .commit_head(&before.version(), None, Some(b"member"))
        .unwrap();
    let key = ring
        .verify(&owner.public().signing, 0)
        .unwrap()
        .current_key("private", &member)
        .unwrap();
    let pack = PackBuilder::new(&key).finish().unwrap();
    contributor.put_pack(&pack).unwrap();
    ring.revoke(&mut keys, &owner, &member.public()).unwrap();
    let old = writer.read_head().unwrap();
    writer
        .commit_head(
            &old.version(),
            Some(&ring.encode().unwrap()),
            Some(b"revoked"),
        )
        .unwrap();
    let now = writer.read_head().unwrap();
    let object = blob(b"after revoke");
    let objects = encode_objects(&[(object.0, object.1, object.2.as_slice())]).unwrap();
    let head = crate::wire::encode_head(None, Some(b"unauthorized")).unwrap();
    for (method, path, bytes, lease) in [
        ("POST", "/v1/objects/put", objects.as_slice(), None),
        ("PUT", "/v1/packs", pack.as_slice(), None),
        (
            "PUT",
            "/v1/head",
            head.as_slice(),
            Some(crate::wire::etag_value(&now.version())),
        ),
    ] {
        let nonce = post_nonce(url.trim_start_matches("http://"));
        assert_eq!(
            raw_bytes(
                &url,
                &signed_request(id, &member, method, path, bytes, &nonce, lease.as_deref())
            ),
            403,
            "{path}"
        );
    }
    assert_eq!(writer.read_head().unwrap(), now);
    assert!(writer.get_batch(&[object.0]).unwrap().is_empty());
}

#[test]
fn keyring_tampering_and_rollback_leave_head_unchanged() {
    let owner = Identity::generate().unwrap();
    let member = Identity::generate().unwrap();
    let stranger = Identity::generate().unwrap();
    let id = [13; 16];
    let (_server, url) = start(id, &owner);
    let remote = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    let empty = remote.read_head().unwrap();
    assert!(remote
        .commit_head(&empty.version(), Some(b"invalid"), None)
        .is_err());
    let (mut ring, keys) = Keyring::create(id, &owner).unwrap();
    let initial = ring.encode().unwrap();
    ring.grant(&keys, &owner, &member.public()).unwrap();
    remote
        .commit_head(
            &empty.version(),
            Some(&ring.encode().unwrap()),
            Some(b"kept"),
        )
        .unwrap();
    let head = remote.read_head().unwrap();
    let contributor = HttpRemote::connect(&url, Some(copy_identity(&member))).unwrap();
    assert!(contributor
        .commit_head(&head.version(), Some(b"invalid"), None)
        .is_err());
    assert!(remote
        .commit_head(&head.version(), Some(&initial), None)
        .is_err());
    let mut bad_head = ring.clone();
    bad_head.head.counter += 1;
    let mut bad_grant = ring.clone();
    bad_grant.grants[0].signature[0] ^= 1;
    let (foreign_owner, _) = Keyring::create(id, &stranger).unwrap();
    let (foreign_remote, _) = Keyring::create([14; 16], &owner).unwrap();
    for bad in [bad_head, bad_grant, foreign_owner, foreign_remote] {
        assert!(remote
            .commit_head(&head.version(), Some(&bad.encode().unwrap()), None)
            .is_err());
        assert_eq!(remote.read_head().unwrap(), head);
    }
    remote.put_batch(&[blob(b"still serves")]).unwrap();
}

#[test]
fn if_match_is_authenticated_and_stale_is_412() {
    let owner = Identity::generate().unwrap();
    let id = [15; 16];
    let (_server, url) = start(id, &owner);
    let remote = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    let empty = remote.read_head().unwrap();
    remote
        .commit_head(&empty.version(), None, Some(b"first"))
        .unwrap();
    let current = remote.read_head().unwrap();
    let old_tag = crate::wire::etag_value(&empty.version());
    let tag = crate::wire::etag_value(&current.version());
    let body = crate::wire::encode_head(None, Some(b"second")).unwrap();
    let nonce = post_nonce(url.trim_start_matches("http://"));
    let signed = signed_request(id, &owner, "PUT", "/v1/head", &body, &nonce, Some(&tag));
    let mut tampered = String::from_utf8(signed.clone())
        .unwrap()
        .replace(&tag, &old_tag)
        .into_bytes();
    assert_eq!(raw_bytes(&url, &tampered), 401);
    assert_eq!(raw_bytes(&url, &signed), 200);
    let nonce = post_nonce(url.trim_start_matches("http://"));
    tampered = signed_request(id, &owner, "PUT", "/v1/head", &body, &nonce, Some(&old_tag));
    let (status, bytes) = exchange(url.trim_start_matches("http://"), &tampered);
    assert_eq!(status, 412);
    assert_eq!(
        crate::wire::decode_head(&bytes).unwrap().1.as_deref(),
        Some(b"second".as_slice())
    );
}

#[test]
fn header_flood_framing_and_caps_are_rejected_before_body() {
    let owner = Identity::generate().unwrap();
    let (_server, url) = start([16; 16], &owner);
    let mut flood = "GET /v1/info HTTP/1.1\r\nHost: localhost\r\n".to_string();
    for n in 0..65 {
        flood.push_str(&format!("X-{n}: a\r\n"));
    }
    flood.push_str("\r\n");
    assert_eq!(raw_bytes(&url, flood.as_bytes()), 431);
    let huge = format!(
        "GET /v1/info HTTP/1.1\r\nHost: localhost\r\nX: {}\r\n\r\n",
        "a".repeat(crate::limits::MAX_HEADERS)
    );
    assert_eq!(raw_bytes(&url, huge.as_bytes()), 431);
    for headers in [
        "Content-Length: 0\r\ncontent-length: 1\r\n",
        "Content-Length: 0\r\nContent-Length: 0\r\n",
        "Content-Length: +0\r\n",
        "Content-Length: 0, 0\r\n",
        "Content-Length: -1\r\n",
        "Content-Length: 18446744073709551616\r\n",
        "Bad(Name): a\r\n",
        "X: a\x01b\r\n",
        "X: a\nInjected: b\r\n",
        " X: folded\r\n",
        "Content-Length: 0\r\nTransfer-Encoding: chunked\r\n",
    ] {
        let bytes = format!("POST /v1/nonce HTTP/1.1\r\nHost: localhost\r\n{headers}\r\n");
        let expected = if headers.contains("18446744073709551616") {
            413
        } else {
            400
        };
        assert_eq!(raw_bytes(&url, bytes.as_bytes()), expected, "{headers:?}");
    }
    assert_eq!(
        raw_bytes(
            &url,
            b"POST /v1/nonce HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
        ),
        501
    );
    assert_eq!(
        raw_bytes(&url, b"POST /v1/nonce HTTP/1.1\r\nHost: localhost\r\n\r\n"),
        411
    );
    for (method, path, cap) in [
        ("POST", "/v1/objects/get", crate::limits::MAX_ID_HTTP),
        ("POST", "/v1/objects/put", crate::limits::MAX_OBJECTS_HTTP),
        ("PUT", "/v1/packs", crate::limits::MAX_PACK_FILE),
        ("PUT", "/v1/head", crate::limits::MAX_HEAD_HTTP),
    ] {
        // Keep the connection open and send no body. A reply proves an early refusal.
        let bytes = format!(
            "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            cap + 1
        );
        assert_eq!(raw_bytes(&url, bytes.as_bytes()), 413, "{path}");
    }
}

#[test]
fn pack_paths_are_canonical_and_cannot_traverse() {
    let owner = Identity::generate().unwrap();
    let (_server, url) = start([17; 16], &owner);
    for suffix in [
        "../1",
        "private/../keyring",
        "%2e%2e/1",
        "private%2f../1",
        "private/01",
        "private/+1",
        "private/-1",
        "private/18446744073709551616",
        "private//1",
        "private/1/../keyring",
        "private/1/%00",
        "private/1/aa",
        "private/1?x",
        "PRIVATE/1",
        "private\\x/1",
        "private/1/",
        "private/1/aa/extra",
    ] {
        let bytes = format!("GET /v1/packs/{suffix} HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert_eq!(raw_bytes(&url, bytes.as_bytes()), 400, "{suffix}");
    }
    assert_eq!(
        raw_status(&url, "GET", "/v1/packs/private/18446744073709551615", &[]),
        200
    );
}

#[test]
fn authenticated_interrupted_upload_preserves_head_and_nonce() {
    let owner = Identity::generate().unwrap();
    let id = [18; 16];
    let (server, url) = start(id, &owner);
    let remote = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    let empty = remote.read_head().unwrap();
    remote
        .commit_head(&empty.version(), None, Some(b"kept"))
        .unwrap();
    let before = remote.read_head().unwrap();
    let body = crate::wire::encode_head(None, Some(b"fully authenticated replacement")).unwrap();
    let nonce = post_nonce(url.trim_start_matches("http://"));
    let bytes = signed_request(
        id,
        &owner,
        "PUT",
        "/v1/head",
        &body,
        &nonce,
        Some(&crate::wire::etag_value(&before.version())),
    );
    let mut stream = TcpStream::connect(server.local_addr()).unwrap();
    stream
        .write_all(&bytes[..bytes.len() - body.len() / 2])
        .unwrap();
    stream.shutdown(std::net::Shutdown::Write).unwrap();
    let mut refused = Vec::new();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream.read_to_end(&mut refused).unwrap();
    assert!(refused.starts_with(b"HTTP/1.1 400"));
    assert_eq!(remote.read_head().unwrap(), before);
    assert_eq!(raw_bytes(&url, &bytes), 200); // Interrupted body never consumed the nonce.
    assert_eq!(
        remote.read_head().unwrap().manifest.as_deref(),
        Some(b"fully authenticated replacement".as_slice())
    );
}

#[test]
fn slow_client_does_not_block_other_requests_and_times_out() {
    let owner = Identity::generate().unwrap();
    let (server, url) = start([19; 16], &owner);
    let mut slow = TcpStream::connect(server.local_addr()).unwrap();
    slow.write_all(b"GET /v1/info HTTP/1.1\r\nHost:").unwrap();
    let begin = std::time::Instant::now();
    assert_eq!(
        HttpRemote::connect(&url, None).unwrap().remote_id(),
        [19; 16]
    );
    assert!(begin.elapsed() < Duration::from_secs(2));
    slow.set_read_timeout(Some(Duration::from_secs(8))).unwrap();
    let mut reply = Vec::new();
    slow.read_to_end(&mut reply).unwrap();
    assert!(reply.starts_with(b"HTTP/1.1 408"));
}

#[test]
fn header_trickle_cannot_extend_total_request_deadline() {
    let owner = Identity::generate().unwrap();
    let (server, _url) = start([23; 16], &owner);
    let mut stream = TcpStream::connect(server.local_addr()).unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    stream
        .write_all(b"GET /v1/info HTTP/1.1\r\nHost: localhost\r\nX: ")
        .unwrap();
    let begin = std::time::Instant::now();
    for _ in 0..120 {
        if stream.write_all(b"a").is_err() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    assert!(response.starts_with(b"HTTP/1.1 408"));
    assert!(begin.elapsed() < Duration::from_secs(13));
}

fn peer_response(status: u16, body: &[u8], headers: &str) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} Reply\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n",
        body.len(),
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

/// Real sockets with deliberately dishonest replies. Consume each request
/// before replying so a reset cannot be confused with protocol rejection.
type CapturedRequests = Arc<std::sync::Mutex<Vec<Vec<u8>>>>;

fn malicious_peer(replies: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<()>) {
    let (url, worker, _) = observing_peer(replies);
    (url, worker)
}

fn observing_peer(
    mut replies: Vec<Vec<u8>>,
) -> (String, std::thread::JoinHandle<()>, CapturedRequests) {
    replies.insert(
        0,
        peer_response(200, &crate::wire::encode_info(&[3; 16]), ""),
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = Arc::clone(&requests);
    let worker = std::thread::spawn(move || {
        for reply in replies {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut incoming = Vec::new();
            let end = loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).unwrap();
                incoming.push(byte[0]);
                if incoming.ends_with(b"\r\n\r\n") {
                    break incoming.len();
                }
            };
            let text = String::from_utf8_lossy(&incoming);
            let length = text
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    key.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            incoming.resize(end + length, 0);
            stream.read_exact(&mut incoming[end..]).unwrap();
            captured.lock().unwrap().push(incoming);
            let _ = stream.write_all(&reply);
        }
    });
    (url, worker, requests)
}

#[test]
fn client_retries_busy_reads_and_reports_typed_refusals() {
    use tig_private::remote::{RemoteError, RemoteHead};
    let head = RemoteHead {
        keyring: None,
        manifest: Some(b"small".to_vec()),
    };
    let body = crate::wire::encode_head(None, head.manifest.as_deref()).unwrap();
    let headers = format!("ETag: {}\r\n", crate::wire::etag_value(&head.version()));
    let (url, worker) = malicious_peer(vec![
        peer_response(503, b"busy", "Retry-After: 1\r\n"),
        peer_response(200, &body, &headers),
    ]);
    let remote = HttpRemote::connect(&url, None).unwrap();
    let begin = std::time::Instant::now();
    assert_eq!(remote.read_head().unwrap().version(), head.version());
    assert!(begin.elapsed() >= Duration::from_secs(1));
    worker.join().unwrap();

    let (url, worker) = malicious_peer((0..4).map(|_| peer_response(503, b"busy", "")).collect());
    assert!(matches!(
        HttpRemote::connect(&url, None).unwrap().read_head(),
        Err(RemoteError::Busy(_))
    ));
    worker.join().unwrap();
    for status in [401, 403] {
        let (url, worker) = malicious_peer(vec![peer_response(status, b"refused", "")]);
        assert!(matches!(
            HttpRemote::connect(&url, None).unwrap().read_head(),
            Err(RemoteError::Denied(_))
        ));
        worker.join().unwrap();
    }
    // A proxy refusal must remain typed even when it exceeds the info cap.
    for status in [401, 403, 503] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let worker = std::thread::spawn(move || {
            for _ in 0..if status == 503 { 4 } else { 1 } {
                let (mut stream, _) = listener.accept().unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    stream.read_exact(&mut byte).unwrap();
                    headers.push(byte[0]);
                }
                stream
                    .write_all(&peer_response(status, &[b'x'; 1024], ""))
                    .unwrap();
            }
        });
        let error = HttpRemote::connect(&url, None).err().unwrap();
        assert!(matches!(
            error,
            RemoteError::Denied(_) | RemoteError::Busy(_)
        ));
        worker.join().unwrap();
    }
}

#[test]
fn client_retries_conditional_commit_and_uploads_with_new_nonces() {
    use tig_private::remote::RemoteHead;
    let owner = Identity::generate().unwrap();
    let empty = RemoteHead {
        keyring: None,
        manifest: None,
    };
    let next = RemoteHead {
        keyring: None,
        manifest: Some(b"small".to_vec()),
    };
    let body = crate::wire::encode_head(None, next.manifest.as_deref()).unwrap();
    let headers = format!("ETag: {}\r\n", crate::wire::etag_value(&next.version()));
    let (url, worker, requests) = observing_peer(vec![
        peer_response(200, &[1; crate::auth::NONCE_LEN], ""),
        peer_response(503, b"busy", ""),
        peer_response(200, &[2; crate::auth::NONCE_LEN], ""),
        peer_response(200, &body, &headers),
    ]);
    let remote = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    assert!(matches!(
        remote
            .commit_head(&empty.version(), None, Some(b"small"))
            .unwrap(),
        CommitOutcome::Committed(_)
    ));
    worker.join().unwrap();
    let requests = requests.lock().unwrap();
    let header = |request: &[u8], name: &str| {
        String::from_utf8_lossy(request)
            .lines()
            .find_map(|line| line.strip_prefix(name).map(str::to_string))
            .unwrap()
    };
    assert_ne!(
        header(&requests[2], "Tig-Nonce: "),
        header(&requests[4], "Tig-Nonce: ")
    );
    assert_ne!(
        header(&requests[2], "Tig-Signature: "),
        header(&requests[4], "Tig-Signature: ")
    );
    assert_eq!(
        header(&requests[2], "If-Match: "),
        header(&requests[4], "If-Match: ")
    );
    let (url, worker) = malicious_peer(vec![
        peer_response(503, b"busy", ""), // nonce issuance itself is transient
        peer_response(200, &[1; crate::auth::NONCE_LEN], ""),
        peer_response(503, b"busy", ""),
        peer_response(200, &[2; crate::auth::NONCE_LEN], ""),
        peer_response(200, &[], ""),
    ]);
    HttpRemote::connect(&url, Some(copy_identity(&owner)))
        .unwrap()
        .put_batch(&[blob(b"small")])
        .unwrap();
    worker.join().unwrap();
}

#[test]
fn client_retries_disconnects_only_for_gets_before_response() {
    let body = crate::wire::encode_head(None, None).unwrap();
    let head = tig_private::remote::RemoteHead {
        keyring: None,
        manifest: None,
    };
    let headers = format!("ETag: {}\r\n", crate::wire::etag_value(&head.version()));
    let (url, worker) = malicious_peer(vec![Vec::new(), peer_response(200, &body, &headers)]);
    HttpRemote::connect(&url, None)
        .unwrap()
        .read_head()
        .unwrap();
    worker.join().unwrap();

    let (url, worker, requests) = observing_peer(vec![Vec::new()]);
    assert!(HttpRemote::connect(&url, None)
        .unwrap()
        .get_batch(&[blob(b"x").0])
        .is_err());
    worker.join().unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);

    // Headers were received, but the body was truncated: no GET retry.
    let (url, worker, requests) = observing_peer(vec![
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nx".to_vec(),
    ]);
    assert!(HttpRemote::connect(&url, None)
        .unwrap()
        .read_head()
        .is_err());
    worker.join().unwrap();
    assert_eq!(requests.lock().unwrap().len(), 2);
}

#[test]
fn client_rejects_unrequested_duplicate_corrupt_and_impossible_objects() {
    let a = blob(b"a");
    let b = blob(b"b");
    let views = [
        vec![(b.0, b.1, b.2.as_slice())],
        vec![(a.0, a.1, a.2.as_slice()), (a.0, a.1, a.2.as_slice())],
        vec![(a.0, a.1, b.2.as_slice())],
    ];
    for objects in views {
        let body = crate::wire::encode_get_response(1, &objects).unwrap();
        let (url, worker) = malicious_peer(vec![peer_response(200, &body, "")]);
        let remote = HttpRemote::connect(&url, None).unwrap();
        assert!(remote.get_batch(&[a.0]).is_err());
        worker.join().unwrap();
    }
    for answered in [0, 2] {
        let body = crate::wire::encode_get_response(answered, &[]).unwrap();
        let (url, worker) = malicious_peer(vec![peer_response(200, &body, "")]);
        assert!(HttpRemote::connect(&url, None)
            .unwrap()
            .get_batch(&[a.0])
            .is_err());
        worker.join().unwrap();
    }
}

#[test]
fn client_rejects_unrequested_and_duplicate_missing_ids() {
    let a = blob(b"a").0;
    let b = blob(b"b").0;
    for ids in [vec![blob(b"unrequested").0], vec![a, a]] {
        let body = crate::wire::encode_ids(&ids).unwrap();
        let (url, worker) = malicious_peer(vec![peer_response(200, &body, "")]);
        assert!(HttpRemote::connect(&url, None)
            .unwrap()
            .missing(&[a, b])
            .is_err());
        worker.join().unwrap();
    }
}

#[test]
fn client_checks_pack_hash_context_and_listing_order() {
    let owner = Identity::generate().unwrap();
    let key = EpochKey::generate(GroupEpoch {
        remote: [3; 16],
        group: "private".into(),
        epoch: 1,
    })
    .unwrap();
    let pack = PackBuilder::new(&key).finish().unwrap();
    let id = ObjectId(*blake3::hash(&pack).as_bytes());
    let listing = crate::wire::encode_ids(&[id]).unwrap();
    let (url, worker) = malicious_peer(vec![
        peer_response(200, &listing, ""),
        peer_response(200, b"wrong bytes", ""),
    ]);
    assert!(HttpRemote::connect(&url, None)
        .unwrap()
        .list_packs("private", 1)
        .is_err());
    worker.join().unwrap();
    let duplicate = crate::wire::encode_ids(&[id, id]).unwrap();
    // A duplicate may be detected after the first pack is downloaded.
    let (url, worker) = malicious_peer(vec![
        peer_response(200, &duplicate, ""),
        peer_response(200, &pack, ""),
    ]);
    assert!(HttpRemote::connect(&url, None)
        .unwrap()
        .list_packs("private", 1)
        .is_err());
    worker.join().unwrap();
    for context in [
        GroupEpoch {
            remote: [4; 16],
            group: "private".into(),
            epoch: 1,
        },
        GroupEpoch {
            remote: [3; 16],
            group: "other".into(),
            epoch: 1,
        },
        GroupEpoch {
            remote: [3; 16],
            group: "private".into(),
            epoch: 2,
        },
    ] {
        let key = EpochKey::generate(context).unwrap();
        let pack = PackBuilder::new(&key).finish().unwrap();
        let listing =
            crate::wire::encode_ids(&[ObjectId(*blake3::hash(&pack).as_bytes())]).unwrap();
        let (url, worker) = malicious_peer(vec![
            peer_response(200, &listing, ""),
            peer_response(200, &pack, ""),
        ]);
        assert!(HttpRemote::connect(&url, Some(copy_identity(&owner)))
            .unwrap()
            .list_packs("private", 1)
            .is_err());
        worker.join().unwrap();
    }
}

#[test]
fn client_bounds_declared_and_chunked_responses() {
    let object = blob(b"x");
    for response in [
        format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            crate::limits::MAX_ID_HTTP + 1
        )
        .into_bytes(),
        // No Content-Length: the streaming cap must still apply.
        {
            let body = vec![0; crate::limits::MAX_ID_HTTP + 1];
            let mut response = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n", body.len()).into_bytes();
            response.extend_from_slice(&body);
            response.extend_from_slice(b"\r\n0\r\n\r\n");
            response
        },
    ] {
        let (url, worker) = malicious_peer(vec![response]);
        assert!(HttpRemote::connect(&url, None)
            .unwrap()
            .missing(&[object.0])
            .is_err());
        worker.join().unwrap();
    }
}

#[test]
fn client_pack_listing_has_an_aggregate_byte_cap() {
    let key = EpochKey::generate(GroupEpoch {
        remote: [3; 16],
        group: "private".into(),
        epoch: 1,
    })
    .unwrap();
    let pack = PackBuilder::new(&key).finish().unwrap();
    let id = ObjectId(*blake3::hash(&pack).as_bytes());
    let last = ObjectId([255; 32]);
    assert!(id < last);
    let listing = crate::wire::encode_ids(&[id, last]).unwrap();
    // The second response is below the single-file cap, but exceeds the
    // epoch's remaining bytes. No huge body needs to be allocated or sent.
    let oversized = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        crate::limits::MAX_PACK_FILE,
    )
    .into_bytes();
    let (url, worker) = malicious_peer(vec![
        peer_response(200, &listing, ""),
        peer_response(200, &pack, ""),
        oversized,
    ]);
    let error = HttpRemote::connect(&url, None)
        .unwrap()
        .list_packs("private", 1)
        .unwrap_err();
    assert!(error.to_string().contains("response is too large"));
    worker.join().unwrap();
}

#[test]
fn client_refuses_redirects_without_contacting_target() {
    let target = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    target.set_nonblocking(true).unwrap();
    let headers = format!(
        "Location: http://{}/v1/head\r\n",
        target.local_addr().unwrap()
    );
    let (url, worker) = malicious_peer(vec![peer_response(302, &[], &headers)]);
    assert!(HttpRemote::connect(&url, None)
        .unwrap()
        .read_head()
        .is_err());
    assert_eq!(
        target.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    worker.join().unwrap();
}

#[test]
fn client_recomputes_stale_and_successful_partial_commit_etags() {
    let owner = Identity::generate().unwrap();
    let current = tig_private::remote::RemoteHead {
        keyring: None,
        manifest: Some(b"other".to_vec()),
    };
    let body = crate::wire::encode_head(None, current.manifest.as_deref()).unwrap();
    let wrong = format!("ETag: \"{}\"\r\n", "ab".repeat(32));
    let empty = tig_private::remote::RemoteHead {
        keyring: None,
        manifest: None,
    };
    for status in [200, 412] {
        let (url, worker) = malicious_peer(vec![
            peer_response(200, &[0; crate::auth::NONCE_LEN], ""),
            peer_response(status, &body, &wrong),
        ]);
        let remote = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
        assert!(remote
            .commit_head(&empty.version(), None, Some(b"sent"))
            .is_err());
        worker.join().unwrap();
    }
    // Even an internally consistent ETag must describe the bytes we submitted.
    let tag = format!("ETag: {}\r\n", crate::wire::etag_value(&current.version()));
    let (url, worker) = malicious_peer(vec![
        peer_response(200, &[0; crate::auth::NONCE_LEN], ""),
        peer_response(200, &body, &tag),
    ]);
    assert!(HttpRemote::connect(&url, Some(copy_identity(&owner)))
        .unwrap()
        .commit_head(&empty.version(), None, Some(b"sent"))
        .is_err());
    worker.join().unwrap();
}

#[test]
fn batches_split_without_losing_missing_or_duplicate_ids() {
    let owner = Identity::generate().unwrap();
    let (_server, url) = start([20; 16], &owner);
    let remote = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    let objects: Vec<_> = (0..crate::limits::MAX_OBJECT_BATCH + 1)
        .map(|n| blob(&n.to_le_bytes()))
        .collect();
    remote.put_batch(&objects).unwrap();
    let mut ids: Vec<_> = objects.iter().map(|object| object.0).collect();
    ids.insert(1, blob(b"missing").0);
    ids.push(ids[0]);
    assert_eq!(remote.get_batch(&ids).unwrap(), objects);
    let absent = blob(b"another missing object").0;
    assert_eq!(
        remote.missing(&[absent, absent, ids[0], ids[0]]).unwrap(),
        vec![absent]
    );
}

#[test]
fn stalled_tls_handshake_does_not_block_accept_and_bad_tls_is_refused() {
    let owner = Identity::generate().unwrap();
    let tls = || crate::TlsConfig {
        cert_pem: include_bytes!("testdata/cert.pem").to_vec(),
        key_pem: include_bytes!("testdata/key.pem").to_vec(),
    };
    let server = serve(
        Arc::new(MemRemote::new([21; 16])),
        owner.public(),
        "127.0.0.1:0".parse().unwrap(),
        Some(tls()),
    )
    .unwrap();
    let mut stalled = TcpStream::connect(server.local_addr()).unwrap();
    // A partial TLS record leaves the worker waiting in the handshake.
    stalled.write_all(&[22, 3, 3, 0, 100, 1]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    let cert = rustls_pemfile::certs(&mut std::io::Cursor::new(include_bytes!(
        "testdata/cert.pem"
    )))
    .next()
    .unwrap()
    .unwrap();
    roots.add(cert).unwrap();
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let session = rustls::ClientConnection::new(
        Arc::new(config),
        rustls::pki_types::ServerName::try_from("localhost").unwrap(),
    )
    .unwrap();
    let socket = TcpStream::connect(server.local_addr()).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    socket
        .set_write_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut stream = rustls::StreamOwned::new(session, socket);
    stream
        .write_all(b"GET /v1/info HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    stalled.shutdown(std::net::Shutdown::Both).unwrap();
    // The production client must reject the fixture's untrusted certificate.
    assert!(HttpRemote::connect(&format!("https://{}", server.local_addr()), None).is_err());
    let broken = crate::TlsConfig {
        cert_pem: Vec::new(),
        key_pem: Vec::new(),
    };
    assert!(serve(
        Arc::new(MemRemote::new([21; 16])),
        owner.public(),
        "127.0.0.1:0".parse().unwrap(),
        Some(broken)
    )
    .is_err());
}

#[test]
fn restart_preserves_objects_packs_owner_and_invalidates_old_nonce() {
    let dir = tempfile::tempdir().unwrap();
    let owner = Identity::generate().unwrap();
    let id = crate::init_server_dir(dir.path(), &owner.public()).unwrap();
    let server = serve_dir(
        dir.path(),
        owner.public(),
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .unwrap();
    let url = format!("http://{}", server.local_addr());
    let writer = HttpRemote::connect(&url, Some(copy_identity(&owner))).unwrap();
    let object = blob(b"persisted");
    writer.put_batch(std::slice::from_ref(&object)).unwrap();
    let key = EpochKey::generate(GroupEpoch {
        remote: id,
        group: "private".into(),
        epoch: 1,
    })
    .unwrap();
    let pack = PackBuilder::new(&key).finish().unwrap();
    writer.put_pack(&pack).unwrap();
    let body = encode_objects(&[(object.0, object.1, object.2.as_slice())]).unwrap();
    let nonce = post_nonce(url.trim_start_matches("http://"));
    let pending = signed_request(id, &owner, "POST", "/v1/objects/put", &body, &nonce, None);
    drop(server);
    let pinned = crate::read_server_owner(dir.path()).unwrap();
    assert_eq!(pinned, owner.public());
    let server = serve_dir(dir.path(), pinned, "127.0.0.1:0".parse().unwrap(), None).unwrap();
    let url = format!("http://{}", server.local_addr());
    assert_eq!(raw_bytes(&url, &pending), 401);
    let reader = HttpRemote::connect(&url, None).unwrap();
    assert_eq!(reader.get_batch(&[object.0]).unwrap(), vec![object]);
    assert_eq!(reader.list_packs("private", 1).unwrap(), vec![pack]);
}

#[test]
fn startup_refuses_keyring_not_signed_by_pinned_owner() {
    let owner = Identity::generate().unwrap();
    let other = Identity::generate().unwrap();
    let remote = Arc::new(MemRemote::new([22; 16]));
    let empty = remote.read_head().unwrap();
    let (ring, _) = Keyring::create([22; 16], &other).unwrap();
    remote
        .commit_head(&empty.version(), Some(&ring.encode().unwrap()), None)
        .unwrap();
    assert!(serve(remote, owner.public(), "127.0.0.1:0".parse().unwrap(), None).is_err());
}
