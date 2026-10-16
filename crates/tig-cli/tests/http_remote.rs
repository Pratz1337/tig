//! Publish, fetch, clone, grant and revoke against an in-process `tig-server`
//! on loopback, through the `tig` binary. Plain http is fine on loopback.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tig_private::keys::Identity;
use tig_remote_http::{init_server_dir, serve_dir, Server};

const SECRET: &str = "API_KEY=http-marker-5f3a\n";

fn tig(dir: &Path, name: &str, identity: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tig"));
    cmd.current_dir(dir)
        .env("TIG_AUTHOR_NAME", name)
        .env("TIG_AUTHOR_EMAIL", format!("{name}@example.com"))
        .env("TIG_TIMESTAMP_MS", "1700000000000")
        .env("TIG_IDENTITY_PASSPHRASE", "tig test identity passphrase").env("TIG_IDENTITY_FILE", identity);
    cmd
}

struct Run {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn run(cmd: &mut Command) -> Run {
    let Output {
        status,
        stdout,
        stderr,
    } = cmd.output().expect("spawn tig");
    Run {
        code: status.code(),
        stdout: String::from_utf8(stdout).expect("stdout is utf-8"),
        stderr: String::from_utf8(stderr).expect("stderr is utf-8"),
    }
}

fn expect_ok(cmd: &mut Command) -> String {
    let run = run(cmd);
    assert!(
        run.code == Some(0),
        "exit {:?}\nstdout:\n{}\nstderr:\n{}",
        run.code,
        run.stdout,
        run.stderr
    );
    run.stdout
}

fn expect_err(cmd: &mut Command) -> String {
    let run = run(cmd);
    assert_eq!(
        run.code,
        Some(1),
        "stdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    run.stderr
}

/// The identity token, the first line of `tig identity`.
fn token(stdout: &str) -> String {
    stdout.lines().next().unwrap_or("").trim().to_string()
}

/// A server on 127.0.0.1 with an ephemeral port, owned by the identity in
/// `owner_file`, storing into a directory remote under `root`.
fn start_server(root: &Path, owner_file: &Path) -> (Server, String) {
    let bytes = fs::read(owner_file).unwrap();
    let owner = Identity::decrypt(&bytes, b"tig test identity passphrase").unwrap().public();
    let dir = root.join("server");
    init_server_dir(&dir, &owner).unwrap();
    let server = serve_dir(
        &dir,
        owner,
        "127.0.0.1:0".parse().unwrap(),
        None,
    )
    .unwrap();
    let url = format!("http://{}", server.local_addr());
    (server, url)
}

fn contains_bytes(root: &Path, needle: &[u8]) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if fs::read(&path)
                .unwrap()
                .windows(needle.len())
                .any(|window| window == needle)
            {
                return true;
            }
        }
    }
    false
}

#[test]
fn two_users_publish_and_fetch_over_http() {
    let tmp = tempfile::tempdir().unwrap();
    let alice_id = tmp.path().join("alice.id");
    let bob_id = tmp.path().join("bob.id");
    let carol_id = tmp.path().join("carol.id");
    let alice = |dir: &Path| tig(dir, "alice", &alice_id);
    let bob = |dir: &Path| tig(dir, "bob", &bob_id);
    let carol = |dir: &Path| tig(dir, "carol", &carol_id);
    expect_ok(alice(tmp.path()).arg("identity"));
    let bob_token = token(&expect_ok(bob(tmp.path()).arg("identity")));
    expect_ok(carol(tmp.path()).arg("identity"));
    let (_server, url) = start_server(tmp.path(), &alice_id);

    let repo = tmp.path().join("alice");
    fs::create_dir_all(&repo).unwrap();
    fs::write(repo.join("readme.txt"), "hello\n").unwrap();
    fs::write(repo.join(".env"), SECRET).unwrap();
    expect_ok(alice(tmp.path()).arg("init").arg(&repo));
    let added = expect_ok(alice(&repo).args(["remote", "add", "origin", &url]));
    assert!(
        added.contains(&format!("added remote origin at {url}")),
        "{added}"
    );
    assert!(repo.join(".tig/remotes/origin/url").is_file());
    assert!(!repo.join(".tig/remotes/origin/path").exists());
    let listed = expect_ok(alice(&repo).args(["remote", "list"]));
    assert_eq!(listed.trim(), format!("origin {url}"));
    let published = expect_ok(alice(&repo).args(["publish", "origin"]));
    assert!(published.contains("sealed: .env"), "{published}");
    assert!(published.contains("you own this remote"), "{published}");
    let server_dir = tmp.path().join("server");
    assert!(!contains_bytes(&server_dir, SECRET.as_bytes()));

    // Carol has no grant: she reads the public part and cannot publish.
    let carol_dir = tmp.path().join("carol");
    let cloned = expect_ok(carol(tmp.path()).args(["clone", &url]).arg(&carol_dir));
    assert!(cloned.contains("pinned owner of origin"), "{cloned}");
    let readme = fs::read_to_string(carol_dir.join("readme.txt")).unwrap();
    assert_eq!(readme, "hello\n");
    assert!(!carol_dir.join(".env").is_file());
    fs::write(carol_dir.join("carol.txt"), "carol\n").unwrap();
    let refused = expect_err(carol(&carol_dir).args(["publish", "origin", "-b", "carol"]));
    assert!(
        refused.contains("you are not a member of remote origin"),
        "{refused}"
    );

    // Bob is granted, clones, sees the secret, and publishes.
    expect_ok(alice(&repo).args(["grant", "origin", &bob_token]));
    let bob_dir = tmp.path().join("bob");
    expect_ok(bob(tmp.path()).args(["clone", &url]).arg(&bob_dir));
    assert_eq!(fs::read_to_string(bob_dir.join(".env")).unwrap(), SECRET);
    fs::write(bob_dir.join("bob.txt"), "from bob\n").unwrap();
    let bob_published = expect_ok(bob(&bob_dir).args(["publish", "origin", "-b", "bob"]));
    assert!(bob_published.contains("(bob)"), "{bob_published}");

    // Alice fetches Bob's work.
    let fetched = expect_ok(alice(&repo).args(["fetch", "origin"]));
    assert!(fetched.contains("bookmark origin/bob"), "{fetched}");
    let cat = expect_ok(alice(&repo).args(["cat", "bob.txt", "-r", "origin/bob"]));
    assert_eq!(cat, "from bob\n");

    // After a revoke Bob's next publish is refused, and says why.
    expect_ok(alice(&repo).args(["revoke", "origin", &bob_token]));
    fs::write(bob_dir.join("bob.txt"), "from bob, again\n").unwrap();
    let refused = expect_err(bob(&bob_dir).args(["publish", "origin", "-b", "bob"]));
    assert!(
        refused.contains("you are not a member of remote origin"),
        "{refused}"
    );
}

#[test]
fn plain_http_is_refused_for_other_hosts_and_unreachable_servers_are_named() {
    let tmp = tempfile::tempdir().unwrap();
    let id = tmp.path().join("me.id");
    let repo = tmp.path().join("repo");
    let me = |dir: &Path| tig(dir, "me", &id);
    expect_ok(me(tmp.path()).arg("init").arg(&repo));
    let refused = expect_err(me(&repo).args(["remote", "add", "origin", "http://example.com"]));
    assert!(refused.contains("loopback"), "{refused}");

    let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", closed.local_addr().unwrap());
    drop(closed);
    expect_ok(me(&repo).args(["remote", "add", "origin", &url]));
    let unreachable = expect_err(me(&repo).args(["fetch", "origin"]));
    assert!(
        unreachable.contains(&format!("cannot reach {url}")),
        "{unreachable}"
    );

    let listed = expect_ok(me(&repo).args(["remote", "list"]));
    assert_eq!(listed.trim(), format!("origin {url}"));
}

#[test]
fn a_directory_remote_configured_before_servers_still_works() {
    let tmp = tempfile::tempdir().unwrap();
    let id = tmp.path().join("me.id");
    let repo = tmp.path().join("repo");
    let remote = tmp.path().join("remote");
    let me = |dir: &Path| tig(dir, "me", &id);
    fs::create_dir_all(&repo).unwrap();
    fs::write(repo.join("a.txt"), "a\n").unwrap();
    expect_ok(me(tmp.path()).arg("init").arg(&repo));
    // The config an older tig wrote: only a `path` file holding the
    // absolute directory and a newline.
    let cfg = repo.join(".tig/remotes/origin");
    fs::create_dir_all(&cfg).unwrap();
    fs::write(cfg.join("path"), format!("{}\n", remote.to_str().unwrap())).unwrap();

    let listed = expect_ok(me(&repo).args(["remote", "list"]));
    assert!(listed.starts_with("origin "), "{listed}");
    assert!(!listed.contains("://"), "{listed}");
    expect_ok(me(&repo).args(["publish", "origin"]));
    assert!(remote.join("manifest").is_file());
    let fetched = expect_ok(me(&repo).args(["fetch", "origin"]));
    assert!(fetched.contains("bookmark origin/main"), "{fetched}");

    let copy = tmp.path().join("copy");
    expect_ok(me(tmp.path()).arg("clone").arg(&remote).arg(&copy));
    assert_eq!(fs::read_to_string(copy.join("a.txt")).unwrap(), "a\n");
    assert!(copy.join(".tig/remotes/origin/path").is_file());
}
