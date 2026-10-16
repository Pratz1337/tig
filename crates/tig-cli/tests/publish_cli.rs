//! Publish, fetch, clone, grant, and revoke through the `tig` binary.
//!
//! After `!.env` is confirmed, `.env` is public. The revoke step puts the
//! built-in floor back (the `!` line is removed) and the next publish passes
//! `--acknowledge-leaked`, so the new `.env` bytes stay sealed. Leaving
//! `!.env` in place would publish those bytes in the clear.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const OLD_MARKER: &str = "API_KEY=alice-marker-old-7c1e\n";
const NEW_MARKER: &str = "API_KEY=alice-marker-new-9b2d\n";
const KEY_MATERIAL: &str = "KEYMAT=alice-key-7c1e\n";

fn tig(dir: &Path, name: &str, email: &str, identity: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tig"));
    cmd.current_dir(dir)
        .env("TIG_AUTHOR_NAME", name)
        .env("TIG_AUTHOR_EMAIL", email)
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

fn identity_lines(stdout: &str) -> (String, String) {
    let mut lines = stdout.lines();
    let token = lines.next().unwrap_or("").trim().to_string();
    let fingerprint = lines
        .next()
        .unwrap_or("")
        .strip_prefix("fingerprint: ")
        .unwrap_or("")
        .trim()
        .to_string();
    (token, fingerprint)
}

#[test]
fn publishing_a_rewritten_change_prints_the_rebase_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let remote = tmp.path().join("remote");
    let identity = tmp.path().join("owner.id");
    let owner = |dir: &Path| tig(dir, "owner", "owner@x", &identity);
    expect_ok(owner(tmp.path()).arg("init").arg(&repo));
    fs::write(repo.join("public"), "first").unwrap();
    expect_ok(owner(&repo).args(["remote", "add", "origin"]).arg(&remote));
    expect_ok(owner(&repo).args(["publish", "origin"]));
    let dir_remote = tig_private::remote::DirRemote::open(&remote).unwrap();
    let head = dir_remote.read_head().unwrap();
    let manifest =
        tig_private::manifest::Manifest::decode(head.manifest.as_ref().unwrap()).unwrap();
    use tig_core::store::StoreExt;
    let change = dir_remote
        .public_store()
        .get_revision(&manifest.refs["main"])
        .unwrap()
        .change_id
        .short(8);
    fs::write(repo.join("public"), "second").unwrap();
    let published = run(owner(&repo).args(["publish", "origin"]));
    assert_eq!(published.code, Some(0), "{}", published.stderr);
    assert!(published.stderr.contains(&format!("warning: rewrites published change `{change}`; collaborators who built on it must rebase")), "{}", published.stderr);
}

fn sealed_names(stdout: &str) -> Vec<String> {
    let line = stdout
        .lines()
        .find(|line| line.starts_with("sealed:"))
        .unwrap_or_else(|| panic!("no sealed line in:\n{stdout}"));
    let rest = line.trim_start_matches("sealed:").trim();
    if rest == "(none)" {
        return Vec::new();
    }
    rest.split(", ").map(str::to_string).collect()
}

fn contains_slice(hay: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && hay.windows(needle.len()).any(|window| window == needle)
}

/// Every file name and every file's bytes under `root`.
fn tree_contains(root: &Path, needle: &[u8]) -> bool {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if contains_slice(name.as_bytes(), needle) {
                return true;
            }
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = fs::read(&path) {
                if contains_slice(&bytes, needle) {
                    return true;
                }
            }
        }
    }
    false
}

fn snapshot_files(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if let Ok(bytes) = fs::read(&path) {
                let rel = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
                out.insert(rel, bytes);
            }
        }
    }
    out
}

#[test]
fn identity_is_created_once_and_show_does_not_create() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("missing.id");
    let denied =
        run(tig(tmp.path(), "Ada", "ada@example.com", &missing).args(["identity", "--show"]));
    assert_eq!(denied.code, Some(1), "{}", denied.stderr);
    assert!(denied.stderr.starts_with("error:"), "{}", denied.stderr);
    assert!(
        denied.stderr.contains("no identity yet"),
        "{}",
        denied.stderr
    );
    assert!(!missing.exists());

    let path = tmp.path().join("person.id");
    let first = expect_ok(tig(tmp.path(), "Ada", "ada@example.com", &path).args(["identity"]));
    let (token, fingerprint) = identity_lines(&first);
    assert!(token.starts_with("tig1:"), "{first}");
    assert_eq!(token.len(), "tig1:".len() + 128, "{first}");
    assert_eq!(fingerprint.len(), 32, "{first}");
    assert!(fs::read(&path).unwrap().starts_with(b"TIGI"));

    let again = expect_ok(tig(tmp.path(), "Ada", "ada@example.com", &path).args(["identity"]));
    assert_eq!(again, first);
    let shown =
        expect_ok(tig(tmp.path(), "Ada", "ada@example.com", &path).args(["identity", "--show"]));
    assert_eq!(shown, first);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn alice_publishes_bob_reads_carol_does_not() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    let remote = tmp.path().join("remote");
    let carol_dir = tmp.path().join("carol");
    let bob_dir = tmp.path().join("bob");
    let alice_id = tmp.path().join("alice.id");
    let bob_id = tmp.path().join("bob.id");
    let carol_id = tmp.path().join("carol.id");

    let alice = |dir: &Path| tig(dir, "Alice", "alice@example.com", &alice_id);
    let bob = |dir: &Path| tig(dir, "Bob", "bob@example.com", &bob_id);
    let carol = |dir: &Path| tig(dir, "Carol", "carol@example.com", &carol_id);

    let alice_id_out = expect_ok(alice(tmp.path()).args(["identity"]));
    let (alice_token, alice_fp) = identity_lines(&alice_id_out);
    assert!(alice_token.starts_with("tig1:"), "{alice_id_out}");

    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(repo.join("secrets")).unwrap();
    fs::write(repo.join(".env"), OLD_MARKER).unwrap();
    fs::write(repo.join("secrets").join("a.key"), KEY_MATERIAL).unwrap();
    fs::write(repo.join("src").join("main.rs"), "fn main() {}\n").unwrap();

    let init = expect_ok(alice(tmp.path()).args(["init"]).arg(&repo));
    assert!(init.contains("wrote .private"), "{init}");
    expect_ok(alice(&repo).args(["describe", "-m", "initial secrets"]));

    let listed = expect_ok(alice(&repo).args(["remote", "list"]));
    assert!(listed.contains("No remotes."), "{listed}");
    let added = expect_ok(alice(&repo).args(["remote", "add", "origin"]).arg(&remote));
    assert!(added.contains("added remote origin"), "{added}");
    let listed = expect_ok(alice(&repo).args(["remote", "list"]));
    assert!(listed.contains("origin "), "{listed}");
    let bad = run(alice(&repo).args(["remote", "add", "Not Valid", "x"]));
    assert_eq!(bad.code, Some(1), "{}", bad.stderr);
    assert!(bad.stderr.contains("[a-z0-9_-]+"), "{}", bad.stderr);

    let published = expect_ok(alice(&repo).args(["publish", "origin"]));
    assert!(
        published.contains("published 1 revision to origin (main)"),
        "{published}"
    );
    assert!(
        published.contains(&format!(
            "you own this remote; your fingerprint: {alice_fp}"
        )),
        "{published}"
    );
    let sealed = sealed_names(&published);
    assert!(sealed.contains(&".env".to_string()), "{published}");
    assert!(sealed.contains(&"secrets".to_string()), "{published}");
    assert!(
        !sealed.iter().any(|name| name.contains("a.key")),
        "{published}"
    );
    assert!(
        !tree_contains(&remote, OLD_MARKER.as_bytes()),
        "old marker leaked"
    );
    assert!(
        !tree_contains(&remote, KEY_MATERIAL.as_bytes()),
        "key material leaked"
    );
    assert!(!tree_contains(&remote, b"a.key"), "a.key name leaked");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let keys = repo
            .join(".tig")
            .join("remotes")
            .join("origin")
            .join("owner-keys");
        let mode = fs::metadata(&keys).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let carol_id_out = expect_ok(carol(tmp.path()).args(["identity"]));
    let (_carol_token, _carol_fp) = identity_lines(&carol_id_out);
    let carol_clone = expect_ok(
        carol(tmp.path())
            .args(["clone"])
            .arg(&remote)
            .arg(&carol_dir),
    );
    assert!(
        carol_clone.contains(&format!(
            "pinned owner of origin: {alice_fp} (verify it with them)"
        )),
        "{carol_clone}"
    );
    assert!(
        carol_clone.contains("bookmark origin/main"),
        "{carol_clone}"
    );
    assert!(!carol_dir.join(".env").exists(), "sealed .env was written");
    assert!(
        !carol_dir.join("secrets").exists(),
        "sealed secrets was written"
    );
    assert!(carol_dir.join("src").join("main.rs").is_file());
    let carol_status = expect_ok(carol(&carol_dir).args(["status"]));
    assert!(carol_status.contains("working change:"), "{carol_status}");
    let carol_log = expect_ok(carol(&carol_dir).args(["log"]));
    assert!(carol_log.contains("root"), "{carol_log}");
    let carol_cat = run(carol(&carol_dir).args(["cat", ".env"]));
    assert_eq!(carol_cat.code, Some(1), "{}", carol_cat.stderr);
    assert!(
        carol_cat.stderr.contains(".env is not a file"),
        "{}",
        carol_cat.stderr
    );
    assert!(
        !carol_cat.stderr.contains("is not in this revision"),
        "{}",
        carol_cat.stderr
    );
    fs::write(
        carol_dir.join(".tig/workspaces/default/state"),
        b"corrupt state",
    )
    .unwrap();
    let rescan = expect_ok(carol(&carol_dir).args(["snapshot", "--rehash"]));
    assert!(rescan.contains("snapshotted 0 changed paths"), "{rescan}");
    let still_sealed = run(carol(&carol_dir).args(["cat", ".env"]));
    assert_eq!(still_sealed.code, Some(1));
    assert!(still_sealed.stderr.contains(".env is not a file"));

    let bob_id_out = expect_ok(bob(tmp.path()).args(["identity"]));
    let (bob_token, bob_fp) = identity_lines(&bob_id_out);
    let granted = expect_ok(alice(&repo).args(["grant", "origin", &bob_token]));
    assert!(
        granted.contains(&format!("granted {bob_fp} on origin")),
        "{granted}"
    );

    let bob_clone = expect_ok(bob(tmp.path()).args(["clone"]).arg(&remote).arg(&bob_dir));
    assert!(
        bob_clone.contains(&format!(
            "pinned owner of origin: {alice_fp} (verify it with them)"
        )),
        "{bob_clone}"
    );
    assert_eq!(
        fs::read(bob_dir.join(".env")).unwrap(),
        OLD_MARKER.as_bytes()
    );
    assert_eq!(
        fs::read(bob_dir.join("secrets").join("a.key")).unwrap(),
        KEY_MATERIAL.as_bytes()
    );
    assert!(bob_dir.join("src").join("main.rs").is_file());

    fs::write(bob_dir.join("src/main.rs"), "// Bob's contribution\n").unwrap();
    let bob_publish = expect_ok(bob(&bob_dir).args(["publish", "origin", "-b", "bob"]));
    assert!(bob_publish.contains("(bob)"), "{bob_publish}");
    assert!(!tree_contains(&remote, OLD_MARKER.as_bytes()));

    fs::remove_file(repo.join(".private")).unwrap();
    fs::write(
        repo.join("src").join("main.rs"),
        "fn main() {}\n// edited\n",
    )
    .unwrap();
    let floored = expect_ok(alice(&repo).args(["publish", "origin"]));
    assert!(!floored.contains("you own this remote"), "{floored}");
    let sealed = sealed_names(&floored);
    assert!(sealed.contains(&".env".to_string()), "{floored}");
    assert!(
        !tree_contains(&remote, OLD_MARKER.as_bytes()),
        "floor let the marker out"
    );

    fs::write(repo.join(".private"), "!.env\n").unwrap();
    let before_refuse = snapshot_files(&remote);
    let refused = run(alice(&repo).args(["publish", "origin"]));
    assert_eq!(refused.code, Some(1), "{}", refused.stderr);
    assert!(refused.stderr.starts_with("error:"), "{}", refused.stderr);
    assert!(refused.stderr.contains(".env"), "{}", refused.stderr);
    assert!(
        refused.stderr.contains("--confirm-negations"),
        "{}",
        refused.stderr
    );
    assert!(!refused.stdout.contains("published"), "{}", refused.stdout);
    assert_eq!(
        snapshot_files(&remote),
        before_refuse,
        "refusal wrote the remote"
    );

    // Confirming the negation is not enough: those bytes were sealed before,
    // so publishing them in the clear needs an explicit declassification.
    let undeclassified = run(alice(&repo).args(["publish", "origin", "--confirm-negations"]));
    assert_eq!(undeclassified.code, Some(1), "{}", undeclassified.stderr);
    assert!(undeclassified.stderr.contains("--declassify"), "{}", undeclassified.stderr);
    assert_eq!(snapshot_files(&remote), before_refuse, "refusal wrote the remote");
    let confirmed = expect_ok(alice(&repo).args([
        "publish",
        "origin",
        "--confirm-negations",
        "--declassify",
        ".env",
    ]));
    let sealed = sealed_names(&confirmed);
    assert!(!sealed.iter().any(|name| name == ".env"), "{confirmed}");
    assert!(
        tree_contains(&remote, OLD_MARKER.as_bytes()),
        "confirmed .env should be public"
    );

    let revoked = expect_ok(alice(&repo).args(["revoke", "origin", &bob_token]));
    assert!(
        revoked.contains(&format!("revoked {bob_fp} on origin")),
        "{revoked}"
    );
    fs::write(repo.join(".private"), "secrets/\n").unwrap();
    fs::write(repo.join(".env"), NEW_MARKER).unwrap();
    let leaked = run(alice(&repo).args(["publish", "origin"]));
    assert_eq!(leaked.code, Some(1), "{}", leaked.stderr);
    assert!(leaked.stderr.contains(".env"), "{}", leaked.stderr);
    assert!(
        leaked.stderr.contains("--acknowledge-leaked"),
        "{}",
        leaked.stderr
    );
    assert!(!leaked.stdout.contains("published"), "{}", leaked.stdout);
    let resealed = run(alice(&repo).args(["publish", "origin", "--acknowledge-leaked"]));
    assert_eq!(
        resealed.code,
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        resealed.stdout,
        resealed.stderr
    );
    let sealed = sealed_names(&resealed.stdout);
    assert!(sealed.contains(&".env".to_string()), "{}", resealed.stdout);
    assert!(resealed.stderr.contains("warning:"), "{}", resealed.stderr);
    assert!(
        !tree_contains(&remote, NEW_MARKER.as_bytes()),
        "new marker leaked"
    );
    assert!(
        tree_contains(&remote, OLD_MARKER.as_bytes()),
        "old public bytes should remain"
    );
    assert!(
        !tree_contains(&remote, b"a.key"),
        "a.key name leaked after reseal"
    );

    let fetched = expect_ok(bob(&bob_dir).args(["fetch", "origin"]));
    assert!(
        !fetched.contains("pinned owner"),
        "second fetch must not pin again:\n{fetched}"
    );
    assert!(fetched.contains("bookmark origin/main"), "{fetched}");
    assert_eq!(
        fs::read(bob_dir.join(".env")).unwrap(),
        OLD_MARKER.as_bytes()
    );
    let cat_work = expect_ok(bob(&bob_dir).args(["cat", ".env"]));
    assert_eq!(cat_work, OLD_MARKER);
    let cat_parent = expect_ok(bob(&bob_dir).args(["cat", ".env", "-r", "@-"]));
    assert_eq!(cat_parent, OLD_MARKER);
    let cat_tip = run(bob(&bob_dir).args(["cat", ".env", "-r", "origin/main"]));
    assert_eq!(cat_tip.code, Some(1), "{}", cat_tip.stderr);
    assert!(
        cat_tip.stderr.contains(".env is not a file"),
        "{}",
        cat_tip.stderr
    );
    assert!(
        !tree_contains(&bob_dir, NEW_MARKER.as_bytes()),
        "bob can see the new marker"
    );
}

#[test]
fn outsider_edits_snapshots_and_republishes_without_deleting_seals() {
    let tmp = tempfile::tempdir().unwrap();
    let owner_repo = tmp.path().join("owner");
    let source = tmp.path().join("source");
    let clone = tmp.path().join("clone");
    let own_remote = tmp.path().join("own-remote");
    let owner_id = tmp.path().join("owner.id");
    let outsider_id = tmp.path().join("outsider.id");
    fs::create_dir(&owner_repo).unwrap();
    fs::write(owner_repo.join(".env"), OLD_MARKER).unwrap();
    fs::write(owner_repo.join("public"), "original").unwrap();
    let owner = |dir: &Path| tig(dir, "owner", "owner@x", &owner_id);
    let outsider = |dir: &Path| tig(dir, "outsider", "outsider@x", &outsider_id);
    expect_ok(owner(tmp.path()).args(["init"]).arg(&owner_repo));
    expect_ok(owner(&owner_repo).args(["remote", "add", "origin"]).arg(&source));
    expect_ok(owner(&owner_repo).args(["publish", "origin"]));
    expect_ok(outsider(tmp.path()).arg("clone").arg(&source).arg(&clone));
    expect_ok(outsider(&clone).args(["edit", "origin/main"]));
    fs::write(clone.join("public"), "outsider edit").unwrap();
    expect_ok(outsider(&clone).args(["snapshot", "--rehash"]));
    for command in ["status", "diff", "log"] {
        let output = expect_ok(outsider(&clone).arg(command));
        assert!(!output.contains("D .env"), "{output}");
        assert!(!output.contains(OLD_MARKER), "{output}");
    }
    expect_ok(outsider(&clone).args(["remote", "add", "mine"]).arg(&own_remote));
    let published = expect_ok(outsider(&clone).args(["publish", "mine"]));
    assert!(sealed_names(&published).contains(&".env".into()));
    assert!(!tree_contains(&own_remote, OLD_MARKER.as_bytes()));
    let cat = run(outsider(&clone).args(["cat", ".env"]));
    assert!(cat.stderr.contains(".env is not a file"));
}

#[test]
fn identity_is_never_saved_as_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("protected.id");
    expect_ok(tig(tmp.path(), "Ada", "ada@example.com", &path).args(["identity"]));
    let stored = fs::read(&path).unwrap();
    assert!(stored.starts_with(b"TIGI"), "identity must have a protected envelope");
    assert_ne!(stored.len(), 64, "raw identity secrets must not be persisted");
}

#[test]
fn identity_migration_preserves_keys_and_bad_passwords_or_tampering_never_replace_them() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("legacy.id");
    let identity = tig_private::keys::Identity::from_bytes([37; 64]);
    fs::write(&path, *identity.to_bytes()).unwrap();
    let shown = expect_ok(tig(tmp.path(), "Ada", "ada@example.com", &path).args(["identity", "--show"]));
    let (token, _) = identity_lines(&shown);
    assert_eq!(token, tig_cli::ui::identity_token(&identity.public()));
    let protected = fs::read(&path).unwrap();
    assert!(protected.starts_with(b"TIGI"));
    assert!(!protected.windows(64).any(|b| b == identity.to_bytes().as_slice()));
    let denied = run(tig(tmp.path(), "Ada", "ada@example.com", &path)
        .env("TIG_IDENTITY_PASSPHRASE", "wrong test passphrase").args(["identity", "--show"]));
    assert_eq!(denied.code, Some(1));
    assert_eq!(fs::read(&path).unwrap(), protected);
    for mut damaged in [protected.clone(), protected[..64].to_vec()] {
        let last = damaged.len() - 1;
        damaged[last] ^= 1;
        fs::write(&path, &damaged).unwrap();
        let denied = run(tig(tmp.path(), "Ada", "ada@example.com", &path).args(["identity", "--show"]));
        assert_eq!(denied.code, Some(1));
        assert_eq!(fs::read(&path).unwrap(), damaged);
    }
}
