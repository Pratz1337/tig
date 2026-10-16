//! Actual role CLI grants, current-policy env authorization, and ownership handoff.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn command(dir: &Path, identity: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_tig"));
    command.current_dir(dir).env("TIG_IDENTITY_FILE", identity)
        .env("TIG_AUTHOR_NAME", "tester").env("TIG_AUTHOR_EMAIL", "tester@example")
        .env("TIG_TIMESTAMP_MS", "1700000000000");
    command
}

fn ok(command: &mut Command) -> Output {
    let output = command.output().unwrap();
    assert!(output.status.success(), "stdout:{}\nstderr:{}", String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    output
}

fn token(dir: &Path, identity: &Path) -> String {
    String::from_utf8(ok(command(dir, identity).arg("identity")).stdout).unwrap().lines().next().unwrap().to_string()
}

#[test]
fn env_uses_literal_role_secrets_real_exit_code_and_denies_cached_revoked_access() {
    let temp = tempfile::tempdir().unwrap();
    let owner_id = temp.path().join("owner.id");
    let reader_id = temp.path().join("reader.id");
    let owner = temp.path().join("owner");
    let reader = temp.path().join("reader");
    let remote = temp.path().join("remote");
    let reader_token = token(temp.path(), &reader_id);
    let owner_token = token(temp.path(), &owner_id);
    ok(command(temp.path(), &owner_id).arg("init").arg(&owner));
    fs::write(owner.join("readme"), "public").unwrap();
    ok(command(&owner, &owner_id).args(["remote", "add", "origin"]).arg(&remote));
    ok(command(&owner, &owner_id).args(["publish", "origin"]));
    ok(command(&owner, &owner_id).args(["role", "origin", "set", "billing", "--rank", "1", "--groups", "billing"]));
    ok(command(&owner, &owner_id).args(["role", "origin", "assign", "billing", &owner_token]));
    ok(command(&owner, &owner_id).args(["role", "origin", "grant", "billing", &owner_token]));
    ok(command(&owner, &owner_id).args(["role", "origin", "assign", "billing", &reader_token]));
    ok(command(&owner, &owner_id).args(["role", "origin", "grant", "billing", &reader_token]));
    fs::write(owner.join(".private"), ".env.billing @billing\n").unwrap();
    fs::write(owner.join(".env.billing"), "TOKEN=literal-$(never-run)\n").unwrap();
    ok(command(&owner, &owner_id).args(["publish", "origin"]));
    ok(command(temp.path(), &reader_id).arg("clone").arg(&remote).arg(&reader));
    ok(command(&reader, &reader_id).args(["edit", "origin/main"]));
    let output = command(&reader, &reader_id).args(["env", "origin", "--role", "billing", "--", "sh", "-c", "printf %s \"$TOKEN\"; exit 7"]).output().unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"literal-$(never-run)");
    assert!(output.stderr.is_empty());
    ok(command(&owner, &owner_id).args(["role", "origin", "unassign", "billing", &reader_token]));
    let marker = temp.path().join("child-ran");
    let denied = command(&reader, &reader_id).args(["env", "origin", "--role", "billing", "--", "touch"]).arg(&marker).output().unwrap();
    assert!(!denied.status.success());
    assert!(!marker.exists());
    assert!(!String::from_utf8_lossy(&denied.stderr).contains("literal-$(never-run)"));
    assert_eq!(fs::read_to_string(reader.join(".env.billing")).unwrap(), "TOKEN=literal-$(never-run)\n");
    ok(command(&owner, &owner_id).args(["role", "origin", "rotate", "billing"]));
    ok(command(&owner, &owner_id).args(["role", "origin", "rotate", "private"]));
    fs::write(owner.join("readme"), "public after rotations").unwrap();
    ok(command(&owner, &owner_id).args(["publish", "origin"]));
}

#[test]
fn transfer_proposal_is_public_successor_accepts_and_former_owner_loses_authority() {
    let temp = tempfile::tempdir().unwrap();
    let owner_id = temp.path().join("owner.id");
    let successor_id = temp.path().join("successor.id");
    let owner = temp.path().join("owner");
    let successor = temp.path().join("successor");
    let remote = temp.path().join("remote");
    let proposal = temp.path().join("transfer.proposal");
    let successor_token = token(temp.path(), &successor_id);
    ok(command(temp.path(), &owner_id).arg("init").arg(&owner));
    fs::write(owner.join("readme"), "public").unwrap();
    ok(command(&owner, &owner_id).args(["remote", "add", "origin"]).arg(&remote));
    ok(command(&owner, &owner_id).args(["publish", "origin"]));
    ok(command(temp.path(), &successor_id).arg("clone").arg(&remote).arg(&successor));
    ok(command(&owner, &owner_id).args(["role", "origin", "set", "publisher", "--rank", "1", "--permissions", "publish"]));
    ok(command(&owner, &owner_id).args(["role", "origin", "assign", "publisher", &successor_token]));
    fs::write(successor.join("readme"), "published by the successor").unwrap();
    ok(command(&successor, &successor_id).args(["publish", "origin"]));
    let target = tig_private::remote::DirRemote::open(&remote).unwrap();
    let before_revoke = tig_private::manifest::Manifest::decode(target.read_head().unwrap().manifest.as_deref().unwrap()).unwrap();
    ok(command(&owner, &owner_id).args(["role", "origin", "unassign", "publisher", &successor_token]));
    let after_revoke = tig_private::manifest::Manifest::decode(target.read_head().unwrap().manifest.as_deref().unwrap()).unwrap();
    assert_ne!(after_revoke.publisher, before_revoke.publisher);
    assert_eq!(after_revoke.refs, before_revoke.refs);
    assert_eq!(after_revoke.packs, before_revoke.packs);
    assert_eq!(after_revoke.changes, before_revoke.changes);
    assert_eq!(after_revoke.reveals, before_revoke.reveals);
    ok(command(&successor, &successor_id).args(["fetch", "origin"]));
    ok(command(&owner, &owner_id).args(["role", "origin", "transfer", &successor_token]).arg(&proposal));
    let bytes = fs::read(&proposal).unwrap();
    assert!(!bytes.windows(64).any(|window| window == fs::read(&owner_id).unwrap()));
    ok(command(&successor, &successor_id).args(["role", "origin", "accept-transfer"]).arg(&proposal));
    ok(command(&successor, &successor_id).args(["role", "origin", "set", "new", "--rank", "1"]));
    let denied = command(&owner, &owner_id).args(["role", "origin", "set", "old", "--rank", "2"]).output().unwrap();
    assert!(!denied.status.success());
    assert!(String::from_utf8_lossy(&denied.stderr).contains("role"));
}
