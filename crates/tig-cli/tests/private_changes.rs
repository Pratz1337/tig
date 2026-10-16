//! Sealed changes through the actual command dispatch and on-disk state.

use std::fs;
use std::path::Path;
use std::process::Command;

use tig_core::store::StoreExt;
use tig_private::manifest::Manifest;
use tig_private::remote::DirRemote;

fn command(dir: &Path, identity: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tig"));
    cmd.current_dir(dir).env("TIG_IDENTITY_PASSPHRASE", "tig test identity passphrase").env("TIG_IDENTITY_FILE", identity)
        .env("TIG_AUTHOR_NAME", "owner").env("TIG_AUTHOR_EMAIL", "owner@example")
        .env("TIG_TIMESTAMP_MS", "1700000000000");
    cmd
}

fn ok(cmd: &mut Command) -> String {
    let output = cmd.output().unwrap();
    assert!(output.status.success(), "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr));
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn seal_reveal_opens_same_history_and_retains_independent_env_privacy() {
    let temp = tempfile::tempdir().unwrap();
    let owner_id = temp.path().join("owner.id");
    let outsider_id = temp.path().join("outsider.id");
    let repo = temp.path().join("owner");
    let remote_path = temp.path().join("remote");
    let outsider = temp.path().join("outsider");
    ok(command(temp.path(), &owner_id).arg("init").arg(&repo));
    fs::write(repo.join("readme"), "public base").unwrap();
    ok(command(&repo, &owner_id).args(["remote", "add", "origin"]).arg(&remote_path));
    ok(command(&repo, &owner_id).args(["publish", "origin"]));
    ok(command(&repo, &owner_id).args(["new", "-m", "SECURITY-FIX-METADATA-38a0"]));
    fs::write(repo.join("fix.txt"), "SEALED-FIX-CONTENT-a70d").unwrap();
    fs::write(repo.join(".env"), "UNRELATED_ENV_SECRET-44bd").unwrap();
    let sealed = ok(command(&repo, &owner_id).args(["seal", "origin", "main", "--role", "private"]));
    assert!(sealed.starts_with("sealed "), "{sealed}");
    let remote = DirRemote::open(&remote_path).unwrap();
    let before = Manifest::decode(remote.read_head().unwrap().manifest.as_deref().unwrap()).unwrap();
    let skeleton = before.refs["main"];
    let public_before = remote.public_store().get_revision(&skeleton).unwrap();
    assert!(public_before.description.is_empty());
    assert_eq!(before.changes.len(), 1);
    assert_eq!(before.reveals.len(), 0);
    let capsule = remote.public_store().get_blob(&before.changes[&skeleton].capsule).unwrap();
    for secret in [b"SEALED-FIX-CONTENT-a70d".as_slice(), b"UNRELATED_ENV_SECRET-44bd", b"SECURITY-FIX-METADATA-38a0"] {
        assert!(!capsule.windows(secret.len()).any(|window| window == secret));
    }
    let saved = tig_private::publish::PublishState::decode(&fs::read(repo.join(".tig/remotes/origin/publish-state")).unwrap()).unwrap();
    assert!(saved.revisions.values().any(|id| *id == skeleton));
    assert_eq!(saved.manifest_seq, before.sequence);
    ok(command(temp.path(), &outsider_id).arg("clone").arg(&remote_path).arg(&outsider));
    ok(command(&outsider, &outsider_id).args(["edit", "origin/main"]));
    assert!(!outsider.join("fix.txt").exists());
    assert_eq!(fs::read_to_string(outsider.join("readme")).unwrap(), "public base");
    let denied = command(&outsider, &outsider_id).args(["reveal", "origin", "-r", "origin/main"]).output().unwrap();
    assert!(!denied.status.success());
    assert_eq!(remote.read_head().unwrap().manifest.as_deref(), Some(before.encode().unwrap().as_slice()));
    ok(command(&repo, &owner_id).args(["reveal", "origin", "-r", "@"]));
    let after = Manifest::decode(remote.read_head().unwrap().manifest.as_deref().unwrap()).unwrap();
    assert_eq!(after.refs, before.refs);
    assert_eq!(after.changes, before.changes);
    assert_eq!(after.reveals.len(), 1);
    assert_eq!(remote.public_store().get_revision(&skeleton).unwrap(), public_before);
    assert_eq!(remote.public_store().get_blob(&before.changes[&skeleton].capsule).unwrap(), capsule);
    ok(command(&outsider, &outsider_id).args(["fetch", "origin"]));
    ok(command(&outsider, &outsider_id).args(["edit", "origin/main"]));
    assert_eq!(fs::read_to_string(outsider.join("fix.txt")).unwrap(), "SEALED-FIX-CONTENT-a70d");
    assert!(!outsider.join(".env").exists());
    let log = ok(command(&outsider, &outsider_id).arg("log"));
    assert!(log.contains("SECURITY-FIX-METADATA-38a0"), "{log}");
    assert!(!log.contains("tig-private-designations"), "{log}");

    let published = fs::read(repo.join(".tig/remotes/origin/publish-state")).unwrap();
    let fetched = fs::read(repo.join(".tig/remotes/origin/fetch-state")).unwrap();
    assert!(tig_private::publish::PublishState::decode(&published).unwrap().revealed.contains(&skeleton));
    assert!(tig_private::publish::PublishState::decode(&published).unwrap().ever_public.contains(&tig_core::RepoPath::new("fix.txt").unwrap()));
    assert!(tig_private::fetch::FetchState::decode(&fetched).unwrap().revealed.contains(&skeleton));
    let signer = tig_private::keys::Identity::decrypt(&fs::read(&owner_id).unwrap(), b"tig test identity passphrase").unwrap();
    let head = remote.read_head().unwrap();
    let dropped = Manifest::signed_with_changes(after.remote, after.sequence + 1, after.refs,
        after.packs, after.changes, Default::default(), &signer).unwrap();
    remote.commit_head(&head.version(), None, Some(&dropped.encode().unwrap())).unwrap();
    let expected = remote.read_head().unwrap().version();
    for arguments in [vec!["publish", "origin"], vec!["seal", "origin", "other", "--role", "private"], vec!["reveal", "origin", "-r", "@"]] {
        let result = command(&repo, &owner_id).args(arguments).output().unwrap();
        assert!(!result.status.success());
        let error = String::from_utf8_lossy(&result.stderr);
        assert!(error.contains("dropped") || error.contains("omitted"), "{error}");
        assert_eq!(remote.read_head().unwrap().version(), expected);
        assert_eq!(fs::read(repo.join(".tig/remotes/origin/publish-state")).unwrap(), published);
        assert_eq!(fs::read(repo.join(".tig/remotes/origin/fetch-state")).unwrap(), fetched);
    }
}

#[test]
fn descendant_publish_keeps_embargoed_fix_private_until_owner_reveal() {
    let temp = tempfile::tempdir().unwrap();
    let identity = temp.path().join("owner.id");
    let repo = temp.path().join("repo");
    let remote_path = temp.path().join("remote");
    let outsider = temp.path().join("outsider");
    let outsider_id = temp.path().join("outsider.id");
    ok(command(temp.path(), &identity).arg("init").arg(&repo));
    fs::write(repo.join("readme"), "public base").unwrap();
    fs::write(repo.join("code.txt"), "old vulnerable implementation").unwrap();
    ok(command(&repo, &identity).args(["remote", "add", "origin"]).arg(&remote_path));
    ok(command(&repo, &identity).args(["publish", "origin"]));
    ok(command(&repo, &identity).args(["new", "-m", "embargoed fix"]));
    fs::write(repo.join("code.txt"), "FIXED-IMPLEMENTATION-28bc").unwrap();
    fs::write(repo.join("fix.txt"), "CAPSULE-ONLY-BODY-e22d").unwrap();
    ok(command(&repo, &identity).args(["seal", "origin", "main", "--role", "private"]));
    let remote = DirRemote::open(&remote_path).unwrap();
    let sealed = Manifest::decode(remote.read_head().unwrap().manifest.as_deref().unwrap()).unwrap();
    let skeleton = sealed.refs["main"];
    ok(command(&repo, &identity).args(["new", "-m", "public docs"]));
    fs::write(repo.join("readme"), "updated public docs").unwrap();
    ok(command(&repo, &identity).args(["publish", "origin"]));
    let child_manifest = Manifest::decode(remote.read_head().unwrap().manifest.as_deref().unwrap()).unwrap();
    let child = remote.public_store().get_revision(&child_manifest.refs["main"]).unwrap();
    assert_eq!(child.parents, vec![skeleton]);
    let files = remote.public_store().get_tree(&child.tree).unwrap();
    assert!(files.get("fix.txt").is_none(), "normal publication leaked the inherited sealed fix");
    assert_eq!(remote.public_store().get_blob(&files.get("code.txt").unwrap().id()).unwrap(), b"old vulnerable implementation");
    assert_eq!(remote.public_store().get_blob(&files.get("readme").unwrap().id()).unwrap(), b"updated public docs");
    assert_eq!(child_manifest.changes, sealed.changes);
    assert!(child_manifest.reveals.is_empty());
    ok(command(temp.path(), &outsider_id).arg("clone").arg(&remote_path).arg(&outsider));
    ok(command(&outsider, &outsider_id).args(["edit", "origin/main"]));
    assert!(!outsider.join("fix.txt").exists());
    assert_eq!(fs::read_to_string(outsider.join("readme")).unwrap(), "updated public docs");
    ok(command(&repo, &identity).args(["new", "-m", "another public child"]));
    fs::write(repo.join("notes"), "public notes").unwrap();
    ok(command(&repo, &identity).args(["publish", "origin"]));
    let grandchild = remote.read_head().unwrap();
    fs::write(repo.join("copied-fix"), "CAPSULE-ONLY-BODY-e22d").unwrap();
    ok(command(&repo, &identity).args(["new", "-m", "copy attempt"]));
    let denied = command(&repo, &identity).args(["publish", "origin", "--declassify", "copied-fix"]).output().unwrap();
    assert!(!denied.status.success(), "ordinary declassification bypassed owner-only reveal");
    assert_eq!(remote.read_head().unwrap().version(), grandchild.version());
    fs::remove_file(repo.join("copied-fix")).unwrap();
    ok(command(&repo, &identity).args(["reveal", "origin", "-r"]).arg(skeleton.to_hex()));
    let revealed = Manifest::decode(remote.read_head().unwrap().manifest.as_deref().unwrap()).unwrap();
    assert_eq!(revealed.refs, Manifest::decode(grandchild.manifest.as_deref().unwrap()).unwrap().refs);
    ok(command(&outsider, &outsider_id).args(["fetch", "origin"]));
    ok(command(&outsider, &outsider_id).args(["edit", "origin/main"]));
    assert_eq!(fs::read_to_string(outsider.join("code.txt")).unwrap(), "FIXED-IMPLEMENTATION-28bc");
    assert_eq!(fs::read_to_string(outsider.join("fix.txt")).unwrap(), "CAPSULE-ONLY-BODY-e22d");
    assert_eq!(fs::read_to_string(outsider.join("notes")).unwrap(), "public notes");
    let before_hiding = remote.read_head().unwrap().version();
    let rules = fs::read_to_string(repo.join(".private")).unwrap();
    fs::write(repo.join(".private"), format!("{rules}\nfix.txt\n")).unwrap();
    let refused = command(&repo, &identity).args(["publish", "origin"]).output().unwrap();
    assert!(!refused.status.success());
    let error = String::from_utf8_lossy(&refused.stderr);
    assert!(error.contains("already leaked") && error.contains("fix.txt"), "{error}");
    assert_eq!(remote.read_head().unwrap().version(), before_hiding);
}
