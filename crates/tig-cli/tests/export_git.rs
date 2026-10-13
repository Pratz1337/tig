use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn tig(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_tig"))
        .args(args)
        .env("TIG_AUTHOR_NAME", "Ada Lovelace")
        .env("TIG_AUTHOR_EMAIL", "ada@example.com")
        .env("TIG_TIMESTAMP_MS", "1700000000000")
        .output()
        .unwrap()
}

fn ok(output: &Output) -> String {
    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .current_dir(dir)
        .env("GIT_AUTHOR_NAME", "Export test")
        .env("GIT_AUTHOR_EMAIL", "export@example.com")
        .env("GIT_COMMITTER_NAME", "Export test")
        .env("GIT_COMMITTER_EMAIL", "export@example.com")
        .args(["-c", "core.autocrlf=false", "-c", "commit.gpgsign=false"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn objects(dir: &Path) -> Vec<(String, Vec<u8>)> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(["cat-file", "--batch-all-objects", "--batch", "--unordered"])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let data = out.stdout;
    let mut objects = Vec::new();
    let mut index = 0;
    while index < data.len() {
        let header_end = data[index..].iter().position(|byte| *byte == b'\n').unwrap() + index;
        let header = std::str::from_utf8(&data[index..header_end]).unwrap();
        let mut parts = header.split(' ');
        let kind = parts.nth(1).unwrap().to_string();
        let size: usize = parts.next().unwrap().parse().unwrap();
        index = header_end + 1;
        objects.push((kind, data[index..index + size].to_vec()));
        index += size + 1;
    }
    objects
}

#[test]
fn export_round_trip_omits_private_paths_and_refuses_a_non_fast_forward() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join("secrets")).unwrap();
    fs::write(repo.join("README"), b"public-readme").unwrap();
    fs::write(repo.join(".env"), b"cli-export-secret-9f3a").unwrap();
    fs::write(repo.join("secrets/token"), b"cli-export-secret-9f3a").unwrap();
    fs::write(repo.join(".private"), b"secrets/\n").unwrap();
    let repo_s = repo.to_str().unwrap();
    ok(&tig(&["init", repo_s]));
    ok(&tig(&["-R", repo_s, "describe", "-m", "public history"]));
    ok(&tig(&["-R", repo_s, "bookmark", "set", "main"]));
    ok(&tig(&["-R", repo_s, "bookmark", "set", "foo..bar"]));

    let dest = tmp.path().join("git");
    let dest_s = dest.to_str().unwrap();
    let first_export = tig(&["-R", repo_s, "export-git", dest_s]);
    let exported = ok(&first_export);
    assert!(
        String::from_utf8_lossy(&first_export.stderr).contains("foo..bar"),
        "{}",
        String::from_utf8_lossy(&first_export.stderr)
    );
    assert!(exported.contains("omitted") && exported.contains("private paths"), "{exported}");
    assert!(!exported.contains("secrets/token"), "{exported}");
    assert!(!dest.join("README").exists());
    fs::write(dest.join("keep.txt"), b"leave the worktree alone").unwrap();
    let secret = b"cli-export-secret-9f3a";
    for (kind, body) in objects(&dest) {
        assert!(!body.windows(secret.len()).any(|window| window == secret), "{kind}");
        if kind == "tree" {
            assert!(!body.windows(b" .env\0".len()).any(|window| window == b" .env\0"));
            assert!(!body.windows(b" secrets\0".len()).any(|window| window == b" secrets\0"));
            assert!(!body.windows(b" token\0".len()).any(|window| window == b" token\0"));
        }
    }
    let first = git(&dest, &["rev-parse", "main"]);
    let again = tig(&["-R", repo_s, "export-git", dest_s]);
    let again_out = ok(&again);
    assert!(again_out.contains("exported 0 revisions"), "{again_out}");
    assert!(again_out.contains("reused"), "{again_out}");
    assert!(String::from_utf8_lossy(&again.stderr).contains("foo..bar"), "{}", String::from_utf8_lossy(&again.stderr));
    assert!(!String::from_utf8_lossy(&again.stderr).contains("secrets/token"));
    assert_eq!(git(&dest, &["rev-parse", "main"]), first);
    assert_eq!(fs::read(dest.join("keep.txt")).unwrap(), b"leave the worktree alone");

    let fresh = tmp.path().join("fresh");
    let fresh_s = fresh.to_str().unwrap();
    let imported = ok(&tig(&["-R", fresh_s, "import-git", dest_s]));
    assert!(imported.contains("imported"), "{imported}");
    assert_eq!(fs::read(fresh.join("README")).unwrap(), b"public-readme");
    assert!(!fresh.join(".env").exists());
    assert!(!fresh.join("secrets").exists());
    let shown = ok(&tig(&["-R", fresh_s, "log"]));
    assert!(shown.contains("public history"), "{shown}");
    assert!(shown.contains("ada@example.com"), "{shown}");

    ok(&tig(&["-R", repo_s, "new", "-m", "second"]));
    ok(&tig(&["-R", repo_s, "bookmark", "set", "main"]));
    let incremental = ok(&tig(&["-R", repo_s, "export-git", "--bookmark", "main", dest_s]));
    assert!(incremental.contains("exported 1 revisions"), "{incremental}");
    assert_ne!(git(&dest, &["rev-parse", "main"]), first);
    assert_eq!(git(&dest, &["rev-parse", "main^"]), first);

    let extra = git(&dest, &["commit-tree", "main^{tree}", "-p", "main", "-m", "someone else"]);
    git(&dest, &["update-ref", "refs/heads/main", &extra]);
    ok(&tig(&["-R", repo_s, "new", "-m", "third"]));
    ok(&tig(&["-R", repo_s, "bookmark", "set", "main"]));
    let refused = tig(&["-R", repo_s, "export-git", dest_s]);
    assert!(!refused.status.success());
    let message = String::from_utf8_lossy(&refused.stderr);
    assert!(message.contains("changed in Git") || message.contains("--force"), "{message}");
    assert_eq!(git(&dest, &["rev-parse", "main"]), extra);
    ok(&tig(&["-R", repo_s, "export-git", "--force", dest_s]));
    assert_ne!(git(&dest, &["rev-parse", "main"]), extra);

    let verbose = tig(&["-R", repo_s, "export-git", "--verbose", dest_s]);
    let verbose_err = String::from_utf8_lossy(&verbose.stderr);
    assert!(verbose_err.contains("omitted private path:"), "{verbose_err}");

    fs::write(repo.join("notes"), b"cli-export-secret-9f3a").unwrap();
    ok(&tig(&["-R", repo_s, "bookmark", "set", "main"]));
    let pasted = tig(&["-R", repo_s, "export-git", dest_s]);
    assert!(!pasted.status.success());
    assert!(String::from_utf8_lossy(&pasted.stderr).contains("notes"), "{}", String::from_utf8_lossy(&pasted.stderr));
    ok(&tig(&[
        "-R",
        repo_s,
        "export-git",
        "--declassify",
        "notes",
        "--force",
        dest_s,
    ]));
}
