//! End-to-end coverage of the `tig` binary. Author and clock come from the
//! environment so the transcript does not depend on the machine.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn tig(dir: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tig"));
    cmd.current_dir(dir)
        .env("TIG_AUTHOR_NAME", "Ada")
        .env("TIG_AUTHOR_EMAIL", "ada@example.com")
        .env("TIG_TIMESTAMP_MS", "1700000000000");
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

#[test]
fn end_to_end_session() {
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join("src")).unwrap();
    fs::write(repo.join(".env"), "SECRET=1\n").unwrap();
    fs::write(repo.join("src/main.rs"), "fn main() {}\n").unwrap();

    let init = expect_ok(tig(tmp.path()).args(["init"]).arg(&repo));
    assert!(init.contains("initialized repo in "), "{init}");
    assert!(init.contains("wrote .private"), "{init}");
    assert!(
        init.contains(".env*") && init.contains("private by default"),
        "{init}"
    );
    assert!(init.contains("Working change:"), "{init}");
    assert!(init.contains("(no description)"), "{init}");

    let status = expect_ok(tig(&repo).args(["status"]));
    assert!(
        status
            .lines()
            .any(|line| line.starts_with("working change:")),
        "{status}"
    );
    assert!(
        status.lines().any(|line| line.starts_with("parent:")),
        "{status}"
    );
    let env_at = status.find("A .env").expect(&status);
    let private_at = status.find("A .private").expect(&status);
    let src_at = status.find("A src/main.rs").expect(&status);
    assert!(env_at < private_at && private_at < src_at, "{status}");

    let denied = run(tig(&repo).args(["describe"]));
    assert_eq!(denied.code, Some(1), "{}", denied.stderr);
    assert!(denied.stderr.starts_with("error:"), "{}", denied.stderr);
    assert!(denied.stderr.contains("-m"), "{}", denied.stderr);

    let described = expect_ok(tig(&repo).args(["describe", "-m", "initial"]));
    assert!(described.contains("Working change:"), "{described}");
    assert!(described.contains("initial"), "{described}");

    let shown = expect_ok(tig(&repo).args(["show"]));
    assert!(shown.contains("initial"), "{shown}");
    assert!(shown.contains("--- /dev/null"), "{shown}");
    assert!(shown.contains("+++ b/src/main.rs"), "{shown}");

    let created = expect_ok(tig(&repo).args(["new", "-m", "next"]));
    assert!(created.contains("Working change:"), "{created}");
    assert!(created.contains("next"), "{created}");

    let log = expect_ok(tig(&repo).args(["log"]));
    let lines: Vec<&str> = log.lines().collect();
    let at = lines
        .iter()
        .position(|line| line.starts_with("@ "))
        .expect(&log);
    assert!(lines[at].contains("(empty)"), "{log}");
    assert!(lines[at].contains("ada@example.com"), "{log}");
    assert!(lines[at].contains("2023-11-14 22:13"), "{log}");
    assert!(lines[at + 1].contains("next"), "{log}");
    let parent = lines
        .iter()
        .position(|line| line.starts_with("o "))
        .expect(&log);
    assert!(!lines[parent].contains("(empty)"), "{log}");
    assert!(lines[parent + 1].contains("initial"), "{log}");
    assert!(lines.contains(&"* root"), "{log}");

    fs::write(repo.join("src/main.rs"), "fn main() {}\n// edited\n").unwrap();
    let diff = expect_ok(tig(&repo).args(["diff"]));
    assert!(diff.contains("--- a/src/main.rs"), "{diff}");
    assert!(diff.contains("+++ b/src/main.rs"), "{diff}");
    assert!(diff.contains("+// edited"), "{diff}");

    let stat = expect_ok(tig(&repo).args(["diff", "--stat"]));
    assert!(stat.contains("src/main.rs | +1 -0"), "{stat}");
    assert!(stat.contains("1 file changed, +1 -0"), "{stat}");

    let recent = expect_ok(tig(&repo).args(["log", "-n", "2"]));
    assert!(
        recent.lines().any(|line| line.starts_with("@ ")),
        "{recent}"
    );
    assert!(recent.contains("next"), "{recent}");
    assert!(recent.contains("initial"), "{recent}");

    let undone = expect_ok(tig(&repo).args(["undo"]));
    assert!(undone.contains("undo"), "{undone}");
    assert_eq!(
        fs::read_to_string(repo.join("src/main.rs")).unwrap(),
        "fn main() {}\n"
    );

    let ops = expect_ok(tig(&repo).args(["op", "log"]));
    assert!(ops.contains("(undo)"), "{ops}");
    assert!(ops.contains("initialize repo"), "{ops}");

    let side = tmp.path().join("side");
    let added = expect_ok(
        tig(&repo)
            .args(["workspace", "add"])
            .arg(&side)
            .args(["--name", "side"]),
    );
    assert!(added.contains("added workspace side"), "{added}");
    let listed = expect_ok(tig(&repo).args(["workspace", "list"]));
    assert!(
        listed.lines().any(|line| line.starts_with("default ")),
        "{listed}"
    );
    assert!(
        listed.lines().any(|line| line.starts_with("side ")),
        "{listed}"
    );
    assert!(side.join("src").join("main.rs").is_file());

    let forgot = expect_ok(tig(&repo).args(["workspace", "forget", "side"]));
    assert!(forgot.contains("forgot workspace side"), "{forgot}");
    let listed = expect_ok(tig(&repo).args(["workspace", "list"]));
    assert!(
        listed.lines().all(|line| !line.starts_with("side ")),
        "{listed}"
    );
    assert!(
        listed.lines().any(|line| line.starts_with("default ")),
        "{listed}"
    );
    assert!(side.join("src").join("main.rs").is_file());

    let marked = expect_ok(tig(&repo).args(["bookmark", "set", "main"]));
    assert!(marked.contains("bookmark main:"), "{marked}");
    let marks = expect_ok(tig(&repo).args(["bookmark", "list"]));
    assert!(
        marks.lines().any(|line| line.starts_with("main ")),
        "{marks}"
    );
    let deleted = expect_ok(tig(&repo).args(["bookmark", "delete", "main"]));
    assert!(deleted.contains("deleted bookmark main"), "{deleted}");
    let marks = expect_ok(tig(&repo).args(["bookmark", "list"]));
    assert_eq!(marks.trim(), "No bookmarks.");

    let cat = run(tig(&repo).args(["cat", "src/main.rs"]));
    assert_eq!(cat.code, Some(0), "{}", cat.stderr);
    assert_eq!(cat.stdout, "fn main() {}\n");

    let private_text = fs::read_to_string(repo.join(".private")).unwrap();
    let line_no = private_text
        .lines()
        .position(|line| line == ".env*")
        .expect("default .env* rule")
        + 1;
    let why_env = expect_ok(tig(&repo).args(["why", ".env"]));
    assert_eq!(
        why_env.trim(),
        format!(".env is private (group: private) because of .private line {line_no}: .env*")
    );
    let why_src = expect_ok(tig(&repo).args(["why", "src/main.rs"]));
    assert_eq!(why_src.trim(), "src/main.rs is public (no rule matches)");

    let bad = run(tig(&repo).args(["show", "not-a-rev"]));
    assert_eq!(bad.code, Some(1));
    assert!(bad.stderr.starts_with("error:"), "{}", bad.stderr);

    let elsewhere = tmp.path().join("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    let missing = run(tig(&elsewhere).args(["status"]));
    assert_eq!(missing.code, Some(1));
    assert!(missing.stderr.starts_with("error:"), "{}", missing.stderr);
    let via_flag = expect_ok(tig(&elsewhere).arg("-R").arg(&repo).arg("st"));
    assert!(
        via_flag
            .lines()
            .any(|line| line.starts_with("working change:")),
        "{via_flag}"
    );

    let snapshot = ops
        .lines()
        .find(|line| line.contains("snapshot workspace") && !line.contains("undo"))
        .expect("edit snapshot in the op log");
    let op_id = snapshot.split_whitespace().next().expect("op id");
    let restored = expect_ok(tig(&repo).args(["op", "restore", op_id]));
    assert!(restored.contains("restored "), "{restored}");
    assert!(restored.contains("Working change:"), "{restored}");
    let body = fs::read_to_string(repo.join("src/main.rs")).unwrap();
    assert!(body.contains("// edited"), "{body}");
}

#[test]
fn init_hints_when_author_is_unset() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let repo = tmp.path().join("repo");
    fs::create_dir(&home).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_tig"));
    cmd.current_dir(tmp.path())
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env_remove("TIG_AUTHOR_NAME")
        .env_remove("TIG_AUTHOR_EMAIL")
        .env("TIG_TIMESTAMP_MS", "0")
        .arg("init")
        .arg(&repo);
    let run = run(&mut cmd);
    assert_eq!(
        run.code,
        Some(0),
        "stdout:\n{}\nstderr:\n{}",
        run.stdout,
        run.stderr
    );
    assert!(run.stdout.contains("wrote .private"), "{}", run.stdout);
    assert!(run.stderr.contains("hint:"), "{}", run.stderr);
    assert!(run.stderr.contains("@localhost"), "{}", run.stderr);
}

#[test]
fn usage_error_exits_2() {
    let tmp = tempfile::tempdir().unwrap();
    let run = run(tig(tmp.path()).args(["--not-a-flag"]));
    assert_eq!(run.code, Some(2), "{}", run.stderr);
}
