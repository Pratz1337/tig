use std::process::Command;

use tig_core::RepoPath;
use tig_private::rules::Rules;

fn private(pattern: &str, path: &str) -> bool {
    Rules::parse(pattern)
        .unwrap()
        .is_private(&RepoPath::new(path).unwrap())
}

/// Use Git's installed matcher as an oracle, without reading its source.
fn git_matches(pattern: &str, paths: &[&str]) -> Vec<bool> {
    let dir = tempfile::tempdir().unwrap();
    let init = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(init.status.success());
    std::fs::write(dir.path().join(".gitignore"), format!("{pattern}\n")).unwrap();
    paths
        .iter()
        .map(|path| {
            let result = Command::new("git")
                .args([
                    "-c",
                    "core.ignoreCase=false",
                    "-c",
                    "core.excludesFile=",
                    "check-ignore",
                    "--no-index",
                    "-q",
                    "--",
                    path,
                ])
                .current_dir(dir.path())
                .output()
                .unwrap();
            assert!(matches!(result.status.code(), Some(0 | 1)), "{:?}", result);
            result.status.success()
        })
        .collect()
}

#[test]
fn whole_component_star_runs_follow_git() {
    for pattern in [
        "***/secret",
        "/***/secret",
        "a/***/secret",
        "a/****/secret",
        "a/**/**/secret",
    ] {
        let paths = [
            "secret",
            "x/secret",
            "x/y/secret",
            "a/secret",
            "a/x/secret",
            "a/x/y/secret",
            "z/a/secret",
        ];
        let want = git_matches(pattern, &paths);
        for (path, want) in paths.into_iter().zip(want) {
            assert_eq!(private(pattern, path), want, "{pattern:?} at {path:?}");
        }
    }
}

#[test]
fn gitignore_globs_escapes_and_classes_match_git() {
    let cases: &[(&str, &[&str])] = &[
        ("**/", &["a", "a/b", "a/b/c"]),
        ("/**", &["a", "a/b", "a/b/c"]),
        ("a/**", &["a", "a/b", "a/b/c", "x/a/b"]),
        ("a/**/", &["a", "a/b", "a/b/c", "x/a/b"]),
        ("a/**/b", &["a/b", "a/x/b", "a/x/y/b", "a/xb", "x/a/b"]),
        ("**a/b", &["a/b", "xa/b", "x/ya/b"]),
        ("a/**b/c", &["a/b/c", "a/xb/c", "a/x/yb/c"]),
        ("**\\/secret", &["secret", "x/secret", "x/y/secret"]),
        ("a\\/b", &["a/b", "x/a/b", "a/b/c"]),
        ("\\/dir", &["dir", "dir/x", "x/dir", "x/dir/y"]),
        ("dir\\/", &["dir", "dir/x", "x/dir", "x/dir/y"]),
        ("a/**\\/b", &["a/b", "a/x/b", "a/x/y/b"]),
        ("a\\/**/b", &["a/b", "a/x/b", "a/x/y/b"]),
        ("a\\/**\\/b", &["a/b", "a/x/b", "a/x/y/b"]),
        ("***\\/secret", &["secret", "x/secret", "x/y/secret"]),
        (r"literal\*", &["literal*", "literalX", "x/literal*"]),
        (r"\[abc]", &["[abc]", "a", "x/[abc]"]),
        (r"\#secret", &["#secret", "secret", "x/#secret"]),
        (r"\!secret", &["!secret", "secret", "x/!secret"]),
        (
            "My\\ Secrets/**",
            &["My Secrets/a", "My/a", "x/My Secrets/a"],
        ),
        ("[!ab].key", &["a.key", "c.key", "].key", "x/c.key"]),
        ("[^ab].key", &["a.key", "c.key", "].key", "x/c.key"]),
        ("[]ab].key", &["] .key", "].key", "a.key", "c.key"]),
        (r"[\]a].key", &["] .key", "].key", "a.key", "c.key"]),
        ("[a-c].key", &["a.key", "b.key", "c.key", "d.key"]),
        ("[.-0].key", &["..key", "0.key", "a/.key"]),
        (r"[\--0].key", &["-.key", "..key", "0.key", "a/.key"]),
        (r"[a\-c].key", &["a.key", "-.key", "b.key", "c.key"]),
        (
            "[$(|)#].key",
            &["$.key", "(.key", "|.key", "#.key", "x.key"],
        ),
        (
            "d[$(|)#]/**",
            &["d$/key", "d(/key", "d|/key", "d#/key", "dX/key"],
        ),
        ("dir/", &["dir", "dir/x", "x/dir", "x/dir/y"]),
        ("/dir/", &["dir", "dir/x", "x/dir", "x/dir/y"]),
        (
            "secret\u{a0}",
            &["secret\u{a0}", "secret", "x/secret\u{a0}"],
        ),
        ("secret\u{2003}key", &["secret\u{2003}key", "secretkey"]),
    ];
    let mut failures = Vec::new();
    for &(pattern, paths) in cases {
        let want = git_matches(pattern, paths);
        for (&path, want) in paths.iter().zip(want) {
            if private(pattern, path) != want {
                failures.push(format!("{pattern:?} at {path:?}: want {want}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn embedded_double_stars_keep_the_more_private_reading() {
    // Git 2.39.5 crosses '/' here; Git 2.56 does not. Protect both readings.
    for (path, want) in [
        ("a/b", true), ("ax/b", true), ("ax/y/b", true), ("x/a/b", false),
    ] {
        assert_eq!(private("a**/b", path), want, "{path}");
    }
    assert!(private("**\n!a**/b", "ax/y/b"));
    assert!(!private("**\n!a**/b", "ax/b"));
    assert!(!private("a**/b\n!ax/y/b", "ax/y/b"));
    for pattern in ["a***/b", "a**/", "a**\\/b", "dir/a**/b"] {
        let path = if pattern.starts_with("dir/") {
            "dir/ax/y/b"
        } else {
            "ax/y/b"
        };
        assert!(private(pattern, path), "{pattern}");
    }
}

#[test]
fn unicode_nfc_and_simple_case_folding_are_explicit() {
    for (pattern, path, want) in [
        ("ǅ.key", "Ǆ.KEY", true),
        ("ǅ.key", "ǆ.key", true),
        ("Σ.key", "ς.key", true),
        ("Σ.key", "σ.key", true),
        ("ß.key", "ẞ.key", true),
        ("ß.key", "ss.key", false),
        ("İ.key", "i.key", false),
        ("İ.key", "i\u{307}.key", false),
        ("ﬁ.key", "fi.key", false),
        ("CAFÉ.key", "cafe\u{301}.KEY", true),
        ("[A-Z].key", "é.key", false),
        ("[A-Z].key", "ſ.key", true),
        ("[A-Z].key", "K.key", true),
        ("[À-Ö].key", "é.key", true),
        ("[À-Ö].key", "ø.key", false),
        ("[!À-Ö].key", "é.key", false),
    ] {
        assert_eq!(private(pattern, path), want, "{pattern:?} at {path:?}");
    }
}

#[test]
fn invalid_and_oversized_rules_return_clear_errors() {
    for pattern in [
        "/",
        "//",
        "a//b",
        "a\\",
        "a[",
        "a[/]b",
        "[z-a]",
        "[[:alpha:]]",
    ] {
        let err = Rules::parse(&format!("# comment\n{pattern}\n")).unwrap_err();
        assert_eq!(err.line, 2, "{pattern}");
        assert!(!err.message.is_empty());
    }
    // Literal backslashes cannot occur in a portable repo path; the parser
    // still accepts an escaped backslash without reinterpreting it as a glob.
    let literal_backslash = Rules::parse(r"secret\\*").unwrap();
    assert!(!literal_backslash.is_private(&RepoPath::new("secret.key").unwrap()));
    let long = "secret".repeat(50_000);
    let err = Rules::parse(&long).unwrap_err();
    assert_eq!(err.line, 1);
    assert!(err.message.contains("size"), "{err}");
}

/// Compiling 25,000 rules takes ~15 s, so it is opt-in.
#[test]
#[ignore = "slow (~15 s): run with `cargo test -- --ignored`"]
fn too_many_rules_return_a_clear_error() {
    let many: String = (0..25_000)
        .map(|n| format!("secret/key-{n:05}\n"))
        .collect();
    let err = Rules::parse(&many).unwrap_err();
    assert_eq!(err.line, 25_000);
    assert!(err.message.contains("rules too large"), "{err}");
}

#[test]
fn unicode_spaces_are_literal_and_escaped_trailing_spaces_parse() {
    for pattern in ["secret\u{a0}", "secret\u{2003}key", "secret\\\u{a0}"] {
        let path = pattern.replace('\\', "");
        assert!(private(pattern, &path), "{pattern:?}");
    }
    let rules = Rules::parse("secret\\ \n").unwrap();
    assert!(!rules.is_private(&RepoPath::new("secret").unwrap()));
    let rules = Rules::parse("secret\\   \n").unwrap();
    assert!(!rules.is_private(&RepoPath::new("secret").unwrap()));
}

#[test]
fn directory_negation_documents_the_contract_decision() {
    // DESIGN says last match wins; Git additionally prunes ignored parents.
    // Keep this difference explicit until the owner chooses the contract.
    let text = "secrets/\n!secrets/public.key";
    assert_eq!(git_matches(text, &["secrets/public.key"]), vec![true]);
    assert!(!private(text, "secrets/public.key"));
    assert!(private(text, "secrets/private.key"));
    assert!(!private("secrets/\n!secrets/", "secrets/private.key"));
    assert!(!private("secrets/\n!secrets/", "secrets"));
}

#[test]
fn unescaped_leading_spaces_cannot_silently_change_a_pattern() {
    assert_eq!(
        git_matches(" secret.key", &[" secret.key", "secret.key"]),
        vec![true, false]
    );
    let error = Rules::parse("# comment\n secret.key\n").unwrap_err();
    assert_eq!(error.line, 2);
    assert!(error.message.contains("leading whitespace"));
    assert!(private(r"\ secret.key", " secret.key"));
    assert!(Rules::parse(" \t \n").is_ok());
}

#[test]
fn unicode_wildcards_document_the_git_compatibility_decision() {
    // The regex matcher counts Unicode scalars; Git wildmatch counts bytes.
    // A negation makes this difference privacy-relevant, so pin the evidence
    // without choosing new wildcard semantics in a review fix.
    for text in ["*.key\n!?.key", "*.key\n![À-Ö].key"] {
        assert_eq!(git_matches(text, &["é.key"]), vec![true]);
        assert!(!private(text, "é.key"));
    }
}

#[test]
fn escaped_separators_and_class_boundaries_follow_git() {
    use std::io::Write;
    use std::process::Stdio;

    let dir = tempfile::tempdir().unwrap();
    assert!(Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .status()
        .unwrap()
        .success());
    let paths = [
        "a/b",
        "a/x/b",
        "a/x/y/b",
        "b",
        "x/b",
        "a/b/x",
        "a.key",
        "b.key",
        "c.key",
        "-.key",
        "].key",
        "[.key",
        "&.key",
        "~.key",
        "a/secret",
        "a/x/secret",
    ];
    for pattern in [
        r"a\/**/b",
        r"a\/**\/**/b",
        r"**\/**/b",
        r"a/**\/**/b",
        r"a/**/b\/",
        r"a\/**/",
        r"a\/**",
        r"[a-b-c].key",
        r"[a\-c-e].key",
        r"[!\]a].key",
        r"[[]\.key",
        r"[&&~].key",
        r"[\^-a].key",
        r"**\/**/secret",
    ] {
        let rules = Rules::parse(pattern).unwrap();
        std::fs::write(dir.path().join(".gitignore"), format!("{pattern}\n")).unwrap();
        let mut child = Command::new("git")
            .args([
                "-c",
                "core.ignoreCase=false",
                "-c",
                "core.excludesFile=",
                "check-ignore",
                "--no-index",
                "-v",
                "-z",
                "--stdin",
            ])
            .current_dir(dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(paths.join("\0").as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(matches!(output.status.code(), Some(0 | 1)));
        let records: Vec<_> = output.stdout.split(|&byte| byte == 0).collect();
        let matched: Vec<_> = records
            .as_chunks::<4>()
            .0
            .iter()
            .map(|record| std::str::from_utf8(record[3]).unwrap())
            .collect();
        for path in paths {
            assert_eq!(
                rules.is_private(&RepoPath::new(path).unwrap()),
                matched.contains(&path),
                "{pattern:?} at {path:?}"
            );
        }
    }
}
