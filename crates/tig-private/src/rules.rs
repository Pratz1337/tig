//! Parsing and matching for the `.private` file.
//!
//! The file is gitignore syntax plus optional `@role` tags. It is compiled
//! once into a single [`globset::GlobSet`]; classifying a path is one query
//! against that set, and the last matching rule wins.

use std::collections::BTreeSet;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};
use tig_core::RepoPath;
use unicode_normalization::UnicodeNormalization;

/// Built-in access group for a positive rule that names no roles.
const BUILTIN_ROLE: &str = "private";

/// Default `.private` contents for a new repository.
///
/// Environment files and private keys are private. The header comment in the
/// string describes the rule format.
pub const DEFAULT_PRIVATE: &str = "\
# .private: paths matched here are private. The repository is public by default.
# gitignore syntax. The last matching line wins. A leading ! makes a path public.
# Optional @role tags choose who can read the path. With no tags, the group is private.
# Write a space inside a pattern as a backslash followed by a space.
.env*
!.env.example
!.env.sample
!.env.template
*.pem
*.key
*.p12
*.pfx
id_rsa
id_dsa
id_ecdsa
id_ed25519
";

/// A problem in a `.private` file. `line` is 1-based. Parsing stops at the first one.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("line {line}: {message}")]
pub struct RuleError {
    /// 1-based line number in the file.
    pub line: usize,
    /// What is wrong with that line.
    pub message: String,
}

/// The rule that decided a path, so a caller can show why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRef {
    /// 1-based line number.
    pub line: usize,
    /// The rule line as written, with trailing whitespace removed.
    pub text: String,
}

/// Whether a path is public or private, and which rule decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Public. `rule` is set when a negation line was the last match.
    Public { rule: Option<RuleRef> },
    /// Private, readable by `readers`. The built-in group is `private`.
    Private {
        readers: BTreeSet<String>,
        rule: RuleRef,
    },
}

/// One parsed rule, plus the readers it grants when it is the last match.
#[derive(Clone, Debug)]
struct CompiledRule {
    reference: RuleRef,
    negated: bool,
    readers: BTreeSet<String>,
}

/// A compiled `.private` file.
///
/// Patterns are turned into one [`GlobSet`] at parse time. [`Rules::classify`]
/// asks that set once and keeps the highest matching rule index.
#[derive(Clone, Debug)]
pub struct Rules {
    set: GlobSet,
    /// Glob index → rule index. Globs are appended in rule order, so the
    /// highest matching glob index belongs to the last matching rule.
    glob_to_rule: Vec<usize>,
    rules: Vec<CompiledRule>,
    /// Custom roles named anywhere in the file. Never includes `private`.
    roles: BTreeSet<String>,
}

impl Rules {
    /// No rules. Every path is public, and the file is in simple mode.
    pub fn empty() -> Self {
        Rules {
            set: GlobSet::empty(),
            glob_to_rule: Vec::new(),
            rules: Vec::new(),
            roles: BTreeSet::new(),
        }
    }

    /// Parse a `.private` file. Stops at the first bad line.
    pub fn parse(text: &str) -> Result<Self, RuleError> {
        let mut rules = Vec::new();
        let mut builder = GlobSetBuilder::new();
        let mut glob_to_rule = Vec::new();
        let mut roles = BTreeSet::new();

        for (idx, raw) in text.lines().enumerate() {
            let line_no = idx + 1;
            let line = raw.trim_end();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let tokens = split_tokens(line);
            let mut tokens = tokens.iter().map(String::as_str);
            // `trim_end` left a non-empty line, so there is at least one token.
            let Some(first) = tokens.next() else {
                continue;
            };
            let (negated, pattern) =
                split_negation(first).map_err(|message| rule_error(line_no, message))?;
            let rest: Vec<&str> = tokens.collect();
            if negated && !rest.is_empty() {
                return Err(rule_error(
                    line_no,
                    "a negated pattern cannot have @role tags",
                ));
            }

            let mut readers = BTreeSet::new();
            for token in rest {
                let role = parse_role(token).map_err(|message| rule_error(line_no, message))?;
                if role != BUILTIN_ROLE {
                    roles.insert(role.clone());
                }
                readers.insert(role);
            }
            if !negated && readers.is_empty() {
                readers.insert(BUILTIN_ROLE.to_string());
            }

            let pattern: String = pattern.nfc().collect();
            let globs = globs_for(&pattern).map_err(|message| rule_error(line_no, message))?;
            let rule_index = rules.len();
            for glob_pattern in &globs {
                let glob =
                    compile_glob(glob_pattern).map_err(|message| rule_error(line_no, message))?;
                builder.add(glob);
                glob_to_rule.push(rule_index);
            }
            rules.push(CompiledRule {
                reference: RuleRef {
                    line: line_no,
                    text: line.to_string(),
                },
                negated,
                readers,
            });
        }

        let set = builder.build().map_err(|e| {
            let line = rules.last().map(|rule| rule.reference.line).unwrap_or(1);
            rule_error(line, format!("invalid pattern: {e}"))
        })?;
        debug_assert_eq!(glob_to_rule.len(), set.len());
        Ok(Rules {
            set,
            glob_to_rule,
            rules,
            roles,
        })
    }

    /// Classify `path`. The repo root is always public.
    ///
    /// The path and every pattern are compared in Unicode NFC, without regard
    /// to ASCII case. The last matching line wins.
    pub fn classify(&self, path: &RepoPath) -> Verdict {
        if path.is_root() {
            return Verdict::Public { rule: None };
        }
        let normalized: String = path.as_str().nfc().collect();
        // One GlobSet query. Glob indices increase with rule order.
        let winner = self
            .set
            .matches(&normalized)
            .into_iter()
            .map(|glob| self.glob_to_rule[glob])
            .max();
        match winner {
            None => Verdict::Public { rule: None },
            Some(index) => {
                let rule = &self.rules[index];
                if rule.negated {
                    Verdict::Public {
                        rule: Some(rule.reference.clone()),
                    }
                } else {
                    Verdict::Private {
                        readers: rule.readers.clone(),
                        rule: rule.reference.clone(),
                    }
                }
            }
        }
    }

    /// Whether `classify` would return [`Verdict::Private`].
    pub fn is_private(&self, path: &RepoPath) -> bool {
        matches!(self.classify(path), Verdict::Private { .. })
    }

    /// Every custom role named in the file, in sorted order. Excludes `private`.
    pub fn roles(&self) -> BTreeSet<String> {
        self.roles.clone()
    }

    /// True when the file names no custom roles.
    ///
    /// `@private` is the built-in group, so a file that only uses it is still
    /// in simple mode.
    pub fn is_simple_mode(&self) -> bool {
        self.roles.is_empty()
    }
}

/// Splits a rule line on unescaped whitespace. `\ ` stays in the token as an
/// escaped space, which the glob compiler reads as a literal space.
fn split_tokens(line: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            cur.push(c);
            if let Some(next) = chars.next() {
                cur.push(next);
            }
        } else if c.is_whitespace() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
        } else {
            cur.push(c);
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

fn rule_error(line: usize, message: impl Into<String>) -> RuleError {
    RuleError {
        line,
        message: message.into(),
    }
}

/// Split a leading `!` from a pattern token. `\!` and `\#` are literals.
fn split_negation(token: &str) -> Result<(bool, String), String> {
    if let Some(rest) = token.strip_prefix("\\!") {
        return Ok((false, format!("!{rest}")));
    }
    if let Some(rest) = token.strip_prefix("\\#") {
        return Ok((false, format!("#{rest}")));
    }
    if let Some(rest) = token.strip_prefix('!') {
        if rest.is_empty() {
            return Err("empty pattern".into());
        }
        return Ok((true, rest.to_string()));
    }
    Ok((false, token.to_string()))
}

fn parse_role(token: &str) -> Result<String, String> {
    let Some(name) = token.strip_prefix('@') else {
        return Err(format!(
            "unexpected token {token:?}: write spaces inside a pattern as \"\\ \"; tags start with @"
        ));
    };
    let ok = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_' | '-'));
    if !ok {
        return Err(format!(
            "invalid role {token:?}: role names are lowercase [a-z0-9_-]+ and at most 64 characters"
        ));
    }
    Ok(name.to_string())
}

/// Gitignore pattern → globs that classify file paths.
///
/// A pattern with no `/` other than a trailing directory slash matches that
/// basename at any depth (`**/name` and `**/name/**`). Any other `/` anchors
/// it at the repo root, after one leading `/` is stripped. A trailing `/`
/// matches the contents of a directory, not a file of that name. A pattern
/// that matches a directory also matches everything inside it, because callers
/// classify file paths rather than pruning a directory walk.
fn globs_for(pattern: &str) -> Result<Vec<String>, String> {
    if pattern.is_empty() {
        return Err("empty pattern".into());
    }
    let directory = pattern.ends_with('/');
    let pattern = pattern.trim_end_matches('/');
    if pattern.is_empty() {
        return Err("empty pattern".into());
    }
    // Decide anchoring before stripping a leading `/`, or `/build` would look
    // like the unanchored basename `build`.
    let anchored = pattern.contains('/');
    let pattern = pattern.strip_prefix('/').unwrap_or(pattern);
    if pattern.is_empty() {
        return Err("empty pattern".into());
    }
    let base = if anchored {
        pattern.to_string()
    } else {
        format!("**/{pattern}")
    };
    // A glob that already ends in `/**` matches every file under that prefix.
    let covers_inside = base.ends_with("/**");
    let mut globs = Vec::with_capacity(2);
    if directory {
        globs.push(if covers_inside {
            base
        } else {
            format!("{base}/**")
        });
    } else {
        globs.push(base.clone());
        if !covers_inside {
            globs.push(format!("{base}/**"));
        }
    }
    Ok(globs)
}

fn compile_glob(pattern: &str) -> Result<globset::Glob, String> {
    // `backslash_escape` is off by default on Windows, where `\` is a
    // separator. Force it on so the same pattern compiles the same way
    // everywhere. `\#` and `\!` are decoded before we get here.
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .case_insensitive(true)
        .backslash_escape(true)
        .build()
        .map_err(|e| format!("invalid pattern {pattern:?}: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_ok(text: &str) -> Rules {
        Rules::parse(text).unwrap_or_else(|e| panic!("parse failed: {e}"))
    }

    fn rp(path: &str) -> RepoPath {
        RepoPath::new(path).unwrap_or_else(|e| panic!("path {path:?}: {e}"))
    }

    fn assert_private(rules: &Rules, path: &str) {
        let path = rp(path);
        assert!(
            rules.is_private(&path),
            "{path} should be private, got {:?}",
            rules.classify(&path)
        );
    }

    fn assert_public(rules: &Rules, path: &str) {
        let path = rp(path);
        assert!(
            !rules.is_private(&path),
            "{path} should be public, got {:?}",
            rules.classify(&path)
        );
    }

    #[test]
    fn default_file() {
        let rules = parse_ok(DEFAULT_PRIVATE);
        assert!(rules.is_simple_mode());
        assert!(rules.roles().is_empty());
        for path in [
            ".env",
            ".env.local",
            "config/.ENV.prod",
            "certs/server.pem",
            "id_rsa.key",
            "src/.env",
            "home/.ssh/id_ed25519",
            "certs/client.p12",
        ] {
            assert_private(&rules, path);
        }
        for path in [
            ".env.example",
            "config/.env.sample",
            "id_rsa.pub",
            "env.txt",
            "src/main.rs",
            "production.env",
            "certs/server.pem.bak",
            "readme.txt",
        ] {
            assert_public(&rules, path);
        }

        let crlf = DEFAULT_PRIVATE.replace('\n', "\r\n");
        let from_crlf = parse_ok(&crlf);
        assert_private(&from_crlf, "config/.ENV.prod");
        assert_public(&from_crlf, "env.txt");
    }

    #[test]
    fn basename_versus_anchored() {
        let rooted = parse_ok("/build\n");
        for path in ["build", "build/out.o", "build/a/b.o"] {
            assert_private(&rooted, path);
        }
        for path in [
            "src/build",
            "src/build/out.o",
            "building",
            "rebuild",
            "lib/rebuild/a",
        ] {
            assert_public(&rooted, path);
        }

        let anywhere = parse_ok("build\n");
        for path in [
            "build",
            "build/out.o",
            "src/build",
            "src/build/out.o",
            "lib/build/a.o",
        ] {
            assert_private(&anywhere, path);
        }
        for path in ["building", "src/building", "rebuild", "src/rebuild/a"] {
            assert_public(&anywhere, path);
        }

        let docs = parse_ok("docs/secret.md\n");
        assert_private(&docs, "docs/secret.md");
        assert_private(&docs, "docs/secret.md/extra");
        for path in [
            "secret.md",
            "src/docs/secret.md",
            "docs/other.md",
            "other/docs/secret.md",
        ] {
            assert_public(&docs, path);
        }
    }

    #[test]
    fn directory_patterns_and_contents() {
        let dir_only = parse_ok("secrets/\n");
        for path in [
            "secrets/a.txt",
            "secrets/a/b.txt",
            "nested/secrets/a.txt",
            "a/b/secrets/c",
        ] {
            assert_private(&dir_only, path);
        }
        for path in ["secrets", "nested/secrets", "secrets2/a.txt", "mysecrets/a"] {
            assert_public(&dir_only, path);
        }

        let name = parse_ok("secrets\n");
        for path in [
            "secrets",
            "secrets/a/b.txt",
            "nested/secrets",
            "nested/secrets/a.txt",
        ] {
            assert_private(&name, path);
        }
        for path in ["secrets2", "mysecrets/a", "secret"] {
            assert_public(&name, path);
        }
    }

    #[test]
    fn double_star_patterns() {
        let billing = parse_ok("internal/billing/**\n");
        assert_private(&billing, "internal/billing/invoice.txt");
        assert_private(&billing, "internal/billing/q/a.txt");
        for path in [
            "internal/billing",
            "internal/other.txt",
            "other/internal/billing/a.txt",
            "internal/billing.txt",
        ] {
            assert_public(&billing, path);
        }

        let keys = parse_ok("**/keys/*.json\n");
        for path in [
            "keys/a.json",
            "a/keys/b.json",
            "a/b/keys/c.json",
            "keys/a.json/extra",
        ] {
            assert_private(&keys, path);
        }
        for path in [
            "keys/sub/a.json",
            "keys/a.txt",
            "key/a.json",
            "keys/a.json.bak",
            "mykeys/a.json",
        ] {
            assert_public(&keys, path);
        }

        let middle = parse_ok("a/**/b.txt\n");
        for path in ["a/b.txt", "a/x/b.txt", "a/x/y/b.txt"] {
            assert_private(&middle, path);
        }
        for path in ["b.txt", "a/x/c.txt", "z/a/b.txt"] {
            assert_public(&middle, path);
        }
    }

    #[test]
    fn star_does_not_cross_slash() {
        let src = parse_ok("src/*.rs\n");
        assert_private(&src, "src/main.rs");
        assert_private(&src, "src/lib.rs");
        for path in [
            "src/nested/main.rs",
            "lib.rs",
            "src/main.rs.bak",
            "other/src/main.rs",
        ] {
            assert_public(&src, path);
        }

        let wild = parse_ok("a*b\n");
        assert_private(&wild, "axb");
        assert_private(&wild, "dir/axb");
        assert_public(&wild, "a/b");
        assert_public(&wild, "dir/a/b");

        let one = parse_ok("file?.txt\n");
        assert_private(&one, "file1.txt");
        assert_private(&one, "dir/fileX.txt");
        assert_public(&one, "file12.txt");
        assert_public(&one, "file1/txt");

        let class = parse_ok("file[123].txt\n");
        assert_private(&class, "file1.txt");
        assert_private(&class, "file3.txt");
        assert_private(&class, "dir/file2.txt");
        assert_public(&class, "file4.txt");
        assert_public(&class, "file12.txt");
    }

    #[test]
    fn negation_last_match_wins() {
        let text = "# header\n\nsecrets/**\n!secrets/README.md\n";
        let rules = parse_ok(text);
        assert_private(&rules, "secrets/other.txt");
        assert_private(&rules, "secrets/sub/README.md");
        assert_public(&rules, "nested/secrets/other.txt");
        assert_public(&rules, "README.md");

        match rules.classify(&rp("secrets/README.md")) {
            Verdict::Public { rule: Some(rule) } => {
                assert_eq!(rule.line, 4);
                assert_eq!(rule.text, "!secrets/README.md");
            }
            other => panic!("expected a negation to decide README, got {other:?}"),
        }
        assert!(!rules.is_private(&rp("secrets/README.md")));
        match rules.classify(&rp("secrets/other.txt")) {
            Verdict::Private { readers, rule } => {
                assert_eq!(readers, BTreeSet::from([BUILTIN_ROLE.to_string()]));
                assert_eq!(rule.line, 3);
                assert_eq!(rule.text, "secrets/**");
            }
            other => panic!("expected secrets/** to win, got {other:?}"),
        }
        assert!(matches!(
            rules.classify(&rp("README.md")),
            Verdict::Public { rule: None }
        ));

        // A later positive rule beats an earlier negation.
        let reversed = parse_ok("!secrets/README.md\nsecrets/**\n");
        assert_private(&reversed, "secrets/README.md");
        assert_private(&reversed, "secrets/other.txt");

        // A negation that nothing else matched still records itself.
        let only_neg = parse_ok("!README.md\n");
        match only_neg.classify(&rp("README.md")) {
            Verdict::Public { rule: Some(rule) } => assert_eq!(rule.text, "!README.md"),
            other => panic!("expected the negation, got {other:?}"),
        }
        assert_public(&only_neg, "dir/README.md");
    }

    #[test]
    fn roles_dedup_sort_and_readers() {
        let text = "\
# who can read what
internal/billing/** @billing @billing @finance
*.pem @security
secrets @zebra @alpha @zebra
plain
*.key @private
mixed @private @audit
";
        let rules = parse_ok(text);
        assert!(!rules.is_simple_mode());
        assert_eq!(
            rules.roles(),
            BTreeSet::from([
                "alpha".to_string(),
                "audit".to_string(),
                "billing".to_string(),
                "finance".to_string(),
                "security".to_string(),
                "zebra".to_string(),
            ])
        );

        match rules.classify(&rp("internal/billing/a.txt")) {
            Verdict::Private { readers, rule } => {
                assert_eq!(
                    readers,
                    BTreeSet::from(["billing".to_string(), "finance".to_string()])
                );
                assert_eq!(rule.line, 2);
                assert_eq!(rule.text, "internal/billing/** @billing @billing @finance");
            }
            other => panic!("billing: {other:?}"),
        }
        match rules.classify(&rp("certs/server.pem")) {
            Verdict::Private { readers, .. } => {
                assert_eq!(readers, BTreeSet::from(["security".to_string()]));
            }
            other => panic!("pem: {other:?}"),
        }
        match rules.classify(&rp("secrets/payroll")) {
            Verdict::Private { readers, .. } => {
                assert_eq!(
                    readers,
                    BTreeSet::from(["alpha".to_string(), "zebra".to_string()])
                );
            }
            other => panic!("secrets: {other:?}"),
        }
        match rules.classify(&rp("plain")) {
            Verdict::Private { readers, .. } => {
                assert_eq!(readers, BTreeSet::from(["private".to_string()]));
            }
            other => panic!("plain: {other:?}"),
        }
        match rules.classify(&rp("id_rsa.key")) {
            Verdict::Private { readers, .. } => {
                assert_eq!(readers, BTreeSet::from(["private".to_string()]));
            }
            other => panic!("key: {other:?}"),
        }
        match rules.classify(&rp("mixed")) {
            Verdict::Private { readers, .. } => {
                assert_eq!(
                    readers,
                    BTreeSet::from(["audit".to_string(), "private".to_string()])
                );
            }
            other => panic!("mixed: {other:?}"),
        }

        let explicit = parse_ok("*.key @private\n");
        assert!(explicit.is_simple_mode());
        assert!(explicit.roles().is_empty());
        assert_private(&explicit, "a.key");

        let team = parse_ok("notes @team-a_1\n");
        assert_eq!(team.roles(), BTreeSet::from(["team-a_1".to_string()]));
    }

    #[test]
    fn errors_report_the_first_bad_line() {
        let bad_role = Rules::parse("# fine\n\n*.pem @Billing\n").unwrap_err();
        assert_eq!(bad_role.line, 3);
        assert!(
            bad_role.message.contains("invalid role"),
            "{}",
            bad_role.message
        );
        assert!(bad_role.to_string().starts_with("line 3:"), "{}", bad_role);

        let negation = Rules::parse("# a\n!secret @billing\n").unwrap_err();
        assert_eq!(negation.line, 2);
        assert!(negation.message.contains("negated"), "{}", negation.message);

        let spaces = Rules::parse("foo bar\n").unwrap_err();
        assert_eq!(spaces.line, 1);
        assert!(spaces.message.contains("unexpected token"), "{}", spaces.message);

        // The extra token is reported, not the later bad role.
        let first = Rules::parse("# ok\nfoo bar\n!nope @billing\n").unwrap_err();
        assert_eq!(first.line, 2);
        assert!(first.message.contains("unexpected token"), "{}", first.message);

        let later = Rules::parse("# ok\n\n*.txt @Bad\n!x @billing\n").unwrap_err();
        assert_eq!(later.line, 3);
        assert!(later.message.contains("invalid role"), "{}", later.message);

        for token in ["@", "@no.dot", "@Upper", "@has/slash"] {
            let err = Rules::parse(&format!("*.txt {token}\n")).unwrap_err();
            assert_eq!(err.line, 1, "{token}");
            assert!(
                err.message.contains("invalid role"),
                "{token}: {}",
                err.message
            );
        }

        let long = format!("* @{}\n", "a".repeat(65));
        let err = Rules::parse(&long).unwrap_err();
        assert_eq!(err.line, 1);
        assert!(err.message.contains("invalid role"), "{}", err.message);

        let max = format!("* @{}\n", "b".repeat(64));
        let rules = parse_ok(&max);
        assert_eq!(rules.roles().iter().next().unwrap().len(), 64);

        let glob = Rules::parse("# c\nok\nfoo[\n").unwrap_err();
        assert_eq!(glob.line, 3);
        assert!(glob.message.contains("invalid pattern"), "{}", glob.message);

        let empty = Rules::parse("!\n").unwrap_err();
        assert_eq!(empty.line, 1);
        assert!(empty.message.contains("empty"), "{}", empty.message);
    }

    #[test]
    fn escaped_spaces() {
        let rules = parse_ok("My\\ Secrets/ @team\nnotes\\ 2024.txt\n");
        assert_private(&rules, "My Secrets/plan.txt");
        assert_private(&rules, "docs/notes 2024.txt");
        assert_public(&rules, "My/plan.txt");
        match rules.classify(&rp("My Secrets/plan.txt")) {
            Verdict::Private { readers, .. } => assert_eq!(readers, BTreeSet::from(["team".to_string()])),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn case_insensitive() {
        let rules = parse_ok("Secrets/**\nDocs/Secret.md\n*.PEM\n");
        assert_private(&rules, "secrets/a.txt");
        assert_private(&rules, "SECRETS/A.TXT");
        assert_private(&rules, "docs/secret.md");
        assert_private(&rules, "DOCS/SECRET.MD");
        assert_private(&rules, "Certs/Server.pem");
        assert_public(&rules, "public.txt");
    }

    #[test]
    fn unicode_nfc() {
        let precomposed = "caf\u{e9}/**\n";
        let decomposed = "cafe\u{0301}/**\n";
        let from_nfc = parse_ok(precomposed);
        let from_nfd = parse_ok(decomposed);

        let nfd_path = "cafe\u{0301}/secret.txt";
        let nfc_path = "caf\u{e9}/secret.txt";
        assert_private(&from_nfc, nfd_path);
        assert_private(&from_nfc, nfc_path);
        assert_private(&from_nfd, nfd_path);
        assert_private(&from_nfd, nfc_path);
        assert_public(&from_nfc, "cafe/secret.txt");
        assert_public(&from_nfd, "cafe/secret.txt");

        // A decomposed pattern also matches a precomposed basename with no slash.
        let name = parse_ok("caf\u{e9}.txt\n");
        assert_private(&name, "sub/cafe\u{0301}.txt");
        assert_public(&name, "sub/cafe.txt");
    }

    #[test]
    fn escaped_hash_and_bang() {
        let rules = parse_ok("#secret\n\\#secret\n\\!keep\n");
        assert_public(&rules, "secret");
        assert_private(&rules, "#secret");
        assert_private(&rules, "dir/#secret");
        assert_private(&rules, "!keep");
        assert_private(&rules, "sub/!keep");
        assert_public(&rules, "keep");

        // The escaped bang is a literal pattern, so a role is allowed.
        let with_role = parse_ok("\\!keep @audit\n");
        match with_role.classify(&rp("!keep")) {
            Verdict::Private { readers, rule } => {
                assert_eq!(readers, BTreeSet::from(["audit".to_string()]));
                assert_eq!(rule.text, "\\!keep @audit");
            }
            other => panic!("expected literal !keep, got {other:?}"),
        }
    }

    #[test]
    fn empty_root_and_simple_mode() {
        let empty = Rules::empty();
        assert!(empty.is_simple_mode());
        assert!(empty.roles().is_empty());
        assert_public(&empty, "src/main.rs");
        assert!(matches!(
            empty.classify(&RepoPath::root()),
            Verdict::Public { rule: None }
        ));

        let comments = parse_ok("# only a comment\n\n# another\n");
        assert!(comments.is_simple_mode());
        assert_public(&comments, ".env");

        let star = parse_ok("*\n");
        assert_private(&star, "a");
        assert_private(&star, "a/b/c");
        assert!(matches!(
            star.classify(&RepoPath::root()),
            Verdict::Public { rule: None }
        ));
    }
}
