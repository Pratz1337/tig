//! Parsing and matching for the `.private` file.
//!
//! The file is gitignore syntax plus optional `@role` tags. Each rule is
//! translated by hand into one anchored regex (so the gitignore rules hold
//! exactly: `*`, `?` and `[...]` never match `/`, and `{}` is literal), and
//! all rules are compiled once into a single [`regex::RegexSet`]. Classifying
//! a path is one query against that set; the last matching rule wins.
//!
//! Matching is Unicode case-insensitive (the regex crate's simple case
//! folding, so `.ÉNV` matches `.énv`) on NFC-normalized text.
//!
//! The built-in floor ([`DEFAULT_PRIVATE`]) always applies underneath the
//! repository file. [`Rules::parse_layered`] puts the floor first and the
//! file after it, so the last match still wins: the file can add private
//! paths, and it can make a default-private path public only with an
//! explicit `!` line. Deleting or emptying `.private` leaves the floor in
//! place, so `.env` stays private. [`Rules::parse`] reads one text and does
//! not add the floor; publish and [`crate::project::rules_of`] use the
//! layered rules.

use std::collections::BTreeSet;

use regex::{RegexSet, RegexSetBuilder};
use tig_core::RepoPath;
use unicode_normalization::UnicodeNormalization;

/// Built-in access group for a positive rule that names no roles.
const BUILTIN_ROLE: &str = "private";

/// The `.private` file `tig init` writes. It holds no rules of its own: the
/// defaults are the built-in floor ([`DEFAULT_PRIVATE`]), which applies
/// anyway. Copying them into the file would turn the floor's own `!` lines
/// into the user's negations, which publish then asks them to confirm.
pub const PRIVATE_FILE_TEMPLATE: &str = "\
# .private: paths matched here are private. The repository is public by default.
# gitignore syntax. The last matching line wins. Write a space as \"\\ \".
# Optional @role tags choose who can read a path (default: the private group).
#
# Always private, even if this file is deleted (built-in defaults):
#   .env* (except .env.example, .env.sample, .env.template),
#   *.pem, *.key, *.p12, *.pfx, id_rsa, id_dsa, id_ecdsa, id_ed25519
# To publish one of those on purpose, add a line like:  !.env.public
# (publish asks you to confirm the first time).
#
# Add your own private paths below, for example:
#   secrets/
#   config/production.yml
";

/// The built-in floor. These rules apply underneath the repository's
/// `.private` even when that file is missing or empty. Environment files and
/// private keys are private.
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

/// Where the deciding rule was written. Line numbers count inside that text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleSource {
    /// A line of the built-in floor ([`DEFAULT_PRIVATE`]).
    BuiltIn,
    /// A line of the repository's `.private` file.
    File,
}

/// The rule that decided a path, so a caller can show why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleRef {
    /// 1-based line number inside [`source`](Self::source), not in the other text.
    pub line: usize,
    /// The rule line as written, with unescaped trailing ASCII spaces removed.
    pub text: String,
    /// Built-in floor, or the repository file.
    pub source: RuleSource,
}

impl RuleRef {
    /// Text for `tig why`. A floor decision reads `built-in default rule: .env*`.
    pub fn explanation(&self) -> String {
        match self.source {
            RuleSource::BuiltIn => format!("built-in default rule: {}", self.text),
            RuleSource::File => format!(".private line {}: {}", self.line, self.text),
        }
    }
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
/// Rule `i` is regex `i` of one [`RegexSet`] built at parse time.
/// [`Rules::classify`] asks that set once and keeps the highest match.
#[derive(Clone, Debug)]
pub struct Rules {
    set: RegexSet,
    rules: Vec<CompiledRule>,
    /// Custom roles named anywhere in the file. Never includes `private`.
    roles: BTreeSet<String>,
}

impl Rules {
    /// No rules. Every path is public, and the file is in simple mode.
    pub fn empty() -> Self {
        Rules {
            set: RegexSet::empty(),
            rules: Vec::new(),
            roles: BTreeSet::new(),
        }
    }

    /// Parse one `.private` text. Stops at the first bad line.
    ///
    /// Does not add the built-in floor. Publish and
    /// [`crate::project::rules_of`] use [`Rules::parse_layered`] so a missing
    /// file still hides `.env`.
    pub fn parse(text: &str) -> Result<Self, RuleError> {
        Self::compile(&[(text, RuleSource::File)])
    }

    /// Rules from `base`, then rules from `file`. The last match wins.
    ///
    /// Line numbers stay inside the text they came from. A bad line in
    /// `file` reports that file's line, not a line of `base`. Pass
    /// [`DEFAULT_PRIVATE`] as `base` for the built-in floor.
    pub fn parse_layered(base: &str, file: &str) -> Result<Self, RuleError> {
        Self::compile(&[(base, RuleSource::BuiltIn), (file, RuleSource::File)])
    }

    fn compile(parts: &[(&str, RuleSource)]) -> Result<Self, RuleError> {
        let mut rules = Vec::new();
        let mut regexes = Vec::new();
        let mut roles = BTreeSet::new();
        for &(text, source) in parts {
            push_rules(text, source, &mut rules, &mut regexes, &mut roles)?;
        }
        let set = RegexSetBuilder::new(&regexes)
            .case_insensitive(true)
            .build()
            .map_err(|e| {
                let line = rules.last().map(|rule| rule.reference.line).unwrap_or(1);
                rule_error(line, format!("rules too large to compile: {e}"))
            })?;
        Ok(Rules { set, rules, roles })
    }

    /// Classify `path`. The repo root is always public.
    ///
    /// The path and every pattern are compared in Unicode NFC, without regard
    /// to case (Unicode simple case folding). The last matching line wins.
    pub fn classify(&self, path: &RepoPath) -> Verdict {
        if path.is_root() {
            return Verdict::Public { rule: None };
        }
        let normalized: String = path.as_str().nfc().collect();
        // One RegexSet query. Indices follow rule order.
        let winner = self.set.matches(&normalized).into_iter().max();
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

/// Appends one text's rules. `line` numbers count inside `text` only.
fn push_rules(
    text: &str,
    source: RuleSource,
    rules: &mut Vec<CompiledRule>,
    regexes: &mut Vec<String>,
    roles: &mut BTreeSet<String>,
) -> Result<(), RuleError> {
    for (idx, raw) in text.lines().enumerate() {
        let line_no = idx + 1;
        let mut line = raw;
        while let Some(before) = line.strip_suffix(' ') {
            // Git ignores trailing ASCII spaces only when unescaped.
            if before.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 1 {
                break;
            }
            line = before;
        }
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let tokens = split_tokens(line);
        let mut tokens = tokens.iter().map(String::as_str);
        // A line containing only separators has no pattern.
        let Some(first) = tokens.next() else {
            continue;
        };
        if line.as_bytes().first().is_some_and(u8::is_ascii_whitespace) {
            return Err(rule_error(
                line_no,
                "leading whitespace in a pattern must be escaped with a backslash",
            ));
        }
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
        let regex = rule_regex(&pattern).map_err(|message| rule_error(line_no, message))?;
        // Compile alone first so a bad pattern reports its own line.
        regex::RegexBuilder::new(&regex)
            .build()
            .map_err(|e| rule_error(line_no, format!("invalid pattern: {e}")))?;
        regexes.push(regex);
        rules.push(CompiledRule {
            reference: RuleRef {
                line: line_no,
                text: line.to_string(),
                source,
            },
            negated,
            readers,
        });
    }
    Ok(())
}

/// Splits a rule line on unescaped ASCII whitespace. `\ ` stays in the token as an
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
        } else if c.is_ascii_whitespace() {
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

/// Translates one gitignore pattern into an anchored regex over file paths.
///
/// - No `/` except a trailing one: matches the basename at any depth.
///   Any other `/` anchors it at the root (one leading `/` is stripped).
/// - A trailing `/` matches only directories, so only paths inside one.
/// - A match on a directory covers everything inside it, because we classify
///   file paths instead of pruning a directory walk.
/// - Two or more stars as a whole component span zero or more directories (leading,
///   middle) or everything inside (trailing). Elsewhere it is plain `*`.
/// - `*`, `?` and `[...]` never match `/`. `{`, `}` and every other
///   character are literal. `\x` escapes `x`.
fn rule_regex(pattern: &str) -> Result<String, String> {
    let directory = pattern.ends_with('/') && !pattern.ends_with("\\/");
    let body = if directory {
        &pattern[..pattern.len() - 1]
    } else {
        pattern
    };
    let anchored = body.contains('/');
    let body = body.strip_prefix('/').unwrap_or(body);
    if body.is_empty() {
        return Err("empty pattern".into());
    }
    let components = split_components(body)?;
    let mut re = String::from("^");
    if !anchored {
        re.push_str("(?:.*/)?");
    }
    let last = components.len() - 1;
    for (i, comp) in components.iter().enumerate() {
        if comp.len() >= 2 && comp.bytes().all(|c| c == b'*') {
            if components.len() == 1 {
                re.push_str("[^/]+");
            } else if i == last {
                // Everything inside the previous component; the slash before
                // this component was already written.
                re.push_str(".+");
            } else {
                // Zero or more whole directories.
                re.push_str("(?:[^/]+/)*");
            }
            continue;
        }
        if i != last {
            if let Some((prefix, stars)) = comp.rsplit_once("\\/") {
                if stars.len() >= 2 && stars.bytes().all(|c| c == b'*') {
                    re.push_str(&component_regex(prefix)?);
                    re.push_str("/(?:[^/]+/)*");
                    continue;
                }
            }
        }
        re.push_str(&component_regex(comp)?);
        if i != last {
            re.push('/');
        }
    }
    re.push_str(if directory { "/.+$" } else { "(?:/.+)?$" });
    Ok(re)
}

/// Splits on unescaped `/`, keeping escapes for `component_regex`.
fn split_components(body: &str) -> Result<Vec<String>, String> {
    let mut out = vec![String::new()];
    let mut chars = body.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => {
                let next = chars.next().ok_or("pattern ends with a lone backslash")?;
                let cur = out.last_mut().expect("never empty");
                cur.push('\\');
                cur.push(next);
            }
            '/' => out.push(String::new()),
            _ => out.last_mut().expect("never empty").push(c),
        }
    }
    if out.iter().any(String::is_empty) {
        return Err("empty path component (\"//\") in pattern".into());
    }
    Ok(out)
}

fn component_regex(comp: &str) -> Result<String, String> {
    let chars: Vec<char> = comp.chars().collect();
    let mut re = String::new();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                // split_components only keeps a backslash with a char after it.
                re.push_str(&regex::escape(&chars[i + 1].to_string()));
                i += 2;
            }
            '*' => {
                let start = i;
                while i < chars.len() && chars[i] == '*' {
                    i += 1;
                }
                // Git also lets a double star cross directories beside an
                // escaped slash. That slash stays literal: unlike `**/`,
                // `**\/` requires a separator even with no matched text.
                let boundary_before = start == 0 || chars[start - 1] == '/';
                let boundary_after = i == chars.len()
                    || (chars.get(i) == Some(&'\\') && chars.get(i + 1) == Some(&'/'));
                re.push_str(if i - start >= 2 && boundary_before && boundary_after {
                    ".*"
                } else {
                    "[^/]*"
                });
            }
            '?' => {
                re.push_str("[^/]");
                i += 1;
            }
            '[' => {
                let (class, next) = class_regex(&chars, i)?;
                re.push_str(&class);
                i = next;
            }
            c => {
                re.push_str(&regex::escape(&c.to_string()));
                i += 1;
            }
        }
    }
    Ok(re)
}

/// Parses `[...]` starting at `start`; returns the regex class and the index
/// after `]`. The class never matches `/`, negated or not.
fn class_regex(chars: &[char], start: usize) -> Result<(String, usize), String> {
    let unclosed = || {
        "unclosed '[' in pattern ('/' cannot appear inside [...]; write \\[ for a literal bracket)"
            .to_string()
    };
    let mut i = start + 1;
    let negated = matches!(chars.get(i), Some('!') | Some('^'));
    if negated {
        i += 1;
    }
    let mut items = String::new();
    let mut first = true;
    loop {
        let c = *chars.get(i).ok_or_else(unclosed)?;
        if c == ']' && !first {
            i += 1;
            break;
        }
        if c == '[' && chars.get(i + 1) == Some(&':') {
            return Err("POSIX character classes like [[:alpha:]] are not supported".into());
        }
        let lo = if c == '\\' {
            i += 1;
            *chars.get(i).ok_or_else(unclosed)?
        } else {
            c
        };
        i += 1;
        first = false;
        if chars.get(i) == Some(&'-') && chars.get(i + 1).is_some_and(|&n| n != ']') {
            let mut hi = chars[i + 1];
            i += 2;
            if hi == '\\' {
                hi = *chars.get(i).ok_or_else(unclosed)?;
                i += 1;
            }
            if hi < lo {
                return Err(format!("invalid range {lo}-{hi} in pattern"));
            }
            items.push_str(&class_char(lo));
            items.push('-');
            items.push_str(&class_char(hi));
        } else {
            items.push_str(&class_char(lo));
        }
    }
    let class = if negated {
        format!("[^{items}/]")
    } else {
        format!("[{items}--/]")
    };
    Ok((class, i))
}

/// One character, escaped for use inside a regex class.
fn class_char(c: char) -> String {
    if c.is_alphanumeric() {
        c.to_string()
    } else {
        format!("\\x{{{:x}}}", c as u32)
    }
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
        assert!(
            spaces.message.contains("unexpected token"),
            "{}",
            spaces.message
        );

        // The extra token is reported, not the later bad role.
        let first = Rules::parse("# ok\nfoo bar\n!nope @billing\n").unwrap_err();
        assert_eq!(first.line, 2);
        assert!(
            first.message.contains("unexpected token"),
            "{}",
            first.message
        );

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
        assert!(glob.message.contains("unclosed"), "{}", glob.message);

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
            Verdict::Private { readers, .. } => {
                assert_eq!(readers, BTreeSet::from(["team".to_string()]))
            }
            other => panic!("{other:?}"),
        }
    }

    /// Bypasses found in security review round 1: each one used to classify
    /// a path the user meant to protect as public.
    #[test]
    fn review_round1_bypasses_are_closed() {
        // Unicode case folding, not just ASCII.
        assert_private(&parse_ok(".ÉNV\n"), ".énv");
        assert_private(&parse_ok("SECRETS/**\n"), "secrets/ÉTÉ.txt");
        assert_private(&parse_ok("k.key\n"), "\u{212A}.key"); // Kelvin sign
                                                              // Character classes never cross '/', negated or not.
        let rules = parse_ok("secrets/**\n!/secrets/public[!x]data\n");
        assert_private(&rules, "secrets/public/data");
        assert_public(&rules, "secrets/publicYdata");
        let slash = Rules::parse("a[/]b\n").unwrap_err();
        assert!(
            slash.message.contains("'/' cannot appear"),
            "{}",
            slash.message
        );
        assert_public(&parse_ok("a[.-0]b\n"), "a/b"); // range spanning '/'
                                                      // Braces are literal in gitignore.
        let braces = parse_ok("secret{1,2}.txt\n");
        assert_private(&braces, "secret{1,2}.txt");
        assert_public(&braces, "secret1.txt");
    }

    #[test]
    fn gitignore_star_forms() {
        let mid = parse_ok("a/**/b\n");
        for p in ["a/b", "a/x/b", "a/x/y/b", "a/b/c"] {
            assert_private(&mid, p);
        }
        assert_public(&mid, "a/xb");
        let lead = parse_ok("**/logs\n");
        assert_private(&lead, "logs/x");
        assert_private(&lead, "deep/logs/x");
        let stars = parse_ok("a**b\n"); // not a whole component: plain '*'
        assert_private(&stars, "axyb");
        assert_public(&stars, "ax/yb");
        assert!(Rules::parse("[[:alpha:]]\n")
            .unwrap_err()
            .message
            .contains("POSIX"));
        assert!(Rules::parse("[z-a]\n")
            .unwrap_err()
            .message
            .contains("range"));
        assert_private(&parse_ok("\\[x]\n"), "[x]");
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

    #[test]
    fn built_in_floor_sits_under_the_file() {
        let floor_line = DEFAULT_PRIVATE
            .lines()
            .position(|line| line == ".env*")
            .unwrap()
            + 1;

        let absent = Rules::parse_layered(DEFAULT_PRIVATE, "").unwrap();
        assert_private(&absent, ".env");
        assert_private(&absent, ".env.local");
        assert_public(&absent, ".env.example");
        assert_public(&absent, "src/main.rs");
        match absent.classify(&rp(".env")) {
            Verdict::Private { rule, .. } => {
                assert_eq!(rule.source, RuleSource::BuiltIn);
                assert_eq!(rule.line, floor_line);
                assert_eq!(rule.text, ".env*");
                assert_eq!(rule.explanation(), "built-in default rule: .env*");
            }
            other => panic!("absent file: {other:?}"),
        }
        // parse() itself does not install the floor.
        assert_public(&Rules::parse("").unwrap(), ".env");

        let extra = Rules::parse_layered(DEFAULT_PRIVATE, "secrets/\n").unwrap();
        assert_private(&extra, ".env");
        assert_private(&extra, "secrets/a.key");
        assert_public(&extra, "src/main.rs");
        match extra.classify(&rp(".env")) {
            Verdict::Private { rule, .. } => assert_eq!(rule.source, RuleSource::BuiltIn),
            other => panic!("file without .env*: {other:?}"),
        }

        let opened = Rules::parse_layered(DEFAULT_PRIVATE, "# keep\n!.env\n").unwrap();
        assert_public(&opened, ".env");
        assert_private(&opened, ".env.local");
        assert_private(&opened, "id_rsa");
        match opened.classify(&rp(".env")) {
            Verdict::Public { rule: Some(rule) } => {
                assert_eq!(rule.source, RuleSource::File);
                assert_eq!(rule.line, 2);
                assert_eq!(rule.text, "!.env");
                assert_eq!(rule.explanation(), ".private line 2: !.env");
            }
            other => panic!("negated .env: {other:?}"),
        }

        let err = Rules::parse_layered(DEFAULT_PRIVATE, "# ok\n!\n").unwrap_err();
        assert_eq!(err.line, 2);
        assert!(err.message.contains("empty"), "{}", err.message);
    }
}
