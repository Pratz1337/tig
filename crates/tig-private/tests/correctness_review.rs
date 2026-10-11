use tig_core::RepoPath;
use tig_private::rules::{Rules, DEFAULT_PRIVATE};

#[test]
fn escaped_trailing_space_cannot_match_a_portable_path() {
    assert!(RepoPath::new("name ").is_err());
    assert!(RepoPath::new("name").is_ok());
}

#[test]
fn default_private_file_matches_design() {
    let rules = Rules::parse(DEFAULT_PRIVATE).unwrap();
    for name in [".env.example", ".env.sample", ".env.template"] {
        assert!(!rules.is_private(&RepoPath::new(name).unwrap()));
    }
    assert!(rules.is_private(&RepoPath::new(".env").unwrap()));
}

#[test]
fn matching_is_case_insensitive_for_unicode_names() {
    let rules = Rules::parse("caf\u{e9}.txt\n").unwrap();
    assert!(rules.is_private(&RepoPath::new("CAF\u{c9}.TXT").unwrap()));
}
