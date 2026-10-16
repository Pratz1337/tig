//! Event-selected scans must respect the authoritative walk's exclusions.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;

use tig_core::RepoPath;

#[test]
fn selected_paths_obey_inherited_ignores_and_workspace_boundaries() {
    let dir = tempfile::TempDir::new().unwrap();
    let root = dir.path();
    for name in ["src", "nested", ".git", "excluded"] {
        fs::create_dir(root.join(name)).unwrap();
    }
    fs::write(root.join(".gitignore"), "*.tmp\nexcluded/\n").unwrap();
    fs::write(root.join("src/.tigignore"), "!keep.tmp\n").unwrap();
    fs::write(root.join("nested/.tig"), "another workspace").unwrap();
    let files = ["src/file", "src/keep.tmp", "src/hide.tmp", "nested/file", ".git/config", "excluded/file", "plain"];
    for name in files {
        fs::write(root.join(name), name).unwrap();
    }
    let mut paths: BTreeSet<_> = files.iter().map(|name| RepoPath::new(name).unwrap()).collect();
    paths.insert(RepoPath::new("missing").unwrap());
    let visit = |found: tig_cli::walk::Found<'_>| found.path.unwrap();
    let (full, _) = tig_cli::walk::walk(root, no_scratch, visit).unwrap();
    let (selected, _) = tig_cli::walk::walk_paths(root, no_scratch, &paths, visit).unwrap();
    let expected: BTreeSet<_> = full.into_iter().filter(|path| paths.contains(path)).collect();
    assert_eq!(selected.into_iter().collect::<BTreeSet<_>>(), expected);
    assert!(expected.contains(&RepoPath::new("src/keep.tmp").unwrap()));
    assert!(!expected.contains(&RepoPath::new("src/hide.tmp").unwrap()));
    assert!(!expected.contains(&RepoPath::new("nested/file").unwrap()));
}

#[cfg(unix)]
#[test]
fn selected_paths_never_follow_symlink_ancestors() {
    let root = tempfile::TempDir::new().unwrap();
    let outside = tempfile::TempDir::new().unwrap();
    fs::write(outside.path().join("secret"), "outside content").unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
    let paths = BTreeSet::from([RepoPath::new("link/secret").unwrap()]);
    let (selected, _) = tig_cli::walk::walk_paths(root.path(), no_scratch, &paths, |found| found.path.unwrap()).unwrap();
    assert!(selected.is_empty());
}

fn no_scratch(_: &OsStr) -> bool { false }
