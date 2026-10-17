use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;

use tig_cli::wc::WorkingCopy;
use tig_core::repo::{Settings, DEFAULT_WORKSPACE};
use tig_core::workspace::Workspace;
use tig_core::RepoPath;

const METADATA: &[&str] = &[".git", ".GIT", ".Hg", ".SvN", ".Jj", ".g\u{200d}it", ".svn\u{feff}"];

#[test]
fn vcs_metadata_aliases_are_excluded_from_full_and_selected_scans() {
    for name in METADATA {
        let dir = tempfile::tempdir().unwrap();
        let relative = format!("nested/{name}/config");
        fs::create_dir_all(dir.path().join("nested").join(name)).unwrap();
        fs::write(dir.path().join(&relative), b"local credential marker").unwrap();
        fs::write(dir.path().join(".gitignore"), b"# ordinary content\n").unwrap();
        let (repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
        let ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
        let path = RepoPath::new(&relative).unwrap();
        assert!(ws.read(&repo, &path).unwrap().is_none(), "snapshotted {relative}");
        assert!(ws.read(&repo, &RepoPath::new(".gitignore").unwrap()).unwrap().is_some());
        let selected = BTreeSet::from([path]);
        let (found, _) = tig_cli::walk::walk_paths(dir.path(), |_: &OsStr| false, &selected, |item| item.path.unwrap()).unwrap();
        assert!(found.is_empty(), "selected scan included {relative}");
        // Rehashing must not accidentally admit a metadata alias either.
        let mut repo = repo;
        wc.snapshot_with_rehash(&mut repo, true).unwrap();
        assert!(Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap()
            .read(&repo, &RepoPath::new(&relative).unwrap()).unwrap().is_none());
    }
}

#[test]
fn checkout_refuses_vcs_metadata_before_any_disk_changes() {
    for name in METADATA {
        for prefix in ["", "nested/"] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("safe.txt"), b"original").unwrap();
            let (mut repo, mut wc) = WorkingCopy::init(dir.path(), Settings::default()).unwrap();
            let relative = format!("{prefix}{name}/hooks/incoming");
            let mut ws = Workspace::open(&repo, DEFAULT_WORKSPACE).unwrap();
            ws.write(&repo, &RepoPath::new("safe.txt").unwrap(), b"changed").unwrap();
            ws.write(&repo, &RepoPath::new(&relative).unwrap(), b"incoming hook").unwrap();
            ws.snapshot(&mut repo).unwrap();
            let state = dir.path().join(".tig/workspaces/default/state");
            let before = fs::read(&state).unwrap();
            let result = wc.checkout(&repo);
            assert!(result.is_err(), "checked out {relative}");
            assert_eq!(fs::read(dir.path().join("safe.txt")).unwrap(), b"original");
            assert_eq!(fs::read(&state).unwrap(), before);
            assert!(!dir.path().join(&relative).exists());
        }
    }
}
