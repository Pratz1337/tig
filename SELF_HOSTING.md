# Developing TIG with TIG

This checkout uses TIG for local changes, snapshots, bookmarks, merges and undo.
The original `.git` directory remains available for GitHub transport and recovery.
Use `bin/tig.exe` on Windows: the `tig` bundled with Git is a different program.
Builds and tests run through `scripts/modal_build.py`; see `scripts/MODAL.md`.

```
bin/tig.exe status
bin/tig.exe status --short
bin/tig.exe status -z
bin/tig.exe diff
bin/tig.exe describe -m "Describe the change"
bin/tig.exe bookmark set master
bin/tig.exe new -m "Next change"
```

`status --short` (`-s`) prints only `A`, `M`, `D` or `C`, one space, and the path.
A clean change prints nothing. `-z` (`--null`) implies `--short` and ends each
record with NUL. Conflicts appear once as `C path`, without explanatory text.
Both formats snapshot edits just like ordinary status and compare the working
change with its first parent. They describe local files, including private files.

## Privacy demo

`.tig` is trusted local metadata. It contains plaintext objects, local history
and key material, and must stay local. `.gitignore` excludes it from Git.
`.private` is public policy; TIG always applies its built-in privacy floor too.
The two explicit PEM exceptions are public localhost TLS fixtures used by tests.

The local `pending/private-demo/` directory contains a generated demonstration
note, not a real credential. Git ignores all of `pending/`. `.tigignore` includes
only this demo directory in TIG; `.private` keeps it out of public exports. The
Modal build uploader excludes `pending/` and `.tig/`.

After each tested change, export only the `master` bookmark:

```
bin/tig.exe bookmark set master
bin/tig.exe export-git .git/tig-public.git --bookmark master --declassify crates/tig-remote-http/src/testdata/cert.pem --declassify crates/tig-remote-http/src/testdata/key.pem
```

The two declassifications permit only the known public test fixtures. Older
revisions predate their `.private` exceptions, so the historical paste check
otherwise refuses their current public copies. No other private path is allowed.

Inspect the exported tree and reachable history before pushing. Neither the demo
note nor `.tig` may be present. The exporter also checks private-content copies.
This demo exercises Git export omission; encrypted collaboration uses TIG remotes
and is described in `DESIGN.md`.

## GitHub bridge

GitHub accepts Git, so the exported bare repository is a transport adapter.
Historical privacy filtering can change imported commit IDs. Preserve GitHub's
existing history by making a bridge merge whose tree is exactly TIG's public
export and whose parents are the observed GitHub tip and the exported TIG tip.
Do not force-push or replace TIG's exported `master` ref with that bridge.

In PowerShell, after the tests and export have passed:

```powershell
$mirror = '.git/tig-public.git'
$url = 'https://github.com/Pratz1337/tig.git'
git --git-dir=$mirror fetch $url master:refs/remotes/github/master
$upstream = git --git-dir=$mirror rev-parse refs/remotes/github/master
$native = git --git-dir=$mirror rev-parse refs/heads/master
$tree = git --git-dir=$mirror rev-parse 'master^{tree}'
# Review first; an unchanged tree needs no bridge commit.
git --git-dir=$mirror diff --stat $upstream $native
$bridge = git --git-dir=$mirror commit-tree $tree -p $upstream -p $native -m 'Describe the tested change'
git --git-dir=$mirror push $url "${bridge}:refs/heads/master"
```

Stop if any command fails. A concurrent GitHub update rejects the ordinary push;
fetch and review it before making a new bridge. This bridge does not run a Git
checkout, staging operation or commit on the source workspace. Continue local work
with TIG. Export again after each tested native change; the export map retains its
own history, independently of GitHub's bridge commits.

After publishing, use `bin/tig.exe new -m "Next change"` before editing again.
This keeps the published native change immutable, so subsequent exports advance
the native bookmark instead of rewriting it.

## Performance

Run `bench/compare.py` against a release binary and retain the raw samples.
`bench/RESULTS.md` includes workloads where TIG is slower. Faster than Git is a
measurement goal for each operation and workload, not a universal guarantee.
See [`bench/SELF_HOSTING.md`](bench/SELF_HOSTING.md) for this checkout's validation
and real-source comparison, including the raw timing samples.
