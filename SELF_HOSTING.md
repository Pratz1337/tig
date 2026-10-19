# Developing TIG with TIG

This checkout uses TIG for local changes, snapshots, bookmarks, merges and undo.
GitHub holds the source, setup scripts, build dependencies and `.private` policy.
Generated `.tig` state and private keys stay on the developer's machine.
Use `bin/tig.exe` on Windows: the `tig` bundled with Git is a different program.
Builds and tests run through `scripts/modal_build.py`; see `scripts/MODAL.md`.

## Set up a fresh Windows workspace from GitHub

Install Python 3.11 or later and Git, then run in PowerShell:

```powershell
git clone https://github.com/Pratz1337/tig.git tig-source
cd tig-source
python -m pip install -r scripts/requirements-build.txt
python -m modal setup
python scripts/modal_build.py release
python scripts/setup_tig.py ../tig-work
cd ../tig-work
bin/tig.exe status
```

The build uses your authenticated Modal account. If you already have the TIG
binary, pass `--tig <path>` to `setup_tig.py` and skip the build. The setup command
imports the full committed GitHub history into a fresh TIG workspace and copies
the executable into its ignored `bin/` directory. Source files, scripts and policy
come from the imported history. It refuses a dirty source clone or a nonempty
destination, so existing work is preserved. A GitHub source ZIP has no history and
cannot be used for this full-history bootstrap.

The first build verifies the clone against recent public GitHub commits and
uploads only committed source; untracked local files are excluded. Later builds
in the TIG workspace export an immutable public snapshot, including uncommitted
public edits, through TIG's native privacy checks. See
[`scripts/MODAL.md`](scripts/MODAL.md) for the upload boundary and regressions.

The source clone stays separate. The new workspace uses `.tig`; there is no Git
index or staging step for local work. The original development checkout also
retains its older `.git` directory for recovery. Both use the optional GitHub
transport adapter below. Internet hosting for a native TIG server is separate
and is not required for this local-workflow setup.

## Daily local work

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
Modal build uploader reads only staged public source and excludes `pending/`
and VCS metadata.

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
In a bootstrapped TIG workspace, `.git/tig-public.git` is only this adapter;
the `.git` parent directory does not contain a working-copy index.
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
See [`bench/RESULTS.md`](bench/RESULTS.md) for the consolidated real-source
comparisons, methods and raw timing samples.
