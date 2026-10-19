# Modal builds

`scripts/modal_build.py` runs Cargo on Modal (Debian, Rust stable, 16 CPU, 32 GiB, 60 min) so this machine does not have to compile. Modal 1.5 is already authenticated for `C:\Program Files\Python311\python.exe`. The `modal` executable is not on `PATH`.

```powershell
& "C:\Program Files\Python311\python.exe" scripts/modal_build.py run -- cargo --version
& "C:\Program Files\Python311\python.exe" scripts/modal_build.py test -p tig-core
& "C:\Program Files\Python311\python.exe" scripts/modal_build.py test -p tig-private --test collaboration
& "C:\Program Files\Python311\python.exe" scripts/modal_build.py clippy
& "C:\Program Files\Python311\python.exe" scripts/modal_build.py release
```

`test` runs `cargo test --workspace --locked` plus any extra arguments. `clippy` runs `cargo clippy --workspace --all-targets --locked -- -D warnings`. `run --` runs the rest of the command in `/repo`. `release` cross-compiles `--target x86_64-pc-windows-gnu --bins` with the mingw linker and writes each `.exe` into `bin\`. The script exits with cargo's status.

Before starting an app, `scripts/build_source.py` prepares an immutable public
source tree. In a TIG workspace it runs `snapshot --rehash`, then
`export-git --working-copy`. Uncommitted public edits are included. The native
exporter applies each revision's `.private`, the privacy floor and the historical
private-content copy check. Only the two already-public localhost TLS fixtures
have exceptions, verified by SHA-256 before and after staging. Existing bookmarks
stay in place; an older binary uses a temporary bookmark to build its replacement.
A local `.private` omitted from the snapshot is refused instead of silently using
different rules. A native workspace requires its executable in `bin/`.

A fresh GitHub clone has no TIG executable yet. Its build reads committed blobs
only, after confirming that HEAD and its tree match a recent public commit of
`Pratz1337/tig`. The verifier downloads the latest 100 public commit IDs from a
fixed anonymous GitHub API URL and compares locally; it never sends an unverified
local Git ID. Tracked edits or a different local `.private` refuse the build.
Untracked files are not inputs. Use a native TIG workspace for other histories
and uncommitted builds.

The uploader reads only the staged tree, with Modal's automatic source inclusion
disabled. The running build scripts must match their public staged bytes.
Symlinks must resolve to public files inside that tree; directory, dangling and
outside links refuse the build. VCS metadata, `target/`, root `bin/`, `pending/`, Python
bytecode and local tool directories are excluded. Nested Cargo `src/bin` entry
points remain build inputs. No Git checkout, filters or
hooks run. Registry, Git dependencies and build outputs persist on the Modal
volume `tig-cargo-cache`. This change does not audit or erase older cache data.

For a fresh machine, install the pinned build dependency with
`python -m pip install -r scripts/requirements-build.txt`, then authenticate with
`python -m modal setup`. The complete Windows bootstrap is in
[`SELF_HOSTING.md`](../SELF_HOSTING.md#set-up-a-fresh-windows-workspace-from-github).

Tests gated with `#[cfg(windows)]` do not run on Modal (Linux). Cross-compile their
test executables on Modal and run the downloaded executables on Windows when
Windows-specific code changes; do not run local Cargo.

The source-boundary regressions run without uploading their fixtures:

```powershell
python -B -X utf8 -m unittest discover -s scripts -p test_build_source.py -v
```

They use `bin/tig.exe`, or `TIG_TEST_BINARY` when set. For programmatic detached
jobs, keep staging alive around the app run:

```python
with build.build_app() as (app, cargo_exec, _):
    with app.run(detach=True):
        call = cargo_exec.spawn(["cargo", "test", "--workspace", "--locked"])
```

## Parallel agents

Agents running Modal at the same time must each set their own cache lane, e.g.
`TIG_MODAL_CACHE=review-a python scripts/modal_build.py test -p tig-private`.
Each lane has its own target directory and source-hash record on the volume
(the first run in a new lane rebuilds the workspace crates once). The default
lane is `main`.
