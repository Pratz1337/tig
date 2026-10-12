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

The upload is the working tree, including uncommitted edits. It skips `target/`, `bin/`, `.git/`, any `.tig/` directory, and `pending/`. Registry, git, and build outputs persist on the Modal volume `tig-cargo-cache`.

Tests gated with `#[cfg(windows)]` do not run on Modal (Linux). Run those locally only when Windows-specific code changes, for example `cargo test -p tig-cli -- <windows test names>`.

## Parallel agents

Agents running Modal at the same time must each set their own cache lane, e.g.
`TIG_MODAL_CACHE=review-a python scripts/modal_build.py test -p tig-private`.
Each lane has its own target directory and source-hash record on the volume
(the first run in a new lane rebuilds the workspace crates once). The default
lane is `main`.
