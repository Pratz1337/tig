# Remote build source privacy review

Validated 2026-10-18. Scope: `scripts/modal_build.py`, its source preparation,
and the CLI working-change export used by that preparation.

## HIGH: raw working-tree uploads bypassed `.private` — FIXED

The old `image.add_local_dir(REPO, ignore=UPLOAD_IGNORE)` mounted the raw workspace.
Its scratch-directory list excluded `.tig` and `pending`, but did not apply the
privacy floor or custom `.private` rules. An offline reproduction using Modal
1.5.5's actual file matcher included `.env`, `notes.key`, `.hg/hgrc` and a private
source path. The reproduction failed before the fix; no credential upload was
needed to demonstrate it. Confidence: high.

Builds now prepare a temporary public tree before creating an app. Native source
goes through TIG's authoritative snapshot and public Git export, including the
existing historical private-content copy check. Python does not reimplement the
privacy matcher. The two already-public localhost TLS fixture exceptions require
their pinned SHA-256 values before export and in the staged result. No other
declassification is added. A local policy omitted by ignore rules refuses the
build, rather than silently applying a different policy.

`export-git --working-copy` exports the working revision and parents under the
Git ref `working-copy` without changing native bookmarks. Its regression first
failed with the old CLI, then passed after implementation. Privacy and ref
movement continue through the existing exporter. An older executable can build
its replacement using a unique temporary bookmark, deleted in `finally`.

Fresh GitHub clones bootstrap from committed blobs only. HEAD and its tree must
match one of the latest 100 public commits from the canonical repository. The
anonymous API URL is fixed: unverified local commit IDs are compared locally,
never sent in a request. Tracked edits and a differing local policy refuse the
build; untracked files are not inputs. Other histories require native TIG.

## Additional upload boundaries checked

- Modal automatic source inclusion is disabled. Remote functions use the staged
  Python module. Both running build scripts must match their public staged bytes
  before an app is created, so a private or changed runner cannot bypass staging
  through serialization.
- The uploader sees only immutable staged files, never the raw repository. VCS
  metadata and scratch directories are excluded before reading source blobs.
  Symlinks must resolve to public files inside the staged tree; outside,
  directory and dangling links refuse the build before upload.
- Git only reads exported or verified committed objects. No checkout, archive
  attribute substitution, hooks, or clean/smudge filters run.
- Ordinary status and snapshot hot paths are unchanged. The explicit remote
  build boundary performs the rehash and historical export checks.

## Verification

- Full Rust workspace tests on Modal: **549 passed, 0 failed, 3 ignored**,
  including the new CLI export regression and all doc tests.
- Modal `cargo clippy --workspace --all-targets --locked -- -D warnings`:
  **exit 0**. Modal's cache reported hard-link fallback warnings; there were no
  clippy failures.
- Windows GNU release cross-build on Modal: **exit 0**. Downloaded executable
  size **24,505,296 bytes**, SHA-256
  `40fba1680d3e5e6e56d4c53075d1638b53d6ad61368ccdafcfbc6dd222a46c8e`.
- Python privacy regressions: **15 passed on Windows**, using the downloaded
  executable; **15 passed on Modal**, using the Linux executable. Earlier runs
  also exercised staging with the previous Windows executable's bookmark fallback.
- A real Modal run with a generated local private probe confirmed that the probe,
  VCS metadata and `pending` were absent from `/repo`, and that `modal_build` was
  imported from `/repo/scripts`. Only the public temporary source mount appeared
  in the app's creation log. The generated probe was removed afterward.
- An actual GitHub clone staged committed public bytes, omitted untracked input,
  refused a tracked local edit and retained its HEAD.

Raw red/green, full-suite, clippy, Windows artifact and live-upload logs remain
local under `.git/tig-bootstrap/`. They are not source upload inputs.

## Limits

This fixes future source preparation; it does not establish what older build
mounts contained or audit/delete prior Modal caches and artifacts. Local code,
the TIG store and the local process remain trusted. Staging is not a sandbox
against a process that can tamper with it after validation. GitHub bootstrap
requires network access and a recent canonical public commit. The source tree
is materialized in memory and on disk; no performance improvement is claimed.
