# Tracked files and ignore rules — 2026-10-18

A real-repository coverage check found that ordinary status skipped edits to
already tracked files when `.gitignore` or `.tigignore` matched them. A benign
Windows reproduction returned a clean status and the old `cat` bytes after a
disk edit. Ignore rules now control discovery of new files; tracked files keep
detecting edits and deletions using their existing stat rows.

## Review and fixes

- **MEDIUM, high confidence — FIXED:** `wc.rs::drop_absent` preserved ignored
  cache rows without checking updates. It now reuses clean rows and reads changed
  tracked content. New ignored files remain untracked.
- **MEDIUM, high confidence — FIXED:** forced reads of ignored legacy large
  blobs changed their IDs despite identical bytes. The fallback now shares
  `read_and_store`, preserving legacy IDs and conflict/symlink handling.
- Changed tracked paths retain ancestor, reparse-point and resolved metadata
  alias checks. Reads crossing a newly nested workspace refuse before recording
  its content. A discovered parent file/symlink replacement discards cached
  descendants without reading through the replacement.

Review covered the fallback, shared reader, stat-cache conditions, state
updates, tests and fixture preparation. The metadata exclusion still runs first.
No permission matching, cryptography, remote policy, object encoding or hash
label changed. Path/disclosure boundaries, races and state transitions were
checked; existing path-based TOCTOU and trusted-store limits remain. Web,
session and database concerns are inapplicable to these filesystem changes.

## Verification

- Regression first: ordinary ignored-file edits and legacy-ID preservation
  failed before the fix. New tests also cover redirected ancestors, nested
  workspace boundaries, clean cache reuse and discovered parent replacements.
- Targeted Modal run: **86 passed, 0 failed, 1 existing ignored**.
- Complete detached Modal workspace run: **544 passed, 0 failed, 3 existing
  ignored**; persisted log and remote exit 0 verified.
- Clippy with `-D warnings` and Windows GNU release cross-build passed.
- Windows test executables were built on Modal and run locally, without local
  Cargo: **20 passed, 0 failed, 2 existing ignored**. This includes the three
  platform-neutral new tests and the working-copy junction/alias/long-path suite.

## Real source fixture

The source is [Gitoxide at ad0202e3](https://github.com/GitoxideLabs/gitoxide/tree/ad0202e3ab396d752a56664001c134f48d834177),
tree `096060a59918228474c3db880317dacdf67456c5`: **3,223 paths, 136 symlinks,
186 tracked paths matched by ignore rules**. No third-party source is included
in this repository.

`imported_status_compare.py` creates a temporary root commit with that exact
tree and imports it into TIG. This keeps all tracked ignored files without
timing history import. Public CLI path listings are checked against the Git
tree before samples are taken. Git attaches to the same materialized working
tree; both tools must report it clean. This Windows run created all 136 symlinks.

The driver interleaves clean status and repeated edits to `README.md`, then
tests a real tracked ignored corpus file. The retained pre-fix binary is checked
for correctness first. Its ignored-edit result is excluded from timings because
it missed the edit; the retained reader then verifies that each timed fixed-TIG
ignored edit was actually recorded. Setup, warming and the documented racy-window
wait are outside timings. Git status inspects edits; TIG status records them.
TIG samples include captured `TIG_TRACE_PERF=1` phase output.

## Results

```powershell
git -c core.longpaths=true -c core.autocrlf=false -c core.symlinks=false clone --depth 1 --single-branch --branch main https://github.com/GitoxideLabs/gitoxide.git .git/tig-bootstrap/gitoxide-source
git -C .git/tig-bootstrap/gitoxide-source fetch --depth 1 origin ad0202e3ab396d752a56664001c134f48d834177
git -C .git/tig-bootstrap/gitoxide-source -c core.longpaths=true checkout --detach ad0202e3ab396d752a56664001c134f48d834177
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/gitoxide-source .git/tig-bootstrap/tig-before-tracked-ignore.exe --runs 15 --json bench/gitoxide-status-2026-10-18.json
```

The retained binary is an ignored pre-fix artifact, not supplied by a fresh
checkout. No competing build, test or benchmark driver was active during the
accepted measurements. A one-sample functional smoke run was excluded. Normal
desktop background services remained active.

Median wall milliseconds, 15 samples per cell
([raw source provenance, executable hashes and phases](gitoxide-status-2026-10-18.json)):

| Operation | Git | Previous TIG | Fixed TIG |
|---|---:|---:|---:|
| Clean status | 60.81 | 42.16 | 41.12 |
| Edit `README.md` | 65.58 | 80.64 | 75.75 |
| Edit tracked ignored corpus file | 68.07 | Incorrect; excluded | 53.50 |

Fixed TIG correctly records the ignored edit and measured faster than Git for
that workflow. The ordinary root-file edit improved against the retained binary
but remains **15.5% slower than Git**. The edited walk/classify/hash phase was
41.53 ms versus 15.47 ms clean; its tracked fallback phase was 6.46 ms versus
the previous binary's 7.11 ms. Directory scheduling and overlap of root-file
reads with child-directory scans are the next profiling target. This is a
measurement lead, not an established causal explanation.

A separate [176-file TIG source comparison](tracked-ignore-self-source-2026-10-18.json)
used independent copies of the exported source and 15 samples per cell:

| Operation | Git | Previous TIG | Fixed TIG |
|---|---:|---:|---:|
| Clean status | 41.64 | 20.47 | 19.18 |
| Edited status | 43.03 | 26.07 | 24.14 |
| Record change | 92.14 | 43.35 | 40.26 |

The source procedure and workflow differences are in [SELF_HOSTING.md](SELF_HOSTING.md).
These warm desktop samples do not establish universal superiority, a guaranteed
speedup, cold-cache performance or behavior on other repositories.
