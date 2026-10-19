# Share wide-directory file visits — measured 2026-10-18

The TypeScript scan remained the largest status phase after the
[Windows filename change](WINDOWS_NAMES.md). Each directory was assigned to one
worker, so its 24,009- and 22,326-entry directories could not distribute their
file visits across the existing worker pool.

## Change and review

Listings above 1,024 entries now share one immutable listing through `Arc` and
queue disjoint ranges of 512 entries. The existing pool remains bounded at 16
workers. Small directories and single-worker walks visit files inline. Child
directories are still queued before file visits. No second file-list buffer or
additional directory read is introduced.

Review covered both job variants, queue completion and failure handling, range
bounds, listing ownership, ignore chains, path validation and the snapshot
callers. Every eligible entry belongs to exactly one range. Existing metadata,
scratch and nested-workspace exclusions happen before file jobs; each visit
still checks ignores and obtains file metadata once. Symlinks retain their
existing handling. Snapshot outcomes remain unordered and are applied by path.
There are no new permission, privacy, crypto or leak checks on a hot path.
Existing filesystem race limits remain.

## Verification

The new blocking-visitor regression first failed on the previous walker: one
file blocked every other visit in a wide directory. It passes with shared file
jobs. A separate compatibility test checks exact-once discovery, ignore
overrides, VCS aliases, scratch exclusions, hidden local files and nested
workspaces with one, two and four workers.

- Modal workspace suite, including doc tests: **551 passed, 0 failed, 3 ignored**.
- Modal workspace clippy with all targets, locked dependencies and `-D warnings`:
  **exit 0**. Cache hard-link fallback warnings did not fail clippy.
- Windows GNU release and unit-test cross-builds on Modal: **exit 0**.
- Downloaded Windows unit executable: **28 passed, 0 failed**. Its length and
  SHA-256 matched the remote manifest before execution.
- Local build-source privacy tests: **15 passed** with the new executable.
  All **11** fresh-workspace setup checks and the Windows clean/add/edit/delete,
  UTF-8, NUL-output and stored-conflict status checks passed.

The release executable is 24,491,723 bytes, SHA-256
`1857fa5a88589e43ebeeed429dd426dbc5260ad948bb5050f77c8f7d5b25068b`.
The retained previous executable's SHA-256 is
`40fba1680d3e5e6e56d4c53075d1638b53d6ad61368ccdafcfbc6dd222a46c8e`.
The frozen public code export is
`982baa0f41198cb3e2dd41475c637241b60c06d5`; the benchmark report is a descendant.
Raw test and artifact logs remain local under `.git/tig-bootstrap/`.

## Measurements

`imported_status_compare.py` alternates Git, retained TIG and current TIG on the
same complete real source tree, with 15 samples per operation and implementation.
Setup, import, settling and warming are excluded; CLI startup and captured output
are included. Every edited TIG sample is checked against its recorded immutable
revision. TIG status records the edit; Git status reports it. These are status
workflows, not a commit-throughput comparison.

TypeScript is pinned to `5237fd46890956e4bb8177a1a05dcd69e4166560`: all 67,920
tracked paths, including both wide directories. The edit target is
`tsc/testdata/baselines/reference/compiler/2dArrays.js`. There are no tracked
ignored files in this fixture, so that mode is empty.

Median wall milliseconds ([all samples](typescript-parallel-walk-2026-10-18.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 310.79 | 457.09 | 318.60 |
| Edited status | 347.80 | 633.76 | 506.55 |

Current TIG's wall medians were **30.3% lower clean** and **20.1% lower edited**
than retained TIG. It had lower wall time in 13 of 15 paired samples in each
mode. The scan span fell from 305.86 to 183.52 ms clean and from 323.40 to
197.95 ms edited; the edited scan was lower in all 15 pairs. Workspace-state
loading stayed close, at 90.48 versus 90.75 ms edited. This supports the
scan-focused change.

This desktop was slower than in earlier reports across all implementations;
compare binaries within this run. Wall ranges were wide: 298.97–543.41 ms for
retained clean status and 225.28–495.71 ms for current clean status. Current TIG
remains about **1.03 times Git's clean wall time** and **1.46 times its edited
wall time**. Further edited-status work is needed.

Gitoxide remains pinned to `ad0202e3ab396d752a56664001c134f48d834177`, with all
3,223 paths, 136 symlinks and 186 tracked ignored paths. Both executables
correctly recorded the ignored-file edit.

Median wall milliseconds ([all samples](gitoxide-parallel-walk-2026-10-18.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 156.31 | 96.31 | 94.21 |
| README edit | 178.59 | 136.01 | 137.86 |
| Tracked ignored-file edit | 194.48 | 152.78 | 146.58 |

The smaller-tree results are close: ordinary edited status was **1.4% higher**,
while clean and ignored-edit medians were lower. These samples do not establish
zero overhead or universally faster performance. TIG remained below Git in all
three modes on this fixture.

```powershell
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/typescript-source.git .git/tig-bootstrap/tig-before-parallel-walk.exe --edit-path tsc/testdata/baselines/reference/compiler/2dArrays.js --runs 15 --json bench/typescript-parallel-walk-2026-10-18.json
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/gitoxide-source .git/tig-bootstrap/tig-before-parallel-walk.exe --runs 15 --json bench/gitoxide-parallel-walk-2026-10-18.json
```

Retain the previous release executable before rebuilding. The result files pin
the frozen code export rather than the later report commit; the original driver
parent-ref value is retained in `source_parent`. No timing samples were removed.
