# Faster common path validation — 2026-10-19

The [wide-directory change](PARALLEL_WALK.md) left workspace-state row decoding
as a measurable status cost. Each cached path validates all its components.
Profiling the retained complete TypeScript fixture identified this validation as
a useful target before changing production code.

## Change and review

`validate_name` now accepts ordinary printable ASCII components in one pass.
The shortcut requires a nonempty name without a trailing dot or space, excludes
`.tig` case aliases, and allows only bytes 32–126 excluding `/`, `\` and `:`.
Consequently it cannot accept empty names, dot components, controls, separators,
alternate-stream syntax or reserved metadata names. Everything else uses the
unchanged validator, preserving Unicode behavior and rejection reasons/order.
The core's deliberate allowance of names such as `CON` and `.git` remains;
filesystem-specific device and metadata checks still run at their boundaries.

Review covered the complete changed functions and their tree/path construction,
canonical decoding, state loading and filesystem callers. No new security or
correctness issue was found. The shortcut accepts a subset of names already
accepted by the fallback. UTF-8 decoding, canonical ordering, state checksums,
count bounds, kinds, flags and stored encodings remain unchanged. No permission,
privacy or crypto work was added to edit/status/snapshot.

The opt-in profiler reads a local state file only when explicitly selected as an
ignored test. It prints aggregate counts and timings, with no paths, IDs or file
contents. Source/fixture filesystem input and state invariants were checked;
network, shell, database, authentication, web/session and injection surfaces are
not introduced by this diff. Existing filesystem race limits remain.

## Verification

The compatibility tests passed before and after optimization. They exercise all
128 ASCII bytes in leading, middle and trailing positions, deliberate allowed
names, Unicode controls, Unicode metadata aliases, and overlapping violations
with exact error reasons. Existing canonical-object and workspace checksum
fixtures also pass.

- Targeted Modal core suite: **76 passed**; state checks: **6 passed**, with the
  opt-in profiler ignored.
- Full Modal workspace, including doc tests: **553 passed, 0 failed, 4 ignored**.
  One ignored test is the new profiler; three were already ignored.
- Workspace clippy, all targets, locked dependencies, `-D warnings`: **exit 0**.
- Modal Windows GNU release/test cross-builds: **exit 0**. Download lengths and
  SHA-256 hashes matched their remote manifests before local execution.
- Native Windows core tests: **76 passed, 0 failed**. Native Windows CLI unit
  tests: **28 passed, 0 failed, 1 profiler ignored**.
- Build-source privacy regressions: **15 passed**. All **11** bootstrap checks,
  Windows status/conflict checks, six metadata-exclusion checks, five incoming
  metadata-tree refusals and the real NTFS Git short-alias check passed.

Release binary SHA-256:
`7c4aefe120167e31053090cc15a8d8b76663a6b1f6aff412b18c47150b38bc4a`
(24,491,725 bytes). Retained previous release:
`1857fa5a88589e43ebeeed429dd426dbc5260ad948bb5050f77c8f7d5b25068b`.
The frozen public code export is
`f9a6d54e74db91b2c6310a4f6d4508f461a2be85`; this report is a descendant.

## Local profiling

The ignored `wc::tests::profile_state_path_decoding` test was cross-built on
Modal with `--release` for Windows. Both versions include the same profiler;
the baseline predates the shortcut. They read the same local state from the
67,920-path fixture. Four invocation pairs alternate first executable, with
seven repetitions per invocation: 28 samples per version and operation.
These are memory-only timings, not CLI wall times. The operations are separate
replays and must not be added together.

Median milliseconds ([all timings](state-path-profile-2026-10-19.json)):

| Operation | Previous validator | Current validator |
|---|---:|---:|
| Decode complete state | 45.001 | 33.379 |
| Construct cached paths | 25.932 | 17.885 |
| Validate components | 19.903 | 12.066 |

Complete state decoding was **25.8% lower** in this paired profile. Raw state,
its digest and internal metadata remain local. The public result contains only
aggregate counts, artifact hashes and timing samples.

To repeat, build the CLI library tests in release mode on Modal, download the
test executable, set `TIG_PROFILE_STATE` locally to the fixture's state file and
run `--ignored --exact wc::tests::profile_state_path_decoding --nocapture`.
Retain a baseline executable with the same profiler before applying the shortcut.

## Whole-command measurements

`imported_status_compare.py` rotates Git, retained TIG and current TIG on one
complete real tree, 15 samples per operation and implementation. Setup/import,
settling and warming are excluded; CLI startup and captured output are included.
Every timed edited TIG result is checked against its immutable recorded revision.
TIG status records changes; Git status reports them. Compare within each run;
desktop conditions differ from earlier reports.

TypeScript: commit `5237fd46890956e4bb8177a1a05dcd69e4166560`, all 67,920 paths,
including the 24,009- and 22,326-entry directories. The edit target is
`tsc/testdata/baselines/reference/compiler/2dArrays.js`. No tracked ignored files
exist in this fixture, so that mode is empty.

Median wall milliseconds ([samples](typescript-path-validation-2026-10-19.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 198.06 | 228.43 | 212.32 |
| Edited status | 192.98 | 325.59 | 313.52 |

Current wall medians were **7.1% lower clean** and **3.7% lower edited**. Wall
time was lower in 12 of 15 clean pairs and 9 of 15 edited pairs, so the edited
wall result is modest and noisy. Cache-row decoding fell from 44.69 to 29.20 ms
clean and 44.46 to 29.46 ms edited; workspace loading fell from 60.11 to 45.04 ms
edited. Scan medians stayed close (129.00 versus 132.68 ms edited), matching the
state-focused change. TIG still takes about **1.07 times Git's clean wall time**
and **1.62 times its edited wall time** here.

Gitoxide: commit `ad0202e3ab396d752a56664001c134f48d834177`, all 3,223 paths,
136 symlinks and 186 tracked ignored paths. Both binaries correctly recorded the
ignored-file edit.

Median wall milliseconds ([samples](gitoxide-path-validation-2026-10-19.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 78.23 | 57.84 | 55.39 |
| README edit | 83.81 | 87.58 | 81.69 |
| Tracked ignored-file edit | 84.04 | 74.30 | 74.07 |

The ignored-edit medians are nearly equal. These results do not establish
universally faster performance; the remaining large-tree scan, tree writing and
state saving costs need further measurement.

```powershell
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/typescript-source.git .git/tig-bootstrap/tig-before-path-parse-1857fa5a.exe --edit-path tsc/testdata/baselines/reference/compiler/2dArrays.js --runs 15 --json bench/typescript-path-validation-2026-10-19.json
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/gitoxide-source .git/tig-bootstrap/tig-before-path-parse-1857fa5a.exe --runs 15 --json bench/gitoxide-path-validation-2026-10-19.json
```

The result source fields pin the frozen code export; `source_parent` retains the
driver's earlier parent-ref value. All timing samples are retained. Full raw
test/build logs and the original local profiling record stay under
`.git/tig-bootstrap/`.
