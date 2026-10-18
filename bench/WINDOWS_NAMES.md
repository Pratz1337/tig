# Avoid Windows filename folding allocations — 2026-10-18

The [wide-tree comparison](WIDE_TREES.md) left TypeScript edited status at
387.93 ms, versus Git's 190.23 ms. Its scan/classify/hash span was 221.92 ms and
workspace-state loading took 51.91 ms. This change targets the scan's Windows
filename checks and makes state loading easier to profile.

## Change and safety boundaries

`windows_name_block` still checks every path component. ASCII device names now
use borrowed, case-insensitive comparisons instead of allocating lowercase
strings. Non-ASCII device names retain `fold_device`, including the superscript
digits. The `.tig` short-name check similarly borrows ASCII names and retains
Unicode folding. Its six-digit limit, leading-zero rejection, and trailing
dot/space handling are unchanged.

UTF-16 counting is skipped only when UTF-8 byte length is at most 255: a string
cannot contain more UTF-16 units than UTF-8 bytes. Longer names still count units,
so names with multibyte characters are not rejected just for exceeding 255 bytes.

`TIG_TRACE_PERF=1` now separates workspace-state file reading, checksum verification,
cache-row decoding, and sorted-index construction. The timers print only phase
names and elapsed times to stderr; they do not print paths, contents or IDs.
Checksum verification, strict path parsing, sorted/unique cache validation and
the frozen state encodings remain intact. No permission or private-rule checks
were added to snapshot or status.

## Verification

The new compatibility test passed before and after the optimization. It covers
mixed-case console devices, extensions, Unicode superscript device and short
aliases, alias digit limits, allowed lookalikes, and the 255/256 UTF-16-unit
boundary with ASCII, accented characters and surrogate pairs.

- Targeted Modal working-copy tests: **12 passed, 0 failed**.
- Complete Modal workspace suite: **548 passed, 0 failed, 3 existing ignored**.
  The detached result and persisted full log, including doc-tests, were checked.
- Clippy with `-D warnings` and the Windows GNU release build passed on Modal.
- Windows test executables built on Modal and run locally: **33 passed,
  0 failed, 2 existing ignored** across working-copy unit tests, tracked ignored
  files and the filesystem review suite. Downloaded artifacts matched remote
  lengths and SHA-256 hashes before execution. No local Cargo was run.
- Windows status, metadata exclusion/refusal and real NTFS short-alias checks
  passed. All **11** fresh-workspace setup checks passed.
- Runtime checks confirmed identical status stdout with tracing enabled and
  disabled, no timing output when disabled, and all four state subphases when
  enabled.

Review covered the changed state-load and name-check functions and their scan
and checkout callers. ASCII comparisons implement the same reserved-name set;
Unicode handling and rejection order remain. Bounds precede the short-prefix
slice. State checksums, cache validation, executable/symlink/conflict handling,
metadata exclusions and checkout preflight remain. No new authentication,
authorization, crypto, shell or network behavior is introduced. Disclosure,
resource bounds, injection, races and state invariants were checked; web,
session and database checks are inapplicable. Existing path-based filesystem
race limits remain.

## Measurement method

The tested source is exported commit
`604a9676c2ab070ae6dd7d6901f5f6776a95fd4c`. The retained executable comes from
the previously published build at `82cd91f52056f6590370b4c30aa0389859231d13`.
The paired drivers record both executable SHA-256 hashes.

TypeScript remains pinned to commit
`5237fd46890956e4bb8177a1a05dcd69e4166560`: all 67,920 tracked paths, including
the two directories with 24,009 and 22,326 entries. The ordinary edit targets
`tsc/testdata/baselines/reference/compiler/2dArrays.js`. There are no tracked
ignored files in this fixture, so that inapplicable mode remains empty/null.

Setup, import, settling and warming are excluded. Process startup and captured
trace output are included. Tool order rotates and reverses. Every timed TIG
edit is checked against the immutable recorded working revision, so a later
snapshot cannot repair a missed edit. Git inspects edits; TIG records them.
Normal desktop services remain active. No competing local build, test or
benchmark runs during accepted samples.

```powershell
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/typescript-source.git .git/tig-bootstrap/tig-before-state-profile.exe --edit-path tsc/testdata/baselines/reference/compiler/2dArrays.js --runs 15 --json bench/typescript-windows-names-2026-10-18.json
```

## TypeScript results

Median wall milliseconds, 15 samples per cell ([raw samples](typescript-windows-names-2026-10-18.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 176.46 | 318.63 | 262.45 |
| Edit in 24,009-entry directory | 184.52 | 402.17 | 349.64 |

Clean status measured **17.6% lower** and edited status **13.1% lower** than
retained TIG. The edited scan/classify/hash span fell from 223.59 to 168.35 ms,
while tree/operation writing stayed at about 26.3 ms and state saving at 25.7 ms.
Workspace-state loading stayed at about 53 ms. This matches the scan-focused
change rather than a change in recorded work or state validation.

The new state-load spans show edited-status medians of 3.83 ms reading the file,
5.42 ms verifying the checksum, 38.82 ms decoding rows and 3.94 ms building the
index. These component medians need not add to the enclosing median.

TIG remains **1.49 times Git's clean-status wall time** and **1.89 times Git's
edited-status wall time** on this fixture. The remaining scan and row-decoding
costs need further work. These results do not establish universally faster
performance, and no safety checks were removed to improve the timings.

## Gitoxide results

The existing fixture remains pinned to
`ad0202e3ab396d752a56664001c134f48d834177`: 3,223 retained paths, 136 symlinks
and 186 tracked paths matched by ignores. Both binaries passed immutable-revision
verification for ignored edits. Median wall milliseconds, 15 samples per cell
([raw samples](gitoxide-windows-names-2026-10-18.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 85.58 | 58.69 | 58.29 |
| Root README edit | 87.12 | 80.29 | 79.42 |
| Tracked ignored-file edit | 93.67 | 71.74 | 70.94 |

The TIG wall medians are close on this smaller tree: 0.7–1.1% lower in this run.
Current TIG remains below Git in all three modes. Compare the paired binaries
within each run; earlier reports remain intact, including their slower cases.

```powershell
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/gitoxide-source .git/tig-bootstrap/tig-before-state-profile.exe --runs 15 --json bench/gitoxide-windows-names-2026-10-18.json
```
