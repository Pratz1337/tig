# Reuse cached directory-entry names — 2026-10-19

The [metadata-filter follow-up](METADATA_PREFIX.md) left the large-tree walk as
the main edited-status cost. A read-only profile of the retained complete
TypeScript fixture found measurable directory listing, disk-path construction
and ignore-matching costs. Cached metadata access was cheap on Windows.

## Change and review

The walker already retains each entry's OS-string name. Its directory and file
visits now join that cached name to the same directory instead of calling
`DirEntry::path` again. These are two production-line changes and one comment.
Rust specifies the same directory/name composition for
[`DirEntry::path`](https://doc.rust-lang.org/std/fs/struct.DirEntry.html#method.path).
The profile also compares all 24,009 resulting paths for equality.

Compatibility tests passed before and after the change. They read the actual
files through the walk's reported paths, checking contents and metadata length
with one, two and four workers. Cases include nested directories, spaces,
non-ASCII names, invalid Unix bytes and a real Windows filename containing an
unpaired surrogate. Invalid names still produce an invalid repository path
while retaining the exact filesystem path. Existing wide-directory, ignore,
nested-workspace and metadata-exclusion tests remain in place.

Review covered the complete walker, its callers, the changed design paragraph,
the profiler and every new test. No new security or correctness issue was found.
The name comes from the same immutable directory entry; renames do not introduce
a new source of names. Metadata/scratch exclusions, ignore precedence, validation,
symlink handling and metadata access retain their order. Existing filesystem
race limits remain. No privacy, permission or crypto scan was added to hot paths.
No authentication, authorization, database, web/session or injection surface was
introduced; input handling, disclosure, resource bounds and state invariants
were checked. The successful opt-in profile prints counts and timings; its local
paths, raw metadata and full logs stay local.

## Verification

- Targeted Modal walker suite before and after: **7 passed**, one profiler ignored.
- Full Modal workspace, including doc tests: **556 passed, 0 failed, 6 ignored**
  across 45 test groups. One ignored test is the new walk profiler.
- Workspace clippy, all targets, locked dependencies, `-D warnings`: **exit 0**.
- Modal Windows GNU release and CLI-unit-test cross-builds: **exit 0**.
  Download lengths and SHA-256 hashes matched the remote manifests.
- Native Windows CLI tests before and after: **31 passed, 0 failed, 3 ignored**.
- Build-source privacy regressions: **15 passed**. All **11** bootstrap checks,
  Windows status/conflict checks, six metadata-exclusion checks, five incoming
  metadata-tree refusals and the real NTFS Git short-alias check passed.

Release binary SHA-256:
`d21f17e73b6bb9137eace13eedb7ab4e6e20391c970bb00cf9419793b9bf8ecf`
(24,459,858 bytes). Retained previous release:
`bf20147e7bf9d6fde9481b3af471f994d9545e659876a40a2c6eff7b97ef4a9e`.
The frozen public code export is
`b0ea710a08c860337bcd40510155e17f46e9b11e`; this report is a descendant.

## Local profiling

Both Windows release test executables contain the same ignored profiler. Four
invocation pairs alternate which executable starts first; each invocation has
seven repetitions, giving 28 samples per version and operation. The flat
directory contains 24,009 regular files. Each version's full production walk
also reports all 67,920 fixture paths, using a lightweight path-only visitor.
That visitor omits classification and has a lighter result type than status.

The serial operation replays and parallel full walk are separate measurements
and must not be added together. Median milliseconds
([all samples](directory-walk-profile-2026-10-19.json)):

| Operation | Previous walker | Current walker |
|---|---:|---:|
| List one directory | 19.257 | 19.061 |
| Entry names and types | 3.393 | 3.477 |
| Disk paths through DirEntry | 26.015 | 26.383 |
| Disk paths through cached names | 21.016 | 21.352 |
| Ignore matching | 29.047 | 29.194 |
| Repository paths | 5.406 | 5.536 |
| Cached metadata access | 0.316 | 0.298 |
| Complete walk, paths only | 81.681 | 77.851 |

Within each executable, cached-name path construction takes about **19% less
time** than the DirEntry replay. The complete path-only walk median is **4.7%
lower** after the production change. Most controls stayed close. Earlier
exploratory profiles and their larger desktop variation remain in the local
logs; these paired measurements are the accepted comparison.

To repeat, cross-build the CLI library tests in release mode on Modal and
download the executable. Set `TIG_PROFILE_ROOT` locally to the fixture workspace
and `TIG_PROFILE_DIR` to `tsc/testdata/baselines/reference/compiler`, then run
`--ignored --exact walk::tests::profile_walk_operations --nocapture`.
Retain the same profiler in the baseline before changing the production lines.

## Whole-command measurements

Git, retained TIG and current TIG rotate execution order on each fixture, with
15 samples per operation and implementation. Setup, settling and warming are
excluded; process startup and captured output are included. Every edited TIG
sample is checked against its immutable recorded revision. TIG status records
edits; Git status reports them. No other local tests or benchmark drivers ran
during the timed samples.

TypeScript uses the retained complete workspace, avoiding another history import.
Before timing, its Git tree and all native cache paths were verified against
the 67,920-path source tree. The edit target's original bytes were checked,
restored after measurement and verified in both TIG and Git. Source commit:
`5237fd46890956e4bb8177a1a05dcd69e4166560`. Edit target:
`tsc/testdata/baselines/reference/compiler/2dArrays.js`. There are no symlinks or
tracked ignored files. Compare within this run: fixture location and desktop
conditions differ from earlier reports.

Median wall milliseconds ([all samples](typescript-cached-directory-2026-10-19.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 141.68 | 142.55 | 142.72 |
| Edited status | 152.29 | 233.65 | 222.57 |

Clean status is effectively unchanged, with a slightly higher median retained.
Edited wall time is **4.7% lower**, with 10 of 15 pairs lower. The edited walk
median fell only from 97.62 to 96.68 ms; unchanged state loading also fell from
35.20 to 32.16 ms. This noise means the whole wall-time reduction cannot all be
attributed to the two changed lines. TIG still takes about **1.01 times Git's
clean wall time** and **1.46 times its edited wall time** here.

Gitoxide uses the public fresh-fixture driver: commit
`ad0202e3ab396d752a56664001c134f48d834177`, all 3,223 paths, 136 materialized
symlinks and 186 tracked ignored files. Both TIG versions correctly recorded
the ignored-file edit.

Median wall milliseconds ([all samples](gitoxide-cached-directory-2026-10-19.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 55.88 | 39.85 | 39.58 |
| README edit | 63.88 | 68.06 | 66.78 |
| Tracked ignored-file edit | 63.03 | 53.94 | 51.69 |

The clean and README-edit changes are modest; only 7 of 15 README pairs were
lower. The ignored-edit median is **4.2% lower**, with 10 of 15 pairs lower.
TIG still trails Git for the README edit. These results do not establish
universally faster performance.

The unchanged public driver can reproduce the workloads with fresh fixtures:

```powershell
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/typescript-source.git .git/tig-bootstrap/tig-before-walk-operations-bf20147e.exe --edit-path tsc/testdata/baselines/reference/compiler/2dArrays.js --runs 15 --json bench/typescript-cached-directory-2026-10-19.json
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/gitoxide-source .git/tig-bootstrap/tig-before-walk-operations-bf20147e.exe --runs 15 --json bench/gitoxide-cached-directory-2026-10-19.json
```

All result source fields pin the frozen code export. `source_parent` preserves
the earlier ref observed by each driver. Every timing sample is retained;
the retained-workspace driver and original raw logs stay in `.git/tig-bootstrap/`.
The next target is to isolate ignore-matching and listing costs further before
changing their behavior. Metadata access is not the measured bottleneck here.
