# Performance measurements

TIG status snapshots edits; Git status only inspects them. Compare equivalent
user workflows while retaining that semantic difference. These measurements
include process startup and captured output on Windows 11, local NTFS,
Intel Core i5-13500H, 16 GB RAM, antivirus enabled and Git 2.56.0.windows.1.
This is a running desktop, not an isolated laboratory. No other benchmark or
local test driver ran during the accepted timing samples.

## Real-source status, 2026-10-19

These are frozen measurements of the cached-directory-name change, before the
subsequent roles fixes. They are not timings of a newly built roles binary.
The public code export is `b0ea710a08c860337bcd40510155e17f46e9b11e`.
Measured TIG SHA-256:
`d21f17e73b6bb9137eace13eedb7ab4e6e20391c970bb00cf9419793b9bf8ecf`.
Retained previous TIG:
`bf20147e7bf9d6fde9481b3af471f994d9545e659876a40a2c6eff7b97ef4a9e`.

Git, previous TIG and measured TIG rotate execution order with 15 samples per
operation. Setup, settling and warming are excluded. Every edited TIG sample
is checked against its immutable recorded revision; original bytes are restored
afterward and verified in both systems. Compare within a run: desktop conditions
and fixture locations differ between reports.

TypeScript commit `5237fd46890956e4bb8177a1a05dcd69e4166560` contains 67,920
paths, no symlinks and no tracked ignored files. The retained workspace's Git
tree and native cache paths were checked against the complete source tree.
The edit target is `tsc/testdata/baselines/reference/compiler/2dArrays.js`.
Median wall milliseconds ([all samples](typescript-cached-directory-2026-10-19.json)):

| Operation | Git | Previous TIG | Measured TIG |
|---|---:|---:|---:|
| Clean status | 141.68 | 142.55 | 142.72 |
| Edited status | 152.29 | 233.65 | 222.57 |

The edited median is 4.7% lower than previous TIG, but still 1.46 times Git's
wall time. Unchanged state loading also became faster in this sample, so the
whole reduction cannot be attributed to the two changed walker lines.

Gitoxide commit `ad0202e3ab396d752a56664001c134f48d834177` contains 3,223
paths, 136 materialized symlinks and 186 tracked ignored files. Both TIG versions
correctly recorded the ignored-file edit. Median wall milliseconds
([all samples](gitoxide-cached-directory-2026-10-19.json)):

| Operation | Git | Previous TIG | Measured TIG |
|---|---:|---:|---:|
| Clean status | 55.88 | 39.85 | 39.58 |
| README edit | 63.88 | 68.06 | 66.78 |
| Tracked ignored-file edit | 63.03 | 53.94 | 51.69 |

TIG wins the clean and ignored-edit workloads but trails Git for the README
edit. Only 7 of 15 README-edit pairs favored measured TIG over previous TIG.
These results do not establish universally faster performance.

To reproduce with fresh fixtures, retain the previous release before rebuilding:

```powershell
python -X utf8 bench/imported_status_compare.py PATH_TO_SOURCE_GIT PATH_TO_PREVIOUS_TIG --runs 15 --json bench/comparison.json
```

Use `--edit-path` for the TypeScript target above. The retained TypeScript run
used an existing verified workspace to avoid another full import; its local
driver and logs remain local. The public driver creates fresh destinations.
The separate [directory-walk profile](directory-walk-profile-2026-10-19.json)
retains 28 samples per version/operation, including all 24,009 path-equality
checks in the wide directory. Path-only walk profiles omit status classification
and must not be added to serial operation replays or whole-command timings.
All earlier raw JSON samples and benchmark drivers remain in this directory;
dated narrative reports are available in repository history.

## Git import

The 2026-10-12 zlib fixture at `767c4c947852e143f582c85f14cf573411df1b35`
contained 1,126 commits, 9,153 packed Git objects and two branches. Clone time
was excluded. Three fresh-store samples per trial compared direct loose writes
against journal insertion plus compaction. The two trial medians reversed the
winner: direct 21.884/17.596 s, journal 16.864/24.656 s. Insertion alone hides
most journal cost, so this does not establish a general storage advantage.
The CLI uses direct writes and leaves no deferred import compaction.

Final full-command fresh imports took 17.470, 18.395 and 18.389 s; unchanged
re-imports took 0.879, 0.977 and 1.015 s. Fresh runs reported 1,126 new revisions;
repeats reported zero new and 1,126 reused. Raw storage and CLI samples remain
local in `target/import-benchmark-trial1.json`, `target/import-benchmark.json`
and `target/import-cli-final.json`. The medians and sample scope are retained
here because those build artifacts are ignored.

Build the CLI and `tig-private`'s `import_bench` example on Modal, then run
`python bench/import_compare.py PATH_TO_SOURCE_GIT --runs 3` locally;
`--cli-only` measures just the CLI. See [IMPORT_GIT.md](../IMPORT_GIT.md) for
privacy rules and when an incremental import requires a fresh destination.
