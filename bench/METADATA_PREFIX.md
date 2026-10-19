# Metadata-name filtering — 2026-10-19

The [path-validation change](PATH_VALIDATION.md) reduced workspace-state loading
cost. The next profile replayed cache lookups, VCS-name filtering and Windows
name checks over the same complete TypeScript workspace. This change removes
unnecessary Unicode conversion and alias matching from ordinary names.

## Change and review

`walk::is_vcs_metadata` returns false immediately when the first encoded OS-string
byte is ASCII other than `.`. All four reserved names start with a dot, and every
character the alias matcher can remove is non-ASCII. An ASCII non-dot prefix
therefore cannot become a metadata name. Empty, dot and non-ASCII prefixes retain
the existing Unicode conversion and complete alias matcher. Invalid OS strings
still return false; the walk's separate path validation remains in place.

Rust documents the OS-string encoding as an ASCII-compatible superset of UTF-8.
The borrowed bytes are examined locally and never serialized or reconstructed.
See the [standard library documentation](https://doc.rust-lang.org/std/ffi/struct.OsStr.html#method.as_encoded_bytes).

Review covered the changed functions, the full walker, state decoding, snapshot
classification, selected-path scans and the underlying alias matcher. No new
security or correctness issue was found. Metadata exclusions, nested-workspace
boundaries, ignore precedence and Windows checkout checks retain their order.
Stored names and encodings are unchanged. No privacy, permission or crypto scan
was added to status or snapshot.

The ignored profiler reads an explicitly selected local state file, decodes it
before timing and prints only aggregate counts and timings. It does not print
paths, IDs or contents. The change introduces no shell, network, database,
authentication, web/session or injection surface. Filesystem input validation,
disclosure, resource bounds and state invariants were reviewed; existing
filesystem race limits remain.

## Verification

The alias corpus passed before optimization and after it. It checks case aliases,
ignorable characters before, inside and after metadata names, all ASCII non-dot
prefixes and ordinary dot names. A second test checks invalid Unix byte strings
and Windows lone surrogates with ASCII, dot and non-ASCII prefixes.

- Targeted Modal walker tests: **6 passed, 0 failed**.
- Full Modal workspace, including doc tests: **555 passed, 0 failed, 5 ignored**
  across 45 test groups. One ignored test is the new opt-in profiler.
- Workspace clippy, all targets, locked dependencies, `-D warnings`: **exit 0**.
- Modal Windows GNU release and CLI-unit-test cross-builds: **exit 0**.
  Download lengths and SHA-256 hashes matched the remote manifests.
- Native Windows CLI unit tests: **30 passed, 0 failed, 2 profilers ignored**.
- Build-source privacy regressions: **15 passed**. All **11** bootstrap checks,
  Windows status/conflict checks, six metadata-exclusion checks, five incoming
  metadata-tree refusals and the real NTFS Git short-alias check passed.

Release binary SHA-256:
`bf20147e7bf9d6fde9481b3af471f994d9545e659876a40a2c6eff7b97ef4a9e`
(24,489,146 bytes). Retained previous release:
`7c4aefe120167e31053090cc15a8d8b76663a6b1f6aff412b18c47150b38bc4a`.
The frozen public code export is
`6b789c01e8bb519bf43e4c0b88f960db12e37872`; this report is a descendant.

## Local profiling

Both Windows release test executables contain the same profiler. They replay the
same local state for 67,920 tracked TypeScript paths. Four invocation pairs
alternate which executable starts first; each invocation has seven repetitions,
giving 28 samples per version and operation. These are memory-only operation
timings, measured separately, and must not be added together.

Median milliseconds ([all samples](metadata-prefix-profile-2026-10-19.json)):

| Operation | Previous filter | Current filter |
|---|---:|---:|
| Cache lookups | 23.728 | 21.263 |
| VCS name checks | 5.972 | 2.662 |
| Windows name checks | 25.544 | 23.534 |

VCS filtering took **55.4% less time** in this profile. The unchanged controls
also improved by roughly 8–10%, showing desktop variation; this is not evidence
of an equivalent whole-command speedup. The filter saves only a few milliseconds
of aggregate CPU work here. Raw state, its digest and internal metadata stay
local; the public profile contains aggregate counts, artifact hashes and timings.

To repeat, cross-build the CLI library tests in release mode on Modal, download
the test executable, set `TIG_PROFILE_STATE` locally to the fixture state file and
run `--ignored --exact wc::tests::profile_snapshot_path_checks --nocapture`.
Retain a baseline executable with the same profiler before applying the shortcut.

## Whole-command measurements

`imported_status_compare.py` rotates Git, retained TIG and current TIG on the same
complete real tree, with 15 samples per operation and implementation. Import,
setup, settling and warming are excluded; process startup and captured output
are included. Every timed edited TIG snapshot is checked against its immutable
recorded revision. TIG status records edits; Git status reports them. No other
local tests or benchmark drivers ran during these timed samples.

TypeScript: commit `5237fd46890956e4bb8177a1a05dcd69e4166560`, all 67,920 paths,
including the 24,009- and 22,326-entry directories. The edited file is
`tsc/testdata/baselines/reference/compiler/2dArrays.js`. This fixture has no
tracked ignored files.

Median wall milliseconds ([all samples](typescript-metadata-prefix-2026-10-19.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 181.01 | 204.81 | 204.68 |
| Edited status | 181.02 | 284.02 | 279.36 |

Clean status is effectively unchanged. Edited wall time was **1.6% lower**, with
11 of 15 pairs lower; this is a modest result. The edited walk/classify/hash
median fell from 123.38 to 120.99 ms. State loading, tree writing and saving stayed
close. TIG still takes about **1.13 times Git's clean wall time** and **1.54 times
its edited wall time** here. The isolated filter result does not establish a
large CLI improvement or universally faster performance.

Gitoxide: commit `ad0202e3ab396d752a56664001c134f48d834177`, all 3,223 paths,
136 symlinks and 186 tracked ignored paths. Both TIG binaries correctly recorded
the ignored-file edit.

Median wall milliseconds ([all samples](gitoxide-metadata-prefix-2026-10-19.json)):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 60.32 | 41.50 | 42.19 |
| README edit | 65.63 | 65.49 | 65.33 |
| Tracked ignored-file edit | 63.01 | 51.55 | 51.36 |

The smaller-tree results are essentially unchanged. The clean median is **1.7%
higher**, although 8 of 15 individual pairs were lower; neither edit mode shows
a material speedup. The slower clean median is retained with every other sample.

```powershell
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/typescript-source.git .git/tig-bootstrap/tig-before-snapshot-checks-7c4aefe1.exe --edit-path tsc/testdata/baselines/reference/compiler/2dArrays.js --runs 15 --json bench/typescript-metadata-prefix-2026-10-19.json
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/gitoxide-source .git/tig-bootstrap/tig-before-snapshot-checks-7c4aefe1.exe --runs 15 --json bench/gitoxide-metadata-prefix-2026-10-19.json
```

All result source fields pin the frozen code export. Full raw test/build logs
and the original profile record stay under `.git/tig-bootstrap/`.

The next measurement should split the remaining large-tree walk cost into
directory listing, ignore matching, path construction and classification before
choosing another optimization. Current edited medians still include 120.99 ms
for walking/classifying/hashing, 26.61 ms for trees/operation and 26.42 ms for
state saving. The small filter change does not address most of those costs.
