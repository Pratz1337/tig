# CLI baseline — 2026-10-12

Measured at `f6837d2c41066427390a02a53bb1e3094ffc7c28`, before implementation changes:

```
cargo build --release -p tig-cli
python bench/compare.py --files 10000 --runs 5 --json target/bench-baseline.json
python bench/trace_status.py
```

Five runs, median wall time including real process startup. Each sample uses a fresh synthetic 10,000-file tree (~100 files per directory, 200 B–8 KiB). These are fairness fixtures, not evidence of real monorepo performance. Raw samples are in `target/bench-baseline.json`; phase traces are in `target/bench-trace.json`.

| Operation | Git | tig | tig / Git |
|---|---:|---:|---:|
| Init + first snapshot | 46,699 ms | 36,663 ms | 0.79x |
| Status, no change | 48 ms | 39 ms | 0.83x |
| Status, 1 file edited | 49 ms | 61 ms | 1.26x |
| Record change | 91 ms | 77 ms | 0.85x |

Git: `git version 2.56.0.windows.1`. Rust: `rustc 1.99.0 (b940084d7 2026-09-28)`, `x86_64-pc-windows-gnu`, release profile. Machine: Intel Core i5-13500H, 12 cores / 16 logical processors, 16 GB RAM, Windows 11 Home Single Language 10.0.26300; local NTFS directories. Antivirus remained enabled. No builds, tests or other benchmark drivers ran alongside the accepted measurements. Earlier overlapping drivers were stopped, their samples discarded, and this run restarted after the other editor was stopped. This is a normally running desktop, not a controlled laboratory or a claim that every background service was idle.

There is substantial cold-run variation: Git init samples ranged from 22.7 to 71.6 seconds; tig from 31.3 to 40.8 seconds. Git's automatic maintenance/repack was observed during an initial commit. File creation and first opens are sensitive to antivirus and filesystem caching. The init scenario runs Git init/add/commit versus tig init/new; record-change runs Git commit versus tig new. They serve the same fixture workflow but have different semantics: **tig status records the edit**, whereas Git status only inspects it. The faster clean status does not mean tig wins every status workload.

## Phase evidence

The separate trace fixture uses the same generated shape, lets the two-second racy window expire, warms status once, then samples five clean statuses and five statuses after distinct one-file edits. `TIG_TRACE_PERF=1` is enabled; nested spans must not be added together.

| Phase (median) | Clean | Edited |
|---|---:|---:|
| Open workspace | 4.47 ms | 4.03 ms |
| Walk + stat + hash | 13.64 ms | 28.83 ms |
| Write trees + operation | 0.00 ms | 2.25 ms |
| Save workspace state | 0.51 ms | 4.99 ms |
| Entire snapshot | 14.66 ms | 36.19 ms |
| Entire in-process command | 20.03 ms | 42.39 ms |
| CLI wall time | 32.48 ms | 55.16 ms |

Median wall time minus the command span is 11.81 ms clean / 11.11 ms edited. A separate five-run `tig --version` median is 9.68 ms (Clap exits before the outer trace span prints). These are observed startup/output/shutdown costs, not the predicted 25–30 ms startup. The expected ~16 ms clean snapshot is close; ~27 ms describes the edited walk/hash phase here, not the whole edited command. Edited status also persists the snapshot and stat cache and reads changed ancestor trees. Those costs explain why it loses to Git's read-only status in this fixture.

The initial `new` also opens and compacts the ~40 MB journal left by initialization into loose objects, because it exceeds 4 MiB. Bulk creation and this deferred compaction are part of the measured init/new workflow. The small journal avoids that many-file cost during subsequent one-file edits.

Follow-up only: measure removing redundant stat-cache copies on clean scans, and bulk import's journal/loose-object tradeoff. The phase evidence locates opportunities; it does not prove a speedup. No hot-path optimization was made for this baseline.

## Check after security fixes and import

A separate five-run trace after the implementation measured clean/edited wall medians of 35.94/68.87 ms, compared with the original trace's 32.48/55.16 ms. The slower sample was retained in `target/bench-trace-post.json`; the original `target/bench-trace.json` was preserved. Comparing separate times on this desktop cannot establish whether the change caused that difference.

To check that concern, `trace_compare.py` alternates the retained baseline release executable and the final executable on **one** fresh 10k-file workspace. Ten samples per executable per scenario, with the first executable alternating each pair. Clean scans are warmed after the racy window; each edited sample appends to the same file before that executable runs, so both commands actually snapshot an edit. No builds/tests or other benchmark drivers ran concurrently.

| Paired trace median | Retained baseline | Final build |
|---|---:|---:|
| Clean status, wall | 31.63 ms | 31.31 ms |
| Edited status, wall | 57.01 ms | 57.27 ms |
| Clean status, in-process | 19.90 ms | 19.62 ms |
| Edited status, in-process | 45.56 ms | 46.02 ms |
| `--version`, wall | 9.40 ms | 9.08 ms |

This paired sample shows no material status/startup regression; it is limited evidence, not proof of zero overhead on every workload. Privacy/crypto/import-state reads remain confined to trust boundaries; the snapshot/walker implementation was not changed. No optimization was applied in response to the earlier slower sample.

```powershell
python bench/trace_compare.py target/release/deps/tig-ed9e0d448ee9a563.exe
```

The baseline executable is an ignored retained build artifact, not reproduced by a fresh build of the final sources. Preserve the executable from a baseline build before repeating this comparison. Raw paired samples: `target/bench-trace-paired.json`.

## Real-source follow-up

The [wide-directory comparison](PARALLEL_WALK.md) retains paired TypeScript and
Gitoxide samples, including the remaining edited-status loss against Git.

The [path-validation follow-up](PATH_VALIDATION.md) profiles cached-path
validation, preserves its policy, and records paired state/CLI measurements.

The [metadata-filter follow-up](METADATA_PREFIX.md) profiles snapshot path checks
and preserves Unicode metadata exclusions while skipping definite non-matches.

The [cached-directory-name follow-up](CACHED_DIRECTORY_NAMES.md) reuses listed
names for disk paths, with before/after filesystem tests and real-source timings.
