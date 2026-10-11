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
