# Git import measurements — 2026-10-12

Source: a real bare clone of [madler/zlib](https://github.com/madler/zlib), HEAD `767c4c947852e143f582c85f14cf573411df1b35`. All reachable history contains 1,126 commits, 9,153 packed Git objects, two local branches, and one 5,343 KiB pack. This is a modest adoption workload, not evidence for a large monorepo. Source clone/network time is excluded.

Machine and toolchain are the same as [RESULTS.md](RESULTS.md): i5-13500H, 16 GB RAM, Windows 11, NTFS, antivirus enabled, stable GNU Rust 1.99.0, Git 2.56.0.windows.1. No tests/builds or other benchmark drivers ran concurrently. Normal desktop services and Codex's Git status polling remained; this was not an isolated laboratory machine. Fresh destination files can trigger antivirus scans. Three samples per trial; destinations are retained under `target` for inspection.

## Bulk storage comparison

The release `import_bench` example measures the library import plus any compaction, excluding CLI initialization, view commit and HEAD checkout. Both backends import identical history into fresh stores with independent import secrets. The journal trial inserts through JournalStore and compacts once before stopping the timer. Direct loose writes use DiskStore. Rules and object conversions are cached within either import.

| API backend | First trial median, total | Second trial median, total | Second trial total samples |
|---|---:|---:|---|
| Direct loose writes | 21.884 s | 17.596 s | 17.562, 19.726, 17.596 s |
| Journal + one compaction | 16.864 s | 24.656 s | 18.665, 27.579, 24.656 s |

The second journal trial's insertion times were 1.655, 1.615 and 7.373 seconds; compaction took 17.009, 25.964 and 17.283 seconds. Reporting only journal insertion would hide most of the cost. The trials reverse which backend wins, so these samples do not establish a robust general advantage. The CLI chooses direct loose writes: it is a simple bulk path and ordinary commands never inherit import compaction. The existing journal remains the ordinary mutation store. No hot-path storage optimization was made.

The journal CLI prototype's three full-command wall samples were approximately 28, 26 and 119 seconds (median 27.960 s). The long sample was retained, not discarded. First opens, filesystem caching and background antivirus activity are plausible contributors; they were not separately profiled, so attributing that outlier entirely to antivirus would be speculation. An earlier loose CLI trial had a 23.921-second median, and a later loose trial had a 19.696-second median. All of this variation is larger than small percentage differences between storage implementations.

## Final CLI

Final release-build numbers include process startup, destination initialization, durable state/object writes, history visibility, bookmarks and HEAD checkout. An unchanged re-import still reads/classifies the reachable Git history to catch changed privacy rules; it reuses object identities and writes no new operation.

| Final CLI operation | Median wall | Wall samples | Throughput using median wall |
|---|---:|---|---:|
| Fresh import, direct loose writes | 18.389 s | 17.470, 18.395, 18.389 s | 61.2 commits/s |
| Unchanged re-import | 0.977 s | 0.879, 0.977, 1.015 s | 1,152 reused commits/s |

All three fresh imports reported 1,126 new revisions and two bookmarks; all three repeats reported zero new revisions and 1,126 reused. These final samples followed the skipped-path inventory fix. The earlier API trials used the same supported-path conversion/storage behavior; zlib did not produce skipped-path or secret warnings.

Raw storage trials: `target/import-benchmark-trial1.json`, `target/import-benchmark.json`. Final CLI samples: `target/import-cli-final.json`. Logs: `target/import-measure.log`, `target/import-measure-final.log`, `target/import-cli-final.log`. Raw files are ignored build artifacts; the tables here preserve the report in Git.

## Reproduce

```powershell
git clone --bare https://github.com/madler/zlib target/import-zlib.git
git -C target/import-zlib.git rev-parse HEAD
cargo build --release -p tig-cli -p tig-private --bin tig --example import_bench
python bench/import_compare.py target/import-zlib.git --runs 3
python bench/import_compare.py target/import-zlib.git --runs 3 --cli-only
```

Record the actual source HEAD when repeating: upstream changes can change counts. Each invocation creates unique fresh destinations without deleting previous data. The first command measures both API backends and the currently built CLI; `--cli-only` measures the final adapter separately. Repeating a source with newly added private rules in strip mode can require a fresh destination, as described in [IMPORT_GIT.md](../IMPORT_GIT.md).

Next performance work should measure storage packs and bulk durability on larger real repositories, with randomized backend order and more repetitions. These timings do not justify a format change on their own.
