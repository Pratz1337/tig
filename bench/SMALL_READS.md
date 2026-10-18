# Small-file streaming reads — 2026-10-18

`tig-core::blob::fill_chunk` previously allocated and zero-filled 4 MiB before
reading any stream, including an empty or tiny source file. It now uses a
bounded standard-library read that grows the buffer as data arrives. Full chunks
reuse that buffer. Chunk boundaries, canonical manifests, ordinary blob IDs and
the 64 GiB content limit are unchanged.

Review finding: **LOW performance, high confidence — FIXED**. The allocation
regression failed against the previous implementation. The production change
replaces the manual fill loop; no permissions, privacy matching, encryption,
remote policy or filesystem path checks changed. The blob module and changed
benchmark were read in full. Stream bounds, EOF, interrupted reads, object
identity, error propagation and disclosure were checked; no additional finding
was identified in this diff. Web/session/database concerns are inapplicable.

## Verification

- Eight focused blob tests passed, including the new allocation and bounded
  interrupted-read regressions, fragmented readers, exact chunk boundaries,
  stable plain-blob IDs and private-content evidence across encodings.
- Modal `cargo test --workspace --locked`: **539 passed, 0 failed, 3 existing
  ignored**. The complete detached rerun returned exit 0 and retained its full
  log. An earlier client-disconnected run was not counted as a pass.
- Modal clippy with `-D warnings` and the Windows GNU release build passed.
- The Windows release round-tripped files of 0, 1, 1,024, 4,194,303, 4,194,304,
  4,194,305, 8,388,608 and 8,388,625 bytes. The retained previous binary read
  those snapshots correctly; Git export preserved the final chunked file bytes.
- Windows compact-status, stored-conflict, metadata-alias and reproducible
  bootstrap checks passed.

## Comparison method

The retained pre-change executable is an ignored local artifact. Keep one from
the preceding build before repeating these comparisons. Raw results record
executable SHA-256 hashes and the exported source revision.

`status_compare.py` generates the existing deterministic 10,000-file fairness
fixture, plus `.gitignore` and `.private`. Git and both TIG binaries operate on
one workspace. Git ignores `.tig`; TIG excludes `.git`. Setup is outside the
timings, the stat-cache racy window expires before warming, and tool order
rotates and reverses across rounds. Every edited sample appends to the same
file before running its command. TIG status records that edit; Git status
inspects it. TIG samples include `TIG_TRACE_PERF=1` phase output, captured by
the driver; Git uses `status --porcelain`.

The separate `self_host_compare.py` comparison uses independent copies of the
same exported public TIG source. See [the original procedure](SELF_HOSTING.md)
for preparation and workflow semantics. Generated-file results do not establish
real monorepo performance, and a desktop timing difference alone does not prove
a causal speedup or universal superiority over Git.

## Results

Both comparisons used 15 samples per cell. Desktop background services remained
active; no other build, test or benchmark driver ran during accepted timings.

```powershell
python -X utf8 bench/status_compare.py .git/tig-bootstrap/tig-before-large-status.exe --runs 15 --json bench/large-status-2026-10-18.json
python -X utf8 bench/self_host_compare.py --baseline .git/tig-bootstrap/tig-before-large-status.exe --runs 15 --json bench/small-reads-real-source-2026-10-18.json
```

Median wall milliseconds on the generated 10k-file fixture
([raw samples and phases](large-status-2026-10-18.json)):

| Operation | Git | Previous TIG | Fixed TIG |
|---|---:|---:|---:|
| Clean status | 52.88 | 32.73 | 31.96 |
| Edited status | 55.14 | 45.18 | 42.34 |

Edited status measured 6.3% lower than the retained TIG binary. Its walk,
classification and hash phase fell from 17.37 to 15.04 ms; total in-process time
fell from 29.49 to 26.85 ms. State saves (2.89/2.84 ms) and tree/operation writes
(1.74/1.73 ms) were similar. The older [10k-file loss](RESULTS.md) remains a
historical result; this new paired sample does not invalidate it.

Median wall milliseconds on the **171-file public TIG source tree**
([raw samples](small-reads-real-source-2026-10-18.json)):

| Operation | Git | Previous TIG | Fixed TIG | Fixed TIG `--short` |
|---|---:|---:|---:|---:|
| Clean status | 43.65 | 21.78 | 20.09 | 19.50 |
| Edited status | 43.90 | 32.81 | 24.33 | 24.49 |
| Record change | 90.88 | 46.87 | 39.72 | 41.38* |

\* Both TIG record fixtures run ordinary `new`; the last cell is another
sample of the same command. These measured workflows all beat Git here.
Larger real repositories, cold-cache behavior and different edit patterns still
need measurement. The allocation regression is directly tested; the observed
wall-time changes also include normal filesystem and antivirus variation.
