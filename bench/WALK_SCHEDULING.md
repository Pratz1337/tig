# Overlap parent-file reads with descendant scans — 2026-10-18

The [Gitoxide comparison](TRACKED_IGNORE.md) left an ordinary root-file edit
15.5% slower than Git. Review found that `walk.rs::list_dir` ran every file
visitor before returning its child directories to the shared queue. A slow
root-file read could therefore leave the rest of the worker pool idle.

**LOW performance, high confidence — FIXED:** eligible children are now queued
after the directory listing, nested-workspace check and ignore-rule loading,
before its file visitors run. The directory listing caches names and file types
for both passes without a separate file-entry vector; metadata is still obtained
once. Results remain unordered and the public
worker limit remains 1–16. Once an error is recorded, further child queues are
discarded and active workers finish before the error returns.

## Verification

- The channel-handshake regression failed before the fix: a root-file visitor
  waiting for a descendant timed out after five seconds. It passes after the
  scheduling change. No sleep is used to create the interleaving.
- A second test checks exact, duplicate-free file coverage with 1, 2 and 4
  workers and verifies missing-root error completion.
- Targeted Modal tests: **75 passed, 0 failed, 0 ignored**.
- Complete workspace run on the final listing revision: **546 passed, 0 failed,
  3 existing ignored**; detached exit 0 and the persisted log were verified.
  The complete run was repeated after replacing the first candidate's buffer.
- Clippy with `-D warnings` and the Windows GNU release build passed.
- Windows test executables built on Modal and run locally: **22 passed,
  0 failed, 2 existing ignored**, including both new walker tests and the
  tracked-ignore/junction/alias/long-path suites. No local Cargo was run.

Review covered the complete walker and benchmark driver changes: queue/active
accounting, condition-variable wakeups, error completion, traversal exclusions,
file coverage and benchmark observation. Existing path-based filesystem race
limits remain. No permissions, encryption, private-rule matching, object
encodings, identifiers or checkout policy changed. Web/session/database checks
are inapplicable to these filesystem paths.

## Measurement method

The real-source fixture remains Gitoxide commit
`ad0202e3ab396d752a56664001c134f48d834177`: 3,223 paths, 136 symlinks and 186
tracked paths matched by ignores. The [fixture procedure](TRACKED_IGNORE.md)
checks exact path coverage and a clean materialized tree before timing. Both
retained and current binaries correctly handle tracked ignored edits now.

The benchmark observer now captures the working revision from the local
version-2 workspace state immediately after each timed edit status, then reads
that exact immutable revision. A later `cat` snapshot cannot repair the result
being checked. A separate Windows reproduction using the pre-fix ignored-file
binary verified that this observer exposes its missed edit. Local metadata is
read for verification; raw metadata and private data are not exported.

Setup and warming are outside samples; process startup and captured TIG phase
output are inside. Tool order rotates and reverses. Git status inspects edits;
TIG status records them. Normal desktop background services remain active.

## Initial candidate and follow-up

The first implementation used a separate file-entry buffer. Its paired
[Gitoxide samples](gitoxide-walk-scheduling-2026-10-18.json) improved root-file
edited status from 71.37 to 59.41 ms, against Git at 62.84 ms. However, the
[10k-file samples](walk-scheduling-10k-2026-10-18.json) showed clean status rising
from 36.11 to 38.39 ms. The in-process walk rose from 11.37 to 13.73 ms;
startup did not explain that increase. Those initial results are retained.

The follow-up reuses the directory listing buffer and caches each entry name
once instead of repeatedly cloning names for boundary, ignore-file and entry
checks. Its verification and measurements are recorded separately below.

## Final measurements

All cells use 15 samples. No competing build, test or benchmark driver ran during
the accepted timings. Initial-candidate results above and one-sample functional
smoke results were not substituted for these final measurements.

```powershell
python -X utf8 bench/status_compare.py .git/tig-bootstrap/tig-before-walk-scheduling.exe --runs 15 --json bench/walk-listing-10k-2026-10-18.json
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/gitoxide-source .git/tig-bootstrap/tig-before-walk-scheduling.exe --runs 15 --json bench/gitoxide-walk-listing-2026-10-18.json
python -X utf8 bench/self_host_compare.py --baseline .git/tig-bootstrap/tig-before-walk-scheduling.exe --runs 15 --json bench/walk-listing-self-source-2026-10-18.json
```

The baseline is a retained ignored executable from before either walker change.
Raw files record both executable SHA-256 hashes and the exported source commit.

Gitoxide median wall milliseconds ([raw samples](gitoxide-walk-listing-2026-10-18.json)):

| Operation | Git | Retained TIG | Final TIG |
|---|---:|---:|---:|
| Clean status | 67.81 | 46.43 | 45.46 |
| Root `README.md` edit | 69.59 | 79.93 | 65.23 |
| Tracked ignored-file edit | 70.92 | 56.06 | 54.17 |

The root edit improved **18.4%** against retained TIG and measured **6.3% faster
than Git** here. Its walk/classify/hash span fell from 43.82 to 34.29 ms;
in-process total fell from 60.65 to 49.64 ms. Both binaries passed the immutable
revision checks for the ignored edit.

Generated 10k-file median wall milliseconds ([raw samples](walk-listing-10k-2026-10-18.json)):

| Operation | Git | Retained TIG | Final TIG |
|---|---:|---:|---:|
| Clean status | 56.76 | 34.22 | 34.75 |
| Edited status | 57.05 | 45.82 | 44.34 |

Clean wall time remained **1.5% higher** than retained TIG in this run. The walk
span was 11.27/11.10 ms and total in-process time 18.92/18.83 ms; the median
portion outside the total span was 15.57/16.09 ms. This does not establish a
clean wall-time improvement. The first candidate's larger in-process regression
was removed, and the small remaining wall difference is retained explicitly.

Public TIG source, 181 files ([raw samples](walk-listing-self-source-2026-10-18.json)):

| Operation | Git | Retained TIG | Final TIG | Final `--short` |
|---|---:|---:|---:|---:|
| Clean status | 46.02 | 20.68 | 19.74 | 19.65 |
| Edited status | 49.59 | 31.87 | 24.60 | 28.62 |
| Record change | 110.82 | 48.75 | 43.50 | 46.50* |

\* Both record fixtures run ordinary `new`; the last cell is another sample of
the same command. Every measured final workflow beat Git in these runs. The
results do not guarantee universal superiority, a zero-cost change on every
tree, cold-cache behavior, or a speedup on other filesystems and machines.
