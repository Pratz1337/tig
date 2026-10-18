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
