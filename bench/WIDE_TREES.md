# Decode wide trees without copying entry names — 2026-10-18

`Tree::decode` copied its entry vector and every filename before passing the copy
to `Tree::new`, then compared the result with the original to check ordering.
It now checks the input's strict bytewise name order and moves the entries into
the same constructor. Name validation, duplicate rejection and conflict-version
validation still run; ordinary and conflict tree encodings are unchanged.

This removes one vector and one filename allocation per entry from each decode.
It does not change the O(N) cost of decoding, rewriting or hashing a wide tree.
The bounded-node format discussed in `DESIGN.md` remains deferred.

## Complete real-source fixture

The public [TypeScript source](https://github.com/microsoft/TypeScript/tree/5237fd46890956e4bb8177a1a05dcd69e4166560)
is pinned to commit `5237fd46890956e4bb8177a1a05dcd69e4166560`, tree
`36a195bcd8d0d663cd2288a8598d4f0fae86fba2`. It contains 67,920 tracked paths
(67,910 regular and 10 executable files). The directory
`tsc/testdata/baselines/reference/compiler` contains 24,009 direct entries;
`tsc/testdata/baselines/reference/conformance` contains 22,326.

The benchmark imports an exact-tree root commit, checks every retained path,
and requires Git to see the same clean materialization. The edit targets
`tsc/testdata/baselines/reference/compiler/2dArrays.js`. Neither source setup nor
history import is timed. Both executable hashes and the exported TIG source
commit are recorded in the raw output. No third-party source is added here.

TypeScript has no tracked files matched by its ignore rules. An initial
one-sample preflight stopped on the driver's previous assumption that such a
file always exists; it produced no timing results. The driver now explicitly
leaves that inapplicable mode empty, with null medians. It also accepts a tracked
regular edit path instead of always editing the root README.

Each timed TIG edit is checked against the immutable working revision captured
immediately after status, so a later snapshot cannot repair a missed edit.
Tool order rotates and reverses. TIG status records edits; Git status inspects
them. Windows process startup is included; normal desktop services remain active.

```powershell
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/typescript-source.git .git/tig-bootstrap/tig-before-tree-decode.exe --edit-path tsc/testdata/baselines/reference/compiler/2dArrays.js --runs 15 --json bench/typescript-tree-decode-2026-10-18.json
```

## Verification

The complete Modal workspace suite finished with **547 passed, 0 failed and
3 existing ignored**. Its detached call returned zero and the persisted complete
log, including doc-tests, was checked before accepting results.

The new wire-compatibility test passes before and after the change. It checks
byte-identical decoding/encoding of empty, ordinary, Unicode, sealed and conflict
entries, and refusal of unordered names, duplicates, invalid paths, reserved
metadata names and noncanonical conflict versions.

Windows object tests: 7 passed. Status checks, metadata exclusions and refused
metadata checkouts passed. All 11 fresh-workspace setup checks passed, including
full-history import, policy/binary copying, clean native status, public export,
and preservation of source clones and existing destinations. Clippy with
`-D warnings` and the Windows GNU release build passed on Modal. No local Cargo
was run.

Review covered the complete `object.rs` and benchmark driver. Input bounds,
UTF-8/name validation, duplicate and ordering errors, conflict-version checks,
sealed IDs, frozen bytes, immutable benchmark observation and subprocess argv
remain sound. The change adds no filesystem operations to tree decoding and no
new crypto, authentication or authorization behavior. Injection, disclosure,
resource bounds, races and state invariants were checked; web/session/database
checks are inapplicable. Existing path-based filesystem race limits remain.

## TypeScript measurements

All cells use 15 samples from the [paired run](typescript-tree-decode-2026-10-18.json).
The tested source is exported commit
`55dd69544fa63c2c4be1cffebb1ff2a4936a75a7`; the retained binary was saved from
the previously published build at `3b0f4d4cb6e717c7a4ea24368f129ab244127613`.
No competing local build, test or benchmark ran during timings; the remote
workspace suite completed while this fixture was still importing.

Median wall milliseconds:

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 174.08 | 307.24 | 308.35 |
| Edit in 24,009-entry directory | 190.23 | 409.83 | 387.93 |

Edited status measured **5.3% lower** than retained TIG. Its tree/operation-write
span fell from 27.72 to 25.96 ms, and scan application from 14.46 to 12.12 ms.
Other spans varied too, so the entire wall-time difference cannot be attributed
to the removed copy. Clean wall time was **0.4% higher**, retained here.

TIG remains **2.04 times Git's edited-status wall time** on this workload, and
its clean status is slower too. This is a measured remaining loss, not evidence
that TIG is universally faster. The edited walk/classify/hash span alone is
221.92 ms, and workspace-state loading takes 51.91 ms. Those are larger next
profiling targets than the remaining 25.96 ms tree/operation-write span. A
different tree format is not justified by this run alone.

The subsequent [Windows filename-check measurements](WINDOWS_NAMES.md) address
part of the scan cost and add finer state-load timings; this run is retained.

## Existing real-source check

The same driver also ran 15 samples on the previously pinned Gitoxide fixture
with its default root-file edit and tracked ignored-file check. It retained all
3,223 paths and 136 symlinks; both binaries correctly recorded ignored edits.
[Raw samples](gitoxide-tree-decode-2026-10-18.json):

| Operation | Git | Retained TIG | Current TIG |
|---|---:|---:|---:|
| Clean status | 64.82 | 45.06 | 43.30 |
| Root README edit | 67.06 | 64.39 | 64.10 |
| Tracked ignored-file edit | 70.28 | 53.07 | 54.71 |

The ignored-edit wall median was **3.1% higher** than retained TIG; that result is
kept alongside the other measurements. Current TIG remained ahead of Git in all
three modes on this fixture. These two real-source runs describe the measured
platform and workloads, not a guarantee for other repositories or machines.

```powershell
python -X utf8 bench/imported_status_compare.py .git/tig-bootstrap/gitoxide-source .git/tig-bootstrap/tig-before-tree-decode.exe --runs 15 --json bench/gitoxide-tree-decode-2026-10-18.json
```
