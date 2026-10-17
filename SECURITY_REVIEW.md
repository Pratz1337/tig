# VCS metadata boundary review — 2026-10-18

Scope: filesystem scanning, tracked-file fallback and checkout. The object,
walker and working-copy modules and the new integration test were read in full.
This is a focused source review with regression and runtime evidence.

## Findings fixed

All three findings have high confidence and failed before the fix.

| Severity | Location | Failure and fix |
|---|---|---|
| HIGH | `crates/tig-cli/src/walk.rs`, `crates/tig-core/src/object.rs` | Exact lowercase exclusions admitted `.GIT/config` and other metadata aliases into snapshots and plaintext public exports. Reuse the portable metadata-name comparison for full and event-selected scans; ASCII comparisons allocate nothing. |
| HIGH | `crates/tig-cli/src/wc.rs::preflight`, `ensure_not_metadata_alias` | An incoming tree could write VCS metadata, including hook paths. Refuse `.git`, `.hg`, `.svn` and `.jj` components, case/HFS+ aliases and resolved Windows aliases before any checkout mutation. |
| HIGH | `crates/tig-cli/src/wc.rs::drop_absent` | Rehash and cache recovery could read newly changed credentials from previously tracked metadata despite the walker exclusion. Drop those paths from the current tree/cache before reading disk contents, preserve the physical files, and warn about old history. |

## Verification

- Regression first: both new integration tests failed against the old scanner
  and checkout; the internal legacy-cache test also failed before its fix.
  The old Windows executable demonstrably tracked and exported a benign marker
  from `.GIT/config`.
- Modal targeted working-copy tests: **57 passed, 0 failed, 1 existing ignored**.
- Modal `python -X utf8 scripts/modal_build.py test`: **537 passed, 0 failed,
  3 existing ignored**; includes the large encrypted-file transfers.
- Modal `python -X utf8 scripts/modal_build.py clippy`: passed with
  `-D warnings`; Windows GNU release cross-build: passed.
- Live Windows release checks: six case/HFS+ metadata aliases were neither
  snapshotted nor present in reachable exported object bodies; five crafted
  metadata trees were refused without partial checkout. An actual NTFS `GIT~1`
  alias resolving to `.git` was also refused. Clean/add/edit/delete status,
  UTF-8/spaces, NUL output and stored-conflict checks passed.

The [raw performance samples](bench/metadata-real-source-2026-10-18.json) compare
the same 168-file public TIG source tree across Git, the retained prior TIG
binary and the fixed release. There are 15 alternating-order samples per cell;
preparation is outside timings and no build/test driver ran during measurement.
The procedure is in [the self-hosting benchmark notes](bench/SELF_HOSTING.md).

| Median milliseconds | Git | Previous TIG | Fixed TIG | Fixed TIG `--short` |
|---|---:|---:|---:|---:|
| Clean status | 38.10 | 17.40 | 16.79 | 16.39 |
| Edited status | 43.30 | 28.87 | 25.11 | 26.08 |
| Record change | 90.06 | 45.95 | 41.31 | 44.79* |

\* Record uses ordinary `new` in both TIG fixtures. This is another sample of
the same command, not a short-output recording feature. Desktop background
services remained active. These results show no measured regression in this
workload; they do not establish a causal speedup or universal superiority. The
previous [10k-file edited-status loss](bench/RESULTS.md) remains a target.

Checked and sound within this scope: ordinary `.gitignore` stays content;
stored names, encodings and hash labels are unchanged; metadata refusal occurs
before checkout writes or deletes; and the snapshot fallback preserves disk
files. Path injection, disclosure and state transitions were checked; existing
path-based TOCTOU limits remain. No crypto, permission matching, remote
authentication or authorization changed. SQL/template injection, web XSS,
cookies, session fixation and CSRF are inapplicable to these filesystem paths.
The alias matcher is bounded by the supplied component length and adds no I/O.

Limits: earlier revisions and operation history still contain any metadata
already recorded; this is not history redaction. Rotate credentials if that
history was shared. Event-selected snapshots defer cleanup of unselected legacy
rows until an authoritative full scan. Actual macOS/HFS+ execution and concurrent
filesystem substitution attacks were not tested. The separate store-directory
and crash-durability gaps in DESIGN.md remain outside this fix.

---

# Integrated publish/fetch review — 2026-10-12

Threat model: attacker controls the public directory remote, including keyring, refs, loose objects and packs. Local identity, owner keys and pins remain trusted. Review covers library projection/pack/keyring/publish/fetch and CLI persistence, clone and working-copy integration. This is a targeted source review and adversarial regression suite, not a formal proof or a hardware power-loss experiment.

## Findings fixed

All findings below have high confidence. The regression was run against the old behavior before the fix.

| Severity | Location in final code | Failure and fix |
|---|---|---|
| HIGH | `crates/tig-private/src/publish.rs:427` | First library publish minted the only epoch secret internally and exposed the remote keyring before returning it. A failure/crash could permanently strand the owner. An empty remote now requires caller-prepared keys. CLI already saves these first. `new_owner_keys` remains in the report for source compatibility but production always returns `None`. |
| HIGH | `crates/tig-cli/src/cmd/remote.rs:284` | Revoke/grant updated the remote before persisting the local counter. A crash could let the owner accept a replayed older epoch. Save a local signed pending keyring and rollback floor first; owner mutations resume that pending write. A newer verified remote head is preserved. Fetch observes the pending floor too. |
| MEDIUM | `crates/tig-private/src/keyring.rs:280` | Crash after saving new epoch keys but before writing the remote left revoke retries failing with “epoch key already stored.” Retry reuses the existing local secret, checks its context, and never replaces it. |
| MEDIUM | `crates/tig-cli/src/cmd/disk.rs:95`, `crates/tig-private/src/remote.rs:345` | Backup replacement moved the only destination away before the new file was installed, leaving a crash gap and deleting pre-existing recovery data. Remove that fallback; failed atomic replacement preserves existing files. |
| MEDIUM | `crates/tig-private/src/remote.rs:105` | Opening a remote created `objects/tmp`, including through attacker-controlled directory redirection. Opening is now read-only; fetch writes only into its local destination store. |
| MEDIUM | `crates/tig-private/src/remote.rs:158`, `crates/tig-core/src/store/disk.rs:66`, `crates/tig-private/src/fetch.rs:34` | Pack limits were per file while the list retained every pack; loose remote reads were unbounded before decoding; metadata-then-read allowed file growth past limits. Bound pack lists in aggregate, use bounded single-handle reads, cap remote loose files and total fetch bytes. The new storage methods are used only at remote boundaries; local hot-path reads are unchanged. |

Crash checks recreate states after keys-only persistence, pending-head persistence, and remote-head persistence before the counter is saved. They also cover an already newer verified remote and failed replacement. First publish refuses unsaved keys without touching the remote. Objects already uploaded before an I/O failure may remain unreachable; this does not disclose their plaintext or lose the saved epoch key. Filesystem directory-entry durability under actual power loss remains the documented gap in DESIGN.md.

## Needs a design decision

These behaviors are demonstrated in tests and deliberately not changed:

- **HIGH — historical paste / private-to-public rename. DECIDED AND FIXED.** Each remote's publish state remembers every non-empty blob ever sealed to it (`ever_private`). Publishing those bytes in a public file — after a rename, a delete, or within one unpublished multi-revision batch — is refused (`PreviouslyPrivate`) unless that exact path is passed with `--declassify <path>`; declassified blobs are remembered. Confirming a negation never declassifies. Tests: `historical_private_bytes_need_explicit_declassification`, `rename_inside_an_unpublished_window_is_also_refused`.
- **MEDIUM — withheld packs versus opaque foreign seals. DECIDED AND FIXED.** Each publish now ends with a publisher-signed manifest (`crates/tig-private/src/manifest.rs`): refs, a monotonic sequence, and every pack ID with its group, epoch and sealed IDs. Signers are the owner or a current-epoch member, checked against the verified keyring. A member who holds an epoch must find every listed pack of that epoch with its listed records, or fetch fails with `WithheldPack`; unlisted unopened seals remain foreign seals, so outsiders are unaffected. The manifest reveals only pack IDs and sealed IDs, which the remote already stores. Revoke re-signs the manifest as owner before the new head. Tests: `withheld_pack_is_an_error_for_members_and_invisible_to_outsiders`, `manifest_signs_refs_and_refuses_tampering_and_rollback`, `member_publishes_and_revoke_resigns_the_manifest_as_owner`.
- **LOW — public metadata can reveal private names/content. DECIDED.** Documented as the metadata exception in DESIGN.md "Privacy"; publish warns (never refuses) when `.private` or a change description mentions a name hidden inside a sealed root. Test: `public_rules_can_disclose_a_name_inside_a_sealed_root` now asserts the warning.

TOFU on first fetch remains vulnerable to first-contact substitution by design. Verify the displayed fingerprint out of band. A server can deny service. Refs and history are now authenticated by the signed manifest, and an older manifest is refused once a newer one has been seen; a fresh fetcher with no prior sequence can still be shown an old genuine manifest (first-contact, like TOFU). Grant-roster completeness is still unauthenticated: a server can hide a grant from its recipient, which only denies that member access. Directory remotes have no compare-and-swap, so concurrent publishers can overwrite each other's manifest (documented in DESIGN.md "Known gaps"). Existing signatures do prevent a server from creating a valid new grant or a valid new epoch head, and local pins/counters reject substitution and observed rollback.

## Checked and fine within these limits

- Scan every file and pathname under the remote after multi-revision, multi-branch history, private renames/deletes/re-additions, negations, `.private` edits/deletion and the built-in floor. Scan decompressed public object bodies as well. Private blobs, private child names, internal trees/revisions, operation/view IDs are absent in that protected history.
- Public projection replaces tree/parent IDs and drops predecessors. Sealed IDs and wire IDs are context-bound keyed values; encrypted indexes contain internal IDs and sealed records. AEAD verifies context, kinds and content hashes. Existing golden/format tests cover signatures, commitments, tampering and nonce-domain separation.
- Pinned-owner substitution, older signed heads, forged grants, cross-remote grants/packs/keyrings, malformed counts/varints, malformed/truncated/tampered packs and portable-path tricks are refused cleanly. Failed fetch does not accept its state or move CLI bookmarks. Some verified unreachable objects may already have been copied locally.
- Missing authenticated sealed targets are refused. Expanded-tree/depth budgets apply to decrypted trees as well as public trees.
- New revisions after revoke use new epoch seals and ciphertext even when a blob duplicates older content. A revoked reader still has the older bytes, which cannot be revoked; it cannot open the new pack or resolve those new seals with its old key.
- Outsider clone → edit → snapshot/rehash → status/diff/log → publish to a different remote preserves opaque seals. Missing files on disk are not interpreted as deleted seals.
- Publish leak scans include reachable history from another publisher/branch. Negations need first-time confirmation; empty private blobs are exempt from paste equality.

Production modules read in full: `tig-private/{rules,keys,project,pack,keyring,remote,publish,fetch}.rs`, CLI `cmd/{publish,fetch,clone,grant,revoke,remote,disk,identity}.rs`. Working-copy, walker, command dispatch and core object/store/repo/workspace/treeops/merge/recovery paths were additionally inspected for integration, path handling and costs. Checklist: authentication/authorization, crypto, disclosure, crash/state races and denial-of-service reviewed (findings above); path/format injection reviewed; SQL, web XSS, cookies/session fixation and CSRF are inapplicable to these local directory commands. Concurrent independent publishers and hard-killed/power-loss filesystem experiments were not validated.

Validation: `cargo test --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`; adversarial MemoryStore + directory-remote tests and real CLI end-to-end tests. Logs are retained under `target/part1-*.log`.
