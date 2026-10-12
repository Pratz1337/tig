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
- **MEDIUM — withheld packs versus opaque foreign seals.** `fetch.rs:293` has no authenticated seal-to-pack/epoch manifest. Removing every pack can make a member fetch successfully with unopened seals; foreign seals must also remain valid. Recommendation: define authenticated availability metadata that lets authorized readers distinguish a missing expected pack from a foreign seal. This needs wire/privacy decisions; rejecting every unopened seal would break outsider and foreign-seal workflows. Evidence: `withheld_packs_are_currently_indistinguishable_from_foreign_seals`.
- **LOW — public metadata can reveal private names/content.** `.private` is required to be public, as are author/committer/message fields. An explicit `secrets/named-in-rules` line exposes that name even if `secrets/` seals whole. Recommendation: explicitly document this metadata exception and warn at publish when public metadata mentions protected names; a private policy file would change the contract. Evidence: `public_rules_can_disclose_a_name_inside_a_sealed_root`. The successful byte scans use root/glob rules without secret child names or secret-bearing descriptions.

TOFU on first fetch remains vulnerable to first-contact substitution by design. Verify the displayed fingerprint out of band. A server can deny service or omit history; the current signed keyring head does not authenticate the public refs/history or the completeness of the grant roster. Recommendation: decide signed-ref and grant-roster completeness guarantees before a network remote. Existing signatures do prevent a server from creating a valid new grant or a valid new epoch head, and local pins/counters reject substitution and observed rollback.

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
