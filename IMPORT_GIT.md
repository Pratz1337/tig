# Importing Git history

Create an empty destination, or run in an existing tig workspace:

```
tig -R new-tig-directory import-git path/to/git-repo
tig -R new-tig-directory import-git path/to/git-repo
```

The first command creates the destination when it is absent or empty, imports history and checks out an empty working change whose parent is Git HEAD. Git working trees, bare repositories, SHA-1 and SHA-256 objects are supported. Existing destination files are snapshotted before an import; recorded local work remains recoverable. Re-import updates bookmarks and preserves the current working change and disk edits. An unchanged re-import writes no new operation. A bookmark moved to local work is refused rather than overwritten by a Git branch. Previously imported history/bookmarks are retained when Git refs disappear.

“Full history” means every commit reachable from Git refs and HEAD, including merges, other branches and commits reachable only from tags. Reflog-only/unreachable objects, Git tag objects, commit signatures and arbitrary extra headers are not imported. Shallow repositories are refused: fetch their complete history first. The source is read through `gix` (gitoxide, MIT/Apache-2.0); hooks, attribute filters, Git LFS smudge/clean programs and the Git working-copy contents are not executed or imported. LFS pointer blobs remain pointer blobs.

Each Git commit maps to one tig revision with its tree, ordered parents, author, committer, message, UTC timestamps and timezone offsets. Git root commits use tig's canonical root as parent. Messages retain trailing newlines. tig's string metadata requires UTF-8; unsupported byte encodings or invalid timestamps fail clearly instead of silently replacing bytes. A detached HEAD becomes the initial working change's parent; an unborn HEAD leaves the empty working copy.

Branches become bookmarks with the same name when tig accepts it. Otherwise the importer uses `git/<UTF-8-name-in-hex>` (with a numeric suffix if necessary to avoid a real branch of that name) and prints the mapping. Every imported ref tip remains visible even if it has no bookmark. Modes `100644`, `100755` and `120000` become File, Executable and Symlink. Submodules (`160000`) and names rejected by tig's portable UTF-8 name policy are skipped, with one sorted warning per path/reason. Invalid directory names skip that subtree. Checkout retains its own platform-specific device-name, collision, alias and redirected-ancestor checks; a portable history can still contain a name that this machine cannot safely check out.

## Identity and retries

The local `.tig/git-import` file stores a random 32-byte import secret, the mode, Git-to-tig revision map and exposure evidence. It is written durably before deriving any ChangeId. Serialized secret buffers zeroize on drop; the file uses secret-file permissions on Unix. Keep this file with repository backups and never upload it to a remote.

The derivation is frozen:

```
subkey = BLAKE3 derive_key("tig git import change id v1", import_secret)
ChangeId = BLAKE3 keyed_hash(subkey, strip_mode_u8 || git_id_length_u8 || git_id_bytes)[0..16]
```

Same secret, mode and Git ID produce the same ChangeId on every machine. Re-import into the same destination is idempotent. Independently initialized destinations use different import secrets and therefore different ChangeIds/revision IDs. This intentional secret input keeps a never-public Git commit hash from becoming a public guessing oracle. It also separates stripped and original history identities. Losing the import secret prevents reproducing the old ChangeIds; the already imported revisions remain usable.

Objects are content-addressed and children are written before their parents. The CLI writes bulk objects directly to the loose store, so ordinary commands do not inherit deferred import compaction. Journal insertion was faster before compaction, but repeated measurements reversed the total-cost comparison; direct loose writes also keep this adapter simpler. The API works with MemoryStore, DiskStore and JournalStore. Classification and converted subtrees/blobs are cached during import; rules are compiled once per distinct root `.private` blob. Completed object/state writes before a view-commit failure are retried without losing the initial HEAD attachment. The operation still uses existing checkout and crash-recovery semantics. Actual directory-entry durability under hardware power loss remains the DESIGN.md limitation.

## Git exposure and stripping

Normal import assumes Git history has already been public. Each commit's UTF-8 paths are classified with its own root `.private` plus the built-in floor, including paths deleted in later commits and paths skipped by the portable-name policy. Skipped private paths get the same rotation warning, but cannot enter tig's publish evidence because they never enter tig history. Every non-UTF-8 leaf is reported as unclassifiable (with its exact hexadecimal Git path); inspect those skipped paths separately, since Unicode rules cannot describe them. Every matched imported path is printed as:

```
.env: already exposed in git history — rotate these secrets
```

Exposure evidence seeds the publish state's `ever_public` at the publish boundary, including for a newly added remote. First publish refuses to pretend imported secrets were never exposed. `--acknowledge-leaked` explicitly accepts sealing them from now on; it cannot erase their prior Git exposure. This does not add matching, crypto, scanning or import-state reads to edit/snapshot/status/diff/log/checkout.

For Git history that has **never been public**, use a separate destination:

```
tig -R never-public-tig import-git path/to/git-repo --strip-private
tig -R never-public-tig import-git path/to/git-repo --strip-private
```

Before storing blobs, strip mode discovers every path private in **any** reachable commit, using each commit's own rules. It removes that union of paths from **every** imported revision and branch, including snapshots before the first private rule was added. It never stores blobs solely for those paths, and reports each stripped path. Negations re-include files when they are never classified private elsewhere in the imported history. The resulting trees and commit identities differ from unstripped history. Strip mode is fixed for that destination; re-import must pass the same mode. An incremental extension is accepted only if it preserves the identities of earlier stripped revisions. If a new rule would retroactively change them, import into a fresh destination; existing work and exposure evidence are retained.

Do not use this as an erasure claim for Git history that was already public. It is path filtering, not secret discovery or redaction of messages, author fields or public `.private` text. Equal bytes at an unmatched public path remain public; see the privacy and metadata limits in [DESIGN.md](DESIGN.md#privacy-tig-private).

The tested toolchain is stable `x86_64-pc-windows-gnu` Rust 1.99.0. The workspace minimum is now documented as 1.89: gix requires 1.88, and the existing journal uses the standard file-lock API introduced in 1.89. No MSVC toolchain is needed.

Validation: `cargo test --workspace` passed 326 tests with four existing ignored tests; `cargo clippy --workspace --all-targets -- -D warnings` passed. Git CLI fixtures cover linear/merge/rename history, original metadata, mode mapping, invalid names/submodules, SHA-256 bare history, explicit empty trees, tag-only history, detached/unborn HEAD, exposure after deletion, global stripping, incremental reuse/refusal, frozen identity encoding, malformed state and persistence retry. Unix checkout mode/symlink and secret-file permission assertions are present but were not executed on Windows. Rust 1.89 itself and hardware power-loss durability were not tested.

Performance evidence and reproducible commands are in [bench/RESULTS.md](bench/RESULTS.md#git-import).
