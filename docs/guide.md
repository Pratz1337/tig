# User guide

Commands, behavior and limits for TIG's main workflows. Start with the [quick start](../README.md#quick-start) if you are new to TIG.

- [Roles and command environments](#roles-and-command-environments)
- [Local conflicts](#local-conflicts)
- [Importing Git history](#importing-git-history)
- [Exporting to Git](#exporting-to-git)
- [Private changes](#private-changes)
- [Large files and filesystem watching](#large-files-and-filesystem-watching)

## Roles and command environments

Roles separate read visibility, key custody, and management. The current owner has management permissions but does not automatically receive a group's secret. A role assignment permits reading; a key grant makes its ciphertext readable. The high-level grant command performs both in one conditional head update. Public role policy, identity tokens, group names, and role names are not secrets.

Start with an initialized repository and an already published remote named `origin`. On another client, fetch or clone first so it has the owner's trust pin. Obtain each person's public token with `tig identity`.

### Define and assign roles

```text
tig role create billing --rank 1
tig role grant billing READER_TOKEN
tig role list
```

The remote defaults to `origin`. The existing explicit form, such as `tig role origin list`, also works. `create` gives a new role its own read group and initializes the creator-owner's key custody. `grant` assigns the role and wraps its key together. Directory and HTTP remotes commit these consecutive signed policy batches in one conditional head update; the server verifies each batch and rejects skipped counters.

`set` creates or replaces a role. Its `--groups` and `--permissions` arguments accept comma-separated names. Larger numeric ranks are higher. A manager can change or assign only roles strictly below their own highest rank, cannot give permissions they lack, and cannot assign themselves a higher role. The current owner is exempt from the rank limit.

The effective permissions are `edit-private`, `manage-roles`, `assign-roles`, and `publish`. For example:

```text
tig role create lead --rank 10 --permissions manage-roles,assign-roles
tig role grant lead MANAGER_TOKEN
```

A manager without a group's read role cannot obtain its key merely by managing it. A current key holder completes pending grants. For a new group, its first authorized reader can create the initial epoch while granting it. Existing groups require existing epoch-key custody for grants and rotation.

A manager can use `assign` before the key holder uses `grant` for that already-assigned role. The key holder needs read access and key custody, without management or publish permission. `pending` lists missing keys for ordinary and combined groups, including `billing+security` when either role permits reading it.

Publishing a new `@billing` tag as the owner also creates that read role and initializes its key automatically. Adding tags is sufficient to switch from simple mode; no migration command is needed. The role policy and published bookmark land in the same conditional head update. Existing simple-mode members retain their private-group access, publish permission, and rule-edit permission through a built-in rank-0 `private` role. New read-role recipients receive no unrelated private-group keys or publish permission. A tag does not change existing roles' ranks or permissions.

Rules with several tags use a combined encryption group. Publish initializes a missing group's epoch for an authorized publishing reader in the same update; other assigned readers remain pending until a key holder wraps its key. Existing epochs are retained.

Put role rules in `.private`, for example:

```text
.env.billing @billing
internal/billing/** @billing
```

Untagged rules retain the `private` group. Each historical revision uses its own rules. Publishing a `.private` change requires `edit-private`, and a publisher cannot assign private content to a group they cannot read. Existing independent private files stay private when a sealed security change is later revealed.

### Remove access and rotate

```text
tig role revoke billing READER_TOKEN
```

`revoke` removes the assignment, rotates affected group keys, and wraps them for the remaining readers in one conditional update. A separate read role can still authorize a member for a shared group. A revoked reader retains old epochs but cannot open new ciphertext.

The advanced `set`, `assign`, `unassign`, `pending`, and `rotate` operations remain available. `set` creates or replaces explicit permission/group definitions. A low-level `unassign` freezes publication until a reader rotates; the high-level `revoke` performs both steps atomically. Existing groups require key custody before grants or rotation; a manager who cannot read them cannot obtain their keys by managing roles.

In role mode, publication can use a verified epoch grant when no local owner key is saved. A saved local key must still match its signed commitment; simple mode continues to require the original owner's local private-group key.

If removing publish permission invalidates the current manifest's signer, the command re-signs its unchanged contents with the acting authorized publisher. A manager without publish permission must have an authorized publisher make that role change instead.

Revocation cannot erase plaintext, old keys, or history someone already received. Fetch can still open historical epochs for which that person has a valid grant. New epochs exclude removed readers. If no remaining reader has the old key, restore authorized custody before rotating; management permission alone cannot manufacture it.

### Transfer ownership

The old owner signs a proposal naming the successor and next policy counter. The proposal also records the observed remote head:

```text
tig role origin transfer SUCCESSOR_TOKEN transfer.proposal
```

Give that proposal file to the successor. On their own client, using their own identity, they run:

```text
tig role origin accept-transfer transfer.proposal
```

Acceptance signs the new keyring head and re-signs existing public reveal certificates. It does not export either person's private identity or raw epoch keys. The CLI checks the recorded head before accepting; if it changed, make a fresh proposal. Concurrent public updates can still be preserved by the conditional commit. The signed authorization binds the successor and policy counter, rather than the recorded head bytes. The root owner pin remains the trust anchor; the former owner's key no longer confers owner authority. Secret access still follows read assignments and key grants, so arrange needed reader custody separately.

### Run a command with role secrets

With `.env.billing` classified as `@billing` and available in the working revision:

```text
tig env origin --role billing -- PROGRAM ARGUMENTS
tig env origin --role billing --file internal/billing/service.env -- PROGRAM ARGUMENTS
```

The default file is `.env.<role>`. Here `--role` selects the read group named in `.private`; a custom role definition can authorize several such groups. The selected source must be classified private for that group. Missing, sealed, unreadable, invalid, and unauthorized sources fail before the child starts. Authorization checks the live verified remote policy even if the file and an old key remain cached locally.

Role commands and `tig env` persist each verified policy counter and signed policy prefix before acting, including a denied environment request. Later commands reject an older head or a different accepted prefix. This local observation floor survives stale fetch/publish cache saves and serializes competing observers. It cannot detect an older genuine policy on first contact or revoke plaintext already held by another process.

Dotenv parsing is literal: optional `export ` and matching outer quotes are supported; `$`, command substitutions, and escapes are not evaluated. The command and its arguments are passed directly to the child without an inserted shell. The child inherits standard input/output/error and its exit status is propagated; it can print or otherwise disclose secrets it receives. tig itself does not print parsed values or include invalid line contents in errors.

## Local conflicts

`tig new left right third` merges any number of parents. Overlapping changes
are stored in the resulting revision, and rewriting a parent rebases its
descendants even when their contents conflict. `tig status` lists unresolved
working-copy paths with `C`; `tig diff`, `tig show` and `tig cat PATH` show
the alternatives. Ordinary merge behavior is unchanged for edits at disjoint
paths. This phase merges at file granularity: different edits to the same file
become a conflict even when a line-based merge could combine them.

Open the conflicted file, keep the desired contents and remove the conflict
marker/label lines. The next command snapshots the resolved file. Unchanged
markers remain a conflict, and partial edits are recorded as an unresolved
draft. Reopening, `snapshot --rehash` and losing the stat cache do not silently
resolve marker files. `tig undo` restores the preceding conflicted revision,
including a partial draft.

Marker files contain no internal object hashes. Generated marker runs are
longer than literal marker runs in the original sides; binary alternatives
show a side-selection hint instead of raw binary contents.

For binary files, modes, symlinks, directories or deletion, select one of the
numbered alternatives shown in the marker file:

```
tig resolve PATH --side 2
tig resolve PATH --base 1
```

Selection preserves the exact original bytes and kind, including a missing
final newline. A directory side restores its subtree; a deleted side removes
the path. Selecting an alternative that is itself a saved draft restores that
unresolved draft. Text editing produces a normal file; use side selection to
preserve a symlink or choose a file mode explicitly.

Conflicts retain structured alternatives, rather than nested marker strings.
The expression stores positive and negative optional leaves, cancels common
terms, and supports multiple contributing sides. Partially edited expressions
remain referenced by subsequent merges so resolution progress is retained.
Expression expansion is bounded; oversized expressions fail without moving
repository state. Recovery checks the conflict object, every referenced side
(including directory contents) and draft bytes.

Unresolved history remains local. Publish and Git export refuse it even when
the conflicted path is private or the current descendant has been resolved.
Resolve the original conflicted change first; its descendants then rebase.
This prevents conflict objects, their internal IDs and competing private
versions from entering a public projection. Fetch also rejects remote conflict
entries. All existing object IDs, cryptographic domains and ordinary tree/cache
encodings remain unchanged; older binaries cannot open the new conflict kinds.

## Importing Git history

Create an empty destination, or run in an existing tig workspace:

```
tig -R new-tig-directory import-git path/to/git-repo
tig -R new-tig-directory import-git path/to/git-repo
```

The first command creates the destination when it is absent or empty, imports history and checks out an empty working change whose parent is Git HEAD. Git working trees, bare repositories, SHA-1 and SHA-256 objects are supported. Existing destination files are snapshotted before an import; recorded local work remains recoverable. Re-import updates bookmarks and preserves the current working change and disk edits. An unchanged re-import writes no new operation. A bookmark moved to local work is refused rather than overwritten by a Git branch. Previously imported history/bookmarks are retained when Git refs disappear.

“Full history” means every commit reachable from Git refs and HEAD, including merges, other branches and commits reachable only from tags. Reflog-only/unreachable objects, Git tag objects, commit signatures and arbitrary extra headers are not imported. Shallow repositories are refused: fetch their complete history first. The source is read through `gix` (gitoxide, MIT/Apache-2.0); hooks, attribute filters, Git LFS smudge/clean programs and the Git working-copy contents are not executed or imported. LFS pointer blobs remain pointer blobs.

Each Git commit maps to one tig revision with its tree, ordered parents, author, committer, message, UTC timestamps and timezone offsets. Git root commits use tig's canonical root as parent. Messages retain trailing newlines. tig's string metadata requires UTF-8; unsupported byte encodings or invalid timestamps fail clearly instead of silently replacing bytes. A detached HEAD becomes the initial working change's parent; an unborn HEAD leaves the empty working copy.

Branches become bookmarks with the same name when tig accepts it. Otherwise the importer uses `git/<UTF-8-name-in-hex>` (with a numeric suffix if necessary to avoid a real branch of that name) and prints the mapping. Every imported ref tip remains visible even if it has no bookmark. Modes `100644`, `100755` and `120000` become File, Executable and Symlink. Submodules (`160000`) and names rejected by tig's portable UTF-8 name policy are skipped, with one sorted warning per path/reason. Invalid directory names skip that subtree. Checkout retains its own platform-specific device-name, collision, alias and redirected-ancestor checks; a portable history can still contain a name that this machine cannot safely check out.

### Identity and retries

The local `.tig/git-import` file stores a random 32-byte import secret, the mode, Git-to-tig revision map and exposure evidence. It is written durably before deriving any ChangeId. Serialized secret buffers zeroize on drop; the file uses secret-file permissions on Unix. Keep this file with repository backups and never upload it to a remote.

The derivation is frozen:

```
subkey = BLAKE3 derive_key("tig git import change id v1", import_secret)
ChangeId = BLAKE3 keyed_hash(subkey, strip_mode_u8 || git_id_length_u8 || git_id_bytes)[0..16]
```

Same secret, mode and Git ID produce the same ChangeId on every machine. Re-import into the same destination is idempotent. Independently initialized destinations use different import secrets and therefore different ChangeIds/revision IDs. This intentional secret input keeps a never-public Git commit hash from becoming a public guessing oracle. It also separates stripped and original history identities. Losing the import secret prevents reproducing the old ChangeIds; the already imported revisions remain usable.

Objects are content-addressed and children are written before their parents. The CLI writes bulk objects directly to the loose store, so ordinary commands do not inherit deferred import compaction. Journal insertion was faster before compaction, but repeated measurements reversed the total-cost comparison; direct loose writes also keep this adapter simpler. The API works with MemoryStore, DiskStore and JournalStore. Classification and converted subtrees/blobs are cached during import; rules are compiled once per distinct root `.private` blob. Completed object/state writes before a view-commit failure are retried without losing the initial HEAD attachment. The operation still uses existing checkout and crash-recovery semantics. Actual directory-entry durability under hardware power loss remains the DESIGN.md limitation.

### Git exposure and stripping

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

Do not use this as an erasure claim for Git history that was already public. It is path filtering, not secret discovery or redaction of messages, author fields or public `.private` text. Equal bytes at an unmatched public path remain public; see the privacy and metadata limits in [DESIGN.md](../DESIGN.md#privacy-tig-private).

The tested toolchain is stable `x86_64-pc-windows-gnu` Rust 1.99.0. The workspace minimum is now documented as 1.89: gix requires 1.88, and the existing journal uses the standard file-lock API introduced in 1.89. No MSVC toolchain is needed.

Validation: `cargo test --workspace` passed 326 tests with four existing ignored tests; `cargo clippy --workspace --all-targets -- -D warnings` passed. Git CLI fixtures cover linear/merge/rename history, original metadata, mode mapping, invalid names/submodules, SHA-256 bare history, explicit empty trees, tag-only history, detached/unborn HEAD, exposure after deletion, global stripping, incremental reuse/refusal, frozen identity encoding, malformed state and persistence retry. Unix checkout mode/symlink and secret-file permission assertions are present but were not executed on Windows. Rust 1.89 itself and hardware power-loss durability were not tested.

Performance evidence and reproducible commands are in [bench/RESULTS.md](../bench/RESULTS.md#git-import).

## Exporting to Git

`tig export-git <path>` writes bookmarks into a Git repository so the history can be pushed to a Git host. Git has no sealed entries. An export is a public channel: private content never becomes a Git object.

```
tig -R repo export-git ../public.git
tig -R repo export-git ../public-repo --bookmark main --verbose
tig -R repo export-git ../build-source.git --working-copy
tig -R repo export-git ../public-repo --declassify notes.txt --force
```

`<path>` is created when it is missing or an empty directory. An existing Git repository is updated. Any other path is refused. A final path component ending in `.git` (ASCII case-insensitive, so `repo.git` counts) is a bare repository. Anything else is a normal repository, and its worktree is left untouched: export writes objects and refs only, and does not check out files. gitoxide writes the objects. Hooks, smudge/clean filters and Git LFS programs are not run.

### What is exported

Every bookmark becomes `refs/heads/<name>`. When `HEAD` is still unborn, it is pointed at `main` if that bookmark was exported, otherwise at the first exported bookmark. That does not check out files. An existing `HEAD` is left as it is. Repeat `--bookmark NAME` to export a subset. A name Git rejects as a branch (`HEAD`, `foo..bar`, names ending in `.lock`) is skipped with a warning. The working change is included only when a bookmark points at it. tig's root revision is not a commit; a revision whose only parent is the root becomes a Git root commit. Other parents keep their order, with the root omitted when it is one parent among several.

File modes are `100644`, `100755` and `120000`. Existing `Sealed` entries are omitted. Commit author, committer, timestamps, timezone offsets and description are copied. Git stores whole seconds, so a sub-second tig timestamp is truncated toward zero (import stores `seconds * 1000`, and that round-trips). The tig change id is not written into the commit. The same revision always produces the same Git commit id. New repositories use SHA-1. An existing repository keeps its hash algorithm.

`--working-copy` snapshots current edits and exports that change and its ancestry
under the Git branch `working-copy`. It does not create, move or delete native
bookmarks, and cannot be combined with `--bookmark`. It uses the same privacy,
paste and ref-movement checks and destination map as bookmark exports. This is
useful for public build inputs without advancing a development bookmark.

### Privacy

Each revision is classified with its own root `.private` plus the built-in floor, using the same rules and directory aggregation as publish. Private paths are deleted from the Git tree rather than replaced with a seal. A directory whose files are all private disappears, including its name. `.private` itself is exported and must classify as public; a private `.private` is refused. Role-tagged paths are omitted using the same privacy rules.

Before any Git object is written, export refuses when a public file's bytes equal a non-empty private blob anywhere in the selected history. The empty blob is exempt. The error names the public paths. `--declassify PATH` allows those paths, one flag per path, and does not declassify any other path. The default summary reports how many private paths were omitted and does not print their names. `--verbose` prints each omitted path. Descriptions and `.private` may still name a file inside a private directory; export emits publish's metadata warning for those names.

Export does not delete a Git branch when the tig bookmark goes away. It does not redact commit messages or author fields.

Embedded `**` before `/` uses the more private interpretation where Git versions disagree. Export warns with the rule and line when a path hits that edge case; it does not print the matched private path. Older export maps are reclassified under this policy while retaining the last exported refs. A changed projection may require a fresh destination or `--force`; neither removes secret bytes already present in an old Git repository.

### Incremental updates and refs

`.tig/git-export/<hex>` remembers the map. The hex is BLAKE3 of the canonical destination path (UTF-8). The file is a versioned encoding with a BLAKE3 checksum, in the same style as the workspace state file. Before reusing mapped commits, export checks their reachable commits, trees and blobs, including hashes and object types. Missing objects cause the selected history to be rebuilt; corrupt existing objects refuse export without moving refs or local state. Refs are moved only after every object is present.

A branch is updated when the new commit is a fast-forward of the commit tig last exported there, and Git still has that commit. If someone else has committed or moved the branch, export refuses and names the Git commit and the last exported commit. A history rewrite that is not a fast-forward is also refused. `--force` overwrites the ref. Passing `--force` does not relax the paste check or the privacy rules.

Re-exporting unchanged bookmarks writes no new objects and does not move refs. Branch and HEAD changes require their observed previous targets to still match. Tree conversion uses an explicit stack and supports tig's normal depth limit.

### What this does not claim

A repository that was imported from Git and then exported is a public projection, not a byte-for-byte copy of the original Git history, once private paths or seals were removed. `--declassify` publishes the bytes at the named public path; it does not put the private path back. Two machines exporting the same revisions get the same Git commit ids. The map file is local bookkeeping, not a secret.

## Private changes

`tig seal REMOTE BOOKMARK --role GROUP [-r REV]` publishes a new change as an immutable opaque public revision. The revision defaults to `@`. Publish the parent history first. The selected group must have a current epoch, the publisher must be allowed to publish and read it, and role-mode `.private` edits require `EDIT_PRIVATE`.

The skeleton retains the random change ID and mapped public parents. Author, committer, description and predecessors are redacted. Its tree retains the public first-parent baseline and adds an opaque `tig-private-change` marker, so previously public files remain usable before reveal. This filename alone does not authorize opening: the signed publish manifest must associate that exact skeleton with its encrypted capsule and wrapper pack.

A fresh per-change key and independently random salt bind the marker to the privacy-projected revision and its complete content closure. The public capsule ciphertext authenticates the remote, group, epoch, skeleton, change ID, marker and key commitment. The key and salt are wrapped in a small role-epoch pack. This key is separate from the role epoch key and cannot open other changes or ordinary private packs.

The capsule contains the fix's projected tree, metadata and file/chunk closure. `.env` and other paths selected by `.private` remain sealed entries inside that tree. Their contents travel only in ordinary encrypted packs under their own privacy groups, never in the revealable capsule. Exact non-empty private files or chunks copied into revealable content are refused. Role readers fetch and open the same public revision locally; access upgrades may create local successors while preserving its public identity and parent graph.

`tig reveal REMOTE -r REV` is irreversible public disclosure. The current policy owner signs a certificate that binds the remote, skeleton, change ID, capsule, marker, group, epoch, commitment, capsule key and salt. Reveal uploads no plaintext objects or packs: one conditional head commit publishes the certificate. A stale head or mismatched keyring commits nothing. The epoch key and independently private inner content remain undisclosed. A member may carry a valid certificate in a later signed manifest, but cannot authorize a reveal. Ownership transfer re-attests already public certificates under the successor owner; the former root owner cannot reveal new changes.

Version-1 manifests remain byte-identical. Version 2 adds cumulative private-change associations and independently owner-signed reveal certificates to the same canonical `Manifest` encoder. Ordinary publications and access changes carry these fields forward. Fetch persists accepted reveal IDs and refuses a later manifest that omits them.

The CLI persists internal-to-public correspondence and rollback floors after successful sealing. It creates no reserved bookmark or synthetic designation history. Local undo does not undo an external seal or a public reveal; the remote revision and certificate remain public. Opened content is retained locally after revocation.

Children created against an opaque parent retain their original public bytes. Opening applies their delta from the skeleton tree onto the decrypted projection, maps the parent to its local revision, and checks the inverse projection before accepting an access upgrade. Descendants and role-private inner seals continue through the existing fetch correspondence and rebasing path.

Large ciphertext capsules use the ordinary 4 MiB chunked-blob format, so uploads and downloads include their full chunk closure. Ordinary inner private content uses 16 MiB encrypted pack batches. Capsule encryption/decryption and the projected plaintext descriptor still use whole buffers and are limited to 256 MiB; this feature does not claim bounded memory for larger sealed fixes. Ordinary large-file streaming is a separate storage capability.

## Large files and filesystem watching

Files up to and including 4 MiB keep their existing kind-1 blob IDs. Longer
files use a version-1 kind-7 manifest naming ordered 4 MiB blob chunks; only
the last chunk may be shorter. Identical chunks deduplicate. The current
manifest limit is 64 GiB per file.

Snapshots read regular files a chunk at a time, growing the read buffer only
as bytes arrive so small files do not allocate and zero-fill a full chunk.
Checkout and `tig cat` stream
the content; checkout validates the complete chunk closure before modifying
disk files. Missing, mistyped, incorrectly sized or corrupt chunks are errors.
Rehashing identical legacy large blobs preserves their IDs and history.
Whole-buffer library helpers refuse content above 256 MiB; callers use
`tig_core::blob::ContentReader` or `write_content` for larger files. Large-file
diffs report content and size changes without loading the entire file as text.

New chunked private content is encrypted in independent packs capped at 16 MiB. Each
file's manifest and chunk closure travel together. Publish and Git export
include canonical 4 MiB chunk IDs and the complete-content blob ID in the
private-content paste check for both legacy and chunked files. This includes
the final short chunk, without rewriting legacy objects or history. It is
an exact file/chunk comparison, not an arbitrary substring scan. Older publish
caches expand their private and declassified evidence once, on the next successful
publish, without changing revision mappings. Missing historical content refuses
that upgrade; computed whole-blob aliases are recovered from stored chunks.
Git export streams
content directly into the object database. Git import chunks the blob after
gitoxide reads it. Packed Git import still materializes a Git blob and refuses
blobs above 256 MiB from their headers before allocating the body.
Legacy kind-1 storage reads retain their existing whole-object behavior.
Private legacy blobs above 4 MiB travel in isolated version-1 packs, preserving
their object IDs and revision history. Their plaintext limit is 256 MiB;
the decoder also allows the 16-byte authentication tag. Directory and HTTPS
remotes accept older packs up to 512 MiB, fetched one at a time. The server
reserves response memory before reading ciphertext, and download size caps
also apply to growing files and chunked HTTP responses. These compatibility
transfers can use substantially more memory than new chunked content.

`tig watch` runs until interrupted and snapshots delivered native filesystem
events. Ordinary file events select those files and force a rehash. Directory
structure, ignore rules, workspace boundaries, event overflow, backend loss
and uncertain rename endpoints trigger a full rehash. The watcher starts
before the initial scan and restarts before scanning after a delivery gap.
Every 15 seconds it reconciles the full working tree even when no events arrive.
External `describe`, `new` and checkout commands are adopted by reloading their
completed workspace state. A checkout still in progress defers scanning and
keeps dirty hints, so the watcher neither exits on stale state nor overwrites
that operation with its previous baseline.

Dirty hints are saved under the workspace metadata with an OS-held lock and
a generation counter. A scan only consumes hints through the generation it
observed; clearing preserves the counter. Enabling the watcher is recorded in
workspace state, so subsequent commands inspect its hints and rehash when
needed. Commands always retain the authoritative full walk. A normal
workspace that has never enabled watching does not open a hint file.
`tig snapshot --rehash` remains the explicit authoritative rebuild.
