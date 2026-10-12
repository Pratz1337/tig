# tig — design and intent

tig is version control built from scratch. It keeps what git got right and fixes four things git gets wrong:

1. **Permissions are all-or-nothing per repo.** tig repos are public by default and private per path (`.private`).
2. **Commits and branches are bookkeeping you do while working.** In tig the working copy *is* a change. It is snapshotted automatically, and every operation can be undone.
3. **Worktrees are expensive bolt-ons.** A tig workspace is `(base revision, overlay)`. Creating one is O(1).
4. **Git assumes a real OS and a POSIX filesystem.** tig is a library first. The filesystem is just one client of the API.

This file is the contract every contributor (human or agent) follows. If code disagrees with it, the code is wrong or this file needs an explicit edit.

## The one rule that beats every other rule

**Nothing may add cost to edit, snapshot, status, diff, log, or checkout.**
Permission checks, `.private` matching, sealing, encryption, and leak scans run only at trust boundaries (publish, fetch, import, rule changes). They are amortized per access group, never per file. Code that puts crypto or rule matching on the hot path gets rejected in review, even if it is correct.

## Taste

- **Small, boring, correct.** Plain data structures, explicit binary encodings, no clever generics. A reader should understand a module in one sitting.
- **No panics on user data.** Corrupt objects, odd paths, and bad rules return `tig_core::Error`. `unwrap()` is only for invariants we hold ourselves, and it gets a comment saying why.
- **Deterministic.** The same inputs give the same object IDs on every machine. No HashMap iteration order leaks into encodings. Timestamps are explicit fields, never read during encoding.
- **The API comes first, then the CLI.** Every CLI command is a thin wrapper over a `tig-core`/`tig-private` function that works with the in-memory store.
- **Honest UX.** If something cannot be undone (a secret already leaked, data already pulled by a revoked member), the tool says so plainly. It never pretends.
- **Tests at the API level** against `MemoryStore`, plus a few CLI end-to-end tests. Property tests for encodings and the path index.

## Architecture

```
crates/
  tig-core     objects, hashing, stores, path index, trees, diff, revisions,
               operation log, repo, workspaces (no filesystem required)
  tig-private  .private rules, roles, keys, sealing, publish/fetch views
  tig-cli      the `tig` binary: thin wrapper; filesystem working copy lives here
```

Dependencies only point downward: cli → private → core.

### Objects (tig-core::object)

All objects are content-addressed by **BLAKE3**: `id = blake3::derive_key("tig object v1", kind_byte || body)`. IDs are 32 bytes and display as lowercase hex.

| Kind | Body |
|---|---|
| `Blob` | raw bytes |
| `Tree` | sorted entries `(name, EntryKind, id)`. Names are non-empty and contain no `/` or NUL. Sort order is plain bytewise on the name (git's export re-sorts). |
| `Revision` | tree, parents, change_id, predecessors, author, timestamp, description |
| `Operation` | parents, view id, timestamp, user, description |
| `View` | workspaces → working revision, bookmarks → revision, heads |

`EntryKind` = `File`, `Executable`, `Symlink`, `Tree`, `Sealed`. A `Sealed` entry stands in for a private subtree in public views (see tig-private).

Encodings are hand-written, versioned, and varint-based (`tig-core::encode`). They are stable: once an encoding ships, changing it requires a new version byte.

### Changes, not commits

- A **change** has a stable random `ChangeId` (16 bytes). Each time its content changes, a new `Revision` is written with the same change_id, and the old revision is listed in `predecessors`.
- The working copy is always a revision (the workspace's "working revision"). Every command first snapshots the working copy (jj-style). There is no staging area.
- `tig new` starts a fresh empty change on top of the current one. `tig describe` sets the message. Branches are optional **bookmarks**.
- Conflicts become objects later (phase 1.5). A rebase never stops halfway. Until then:
  - **Explicit actions** that would conflict (abandon, a merge in `new`) are refused, and nothing changes.
  - **Automatic rebases of descendants** never fail the operation. Every command snapshots first, so a failure there would strand the user. A descendant whose rebase would conflict stays on the previous version of its parent, which stays visible (`log` marks it "(previous version)"), and the command prints a warning naming the paths. Nothing is lost, and nothing changes silently.
- The root revision can never be a working change: it can't be rewritten, so edits on it could never be recorded. `tig new root` starts a change on top of it.

### Operation log

Every mutation of repo state writes a new `View` plus an `Operation` pointing at it, then moves the single op-head pointer (an atomic file replace on disk, a swap in memory). `undo` writes a new operation whose view equals the parent's view. Nothing is ever destroyed, so `undo` is always available.

**Two kinds of head update.** User actions (describe, new, undo, publish, and so on) move the durable `op_head`, which is synced. Working-copy snapshots only record what is already on disk, so they write the unsynced `op_head.light`: `(label, base, recent light heads, checksum)`. It counts only while its checksum holds and `base` is still the durable head. A crash can lose it, but the next command simply snapshots the same files again; a workspace state left ahead of the repo re-scans from disk. git does not sync its index for the same reason. This saves an fsync on every edit.

### Stores

`trait Store`: `get`, `put`, `has`. Backends:
- `MemoryStore`: agents, tests, the fastest path.
- `DiskStore`: loose objects, lz4-compressed, sharded `objects/ab/cdef…`, written atomically (tmp + rename).
- `JournalStore` (what a repo on disk uses): small objects (≤ 64 KiB) are appended to one `store/journal` file, larger ones go to `DiskStore`. On Windows the antivirus scans a file the first time it is opened after a change (about 6 ms each); a snapshot used to create about seven new files, and the next command paid for each. The journal makes that one file. It is the frozen-base-plus-ledger idea applied to storage: the journal is the ledger over loose objects, and it is compacted into them once it passes 4 MB, before the scan cost starts to grow with its size. A record counts only if its body hashes to its ID, so a torn tail is ignored. Appends take an OS file lock, and one handle stays open for the store's lifetime. Packs for transfer come later.

Object storage is plaintext for whoever holds it. Encryption happens only when objects leave the machine.
`Store::kind` is a cheap object type check that need not verify the body hash; `get_raw` reads and verifies the body.

### Path index (from HRT-LI, the parts that matter)

The working-copy index is a **frozen sorted snapshot plus a small mutation ledger**:
- Edits only touch the ledger. The frozen base is never rewritten on the hot path.
- Inverse edits cancel (add then remove the same path leaves the ledger as it was).
- Once the ledger passes a threshold, it is consolidated into a new frozen snapshot.
- Directory listings and counts are range queries over the sorted order.
- The learned rank model from HRT-LI is **deferred**. A sorted array plus binary search is the baseline, and it gets replaced only if a benchmark proves path lookup is a bottleneck.
- Rank and range counts never cross a trust boundary. Public views get their own index, in which a sealed folder counts as one entry.

### Workspaces

A workspace is `(working revision, overlay)`. The overlay maps path → `Some(file)`, `None` (deleted), or an internal `Some(tree)` graft that fully replaces a deleted or replaced directory. Edits under a graft update that subtree; reads and listings resolve through it without bringing back base siblings. Restoring the base subtree ID cancels the graft. The public workspace edit API only accepts files and deletions. A snapshot folds the overlay into new trees, reusing every unchanged subtree by ID, so the cost is proportional to the changed paths. Many workspaces share one store, so ten agents cost one repo plus their deltas.

The filesystem working copy (`tig-cli`) is one client: it uses a stat cache (path → size, mtime, id) to find changed files and feeds them into the overlay. Its walk (`walk.rs`) lists each directory with one `read_dir` (on Windows the listing already carries sizes and times, like git's `fscache`), spreads directories over a thread pool (like git's `preloadIndex`), and decides each file on the worker threads. A file the stat cache cannot vouch for is read and stored on the worker that found it, so the read (on Windows, the antivirus scan of a just-modified file) overlaps the rest of the walk. When every cached path was seen, the deletion pass is skipped. A small hint file, `hot`, lists files whose content recent snapshots recorded; when a workspace opens, background threads open those files before the journal and stat cache load, so a re-edited file's antivirus scan is already done when the walk reaches it (`prefetch.rs`; nothing is read and nothing depends on the result). Status always records the edit, so unlike `git status` it must read a changed file; this overlap is how it stays ahead anyway. Snapshot-only state saves are not fsynced (the snapshot's op head is not either); checkouts still fsync. `TIG_TRACE_PERF=1` prints a per-phase timing breakdown of any command, like `GIT_TRACE_PERFORMANCE`.

Stat scans reuse the frozen cache and update only changed rows. An identical revision, tree and stat cache needs no state-file rewrite; changes to timestamps or racy flags still get saved. Checking out an identical tree only records the revision move, without file-write preflight. Checkouts that change files retain the complete preflight and per-path safety checks.

### Privacy (tig-private)

The `.private` file sits at the repo root and uses `.gitignore` syntax, with optional `@role` tags:

```
.env*
*.pem
*.key
internal/billing/**   @billing
```

- A line without a role belongs to the built-in group `private` (simple mode). Last match wins. `!` negates. Matching is case-insensitive and Unicode-NFC-normalized for safety.
- Two deliberate differences from gitignore, both pinned by tests in `tig-private/tests/review_round2.rs`:
  - **A negation can re-include a file inside a private folder.** With `secrets/` then `!secrets/README.md`, the README is public. Git never re-includes files under an excluded directory. Publishing one file out of a private folder is a feature here, and publish asks for confirmation the first time a negation makes something public.
  - **Wildcards count characters, not bytes.** `?` matches `é`, and `[À-Ö]` is a range of characters. Git's wildmatch counts bytes, so `!?.key` would not reach `é.key` there. Characters are what people mean when they write these patterns.
- Leading whitespace in a pattern must be escaped (`\ name`). An unescaped leading space is an error rather than a silent part of the name. Unescaped trailing spaces are dropped, as in git.
- New repos ship this default `.private` (`tig_private::rules::DEFAULT_PRIVATE`): `.env*` except `.env.example`, `.env.sample` and `.env.template`, plus `*.pem`, `*.key`, `*.p12`, `*.pfx`, and the SSH key names `id_rsa`, `id_dsa`, `id_ecdsa`, `id_ed25519`. The example files stay public on purpose: projects commit them for every contributor, and making them private by default would teach people to fight the tool on day one.
- **Built-in floor.** The default rules always apply *underneath* the repo's `.private`, even if that file is deleted or rewritten. `.private` can add private paths. It can make a default-private path public only with an explicit negation (`!.env`), which publish asks to confirm the first time. So forgetting a line, or deleting the file, can never publish a `.env`. `tig init` also writes the defaults into `.private`, so people can see them.
- `tig why <path>` prints the effective rule and group, including when the built-in floor decided it.
- **Metadata exception.** `.private` itself, change descriptions, author and committer fields, and bookmark names are public. If you write the name of a file that lives inside a sealed folder into one of them, that name is public. Publish warns when `.private` or a description mentions such a name, but does not refuse: these fields have to be public for outsiders to understand and build the repo.
- **Declassification.** Every non-empty blob ever sealed to a remote is remembered. Publishing the same bytes in a public file — after a rename, a delete, or within one unpublished batch — is refused unless that path is passed with `--declassify <path>`. Confirming a negation makes a path public from now on; it never declassifies bytes that were sealed.
- **Publishing** builds a public view: every private path is replaced by a sealed entry, and private content is encrypted into one sealed pack per access group and push window (X25519 key wrapping per member, content keys per epoch). The exact rules are in "Crypto and wire rules" below.
- **The leak rule:** if a path was public in an earlier published snapshot and later becomes private, tig refuses to pretend it is hidden. It says the content already leaked and tells you to rotate it.
- Roles, the Discord-style hierarchy, and two-step grants come after simple mode works end to end.

### Crypto and wire rules

These are non-negotiable. Reviewers check every publish/fetch change against them.

1. **A sealed entry never contains an internal ID.** Internal IDs are plain, unsalted content hashes, so a small private file could be guessed from its ID. A sealed entry holds a `SealedId` = BLAKE3 keyed hash under a secret per-entry `SealSalt` (`tig_core::seal`). `SealedId` is its own type, and `TreeEntry::new` refuses `EntryKind::Sealed`. The only way to build a sealed entry is `TreeEntry::sealed(name, SealedId)`, so the type system blocks the mistake.
   - Salt: `salt = keyed_hash(derive_key(SEAL_SALT_KEY, epoch_material), path_byte_len_u64_le || path || kind || target_id)`, where `epoch_material = epoch_key_bytes || remote_byte_len_u64_le || remote_16 || group_byte_len_u64_le || group_utf8 || epoch_u64_le`. It is deterministic, so an unchanged private folder keeps the same sealed ID across publishes in that group and epoch and public history stays stable. It is bound to the content, so disclosing one salt on embargo day reveals nothing about other entries or other versions of the same path.
   - Known leak, by design: outsiders can see *that* a sealed entry changed between revisions, never what changed.
2. **Only public-projection IDs and keyed IDs cross the wire.** This rule is broader than "don't send private object IDs". Any internal ID whose hash covers private content can be used to test a guess: the internal tree above `.env`, every internal revision, and every operation and view. So:
   - Publishing produces a **public projection**: public trees (private entries replaced by sealed entries), public revisions whose tree and parents are public IDs and whose predecessors are dropped, and public blobs.
   - Have/want negotiation lists public-projection IDs for public objects, and `WireId = keyed_hash(derive_key(WIRE_ID_KEY, epoch_material), object_id)` for private objects. The server routes by remote and group and never sees a plain private ID.
   - Operations, views, and internal revision and tree IDs never leave the machine. Users share change IDs (random) or public revision IDs.
   - Readers rebuild internal trees locally by opening the sealed entries they hold keys for.
3. **One AEAD: XChaCha20-Poly1305.** Use it everywhere: random nonces for key wrapping, and synthetic nonces for pack objects (`nonce = keyed_hash(derive_key(NONCE_KEY, epoch_material), kind || object_id)[..24]`, a deterministic construction that keeps dedup within a group and epoch). Its 192-bit nonce makes random nonces safe and leaves a wide margin for synthetic ones, so contributors never have to choose. Associated data binds every object ciphertext to `(remote, group, epoch, object kind, object_id)`, so ciphertexts cannot be swapped between remotes, groups, or epochs. This is not misuse-resistant SIV: `encrypt_object` is fallible and checks `hash_object(kind, body) == object_id` before encryption; `decrypt_object` checks the hash after authenticated decryption and refuses a mismatch. Each `EpochKey` carries its immutable `GroupEpoch`, and every subkey includes that context, so even accidentally restoring the same secret bytes in two contexts gives unrelated subkeys. Different associated data alone would not make key/nonce reuse safe. Generate fresh random epoch secrets for each group and epoch.
4. **Labels are frozen.** Every domain-separation string lives in `tig_core::domain`. They are internal protocol constants, not branding, and they stay as written even if the product is renamed. Golden tests pin object IDs, context-bound crypto outputs, fingerprints, commitments and signed-grant encoding. Context binding changes the pre-repository subkey derivation; existing labels' bytes are unchanged. The labels added for identity, grants and packs are `IDENTITY_FINGERPRINT`, `EPOCH_KEY_COMMITMENT`, `GRANT_SIGNATURE`, `PACK_INDEX_AAD` and `KEYRING_HEAD_SIGNATURE`.
5. **Every key gets its own subkey.** The epoch key is never used directly. Each purpose (`CONTENT_KEY`, `NONCE_KEY`, `SEAL_SALT_KEY`, `WIRE_ID_KEY`) derives its own subkey with `blake3::derive_key(label, epoch_material)`. Epoch secrets, seal salts, exported identity secrets, derived subkeys, KDF material and decrypted plaintext buffers are zeroized on drop; `SealSalt` and `EpochKey` are not cloneable. Identity's X25519 and Ed25519 secrets are also zeroized by their key types. Zeroization limits secret lifetime; it is not a guarantee against compiler copies or a compromised process.
6. **Paste detection** compares keyed IDs of changed public blobs against keyed IDs of private blobs at publish time. The empty blob is exempt, because an empty `.env` matches every empty file.

### Publish and fetch (phase 1: simple mode, local directory remotes)

**Sealing plan.** At publish, the tree is classified with the `.private` rules *of the revision being published*. A directory is sealed as **one** entry when every file under it is private to the same readers. Otherwise tig recurses, and private files are sealed individually. So a fully private `secrets/` shows up only as `secrets` → sealed, while a folder with one re-included file reveals the names of its sealed siblings (honest, and documented in `tig why`). `.private` itself must classify as public; publish refuses otherwise.

A present `.private` must be a UTF-8 regular file (an executable file is also accepted). Symlinks, directories, sealed entries, invalid UTF-8 and invalid rules refuse projection; only an absent file means empty rules. Existing sealed entries are opaque and neutral for directory aggregation: they add no readers and do not make a directory mixed. A folder whose other files are uniformly private seals whole, preserving foreign seals inside the hidden private subtree. A folder containing only foreign seals, or foreign seals and public files, stays public. Seals absorbed into a private folder are not reported as public files.

**Public projection.** Each published revision gets a public twin: same change ID, author, committer and description, a public tree (private entries replaced by `TreeEntry::sealed`), public parents, and no predecessors. The root revision projects to itself. A local map (internal revision → public revision, per remote) makes republishing incremental.

Fetch reopens previously fetched seals when access is granted later and preserves content already opened locally. It budgets expanded tree entries across the fetch, including decrypted subtrees, and refuses missing file targets before moving bookmarks. Fetch, publish, grant and revoke share the same pinned owner and highest keyring counter. Publish also checks the remote's reachable public history for paths already exposed by another publisher or branch.

**Sealed packs.** Objects reachable under a sealed entry go into one pack per group, epoch and publish:
- an **index**, encrypted with a random nonce under the content subkey: `(wire_id, kind, object_id)` for every object, plus `(sealed_id, path, kind, target_id)` for every sealed entry;
- the **objects**, as `(wire_id, ciphertext)`, encrypted with `EpochKey::encrypt_object`.

The file is magic `TIGP`, version 1, the remote id, a length-prefixed group, the epoch, the 24-byte index nonce, the length-prefixed index ciphertext, then each object as `wire_id || length-prefixed ciphertext`. Index associated data is `PACK_INDEX_AAD || context || pack header`, where `context` is the remote, group and epoch encoding from epoch material (without the epoch key bytes) and the pack header is every byte in front of the index ciphertext. The server sees remote, group, epoch, wire IDs and sizes, never plain IDs or names. Readers decrypt the index, then each object with `decrypt_object` (which verifies `hash_object(kind, body) == id`), verify each sealed ID with the derived salt, and rebuild internal trees by substituting sealed entries. Objects already sent for that group and epoch (tracked by wire ID) are not sent again.

**Keyring.** Phase 1 has one group, `private`, and only the owner may grant. Every identity has independent X25519 encryption and Ed25519 signing keys; `PublicIdentity` contains both public keys. Local identity storage is 64 bytes: X25519 secret followed by Ed25519 seed. The owner's epoch keys live in the owner's local keystore with their group and epoch; the owner never takes its own epoch keys from a remote. The remote stores the owner's public identity and per-epoch owner-signed `Grant`s for members. Members pin the owner's signing key on first fetch (TOFU with the identity fingerprint shown), or verify it out of band; subsequent fetches use that local pin, never a trust key supplied by a grant. The display fingerprint is the first 16 hex characters of `derive_key(IDENTITY_FINGERPRINT, encryption_public_key || signing_public_key)`.

A grant contains `(GroupEpoch, recipient PublicIdentity, WrappedKey, commitment, granter signing public key, Ed25519 signature)`. The commitment is `derive_key(EPOCH_KEY_COMMITMENT, epoch_material)`. The signed bytes are `GRANT_SIGNATURE_utf8 || remote_byte_len_u64_le || remote_16 || group_byte_len_u64_le || group_utf8 || epoch_u64_le || recipient_encryption_32 || recipient_signing_32 || ephemeral_32 || nonce_24 || ciphertext_byte_len_u64_le || ciphertext || commitment_32 || granter_signing_32`; the signature is 64 bytes. `open_grant` checks the granter against the pinned owner signing key, verifies the Ed25519 signature strictly, matches both recipient keys to the local identity, unwraps with the signed context, then checks the commitment in constant time. Any failure refuses the grant. Revoking starts a new random epoch key, granted to remaining members; old packs stay under old epochs, because their data already left.

Without the existing epoch key a server cannot grant access to existing ciphertext. Anonymous X25519 wrapping still authenticates no sender: a server can create a new key it knows and wrap it to any public recipient. Accepting that key for future publishing would expose future private content. Owner-local key provenance and owner-signed grants checked against a pinned key prevent that substitution after the trust anchor is established. TOFU cannot detect an attacker on the first fetch, and signatures alone do not detect rollback to an old valid owner grant.

**Required when publish and fetch are built (decided):**
- **Repository binding.** `tig init` creates a random 16-byte repository ID. A remote uses that id, or a fresh 16-byte id created at its first publish. It is `GroupEpoch.remote`. Length-prefixed (`remote_byte_len_u64_le || remote_16`), it goes into epoch material, every AEAD associated-data string, the grant signature, the epoch-key commitment and the keyring head, so a grant or ciphertext from one remote is useless in another that shares an owner identity.
- **Rollback protection.** The keyring carries an owner-signed head: `(repository ID, monotonic counter, current epoch per group)`, signed under `KEYRING_HEAD_SIGNATURE`. Members and the owner store the highest counter they have seen and refuse an older head. Without that, a server could hide a revocation by serving the previous epoch, which a removed member still holds. Publish always encrypts under the epoch named by the newest verified head.
- **Signed publish manifest.** Every publish ends by writing `manifest`, signed under `PUBLISH_MANIFEST_SIGNATURE` by the publisher: `(repository ID, sequence, publisher signing key, refs, packs)`. `packs` is cumulative: pack ID (BLAKE3 of the pack bytes) → group, epoch, and the sealed IDs whose records the pack carries. The signer must be the keyring owner or hold a grant for the current epoch, checked against a keyring already verified with the pin and counter. Fetch takes refs only from the manifest (the plain `refs` file is a convenience copy and is never trusted). Publish and fetch store the highest sequence they have seen and refuse a lower one, and a publisher that has seen a manifest refuses a remote without one. A member who holds an epoch must find every pack the manifest lists for it, carrying the listed records; otherwise fetch fails with `WithheldPack`. Unopened seals with no listed pack in an epoch the reader holds are foreign seals and stay sealed, so outsiders and foreign seals work as before. Revoke re-signs the current manifest as the owner (against the old keyring) before writing the new head, so a manifest last signed by the removed member never becomes unverifiable.

**Publish refuses, naming the paths, when:**
1. a path that was public in any earlier publish to this remote is now private: it already leaked, so rotate it. This is overridable with an explicit acknowledgment that still seals from now on.
2. a public file's content equals a non-empty private file's content (paste detection);
3. a negation makes a path public that was not public before. This needs an explicit confirmation the first time.
4. the rules name roles (phase 2) or `.private` would be private.

**Remote layout (a plain directory).** `objects/` (a DiskStore of public objects only), `packs/<group>/<epoch>/<pack-id>.pack`, `keyring`, `manifest` (signed refs and pack list), `refs` (unsigned copy of the bookmarks). It is dumb storage: no server-side decryption, ever.

### Paths

`object::validate_name` enforces a portable-name policy everywhere, including when decoding stored trees. It rejects `\`, `:`, control characters, a trailing `.` or space (Windows silently strips them, so `.env.` would land on disk as `.env`), and anything that aliases `.tig` (any case, or with HFS+-ignorable characters). Some names are only dangerous on some filesystems but exist in real repos, such as `aux.c` in Linux and `A` next to `a`. The filesystem working copy must check those before writing anything: Windows device names, case collisions on case-insensitive volumes, NTFS 8.3 aliases such as `TIG~1`, and never writing through a symlink or reparse-point ancestor.

### Known gaps (tracked, not forgotten)

- **Crash durability:** objects are written by rename but directory entries are not fsynced before the op head moves. Recovery avoids per-object fsync on snapshot, which would break the hot-path rule. The synced, atomically replaced `op_head` record keeps its current ID on the first line and up to 32 recent prior heads on subsequent lines; legacy single-ID records remain readable. Missing or corrupt operation/view metadata triggers recovery on load. `tig op recover` explicitly checks all revision, tree and blob objects reachable from the current view, including visible revision parents, then falls back to the newest complete candidate from recent heads and readable operation ancestry. Sealed IDs are opaque and need no object; predecessor and older operation history are not part of view completeness. Recovery checks hashes and object kinds, reports the restored operation, and preserves files on disk. After fallback the opened workspace discards its stat cache and the next snapshot reads disk edits against the recovered view, including tracked ignored files. Healthy integrity checks retain workspace state. Other workspaces keep their stale baselines and require an explicit stale update; if that baseline is itself missing, they fail safely. A lost or malformed `op_head`, exhausted candidates, or a crash between fallback and cache invalidation can still require manual repair. Tests inject missing/corrupt objects; hardware power-loss durability is not established. Working-copy state has a BLAKE3 checksum; older state versions force a full rescan. A completed snapshot whose state save failed recovers automatically only across one content rewrite with matching change, parents and description, after checking the disk against the resulting tree. Other stale moves require `tig workspace update-stale`, which saves differing local edits as a separate change based on the recorded revision before checking out the current working revision.
- **Stat-cache blind spot (accepted, as in git):** an edit that keeps a file's size and restores its old mtime is not noticed by the fast path. Re-reading every file on every command would break the hot-path rule. Mitigations: change-time is compared too where the OS exposes it (Unix ctime), and `tig snapshot --rehash` re-reads everything.
- **NTFS alternate data streams (accepted, as in git):** blobs hold a file's main stream only, so checkout replaces a file without keeping its alternate streams.
- **Tampered `.tig` store:** `DiskStore` follows junctions or symlinks planted inside `.tig/store` shard directories. `.tig` is trusted local metadata (opening a workspace already refuses redirected metadata directories), so this needs local tampering first. Hardening the store's own writes is deferred.
- **Huge objects:** `DiskStore` reads a whole loose file into memory. Large files get chunked blobs and streaming in the storage phase. Until then, a corrupt multi-gigabyte file can cost one large allocation.
- **Wide directories:** a tree object lists all of a directory's entries, as in git. Editing one file in a directory of N entries re-encodes and rehashes O(N) bytes, and lookup or diff decode the whole directory. Depth-wise cost already follows the changed paths. If benchmarks on real monorepos show this matters, directories get chunked into bounded-size nodes with structural sharing (a prolly or B-tree layout). That is a format change, so it is decided by measurement, not guesswork.
- **Concurrent publishers on a directory remote:** the remote has no compare-and-swap, so two publishers racing can each write a manifest and the last one wins, dropping the other's ref update and pack listing (the pack file itself stays). The loser's next publish restores neither automatically; it republishes its own revisions. A network remote will make the manifest write conditional on the sequence it read.
- **Server-side denial:** a server can still refuse to serve anything, or serve nothing new to a fresh fetcher who has seen no manifest yet (TOFU, like the owner pin). The manifest turns silent omission into an error only for readers that have seen a newer sequence or hold the withheld epoch.
- **Visual spoofing in `.private`:** matching uses NFC plus Unicode case folding. Fullwidth or zero-width look-alikes (`．ｅｎｖ`) are different names and are not treated as `.env`. A publish-time warning for confusable names is a possible later addition.

## Git import

`tig import-git <path>` imports all commits reachable from Git refs and HEAD via gitoxide, preserving author, committer, message, timestamps and ordered parents. Branches become bookmarks; the first import starts a working change on Git HEAD. Subsequent imports preserve local working-copy edits. Submodules and non-portable path entries are skipped with a per-path warning; shallow history and invalid UTF-8 metadata/rules are refused rather than silently changed.

Imports classify each revision with its own `.private` plus the built-in floor. Matching paths, including ones subsequently deleted, are reported as already exposed in Git history and seed first-publish leak evidence. `--strip-private` is for never-public Git repositories: the union of paths private in any reachable commit is removed from every imported revision before their blobs are stored. An incremental strip import that would retroactively change earlier imported revisions is refused and requires a fresh destination. It does not redact public metadata or detect unclassified copies of a secret.

ChangeIds are derived deterministically from Git commit IDs under a random local import secret saved in `.tig/git-import` before use. The frozen `GIT_IMPORT_CHANGE_ID` label derives that subkey; its keyed hash covers the strip flag, Git ID byte length and Git ID bytes, taking the first 16 output bytes. Re-import with the same secret and mode is idempotent; independent destination secrets give different identities. The secret prevents importing a private Git hash as an unsalted public guessing oracle. Changing strip mode requires a separate destination. Object encodings and ordinary hot paths do not change. See `IMPORT_GIT.md` for the complete behavior and `bench/IMPORT.md` for measured bulk-storage costs.

## Phases

- **Phase 1 (now):** core objects + stores, path index, trees/diff, revisions/changes, op log + undo, in-memory and filesystem workspaces, CLI (`init status diff log show new describe edit undo op-log workspace bookmark cat why`), `.private` rules plus local publish/fetch with sealing in simple mode, benchmarks against git.
- **Phase 2:** git import is implemented (via gitoxide, MIT/Apache); git export, network remotes and a server, roles/hierarchy, conflicts as objects, filesystem watcher and storage packs remain.

## Licensing

tig is MIT/Apache-2.0. Never copy git's GPLv2 code. Borrow from gitoxide (MIT/Apache) where useful.
