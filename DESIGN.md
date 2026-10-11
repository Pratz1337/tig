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
- Conflicts become objects later (phase 1.5). A rebase never stops halfway.

### Operation log

Every mutation of repo state writes a new `View` plus an `Operation` pointing at it, then moves the single op-head pointer (an atomic file replace on disk, a swap in memory). `undo` writes a new operation whose view equals the parent's view. Nothing is ever destroyed, so `undo` is always available.

### Stores

`trait Store`: `get`, `put`, `has`. Backends:
- `MemoryStore`: agents, tests, the fastest path.
- `DiskStore`: loose objects, lz4-compressed, sharded `objects/ab/cdef…`, written atomically (tmp + rename). Packs come later.

Object storage is plaintext for whoever holds it. Encryption happens only when objects leave the machine.

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

The filesystem working copy (`tig-cli`) is one client: it uses a stat cache (path → size, mtime, id) to find changed files and feeds them into the overlay.

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
- `tig why <path>` prints the effective rule and group.
- **Publishing** builds a public view: every private path is replaced by a sealed entry, and private content is encrypted into one sealed pack per access group and push window (X25519 key wrapping per member, content keys per epoch). The exact rules are in "Crypto and wire rules" below.
- **The leak rule:** if a path was public in an earlier published snapshot and later becomes private, tig refuses to pretend it is hidden. It says the content already leaked and tells you to rotate it.
- Roles, the Discord-style hierarchy, and two-step grants come after simple mode works end to end.

### Crypto and wire rules

These are non-negotiable. Reviewers check every publish/fetch change against them.

1. **A sealed entry never contains an internal ID.** Internal IDs are plain, unsalted content hashes, so a small private file could be guessed from its ID. A sealed entry holds a `SealedId` = BLAKE3 keyed hash under a secret per-entry `SealSalt` (`tig_core::seal`). `SealedId` is its own type, and `TreeEntry::new` refuses `EntryKind::Sealed`. The only way to build a sealed entry is `TreeEntry::sealed(name, SealedId)`, so the type system blocks the mistake.
   - Salt: `salt = keyed_hash(derive_key(SEAL_SALT_KEY, epoch_key), path || kind || target_id)`. It is deterministic, so an unchanged private folder keeps the same sealed ID across publishes and public history stays stable. It is bound to the content, so disclosing one salt on embargo day reveals nothing about other entries or other versions of the same path.
   - Known leak, by design: outsiders can see *that* a sealed entry changed between revisions, never what changed.
2. **Only public-projection IDs and keyed IDs cross the wire.** This rule is broader than "don't send private object IDs". Any internal ID whose hash covers private content can be used to test a guess: the internal tree above `.env`, every internal revision, and every operation and view. So:
   - Publishing produces a **public projection**: public trees (private entries replaced by sealed entries), public revisions whose tree and parents are public IDs and whose predecessors are dropped, and public blobs.
   - Have/want negotiation lists public-projection IDs for public objects, and `WireId = keyed_hash(derive_key(WIRE_ID_KEY, epoch_key), object_id)` for private objects. The server routes by group and never sees a plain private ID.
   - Operations, views, and internal revision and tree IDs never leave the machine. Users share change IDs (random) or public revision IDs.
   - Readers rebuild internal trees locally by opening the sealed entries they hold keys for.
3. **One AEAD: XChaCha20-Poly1305.** Use it everywhere: random nonces for key wrapping, and synthetic nonces for pack objects (`nonce = keyed_hash(derive_key(NONCE_KEY, epoch_key), object_id)[..24]`, an SIV-style construction that keeps dedup within a group and epoch). Its 192-bit nonce makes random nonces safe and leaves a wide margin for synthetic ones, so contributors never have to choose. Associated data binds every ciphertext to `(group, epoch, object kind)`, so ciphertexts cannot be swapped between groups.
4. **Labels are frozen.** Every domain-separation string lives in `tig_core::domain`. They are internal protocol constants, not branding, and they stay as written even if the product is renamed. A golden test pins object IDs.
5. **Every key gets its own subkey.** The epoch key is never used directly. Each purpose (`CONTENT_KEY`, `NONCE_KEY`, `SEAL_SALT_KEY`, `WIRE_ID_KEY`) derives its own subkey with `blake3::derive_key`.
6. **Paste detection** compares keyed IDs of changed public blobs against keyed IDs of private blobs at publish time. The empty blob is exempt, because an empty `.env` matches every empty file.

### Paths

`object::validate_name` enforces a portable-name policy everywhere, including when decoding stored trees. It rejects `\`, `:`, control characters, a trailing `.` or space (Windows silently strips them, so `.env.` would land on disk as `.env`), and anything that aliases `.tig` (any case, or with HFS+-ignorable characters). Some names are only dangerous on some filesystems but exist in real repos, such as `aux.c` in Linux and `A` next to `a`. The filesystem working copy must check those before writing anything: Windows device names, case collisions on case-insensitive volumes, NTFS 8.3 aliases such as `TIG~1`, and never writing through a symlink or reparse-point ancestor.

### Known gaps (tracked, not forgotten)

- **Crash durability:** objects are written by rename but directory entries are not fsynced before the op head moves. The plan is crash recovery over an fsync storm: on load, if the current operation references missing objects, fall back to the newest operation whose objects are complete, and say so. Per-object fsync on snapshot would break the hot-path rule.
- **Huge objects:** `DiskStore` reads a whole loose file into memory. Large files get chunked blobs and streaming in the storage phase. Until then, a corrupt multi-gigabyte file can cost one large allocation.
- **Revision tree validation:** `Transaction::rewrite` accepts an untyped `ObjectId` for the tree, so an API caller can commit a missing object or a blob as the root. Reads then fail. Validating it through the current Store API reloads the root tree on snapshot; choosing a validated tree-ID API or a cheap object-kind lookup needs a decision under the hot-path rule. The regression is pinned as an ignored decision test in `tig-core/tests/review_round2.rs`.
- **Untrusted tree expansion:** a tree DAG in which many entries share one subtree can expand exponentially when walked. Fetch must budget expanded entries before accepting objects from a peer. Depth is already capped at `treeops::MAX_TREE_DEPTH`.
- **Wide directories:** a tree object lists all of a directory's entries, as in git. Editing one file in a directory of N entries re-encodes and rehashes O(N) bytes, and lookup or diff decode the whole directory. Depth-wise cost already follows the changed paths. If benchmarks on real monorepos show this matters, directories get chunked into bounded-size nodes with structural sharing (a prolly or B-tree layout). That is a format change, so it is decided by measurement, not guesswork.
- **Visual spoofing in `.private`:** matching uses NFC plus Unicode case folding. Fullwidth or zero-width look-alikes (`．ｅｎｖ`) are different names and are not treated as `.env`. A publish-time warning for confusable names is a possible later addition.

## Phases

- **Phase 1 (now):** core objects + stores, path index, trees/diff, revisions/changes, op log + undo, in-memory and filesystem workspaces, CLI (`init status diff log show new describe edit undo op-log workspace bookmark cat why`), `.private` rules plus local publish/fetch with sealing in simple mode, benchmarks against git.
- **Phase 2:** git import/export (via gitoxide, MIT/Apache), remotes and a server, roles/hierarchy, conflicts as objects, filesystem watcher, packs.

## Licensing

tig is MIT/Apache-2.0. Never copy git's GPLv2 code. Borrow from gitoxide (MIT/Apache) where useful.
