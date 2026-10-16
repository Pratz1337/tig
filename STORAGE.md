# Large files and filesystem watching

Files up to and including 4 MiB keep their existing kind-1 blob IDs. Longer
files use a version-1 kind-7 manifest naming ordered 4 MiB blob chunks; only
the last chunk may be shorter. Identical chunks deduplicate. The current
manifest limit is 64 GiB per file.

Snapshots read regular files a chunk at a time. Checkout and `tig cat` stream
the content; checkout validates the complete chunk closure before modifying
disk files. Missing, mistyped, incorrectly sized or corrupt chunks are errors.
Rehashing identical legacy large blobs preserves their IDs and history.
Whole-buffer library helpers refuse content above 256 MiB; callers use
`tig_core::blob::ContentReader` or `write_content` for larger files. Large-file
diffs report content and size changes without loading the entire file as text.

Private content is encrypted in independent packs capped at 16 MiB. Each
file's manifest and chunk closure travel together. Publish and Git export
include chunk IDs in the private-content paste check. Git export streams
content directly into the object database. Git import chunks the blob after
gitoxide reads it. Packed Git import still materializes a Git blob and refuses
blobs above 256 MiB from their headers before allocating the body.
Legacy kind-1 storage reads also retain their existing whole-object behavior.
A legacy private blob larger than 16 MiB cannot be freshly uploaded in the
new bounded pack path, and fetching an older pack larger than 16 MiB is
refused before allocation. Such history needs a separate migration or legacy
transport solution; local rehash deliberately preserves its old IDs.

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
