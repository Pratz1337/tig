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
