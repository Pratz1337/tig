# Exporting to Git

`tig export-git <path>` writes bookmarks into a Git repository so the history can be pushed to a Git host. Git has no sealed entries. An export is a public channel: private content never becomes a Git object.

```
tig -R repo export-git ../public.git
tig -R repo export-git ../public-repo --bookmark main --verbose
tig -R repo export-git ../public-repo --declassify notes.txt --force
```

`<path>` is created when it is missing or an empty directory. An existing Git repository is updated. Any other path is refused. A final path component ending in `.git` (ASCII case-insensitive, so `repo.git` counts) is a bare repository. Anything else is a normal repository, and its worktree is left untouched: export writes objects and refs only, and does not check out files. gitoxide writes the objects. Hooks, smudge/clean filters and Git LFS programs are not run.

## What is exported

Every bookmark becomes `refs/heads/<name>`. When `HEAD` is still unborn, it is pointed at `main` if that bookmark was exported, otherwise at the first exported bookmark. That does not check out files. An existing `HEAD` is left as it is. Repeat `--bookmark NAME` to export a subset. A name Git rejects as a branch (`HEAD`, `foo..bar`, names ending in `.lock`) is skipped with a warning. The working change is included only when a bookmark points at it. tig's root revision is not a commit; a revision whose only parent is the root becomes a Git root commit. Other parents keep their order, with the root omitted when it is one parent among several.

File modes are `100644`, `100755` and `120000`. Existing `Sealed` entries are omitted. Commit author, committer, timestamps, timezone offsets and description are copied. Git stores whole seconds, so a sub-second tig timestamp is truncated toward zero (import stores `seconds * 1000`, and that round-trips). The tig change id is not written into the commit. The same revision always produces the same Git commit id. New repositories use SHA-1. An existing repository keeps its hash algorithm.

## Privacy

Each revision is classified with its own root `.private` plus the built-in floor, using the same rules and directory aggregation as publish. Private paths are deleted from the Git tree rather than replaced with a seal. A directory whose files are all private disappears, including its name. `.private` itself is exported and must classify as public; a private `.private` is refused. Simple mode only: rules that name a role are refused.

Before any Git object is written, export refuses when a public file's bytes equal a non-empty private blob anywhere in the selected history. The empty blob is exempt. The error names the public paths. `--declassify PATH` allows those paths, one flag per path, and does not declassify any other path. The default summary reports how many private paths were omitted and does not print their names. `--verbose` prints each omitted path. Descriptions and `.private` may still name a file inside a private directory; export emits publish's metadata warning for those names.

Export does not delete a Git branch when the tig bookmark goes away. It does not redact commit messages or author fields.

Embedded `**` before `/` uses the more private interpretation where Git versions disagree. Export warns with the rule and line when a path hits that edge case; it does not print the matched private path. Older export maps are reclassified under this policy while retaining the last exported refs. A changed projection may require a fresh destination or `--force`; neither removes secret bytes already present in an old Git repository.

## Incremental updates and refs

`.tig/git-export/<hex>` remembers the map. The hex is BLAKE3 of the canonical destination path (UTF-8). The file is a versioned encoding with a BLAKE3 checksum, in the same style as the workspace state file. Before reusing mapped commits, export checks their reachable commits, trees and blobs, including hashes and object types. Missing objects cause the selected history to be rebuilt; corrupt existing objects refuse export without moving refs or local state. Refs are moved only after every object is present.

A branch is updated when the new commit is a fast-forward of the commit tig last exported there, and Git still has that commit. If someone else has committed or moved the branch, export refuses and names the Git commit and the last exported commit. A history rewrite that is not a fast-forward is also refused. `--force` overwrites the ref. Passing `--force` does not relax the paste check or the privacy rules.

Re-exporting unchanged bookmarks writes no new objects and does not move refs. Branch and HEAD changes require their observed previous targets to still match. Tree conversion uses an explicit stack and supports tig's normal depth limit.

## What this does not claim

A repository that was imported from Git and then exported is a public projection, not a byte-for-byte copy of the original Git history, once private paths or seals were removed. `--declassify` publishes the bytes at the named public path; it does not put the private path back. Two machines exporting the same revisions get the same Git commit ids. The map file is local bookkeeping, not a secret.

Validation is `cargo test --workspace` and `cargo clippy --workspace --all-targets -- -D warnings` on stable `x86_64-pc-windows-gnu`.
