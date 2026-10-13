# Local conflicts

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
