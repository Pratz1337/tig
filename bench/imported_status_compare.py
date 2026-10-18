"""Compare status on a real Git tree, retaining tracked files matched by ignores.

SOURCE is a local clone; BASELINE predates the tracked-ignore fix. A temporary
root commit preserves its exact HEAD tree
without timing history import. No source files are changed or copied into TIG's
project. Export TIG's public master before measuring the current bin/ executable.
"""

import argparse
import hashlib
import json
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
import trace_status
from compare import ENV, ROOT, run


def call(cwd, *args, data=None):
    result = subprocess.run([str(arg) for arg in args], cwd=cwd, env=ENV, input=data, capture_output=True, check=True)
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("--runs", type=int, default=15)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    source = args.source.resolve()
    current = ROOT / "bin" / ("tig.exe" if sys.platform == "win32" else "tig")
    binaries = {"baseline": args.baseline.resolve(), "current": current}
    commit = call(source, "git", "rev-parse", "HEAD").decode().strip()
    tree = call(source, "git", "rev-parse", f"{commit}^{{tree}}").decode().strip()
    entries = call(source, "git", "ls-tree", "-rz", commit).split(b"\0")[:-1]
    modes = {row.split(b"\t", 1)[1]: row.split(b" ", 1)[0] for row in entries}
    assert set(modes.values()) <= {b"100644", b"100755", b"120000"}, "fixture contains unsupported entries"
    samples = {name: {mode: [] for mode in ("clean", "edited", "ignored edit")} for name in ("git", *binaries)}
    with tempfile.TemporaryDirectory(prefix="tig-imported-status-") as tmp:
        base = Path(tmp)
        bare = base / "snapshot.git"
        call(base, "git", "init", "--bare", "-q", "-b", "main", bare)
        objects = call(source, "git", "rev-parse", "--path-format=absolute", "--git-path", "objects").decode().strip()
        (bare / "objects/info/alternates").write_text(objects.replace("\\", "/") + "\n", encoding="utf-8", newline="\n")
        flat = call(base, "git", f"--git-dir={bare}", "commit-tree", tree, "-m", "Benchmark snapshot").decode().strip()
        call(base, "git", f"--git-dir={bare}", "update-ref", "refs/heads/main", flat)
        root = base / "work"
        imported = subprocess.run([str(current), "-R", str(root), "import-git", str(bare)], env=ENV, capture_output=True, check=True)
        assert b"warning:" not in imported.stderr, imported.stderr.decode(errors="replace")
        call(root, current, "edit", "@-")
        records = call(root, current, "status", "-z").split(b"\0")[:-1]
        assert {row[2:] for row in records} == set(modes), "TIG did not retain the complete source tree"
        call(root, current, "new", "-m", "benchmark base")
        symlinks = [name for name, mode in modes.items() if mode == b"120000"]
        actual_links = sum((root / name.decode()).is_symlink() for name in symlinks)
        assert actual_links in (0, len(symlinks)), "mixed symlinks and stand-ins cannot share one Git setting"
        call(root, "git", "init", "-q", "-b", "main")
        (root / ".git/objects/info/alternates").write_text((bare / "objects").as_posix() + "\n", encoding="utf-8", newline="\n")
        (root / ".git/info/exclude").write_text("/.tig/\n", encoding="utf-8", newline="\n")
        call(root, "git", "config", "core.autocrlf", "false")
        call(root, "git", "config", "core.filemode", "false" if sys.platform == "win32" else "true")
        call(root, "git", "config", "core.symlinks", "true" if actual_links else "false")
        call(root, "git", "update-ref", "refs/heads/main", flat)
        call(root, "git", "read-tree", "HEAD")
        assert call(root, "git", "status", "--porcelain") == b"", "Git sees a different materialized tree"
        ignored = subprocess.run(["git", "check-ignore", "--no-index", "-z", "--stdin"], cwd=root, env=ENV,
                                 input=b"\0".join(sorted(modes)) + b"\0", capture_output=True)
        assert ignored.returncode in (0, 1)
        ignored_paths = ignored.stdout.split(b"\0")[:-1]
        ignored_file = next(name for name in sorted(ignored_paths) if modes[name] != b"120000").decode()
        assert b"README.md" in modes
        time.sleep(2.1)
        for binary in binaries.values():
            assert call(root, binary, "status", "--short") == b""
        run(["git", "status", "--porcelain"], root)
        baseline_ignored_correct = None
        for mode in ("clean", "edited", "ignored edit"):
            path = root / (ignored_file if mode == "ignored edit" else "README.md")
            if mode == "ignored edit":
                with path.open("ab") as stream:
                    stream.write(b"\nretained binary correctness check\n")
                baseline_ignored_correct = call(root, binaries["baseline"], "cat", ignored_file) == path.read_bytes()
                assert not baseline_ignored_correct, "use a retained binary from before the tracked-ignore fix"
                assert call(root, current, "cat", ignored_file) == path.read_bytes()
            names = list(samples) if mode != "ignored edit" else ["git", "current"]
            for sample in range(args.runs):
                offset = sample % len(names)
                order = names[offset:] + names[:offset]
                if sample % 2:
                    order.reverse()
                for name in order:
                    if mode != "clean":
                        with path.open("ab") as stream:
                            stream.write(f"\nbenchmark {mode} {sample} {name}\n".encode())
                    if name == "git":
                        row = {"wall_ms": run(["git", "status", "--porcelain"], root) * 1000}
                    else:
                        trace_status.TIG = binaries[name]
                        row = trace_status.traced(root, ["status"])
                        del row["trace"]
                        if mode == "ignored edit":
                            assert call(root, binaries["baseline"], "cat", ignored_file) == path.read_bytes(), "timed status missed the edit"
                    samples[name][mode].append(row)
    result = {
        "fixture_commit": commit, "fixture_tree": tree, "files": len(modes),
        "tracked_ignored_files": len(ignored_paths), "edited_ignored_path": ignored_file,
        "symlinks": len(symlinks), "materialized_symlinks": actual_links,
        "complete_tree_verified": True, "baseline_ignored_edit_correct": baseline_ignored_correct,
        "source": call(ROOT, "git", "--git-dir=" + str(ROOT / ".git/tig-public.git"), "rev-parse", "master").decode().strip(),
        "platform": platform.platform(), "git_version": call(ROOT, "git", "--version").decode().strip(),
        "binaries_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()},
        "runs": args.runs, "samples": samples,
        "median_ms": {name: {mode: statistics.median(row["wall_ms"] for row in rows) if rows else None for mode, rows in modes.items()} for name, modes in samples.items()},
    }
    args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"files": result["files"], "tracked_ignored_files": len(ignored_paths), "baseline_ignored_edit_correct": baseline_ignored_correct, "median_ms": result["median_ms"]}, indent=2))


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stderr:
            print(error.stderr.decode(errors="replace"), file=sys.stderr)
        raise
