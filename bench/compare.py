"""Time tig against git on the same synthetic repositories.

Both tools are driven through their real command-line binaries, so the
numbers include process start-up, exactly what a user sees.

Generated repositories are a fairness fixture. They are not proof of
real monorepo performance.

    python bench/compare.py --files 10000 100000 --runs 5

Prints a markdown table; --json writes raw samples. Release build first:
    cargo build --release -p tig-cli
"""

import argparse
import json
import os
import random
import shutil
import statistics
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIG = ROOT / "target" / "release" / ("tig.exe" if os.name == "nt" else "tig")
ENV = dict(
    os.environ,
    TIG_AUTHOR_NAME="bench",
    TIG_AUTHOR_EMAIL="bench@example.com",
    GIT_AUTHOR_NAME="bench",
    GIT_AUTHOR_EMAIL="bench@example.com",
    GIT_COMMITTER_NAME="bench",
    GIT_COMMITTER_EMAIL="bench@example.com",
)


def make_tree(root: Path, files: int, seed: int = 7) -> None:
    """A monorepo-shaped tree: ~100 files per directory, 3 levels deep,
    files of 200 B to 8 KiB."""
    rng = random.Random(seed)
    for i in range(files):
        d = root / f"pkg{i // 10000:03d}" / f"mod{(i // 100) % 100:02d}"
        d.mkdir(parents=True, exist_ok=True)
        size = rng.randint(200, 8192)
        (d / f"file{i:07d}.txt").write_bytes(rng.randbytes(size // 2).hex().encode()[:size])


def run(cmds, cwd):
    """Wall time for one argv, or several argv lists back to back.

    Each entry is a real CLI process, so start-up is included. A list of
    lists is one sample: git's first scenario is init, add, and commit.
    """
    if isinstance(cmds[0], str):
        cmds = [cmds]
    start = time.perf_counter()
    for cmd in cmds:
        subprocess.run(cmd, cwd=cwd, env=ENV, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return time.perf_counter() - start


def touch_one(root: Path, n: int) -> None:
    f = root / "pkg000" / "mod00" / "file0000000.txt"
    f.write_bytes(f.read_bytes() + f"edit {n}\n".encode())


def scenarios(tool: str):
    """(name, setup-or-None, command) in the order they run on one repo.

    command is one argv list, or a list of them timed as a single sample.
    Git's first sample is init, add, and the initial commit. tig init
    snapshots the initial change; new then records it as the parent of an
    empty working change, so both tools begin the status samples clean.
    """
    if tool == "git":
        return [
            ("init + first snapshot", None, [
                ["git", "init", "-q"],
                ["git", "add", "-A"],
                ["git", "commit", "-qm", "base"],
            ]),
            ("status, no change", None, ["git", "status", "--porcelain"]),
            ("status, 1 file edited", "edit", ["git", "status", "--porcelain"]),
            ("record change", "edit", ["git", "commit", "-qam", "x"]),
        ]
    return [
        ("init + first snapshot", None, [
            [str(TIG), "init", "."],
            [str(TIG), "new", "-m", "base"],
        ]),
        ("status, no change", None, [str(TIG), "status"]),
        ("status, 1 file edited", "edit", [str(TIG), "status"]),
        ("record change", "edit", [str(TIG), "new", "-m", "x"]),
    ]


def bench(files: int, runs: int):
    results = {}
    for tool in ("git", "tig"):
        samples = {name: [] for name, _, _ in scenarios(tool)}
        for r in range(runs):
            with tempfile.TemporaryDirectory(prefix=f"tigbench-{tool}-") as tmp:
                root = Path(tmp)
                make_tree(root, files)
                for i, (name, setup, cmd) in enumerate(scenarios(tool)):
                    if setup == "edit":
                        touch_one(root, r * 10 + i)
                    samples[name].append(run(cmd, root))
        results[tool] = samples
    return results


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--files", type=int, nargs="+", default=[10000])
    ap.add_argument("--runs", type=int, default=5)
    ap.add_argument("--json", type=Path)
    args = ap.parse_args()
    if not TIG.exists():
        raise SystemExit(f"build tig first: cargo build --release -p tig-cli ({TIG} missing)")
    git_version = subprocess.run(["git", "--version"], capture_output=True, text=True).stdout.strip()
    print(f"{git_version}; tig at {TIG}; {args.runs} runs, median shown\n")
    raw = {}
    for n in args.files:
        res = bench(n, args.runs)
        raw[n] = res
        print(f"### {n:,} files\n")
        print("| operation | git | tig | tig / git |")
        print("|---|---:|---:|---:|")
        for name, _, _ in scenarios("tig"):
            g = statistics.median(res["git"][name])
            t = statistics.median(res["tig"][name])
            print(f"| {name} | {g * 1000:.0f} ms | {t * 1000:.0f} ms | {t / g:.2f}x |")
        print()
    if args.json:
        args.json.write_text(json.dumps(raw, indent=2))


if __name__ == "__main__":
    main()
