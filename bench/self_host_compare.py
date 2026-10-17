"""Compare real TIG source trees using Git and retained/current TIG binaries.

Export the public master bookmark to .git/tig-public.git first. Preparation
is outside the timings; each sample includes real CLI startup and exit.
"""

import argparse
import hashlib
import json
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
from compare import ENV, ROOT, run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--runs", type=int, default=15)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    current = ROOT / "bin" / ("tig.exe" if sys.platform == "win32" else "tig")
    binaries = {"baseline": args.baseline.resolve(), "current": current, "short": current}
    modes = ("clean status", "edited status", "record change")
    samples = {tool: {mode: [] for mode in modes} for tool in ("git", *binaries)}
    with tempfile.TemporaryDirectory(prefix="tig-real-source-") as tmp:
        git_root = Path(tmp) / "git"
        subprocess.run(
            ["git", "clone", "--quiet", "--shared", "--branch", "master",
             str(ROOT / ".git/tig-public.git"), str(git_root)],
            env=ENV, check=True,
        )
        roots = {"git": git_root}
        files = sum(1 for path in git_root.rglob("*") if path.is_file() and ".git" not in path.parts)
        for name, binary in binaries.items():
            roots[name] = Path(tmp) / name
            shutil.copytree(git_root, roots[name], ignore=shutil.ignore_patterns(".git"))
            run([str(binary), "init", "."], roots[name])
            run([str(binary), "new", "-m", "benchmark base"], roots[name])
        # Let the documented stat-cache racy window expire before clean samples.
        time.sleep(2.1)
        for name, root in roots.items():
            command = ["git", "status", "--porcelain"] if name == "git" else [str(binaries[name]), "status"]
            run(command, root)
        for mode in modes:
            for sample in range(args.runs):
                order = list(roots) if sample % 2 == 0 else list(reversed(roots))
                for name in order:
                    root = roots[name]
                    if mode != "clean status":
                        with (root / "README.md").open("ab") as stream:
                            stream.write(f"\nbenchmark edit {mode} {sample}\n".encode())
                    if name == "git":
                        command = (["git", "commit", "-qam", "benchmark change"]
                                   if mode == "record change" else ["git", "status", "--porcelain"])
                    else:
                        command = ([str(binaries[name]), "new", "-m", "benchmark change"]
                                   if mode == "record change" else [str(binaries[name]), "status"])
                        if name == "short" and mode != "record change":
                            command.append("--short")
                    samples[name][mode].append(run(command, root) * 1000)
    result = {
        "source": subprocess.check_output(
            ["git", "--git-dir=" + str(ROOT / ".git/tig-public.git"), "rev-parse", "master"], text=True,
        ).strip(),
        "files": files,
        "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
        "platform": platform.platform(),
        "binaries_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()},
        "runs": args.runs,
        "samples_ms": samples,
        "median_ms": {name: {mode: statistics.median(rows) for mode, rows in values.items()}
                      for name, values in samples.items()},
    }
    args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"files": files, "runs": args.runs, "median_ms": result["median_ms"]}, indent=2))


if __name__ == "__main__":
    main()
