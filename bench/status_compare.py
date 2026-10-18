"""Interleave Git and retained/current TIG status on one generated 10k tree.

This is a fairness fixture, not evidence of real monorepo performance.
Keep a baseline release binary before changing TIG; build the current bin/ and
export public master to .git/tig-public.git before measuring.
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
from compare import ROOT, make_tree, run, touch_one


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("--runs", type=int, default=15)
    parser.add_argument("--json", type=Path, required=True)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    current = ROOT / "bin" / ("tig.exe" if sys.platform == "win32" else "tig")
    binaries = {"baseline": args.baseline.resolve(), "current": current}
    samples = {name: {mode: [] for mode in ("clean", "edited")} for name in ("git", *binaries)}
    with tempfile.TemporaryDirectory(prefix="tig-status-compare-") as tmp:
        root = Path(tmp)
        make_tree(root, 10000)
        (root / ".gitignore").write_text("/.tig/\n", encoding="utf-8")
        run([[str(current), "init", "."], [str(current), "new", "-m", "base"]], root)
        run([["git", "init", "-q"], ["git", "add", "-A"], ["git", "commit", "-qm", "base"]], root)
        # Both tools track the same files, including the generated privacy policy.
        assert len(subprocess.check_output(["git", "ls-files", "-z"], cwd=root).split(b"\0")) - 1 == 10002
        time.sleep(2.1)  # Expire the documented stat-cache racy window.
        for binary in binaries.values():
            run([str(binary), "status"], root)
        run(["git", "status", "--porcelain"], root)
        for mode in ("clean", "edited"):
            for sample in range(args.runs):
                order = list(samples)
                offset = sample % len(order)
                order = order[offset:] + order[:offset]
                if sample % 2:
                    order.reverse()
                for index, name in enumerate(order):
                    if mode == "edited":
                        touch_one(root, sample * len(order) + index)
                    if name == "git":
                        row = {"wall_ms": run(["git", "status", "--porcelain"], root) * 1000}
                    else:
                        trace_status.TIG = binaries[name]
                        row = trace_status.traced(root, ["status"])
                        del row["trace"]
                    samples[name][mode].append(row)
    result = {
        "generated_files": 10000,
        "tracked_files": 10002,
        "source": subprocess.check_output(["git", "--git-dir=" + str(ROOT / ".git/tig-public.git"), "rev-parse", "master"], text=True).strip(),
        "platform": platform.platform(),
        "git_version": subprocess.check_output(["git", "--version"], text=True).strip(),
        "binaries_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in binaries.items()},
        "runs": args.runs,
        "samples": samples,
        "median_ms": {name: {mode: statistics.median(row["wall_ms"] for row in rows) for mode, rows in modes.items()} for name, modes in samples.items()},
    }
    args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(result["median_ms"], indent=2))


if __name__ == "__main__":
    main()
