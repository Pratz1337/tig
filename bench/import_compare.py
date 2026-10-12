"""Measure API storage and complete CLI import on a locally cloned real repo.

Build tig and the import_bench example in release mode first. Retains each
fresh destination under target for inspection; never deletes existing data.
"""

import argparse
import json
import os
import statistics
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def timed(argv, env):
    started = time.perf_counter()
    result = subprocess.run(argv, env=env, capture_output=True, text=True, encoding="utf-8", check=True)
    return {"wall_s": time.perf_counter() - started, "stdout": result.stdout, "stderr": result.stderr}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--cli-only", action="store_true", help="measure the final CLI without repeating the storage comparison")
    args = parser.parse_args()
    source = args.source.resolve()
    suffix = ".exe" if os.name == "nt" else ""
    example = ROOT / "target" / "release" / "examples" / f"import_bench{suffix}"
    tig = ROOT / "target" / "release" / f"tig{suffix}"
    prefix = ROOT / "target" / f"import-measure-{time.time_ns()}"
    env = dict(os.environ, TIG_AUTHOR_NAME="bench", TIG_AUTHOR_EMAIL="bench@example.com")
    output = {"source": str(source), "runs": args.runs, "loose": [], "journal": [], "cli": [], "reimport": []}
    for backend in (() if args.cli_only else ("loose", "journal")):
        for run in range(args.runs):
            store = Path(f"{prefix}-{backend}-{run}")
            row = timed([str(example), str(source), str(store), backend], env)
            output[backend].append(row)
            print(row["stdout"].strip(), flush=True)
    for run in range(args.runs):
        dest = Path(f"{prefix}-cli-{run}")
        argv = [str(tig), "-R", str(dest), "import-git", str(source)]
        row = timed(argv, env)
        output["cli"].append(row)
        print("CLI", row["stdout"].strip(), flush=True)
        repeated = timed(argv, env)
        output["reimport"].append(repeated)
        print("repeat", repeated["stdout"].strip(), flush=True)
    path = ROOT / "target" / ("import-cli-final.json" if args.cli_only else "import-benchmark.json")
    path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    for name in ("loose", "journal", "cli", "reimport"):
        if output[name]:
            print(f"{name} median wall: {statistics.median(row['wall_s'] for row in output[name]):.3f} s")


if __name__ == "__main__":
    main()
