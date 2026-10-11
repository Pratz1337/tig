"""Separate CLI wall time from TIG_TRACE_PERF phases on a 10k-file tree."""

import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
from compare import ENV, ROOT, TIG, make_tree, touch_one


def traced(root, args):
    start = time.perf_counter()
    result = subprocess.run(
        [str(TIG), *args], cwd=root, env=dict(ENV, TIG_TRACE_PERF="1"),
        capture_output=True, text=True, check=True,
    )
    wall = (time.perf_counter() - start) * 1000
    phases = {}
    for line in result.stderr.splitlines():
        match = re.fullmatch(r"trace:\s+([\d.]+) ms\s+(.*)", line)
        if match:
            phases[match[2]] = float(match[1])
    return {"wall_ms": wall, "phases_ms": phases, "trace": result.stderr}


def main():
    with tempfile.TemporaryDirectory(prefix="tigtrace-") as tmp:
        root = Path(tmp)
        make_tree(root, 10000)
        setup = [traced(root, ["init", "."]), traced(root, ["new", "-m", "base"])]
        # Let stat-cache racy flags expire, then warm and clear them once.
        time.sleep(2.1)
        traced(root, ["status"])
        clean = [traced(root, ["status"]) for _ in range(5)]
        edited = []
        for i in range(5):
            touch_one(root, i)
            edited.append(traced(root, ["status"]))
        startup = [traced(root, ["--version"]) for _ in range(5)]
    output = {"files": 10000, "setup": setup, "clean": clean,
              "edited": edited, "startup": startup}
    path = ROOT / "target" / "bench-trace.json"
    path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    for name in ("clean", "edited", "startup"):
        print(name)
        for row in output[name]:
            print(f"wall {row['wall_ms']:.2f} ms; {row['phases_ms']}")


if __name__ == "__main__":
    main()
