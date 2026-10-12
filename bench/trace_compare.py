"""Interleave a retained baseline executable and current tig on one 10k tree."""

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
import trace_status
from compare import ROOT, make_tree, touch_one


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("baseline", type=Path)
    args = parser.parse_args()
    binaries = {"baseline": args.baseline.resolve(), "current": trace_status.TIG}
    output = {name: {mode: [] for mode in ("clean", "edited", "startup")} for name in binaries}
    with tempfile.TemporaryDirectory(prefix="tigpaired-") as tmp:
        root = Path(tmp)
        make_tree(root, 10000)
        trace_status.traced(root, ["init", "."])
        trace_status.traced(root, ["new", "-m", "base"])
        time.sleep(2.1)
        for binary in binaries.values():
            trace_status.TIG = binary
            trace_status.traced(root, ["status"])
        for mode in ("clean", "edited", "startup"):
            for pair in range(10):
                order = ("baseline", "current") if pair % 2 == 0 else ("current", "baseline")
                for index, name in enumerate(order):
                    if mode == "edited":
                        touch_one(root, pair * 2 + index)
                    trace_status.TIG = binaries[name]
                    output[name][mode].append(trace_status.traced(root, ["--version"] if mode == "startup" else ["status"]))
    (ROOT / "target" / "bench-trace-paired.json").write_text(json.dumps(output, indent=2), encoding="utf-8")
    for name, modes in output.items():
        for mode, rows in modes.items():
            print(name, mode, "wall", round(statistics.median(row["wall_ms"] for row in rows), 2),
                  "total", round(statistics.median(row["phases_ms"].get("total", 0) for row in rows), 2),
                  "walk", round(statistics.median(row["phases_ms"].get("snapshot: walk + stat + hash", 0) for row in rows), 2))


if __name__ == "__main__":
    main()
