"""Measure hot commands with 0% / 10% private files, plus first publish.

Generated fixtures, real CLI processes and local directory remotes. Private
rules are installed before init, so the first publish has no historical leak.
Publish uses the original baseline revision, keeping its workload independent
of the number of timed edits. Each publish gets a fresh remote.
"""
import argparse
import hashlib
import json
import re
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.dont_write_bytecode = True
from compare import ENV, ROOT, TIG, make_tree, touch_one

PHASE = re.compile(r"trace:\s+([\d.]+) ms\s+(.*)")


def command(root, identity, args, measured=False):
    env = dict(ENV, TIG_IDENTITY_FILE=str(identity))
    if measured:
        env["TIG_TRACE_PERF"] = "1"
    start = time.perf_counter()
    result = subprocess.run([str(TIG), *args], cwd=root, env=env,
                            capture_output=True, text=True, check=True)
    row = {"wall_ms": (time.perf_counter() - start) * 1000}
    if measured:
        row["phases_ms"] = {m[2]: float(m[1]) for line in result.stderr.splitlines()
                            if (m := PHASE.fullmatch(line))}
    return row, result.stdout


def private_rules(files):
    count = files // 10
    directories, remainder = divmod(count, 100)
    rules = [f"pkg{d // 100:03d}/mod{d % 100:02d}/" for d in range(directories)]
    for i in range(directories * 100, directories * 100 + remainder):
        rules.append(f"pkg{i // 10000:03d}/mod{(i // 100) % 100:02d}/file{i:07d}.txt")
    return "\n".join(rules) + "\n"


def hot_samples(cases, runs):
    output = {name: {mode: [] for mode in ("clean status", "edited status", "record change")}
              for name in cases}
    time.sleep(2.1)  # Expire the stat cache's racy window before clean samples.
    for root, identity in cases.values():
        command(root, identity, ["status"])
    for mode in output["public"]:
        for i in range(runs):
            order = ("public", "private10") if i % 2 == 0 else ("private10", "public")
            for name in order:
                root, identity = cases[name]
                if mode != "clean status":
                    touch_one(root, i)
                args = ["new", "-m", "bench"] if mode == "record change" else ["status"]
                row, _ = command(root, identity, args, measured=True)
                output[name][mode].append(row)
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=10000)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--json", type=Path, default=ROOT / "target/privacy-benchmark.json")
    args = parser.parse_args()
    if args.files < 10 or args.runs < 1:
        parser.error("use at least 10 files and one run")
    result = {"files": args.files, "private_files": args.files // 10, "runs": args.runs,
              "binary_sha256": hashlib.sha256(TIG.read_bytes()).hexdigest()}
    with tempfile.TemporaryDirectory(prefix="tigprivacy-") as temporary:
        base = Path(temporary)
        cases = {}
        for name in ("public", "private10"):
            root = base / name
            root.mkdir()
            make_tree(root, args.files)
            (root / ".private").write_text(private_rules(args.files) if name == "private10" else "# public fixture\n", encoding="utf-8")
            identity = base / (name + ".identity")
            command(root, identity, ["init", "."])
            command(root, identity, ["new", "-m", "base"])
            command(root, identity, ["bookmark", "set", "benchmark-base", "-r", "@-"])
            cases[name] = root, identity
            print(f"initialized {name}", flush=True)
        result["before_publish"] = hot_samples(cases, args.runs)
        assert all(not identity.exists() for _, identity in cases.values()), "hot commands created an identity"
        result["publish"] = {name: [] for name in cases}
        for i in range(args.runs):
            for name in (("public", "private10") if i % 2 == 0 else ("private10", "public")):
                root, identity = cases[name]
                file = root / "pkg000/mod00/file0000000.txt"
                before = file.read_bytes()
                remote = base / f"remote-{name}-{i}"
                nickname = f"sample{i}"
                command(root, identity, ["remote", "add", nickname, str(remote)])
                row, summary = command(root, identity, ["publish", nickname, "--revision", "benchmark-base"], measured=True)
                row["summary"] = summary
                if name == "private10":
                    count = re.search(r"private objects sealed: (\d+)", summary)
                    assert count and int(count[1]) >= args.files // 10, summary
                assert file.read_bytes() == before, "publish changed the working file"
                _, recorded = command(root, identity, ["cat", "pkg000/mod00/file0000000.txt"])
                assert recorded.encode() == before, "local working revision became sealed"
                result["publish"][name].append(row)
                print(f"published {name} sample {i + 1}", flush=True)
        result["after_publish"] = hot_samples(cases, args.runs)
    args.json.write_text(json.dumps(result, indent=2), encoding="utf-8")
    for stage in ("before_publish", "after_publish"):
        print(stage)
        for mode in result[stage]["public"]:
            values = [statistics.median(row["wall_ms"] for row in result[stage][name][mode]) for name in cases]
            print(f"  {mode}: public={values[0]:.2f} ms, private10={values[1]:.2f} ms")
    values = [statistics.median(row["wall_ms"] for row in result["publish"][name]) for name in cases]
    print(f"first publish: public={values[0]:.2f} ms, private10={values[1]:.2f} ms")


if __name__ == "__main__":
    main()
