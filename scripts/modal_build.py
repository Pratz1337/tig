"""Run tig Cargo commands on Modal and return the cargo exit code.

Heavy builds stay off this machine. The Debian image (rustup + mingw) is
cached by Modal. Each run stages public source before uploading and reuses
the ``tig-cargo-cache`` volume for the registry, git checkout, and
``CARGO_TARGET_DIR``. See scripts/MODAL.md for the source boundary.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True

import modal

from build_source import UPLOAD_IGNORE, public_source

REPO = Path(__file__).resolve().parents[1]
RUNNER_SOURCES = {name: (REPO / name).read_bytes() for name in ("scripts/modal_build.py", "scripts/build_source.py")}
REMOTE_REPO = "/repo"
CACHE_ROOT = "/cargo-cache"
CARGO_HOME = f"{CACHE_ROOT}/cargo-home"
# Concurrent agents must not share a target dir or the source-hash record
# (their trees differ), so each picks a lane: TIG_MODAL_CACHE=<name>.
LANE = "".join(c for c in os.environ.get("TIG_MODAL_CACHE", "main") if c.isalnum() or c in "-_") or "main"
TARGET_DIR = f"{CACHE_ROOT}/target" if LANE == "main" else f"{CACHE_ROOT}/target-{LANE}"
RELEASE_DIR = f"{TARGET_DIR}/x86_64-pc-windows-gnu/release"

base_image = (
    modal.Image.debian_slim(python_version="3.11")
    .apt_install(
        "build-essential",
        "ca-certificates",
        "cmake",
        "curl",
        "gcc-mingw-w64-x86-64",
        "git",
        "pkg-config",
    )
    .run_commands(
        "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | "
        "sh -s -- -y --default-toolchain stable --profile minimal "
        "--component clippy,rustfmt",
        ". /root/.cargo/env && rustup target add x86_64-pc-windows-gnu",
    )
    .env(
        {
            "PATH": "/root/.cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "CARGO_TERM_COLOR": "always",
            "PYTHONPATH": "/repo/scripts",
        }
    )
)

volume = modal.Volume.from_name("tig-cargo-cache", create_if_missing=True)

RUN_ENV = {
    "CARGO_HOME": CARGO_HOME,
    "CARGO_TARGET_DIR": TARGET_DIR,
    "TIG_MODAL_CACHE": LANE,
    "CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER": "x86_64-w64-mingw32-gcc",
    "CC_x86_64_pc_windows_gnu": "x86_64-w64-mingw32-gcc",
    "CXX_x86_64_pc_windows_gnu": "x86_64-w64-mingw32-g++",
}


def _strip_ddash(args: list[str]) -> list[str]:
    if args and args[0] == "--":
        return args[1:]
    return args


SRC_HASHES = f"{TARGET_DIR}/src-mtimes.json"


def _sync_mtimes() -> None:
    """Make cargo's mtime-based freshness check match the source content.

    Uploaded files do not carry trustworthy mtimes, so cargo could reuse
    artifacts on the cache volume that were built from different sources.
    Each file gets the time its current content was first seen in this lane.
    A fixed "old" time for unchanged files is not enough: an artifact built
    for another package or feature selection from an earlier version of the
    file would then look fresh.
    """
    import hashlib
    import json

    try:
        with open(SRC_HASHES, encoding="utf-8") as f:
            previous = json.load(f)
    except (OSError, ValueError):
        previous = {}
    current = {}
    now = time.time()
    changed = 0
    for root, _dirs, files in os.walk(REMOTE_REPO):
        for name in files:
            path = os.path.join(root, name)
            with open(path, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            rel = os.path.relpath(path, REMOTE_REPO)
            seen = previous.get(rel)
            if isinstance(seen, list) and len(seen) == 2 and seen[0] == digest:
                stamp = float(seen[1])
            else:
                stamp = now
                changed += 1
            current[rel] = [digest, stamp]
            os.utime(path, (stamp, stamp))
    with open(SRC_HASHES, "w", encoding="utf-8") as f:
        json.dump(current, f)
    print(f"sources: {len(current)} files, {changed} changed since last run", flush=True)


def _stream(cmd: list[str]) -> int:
    print("+ " + " ".join(cmd), flush=True)
    proc = subprocess.Popen(
        cmd,
        cwd=REMOTE_REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="", flush=True)
    return proc.wait()


def _cargo_exec(cmd: list[str]) -> int:
    os.makedirs(CARGO_HOME, exist_ok=True)
    os.makedirs(TARGET_DIR, exist_ok=True)
    _sync_mtimes()
    try:
        return _stream(cmd)
    finally:
        volume.commit()


def _cargo_release() -> dict:
    """Build Windows GNU bins and return their bytes. ``code`` is cargo's status."""
    os.makedirs(CARGO_HOME, exist_ok=True)
    os.makedirs(TARGET_DIR, exist_ok=True)
    _sync_mtimes()
    try:
        code = _stream(
            [
                "cargo",
                "build",
                "--release",
                "--locked",
                "--target",
                "x86_64-pc-windows-gnu",
                "--bins",
            ]
        )
        if code != 0:
            return {"code": code, "bins": []}
        bins = []
        release = Path(RELEASE_DIR)
        for path in sorted(release.glob("*.exe")):
            data = path.read_bytes()
            bins.append({"name": path.name, "size": len(data), "data": data})
        return {"code": 0, "bins": bins}
    finally:
        volume.commit()


@contextlib.contextmanager
def build_app(root=REPO, binary=None):
    with public_source(root, binary) as source:
        for name in ("scripts/modal_build.py", "scripts/build_source.py", "Cargo.toml", "Cargo.lock"):
            if not (source / name).is_file():
                raise RuntimeError(f"public source omits required build input {name}; refusing upload")
        for name, expected in RUNNER_SOURCES.items():
            if (source / name).read_bytes() != expected:
                raise RuntimeError(f"{name} differs from the running build program; refusing upload")
        image = base_image.add_local_dir(source, remote_path=REMOTE_REPO, ignore=UPLOAD_IGNORE)
        app = modal.App("tig-build", include_source=False)
        options = dict(image=image, cpu=16, memory=32 * 1024, timeout=60 * 60,
                       volumes={CACHE_ROOT: volume}, env=RUN_ENV, serialized=True)
        cargo_exec = app.function(name="cargo_exec", **options)(_cargo_exec)
        cargo_release = app.function(name="cargo_release", **options)(_cargo_release)
        yield app, cargo_exec, cargo_release


def _run_remote(cmd: list[str]) -> int:
    started = time.perf_counter()
    with build_app() as (app, cargo_exec, _):
        with modal.enable_output():
            with app.run():
                code = cargo_exec.remote(cmd)
    elapsed = time.perf_counter() - started
    print(f"modal exit {code} in {elapsed:.1f}s", flush=True)
    return int(code)


def _scope(rest: list[str]) -> list[str]:
    """`--workspace` unless the caller picked packages with -p/--package."""
    picked = any(a in ("-p", "--package") or a.startswith(("--package=", "-p")) for a in rest)
    return [] if picked else ["--workspace"]


def main(argv: list[str] | None = None) -> int:
    # Modal and cargo print Unicode; the Windows console default (cp1252)
    # would crash on it.
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    # Cargo flags such as -p must not be parsed as flags of this script.
    if argv is None:
        argv = sys.argv[1:]
    parser = argparse.ArgumentParser(description="Build and test tig on Modal.")
    parser.add_argument("cmd", choices=("test", "clippy", "run", "release"))
    # Only the subcommand is ours; everything after it goes to cargo (or to
    # the shell for `run`) untouched, so argparse never sees `-p`.
    args = parser.parse_args(argv[:1])
    rest = _strip_ddash(argv[1:])

    if args.cmd == "test":
        return _run_remote(["cargo", "test", *_scope(rest), "--locked", *rest])

    if args.cmd == "clippy":
        return _run_remote(
            [
                "cargo",
                "clippy",
                *_scope(rest),
                "--all-targets",
                "--locked",
                *rest,
                "--",
                "-D",
                "warnings",
            ]
        )

    if args.cmd == "run":
        if not rest:
            parser.error("run requires a command after --")
        return _run_remote(rest)

    started = time.perf_counter()
    with build_app() as (app, _, cargo_release):
        with modal.enable_output():
            with app.run():
                result = cargo_release.remote()
    elapsed = time.perf_counter() - started
    code = int(result["code"])
    print(f"modal exit {code} in {elapsed:.1f}s", flush=True)
    if code != 0:
        return code
    dest = REPO / "bin"
    dest.mkdir(parents=True, exist_ok=True)
    if not result["bins"]:
        print("no .exe files were produced", flush=True)
        return 1
    for item in result["bins"]:
        path = dest / item["name"]
        path.write_bytes(item["data"])
        print(f"{path} {item['size']} bytes", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
