"""Prepare immutable public source before starting a remote build."""

import contextlib
import hashlib
import json
import os
import subprocess
import tempfile
import urllib.request
import uuid
from pathlib import Path


PUBLIC_COMMITS = "https://api.github.com/repos/Pratz1337/tig/commits?per_page=100"
# Only the already-public localhost TLS fixtures may bypass historical paste checks.
PUBLIC_FIXTURES = {
    "crates/tig-remote-http/src/testdata/cert.pem": "4652c703edf59a91435bb659a2456ccc33945ed4357c83f230ec43ce1f88fd87",
    "crates/tig-remote-http/src/testdata/key.pem": "a3f1f697f1d2b6f3688ed7841331d4f18c1df11105d72257cfeeb48f25076171",
}
UPLOAD_IGNORE = ["target", "bin", ".git", ".tig", ".hg", ".svn", ".jj", "pending", "__pycache__", ".claude", ".grok"]
IGNORABLE = "\u200c\u200d\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u206a\u206b\u206c\u206d\u206e\u206f\ufeff"


def call(root, *args, data=None):
    result = subprocess.run([str(arg) for arg in args], cwd=root, input=data, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace").strip())
    return result.stdout


def check_policy(root, expected):
    policy = root / ".private"
    if policy.is_symlink() or policy.is_dir() or (policy.read_bytes() if policy.is_file() else None) != expected:
        raise RuntimeError("local .private differs from the staged policy; refusing upload")


def public_git_commit(root):
    if Path(call(root, "git", "rev-parse", "--show-toplevel").decode().strip()).resolve() != root:
        raise RuntimeError("bootstrap needs the root of a GitHub checkout")
    if call(root, "git", "status", "--porcelain", "--untracked-files=no"):
        raise RuntimeError("bootstrap needs a clean GitHub checkout; use a TIG workspace for uncommitted builds")
    commit = call(root, "git", "rev-parse", "HEAD").decode().strip()
    if len(commit) != 40 or any(c not in "0123456789abcdef" for c in commit):
        raise RuntimeError("bootstrap needs a public GitHub commit")
    # Fetch public IDs first: never send an unverified local Git ID to GitHub.
    with urllib.request.urlopen(PUBLIC_COMMITS, timeout=30) as response:
        recent = json.load(response)
    public = next((item for item in recent if item.get("sha") == commit), None)
    tree = call(root, "git", "rev-parse", "HEAD^{tree}").decode().strip()
    if public is None or public.get("commit", {}).get("tree", {}).get("sha") != tree:
        raise RuntimeError("bootstrap needs a recent public GitHub commit; use TIG for other source histories")
    entry = call(root, "git", "ls-tree", commit, ".private")
    expected = call(root, "git", "show", f"{commit}:.private") if entry else None
    check_policy(root, expected)
    print(f"bootstrap source: public GitHub commit {commit}; untracked files are not build inputs", flush=True)
    return commit


def native_export(root, binary, destination):
    call(root, binary, "snapshot", "--rehash")
    declassify = []
    for name, expected in PUBLIC_FIXTURES.items():
        path = root / name
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == expected:
            declassify.extend(["--declassify", name])
    args = [binary, "export-git", destination, *declassify]
    if b"--working-copy" in call(root, binary, "export-git", "--help"):
        call(root, *args, "--working-copy")
        return "working-copy", declassify[1::2]
    # An older binary must still be able to build its replacement safely.
    bookmark = "build-source-" + uuid.uuid4().hex
    call(root, binary, "bookmark", "set", bookmark)
    try:
        call(root, *args, "--bookmark", bookmark)
    finally:
        call(root, binary, "bookmark", "delete", bookmark)
    return bookmark, declassify[1::2]


def copy_tree(root, revision, destination):
    entries = call(root, "git", "ls-tree", "-rz", revision).split(b"\0")[:-1]
    parsed = []
    for row in entries:
        meta, name = row.split(b"\t", 1)
        parts = name.decode("utf-8").split("/")
        if any("".join(c for c in p if c not in IGNORABLE).lower() in UPLOAD_IGNORE for p in parts):
            continue
        parsed.append((meta, name))
    ids = [meta.split()[2] for meta, _ in parsed]
    data = call(root, "git", "cat-file", "--batch", data=b"\n".join(ids) + b"\n")
    offset = 0
    links = []
    for (meta, raw_path), expected_id in zip(parsed, ids):
        mode, kind, _ = meta.split()
        name = raw_path.decode("utf-8")
        parts = name.split("/")
        if any(
            not p or p in (".", "..") or "\\" in p or ":" in p or p.endswith((".", " "))
            or any(ord(c) < 32 or ord(c) == 127 for c in p)
            for p in parts
        ):
            raise RuntimeError("source contains a non-portable path")
        if mode not in (b"100644", b"100755", b"120000") or kind != b"blob":
            raise RuntimeError("source contains an unsupported entry")
        end = data.index(b"\n", offset)
        oid, object_kind, size = data[offset:end].split()
        if oid != expected_id or object_kind != b"blob":
            raise RuntimeError("source object is missing or has the wrong kind")
        size = int(size)
        body = data[end + 1:end + 1 + size]
        offset = end + 1 + size
        if len(body) != size or data[offset:offset + 1] != b"\n":
            raise RuntimeError("source object is truncated")
        offset += 1
        path = destination.joinpath(*parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        if mode == b"120000":
            links.append((path, body.decode("utf-8")))
        else:
            path.write_bytes(body)
            path.chmod(0o755 if mode == b"100755" else 0o644)
    for path, target in links:
        resolved = (path.parent / target).resolve()
        if not resolved.is_relative_to(destination) or resolved.is_dir():
            raise RuntimeError("source symlinks must resolve to public files inside the staged tree")
        path.symlink_to(target)
    for path, _ in links:
        target = path.resolve(strict=True)
        if not target.is_relative_to(destination) or not target.is_file():
            raise RuntimeError("source symlinks must resolve to public files inside the staged tree")
    return {name.decode("utf-8") for _, name in parsed}


@contextlib.contextmanager
def public_source(root, binary=None):
    root = root.resolve()
    with tempfile.TemporaryDirectory(prefix="tig-public-build-") as tmp:
        base = Path(tmp)
        source = base / "source"
        source.mkdir()
        if (root / ".tig").exists():
            binary = binary or root / "bin" / ("tig.exe" if os.name == "nt" else "tig")
            if not binary.is_file():
                raise RuntimeError("a native TIG workspace needs its TIG binary in bin/ before remote builds")
            exported = base / "public.git"
            revision, exceptions = native_export(root, binary, exported)
            names = copy_tree(exported, revision, source)
            check_policy(root, (source / ".private").read_bytes() if ".private" in names else None)
            for name in exceptions:
                path = source / name
                if path.is_symlink() or hashlib.sha256(path.read_bytes()).hexdigest() != PUBLIC_FIXTURES[name]:
                    raise RuntimeError("a TLS fixture changed during source preparation; refusing upload")
        else:
            copy_tree(root, public_git_commit(root), source)
        yield source
