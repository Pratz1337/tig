"""Create a local TIG workspace from a fresh GitHub checkout, preserving history."""

import argparse
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="new workspace outside this Git checkout")
    parser.add_argument("--tig", type=Path, default=ROOT / "bin" / ("tig.exe" if os.name == "nt" else "tig"))
    args = parser.parse_args()
    target = args.directory.resolve()
    binary = args.tig.resolve()
    if target.is_relative_to(ROOT):
        parser.error("choose a workspace directory outside the Git checkout")
    if target.exists() and (not target.is_dir() or any(target.iterdir())):
        parser.error("workspace directory must be empty; existing work is never overwritten")
    if not binary.is_file():
        parser.error("build TIG first: python scripts/modal_build.py release")
    if not (ROOT / ".git").exists():
        parser.error("use a full GitHub clone; a source ZIP has no history to import")
    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT,
    )
    if dirty:
        parser.error("use a clean GitHub checkout; uncommitted source files are not imported")
    subprocess.run([str(binary), "-R", str(target), "import-git", str(ROOT)], check=True)
    (target / "bin").mkdir(exist_ok=True)
    shutil.copy2(binary, target / "bin" / binary.name)
    print(f"TIG workspace ready: {target}")
    print(f"Run: {target / 'bin' / binary.name} -R {target} status")


if __name__ == "__main__":
    main()
