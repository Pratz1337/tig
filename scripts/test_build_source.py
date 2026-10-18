"""Local privacy-boundary tests; never starts a Modal app or uploads data."""

import os
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path

sys.dont_write_bytecode = True
from build_source import public_source

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("TIG_TEST_BINARY", str(ROOT / "bin" / ("tig.exe" if os.name == "nt" else "tig")))).resolve()


@unittest.skipUnless(BINARY.is_file(), "set TIG_TEST_BINARY to a built TIG executable")
class PublicBuildSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="tig-source-test-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "repo"
        self.repo.mkdir()
        self.marker = ("private-build-input-" + uuid.uuid4().hex).encode()
        (self.repo / "public.rs").write_bytes(b"public original\n")
        (self.repo / ".env.example").write_bytes(b"PUBLIC=example\n")
        (self.repo / ".env").write_bytes(self.marker)
        self.tig("init")
        self.tig("bookmark", "set", "main")
        self.tig("new")

    def tig(self, *args):
        result = subprocess.run([str(BINARY), *args], cwd=self.repo, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        return result.stdout

    def stage(self):
        return public_source(self.repo, BINARY)

    def test_floor_metadata_and_uncommitted_source(self):
        (self.repo / "public.rs").write_bytes(b"uncommitted public edit\n")
        for name in (".ENV.local", "local.key", "id_ed25519", ".hg/hgrc", ".svn/entries", ".jj/repo/key", ".grok/config", "pending/local.txt"):
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"build scratch data\n" if name in (".grok/config", "pending/local.txt") else self.marker)
        with self.stage() as source:
            self.assertEqual((source / "public.rs").read_bytes(), b"uncommitted public edit\n")
            self.assertEqual((source / ".env.example").read_bytes(), b"PUBLIC=example\n")
            for path in source.rglob("*"):
                if path.is_file():
                    self.assertNotIn(self.marker, path.read_bytes())
            self.assertFalse(any((source / name).exists() for name in (".tig", ".git", ".env", ".hg", ".svn", ".jj", ".grok", "pending")))

    def test_roles_unicode_and_negations_use_native_rules(self):
        (self.repo / ".private").write_text("sécrets/** @developers\n!sécrets/public.rs\n", encoding="utf-8")
        directory = self.repo / "se\u0301crets"
        directory.mkdir()
        (directory / "private.rs").write_bytes(self.marker)
        (directory / "public.rs").write_bytes(b"explicitly public\n")
        with self.stage() as source:
            self.assertFalse((source / directory.name / "private.rs").exists())
            self.assertEqual((source / directory.name / "public.rs").read_bytes(), b"explicitly public\n")

    def test_stage_is_immutable_and_bookmarks_are_preserved(self):
        before = self.tig("bookmark", "list")
        with self.stage() as source:
            (self.repo / "public.rs").write_bytes(b"changed after staging\n")
            self.assertEqual((source / "public.rs").read_bytes(), b"public original\n")
        self.assertEqual(self.tig("bookmark", "list"), before)

    def test_private_copy_refuses_before_upload(self):
        (self.repo / "public.rs").write_bytes(self.marker)
        with self.assertRaisesRegex(RuntimeError, "bytes equal to a private file"):
            with self.stage():
                self.fail("private copy must not produce build inputs")

    def test_invalid_policy_refuses_before_upload(self):
        (self.repo / ".private").write_bytes(b"\xff")
        with self.assertRaisesRegex(RuntimeError, ".private is invalid"):
            with self.stage():
                self.fail("invalid policy must not produce build inputs")

    def test_fixture_paths_do_not_declassify_different_private_bytes(self):
        name = "crates/tig-remote-http/src/testdata/key.pem"
        path = self.repo / name
        path.parent.mkdir(parents=True)
        path.write_bytes(self.marker)
        (self.repo / ".private").write_text(f"!{name}\n")
        with self.assertRaisesRegex(RuntimeError, "bytes equal to a private file"):
            with self.stage():
                self.fail("fixture pathname must not authorize different private content")

    def test_missing_and_empty_policy_keep_the_privacy_floor(self):
        for value in (None, b""):
            policy = self.repo / ".private"
            if value is None:
                policy.unlink()
            else:
                policy.write_bytes(value)
            with self.stage() as source:
                self.assertFalse((source / ".env").exists())

    def test_untracked_ignored_policy_refuses_before_upload(self):
        (self.repo / ".private").unlink()
        self.tig("snapshot")
        (self.repo / ".gitignore").write_text(".private\n")
        (self.repo / ".private").write_text("public.rs\n")
        with self.assertRaisesRegex(RuntimeError, "differs from the staged policy"):
            with self.stage():
                self.fail("an ignored local privacy policy must not be silently skipped")

    def link(self, target, directory=False):
        try:
            (self.repo / "link.rs").symlink_to(target, target_is_directory=directory)
        except OSError as error:
            self.skipTest(f"symlink creation unavailable: {error}")

    def test_public_file_link_stays_inside_snapshot(self):
        self.link("public.rs")
        with self.stage() as source:
            self.assertTrue((source / "link.rs").is_symlink())
            self.assertEqual((source / "link.rs").read_bytes(), b"public original\n")

    def test_link_outside_snapshot_refuses_before_upload(self):
        outside = self.base / "outside.rs"
        outside.write_bytes(self.marker)
        self.link(outside)
        with self.assertRaisesRegex(RuntimeError, "inside the staged tree"):
            with self.stage():
                self.fail("outside link must not produce build inputs")

    def test_link_to_omitted_private_file_refuses_before_upload(self):
        self.link(".env")
        with self.assertRaises(FileNotFoundError):
            with self.stage():
                self.fail("private link target must not produce build inputs")

    def test_directory_link_refuses_before_upload(self):
        directory = self.repo / "source-dir"
        directory.mkdir()
        (directory / "code.rs").write_bytes(b"public directory contents\n")
        self.link("source-dir", directory=True)
        with self.assertRaisesRegex(RuntimeError, "inside the staged tree"):
            with self.stage():
                self.fail("directory link must not produce recursive build inputs")

    def runner_files(self):
        import modal_build
        for name, data in modal_build.RUNNER_SOURCES.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        (self.repo / "Cargo.toml").write_text("[workspace]\n")
        (self.repo / "Cargo.lock").write_text("version = 4\n")
        return modal_build

    def test_private_runner_refuses_before_app_creation(self):
        build = self.runner_files()
        (self.repo / ".private").write_text("scripts/modal_build.py\n")
        with self.assertRaisesRegex(RuntimeError, "omits required build input"):
            with build.build_app(self.repo, BINARY):
                self.fail("private build program must not be serialized")

    def test_changed_runner_refuses_before_app_creation(self):
        build = self.runner_files()
        with (self.repo / "scripts/modal_build.py").open("ab") as stream:
            stream.write(b"\n# changed after program loading\n")
        with self.assertRaisesRegex(RuntimeError, "differs from the running build program"):
            with build.build_app(self.repo, BINARY):
                self.fail("mismatched build program must not be serialized")

    def test_matching_runner_can_construct_both_build_functions(self):
        build = self.runner_files()
        with build.build_app(self.repo, BINARY) as (app, cargo_exec, cargo_release):
            self.assertEqual(app.name, "tig-build")
            self.assertTrue(callable(cargo_exec.remote))
            self.assertTrue(callable(cargo_release.remote))


if __name__ == "__main__":
    unittest.main()
