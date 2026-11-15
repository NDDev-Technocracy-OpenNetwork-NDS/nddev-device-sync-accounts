import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("generate", Path(__file__).with_name("generate.py"))
generate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(generate)


class ProtocolSourceTests(unittest.TestCase):
    def test_local_source_uses_the_locked_commit_and_preserves_the_checkout(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def git(*args):
                return subprocess.check_output(["git", "-C", directory, *args], text=True)
            git("init", "--quiet")
            git("config", "user.name", "Fixture")
            git("config", "user.email", "fixture@example.invalid")
            (root / "schema.txt").write_text("pinned\n")
            git("add", ".")
            git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "fixture: pinned")
            pinned = git("rev-parse", "HEAD").strip()
            (root / "schema.txt").write_text("later\n")
            git("-c", "commit.gpgsign=false", "commit", "--quiet", "-am", "fixture: later")
            before = git("rev-parse", "HEAD")
            with mock.patch.dict(os.environ, {"NDS_PROTOCOL_SOURCE": directory}):
                archive = generate.protocol_archive({"source_repo": "example/protocol", "source_commit": pinned})
            with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
                self.assertEqual(tar.extractfile("schema.txt").read(), b"pinned\n")
            self.assertEqual(git("rev-parse", "HEAD"), before)
            self.assertEqual((root / "schema.txt").read_text(), "later\n")
            self.assertEqual(git("status", "--porcelain"), "")

    def test_an_explicit_missing_checkout_does_not_fall_back_to_a_network_fetch(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"NDS_PROTOCOL_SOURCE": str(Path(directory) / "missing")}):
                with mock.patch.object(generate.subprocess, "run", side_effect=AssertionError("network fallback")):
                    with self.assertRaises(FileNotFoundError):
                        generate.protocol_archive({"source_repo": "example/protocol", "source_commit": "0" * 40})


if __name__ == "__main__":
    unittest.main()
