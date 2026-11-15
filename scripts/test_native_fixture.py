import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest

SCRIPT = Path(__file__).with_name("with-secret-service.py")


def live_group(group):
    live = []
    for path in Path("/proc").glob("[0-9]*/stat"):
        try:
            fields = path.read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group and fields[0] not in ("Z", "X"):
                live.append(int(path.parent.name))
        except (OSError, ValueError, IndexError):
            pass
    return live


@unittest.skipUnless(sys.platform == "linux", "the isolated Secret Service fixture is Linux-only")
class NativeFixtureTests(unittest.TestCase):
    def test_command_failure_keeps_its_status_and_removes_the_private_store(self):
        with tempfile.TemporaryDirectory() as directory:
            env = dict(os.environ, TMPDIR=directory)
            result = subprocess.run(
                [sys.executable, str(SCRIPT), sys.executable, "-c", "raise SystemExit(7)"],
                env=env, capture_output=True, text=True, timeout=25,
            )
            self.assertEqual(result.returncode, 7, result.stderr)
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_cancellation_stops_its_process_group_and_removes_the_private_store(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = Path(directory) / "ready.json"
            code = (
                "import json,os,sys,time;"
                "from pathlib import Path;"
                "Path(sys.argv[1]).write_text(json.dumps({'group':os.getpgrp()}));"
                "time.sleep(60)"
            )
            process = subprocess.Popen(
                [sys.executable, str(SCRIPT), sys.executable, "-c", code, str(ready)],
                env=dict(os.environ, TMPDIR=directory),
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            try:
                deadline = time.monotonic() + 20
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(ready.exists(), "fixture did not become ready")
                group = json.loads(ready.read_text())["group"]
                process.terminate()
                _out, err = process.communicate(timeout=15)
                self.assertEqual(process.returncode, 143, err)
                deadline = time.monotonic() + 5
                while live_group(group) and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertEqual(live_group(group), [], "owned fixture processes remain")
                self.assertEqual(list(Path(directory).iterdir()), [ready])
            finally:
                if process.poll() is None:
                    process.terminate()
                    process.communicate(timeout=15)


if __name__ == "__main__":
    unittest.main()
