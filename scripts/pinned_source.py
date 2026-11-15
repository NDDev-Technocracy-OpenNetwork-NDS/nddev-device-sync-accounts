"""Read one exact public Git source without modifying any selected checkout."""
from pathlib import Path
import re
import subprocess
import tempfile


def source_archive(repository, commit, source=None):
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("source needs an exact commit")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("source needs an exact GitHub repository")
    if source is not None:
        if not Path(source).is_dir():
            raise FileNotFoundError("selected source checkout is not a directory")
        return subprocess.check_output(
            ["git", "-C", str(source), "archive", commit], timeout=30
        )
    with tempfile.TemporaryDirectory(prefix="nds-source-") as directory:
        subprocess.run(["git", "init", "--quiet", "--bare", directory], check=True, timeout=30)
        subprocess.run(
            ["git", "-C", directory, "fetch", "--quiet", "--no-tags", "--depth=1",
             f"https://github.com/{repository}.git", commit],
            check=True, timeout=120,
        )
        return subprocess.check_output(
            ["git", "-C", directory, "archive", commit], timeout=30
        )
