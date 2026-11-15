#!/usr/bin/env python3
"""Generate transport DTOs from the immutable protocol source; reject drift."""
import argparse
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def protocol_archive(lock):
    """Use the selected checkout, or fetch the exact public dependency for a standalone build."""
    commit = lock["source_commit"]
    repository = lock["source_repo"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("protocol source needs an exact commit")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("protocol source needs an exact GitHub repository")
    explicit = os.environ.get("NDS_PROTOCOL_SOURCE")
    source = Path(explicit) if explicit else ROOT.parent / "nddev-device-sync-protocol"
    if explicit and not source.is_dir():
        raise FileNotFoundError("selected protocol checkout is not a directory")
    if explicit or source.is_dir():
        return subprocess.check_output(
            ["git", "-C", str(source), "archive", commit], timeout=30
        )
    with tempfile.TemporaryDirectory(prefix="nds-protocol-") as directory:
        subprocess.run(["git", "init", "--quiet", "--bare", directory], check=True, timeout=30)
        subprocess.run(
            ["git", "-C", directory, "fetch", "--quiet", "--no-tags", "--depth=1",
             f"https://github.com/{repository}.git", commit],
            check=True, timeout=120,
        )
        return subprocess.check_output(
            ["git", "-C", directory, "archive", commit], timeout=30
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    lock = tomllib.loads((ROOT / "protocol.lock").read_text())
    archive = protocol_archive(lock)
    with tempfile.TemporaryDirectory() as directory:
        temporary = Path(directory)
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(temporary, filter="data")
        subprocess.run(["bun", "install", "--frozen-lockfile", "--ignore-scripts"],
                       cwd=temporary, check=True, timeout=120)
        for profile, filename in [
            ("company", "company_wire.rs"), ("organizations", "organizations_wire.rs"),
            ("auth", "wire.rs"), ("health", "health_wire.rs"),
            ("devices", "device_wire.rs"), ("personal", "personal_wire.rs"),
            ("sync", "sync_wire.rs"), ("sync3", "sync3_wire.rs"), ("vault", "vault_wire.rs"),
            ("observability", "observability_wire.rs"), ("screen", "screen_wire.rs"),
        ]:
            generated = temporary / filename
            subprocess.run(
                ["bun", "scripts/generate-dtos.mjs", "rust", profile, str(generated)],
                cwd=temporary, check=True, timeout=30,
            )
            subprocess.run(["rustfmt", "--edition", "2024", str(generated)],
                           check=True, timeout=30)
            target = ROOT / "src" / filename
            if args.check:
                if target.read_bytes() != generated.read_bytes():
                    raise SystemExit(f"Generated DTO drift: {target.name}; run just generate")
            else:
                target.write_bytes(generated.read_bytes())


if __name__ == "__main__":
    main()
