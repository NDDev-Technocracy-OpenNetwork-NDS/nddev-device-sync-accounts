#!/usr/bin/env python3
"""Generate transport DTOs from the immutable protocol source; reject drift."""
import argparse
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--check", action="store_true")
args = parser.parse_args()
lock = tomllib.loads((ROOT / "protocol.lock").read_text())
source = Path(os.environ.get("NDS_PROTOCOL_SOURCE", str(ROOT.parent / "nddev-device-sync-protocol")))
archive = subprocess.check_output(["git", "-C", str(source), "archive", lock["source_commit"]])
with tempfile.TemporaryDirectory() as directory:
    temporary = Path(directory)
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(temporary, filter="data")
    subprocess.run(["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], cwd=temporary, check=True)
    for profile, filename in [("company", "company_wire.rs"), ("auth", "wire.rs"), ("health", "health_wire.rs"), ("devices", "device_wire.rs"), ("sync", "sync_wire.rs"), ("sync3", "sync3_wire.rs"), ("vault", "vault_wire.rs"), ("observability", "observability_wire.rs"), ("screen", "screen_wire.rs")]:
        generated = temporary / filename
        subprocess.run(["node", "scripts/generate-dtos.mjs", "rust", profile, str(generated)], cwd=temporary, check=True)
        subprocess.run(["rustfmt", "--edition", "2024", str(generated)], check=True)
        target = ROOT / "src" / filename
        if args.check:
            if target.read_bytes() != generated.read_bytes():
                raise SystemExit(f"Generated DTO drift: {target.name}; run just generate")
        else:
            target.write_bytes(generated.read_bytes())
