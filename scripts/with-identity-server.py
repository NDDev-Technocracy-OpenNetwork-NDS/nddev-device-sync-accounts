#!/usr/bin/env python3
"""Run a client against the pinned server's owned PostgreSQL/SMTP fixture."""
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from pinned_source import source_archive

ROOT = Path(__file__).resolve().parents[1]


def run_owned(arguments, *, timeout, **kwargs):
    child = subprocess.Popen(arguments, start_new_session=True, **kwargs)
    try:
        result = child.wait(timeout=timeout)
        if result:
            raise subprocess.CalledProcessError(result, arguments)
    finally:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait()


def main():
    if sys.platform != "linux" or len(sys.argv) < 2:
        raise SystemExit("usage on Linux: with-identity-server.py COMMAND [ARGUMENTS...]")
    lock = tomllib.loads((ROOT / "acceptance-server.lock").read_text())
    archive = source_archive(lock["source_repo"], lock["source_commit"])
    with tempfile.TemporaryDirectory(prefix="nds-identity-") as directory:
        root = Path(directory)
        source = root / "source"
        source.mkdir()
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            tar.extractall(source, filter="data")
        target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()
        # Compile historical fixture source with this project's selected SDK;
        # its own old rust-toolchain file must not install another compiler.
        toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
        env = dict(os.environ, CARGO_TARGET_DIR=str(target), RUSTUP_TOOLCHAIN=toolchain)
        def terminate(number, _frame):
            raise SystemExit(128 + number)
        previous = signal.signal(signal.SIGTERM, terminate)
        producer = None
        receipt = root / "identity.json"
        stop = receipt.with_suffix(".stop")
        try:
            run_owned(["cargo", "build", "--locked", "--bin", "nddev-device-sync-server",
                       "--jobs", "4"], cwd=source, env=env, timeout=900)
            binary = target / "debug/nddev-device-sync-server"
            with binary.open("rb") as artifact:
                digest = hashlib.file_digest(artifact, "sha256").hexdigest()
            # The producer validates this exact binary and owns every server,
            # database, mailbox, synthetic identity and telemetry child.
            with (root / "producer.log").open("w") as log:
                try:
                    producer = subprocess.Popen(
                        [sys.executable, str(source / "scripts/check-postgres.py"),
                         "--fixture-receipt", str(receipt), "--fixture-server", str(binary),
                         "--fixture-server-sha256", digest, "--fixture-seconds", "300"],
                        cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT,
                    )
                    deadline = time.monotonic() + 180
                    while not receipt.is_file():
                        if producer.poll() is not None:
                            raise RuntimeError("owned server fixture failed before readiness")
                        if time.monotonic() >= deadline:
                            raise TimeoutError("owned server fixture did not become ready")
                        time.sleep(0.1)
                    state = json.loads(receipt.read_text())
                    if state["status"] != "running" or state["stop_marker"] != str(stop):
                        raise RuntimeError("owned server fixture has an invalid receipt")
                    print("Pinned identity fixture ready; credentials stay in its private directory.", flush=True)
                    run_owned(
                        [sys.executable, str(ROOT / "scripts/with-secret-service.py"),
                         *sys.argv[1:]],
                        cwd=ROOT, env=env | {"NDS_FIXTURE_RECEIPT": str(receipt)},
                        timeout=180,
                    )
                finally:
                    # A marker also works during startup: the producer reaches
                    # its normal cleanup without interrupting resource creation.
                    if producer is not None:
                        signal.signal(signal.SIGTERM, signal.SIG_IGN)
                        stop.touch()
                        try:
                            producer.wait(timeout=120)
                        except subprocess.TimeoutExpired:
                            producer.send_signal(signal.SIGINT)
                            producer.wait(timeout=45)
                if producer.returncode:
                    raise RuntimeError("owned server fixture failed during shutdown")
                if json.loads(receipt.read_text())["status"] != "stopped":
                    raise RuntimeError("owned server fixture did not acknowledge shutdown")
                print("Owned identity fixture stopped.", flush=True)
        finally:
            signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.returncode) from None
