#!/usr/bin/env python3
"""Run acceptance under an owned, unlocked Linux Secret Service, never the login store."""
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import tempfile

SESSION = r"""
root=$1
shift
keyring_pid=
cleanup() {
    if [ -n "$keyring_pid" ]; then
        kill "$keyring_pid" 2>/dev/null || true
        wait "$keyring_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT
gnome-keyring-daemon --version
gnome-keyring-daemon --foreground --unlock --components=secrets \
    --control-directory "$root/control" < "$root/password" > "$root/daemon.log" 2>&1 &
keyring_pid=$!
timeout 15s gdbus wait --session org.freedesktop.secrets
kill -0 "$keyring_pid"
owner=$(gdbus call --session --dest org.freedesktop.DBus --object-path /org/freedesktop/DBus \
    --method org.freedesktop.DBus.GetConnectionUnixProcessID org.freedesktop.secrets)
[ "$owner" = "(uint32 $keyring_pid,)" ]
rm -- "$root/password"
"$@"
"""


def main():
    if sys.platform != "linux" or len(sys.argv) < 2:
        raise SystemExit("usage on Linux: with-secret-service.py COMMAND [ARGUMENTS...]")
    with tempfile.TemporaryDirectory(prefix="nds-native-store-") as directory:
        root = Path(directory)
        env = dict(os.environ)
        for key in ("GNOME_KEYRING_CONTROL", "GNOME_KEYRING_PID", "DISPLAY", "WAYLAND_DISPLAY",
                    "XAUTHORITY", "DBUS_STARTER_ADDRESS", "DBUS_STARTER_BUS_TYPE",
                    "GNOME_KEYRING_DEBUG", "G_MESSAGES_DEBUG"):
            env.pop(key, None)
        for key, name in (("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config"),
                          ("XDG_CACHE_HOME", "cache"), ("XDG_STATE_HOME", "state"),
                          ("XDG_RUNTIME_DIR", "runtime")):
            path = root / name
            path.mkdir(mode=0o700)
            env[key] = str(path)
        (root / "control").mkdir(mode=0o700)
        password = root / "password"
        password.touch(mode=0o600)
        password.write_text(secrets.token_hex(32))
        child = subprocess.Popen(
            ["dbus-run-session", "--", "bash", "-euo", "pipefail", "-c",
             SESSION, "native-store", directory, *sys.argv[1:]],
            env=env, start_new_session=True,
        )
        def terminate(number, _frame):
            raise SystemExit(128 + number)
        previous = signal.signal(signal.SIGTERM, terminate)
        try:
            result = child.wait()
            return result if result >= 0 else 128 - result
        finally:
            signal.signal(signal.SIGTERM, previous)
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGTERM)
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait()
                except ProcessLookupError:
                    child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
