#!/usr/bin/env python3
"""Start and stop only this checkout's local adapter and gateway processes."""

import argparse
import json
import os
import signal
import socket
import stat
import subprocess
import time

from local import EVIDENCE, LOCAL, PORT, ROOT, cli, environment
from pathlib import Path

RECORD = LOCAL / "processes.json"


def clear_stale_socket():
    path = LOCAL / "driver.sock"
    if not path.exists():
        return
    metadata = path.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise RuntimeError("unexpected driver socket ownership or type")
    with socket.socket(socket.AF_UNIX) as connection:
        if connection.connect_ex(str(path)) == 0:
            raise RuntimeError("a live adapter already owns the driver socket")
    path.unlink()


def stop():
    if not RECORD.exists():
        return
    processes = json.loads(RECORD.read_text())
    for name, entry in processes.items():
        pid = entry["pid"]
        query = subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                               capture_output=True, text=True)
        if query.returncode:
            continue
        if entry["executable"] not in query.stdout:
            raise RuntimeError(f"refusing to signal reused PID for {name}")
        if os.getpgid(pid) != pid:
            raise RuntimeError(f"unexpected process group for {name}")
        os.killpg(pid, signal.SIGINT)
    active = []
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        active = []
        for entry in processes.values():
            query = subprocess.run(["ps", "-p", str(entry["pid"]), "-o", "command="],
                                   capture_output=True, text=True)
            if entry["executable"] in query.stdout:
                active.append(entry)
        if not active:
            break
        time.sleep(0.1)
    for entry in active:
        query = subprocess.run(["ps", "-p", str(entry["pid"]), "-o", "command="],
                               capture_output=True, text=True)
        if entry["executable"] in query.stdout and os.getpgid(entry["pid"]) == entry["pid"]:
            os.killpg(entry["pid"], signal.SIGKILL)
    RECORD.unlink()
    clear_stale_socket()


def start(prototype, adapter_path=None):
    if RECORD.exists():
        raise RuntimeError("process record exists; inspect or stop local services first")
    clear_stale_socket()
    EVIDENCE.mkdir(exist_ok=True)
    adapter = adapter_path or ROOT / "target/debug/openshell-kata"
    gateway = LOCAL / "bin/openshell-gateway"
    commands = {
        "adapter": [str(adapter), "--socket", str(LOCAL / "driver.sock"),
                    "--gateway", f"https://127.0.0.1:{PORT}",
                    "--gateway-ca", str(LOCAL / "tls/ca.crt"),
                    "--lifecycle", str(ROOT / "runtime/lifecycle.py")],
        "gateway": [str(gateway), "--config", str(LOCAL / "gateway.toml"),
                    "--health-port", str(PORT + 1)],
    }
    if prototype:
        commands["adapter"].append("--prototype-policy-mode")
    processes = {}
    try:
        for name, command in commands.items():
            with (EVIDENCE / f"{name}.log").open("a") as log:
                process = subprocess.Popen(command, cwd=ROOT, env=environment(),
                                           stdout=log, stderr=subprocess.STDOUT,
                                           start_new_session=True)
            processes[name] = {"pid": process.pid, "executable": command[0]}
            RECORD.write_text(json.dumps(processes, indent=2) + "\n")
            RECORD.chmod(0o600)
            if name == "adapter":
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("adapter exited; inspect evidence/adapter.log")
                    if (LOCAL / "driver.sock").exists():
                        break
                    time.sleep(0.1)
                else:
                    raise RuntimeError("adapter did not bind its Unix socket")
        for _ in range(50):
            result = cli("gateway", "info", "--output", "json", check=False, timeout=3)
            if result.returncode == 0:
                print("Local adapter and gateway are ready")
                return
            time.sleep(0.1)
        raise RuntimeError("gateway did not become ready; inspect evidence/gateway.log")
    except BaseException:
        stop()
        raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("start", "stop"))
    parser.add_argument("--prototype-policy-mode", action="store_true")
    parser.add_argument("--adapter", type=lambda value: Path(value).resolve())
    args = parser.parse_args()
    if args.action == "stop":
        stop()
    else:
        start(args.prototype_policy_mode, args.adapter)
