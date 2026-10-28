"""Isolated local test paths and process execution; no cloud credentials inherited."""

from pathlib import Path
import json
import os
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent.parent
LOCAL = ROOT / ".local"
EVIDENCE = ROOT / "evidence"
GATEWAY = "kata-rust"
PORT = 29670


def environment():
    keep = ("PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_CTYPE", "SHELL")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    for key, name in (("XDG_CONFIG_HOME", "config"), ("XDG_STATE_HOME", "state"),
                      ("XDG_CACHE_HOME", "cache"), ("XDG_DATA_HOME", "data")):
        directory = LOCAL / name
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        env[key] = str(directory)
    env["OPENSHELL_LOCAL_TLS_DIR"] = str(LOCAL / "tls")
    env["OPENSHELL_GATEWAY_NAME"] = GATEWAY
    env["OPENSHELL_KATA_STATE_DIR"] = str(LOCAL / "runtime")
    if "LLVM_PROFILE_FILE" in os.environ:
        env["LLVM_PROFILE_FILE"] = os.environ["LLVM_PROFILE_FILE"]
    return env


def cli(*arguments, timeout=120, label=None, input_data=None, check=True):
    command = [str(LOCAL / "bin/openshell"), *map(str, arguments)]
    if label:
        print(f"Checking {label}", flush=True)
    started = time.monotonic()
    process = subprocess.Popen(command, cwd=ROOT, env=environment(),
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, start_new_session=True)
    try:
        stdout, stderr = process.communicate(input_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            stdout, stderr = process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            stdout, stderr = process.communicate()
        stderr += f"\nCLI check timed out after {timeout} seconds".encode()
    result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    if label:
        EVIDENCE.mkdir(exist_ok=True)
        record = {"command": ["openshell", *map(str, arguments)],
                  "exit_code": result.returncode,
                  "duration_seconds": round(time.monotonic() - started, 3),
                  "stdout": result.stdout.decode(errors="replace"),
                  "stderr": result.stderr.decode(errors="replace")}
        (EVIDENCE / (label + ".json")).write_text(json.dumps(record, indent=2) + "\n")
    if check and result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result
