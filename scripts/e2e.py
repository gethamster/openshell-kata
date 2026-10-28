#!/usr/bin/env python3
"""Exercise the unmodified OpenShell CLI against the local Rust adapter."""

from concurrent.futures import ThreadPoolExecutor
import argparse
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import time
import urllib.request

from local import EVIDENCE, LOCAL, PORT, ROOT, cli, environment

NAME = "rust-upload-check"
REMOTE = "/sandbox/project/upload"


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def execute(label, command, timeout=120):
    return cli("sandbox", "exec", NAME, "--no-tty", "--", "sh", "-ec",
               command, timeout=timeout, label=label)


def fixture():
    directory = LOCAL / "fixtures/upload"
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "nested").mkdir(exist_ok=True)
    (directory / "nested/text.txt").write_text("Rust adapter round trip\n")
    (directory / "probe.sh").write_text("#!/bin/sh\nprintf 'executable mode preserved\\n'\n")
    (directory / "probe.sh").chmod(0o755)
    (directory / "binary.dat").write_bytes(bytes(range(256)) * 256)
    # A deterministic 16 MiB input exercises backpressure beyond pipe buffers.
    with (directory / "large.bin").open("wb") as target:
        block = hashlib.shake_256(b"openshell-kata-transfer-regression").digest(1024 * 1024)
        for _ in range(16):
            target.write(block)
    (directory / "index.html").write_text("Rust OpenShell + Kata + Docker Compose: OK\n")
    (directory / "Dockerfile").write_text(
        'FROM busybox:1.37\nWORKDIR /www\nCOPY index.html .\n'
        'CMD ["httpd", "-f", "-p", "8080", "-h", "/www"]\n')
    (directory / "compose.yaml").write_text(
        'services:\n  web:\n    build: .\n    ports: ["127.0.0.1:18080:8080"]\n'
        '  worker:\n    image: busybox:1.37\n    command: ["sleep", "1800"]\n')
    return directory


def upload(directory, iteration):
    return cli("sandbox", "upload", "--no-git-ignore", NAME, directory,
               "/sandbox/project", timeout=180, label=f"upload-{iteration}")


def round_trip(directory, iteration):
    destination = LOCAL / "downloads" / str(iteration)
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    cli("sandbox", "download", NAME, REMOTE, destination,
        timeout=180, label=f"download-{iteration}")
    expected = {str(path.relative_to(directory)): digest(path)
                for path in directory.rglob("*") if path.is_file()}
    candidates = [destination, destination / "upload"]
    actual = None
    for candidate in candidates:
        found = {str(path.relative_to(candidate)): digest(path)
                 for path in candidate.rglob("*") if path.is_file()}
        if found == expected:
            actual = found
            break
    if actual is None:
        raise AssertionError(f"download hash mismatch: {destination}")
    (EVIDENCE / f"hashes-{iteration}.json").write_text(json.dumps(actual, indent=2) + "\n")


def main(resume=False):
    directory = fixture()
    cli("gateway", "info", "--output", "json", label="gateway-info")
    if not resume:
        cli("policy", "set", "--global", "--yes", "--policy",
            ROOT / "scripts/protocol-fixture.yaml", label="protocol-fixture")
        cli("sandbox", "create", "--name", NAME, "--from", "docker:29-dind",
            "--detach", "--no-auto-providers", "--", "sh", "-c", "sleep 3600",
            timeout=300, label="create")
    listing = json.loads(cli("sandbox", "list", "--output", "json", label="sandbox-ready").stdout)
    sandbox_id = next(item["id"] for item in listing["sandboxes"] if item["name"] == NAME)
    execute("identity", "id; uname -r; docker version --format '{{.Server.Version}}'")
    upload(directory, 0)
    execute("executable-mode", REMOTE + "/probe.sh")
    round_trip(directory, 0)
    execute("compose", "cd " + REMOTE + "; docker compose up -d --build; "
            "docker compose ps; wget -qO- http://127.0.0.1:18080", timeout=240)
    forward = subprocess.Popen(
        [str(LOCAL / "bin/openshell"), "forward", "service", NAME,
         "--target-port", "18080", "--local", "127.0.0.1:29680"],
        env=environment(), cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        response = None
        for _ in range(20):
            if forward.poll() is not None:
                raise RuntimeError("preview forward exited")
            try:
                with urllib.request.urlopen("http://127.0.0.1:29680", timeout=10) as handle:
                    response = {"status": handle.status, "body": handle.read(4096).decode()}
                break
            except OSError:
                time.sleep(0.25)
        assert response and response["status"] == 200 and "Compose: OK" in response["body"]
        (EVIDENCE / "preview.json").write_text(json.dumps(response, indent=2) + "\n")
        # Reproduce the original failure order: Compose, preview, then upload.
        for iteration in range(1, 4):
            with ThreadPoolExecutor(max_workers=2) as executor:
                transfer = executor.submit(upload, directory, iteration)
                command = executor.submit(execute, f"concurrent-{iteration}",
                                          "printf 'concurrent exec works\\n'; docker ps --format '{{.Names}}'")
                transfer.result()
                command.result()
            round_trip(directory, iteration)
    finally:
        forward.terminate()
        try:
            forward.wait(timeout=5)
        except subprocess.TimeoutExpired:
            forward.kill()
            forward.wait()
    cli("sandbox", "stop", NAME, timeout=120, label="stop")
    cli("sandbox", "start", NAME, timeout=300, label="start")
    execute("after-restart", "sha256sum " + REMOTE + "/large.bin; docker info >/dev/null")
    round_trip(directory, "restart")
    cli("sandbox", "delete", NAME, timeout=120, label="delete")
    for _ in range(60):
        remaining = json.loads(cli("sandbox", "list", "--output", "json").stdout)["sandboxes"]
        if not (LOCAL / "runtime" / sandbox_id).exists() and not any(s["id"] == sandbox_id for s in remaining):
            break
        time.sleep(1)
    else:
        raise AssertionError("sandbox deletion did not reconcile both runtime and gateway state")
    (EVIDENCE / "runtime-deleted.json").write_text(json.dumps({"sandbox_id": sandbox_id, "deleted": True}) + "\n")
    print("PASS: upload/download hashes, concurrent exec, Compose, preview, restart, delete")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--resume", action="store_true")
    main(parser.parse_args().resume)
