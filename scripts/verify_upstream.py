#!/usr/bin/env python3
"""Verify that the vendored protocol files match their recorded upstream bytes."""

import hashlib
from pathlib import Path

root = Path(__file__).resolve().parent.parent / "proto"
for line in (root / "SHA256SUMS").read_text().splitlines():
    expected, name = line.split()
    path = root / name.lstrip("*")
    if path.parent != root or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
        raise SystemExit(f"Vendored protocol checksum mismatch: {name}")
print("Vendored OpenShell protocol checksums verified")
