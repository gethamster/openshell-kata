#!/usr/bin/env python3
"""Fetch pinned official test tools, verifying archives before extracting binaries."""

import hashlib
from pathlib import Path
import platform
import shutil
import tarfile
import tempfile
import urllib.request

from local import LOCAL

VERSION = "v0.1.6"
ARCHIVES = {
    ("Darwin", "arm64"): (
        ("openshell", "aarch64-apple-darwin", "334e9cf24994a5bfd34691e9835920da15f5ef224cc96be0d4751eadfa279897"),
        ("openshell-gateway", "aarch64-apple-darwin", "8313480f7d00264fc6c8eaad6e522736b20be97bed6a8f309c08fcb10e3c617b")),
    ("Linux", "x86_64"): (
        ("openshell", "x86_64-unknown-linux-musl", "2951c67366f3e3584ed9cec8d49b9f0b0eefc8cacea8b0582ac164590492f136"),
        ("openshell-gateway", "x86_64-unknown-linux-gnu", "811265a55993beb333905a5b560764a40aa9177250171f711dce8ba820f7eff8")),
    ("Linux", "aarch64"): (
        ("openshell", "aarch64-unknown-linux-musl", "259452a6065c4f76e71884b84e8696cc0fec2f8a832891d333f268ca7bb55a21"),
        ("openshell-gateway", "aarch64-unknown-linux-gnu", "de7342457746829138cecbc21cc90a2d5d4c0ea22a362b976831ac3bbb0109d6")),
}


def main():
    architecture = (platform.system(), platform.machine())
    if architecture not in ARCHIVES:
        raise SystemExit(f"No qualified tool archive configured for {architecture}")
    destination = LOCAL / "bin"
    destination.mkdir(parents=True, exist_ok=True)
    for binary, target, expected in ARCHIVES[architecture]:
        name = f"{binary}-{target}.tar.gz"
        url = f"https://github.com/NVIDIA/OpenShell/releases/download/{VERSION}/{name}"
        with tempfile.TemporaryDirectory(dir=LOCAL) as temporary:
            archive = Path(temporary) / name
            checksum = hashlib.sha256()
            with urllib.request.urlopen(url, timeout=60) as source, archive.open("wb") as output:
                for chunk in iter(lambda: source.read(1024 * 1024), b""):
                    checksum.update(chunk)
                    output.write(chunk)
            if checksum.hexdigest() != expected:
                raise RuntimeError(f"Archive checksum mismatch: {name}")
            with tarfile.open(archive) as package:
                entry = package.getmember(binary)
                if not entry.isfile():
                    raise RuntimeError(f"Expected regular binary in {name}")
                with package.extractfile(entry) as source, (Path(temporary) / binary).open("wb") as output:
                    shutil.copyfileobj(source, output)
            staged = Path(temporary) / binary
            staged.chmod(0o755)
            staged.replace(destination / binary)
        print(f"Installed verified {binary} {VERSION}")


if __name__ == "__main__":
    main()
