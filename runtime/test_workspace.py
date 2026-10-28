#!/usr/bin/env python3
"""Verify the exact OpenShell download workspace probe over pinned guest SSH."""
import importlib.util
import json
import sys
from pathlib import Path


def main():
    spec = importlib.util.spec_from_file_location('lifecycle', Path(__file__).with_name('lifecycle.py'))
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)
    metadata = json.loads(Path(sys.argv[1]).read_text())
    lifecycle.guest_ssh(metadata, 'mkdir -p /sandbox/project/upload')
    probe = lifecycle.guest_ssh(metadata, 'pwd -P && realpath -e -- /sandbox/project/upload')
    lines = probe.stdout.decode().splitlines()
    assert lines == ['/sandbox', '/sandbox/project/upload'], lines
    version = lifecycle.guest_ssh(metadata, 'realpath --version').stdout.decode()
    assert 'GNU coreutils' in version, version
    print(json.dumps({'workspace_probe': lines, 'realpath': version.splitlines()[0]}))


if __name__ == '__main__':
    main()
