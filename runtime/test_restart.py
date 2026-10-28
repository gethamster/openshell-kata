#!/usr/bin/env python3
"""Validate guest replacement, Docker readiness, IP refresh, and workspace retention."""
import importlib.util
import json
import os
import sys
from pathlib import Path


def main():
    spec = importlib.util.spec_from_file_location('lifecycle', Path(__file__).with_name('lifecycle.py'))
    lifecycle = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lifecycle)
    metadata = json.loads(Path(sys.argv[1]).read_text())
    folder = Path(metadata['private_key_path']).parent
    os.environ['OPENSHELL_KATA_STATE_DIR'] = str(folder.parent)
    sandbox_id = metadata['sandbox_id']
    before_state = lifecycle.load_state(folder)
    lifecycle.wait_ready(metadata)
    lifecycle.guest_ssh(metadata, 'printf restart-persistence > /sandbox/restart-proof.txt')
    before = lifecycle.guest_ssh(metadata, 'cat /proc/sys/kernel/random/boot_id; cat /var/run/docker.pid; echo; docker version --format "{{.Server.Version}}"', timeout=60).stdout.decode().splitlines()
    lifecycle.operate('stop', sandbox_id)
    after_metadata = lifecycle.operate('start', sandbox_id)
    after_state = lifecycle.load_state(folder)
    after = lifecycle.guest_ssh(after_metadata, 'cat /proc/sys/kernel/random/boot_id; cat /var/run/docker.pid; echo; docker version --format "{{.Server.Version}}"; cat /sandbox/restart-proof.txt', timeout=60).stdout.decode().splitlines()
    assert before[0] != after[0], 'Kata guest kernel was not replaced'
    assert before[2] == after[2], 'Docker did not become ready again'
    assert after[3] == 'restart-persistence', 'workspace was not retained'
    assert metadata['port'] == after_metadata['port'], 'client loopback port changed'
    print(json.dumps({'before_boot_id':before[0], 'after_boot_id':after[0],
                      'before_docker_pid':before[1], 'after_docker_pid':after[1],
                      'docker_version':after[2], 'workspace_retained':True,
                      'before_ip':before_state['guest_ip'], 'after_ip':after_state['guest_ip'],
                      'loopback_port':after_metadata['port']}))


if __name__ == '__main__':
    main()
