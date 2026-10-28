#!/usr/bin/env python3
"""Exercise concurrent SFTP while an SSH command keeps stdin open."""
import concurrent.futures
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def ssh_options(metadata):
    return ['-F', '/dev/null', '-i', metadata['private_key_path'],
            '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile=' + metadata['known_hosts_path']]


def quoted(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'


def main():
    metadata = json.loads(Path(sys.argv[1]).read_text())
    options = ssh_options(metadata)
    target = metadata['username'] + '@' + metadata['host']
    main_command = subprocess.Popen(['ssh', *options, '-p', str(metadata['port']), target,
                                     'sleep 120'], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with tempfile.TemporaryDirectory(prefix='openshell-transfer-') as directory:
            folder = Path(directory)
            payload = bytes(range(256)) * (16 * 1024 * 1024 // 256)
            source = folder / 'source.bin'
            source.write_bytes(payload)
            digest = hashlib.sha256(payload).hexdigest()
            def transfer(index):
                destination = folder / f'copy-{index}.bin'
                batch = folder / f'batch-{index}.txt'
                remote = f'/sandbox/transport-{index}.bin'
                batch.write_text(f'put {quoted(source)} {quoted(remote)}\nget {quoted(remote)} {quoted(destination)}\nrm {quoted(remote)}\n')
                subprocess.run(['sftp', *options, '-P', str(metadata['port']),
                                '-b', str(batch), target], check=True,
                               capture_output=True, timeout=120)
                assert hashlib.sha256(destination.read_bytes()).hexdigest() == digest
                return {'index': index, 'bytes': len(payload), 'sha256': digest}
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(transfer, range(4)))
            subprocess.run(['ssh', *options, '-p', str(metadata['port']), target,
                            'id; uname -r; docker version --format "{{.Server.Version}}"'],
                           check=True, timeout=30)
            assert main_command.poll() is None, 'long-lived command ended during transfer'
            print(json.dumps({'uploads_and_downloads': results,
                              'main_command_still_alive': main_command.poll() is None}))
    finally:
        main_command.terminate()
        try:
            main_command.wait(timeout=5)
        except subprocess.TimeoutExpired:
            main_command.kill()
            main_command.wait()


if __name__ == '__main__':
    main()
