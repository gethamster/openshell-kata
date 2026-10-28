#!/usr/bin/env python3
"""Local Kata lifecycle; guest data transport is SSH, never containerd exec."""
import fcntl
import hashlib
import json
import os
import re
import shutil
import shlex
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
VM = os.environ.get('OPENSHELL_KATA_VM', 'openshell-kata-rust')
IMAGE = 'openshell-kata-guest:local'
PUBLIC_FIELDS = ('sandbox_id', 'host', 'port', 'username', 'private_key_path', 'known_hosts_path')
PING_SCRIPT = ('import socket,sys; s=socket.socket(socket.AF_UNIX); s.settimeout(2); '
               's.connect("/var/run/docker.sock"); '
               's.sendall(b"GET /_ping HTTP/1.0"+bytes([13,10,13,10])); '
               'sys.exit(0 if b" 200 " in s.recv(4096) else 1)')


def validate_id(value):
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,95}', value):
        raise ValueError('invalid sandbox ID')
    return value


def private_directory(path):
    if path.is_symlink():
        raise ValueError('state directory must not be a symlink')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir():
        raise ValueError('state path must be a directory')
    path.chmod(0o700)
    return path


def available_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def public_metadata(value):
    return {key: value[key] for key in PUBLIC_FIELDS}


def command(argv, timeout=120, check=True, input_data=None):
    result = subprocess.run(argv, input=input_data, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f'{Path(argv[0]).name} failed: {result.stderr.decode(errors="replace")[-1500:]}')
    return result


def vm_command(*argv, **kwargs):
    return command(['limactl', 'shell', VM, 'sudo', *argv], **kwargs)


def nerdctl(*argv, **kwargs):
    return vm_command('timeout', '90', 'nerdctl', *argv, **kwargs)


def ssh_config():
    return str(Path.home() / '.lima' / VM / 'ssh.config')


def control_path(folder):
    directory = private_directory(folder.parent / '.t')
    path = directory / hashlib.sha256(str(folder).encode()).hexdigest()[:20]
    if len(str(path).encode()) > 80:
        raise ValueError('runtime state path is too long for an SSH control socket')
    return path


def tunnel_control(folder, operation):
    return command(['ssh', '-F', ssh_config(), '-S', str(control_path(folder)),
                    '-O', operation, f'lima-{VM}'], timeout=10, check=False)


def open_tunnel(folder, state):
    if tunnel_control(folder, 'check').returncode == 0:
        return
    socket_path = control_path(folder)
    if socket_path.exists():
        socket_path.unlink()
    # ExitOnForwardFailure prevents a race from silently connecting to a different local service.
    command(['ssh', '-F', ssh_config(), '-M', '-S', str(control_path(folder)),
             '-fNT', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=15',
             '-o', 'ServerAliveCountMax=3', '-L',
             f'127.0.0.1:{state["port"]}:{state["guest_ip"]}:22', f'lima-{VM}'], timeout=20)


def guest_ssh(state, *argv, check=True, timeout=20):
    return command(['ssh', '-F', '/dev/null', '-i', state['private_key_path'],
                    '-o', 'IdentitiesOnly=yes', '-o', 'BatchMode=yes',
                    '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectTimeout=3',
                    '-o', f'UserKnownHostsFile={state["known_hosts_path"]}',
                    '-p', str(state['port']), f'sandbox@127.0.0.1', *argv],
                   timeout=timeout, check=check)


def wait_ready(state):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            result = guest_ssh(state, 'python3 -c ' + shlex.quote(PING_SCRIPT), check=False, timeout=10)
            if result.returncode == 0:
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(1)
    raise RuntimeError('guest SSH or Docker did not become ready within 180 seconds')


def save_state(folder, state):
    temporary = folder / 'metadata.new'
    temporary.write_text(json.dumps(state))
    temporary.chmod(0o600)
    temporary.replace(folder / 'metadata.json')


def load_state(folder):
    path = folder / 'metadata.json'
    if path.is_symlink():
        raise ValueError('metadata must not be a symlink')
    return json.loads(path.read_text())


def create_network(sandbox_id):
    # One bridge per sandbox makes FORWARD filtering cover sibling traffic.
    for index in range(1, 250):
        name = f'okata-{index}'
        result = nerdctl('network', 'create', '--subnet', f'10.202.{index}.0/24', name, check=False)
        if result.returncode == 0:
            try:
                # CNI prepends ACCEPT chains, so reassert the boundary after network creation.
                vm_command('iptables', '-D', 'FORWARD', '-s', '10.202.0.0/16', '-d', '10.202.0.0/16', '-j', 'DROP', check=False)
                vm_command('iptables', '-I', 'FORWARD', '1', '-s', '10.202.0.0/16', '-d', '10.202.0.0/16', '-j', 'DROP')
                return name
            except Exception:
                nerdctl('network', 'rm', name, check=False)
                raise
    raise RuntimeError('no sandbox network allocation available')


def create(folder, sandbox_id):
    if (folder / 'metadata.json').exists():
        raise ValueError('sandbox already exists')
    if nerdctl('inspect', sandbox_id, check=False).returncode == 0:
        raise ValueError('container already exists without lifecycle metadata')
    client_key = folder / 'client_key'
    host_key = folder / 'host_key'
    for path in (client_key, host_key):
        command(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(path)])
    network = create_network(sandbox_id)
    state = {'sandbox_id': sandbox_id, 'host': '127.0.0.1', 'port': available_port(),
             'username': 'sandbox', 'private_key_path': str(client_key),
             'known_hosts_path': str(folder / 'known_hosts'), 'network': network}
    try:
        nerdctl('create', '--runtime', 'io.containerd.kata.v2', '--name', sandbox_id,
                '--network', network, '--label', 'openshell-kata.managed=true',
                '--cap-add', 'ALL', '--security-opt', 'seccomp=unconfined',
                '--security-opt', 'apparmor=unconfined', '--tmpfs', '/var/lib/docker:rw,size=2147483648',
                '--env', 'DOCKER_TLS_CERTDIR=', IMAGE, '/usr/local/sbin/openshell-kata-init')
        # Only the client PUBLIC key enters the guest. Its private key stays outside the VM.
        stage = command(['limactl', 'shell', VM, 'mktemp', '-d', '/tmp/openshell-kata.XXXXXXXX']).stdout.decode().strip()
        try:
            for source, target in ((client_key.with_suffix('.pub'), 'authorized_keys'),
                                   (host_key, 'ssh_host_ed25519_key')):
                command(['limactl', 'cp', str(source), f'{VM}:{stage}/{target}'])
                nerdctl('cp', f'{stage}/{target}', f'{sandbox_id}:/etc/ssh/{target}')
        finally:
            vm_command('rm', '-rf', '--', stage)
        nerdctl('start', sandbox_id)
        inspection = json.loads(nerdctl('inspect', sandbox_id).stdout)[0]
        state['guest_ip'] = next(iter(inspection['NetworkSettings']['Networks'].values()))['IPAddress']
        public_host_key = host_key.with_suffix('.pub').read_text().strip().split()
        known_hosts = f'[127.0.0.1]:{state["port"]} {public_host_key[0]} {public_host_key[1]}\n'
        Path(state['known_hosts_path']).write_text(known_hosts)
        Path(state['known_hosts_path']).chmod(0o600)
        save_state(folder, state)
        open_tunnel(folder, state)
        wait_ready(state)
        return public_metadata(state)
    except Exception:
        tunnel_control(folder, 'exit')
        nerdctl('rm', '-f', sandbox_id, check=False)
        nerdctl('network', 'rm', network, check=False)
        raise



def require_container_absent(sandbox_id):
    result = nerdctl('inspect', '--mode=native', sandbox_id, check=False)
    if result.returncode == 0:
        raise ValueError('container exists without lifecycle metadata')
    message = result.stderr.decode(errors='replace').strip()
    # Match the pinned nerdctl version's exact single-object NotFound response.
    # A failed connection, partial output, or an error naming another object is not absence.
    pattern = (r'(?:time="[^"\n]+"\s+)?level=fatal msg="1 errors: \[no such object '
               + re.escape(sandbox_id) + r'\]"')
    if (result.returncode == 1 and result.stdout.strip() in (b'', b'[]')
            and re.fullmatch(pattern, message)):
        return
    raise RuntimeError('could not confirm container absence: ' + message[-1500:])


def operate(action, sandbox_id):
    validate_id(sandbox_id)
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', VM):
        raise ValueError('invalid VM name')
    root = private_directory(Path(os.environ.get('OPENSHELL_KATA_STATE_DIR',
                                str(HERE.parent / '.local/runtime'))).absolute())
    # Serialize lifecycle transitions; SSH exec and SFTP do not take this lock.
    with (root / '.lock').open('a') as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        folder = root / sandbox_id
        if action == 'create':
            if folder.exists():
                raise ValueError('sandbox state already exists')
            private_directory(folder)
            try:
                return create(folder, sandbox_id)
            except Exception:
                shutil.rmtree(folder)
                raise
        if folder.is_symlink():
            raise ValueError('invalid sandbox state path')
        if not folder.exists() and action == 'delete':
            require_container_absent(sandbox_id)
            return {}
        if not folder.is_dir():
            raise ValueError('unknown sandbox')
        state = load_state(folder)
        if state['sandbox_id'] != sandbox_id:
            raise ValueError('sandbox state ID mismatch')
        if action == 'start':
            inspection = json.loads(nerdctl('inspect', sandbox_id).stdout)[0]
            if not inspection['State']['Running']:
                nerdctl('start', sandbox_id)
                inspection = json.loads(nerdctl('inspect', sandbox_id).stdout)[0]
            guest_ip = next(iter(inspection['NetworkSettings']['Networks'].values()))['IPAddress']
            if not guest_ip:
                raise RuntimeError('started sandbox has no network address')
            if guest_ip != state['guest_ip']:
                tunnel_control(folder, 'exit')
                state = {**state, 'guest_ip': guest_ip}
                save_state(folder, state)
            open_tunnel(folder, state)
            wait_ready(state)
            return public_metadata(state)
        if action == 'stop':
            tunnel_control(folder, 'exit')
            nerdctl('stop', '--time', '10', sandbox_id)
            return {}
        if action == 'delete':
            tunnel_control(folder, 'exit')
            nerdctl('rm', '-f', sandbox_id)
            nerdctl('network', 'rm', state['network'])
            shutil.rmtree(folder)
            return {}
        raise ValueError('unknown lifecycle action')


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in {'create', 'start', 'stop', 'delete'}:
        raise ValueError('usage: lifecycle.py create|start|stop|delete SANDBOX_ID')
    print(json.dumps(operate(sys.argv[1], sys.argv[2])))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
