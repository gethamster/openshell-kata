import importlib.util
import tempfile
import unittest
import subprocess
from unittest.mock import patch
from pathlib import Path

spec = importlib.util.spec_from_file_location('lifecycle', Path(__file__).with_name('lifecycle.py'))
lifecycle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lifecycle)

class ValidationTests(unittest.TestCase):
    def test_rejects_shell_paths_and_empty_ids(self):
        for value in ['', '../tenant', 'a/b', 'a;echo x', '-flag', 'x' * 97]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                lifecycle.validate_id(value)

    def test_accepts_uuid_and_named_sandbox(self):
        for value in ['17cbfe6c-aa00-4484-aebc-d6ae293636b8', 'sandbox_42']:
            self.assertEqual(value, lifecycle.validate_id(value))

    def test_port_is_bound_to_loopback(self):
        port = lifecycle.available_port()
        self.assertGreater(port, 1024)
        self.assertLessEqual(port, 65535)

    def test_metadata_exposes_only_transport_fields(self):
        result = lifecycle.public_metadata({'sandbox_id': 'a', 'host': '127.0.0.1', 'port': 2300,
            'username': 'sandbox', 'private_key_path': '/private/key', 'known_hosts_path': '/private/known',
            'guest_ip': '10.89.0.2', 'network': 'internal'})
        self.assertEqual(set(result), {'sandbox_id', 'host', 'port', 'username', 'private_key_path', 'known_hosts_path'})

    def test_private_directory_rejects_symlink(self):
        with tempfile.TemporaryDirectory() as root:
            real = Path(root) / 'real'; real.mkdir()
            link = Path(root) / 'link'; link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(ValueError):
                lifecycle.private_directory(link)

class ReadinessTests(unittest.TestCase):
    def test_retries_connection_timeout_instead_of_destroying_guest(self):
        with patch.object(lifecycle, 'guest_ssh', side_effect=[subprocess.TimeoutExpired('ssh', 10), subprocess.CompletedProcess('ssh', 0)] ) as probe, patch.object(lifecycle.time, 'sleep'):
            lifecycle.wait_ready({})
        self.assertEqual(probe.call_count, 2)

    def test_nonzero_probe_retries(self):
        with patch.object(lifecycle, 'guest_ssh', side_effect=[subprocess.CompletedProcess('ssh', 255), subprocess.CompletedProcess('ssh', 0)]) as probe, patch.object(lifecycle.time, 'sleep'):
            lifecycle.wait_ready({})
        self.assertEqual(probe.call_count, 2)

class ControlSocketTests(unittest.TestCase):
    def test_full_uuid_control_paths_fit_macos_temporary_socket_suffix(self):
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            first = Path(temporary) / '11111111-1111-4111-8111-111111111111'
            second = Path(temporary) / '22222222-2222-4222-8222-222222222222'
            one = lifecycle.control_path(first)
            two = lifecycle.control_path(second)
            self.assertNotEqual(one, two)
            self.assertLessEqual(len(str(one).encode()) + 17, 104)
            self.assertEqual(one.parent.stat().st_mode & 0o777, 0o700)

    def test_long_custom_state_root_fails_clearly(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(ValueError, 'too long'):
                lifecycle.control_path(Path(temporary) / ('x' * 90) / 'one')

class StateTests(unittest.TestCase):
    def test_state_is_private_and_atomically_round_trips(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = lifecycle.private_directory(Path(temporary) / 'state')
            lifecycle.save_state(folder, {'sandbox_id': 'one'})
            self.assertEqual(lifecycle.load_state(folder), {'sandbox_id': 'one'})
            self.assertEqual((folder / 'metadata.json').stat().st_mode & 0o777, 0o600)
            self.assertEqual(folder.stat().st_mode & 0o777, 0o700)
            self.assertFalse((folder / 'metadata.new').exists())

    def test_metadata_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            (folder / 'other').write_text('{}')
            (folder / 'metadata.json').symlink_to(folder / 'other')
            with self.assertRaises(ValueError): lifecycle.load_state(folder)

    def test_failed_create_removes_only_its_state(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(lifecycle.os.environ, {'OPENSHELL_KATA_STATE_DIR': temporary}):
            keep = Path(temporary) / 'unrelated'; keep.mkdir()
            with patch.object(lifecycle, 'create', side_effect=RuntimeError('failed')):
                with self.assertRaises(RuntimeError): lifecycle.operate('create', 'new')
            self.assertTrue(keep.is_dir())
            self.assertFalse((Path(temporary) / 'new').exists())

    def test_start_running_guest_does_not_restart_it(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(lifecycle.os.environ, {'OPENSHELL_KATA_STATE_DIR': temporary}):
            folder = Path(temporary) / 'one'; folder.mkdir()
            state = {'sandbox_id':'one', 'host':'127.0.0.1', 'port':2222, 'username':'sandbox', 'private_key_path':'key', 'known_hosts_path':'hosts', 'guest_ip':'10.202.1.2'}
            lifecycle.save_state(folder, state)
            reply = subprocess.CompletedProcess('inspect', 0, b'[{"State":{"Running":true},"NetworkSettings":{"Networks":{"net":{"IPAddress":"10.202.1.2"}}}}]')
            with patch.object(lifecycle, 'nerdctl', return_value=reply) as ctl, patch.object(lifecycle, 'open_tunnel'), patch.object(lifecycle, 'wait_ready'):
                self.assertEqual(lifecycle.operate('start', 'one'), lifecycle.public_metadata(state))
            ctl.assert_called_once_with('inspect', 'one')

    def test_restart_refreshes_changed_ip_before_reopening_tunnel(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(lifecycle.os.environ, {'OPENSHELL_KATA_STATE_DIR': temporary}):
            folder = Path(temporary) / 'one'; folder.mkdir()
            state = {'sandbox_id':'one', 'host':'127.0.0.1', 'port':2222, 'username':'sandbox', 'private_key_path':'key', 'known_hosts_path':'hosts', 'guest_ip':'10.202.1.2'}
            lifecycle.save_state(folder, state)
            stopped = subprocess.CompletedProcess('inspect', 0, b'[{"State":{"Running":false}}]')
            started = subprocess.CompletedProcess('start', 0)
            running = subprocess.CompletedProcess('inspect', 0, b'[{"State":{"Running":true},"NetworkSettings":{"Networks":{"net":{"IPAddress":"10.202.1.3"}}}}]')
            with patch.object(lifecycle, 'nerdctl', side_effect=[stopped, started, running]) as ctl, patch.object(lifecycle, 'tunnel_control') as tunnel, patch.object(lifecycle, 'open_tunnel') as reopen, patch.object(lifecycle, 'wait_ready') as ready:
                result = lifecycle.operate('start', 'one')
            refreshed = {**state, 'guest_ip':'10.202.1.3'}
            self.assertEqual(result, lifecycle.public_metadata(state))
            self.assertEqual(lifecycle.load_state(folder), refreshed)
            self.assertEqual(ctl.call_args_list, [unittest.mock.call('inspect', 'one'), unittest.mock.call('start', 'one'), unittest.mock.call('inspect', 'one')])
            tunnel.assert_called_once_with(folder, 'exit')
            reopen.assert_called_once_with(folder, refreshed)
            ready.assert_called_once_with(refreshed)

    def test_stop_and_delete_call_only_owned_id(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(lifecycle.os.environ, {'OPENSHELL_KATA_STATE_DIR': temporary}):
            folder = Path(temporary) / 'one'; folder.mkdir()
            lifecycle.save_state(folder, {'sandbox_id':'one', 'network':'okata-1'})
            with patch.object(lifecycle, 'nerdctl') as ctl, patch.object(lifecycle, 'tunnel_control'):
                self.assertEqual(lifecycle.operate('stop', 'one'), {})
                ctl.assert_called_once_with('stop', '--time', '10', 'one')
                ctl.reset_mock()
                self.assertEqual(lifecycle.operate('delete', 'one'), {})
                self.assertEqual(ctl.call_args_list, [unittest.mock.call('rm', '-f', 'one'), unittest.mock.call('network', 'rm', 'okata-1')])
            self.assertFalse(folder.exists())

    def test_cross_id_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(lifecycle.os.environ, {'OPENSHELL_KATA_STATE_DIR': temporary}):
            folder = Path(temporary) / 'one'; folder.mkdir()
            lifecycle.save_state(folder, {'sandbox_id':'two'})
            with self.assertRaises(ValueError): lifecycle.operate('stop', 'one')

class IdempotentDeletionTests(unittest.TestCase):
    def test_repeated_delete_accepts_only_confirmed_absence(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(lifecycle.os.environ, {'OPENSHELL_KATA_STATE_DIR': temporary}):
            folder = Path(temporary) / 'one'; folder.mkdir()
            lifecycle.save_state(folder, {'sandbox_id':'one', 'network':'okata-1'})
            missing = subprocess.CompletedProcess('inspect', 1, b'[]\n', b'time="now" level=fatal msg="1 errors: [no such object one]"\n')
            with patch.object(lifecycle, 'nerdctl', side_effect=[subprocess.CompletedProcess('rm',0), subprocess.CompletedProcess('network rm',0), missing]) as ctl, patch.object(lifecycle, 'tunnel_control'):
                self.assertEqual(lifecycle.operate('delete', 'one'), {})
                self.assertEqual(lifecycle.operate('delete', 'one'), {})
            self.assertEqual(ctl.call_args_list[-1], unittest.mock.call('inspect', '--mode=native', 'one', check=False))

    def test_missing_metadata_does_not_authorize_existing_container_deletion(self):
        with tempfile.TemporaryDirectory() as temporary, patch.dict(lifecycle.os.environ, {'OPENSHELL_KATA_STATE_DIR': temporary}), patch.object(lifecycle, 'nerdctl', return_value=subprocess.CompletedProcess('inspect', 0, b'[{}]', b'')) as ctl:
            with self.assertRaisesRegex(ValueError, 'without lifecycle metadata'):
                lifecycle.operate('delete', 'one')
            ctl.assert_called_once_with('inspect', '--mode=native', 'one', check=False)

    def test_transport_failure_is_not_absence(self):
        failure = subprocess.CompletedProcess('inspect', 1, b'', b'failed to dial containerd socket: connection refused')
        with tempfile.TemporaryDirectory() as temporary, patch.dict(lifecycle.os.environ, {'OPENSHELL_KATA_STATE_DIR': temporary}), patch.object(lifecycle, 'nerdctl', return_value=failure) as ctl:
            with self.assertRaisesRegex(RuntimeError, 'confirm'):
                lifecycle.operate('delete', 'one')
            self.assertEqual(ctl.call_count, 1)

    def test_not_found_for_different_id_is_rejected(self):
        failure = subprocess.CompletedProcess('inspect', 1, b'[]', b'level=fatal msg="1 errors: [no such object other]"')
        with tempfile.TemporaryDirectory() as temporary, patch.dict(lifecycle.os.environ, {'OPENSHELL_KATA_STATE_DIR': temporary}), patch.object(lifecycle, 'nerdctl', return_value=failure):
            with self.assertRaises(RuntimeError): lifecycle.operate('delete', 'one')

class ProvisionTests(unittest.TestCase):
    def test_provision_copies_only_client_public_key_and_pins_host_key(self):
        def external(argv, **kwargs):
            if argv[0] == 'ssh-keygen':
                key = Path(argv[-1]); key.write_text('private-placeholder')
                key.with_suffix('.pub').write_text('ssh-ed25519 TEST-PUBLIC comment')
            stdout = b'/tmp/openshell-kata.test\n' if 'mktemp' in argv else b''
            return subprocess.CompletedProcess(argv, 0, stdout, b'')
        def container(*args, **kwargs):
            if args == ('inspect', 'one'):
                if kwargs.get('check') is False:
                    return subprocess.CompletedProcess(args, 1, b'', b'not found')
                return subprocess.CompletedProcess(args, 0, b'[{"NetworkSettings":{"Networks":{"net":{"IPAddress":"10.202.1.2"}}}}]', b'')
            return subprocess.CompletedProcess(args, 0, b'', b'')
        with tempfile.TemporaryDirectory(dir='/tmp') as temporary:
            folder = lifecycle.private_directory(Path(temporary))
            with patch.object(lifecycle, 'command', side_effect=external) as calls, patch.object(lifecycle, 'nerdctl', side_effect=container), patch.object(lifecycle, 'vm_command'), patch.object(lifecycle, 'create_network', return_value='net'), patch.object(lifecycle, 'open_tunnel'), patch.object(lifecycle, 'wait_ready'), patch.object(lifecycle, 'available_port', return_value=2222):
                result = lifecycle.create(folder, 'one')
            self.assertEqual(result['sandbox_id'], 'one')
            self.assertEqual(lifecycle.load_state(folder)['guest_ip'], '10.202.1.2')
            copies = [call.args[0] for call in calls.call_args_list if call.args[0][:2] == ['limactl', 'cp']]
            self.assertEqual(len(copies), 2)
            self.assertTrue(any(str(folder / 'client_key.pub') in call for call in copies))
            self.assertFalse(any(str(folder / 'client_key') in call for call in copies))
            self.assertIn('[127.0.0.1]:2222 ssh-ed25519 TEST-PUBLIC', (folder / 'known_hosts').read_text())

    def test_runtime_command_errors_preserve_diagnostic(self):
        failure = subprocess.CompletedProcess(['tool'], 3, b'', b'operation refused')
        with patch.object(lifecycle.subprocess, 'run', return_value=failure):
            with self.assertRaisesRegex(RuntimeError, 'operation refused'):
                lifecycle.command(['tool'])

    def test_readiness_has_a_total_deadline(self):
        with patch.object(lifecycle.time, 'monotonic', side_effect=[0, 181]):
            with self.assertRaisesRegex(RuntimeError, '180 seconds'):
                lifecycle.wait_ready({})

class BoundaryTests(unittest.TestCase):
    def test_create_refuses_existing_foreign_container(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(lifecycle, 'nerdctl', return_value=subprocess.CompletedProcess('inspect', 0)):
            with self.assertRaises(ValueError): lifecycle.create(Path(temporary), 'one')

    def test_network_creation_reasserts_isolation_first(self):
        with patch.object(lifecycle, 'nerdctl', return_value=subprocess.CompletedProcess('create', 0)), patch.object(lifecycle, 'vm_command') as vm:
            self.assertEqual(lifecycle.create_network('one'), 'okata-1')
        self.assertEqual(vm.call_args.args[:4], ('iptables', '-I', 'FORWARD', '1'))

    def test_network_is_removed_if_filter_cannot_be_installed(self):
        with patch.object(lifecycle, 'nerdctl', return_value=subprocess.CompletedProcess('create', 0)) as ctl, patch.object(lifecycle, 'vm_command', side_effect=RuntimeError('firewall unavailable')):
            with self.assertRaises(RuntimeError): lifecycle.create_network('one')
        self.assertIn(unittest.mock.call('network', 'rm', 'okata-1', check=False), ctl.call_args_list)

    def test_invalid_id_never_runs_external_commands(self):
        with patch.object(lifecycle, 'command') as execute:
            with self.assertRaises(ValueError): lifecycle.operate('create', '../other')
        execute.assert_not_called()

if __name__ == '__main__':
    unittest.main()
