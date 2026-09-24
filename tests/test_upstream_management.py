"""Live upstream edits use the real manager and real files, with Linux commands faked."""
import ast
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import Mock

import test_awg_manager as manager_module
from awg_protocol import generate_params, render_params


class UpstreamManagementTests(unittest.TestCase):
    server = manager_module.ManagerTests.server
    client = manager_module.ManagerTests.client

    def setUp(self):
        manager_module.ManagerTests.setUp(self)
        self.live = set()
        self.commands = []
        self.manager.execute_command = Mock(side_effect=self.execute)
        self.manager.is_interface_running = Mock(side_effect=lambda name: name in self.live)
        self.manager.configure_upstream_routing = Mock(return_value=True)
        self.manager.cleanup_upstream_routing = Mock(return_value=True)
        self.manager.configure_wireguard_fail_closed_routing = Mock(return_value=True)
        self.manager.setup_iptables = Mock(return_value=True)
        self.manager.cleanup_iptables = Mock(return_value=True)

    def execute(self, command):
        self.commands.append(command)
        if command.startswith('ip link show '):
            return 'state UNKNOWN' if command.split()[3] in self.live else None
        if command.startswith('/usr/bin/awg-quick up '):
            self.live.add(command.split()[2])
        if command.startswith('/usr/bin/awg-quick down '):
            self.live.discard(command.split()[2])
        return 'public'

    @staticmethod
    def imported_config(version='2', address='10.8.0.2/32', mtu=1280):
        params = generate_params(version=version)
        return (f'[Interface]\nPrivateKey = {manager_module.IMPORT_PRIVATE_KEY}\n'
                f'Address = {address}\nMTU = {mtu}\n' + render_params(params) +
                f'[Peer]\nPublicKey = {manager_module.IMPORT_PUBLIC_KEY}\nEndpoint = 192.0.2.5:51820\n'
                'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 15-30\n')

    def provision(self, entry='2', running=True):
        server = self.server(awg_version=entry)
        client = self.client(server)
        peer = '\r\n# retained client\r\n[Peer]\r\nPublicKey = public-client\r\nAllowedIPs = 10.0.0.2/32\r\n'
        with open(server['config_path'], 'ab') as config:
            config.write(peer.encode())
        if running:
            self.live.add(server['interface'])
            server['status'] = 'running'
        self.manager.save_config()
        self.entry_before = Path(server['config_path']).read_bytes()
        self.client_before = copy.deepcopy(client)
        self.clients_before = copy.deepcopy(server['clients'])
        self.commands.clear()
        return server

    def assert_entry_unchanged(self, server):
        self.assertEqual(Path(server['config_path']).read_bytes(), self.entry_before)
        self.assertEqual(server['clients'], self.clients_before)
        self.assertEqual(self.manager.config['clients']['c1'], self.client_before)
        self.assertFalse(any(command.startswith(f'/usr/bin/awg-quick down {server["interface"]} ')
                             or command == f'/usr/bin/awg-quick up {server["interface"]}'
                             for command in self.commands))

    def attach(self, server, **data):
        return self.manager.update_server_upstream(server['id'], {
            'import_config': self.imported_config(), 'routing_mode': 'all', **data})

    def test_running_awg2_and_awg3_attach_both_upstream_versions(self):
        for entry in ('2', '3'):
            for upstream in ('2', '3'):
                with self.subTest(entry=entry, upstream=upstream):
                    self.setUp()
                    server = self.provision(entry)
                    before = copy.deepcopy(server)
                    self.attach(server, import_config=self.imported_config(upstream, mtu=1400))
                    self.assert_entry_unchanged(server)
                    self.assertEqual(server['mtu'], before['mtu'])
                    self.assertEqual(server['obfuscation_params'], before['obfuscation_params'])
                    self.assertEqual(server['awg_version'], entry)
                    self.assertEqual(server['upstream']['awg_version'], upstream)
                    self.assertEqual(server['upstream']['mtu'], 1400)
                    self.assertEqual(server['status'], 'running')
                    self.assertIn(server['interface'], self.live)
                    self.assertIn(server['upstream']['interface'], self.live)
                    self.assertIn('MTU = 1400', Path(server['upstream']['config_path']).read_text())
                    guard_index = next(index for index, command in enumerate(self.commands) if command.startswith('iptables -I FORWARD 1 '))
                    up_index = next(index for index, command in enumerate(self.commands) if 'awg-quick up' in command)
                    self.assertLess(guard_index, up_index)
                    self.assertTrue(self.commands[-1].startswith('iptables -D FORWARD '))
                    self.assertEqual(json.loads(Path(manager_module.CONFIG_FILE).read_text()), self.manager.config)

    def test_stopped_entry_is_not_started_and_its_status_is_preserved(self):
        server = self.provision(running=False)
        self.attach(server, routing_mode='ai_tiktok')
        self.assert_entry_unchanged(server)
        self.assertEqual(server['status'], 'stopped')
        self.assertFalse(self.live)
        self.manager.setup_iptables.assert_not_called()
        self.assertFalse(any('awg-quick' in command for command in self.commands))

    def test_edit_policy_without_import_keeps_upstream_keys_and_config_bytes(self):
        server = self.provision()
        self.attach(server)
        upstream = copy.deepcopy(server['upstream'])
        content = Path(upstream['config_path']).read_bytes()
        self.manager.update_server_upstream(server['id'], {'routing_mode': 'ai_tiktok', 'failover_mode': 'fail_open'})
        self.assert_entry_unchanged(server)
        self.assertEqual(server['upstream'], dict(upstream, routing_mode='ai_tiktok', split_ru_local=False))
        self.assertEqual(Path(upstream['config_path']).read_bytes(), content)
        self.assertEqual(server['linked_failover_mode'], 'fail_open')
        self.manager.update_server_upstream(server['id'], {'split_ru_local': True})
        self.assertEqual(server['upstream']['routing_mode'], 'ru_split')

    def test_custom_service_ranges_are_normalized_preserved_and_explicitly_cleared(self):
        for version in ('2', '3'):
            with self.subTest(version=version):
                self.setUp()
                server = self.provision(version)
                self.attach(server, routing_mode='ai_tiktok', service_cidrs=[
                    '104.18.31.77', '8.8.4.7/24', '104.18.31.77/32'])
                expected = ['8.8.4.0/24', '104.18.31.77/32']
                self.assertEqual(server['upstream']['service_cidrs'], expected)
                path = Path(server['upstream']['config_path'])
                imported_bytes = path.read_bytes()
                imported_keys = {key: server['upstream'].get(key) for key in
                                 ('private_key', 'public_key', 'preshared_key')}
                persisted = json.loads(Path(manager_module.CONFIG_FILE).read_text())
                self.assertEqual(persisted['servers'][0]['upstream']['service_cidrs'], expected)
                self.manager.update_server_upstream(server['id'], {'failover_mode': 'fail_open'})
                self.assertEqual(server['upstream']['service_cidrs'], expected)
                self.assertEqual(path.read_bytes(), imported_bytes)
                self.manager.update_server_upstream(server['id'], {'service_cidrs': []})
                self.assertEqual(server['upstream']['service_cidrs'], [])
                self.assertEqual(path.read_bytes(), imported_bytes)
                self.assertEqual({key: server['upstream'].get(key) for key in imported_keys}, imported_keys)
                persisted = json.loads(Path(manager_module.CONFIG_FILE).read_text())
                self.assertEqual(persisted['servers'][0]['upstream']['service_cidrs'], [])
                self.assert_entry_unchanged(server)

    def test_upstream_replacement_without_service_ranges_preserves_custom_selection(self):
        server = self.provision()
        self.attach(server, routing_mode='ai_tiktok', service_cidrs=['8.8.4.0/24'])
        self.manager.update_server_upstream(server['id'], {'import_config': self.imported_config('3')})
        self.assertEqual(server['upstream']['service_cidrs'], ['8.8.4.0/24'])
        self.assertEqual(server['upstream']['awg_version'], '3')
        self.assert_entry_unchanged(server)

    def test_invalid_service_ranges_leave_running_link_and_files_untouched(self):
        server = self.provision()
        self.attach(server, routing_mode='ai_tiktok', service_cidrs=['8.8.4.0/24'])
        before = copy.deepcopy(self.manager.config)
        paths = [Path(manager_module.CONFIG_FILE), Path(server['config_path']),
                 Path(server['upstream']['config_path'])]
        files = {path: path.read_bytes() for path in paths}
        before_live = self.live.copy()
        self.commands.clear()
        self.manager.configure_upstream_routing.reset_mock()
        self.manager.cleanup_upstream_routing.reset_mock()
        invalid = (['0.0.0.0/0'], ['10.0.0.0/8'], ['127.0.0.1'], ['100.64.0.0/10'],
                   ['2001:4860::/32'], ['8.8.4.4;id'], ['8.8.4.4\n'], '8.8.4.4', [True])
        for ranges in invalid:
            with self.subTest(ranges=ranges), self.assertRaises(ValueError):
                self.manager.update_server_upstream(server['id'], {'service_cidrs': ranges})
        self.assertEqual(self.manager.config, before)
        self.assertEqual(self.live, before_live)
        self.assertEqual(self.commands, [])
        for path, content in files.items():
            self.assertEqual(path.read_bytes(), content)
        self.manager.configure_upstream_routing.assert_not_called()
        self.manager.cleanup_upstream_routing.assert_not_called()
        self.assert_entry_unchanged(server)

    def test_failed_service_range_update_restores_previous_pool_selection_and_files(self):
        server = self.provision()
        self.attach(server, routing_mode='ai_tiktok', service_cidrs=['8.8.4.0/24'])
        before = copy.deepcopy(self.manager.config)
        paths = [Path(manager_module.CONFIG_FILE), Path(server['config_path']),
                 Path(server['upstream']['config_path'])]
        files = {path: path.read_bytes() for path in paths}
        attempted_ranges = []

        def apply_then_fail_once(current):
            attempted_ranges.append(copy.deepcopy(current['upstream']['service_cidrs']))
            return len(attempted_ranges) > 1

        self.manager.configure_upstream_routing.side_effect = apply_then_fail_once
        with self.assertRaisesRegex(RuntimeError, 'previous configuration was restored'):
            self.manager.update_server_upstream(server['id'], {'service_cidrs': ['104.18.31.77/32']})
        self.assertEqual(attempted_ranges, [['104.18.31.77/32'], ['8.8.4.0/24']])
        self.assertEqual(self.manager.config, before)
        for path, content in files.items():
            self.assertEqual(path.read_bytes(), content)
        self.assertIn(server['upstream']['interface'], self.live)
        self.assert_entry_unchanged(server)

    def test_replacing_import_retains_routing_identifiers_and_selected_policy(self):
        server = self.provision()
        self.attach(server, routing_mode='ai_tiktok')
        old = copy.deepcopy(server['upstream'])
        self.manager.update_server_upstream(server['id'], {'import_config': self.imported_config('3')})
        for field in ('interface', 'table_id', 'config_path', 'routing_mode'):
            self.assertEqual(server['upstream'][field], old[field])
        self.assertEqual(server['upstream']['awg_version'], '3')
        self.assert_entry_unchanged(server)

    def test_detach_running_and_stopped_entries_preserves_clients(self):
        for running in (True, False):
            with self.subTest(running=running):
                self.setUp()
                server = self.provision(running=running)
                self.attach(server)
                upstream = copy.deepcopy(server['upstream'])
                self.manager.remove_server_upstream(server['id'])
                self.assert_entry_unchanged(server)
                self.assertEqual(server['mode'], 'standalone')
                self.assertIsNone(server['upstream'])
                self.assertEqual(server['egress_interface'], 'eth+')
                self.assertFalse(Path(upstream['config_path']).exists())
                self.assertNotIn(upstream['interface'], self.live)
                self.assertEqual(server['interface'] in self.live, running)

    def test_failed_attach_restores_config_disk_and_local_forwarding(self):
        server = self.provision()
        before = copy.deepcopy(self.manager.config)
        persisted = Path(manager_module.CONFIG_FILE).read_bytes()
        self.manager.configure_upstream_routing.return_value = False
        with self.assertRaisesRegex(RuntimeError, 'previous configuration was restored'):
            self.attach(server)
        self.assertEqual(self.manager.config, before)
        self.assertEqual(Path(manager_module.CONFIG_FILE).read_bytes(), persisted)
        self.assertEqual(self.live, {server['interface']})
        self.assertFalse(Path(self.directory.name, server['interface'] + '-up.conf').exists())
        self.manager.setup_iptables.assert_called_with(server['interface'], server['subnet'], 'eth+')
        self.assert_entry_unchanged(server)

    def test_failed_replacement_restores_old_link_and_exact_configuration(self):
        server = self.provision()
        self.attach(server)
        before = copy.deepcopy(self.manager.config)
        path = Path(server['upstream']['config_path'])
        path.write_bytes(path.read_bytes().replace(b'\n', b'\r\n') + b'# keep comment\r\n')
        previous_bytes = path.read_bytes()
        self.manager.configure_upstream_routing.side_effect = [False, True]
        with self.assertRaisesRegex(RuntimeError, 'previous configuration was restored'):
            self.attach(server, import_config=self.imported_config('3'))
        self.assertEqual(self.manager.config, before)
        self.assertEqual(path.read_bytes(), previous_bytes)
        self.assertIn(server['upstream']['interface'], self.live)
        self.assert_entry_unchanged(server)

    def test_failed_persistence_on_detach_restores_file_and_live_upstream(self):
        server = self.provision()
        self.attach(server)
        before = copy.deepcopy(self.manager.config)
        persisted = Path(manager_module.CONFIG_FILE).read_bytes()
        path = Path(server['upstream']['config_path'])
        upstream_bytes = path.read_bytes()
        self.manager.save_config = Mock(side_effect=OSError('disk full'))
        with self.assertRaisesRegex(RuntimeError, 'previous configuration was restored'):
            self.manager.remove_server_upstream(server['id'])
        self.assertEqual(self.manager.config, before)
        self.assertEqual(Path(manager_module.CONFIG_FILE).read_bytes(), persisted)
        self.assertEqual(path.read_bytes(), upstream_bytes)
        self.assertIn(server['upstream']['interface'], self.live)
        self.assert_entry_unchanged(server)

    def test_forwarding_failure_rolls_back_and_guard_is_released_last(self):
        server = self.provision()
        before = copy.deepcopy(self.manager.config)
        self.manager.setup_iptables.side_effect = [False, True]
        with self.assertRaisesRegex(RuntimeError, 'previous configuration was restored'):
            self.attach(server)
        self.assertEqual(self.manager.config, before)
        self.assertTrue(self.commands[-1].startswith('iptables -D FORWARD '))

    def test_failed_atomic_write_restores_previous_upstream_bytes(self):
        server = self.provision()
        self.attach(server)
        before = copy.deepcopy(self.manager.config)
        path = Path(server['upstream']['config_path'])
        previous_bytes = path.read_bytes()
        atomic_write = self.manager._atomic_config_write
        failed = False

        def fail_after_first_replace(destination, content):
            nonlocal failed
            atomic_write(destination, content)
            if destination == str(path) and not failed:
                failed = True
                raise OSError('failed after replace')

        self.manager._atomic_config_write = fail_after_first_replace
        with self.assertRaisesRegex(RuntimeError, 'previous configuration was restored'):
            self.attach(server, import_config=self.imported_config('3'))
        self.assertEqual(path.read_bytes(), previous_bytes)
        self.assertEqual(self.manager.config, before)
        self.assertIn(server['upstream']['interface'], self.live)

    def test_guard_install_failure_does_not_touch_existing_routes_or_files(self):
        server = self.provision()
        before = copy.deepcopy(self.manager.config)

        def fail_guard(command):
            return None if command.startswith('iptables -I FORWARD 1 ') else self.execute(command)

        self.manager.execute_command.side_effect = fail_guard
        with self.assertRaisesRegex(RuntimeError, 'previous configuration was restored'):
            self.attach(server)
        self.assertEqual(self.manager.config, before)
        self.manager.cleanup_iptables.assert_not_called()
        self.manager.configure_upstream_routing.assert_not_called()
        self.assertEqual(self.live, {server['interface']})

    def test_retained_recovery_guard_rejects_retry_without_mutating_link(self):
        server = self.provision()
        self.attach(server)
        before = copy.deepcopy(self.manager.config)
        files = {path: Path(path).read_bytes() for path in (manager_module.CONFIG_FILE,
                 server['config_path'], server['upstream']['config_path'])}
        self.commands.clear()
        self.manager.cleanup_upstream_routing.reset_mock()
        self.manager.execute_command.side_effect = lambda command: 'blocked' if command.startswith('if iptables -C FORWARD ') else self.execute(command)
        with self.assertRaisesRegex(ValueError, 'needs recovery'):
            self.manager.update_server_upstream(server['id'], {'routing_mode': 'ai_tiktok'})
        self.assertEqual(self.manager.config, before)
        for path, content in files.items():
            self.assertEqual(Path(path).read_bytes(), content)
        self.manager.cleanup_upstream_routing.assert_not_called()
        self.assertFalse(any('awg-quick' in command or command.startswith('iptables -I ') for command in self.commands))

    def test_legacy_shared_table_is_reallocated_on_policy_edit(self):
        server = self.provision()
        self.attach(server)
        old_table = server['upstream']['table_id']
        second = self.server(awg_version='3', subnet='10.9.0.0/24')
        second.update(mode='edge_linked', upstream={'table_id': old_table, 'fwmark': 40960,
                      'interface': 'wg-other-up', 'local_address': '10.8.0.3/32'})
        before_second = copy.deepcopy(second)
        self.manager.update_server_upstream(server['id'], {'routing_mode': 'ai_tiktok'})
        self.assertNotEqual(server['upstream']['table_id'], old_table)
        self.assertNotEqual(server['upstream']['fwmark'], 40960)
        self.assertEqual(second, before_second)
        self.assert_entry_unchanged(server)

    def test_failed_rollback_leaves_guard_and_reports_blocked_traffic(self):
        server = self.provision()
        self.attach(server)
        self.commands.clear()
        self.manager.configure_upstream_routing.return_value = False
        with self.assertRaisesRegex(RuntimeError, 'traffic is blocked'):
            self.attach(server, import_config=self.imported_config('3'))
        self.assertFalse(any(c.startswith('iptables -D FORWARD ') for c in self.commands))

    def test_local_fallback_is_restored_on_failed_edit(self):
        server = self.provision()
        self.attach(server)
        server.update(routing_state='local', egress_interface='eth+', linked_failover_mode='fail_open')
        self.manager.save_config()
        self.manager.configure_upstream_routing.side_effect = [False, True]
        with self.assertRaises(RuntimeError):
            self.manager.update_server_upstream(server['id'], {'routing_mode': 'ai_tiktok'})
        self.assertEqual(server['routing_state'], 'local')
        self.manager.cleanup_upstream_routing.assert_called_with(server, preserve_classifier=False)

    def test_selective_local_fallback_keeps_dns_learning_after_failed_edit(self):
        server = self.provision()
        self.attach(server, routing_mode='ai_tiktok')
        server.update(routing_state='local', egress_interface='eth+', linked_failover_mode='fail_open')
        self.manager.save_config()
        self.manager.configure_upstream_routing.side_effect = [False, True]
        with self.assertRaises(RuntimeError):
            self.manager.update_server_upstream(server['id'], {'routing_mode': 'all'})
        self.assertEqual(server['routing_state'], 'local')
        self.manager.cleanup_upstream_routing.assert_called_with(server, preserve_classifier=True)
        self.assertTrue(Path(self.directory.name, 'routing', f"dns-{server['upstream']['table_id']}.conf").exists())

    def test_missing_old_interface_restores_fail_closed_policy(self):
        server = self.provision()
        self.attach(server)
        self.live.discard(server['upstream']['interface'])
        self.manager.configure_upstream_routing.return_value = False
        with self.assertRaises(RuntimeError):
            self.manager.update_server_upstream(server['id'], {'routing_mode': 'ru_split'})
        self.manager.configure_wireguard_fail_closed_routing.assert_called_with(server)

    def test_invalid_policy_import_type_and_overlapping_network_are_rejected_before_mutation(self):
        server = self.provision()
        before = copy.deepcopy(self.manager.config)
        for data in ({}, [], {'import_config': 4}, {'routing_mode': 'typo'},
                     {'import_config': self.imported_config(), 'failover_mode': 'bad'},
                     {'import_config': self.imported_config(address='10.0.0.2/32')}):
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    self.manager.update_server_upstream(server['id'], data)
        self.assertEqual(self.manager.config, before)
        self.assertFalse(any('iptables' in command or 'awg-quick' in command for command in self.commands))

    def test_import_cannot_overlap_another_local_entry_or_upstream(self):
        server = self.provision()
        other = self.server(awg_version='3', subnet='10.8.0.0/24')
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            self.attach(server)
        other['subnet'] = '10.9.0.0/24'
        other['upstream'] = {'interface': 'other-up', 'local_address': '10.8.0.2/32'}
        with self.assertRaisesRegex(ValueError, 'overlaps'):
            self.attach(server)

    def test_unmanaged_interface_and_configuration_are_never_overwritten(self):
        server = self.provision()
        interface = server['interface'] + '-up'
        self.live.add(interface)
        with self.assertRaisesRegex(ValueError, 'unmanaged network interface'):
            self.attach(server)
        self.live.remove(interface)
        path = Path(self.directory.name, interface + '.conf')
        path.write_bytes(b'private unmanaged file\r\n')
        with self.assertRaisesRegex(ValueError, 'unmanaged configuration'):
            self.attach(server)
        self.assertEqual(path.read_bytes(), b'private unmanaged file\r\n')

    def test_unknown_server_returns_none_and_standalone_detach_is_idempotent(self):
        self.assertIsNone(self.manager.update_server_upstream('missing', {}))
        self.assertIsNone(self.manager.remove_server_upstream('missing'))
        server = self.provision()
        before = copy.deepcopy(server)
        self.assertEqual(self.manager.remove_server_upstream(server['id']), before)


class UpstreamApiTests(unittest.TestCase):
    def setUp(self):
        try:
            from flask import Flask, jsonify, request
        except ImportError:
            self.skipTest('Flask is unavailable')
        self.manager = Mock()
        application = Flask(__name__)
        namespace = dict(app=application, jsonify=jsonify, request=request, amnezia_manager=self.manager)
        source = Path(__file__).resolve().parents[1] / 'web-ui' / 'app.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == 'manage_server_upstream']
        exec(compile(tree, str(source), 'exec'), namespace)
        self.client = application.test_client()

    def test_put_delete_and_errors(self):
        self.manager.update_server_upstream.return_value = {'id': 'one', 'mode': 'edge_linked'}
        response = self.client.put('/api/servers/one/upstream', json={'routing_mode': 'ai_tiktok'})
        self.assertEqual(response.status_code, 200)
        self.manager.update_server_upstream.assert_called_once_with('one', {'routing_mode': 'ai_tiktok'})
        self.manager.remove_server_upstream.return_value = {'id': 'one', 'mode': 'standalone'}
        self.assertEqual(self.client.delete('/api/servers/one/upstream').status_code, 200)
        self.manager.update_server_upstream.return_value = None
        self.assertEqual(self.client.put('/api/servers/missing/upstream', json={}).status_code, 404)
        for payload in ([], None, 'not an object'):
            self.assertEqual(self.client.put('/api/servers/one/upstream', json=payload).status_code, 400)
        self.manager.update_server_upstream.side_effect = ValueError('invalid policy')
        self.assertEqual(self.client.put('/api/servers/one/upstream', json={}).status_code, 400)
        self.manager.update_server_upstream.side_effect = RuntimeError('previous configuration was restored')
        self.assertEqual(self.client.put('/api/servers/one/upstream', json={}).status_code, 500)


if __name__ == '__main__':
    unittest.main()
