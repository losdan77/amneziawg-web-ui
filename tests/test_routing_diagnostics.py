"""Read-only destination diagnostics exercise the real manager with kernel IO mocked."""
import ast
import base64
import copy
import json
from pathlib import Path
import secrets
import unittest
from unittest.mock import Mock, patch

import test_awg_manager as manager_module
from routing_policy import SelectiveRouting


class RoutingDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        manager_module.ManagerTests.setUp(self)
        self.commands = []
        self.route_override = None
        self.missing_rule = None
        self.server = {
            'id': 'entry', 'name': 'Example entry', 'protocol': 'wireguard',
            'interface': 'wg1', 'subnet': '10.1.0.0/24', 'server_ip': '10.1.0.1',
            'dns': ['1.1.1.1'], 'mode': 'edge_linked', 'routing_state': 'upstream',
            'linked_failover_mode': 'fail_close', 'private_key': 'DO-NOT-EXPOSE-ENTRY-KEY',
            'clients': [{'client_ip': '10.1.0.2', 'client_private_key': 'DO-NOT-EXPOSE-CLIENT-KEY'}],
            'upstream': {'interface': 'wg1-up', 'table_id': 201, 'fwmark': 41001,
                         'routing_mode': 'ai_tiktok', 'endpoint': 'exit.example:51820',
                         'public_key': 'DO-NOT-EXPOSE-PEER-KEY',
                         'private_key': 'DO-NOT-EXPOSE-UPSTREAM-KEY',
                         'preshared_key': 'DO-NOT-EXPOSE-PRESHARED-KEY'},
        }
        self.manager.config['servers'] = [self.server]
        self.manager.execute_command = Mock(side_effect=self.execute)
        self.manager.is_upstream_healthy = Mock(return_value=(True, 8))
        self.manager.save_config = Mock()
        self.resolver = Mock(return_value={
            'addresses': ['104.18.31.77'], 'errors': [],
            'queried_hosts': 1, 'resolved_hosts': 1,
        })
        resolver_patch = patch.object(manager_module, 'resolve_service_hosts', self.resolver)
        resolver_patch.start()
        self.addCleanup(resolver_patch.stop)
        dns_patch = patch.object(SelectiveRouting, '_dns_pid', return_value=12345)
        dns_patch.start()
        self.addCleanup(dns_patch.stop)

    def execute(self, command):
        self.commands.append(command)
        if command.startswith('ipset list awgsel_201'):
            return 'Name: awgsel_201\nNumber of entries: 3\nMembers:\n104.18.31.77 timeout 800\n'
        if command.startswith('ipset list awgpool_201'):
            return 'Name: awgpool_201\nNumber of entries: 2\nMembers:\n160.79.104.0/23 timeout 0\n'
        if command.startswith('ipset test '):
            matched = (('awgsel_201' in command and '104.18.31.77' in command)
                       or ('awgpool_201' in command and '160.79.104.10' in command))
            return 'matched' if matched else ''
        if command.startswith('iptables -t mangle -L AWGSEL_201'):
            return ('Chain AWGSEL_201 (1 references)\n'
                    ' pkts bytes target prot opt in out source destination\n'
                    ' 7 420 MARK all -- * * 0.0.0.0/0 0.0.0.0/0 match-set awgsel_201 dst MARK set 0xa029\n'
                    ' 2 120 MARK all -- * * 0.0.0.0/0 0.0.0.0/0 match-set awgpool_201 dst MARK set 0xa029\n'
                    ' 9 540 CONNMARK all -- * * 0.0.0.0/0 0.0.0.0/0 CONNMARK save\n')
        if command.startswith('iptables -t mangle -C '):
            missing = ((self.missing_rule == 'jump' and 'PREROUTING' in command)
                       or (self.missing_rule == 'dns' and 'match-set awgsel_201' in command)
                       or (self.missing_rule == 'pool' and 'match-set awgpool_201' in command))
            return '' if missing else 'attached'
        if command.startswith('ip -j -4 route get '):
            if self.route_override is not None:
                return self.route_override
            device = 'wg1-up' if 'mark 41001' in command else 'eth0'
            return json.dumps([{'dev': device, 'table': 201 if device == 'wg1-up' else 254}])
        if command.startswith('ip link show '):
            return 'state UNKNOWN'
        return ''

    def test_selected_destination_reports_real_client_route_without_mutation_or_secrets(self):
        before = copy.deepcopy(self.manager.config)
        result = self.manager.get_upstream_diagnostics('entry', 'chatgpt.com')
        self.assertEqual(result['routing_mode'], 'ai_tiktok')
        self.assertTrue(result['classifier']['dns_running'])
        self.assertEqual(result['classifier']['dns_entries'], 3)
        self.assertEqual(result['classifier']['pool_entries'], 2)
        self.assertEqual(result['classifier']['matched_packets'], 9)
        self.assertTrue(result['classifier']['rules_attached'])
        destination = result['destinations'][0]
        self.assertEqual(destination['address'], '104.18.31.77')
        self.assertTrue(destination['dns_match'])
        self.assertTrue(destination['matched'])
        self.assertEqual(destination['route'], 'upstream')
        self.assertEqual(destination['egress'], 'wg1-up')
        self.assertTrue(any('from 10.1.0.2 iif wg1 mark 41001' in command
                            for command in self.commands))
        allowed = ('ipset list ', 'ipset test ', 'iptables -t mangle -L ',
                   'iptables -t mangle -C ', 'ip -j -4 route get ', 'ip link show ', '/usr/bin/awg show ')
        self.assertTrue(all(command.startswith(allowed) for command in self.commands), self.commands)
        self.assertEqual(self.manager.config, before)
        self.manager.save_config.assert_not_called()
        serialized = json.dumps(result)
        self.assertNotIn('DO-NOT-EXPOSE', serialized)
        self.assertNotIn('private_key', serialized)
        self.assertNotIn('preshared_key', serialized)

    def test_public_ip_in_builtin_pool_is_matched_without_dns_lookup(self):
        result = self.manager.get_upstream_diagnostics('entry', '160.79.104.10')
        self.resolver.assert_not_called()
        target = result['destinations'][0]
        self.assertTrue(target['pool_match'])
        self.assertFalse(target['dns_match'])
        self.assertEqual(target['route'], 'upstream')

    def test_ordinary_ip_checks_unmarked_client_route(self):
        result = self.manager.get_upstream_diagnostics('entry', '8.8.4.4')
        target = result['destinations'][0]
        self.assertFalse(target['matched'])
        self.assertEqual(target['route'], 'local')
        queries = [command for command in self.commands if command.startswith('ip -j -4 route get ')]
        self.assertEqual(len(queries), 1)
        self.assertIn('from 10.1.0.2 iif wg1', queries[0])
        self.assertNotIn('mark 41001', queries[0])

    def test_kernel_blackhole_is_reported_as_blocked(self):
        self.route_override = json.dumps([{'type': 'blackhole', 'table': 201}])
        result = self.manager.get_upstream_diagnostics('entry', 'chatgpt.com')
        self.assertEqual(result['destinations'][0]['route'], 'blocked')

    def test_failed_route_query_does_not_claim_a_working_tunnel(self):
        self.route_override = 'not valid JSON'
        result = self.manager.get_upstream_diagnostics('entry', 'chatgpt.com')
        self.assertEqual(result['destinations'][0]['route'], 'unknown')

    def test_dns_failure_is_explained_and_does_not_populate_destinations(self):
        self.resolver.return_value = {'addresses': [], 'errors': ['chatgpt.com'],
                                      'queried_hosts': 1, 'resolved_hosts': 0}
        result = self.manager.get_upstream_diagnostics('entry', 'chatgpt.com')
        self.assertEqual(result['destinations'], [])
        self.assertIn('DNS', ' '.join(result['warnings']))
        self.assertFalse(any('route get ' in command for command in self.commands))

    def test_unmatched_service_warns_about_encrypted_dns_and_client_differences(self):
        self.resolver.return_value['addresses'] = ['104.18.31.99']
        result = self.manager.get_upstream_diagnostics('entry', 'chatgpt.com')
        self.assertFalse(result['destinations'][0]['matched'])
        self.assertEqual(result['destinations'][0]['route'], 'local')
        warnings = ' '.join(result['warnings'])
        self.assertTrue('DoH' in warnings or 'DNS' in warnings, warnings)

    def test_invalid_destination_is_rejected_before_commands_or_dns(self):
        invalid = ('chatgpt.com;id', '$(id)', 'chatgpt.com\nwhoami', 'https://chatgpt.com',
                   'chatgpt.com | id', 'chatgpt.com\'x', '10.0.0.1', '127.0.0.1', '::1')
        for destination in invalid:
            with self.subTest(destination=destination), self.assertRaises(ValueError):
                self.manager.get_upstream_diagnostics('entry', destination)
        self.manager.execute_command.assert_not_called()
        self.resolver.assert_not_called()

    def test_server_identifiers_cannot_be_used_as_shell_input(self):
        self.assertIsNone(self.manager.get_upstream_diagnostics('entry;id', 'chatgpt.com'))
        self.manager.execute_command.assert_not_called()
        self.resolver.assert_not_called()

    def test_vless_domain_match_uses_socket_mark_without_awg_client_source(self):
        self.server['protocol'] = 'vless'
        result = self.manager.get_upstream_diagnostics('entry', 'chatgpt.com')
        self.assertTrue(result['destinations'][0]['dns_match'])
        self.assertEqual(result['destinations'][0]['route'], 'upstream')
        self.assertTrue(any('route get 104.18.31.77 mark 41001' in command for command in self.commands))
        self.assertFalse(any(' from ' in command or ' iif ' in command or 'ipset' in command
                             for command in self.commands))

    def test_vless_builtin_pool_matches_literal_ip(self):
        self.server['protocol'] = 'vless'
        result = self.manager.get_upstream_diagnostics('entry', '160.79.104.10')
        self.assertTrue(result['destinations'][0]['pool_match'])
        self.assertEqual(result['destinations'][0]['route'], 'upstream')
        self.resolver.assert_not_called()

    def test_vless_local_fallback_does_not_use_upstream_mark(self):
        self.server.update(protocol='vless', routing_state='local', linked_failover_mode='fail_open')
        self.manager.is_upstream_healthy.return_value = (False, None)
        result = self.manager.get_upstream_diagnostics('entry', 'chatgpt.com')
        self.assertTrue(result['destinations'][0]['matched'])
        self.assertEqual(result['destinations'][0]['route'], 'local')
        self.assertFalse(any('mark 41001' in command for command in self.commands))
        self.assertIn('fail_open', ' '.join(result['warnings']))

    def test_unsafe_stored_interface_is_rejected_before_kernel_reads(self):
        self.server['upstream']['interface'] = 'wg1-up;id'
        with self.assertRaises(ValueError):
            self.manager.get_upstream_diagnostics('entry', '104.18.31.77')
        self.manager.execute_command.assert_not_called()

    def test_set_membership_without_prerouting_jump_does_not_claim_upstream(self):
        self.missing_rule = 'jump'
        result = self.manager.get_upstream_diagnostics('entry', '104.18.31.77')
        self.assertTrue(result['destinations'][0]['matched'])
        self.assertTrue(result['destinations'][0]['dns_match'])
        self.assertFalse(result['classifier']['rules_attached'])
        self.assertEqual(result['destinations'][0]['route'], 'local')
        self.assertFalse(any('mark 41001' in command for command in self.commands
                             if command.startswith('ip -j -4 route get ')))

    def test_missing_matching_mark_rule_does_not_claim_upstream(self):
        for rule, address in (('dns', '104.18.31.77'), ('pool', '160.79.104.10')):
            with self.subTest(rule=rule):
                self.missing_rule = rule
                self.commands.clear()
                result = self.manager.get_upstream_diagnostics('entry', address)
                self.assertTrue(result['destinations'][0]['matched'])
                self.assertFalse(result['classifier']['rules_attached'])
                self.assertEqual(result['destinations'][0]['route'], 'local')
                self.assertFalse(any('mark 41001' in command for command in self.commands
                                     if command.startswith('ip -j -4 route get ')))

    def test_unrelated_missing_classifier_rule_does_not_hide_a_working_route(self):
        self.missing_rule = 'pool'
        result = self.manager.get_upstream_diagnostics('entry', '104.18.31.77')
        self.assertFalse(result['classifier']['rules_attached'])
        self.assertTrue(result['destinations'][0]['dns_match'])
        self.assertEqual(result['destinations'][0]['route'], 'upstream')


class RoutingDiagnosticsApiTests(unittest.TestCase):
    def setUp(self):
        try:
            from flask import Flask, Response, jsonify, request
        except ImportError:
            self.skipTest('Flask is unavailable')
        application = Flask(__name__)
        self.manager = Mock()
        namespace = dict(app=application, Response=Response, jsonify=jsonify, request=request,
                         secrets=secrets, ADMIN_USERNAME='fixture', ADMIN_PASSWORD='fixture-pass',
                         PUBLIC_SERVER_SUBSCRIPTIONS=False, amnezia_manager=self.manager)
        source = Path(__file__).resolve().parents[1] / 'web-ui' / 'app.py'
        tree = ast.parse(source.read_text(encoding='utf-8'))
        names = {'_admin_auth_ok', '_admin_auth_required', 'protect_admin_api', 'upstream_diagnostics'}
        tree.body = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name in names]
        exec(compile(tree, str(source), 'exec'), namespace)
        self.client = application.test_client()
        self.headers = {'Authorization': 'Basic ' + base64.b64encode(b'fixture:fixture-pass').decode()}

    def test_diagnostics_requires_admin_authentication(self):
        path = '/api/servers/entry/upstream/diagnostics'
        self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.client.get(path, headers={'Authorization': 'Basic Zm9vOmJhcg=='}).status_code, 401)
        self.manager.get_upstream_diagnostics.assert_not_called()

    def test_get_forwards_destination_and_handles_missing_or_invalid_input(self):
        path = '/api/servers/entry/upstream/diagnostics'
        self.manager.get_upstream_diagnostics.return_value = {'destinations': [], 'warnings': []}
        response = self.client.get(path + '?destination=160.79.104.10', headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.manager.get_upstream_diagnostics.assert_called_once_with('entry', '160.79.104.10')
        self.manager.get_upstream_diagnostics.return_value = None
        self.assertEqual(self.client.get(path, headers=self.headers).status_code, 404)
        self.manager.get_upstream_diagnostics.side_effect = ValueError('Invalid domain')
        self.assertEqual(self.client.get(path, headers=self.headers).status_code, 400)
        self.manager.get_upstream_diagnostics.side_effect = RuntimeError('SECRET ERROR DETAIL')
        response = self.client.get(path, headers=self.headers)
        self.assertEqual(response.status_code, 500)
        self.assertNotIn(b'SECRET', response.data)
        self.assertEqual(self.client.post(path, headers=self.headers).status_code, 405)


if __name__ == '__main__':
    unittest.main()
