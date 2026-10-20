"""Manager integration for domain-based AWG service selection.

Exercise actual persistence, transaction rollback and policy generation; only
Linux commands and the external transparent routing process are replaced.
"""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import test_awg_manager as manager_module
import test_routing_manager as routing_tests
import test_routing_diagnostics as diagnostic_tests
import test_upstream_management as upstream_tests
from service_domains import DEFAULT_SELECTED_SERVICES


class SelectedServiceManagementTests(unittest.TestCase):
    server = upstream_tests.UpstreamManagementTests.server
    client = upstream_tests.UpstreamManagementTests.client
    execute = upstream_tests.UpstreamManagementTests.execute
    imported_config = staticmethod(upstream_tests.UpstreamManagementTests.imported_config)
    provision = upstream_tests.UpstreamManagementTests.provision
    assert_entry_unchanged = upstream_tests.UpstreamManagementTests.assert_entry_unchanged
    attach = upstream_tests.UpstreamManagementTests.attach
    setUp = upstream_tests.UpstreamManagementTests.setUp

    def test_creation_and_live_awg2_awg3_edits_preserve_clients_and_credentials(self):
        for version in ('2', '3'):
            with self.subTest(version=version):
                self.setUp()
                server = self.provision(version)
                original_keys = {key: server.get(key) for key in ('private_key', 'public_key')}
                self.attach(server, routing_mode='selected_services')
                self.assertEqual(server['upstream']['selected_services'], list(DEFAULT_SELECTED_SERVICES))
                upstream_before = copy.deepcopy(server['upstream'])
                content = Path(upstream_before['config_path']).read_bytes()
                self.manager.update_server_upstream(server['id'], {
                    'selected_services': ['claude', 'tiktok', 'claude']})
                self.assertEqual(server['upstream']['selected_services'], ['claude', 'tiktok'])
                for key in ('private_key', 'public_key', 'preshared_key', 'table_id', 'fwmark', 'interface'):
                    self.assertEqual(server['upstream'].get(key), upstream_before.get(key))
                self.assertEqual({key: server.get(key) for key in original_keys}, original_keys)
                self.assertEqual(Path(upstream_before['config_path']).read_bytes(), content)
                self.assert_entry_unchanged(server)
                self.manager.update_server_upstream(server['id'], {'selected_services': []})
                self.assertEqual(server['upstream']['selected_services'], [])
                self.manager.update_server_upstream(server['id'], {'failover_mode': 'fail_open'})
                self.assertEqual(server['upstream']['selected_services'], [])
                persisted = json.loads(Path(manager_module.CONFIG_FILE).read_text())
                self.assertEqual(persisted['servers'][0]['upstream']['selected_services'], [])
                reloaded = self.manager.load_config()
                self.assertEqual(reloaded['servers'][0]['upstream']['selected_services'], [])
                self.assert_entry_unchanged(server)
                self.assertTrue(any(c.startswith('iptables -I INPUT 1 ') for c in self.commands))
                self.assertTrue(any(c.startswith('iptables -D INPUT ') for c in self.commands))

    def test_new_linked_server_persists_default_and_explicit_empty_selection(self):
        for services in (None, []):
            with self.subTest(services=services):
                self.setUp()
                data = {'import_config': self.imported_config(), 'routing_mode': 'selected_services'}
                if services is not None:
                    data['selected_services'] = services
                server = self.server(mode='edge_linked', upstream=data)
                expected = list(DEFAULT_SELECTED_SERVICES) if services is None else []
                self.assertEqual(server['upstream']['selected_services'], expected)
                self.assertEqual(json.loads(Path(manager_module.CONFIG_FILE).read_text())['servers'][0]['upstream']['selected_services'], expected)

    def test_invalid_service_choice_never_changes_config_files_or_live_interface(self):
        server = self.provision()
        self.attach(server, routing_mode='selected_services', selected_services=['claude'])
        before = copy.deepcopy(self.manager.config)
        paths = [Path(manager_module.CONFIG_FILE), Path(server['config_path']), Path(server['upstream']['config_path'])]
        files = {path: path.read_bytes() for path in paths}
        before_live = self.live.copy()
        self.commands.clear()
        invalid = ('claude', {}, True, ['youtube'], [True], [1], ['claude;id'], [['claude']])
        for services in invalid:
            with self.subTest(services=services), self.assertRaises(ValueError):
                self.manager.update_server_upstream(server['id'], {'selected_services': services})
        self.assertEqual(self.manager.config, before)
        self.assertEqual(self.live, before_live)
        self.assertEqual(self.commands, [])
        for path, content in files.items():
            self.assertEqual(path.read_bytes(), content)

    def test_switching_to_domain_mode_retains_broad_profile_and_custom_addresses(self):
        server = self.provision()
        self.attach(server, routing_mode='ai_tiktok', service_ip_profile='expanded', service_cidrs=['8.8.8.0/24'])
        self.manager.update_server_upstream(server['id'], {'routing_mode': 'selected_services', 'selected_services': ['tiktok']})
        self.assertEqual(server['upstream']['service_ip_profile'], 'expanded')
        self.assertEqual(server['upstream']['service_cidrs'], ['8.8.8.0/24'])
        self.manager.update_server_upstream(server['id'], {'routing_mode': 'ai_tiktok'})
        self.assertEqual(server['upstream']['selected_services'], ['tiktok'])
        self.assertEqual(server['upstream']['service_ip_profile'], 'expanded')
        self.assert_entry_unchanged(server)

    def test_replacement_config_retains_selected_services(self):
        server = self.provision()
        self.attach(server, routing_mode='selected_services', selected_services=['claude'])
        self.manager.update_server_upstream(server['id'], {'import_config': self.imported_config('3')})
        self.assertEqual(server['upstream']['selected_services'], ['claude'])
        self.assertEqual(server['upstream']['routing_mode'], 'selected_services')
        self.assert_entry_unchanged(server)

    def test_failed_live_service_change_restores_prior_selection_and_releases_both_guards(self):
        for version in ('2', '3'):
            with self.subTest(version=version):
                self.setUp()
                server = self.provision(version)
                self.attach(server, routing_mode='selected_services', selected_services=['claude'])
                before = copy.deepcopy(self.manager.config)
                paths = [Path(manager_module.CONFIG_FILE), Path(server['config_path']), Path(server['upstream']['config_path'])]
                files = {path: path.read_bytes() for path in paths}
                attempted = []
                def apply(current):
                    attempted.append(copy.deepcopy(current['upstream']['selected_services']))
                    return len(attempted) > 1
                self.commands.clear()
                self.manager.configure_upstream_routing.side_effect = apply
                with self.assertRaisesRegex(RuntimeError, 'previous configuration was restored'):
                    self.manager.update_server_upstream(server['id'], {'selected_services': ['tiktok']})
                self.assertEqual(attempted, [['tiktok'], ['claude']])
                self.assertEqual(self.manager.config, before)
                for path, content in files.items():
                    self.assertEqual(path.read_bytes(), content)
                self.assert_entry_unchanged(server)
                self.assertIn(server['upstream']['interface'], self.live)
                self.assertTrue(any(c.startswith('iptables -D INPUT ') for c in self.commands))
                self.assertTrue(any(c.startswith('iptables -D FORWARD ') for c in self.commands))


    def test_release_failure_rearms_input_guard_before_rollback_cleanup(self):
        server = self.provision()
        self.attach(server, routing_mode='selected_services', selected_services=['claude'])
        self.commands.clear()
        failed = False
        def execute(command):
            nonlocal failed
            result = self.execute(command)
            if command.startswith('iptables -D FORWARD ') and not failed:
                failed = True
                return None
            return result
        self.manager.execute_command = Mock(side_effect=execute)
        self.manager.cleanup_upstream_routing = Mock(side_effect=lambda current: self.commands.append('cleanup-domain-route') or True)
        with self.assertRaisesRegex(RuntimeError, 'previous configuration was restored'):
            self.manager.update_server_upstream(server['id'], {'selected_services': ['tiktok']})
        failure = next(i for i, command in enumerate(self.commands) if command.startswith('iptables -D FORWARD '))
        rollback = next(i for i in range(failure + 1, len(self.commands)) if self.commands[i] == 'cleanup-domain-route')
        self.assertTrue(any('iptables -I INPUT 1 ' in command for command in self.commands[failure + 1:rollback]),
                        'rollback must protect transparent traffic again after INPUT was released')
        self.assertEqual(server['upstream']['selected_services'], ['claude'])
        self.assert_entry_unchanged(server)

    def test_repeated_start_does_not_guard_an_already_running_entry(self):
        server = self.provision()
        self.attach(server, routing_mode='selected_services', selected_services=['claude'])
        self.commands.clear()
        self.manager.start_server = manager_module.AmneziaManager.start_server.__get__(self.manager)
        def execute(command):
            if command == f"/usr/bin/awg-quick up {server['interface']}":
                self.commands.append(command)
                return None  # awg-quick rejects an already existing interface.
            return self.execute(command)
        self.manager.execute_command = Mock(side_effect=execute)
        self.manager.start_server(server['id'])
        self.assertFalse(any('iptables -I INPUT 1 ' in command or 'iptables -I FORWARD 1 ' in command
                             for command in self.commands), 'repeated start must not block the working entry')
        self.assertEqual(server['status'], 'running')
        self.assertIn(server['interface'], self.live)

    def test_start_and_stop_protect_transparent_traffic_before_interface_and_capture_changes(self):
        server = self.provision(running=False)
        self.attach(server, routing_mode='selected_services', selected_services=['claude'])
        self.commands.clear()
        self.manager.start_server = manager_module.AmneziaManager.start_server.__get__(self.manager)
        self.assertTrue(self.manager.start_server(server['id']))
        entry_up = self.commands.index(f"/usr/bin/awg-quick up {server['interface']}")
        for chain in ('INPUT', 'FORWARD'):
            self.assertTrue(any(f'iptables -I {chain} 1 ' in command for command in self.commands[:entry_up]),
                            f'{chain} must be guarded before new selected-mode entry accepts traffic')
        self.commands.clear()
        self.manager.cleanup_iptables = Mock(side_effect=lambda *args: self.commands.append('cleanup-forwarding') or True)
        self.manager.cleanup_upstream_routing = Mock(side_effect=lambda current: self.commands.append('cleanup-domain-route') or True)
        self.assertTrue(self.manager.stop_server(server['id']))
        cleanup = min(self.commands.index('cleanup-forwarding'), self.commands.index('cleanup-domain-route'))
        for chain in ('INPUT', 'FORWARD'):
            self.assertTrue(any(f'iptables -I {chain} 1 ' in command for command in self.commands[:cleanup]),
                            f'{chain} must be guarded before transparent capture is removed')
        self.assertNotIn(server['interface'], self.live)


class SelectedServiceRoutingTests(unittest.TestCase):
    execute = routing_tests.RoutingManagerTests.execute

    def setUp(self):
        routing_tests.RoutingManagerTests.setUp(self)
        self.server['upstream'].update(routing_mode='selected_services', selected_services=['claude'])
        self.proxy = Mock()
        patcher = patch.object(manager_module, 'DomainProxy', return_value=self.proxy)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_routes_use_connection_mark_and_nat_without_broad_ipsets(self):
        self.assertTrue(self.manager.configure_upstream_routing(self.server))
        joined = '\n'.join(self.commands)
        self.assertIn('rule add fwmark 41001 table 201', joined)
        self.assertNotIn('rule add from 10.1.0.0/24', joined)
        self.assertIn('-m mark --mark 41001 -o wg1-up -j MASQUERADE', joined)
        self.assertNotIn('ipset', joined)
        self.assertNotIn('dnsmasq', joined)
        self.proxy.configure.assert_called_once_with(self.server)
        terminal = self.commands.index('ip -4 route replace blackhole default metric 32767 table 201')
        active = self.commands.index('ip -4 route replace default dev wg1-up metric 10 table 201')
        self.assertLess(terminal, active)

    def test_fail_close_keeps_proxy_and_blocks_only_marked_tunnel_traffic(self):
        self.assertTrue(self.manager.configure_wireguard_fail_closed_routing(self.server))
        joined = '\n'.join(self.commands)
        self.assertIn('blackhole default metric 32767 table 201', joined)
        self.assertIn('rule add fwmark 41001 table 201', joined)
        self.assertNotIn('rule add from ', joined)
        self.assertNotIn('route replace default dev wg1-up', joined)
        self.proxy.configure.assert_called_once_with(self.server)
        self.proxy.restart.assert_not_called()

    def test_fail_open_flushes_connections_and_removes_tunnel_policy_rule(self):
        self.server['linked_failover_mode'] = 'fail_open'
        self.manager.setup_iptables = Mock(return_value=True)
        self.manager.cleanup_iptables = Mock(return_value=True)
        self.assertTrue(self.manager.switch_server_egress(self.server, 'local'))
        joined = '\n'.join(self.commands)
        self.assertEqual(self.server['routing_state'], 'local')
        self.assertIn('rule del fwmark 41001 table 201', joined)
        self.assertNotIn('rule add fwmark', joined)
        self.assertNotIn('blackhole default', joined)
        self.proxy.cleanup.assert_not_called()
        self.proxy.restart.assert_called_once_with(self.server)
        self.proxy.configure.assert_not_called()
        self.assertEqual(json.loads(Path(manager_module.CONFIG_FILE).read_text())['servers'][0]['routing_state'], 'local')

    def test_upstream_recovery_flushes_cached_dns_and_sockets_after_restoring_route(self):
        for state, unhealthy in (('local', False), ('upstream', True)):
            with self.subTest(state=state, unhealthy=unhealthy):
                self.commands.clear()
                self.proxy.reset_mock()
                self.server['routing_state'] = state
                self.server['_upstream_unhealthy'] = unhealthy
                restart_commands = []
                self.proxy.restart.side_effect = lambda current: restart_commands.extend(self.commands)
                self.assertTrue(self.manager.configure_upstream_routing(self.server))
                self.proxy.restart.assert_called_once_with(self.server)
                self.proxy.configure.assert_not_called()
                self.assertIn('ip -4 route replace default dev wg1-up metric 10 table 201', restart_commands,
                              'the restored tunnel route must exist before fresh proxy connections start')
                self.assertTrue(any('rule add fwmark 41001 table 201' in command for command in restart_commands))

    def test_already_local_and_healthy_upstream_do_not_restart_existing_connections(self):
        self.server['routing_state'] = 'local'
        self.assertTrue(self.manager.configure_wireguard_local_routing(self.server))
        self.proxy.configure.assert_called_once_with(self.server)
        self.proxy.restart.assert_not_called()
        self.proxy.reset_mock()
        self.server['routing_state'] = 'upstream'
        self.assertTrue(self.manager.configure_upstream_routing(self.server))
        self.proxy.configure.assert_called_once_with(self.server)
        self.proxy.restart.assert_not_called()

    def test_cleanup_stops_proxy_and_removes_its_mark_nat(self):
        self.assertTrue(self.manager.cleanup_upstream_routing(self.server))
        self.proxy.cleanup.assert_called_once_with(self.server)
        joined = '\n'.join(self.commands)
        self.assertIn('-D POSTROUTING -m mark --mark 41001 -o wg1-up -j MASQUERADE', joined)
        self.assertIn('rule del fwmark 41001 table 201', joined)
        self.assertNotIn('ipset', joined)

    def test_proxy_failure_propagates_for_transaction_rollback(self):
        self.proxy.configure.side_effect = RuntimeError('transparent listener failed')
        with self.assertRaisesRegex(RuntimeError, 'transparent listener failed'):
            self.manager.configure_upstream_routing(self.server)


class SelectedServiceXrayTests(unittest.TestCase):
    output = routing_tests.XrayRoutingConfigTests.output

    def setUp(self):
        routing_tests.XrayRoutingConfigTests.setUp(self)
        self.server['upstream'].update(routing_mode='selected_services', selected_services=['claude'],
                                      service_ip_profile='expanded', service_cidrs=['8.8.8.0/24'])

    def test_youtube_precedes_selected_domains_and_ip_pools_are_ignored(self):
        config = self.output()
        rules = config['routing']['rules']
        self.assertEqual(len(rules), 3)
        self.assertEqual(rules[0]['outboundTag'], 'direct')
        self.assertIn('domain:youtube.com', rules[0]['domain'])
        self.assertIn('domain:googlevideo.com', rules[0]['domain'])
        self.assertEqual(rules[1]['outboundTag'], 'vless-v1-awg')
        self.assertIn('domain:claude.ai', rules[1]['domain'])
        self.assertNotIn('domain:openai.com', rules[1]['domain'])
        self.assertNotIn('domain:tiktok.com', rules[1]['domain'])
        self.assertTrue(all('ip' not in rule for rule in rules))
        self.assertEqual(rules[2], {'type': 'field', 'inboundTag': ['vless-v1'], 'outboundTag': 'direct'})
        self.assertTrue(config['inbounds'][0]['sniffing']['routeOnly'])
        self.assertEqual(config['outbounds'][1]['streamSettings']['sockopt']['mark'], 41001)

    def test_voice_fallback_is_limited_to_official_hosts_and_udp_port(self):
        self.server['upstream']['selected_services'] = ['chatgpt']
        rules = self.output()['routing']['rules']
        self.assertIn('domain:youtube.com', rules[0]['domain'])
        voice = [rule for rule in rules if 'ip' in rule]
        self.assertEqual(len(voice), 1)
        self.assertEqual(voice[0]['network'], 'udp')
        self.assertEqual(voice[0]['port'], '3478')
        self.assertTrue(all(value.endswith('/32') for value in voice[0]['ip']))
        self.assertNotIn('8.8.8.0/24', voice[0]['ip'])

    def test_empty_selection_and_fail_open_have_no_tunnel_domain_rules(self):
        self.server['upstream']['selected_services'] = []
        rules = self.output()['routing']['rules']
        self.assertTrue(all(rule['outboundTag'] == 'direct' for rule in rules))
        self.server['upstream']['selected_services'] = ['claude']
        self.server['routing_state'] = 'local'
        config = self.output()
        self.assertEqual(config['routing']['rules'], [{'type': 'field', 'inboundTag': ['vless-v1'], 'outboundTag': 'direct'}])
        self.assertEqual([outbound['tag'] for outbound in config['outbounds']], ['direct'])


class SelectedServiceDiagnosticTests(unittest.TestCase):
    execute = diagnostic_tests.RoutingDiagnosticsTests.execute

    def setUp(self):
        diagnostic_tests.RoutingDiagnosticsTests.setUp(self)
        self.server['upstream'].update(routing_mode='selected_services', selected_services=['claude'])
        self.proxy = Mock()
        self.proxy.status.return_value = {'running': True, 'capture_ready': True}
        patcher = patch.object(manager_module, 'DomainProxy', return_value=self.proxy)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_same_resolved_ip_has_distinct_service_and_youtube_decisions(self):
        before = copy.deepcopy(self.manager.config)
        service = self.manager.get_upstream_diagnostics('entry', 'claude.ai')
        youtube = self.manager.get_upstream_diagnostics('entry', 'youtube.com')
        self.assertEqual(service['destinations'][0]['address'], youtube['destinations'][0]['address'])
        self.assertEqual(service['destinations'][0]['route'], 'upstream')
        self.assertEqual(youtube['destinations'][0]['route'], 'local')
        self.assertTrue(service['destinations'][0]['matched'])
        self.assertFalse(youtube['destinations'][0]['matched'])
        self.assertEqual(service['classifier']['engine'], 'sing-box')
        self.assertTrue(service['classifier']['proxy_running'])
        self.assertEqual(service['selected_services'], ['claude'])
        self.assertEqual(self.manager.config, before)
        self.manager.save_config.assert_not_called()
        self.assertNotIn('DO-NOT-EXPOSE', json.dumps(service))
        self.assertFalse(any(command.startswith('ipset ') for command in self.commands))

    def test_raw_ip_never_claims_service_classification(self):
        result = self.manager.get_upstream_diagnostics('entry', '104.18.31.77')
        self.assertEqual(result['destinations'][0]['classification'], 'unknown_without_domain')
        self.assertEqual(result['destinations'][0]['route'], 'unknown')
        self.assertEqual(result['destinations'][0]['egress'], '')

    def test_failed_capture_or_process_makes_predicted_route_unknown(self):
        for state in ({'running': False, 'capture_ready': True}, {'running': True, 'capture_ready': False}):
            with self.subTest(state=state):
                self.proxy.status.return_value = state
                result = self.manager.get_upstream_diagnostics('entry', 'claude.ai')
                self.assertEqual(result['destinations'][0]['route'], 'unknown')
                self.assertTrue(result['destinations'][0]['matched'])

    def test_vless_uses_its_xray_classifier(self):
        self.server['protocol'] = 'vless'
        result = self.manager.get_upstream_diagnostics('entry', 'claude.ai')
        self.assertEqual(result['classifier']['engine'], 'xray')
        self.assertEqual(result['destinations'][0]['route'], 'upstream')
        self.proxy.status.assert_not_called()


if __name__ == '__main__':
    unittest.main()
