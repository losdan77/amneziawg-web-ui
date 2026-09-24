"""Exercise actual policy generation, imports and Xray output with external IO mocked."""
import copy
import errno
import json
import os
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import test_awg_manager as manager_module
from awg_protocol import generate_params
from routing_policy import AI_TIKTOK_DOMAINS


class RoutingManagerTests(unittest.TestCase):
    imported_config = manager_module.ManagerTests.imported_config

    def setUp(self):
        manager_module.ManagerTests.setUp(self)
        self.manager.ru_split_cidrs = ['5.8.0.0/16', '5.16.0.0/14']
        self.commands = []
        self.manager.execute_command = Mock(side_effect=self.execute)
        self.socket_patch = patch.object(manager_module, 'socket', Mock(gethostbyname=Mock(return_value='192.0.2.5')), create=True)
        self.socket_patch.start()
        self.addCleanup(self.socket_patch.stop)
        self.server = {'id': 'entry', 'name': 'Test entry', 'interface': 'wg1', 'subnet': '10.1.0.0/24',
                       'server_ip': '10.1.0.1', 'dns': ['1.1.1.1'], 'protocol': 'wireguard',
                       'mode': 'edge_linked', 'routing_state': 'upstream', 'egress_interface': 'wg1-up',
                       'linked_failover_mode': 'fail_close', 'clients': [],
                       'upstream': {'table_id': 201, 'interface': 'wg1-up', 'endpoint': 'exit.example:51820',
                                    'fwmark': 41001, 'routing_mode': 'ai_tiktok'}}
        self.manager.config['servers'] = [self.server]
        self.manager.save_config()

    def execute(self, command):
        self.commands.append(command)
        if command == 'ip -4 route show default | head -n1':
            return 'default via 192.0.2.254 dev ens3 proto dhcp'
        if command.startswith('ip link show '):
            return 'state UNKNOWN'
        return ''

    def test_selective_routes_marks_and_never_all_subnet_or_ru_destinations(self):
        self.assertTrue(self.manager.configure_upstream_routing(self.server))
        joined = '\n'.join(self.commands)
        self.assertIn('rule add fwmark 41001 table 201', joined)
        self.assertNotIn('rule add from 10.1.0.0/24', joined)
        self.assertFalse(any(cidr in joined for cidr in self.manager.ru_split_cidrs))
        self.assertIn('route replace 192.0.2.5/32 via 192.0.2.254 dev ens3', joined)
        self.assertIn('ipset create awgsel_201', joined)
        terminal = self.commands.index('ip -4 route replace blackhole default metric 32767 table 201')
        active = self.commands.index('ip -4 route replace default dev wg1-up metric 10 table 201')
        self.assertLess(terminal, active)

    def test_all_and_ru_modes_route_the_subnet_and_only_ru_gets_exceptions(self):
        for mode in ('all', 'ru_split'):
            with self.subTest(mode=mode):
                self.commands.clear()
                self.server['upstream']['routing_mode'] = mode
                self.manager.configure_upstream_routing(self.server)
                joined = '\n'.join(self.commands)
                self.assertIn('rule add from 10.1.0.0/24 table 201', joined)
                self.assertNotIn('rule add fwmark', joined)
                self.assertNotIn('dnsmasq', joined)
                for cidr in self.manager.ru_split_cidrs:
                    self.assertEqual(cidr in joined, mode == 'ru_split')

    def test_failclosed_preserves_selective_classifier_and_terminal_route(self):
        self.manager.configure_wireguard_fail_closed_routing(self.server)
        joined = '\n'.join(self.commands)
        self.assertIn('route replace blackhole default metric 32767 table 201', joined)
        self.assertIn('route del default metric 10 table 201', joined)
        self.assertNotIn('route replace default dev', joined)
        self.assertIn('rule add fwmark 41001 table 201', joined)
        self.assertIn('CONNMARK --restore-mark', joined)
        self.assertFalse(any(cidr in joined for cidr in self.manager.ru_split_cidrs))

    def test_failclosed_ru_keeps_only_ru_direct_exceptions(self):
        self.server['upstream']['routing_mode'] = 'ru_split'
        self.manager.configure_wireguard_fail_closed_routing(self.server)
        joined = '\n'.join(self.commands)
        for cidr in self.manager.ru_split_cidrs:
            self.assertIn(f'{cidr} via 192.0.2.254 dev ens3 table 201', joined)
        self.assertIn('rule add from 10.1.0.0/24 table 201', joined)
        self.assertNotIn('dnsmasq', joined)

    def test_cleanup_is_scoped_to_owned_table_mark_and_dns(self):
        self.manager.configure_upstream_routing(self.server)
        self.commands.clear()
        self.manager.cleanup_upstream_routing(self.server)
        joined = '\n'.join(self.commands)
        self.assertIn('rule del fwmark 41001 table 201 priority 10201', joined)
        self.assertIn('rule del from 10.1.0.0/24 table 201 priority 10201', joined)
        self.assertIn('route flush table 201', joined)
        self.assertIn('ipset destroy awgsel_201', joined)
        self.assertNotIn('table main', joined)
        self.assertFalse(Path(self.directory.name, 'routing', 'dns-201.conf').exists())

    def test_failed_terminal_route_prevents_installing_active_route(self):
        self.manager.execute_command.side_effect = lambda command: None if 'blackhole default' in command else self.execute(command)
        with self.assertRaises(RuntimeError):
            self.manager.configure_upstream_routing(self.server)
        self.assertFalse(any('route replace default dev' in command for command in self.commands))

    def test_failopen_switch_keeps_dns_learning_and_saves_local_state(self):
        self.server['linked_failover_mode'] = 'fail_open'
        self.manager.configure_upstream_routing(self.server)
        self.commands.clear()
        real_exists = os.path.exists
        with patch.object(manager_module.os.path, 'exists', side_effect=lambda path: True if str(path).startswith('/app/scripts/') else real_exists(path)):
            self.assertTrue(self.manager.switch_server_egress(self.server, 'local'))
        self.assertEqual(self.server['routing_state'], 'local')
        self.assertEqual(self.server['egress_interface'], 'eth+')
        self.assertFalse(any('blackhole default' in command for command in self.commands))
        self.assertTrue(any('rule del fwmark 41001 table 201' in command for command in self.commands))
        self.assertFalse(any('ipset destroy' in command or '-D PREROUTING' in command for command in self.commands))
        self.assertFalse(any('rule add fwmark' in command for command in self.commands))
        self.assertTrue(Path(self.directory.name, 'routing', 'dns-201.conf').exists())
        self.assertTrue(any('setup_iptables.sh wg1 10.1.0.0/24 eth+' in command for command in self.commands))
        self.assertEqual(json.loads(Path(manager_module.CONFIG_FILE).read_text())['servers'][0]['routing_state'], 'local')

    def test_vless_policy_uses_mark_and_blocks_marked_ipv6(self):
        self.server['protocol'] = 'vless'
        self.manager.configure_upstream_routing(self.server)
        joined = '\n'.join(self.commands)
        self.assertIn('ip -6 route replace blackhole default table 201', joined)
        self.assertIn('ip -6 rule add fwmark 41001 table 201', joined)
        self.assertIn('ip -4 rule add fwmark 41001 table 201', joined)
        self.assertIn('-m mark --mark 41001 -o wg1-up -j MASQUERADE', joined)
        self.assertNotIn('rule add from', joined)
        self.assertNotIn('dnsmasq', joined)
        self.assertFalse(any(cidr in joined for cidr in self.manager.ru_split_cidrs))

    def test_vless_failclosed_then_cleanup_has_matching_ipv4_ipv6_resources(self):
        self.server['protocol'] = 'vless'
        self.manager.configure_vless_fail_closed_routing(self.server)
        joined = '\n'.join(self.commands)
        self.assertIn('ip -4 route replace blackhole default metric 32767 table 201', joined)
        self.assertIn('ip -6 route replace blackhole default table 201', joined)
        self.assertNotIn('route replace default dev', joined)
        self.commands.clear()
        self.manager.cleanup_upstream_routing(self.server)
        self.assertIn('ip -6 route flush table 201', '\n'.join(self.commands))

    def test_vless_remains_usable_when_kernel_has_no_ipv6_support(self):
        self.server['protocol'] = 'vless'
        for error_code in (errno.EAFNOSUPPORT, errno.EPROTONOSUPPORT):
            with self.subTest(error_code=error_code):
                self.commands.clear()
                manager_module.socket.socket.side_effect = OSError(error_code, 'IPv6 is unavailable')
                self.assertTrue(self.manager.configure_upstream_routing(self.server))
                joined = '\n'.join(self.commands)
                self.assertIn('ip -4 rule add fwmark 41001 table 201', joined)
                self.assertIn('route replace default dev wg1-up metric 10 table 201', joined)
                self.assertNotIn('ip -6', joined)

    def test_vless_does_not_ignore_other_ipv6_probe_errors(self):
        self.server['protocol'] = 'vless'
        manager_module.socket.socket.side_effect = OSError(errno.EACCES, 'Permission denied')
        with self.assertRaises(OSError):
            self.manager.configure_upstream_routing(self.server)
        self.assertFalse(any('route replace default dev' in command for command in self.commands))

    def test_vless_does_not_ignore_ipv6_routing_failure(self):
        self.server['protocol'] = 'vless'
        self.manager.execute_command.side_effect = lambda command: None if command.startswith('ip -6 route replace') else self.execute(command)
        with self.assertRaises(RuntimeError):
            self.manager.configure_upstream_routing(self.server)
        manager_module.socket.socket.return_value.close.assert_called_once()
        self.assertFalse(any('route replace default dev' in command for command in self.commands))

    def test_malformed_imports_and_shell_metacharacters_fail_before_commands(self):
        config = self.imported_config(generate_params(version='2'))
        replacements = [(f'PrivateKey = {manager_module.IMPORT_PRIVATE_KEY}', "PrivateKey = a';touch /tmp/owned;'"),
                        (f'PublicKey = {manager_module.IMPORT_PUBLIC_KEY}', 'PublicKey = $(id)'),
                        ('Endpoint = 192.0.2.5:51820', 'Endpoint = host;id:51820'),
                        ('Endpoint = 192.0.2.5:51820', 'Endpoint = 192.0.2.5:99999'),
                        ('Address = 10.8.0.2/32', 'Address = 2001:db8::1/64'),
                        ('Address = 10.8.0.2/32', 'Address = 10.8.0.2/32, 10.8.0.3/32'),
                        ('AllowedIPs = 0.0.0.0/0', 'AllowedIPs = 10.0.0.0/8'),
                        ('AllowedIPs = 0.0.0.0/0', 'AllowedIPs = 0.0.0.0/0;id'),
                        ('MTU = 1280', 'MTU = 1500'),
                        ('PersistentKeepalive = 15-30', 'PersistentKeepalive = 0;id')]
        for original, malicious in replacements:
            with self.subTest(value=malicious):
                self.commands.clear()
                with self.assertRaises(ValueError):
                    self.manager.build_imported_upstream_config(server_id='one', upstream_interface='wg1-up',
                        upstream_data={'import_config': config.replace(original, malicious)}, mtu=1280)
                self.assertEqual(self.commands, [])
        with self.assertRaises(ValueError):
            self.manager.parse_amnezia_config_text(config + '\n[Peer]\nPublicKey = another\n')

    def test_import_never_executes_or_renders_user_supplied_hooks(self):
        config = self.imported_config(generate_params(version='3')).replace('[Peer]', 'PostUp = touch /tmp/owned\n[Peer]')
        upstream, _, mtu, _ = self.manager.build_imported_upstream_config(server_id='one', upstream_interface='wg1-up',
            upstream_data={'import_config': config, 'routing_mode': 'ai_tiktok'}, mtu=1280)
        self.assertNotIn('PostUp', self.manager.generate_upstream_config_content(upstream, mtu))
        self.assertFalse(any('/tmp/owned' in command for command in self.commands))
        self.assertEqual(upstream['routing_mode'], 'ai_tiktok')
        self.assertFalse(upstream['split_ru_local'])

    def test_import_rejects_base64_keys_with_wrong_decoded_length(self):
        config = self.imported_config(generate_params(version='2'))
        for field, valid in (('PrivateKey', manager_module.IMPORT_PRIVATE_KEY),
                             ('PublicKey', manager_module.IMPORT_PUBLIC_KEY),
                             ('PresharedKey', manager_module.IMPORT_PRESHARED_KEY)):
            source = config if field != 'PresharedKey' else config + f'PresharedKey = {valid}\n'
            for malformed in ('private', 'c2hvcnQ=', 'AAAA', '====', manager_module.IMPORT_PRIVATE_KEY[:-1]):
                with self.subTest(field=field, value=malformed), self.assertRaises(ValueError):
                    self.manager.build_imported_upstream_config(server_id='one', upstream_interface='wg1-up',
                        upstream_data={'import_config': source.replace(f'{field} = {valid}', f'{field} = {malformed}')}, mtu=1280)
        self.commands.clear()
        upstream, _, _, _ = self.manager.build_imported_upstream_config(server_id='one', upstream_interface='wg1-up',
            upstream_data={'import_config': config + f'PresharedKey = {manager_module.IMPORT_PRESHARED_KEY}\n'}, mtu=1280)
        self.assertEqual(upstream['private_key'], manager_module.IMPORT_PRIVATE_KEY)
        self.assertEqual(upstream['public_key'], manager_module.IMPORT_PUBLIC_KEY)
        self.assertEqual(upstream['preshared_key'], manager_module.IMPORT_PRESHARED_KEY)

    def test_exhausted_table_and_mark_allocators_do_not_reuse_active_ids(self):
        self.manager.config['servers'] = [
            {'upstream': {'table_id': 200, 'fwmark': 40960}},
            {'upstream': {'table_id': 201, 'fwmark': 40961}},
        ]
        with self.assertRaisesRegex(ValueError, 'No free upstream routing tables'):
            self.manager._allocate_upstream_table_id(base=200, span=2)
        with self.assertRaisesRegex(ValueError, 'No free upstream packet marks'):
            self.manager._allocate_upstream_fwmark(base=40960, span=2)
        self.assertEqual(self.manager._allocate_upstream_table_id(base=200, span=3), 202)
        self.assertEqual(self.manager._allocate_upstream_fwmark(base=40960, span=3), 40962)

    def test_shared_legacy_table_cleanup_preserves_remaining_owner_state(self):
        self.server['upstream']['routing_mode'] = 'all'
        other = copy.deepcopy(self.server)
        other.update(id='other', interface='wg2', subnet='10.2.0.0/24', server_ip='10.2.0.1', egress_interface='wg2-up')
        other['upstream'].update(interface='wg2-up', fwmark=41002)
        self.manager.config['servers'].append(other)
        for state in ('upstream', 'local', 'unhealthy'):
            with self.subTest(state=state):
                other['routing_state'] = 'local' if state == 'local' else 'upstream'
                other['_upstream_unhealthy'] = state == 'unhealthy'
                self.commands.clear()
                self.manager.cleanup_upstream_routing(self.server)
                joined = '\n'.join(self.commands)
                self.assertNotIn('route flush table 201', joined)
                self.assertNotIn('ipset destroy', joined)
                if state == 'upstream':
                    self.assertIn('route replace default dev wg2-up', joined)
                else:
                    self.assertNotIn('route replace default dev wg2-up', joined)
                if state == 'unhealthy':
                    self.assertIn('route replace blackhole default metric 32767 table 201', joined)
                    self.assertIn('route del default metric 10 table 201', joined)
                if state == 'local':
                    self.assertNotIn('rule add ', joined)
                    self.assertNotIn('blackhole default', joined)


class RoutingLifecycleTests(unittest.TestCase):
    """Run real startup, health-worker, teardown and status against simulated Linux IO."""
    def setUp(self):
        self.live = set()
        self.upstream_start_fails = False
        self.route_active = True
        self.handshake_healthy = True
        RoutingManagerTests.setUp(self)
        del self.manager.start_server  # Restore the actual method hidden by the shared fixture.
        self.server['status'] = 'stopped'
        self.server['config_path'] = str(Path(self.directory.name, 'wg1.conf'))
        self.server['upstream'].update(config_path=str(Path(self.directory.name, 'wg1-up.conf')),
                                       public_key=manager_module.IMPORT_PUBLIC_KEY)
        Path(self.server['config_path']).write_text('entry config preserved')
        Path(self.server['upstream']['config_path']).write_text('upstream config preserved')
        real_exists = os.path.exists
        scripts = patch.object(manager_module.os.path, 'exists', side_effect=lambda path:
                               True if str(path).startswith('/app/scripts/') else real_exists(path))
        scripts.start()
        self.addCleanup(scripts.stop)
        for key, value in (('LINK_HANDSHAKE_TIMEOUT', 3600), ('LINK_HEALTH_CHECK_INTERVAL', 15)):
            setting = patch.object(manager_module, key, value, create=True)
            setting.start()
            self.addCleanup(setting.stop)

    def execute(self, command):
        result = RoutingManagerTests.execute(self, command)
        if command.startswith('ip link show '):
            return 'state UNKNOWN' if command.split()[3] in self.live else None
        if command.startswith('/usr/bin/awg-quick up '):
            interface = command.split()[2]
            if interface == 'wg1-up' and self.upstream_start_fails:
                return None
            self.live.add(interface)
        if command.startswith('/usr/bin/awg-quick down '):
            self.live.discard(command.split()[2])
        if command == '/usr/bin/awg show wg1-up latest-handshakes':
            age = 30 if self.handshake_healthy else 7200
            return f'{manager_module.IMPORT_PUBLIC_KEY}\t{int(time.time()) - age}'
        if command == 'ip -4 route show table 201 default':
            return ('default dev wg1-up metric 10\n' if self.route_active else '') + 'blackhole default metric 32767'
        if command.startswith('ip -4 route replace default dev wg1-up'):
            self.route_active = True
        if command.startswith('ip -4 route del default metric 10') or command.startswith('ip route flush table 201'):
            self.route_active = False
        return result

    def health_tick(self):
        self.manager.stop_expiration_worker = Mock()
        self.manager.stop_expiration_worker.is_set.side_effect = [False, True]
        self.manager.link_health_worker()

    def test_startup_failclose_retains_entry_and_direct_destinations_during_upstream_outage(self):
        self.upstream_start_fails = True
        self.assertTrue(self.manager.start_server(self.server['id']))
        self.assertEqual(self.live, {'wg1'})
        self.assertEqual(self.server['status'], 'running')
        self.assertEqual(self.manager.get_server_status(self.server['id']), 'running')
        self.assertEqual(self.server['routing_state'], 'upstream')
        self.assertFalse(self.route_active)
        joined = '\n'.join(self.commands)
        self.assertIn('blackhole default', joined)
        self.assertIn('rule add fwmark 41001 table 201', joined)
        self.assertIn('dnsmasq --conf-file=', joined)
        self.assertNotIn('/usr/bin/awg-quick down wg1', joined)

    def test_startup_failopen_retains_classifier_but_routes_everything_locally(self):
        self.upstream_start_fails = True
        self.server['linked_failover_mode'] = 'fail_open'
        self.assertTrue(self.manager.start_server(self.server['id']))
        self.assertEqual(self.live, {'wg1'})
        self.assertEqual(self.server['routing_state'], 'local')
        joined = '\n'.join(self.commands)
        self.assertIn('dnsmasq --conf-file=', joined)
        self.assertNotIn('rule add fwmark', joined)
        self.assertNotIn('ipset destroy', joined)
        self.assertNotIn('blackhole default', joined)

    def test_startup_routing_exception_tears_down_new_entry_and_releases_guard_last(self):
        self.manager.execute_command.side_effect = lambda command: None if command.startswith('ip -4 route replace blackhole ') else self.execute(command)
        self.assertFalse(self.manager.start_server(self.server['id']))
        self.assertFalse(self.live)
        self.assertEqual(self.server['status'], 'stopped')
        self.assertEqual(self.manager.get_server_status(self.server['id']), 'stopped')
        guard_index = next(index for index, command in enumerate(self.commands) if command.startswith('iptables -I FORWARD 1 '))
        entry_down_index = next(index for index, command in enumerate(self.commands) if command.startswith('/usr/bin/awg-quick down wg1 '))
        unguard_index = next(index for index, command in enumerate(self.commands) if command.startswith('iptables -D FORWARD '))
        self.assertLess(guard_index, entry_down_index)
        self.assertLess(entry_down_index, unguard_index)
        self.assertTrue(any('route flush table 201' in command for command in self.commands))
        self.assertFalse(Path(self.directory.name, 'routing', 'dns-201.conf').exists())
        self.assertEqual(json.loads(Path(manager_module.CONFIG_FILE).read_text())['servers'][0]['status'], 'stopped')

    def test_health_restores_active_route_even_when_unhealthy_flag_was_lost(self):
        self.live.update(('wg1', 'wg1-up'))
        self.route_active = False
        self.server['routing_state'] = 'upstream'
        self.server.pop('_upstream_unhealthy', None)
        self.health_tick()
        self.assertTrue(self.route_active)
        self.assertEqual(self.server['routing_state'], 'upstream')
        self.assertTrue(any(command.startswith('ip -4 route replace default dev wg1-up') for command in self.commands))
        self.assertFalse(any('ipset destroy' in command for command in self.commands))

    def test_healthy_health_check_does_not_rebuild_live_routes(self):
        self.live.update(('wg1', 'wg1-up'))
        self.route_active = True
        self.health_tick()
        self.assertFalse(any('route replace' in command or 'ipset destroy' in command for command in self.commands))

    def test_health_outage_then_recovery_reinstalls_tunnel_after_local_fallback(self):
        self.live.update(('wg1', 'wg1-up'))
        self.server['linked_failover_mode'] = 'fail_open'
        self.handshake_healthy = False
        self.health_tick()
        self.assertEqual(self.server['routing_state'], 'local')
        self.assertFalse(self.route_active)
        self.assertFalse(any('ipset destroy' in command for command in self.commands))
        self.handshake_healthy = True
        self.commands.clear()
        self.health_tick()
        self.assertEqual(self.server['routing_state'], 'upstream')
        self.assertTrue(self.route_active)

    def test_stopped_entry_is_never_started_by_the_health_worker(self):
        self.handshake_healthy = False
        self.health_tick()
        self.assertFalse(self.live)
        self.assertFalse(any('awg-quick up' in command for command in self.commands))

    def test_delete_stale_stopped_status_cleans_actual_active_interfaces(self):
        self.live.update(('wg1', 'wg1-up'))
        self.server['status'] = 'stopped'
        self.manager.configure_upstream_routing(self.server)
        self.assertTrue(self.manager.delete_server(self.server['id']))
        self.assertFalse(self.live)
        self.assertEqual(self.manager.config['servers'], [])
        self.assertFalse(Path(self.directory.name, 'routing', 'dns-201.conf').exists())
        self.assertFalse(Path(self.directory.name, 'wg1.conf').exists())
        self.assertFalse(Path(self.directory.name, 'wg1-up.conf').exists())


class XrayRoutingConfigTests(unittest.TestCase):
    def setUp(self):
        manager_module.ManagerTests.setUp(self)
        settings = {'XRAY_CONFIG_DIR': self.directory.name,
                    'XRAY_CONFIG_FILE': str(Path(self.directory.name, 'xray.json')),
                    'XRAY_DOMAIN_STRATEGY': 'UseIPv4', 'XRAY_DNS_QUERY_STRATEGY': 'UseIPv4',
                    'XRAY_TCP_FAST_OPEN': False, 'XRAY_TCP_MAX_SEG': 0}
        for key, value in settings.items():
            patcher = patch.object(manager_module, key, value, create=True)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.server = {'id': 'v1', 'protocol': 'vless', 'mode': 'edge_linked', 'routing_state': 'upstream',
                       'upstream': {'table_id': 301, 'fwmark': 41001, 'routing_mode': 'ai_tiktok'},
                       'vless': {'transport': 'ws', 'security': 'tls', 'inbound_port': 9443,
                                 'domain': 'vpn.example', 'path': '/vpn'},
                       'clients': [{'uuid': 'client-uuid', 'name': 'client'}]}
        self.manager.config['servers'] = [self.server]

    def output(self):
        self.manager._write_xray_config()
        return json.loads(Path(manager_module.XRAY_CONFIG_FILE).read_text())

    def test_selective_domain_rule_precedes_direct_fallback_and_uses_force_ipv4(self):
        config = self.output()
        rules = config['routing']['rules']
        self.assertEqual(len(rules), 3)
        self.assertEqual(rules[0]['domain'], ['domain:' + domain for domain in AI_TIKTOK_DOMAINS])
        self.assertEqual(rules[0]['outboundTag'], 'vless-v1-awg')
        self.assertEqual(rules[1], {'type': 'field', 'inboundTag': ['vless-v1'],
                                   'ip': ['160.79.104.0/23'], 'outboundTag': 'vless-v1-awg'})
        self.assertEqual(rules[2], {'type': 'field', 'inboundTag': ['vless-v1'], 'outboundTag': 'direct'})
        upstream = next(outbound for outbound in config['outbounds'] if outbound['tag'] == 'vless-v1-awg')
        self.assertEqual(upstream['settings']['domainStrategy'], 'ForceIPv4')
        self.assertEqual(upstream['streamSettings']['sockopt']['mark'], 41001)
        self.assertTrue(config['inbounds'][0]['sniffing']['routeOnly'])
        self.assertEqual(config['routing']['domainStrategy'], 'IPOnDemand')

    def test_failopen_local_state_routes_every_destination_direct(self):
        self.server['routing_state'] = 'local'
        config = self.output()
        self.assertEqual(config['routing']['rules'], [{'type': 'field', 'inboundTag': ['vless-v1'], 'outboundTag': 'direct'}])
        self.assertEqual([item['tag'] for item in config['outbounds']], ['direct'])
        self.assertEqual(config['routing']['domainStrategy'], 'IPIfNonMatch')

    def test_custom_ipv4_pools_apply_only_to_the_selected_inbound(self):
        self.server['upstream']['service_cidrs'] = ['8.8.8.8', '9.9.9.0/24']
        config = self.output()
        rule = config['routing']['rules'][1]
        self.assertEqual(rule['ip'], ['160.79.104.0/23', '8.8.8.8/32', '9.9.9.0/24'])
        self.assertEqual(rule['inboundTag'], ['vless-v1'])
        self.assertEqual(rule['outboundTag'], 'vless-v1-awg')

    def test_all_mode_and_ru_mode_send_whole_inbound_to_marked_outbound(self):
        for mode in ('all', 'ru_split'):
            with self.subTest(mode=mode):
                self.server['upstream']['routing_mode'] = mode
                rules = self.output()['routing']['rules']
                self.assertEqual(rules, [{'type': 'field', 'inboundTag': ['vless-v1'], 'outboundTag': 'vless-v1-awg'}])

    def test_multiple_inbounds_never_share_selective_rules_or_marks(self):
        second = copy.deepcopy(self.server)
        second['id'] = 'v2'
        second['vless']['inbound_port'] = 9444
        second['upstream'].update(table_id=302, fwmark=41002)
        self.manager.config['servers'].append(second)
        config = self.output()
        rules = config['routing']['rules']
        self.assertEqual([rule['inboundTag'] for rule in rules], [['vless-v1']] * 3 + [['vless-v2']] * 3)
        self.assertEqual([outbound['streamSettings']['sockopt']['mark'] for outbound in config['outbounds'][1:]], [41001, 41002])


if __name__ == '__main__':
    unittest.main()
