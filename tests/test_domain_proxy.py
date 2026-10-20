"""Domain routing keeps shared CDN destinations separate and owns only its state."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-ui'))
from domain_proxy import DomainProxy, FAKEIP_NETWORK


class DomainProxyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.run = Mock(return_value='')
        self.proxy = DomainProxy(self.run, self.temporary.name)
        self.server = {
            'interface': 'wg1', 'subnet': '10.1.0.0/24', 'server_ip': '10.1.0.1',
            'upstream': {'table_id': 201, 'fwmark': 41001,
                         'selected_services': ['chatgpt', 'codex', 'claude', 'tiktok']},
        }

    def config(self):
        return self.proxy.build_config(self.server)

    def test_domain_identity_has_priority_over_shared_ip_and_default_is_local(self):
        config = self.config()
        rules = config['route']['rules']
        youtube = next(i for i, rule in enumerate(rules) if 'youtube.com' in rule.get('domain_suffix', []))
        service = next(i for i, rule in enumerate(rules) if 'chatgpt.com' in rule.get('domain_suffix', []))
        self.assertLess(youtube, service)
        self.assertEqual(rules[youtube]['outbound'], 'local')
        self.assertEqual(rules[service]['outbound'], 'tunnel')
        self.assertEqual(config['route']['final'], 'local')
        for rule in rules:
            if 'ip_cidr' in rule and rule.get('outbound') == 'tunnel':
                self.assertTrue(all(network.endswith('/32') for network in rule['ip_cidr']))
                self.assertEqual(rule['port'], [3478])
                self.assertEqual(rule['network'], 'udp')
        self.assertNotIn('google.com', rules[service].get('domain_suffix', []))

    def test_empty_selection_cannot_create_match_all_tunnel_rule(self):
        self.server['upstream']['selected_services'] = []
        config = self.config()
        self.assertFalse(any(rule.get('outbound') == 'tunnel' for rule in config['route']['rules']))
        self.assertFalse(any(rule.get('server') in ('fakeip', 'tunnel-dns') for rule in config['dns']['rules']))

    def test_selecting_only_claude_does_not_route_openai_or_tiktok(self):
        self.server['upstream']['selected_services'] = ['claude']
        selected = [rule for rule in self.config()['route']['rules'] if rule.get('outbound') == 'tunnel']
        self.assertEqual(len(selected), 1)
        self.assertIn('claude.ai', selected[0]['domain_suffix'])
        self.assertNotIn('chatgpt.com', selected[0]['domain_suffix'])
        self.assertNotIn('tiktok.com', selected[0]['domain_suffix'])

    def test_fakeip_maps_only_selected_domains_and_keeps_youtube_real(self):
        config = self.config()
        dns_rules = config['dns']['rules']
        youtube = next(i for i, rule in enumerate(dns_rules) if 'youtube.com' in rule.get('domain_suffix', []))
        fake = next(i for i, rule in enumerate(dns_rules) if rule.get('server') == 'fakeip')
        self.assertLess(youtube, fake)
        self.assertEqual(dns_rules[youtube]['server'], 'local-dns')
        self.assertEqual(dns_rules[fake]['query_type'], ['A'])
        self.assertEqual(dns_rules[fake]['rewrite_ttl'], 60)
        hints = next(rule for rule in dns_rules if 'HTTPS' in rule.get('query_type', []))
        self.assertTrue(hints['domain_suffix'])
        self.assertEqual(hints['action'], 'predefined')
        self.assertEqual(config['dns']['servers'][-1]['inet4_range'], FAKEIP_NETWORK)
        self.assertTrue(config['experimental']['cache_file']['store_fakeip'])

    def test_only_tunnel_outbound_and_its_dns_have_europe_mark(self):
        config = self.config()
        local, tunnel = config['outbounds']
        self.assertNotIn('routing_mark', local)
        self.assertEqual(tunnel['routing_mark'], 41001)
        local_dns, tunnel_dns = config['dns']['servers'][:2]
        self.assertNotIn('routing_mark', local_dns)
        self.assertEqual(tunnel_dns['routing_mark'], 41001)
        self.assertEqual(local['domain_resolver']['server'], 'local-dns')
        self.assertEqual(tunnel['domain_resolver']['server'], 'tunnel-dns')
        self.assertEqual(config['inbounds'][0]['listen'], '127.0.0.1')

    def test_separate_servers_do_not_share_ports_marks_tables_or_cache(self):
        second = copy.deepcopy(self.server)
        second.update(interface='wg2', subnet='10.2.0.0/24', server_ip='10.2.0.1')
        second['upstream'].update(table_id=202, fwmark=41002)
        first_context, second_context = self.proxy._context(self.server), self.proxy._context(second)
        for key in ('port', 'capture_mark', 'capture_table', 'priority', 'chain'):
            self.assertNotEqual(first_context[key], second_context[key])
        self.assertNotEqual(self.config()['experimental']['cache_file']['path'],
                            self.proxy.build_config(second)['experimental']['cache_file']['path'])

    def test_invalid_context_never_reaches_shell(self):
        for field, value in [('interface', 'wg1; reboot'), ('server_ip', '10.2.0.1')]:
            server = copy.deepcopy(self.server)
            server[field] = value
            with self.assertRaises(ValueError):
                self.proxy.configure(server)
        for table in (0, 199, 10000, 65535):
            server = copy.deepcopy(self.server)
            server['upstream']['table_id'] = table
            with self.assertRaises(ValueError):
                self.proxy.configure(server)
        self.run.assert_not_called()

    def test_reserved_fakeip_ranges_and_capture_marks_are_rejected(self):
        for subnet, address in [('198.18.0.0/24', '198.18.0.1'), ('198.19.0.0/24', '198.19.0.1')]:
            server = copy.deepcopy(self.server)
            server.update(subnet=subnet, server_ip=address)
            with self.assertRaisesRegex(ValueError, 'FakeIP'):
                self.proxy.configure(server)
        server = copy.deepcopy(self.server)
        server['upstream']['local_address'] = '198.19.3.2/30'
        with self.assertRaisesRegex(ValueError, 'FakeIP'):
            self.proxy.configure(server)
        server['upstream'].pop('local_address')
        server['upstream']['fwmark'] = 0x40000000 + 201
        with self.assertRaises(ValueError):
            self.proxy.configure(server)
        self.run.assert_not_called()

    def test_status_detects_missing_tproxy_target_policy_route_and_input_rule(self):
        for missing in ('PREROUTING', '-p tcp -j TPROXY', '--dport 53', 'rule show', 'route show', '-C INPUT'):
            with self.subTest(missing=missing):
                self.run.side_effect = lambda command: None if missing in command else ''
                with patch.object(self.proxy, '_pid', return_value=123), patch.object(self.proxy, '_listening', return_value=True):
                    status = self.proxy.status(self.server)
                self.assertTrue(status['running'])
                self.assertFalse(status['capture_ready'])

    def test_input_accept_does_not_jump_ahead_of_transaction_drop_guard(self):
        self.proxy._capture(self.proxy._context(self.server))
        commands = [call.args[0] for call in self.run.call_args_list]
        input_commands = [command for command in commands if '-C INPUT' in command]
        self.assertEqual(len(input_commands), 2)
        self.assertTrue(all('|| iptables -A INPUT' in command for command in input_commands))
        self.assertFalse(any('-I INPUT' in command for command in input_commands))

    def test_capture_is_scoped_dns_precedes_lan_bypass_and_no_global_nat(self):
        self.proxy._capture(self.proxy._context(self.server))
        commands = [call.args[0] for call in self.run.call_args_list]
        joined = '\n'.join(commands)
        self.assertIn('PREROUTING -i wg1 -s 10.1.0.0/24 -j AWGDOM_201', joined)
        self.assertIn('INPUT -i wg1 -s 10.1.0.0/24 -p tcp -m mark --mark 1073742025 -j ACCEPT', joined)
        self.assertIn('local 0.0.0.0/0 dev lo table 50201', joined)
        self.assertNotIn('table main', joined)
        self.assertNotIn('-t nat', joined)
        dns = next(i for i, command in enumerate(commands) if '--dport 53' in command)
        lan = next(i for i, command in enumerate(commands) if '-d 10.0.0.0/8 -j RETURN' in command)
        intercept = next(i for i, command in enumerate(commands) if '-C AWGDOM_201 -p tcp -j TPROXY' in command)
        self.assertLess(dns, lan)
        self.assertLess(lan, intercept)
        self.assertTrue(commands[-1].startswith('iptables -t mangle -C PREROUTING'))

    def test_invalid_staged_config_does_not_stop_working_process_or_touch_capture(self):
        paths = self.proxy._paths(201)
        paths['config'].write_text('old config', encoding='utf-8')
        self.run.return_value = None
        with patch.object(self.proxy, '_stop') as stop, patch.object(self.proxy, '_capture') as capture:
            with self.assertRaises(RuntimeError):
                self.proxy.configure(self.server)
        stop.assert_not_called()
        capture.assert_not_called()
        self.assertEqual(paths['config'].read_text(), 'old config')
        self.assertFalse(paths['config'].with_suffix('.check.json').exists())

    def test_start_failure_restores_previous_config(self):
        paths = self.proxy._paths(201)
        paths['config'].write_text('old config', encoding='utf-8')
        with patch.object(self.proxy, '_stop'), patch.object(self.proxy, '_start', side_effect=[RuntimeError('start'), None]) as start:
            with self.assertRaisesRegex(RuntimeError, 'start'):
                self.proxy.configure(self.server)
        self.assertEqual(paths['config'].read_text(), 'old config')
        self.assertEqual(start.call_count, 2)
        self.assertFalse(any('-I PREROUTING' in call.args[0] for call in self.run.call_args_list))

    def test_unchanged_healthy_config_never_restarts_connections(self):
        with patch.object(self.proxy, '_stop') as stop, patch.object(self.proxy, '_start') as start:
            self.proxy.configure(self.server)
            stop.reset_mock()
            start.reset_mock()
            self.run.reset_mock()
            with patch.object(self.proxy, '_pid', return_value=123), patch.object(self.proxy, '_listening', return_value=True):
                self.proxy.ensure_running(self.server)
            stop.assert_not_called()
            start.assert_not_called()
            self.assertFalse(any('sing-box check' in call.args[0] for call in self.run.call_args_list))

    def test_dead_process_restarts_without_removing_capture_or_fakeip_cache(self):
        with patch.object(self.proxy, '_stop'), patch.object(self.proxy, '_start'):
            self.proxy.configure(self.server)
        cache = self.proxy._paths(201)['cache']
        cache.write_bytes(b'persistent fakeip map')
        self.run.reset_mock()
        with patch.object(self.proxy, '_pid', return_value=None), patch.object(self.proxy, '_start') as start:
            self.proxy.ensure_running(self.server)
            start.assert_called_once_with(201)
        self.assertEqual(cache.read_bytes(), b'persistent fakeip map')
        self.assertFalse(any('-D PREROUTING' in call.args[0] for call in self.run.call_args_list))

    def test_failover_restart_keeps_capture_until_new_process_is_ready(self):
        with patch.object(self.proxy, '_stop') as stop, patch.object(self.proxy, '_start'):
            self.proxy.configure(self.server)
            stop.reset_mock()
            self.run.reset_mock()
            self.proxy.restart(self.server)
        self.assertTrue(stop.called)
        self.assertFalse(any('-D PREROUTING' in call.args[0] for call in self.run.call_args_list))

    def test_cleanup_retains_fakeip_but_drops_only_owned_resources(self):
        paths = self.proxy._paths(201)
        paths['cache'].write_bytes(b'persistent fakeip map')
        paths['config'].write_text('{}')
        with patch.object(self.proxy, '_stop') as stop:
            self.proxy.cleanup(self.server)
            stop.assert_called_once_with(201)
        joined = '\n'.join(call.args[0] for call in self.run.call_args_list)
        self.assertIn('route flush table 50201', joined)
        self.assertNotIn('route flush table 201', joined)
        self.assertNotIn('-F INPUT', joined)
        self.assertNotIn('-F PREROUTING', joined)
        self.assertEqual(paths['cache'].read_bytes(), b'persistent fakeip map')
        self.assertFalse(paths['config'].exists())

    def test_unrelated_reused_pid_is_not_stopped(self):
        self.proxy._paths(201)['pid'].write_text('123')
        with patch('domain_proxy.Path.read_bytes', return_value=b'/usr/bin/other\0run\0-c\0x\0'), patch('domain_proxy.os.kill') as kill:
            self.proxy._stop(201)
            kill.assert_not_called()
        self.assertFalse(self.proxy._paths(201)['pid'].exists())

    def test_fakeip_without_domain_has_reject_guard(self):
        guard = self.config()['route']['rules'][-1]
        self.assertEqual(guard['action'], 'reject')
        self.assertEqual(guard['mode'], 'and')
        self.assertEqual(guard['rules'][0]['ip_cidr'], [FAKEIP_NETWORK])
        self.assertTrue(guard['rules'][1]['invert'])


if __name__ == '__main__':
    unittest.main()
