"""DNS classifier configuration and resource ownership without a root daemon."""
import copy
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-ui'))
from routing_policy import AI_TIKTOK_DOMAINS, SelectiveRouting, normalize_routing_policy


class PolicyNormalizationTests(unittest.TestCase):
    def test_explicit_modes_override_legacy_checkbox(self):
        for mode in ('all', 'ru_split', 'ai_tiktok'):
            self.assertEqual(normalize_routing_policy({'routing_mode': mode, 'split_ru_local': True}), mode)

    def test_legacy_default_and_boolean_values_are_preserved(self):
        self.assertEqual(normalize_routing_policy({}), 'ru_split')
        for value in (True, None, 'true', '1', 'yes', 'on', ' TRUE '):
            self.assertEqual(normalize_routing_policy({'split_ru_local': value}), 'ru_split')
        for value in (False, 'false', '0', 'no', 'off'):
            self.assertEqual(normalize_routing_policy({'split_ru_local': value}), 'all')

    def test_invalid_policy_is_never_silently_treated_as_direct(self):
        for mode in ('', 'unknown', 'AI_TIKTOK', [], {}, 4):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                normalize_routing_policy({'routing_mode': mode})

    def test_service_suffixes_are_unique_safe_and_do_not_capture_entire_shared_providers(self):
        self.assertEqual(len(AI_TIKTOK_DOMAINS), len(set(AI_TIKTOK_DOMAINS)))
        for domain in AI_TIKTOK_DOMAINS:
            self.assertRegex(domain, r'^[a-z0-9]+(?:[.-][a-z0-9]+)+$')
        self.assertTrue({'chatgpt.com', 'openai.com', 'claude.ai', 'tiktok.com', 'tiktokcdn.com'} <= set(AI_TIKTOK_DOMAINS))
        self.assertTrue({'google.com', 'microsoft.com', 'cloudflare.com', 'amazonaws.com'}.isdisjoint(AI_TIKTOK_DOMAINS))


class SelectiveRoutingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.commands = []
        self.run = Mock(side_effect=lambda command: self.commands.append(command) or '')
        self.routing = SelectiveRouting(self.run, self.directory.name)
        self.server = {'interface': 'wg1', 'subnet': '10.1.0.0/24', 'server_ip': '10.1.0.1',
                       'dns': ['1.1.1.1', '8.8.8.8'], 'upstream': {'table_id': 201, 'fwmark': 41001}}

    def test_dns_daemon_is_bound_to_entry_ip_and_populates_its_own_ipset(self):
        self.routing.configure(self.server)
        config = Path(self.directory.name, 'dns-201.conf').read_text()
        for directive in ('port=5353', 'listen-address=10.1.0.1', 'bind-interfaces', 'no-resolv',
                          'filter-AAAA', 'server=1.1.1.1', 'server=8.8.8.8'):
            self.assertIn(directive + '\n', config)
        for domain in AI_TIKTOK_DOMAINS:
            self.assertIn(f'ipset=/{domain}/awgsel_201\n', config)
        self.assertEqual(sum(command.startswith('dnsmasq --conf-file=') for command in self.commands), 1)
        self.assertNotIn('server=10.1.0.1', config)

    def test_dns_cache_lifetime_is_less_than_ipset_timeout_and_flows_keep_marks(self):
        self.routing.configure(self.server)
        config = Path(self.directory.name, 'dns-201.conf').read_text()
        ttl = int(re.search(r'^max-cache-ttl=(\d+)$', config, re.M).group(1))
        set_command = next(command for command in self.commands if command.startswith('ipset create '))
        timeout = int(re.search(r'timeout (\d+)', set_command).group(1))
        self.assertGreater(timeout, ttl)
        self.assertIn('max-ttl=300', config)
        joined = '\n'.join(self.commands)
        self.assertIn('-m connmark --mark 41001 -j CONNMARK --restore-mark', joined)
        self.assertIn('-m set --match-set awgsel_201 dst -j MARK --set-mark 41001', joined)
        self.assertIn('-m mark --mark 41001 -j CONNMARK --save-mark', joined)

    def test_dns_redirect_and_classification_apply_only_to_entry_subnet_and_interface(self):
        self.routing.configure(self.server)
        prerouting = [command for command in self.commands if ' PREROUTING ' in command]
        self.assertEqual(len(prerouting), 3)
        self.assertTrue(all('-i wg1 -s 10.1.0.0/24' in command for command in prerouting))
        self.assertTrue(any('-p tcp --dport 53' in command for command in prerouting))
        self.assertTrue(any('-p udp --dport 53' in command for command in prerouting))
        self.assertFalse(any('OUTPUT' in command for command in self.commands))

    def test_two_entries_use_independent_dns_files_sets_and_chains(self):
        self.routing.configure(self.server)
        second = copy.deepcopy(self.server)
        second.update(interface='wg2', subnet='10.2.0.0/24', server_ip='10.2.0.1')
        second['upstream'].update(table_id=202, fwmark=41002)
        self.routing.configure(second)
        first_content = Path(self.directory.name, 'dns-201.conf').read_bytes()
        self.commands.clear()
        self.routing.cleanup(second)
        self.assertEqual(Path(self.directory.name, 'dns-201.conf').read_bytes(), first_content)
        self.assertFalse(Path(self.directory.name, 'dns-202.conf').exists())
        self.assertTrue(all('201' not in command and 'wg1' not in command for command in self.commands))
        self.assertFalse(any('iptables -F ' == command for command in self.commands))

    def test_dns_does_not_recurse_into_its_own_address(self):
        self.server['dns'] = ['10.1.0.1', '::1']
        self.routing.ensure_dns(self.server)
        config = Path(self.directory.name, 'dns-201.conf').read_text()
        self.assertIn('server=1.1.1.1', config)
        self.assertNotIn('server=10.1.0.1', config)

    def test_unowned_pid_is_not_killed(self):
        Path(self.directory.name, 'dns-201.pid').write_text('99')
        with patch.object(Path, 'read_bytes', return_value=b'/usr/bin/unrelated\0--conf-file=other\0'), \
                patch('routing_policy.os.kill') as kill:
            self.routing.cleanup(self.server)
        kill.assert_not_called()

    def test_owned_pid_is_reused_and_only_owned_daemon_is_stopped(self):
        config_path = Path(self.directory.name, 'dns-201.conf')
        config_path.write_text('existing config')
        Path(self.directory.name, 'dns-201.pid').write_text('99')
        command_line = b'/usr/sbin/dnsmasq\0' + f'--conf-file={config_path}'.encode() + b'\0'
        with patch.object(Path, 'read_bytes', return_value=command_line) as read_process, patch('routing_policy.os.kill') as kill:
            def stop_process(*args):
                read_process.return_value = b''
            kill.side_effect = stop_process
            self.routing.ensure_dns(self.server)
            self.run.assert_not_called()
            self.routing.cleanup(self.server)
            kill.assert_called_once()
            self.assertEqual(kill.call_args.args[0], 99)

    def test_command_failure_and_invalid_interface_abort_configuration(self):
        self.run.side_effect = None
        self.run.return_value = None
        with self.assertRaises(RuntimeError):
            self.routing.configure(self.server)
        self.assertTrue(all(call.args[0].startswith('ipset ') for call in self.run.call_args_list))
        self.run.reset_mock()
        self.server['interface'] = 'wg1;touch x'
        with self.assertRaises(ValueError):
            self.routing.configure(self.server)
        self.run.assert_not_called()

    def test_cached_addresses_survive_replacement_but_expired_entries_do_not(self):
        self.run.side_effect = lambda command: self.commands.append(command) or (
            'add awgsel_201 203.0.113.5 timeout 120\nadd awgsel_201 203.0.113.6 timeout 1\n'
            if command.startswith('ipset save ') else '')
        with patch('routing_policy.time.time', return_value=1000):
            self.routing.cleanup(self.server)
        cache = Path(self.directory.name, 'addresses-wg1.json')
        self.assertEqual(json.loads(cache.read_text()), {'203.0.113.5': 1120, '203.0.113.6': 1001})
        self.commands.clear()
        self.server['upstream']['table_id'] = 205
        with patch('routing_policy.time.time', return_value=1002):
            self.routing.configure(self.server)
        self.assertIn('ipset add awgsel_205 203.0.113.5 timeout 118 -exist', self.commands)
        self.assertFalse(any('ipset add' in command and '203.0.113.6' in command for command in self.commands))

    def test_existing_ipset_is_not_repopulated_with_older_cached_values(self):
        Path(self.directory.name, 'addresses-wg1.json').write_text(json.dumps({'203.0.113.5': 1120}))
        self.run.side_effect = lambda command: self.commands.append(command) or ('awgsel_201' if command == 'ipset list -n' else '')
        with patch('routing_policy.time.time', return_value=1000):
            self.routing.configure(self.server)
        self.assertFalse(any(command.startswith('ipset add awgsel_') for command in self.commands))


if __name__ == '__main__':
    unittest.main()
