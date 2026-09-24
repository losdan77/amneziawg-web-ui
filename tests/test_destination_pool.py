"""DNS-independent destination pool validation, refresh and persistence."""
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-ui'))
from routing_policy import (BUILTIN_SERVICE_CIDRS, SEED_TTL, SelectiveRouting,
                            normalize_service_cidrs, resolve_service_hosts)


class DestinationValidationTests(unittest.TestCase):
    def test_public_addresses_and_networks_are_canonical_and_deduplicated(self):
        self.assertEqual(normalize_service_cidrs(['8.8.8.8', '8.8.8.8/32', '104.16.2.3/13']),
                         ['8.8.8.8/32', '104.16.0.0/13'])
        self.assertEqual(normalize_service_cidrs(None), [])
        self.assertEqual(normalize_service_cidrs([]), [])

    def test_bad_entries_cannot_route_all_private_or_reserved_traffic(self):
        rejected = ('0.0.0.0/0', '128.0.0.0/1', '8.0.0.0/7', '10.1.1.1',
                    '192.168.1.0/24', '100.64.0.0/10', '127.0.0.1', '169.254.1.1',
                    '224.0.0.1', '240.0.0.1', '203.0.113.1', '198.18.0.0/15',
                    '192.0.0.0/8', '172.0.0.0/8', '100.0.0.0/8', '::/0',
                    '8.8.8.8\n1.1.1.1', ' 8.8.8.8', '8.8.8.8;echo bad', '', None, 7)
        for value in rejected:
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_service_cidrs([value])
        for value in ('8.8.8.8', {}, ['8.8.8.8'] * 257):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_service_cidrs(value)

    def test_parallel_resolution_filters_answers_and_preserves_other_successes(self):
        def resolver(host):
            if host == 'failed.example':
                raise TimeoutError('unavailable')
            return ['8.8.8.8', '8.8.8.8', '1.1.1.1', '::1', '127.0.0.1',
                    '10.0.0.1', '203.0.113.1', '224.0.0.1', 'not an address']
        result = resolve_service_hosts(('works.example', 'failed.example'), resolver)
        self.assertEqual(result, {'addresses': ['1.1.1.1', '8.8.8.8'],
                                 'errors': ['failed.example'], 'resolved_hosts': 1, 'queried_hosts': 2})

    def test_empty_or_non_public_answers_are_reported_as_failures(self):
        result = resolve_service_hosts(('empty.example',), lambda _: ['192.168.0.1'])
        self.assertEqual(result['addresses'], [])
        self.assertEqual(result['errors'], ['empty.example'])
        self.assertEqual(result['resolved_hosts'], 0)

    def test_default_doh_validates_dns_status_and_a_record_type(self):
        response = Mock()
        response.json.return_value = {'Status': 0, 'Answer': [
            {'type': 1, 'data': '8.8.8.8'}, {'type': 5, 'data': 'alias.example'},
            {'type': 28, 'data': '2001:4860:4860::8888'}]}
        with patch('routing_policy.requests.get', return_value=response) as get:
            result = resolve_service_hosts(('works.example',))
        self.assertEqual(result['addresses'], ['8.8.8.8'])
        self.assertEqual(get.call_args.args[0], 'https://dns.google/resolve')
        self.assertEqual(get.call_args.kwargs['timeout'], (3, 5))
        response.raise_for_status.assert_called_once()


class DestinationPoolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.commands = []
        self.responses = {}
        self.run = Mock(side_effect=lambda command: self.commands.append(command) or self.responses.get(command, ''))
        self.routing = SelectiveRouting(self.run, self.directory.name)
        self.server = {'interface': 'wg1', 'subnet': '10.1.0.0/24', 'server_ip': '10.1.0.1',
                       'dns': ['1.1.1.1'], 'upstream': {'table_id': 201, 'fwmark': 41001}}

    def result(self, addresses, errors=None):
        return {'addresses': addresses, 'errors': errors or [],
                'resolved_hosts': bool(addresses), 'queried_hosts': 1}

    def test_official_and_custom_networks_are_permanent_and_dns_set_is_separate(self):
        self.server['upstream']['service_cidrs'] = ['8.8.8.0/24']
        self.routing.configure(self.server)
        for network in [*BUILTIN_SERVICE_CIDRS, '8.8.8.0/24']:
            self.assertIn(f'ipset add awgpool_201 {network} timeout 0 -exist', self.commands)
        self.assertTrue(any(command.startswith('ipset create awgsel_201 hash:ip') for command in self.commands))
        self.assertTrue(any(command.startswith('ipset create awgpool_201 hash:net') for command in self.commands))
        self.assertFalse(any('ipset flush' in command for command in self.commands))

    def test_live_chain_pool_classifier_precedes_preexisting_save_mark(self):
        self.routing.configure(self.server)
        pool_rule = next(command for command in self.commands if 'iptables -t mangle -I AWGSEL_201' in command)
        self.assertIn('-I AWGSEL_201 2 -m set --match-set awgpool_201 dst -j MARK --set-mark 41001', pool_rule)
        self.assertIn('-C AWGSEL_201', pool_rule)
        self.assertTrue(any('CONNMARK --restore-mark' in command for command in self.commands))
        self.assertTrue(any('CONNMARK --save-mark' in command for command in self.commands))

    def test_reapply_removes_old_custom_network_but_preserves_dynamic_addresses(self):
        self.responses['ipset save awgpool_201'] = (
            'add awgpool_201 8.8.4.0/24 timeout 0\n'
            'add awgpool_201 8.8.8.8 timeout 200\n'
            'add awgpool_201 160.79.104.0/23 timeout 0\n')
        self.routing.configure(self.server)
        self.assertIn('ipset del awgpool_201 8.8.4.0/24 -exist', self.commands)
        self.assertFalse(any(command.startswith('ipset del ') and '8.8.8.8' in command for command in self.commands))
        self.assertFalse(any(command.startswith('ipset del ') and '160.79.104.0/23' in command for command in self.commands))

    def test_seed_application_can_classify_without_client_dns_and_survives_namespace_loss(self):
        with patch('routing_policy.time.time', return_value=1000):
            self.routing.configure(self.server)
            self.routing.apply_seed_addresses(self.server, self.result(['8.8.8.8']))
        self.assertIn(f'ipset add awgpool_201 8.8.8.8/32 timeout {SEED_TTL} -exist', self.commands)
        # No cleanup is called: a fresh namespace has no ipsets or DNS process.
        self.commands.clear()
        restarted = SelectiveRouting(self.run, self.directory.name)
        with patch('routing_policy.time.time', return_value=1020):
            restarted.configure(self.server)
        self.assertIn(f'ipset add awgpool_201 8.8.8.8/32 timeout {SEED_TTL - 20} -exist', self.commands)
        self.assertFalse(any(command.startswith('ipset add awgsel_201') for command in self.commands))

    def test_failed_refresh_retains_unexpired_seed_and_last_success(self):
        with patch('routing_policy.time.time', return_value=1000):
            self.routing.apply_seed_addresses(self.server, self.result(['8.8.8.8']))
        with patch('routing_policy.time.time', return_value=1050):
            status = self.routing.apply_seed_addresses(self.server, self.result([], ['failed.example']))
        self.assertIn(f'ipset add awgpool_201 8.8.8.8/32 timeout {SEED_TTL - 50} -exist', self.commands)
        self.assertEqual(status['last_success'], 1000)
        self.assertEqual(status['last_attempt'], 1050)
        self.assertEqual(status['addresses'], 1)
        self.assertEqual(status['errors'], ['failed.example'])
        self.assertEqual(self.routing.seed_status(self.server), status)
        with patch('routing_policy.time.time', return_value=5000):
            status = self.routing.apply_seed_addresses(self.server, self.result([]))
        self.assertEqual(status['addresses'], 0)

    def test_periodic_dns_snapshot_survives_restart_without_cleanup(self):
        self.responses['ipset save awgsel_201 2>/dev/null'] = 'add awgsel_201 8.8.4.4 timeout 120\n'
        with patch('routing_policy.time.time', return_value=1000):
            self.routing.save_addresses(self.server)
        self.commands.clear()
        with patch('routing_policy.time.time', return_value=1010):
            SelectiveRouting(self.run, self.directory.name).configure(self.server)
        self.assertIn('ipset add awgsel_201 8.8.4.4 timeout 110 -exist', self.commands)
        self.assertEqual(list(Path(self.directory.name).glob('*.tmp')), [])

    def test_failed_dns_snapshot_keeps_the_last_successful_snapshot(self):
        command = 'ipset save awgsel_201 2>/dev/null'
        self.responses[command] = 'add awgsel_201 8.8.4.4 timeout 120\n'
        self.routing.save_addresses(self.server)
        cache = Path(self.directory.name, 'addresses-wg1.json')
        before = cache.read_bytes()
        self.responses[command] = None
        self.routing.save_addresses(self.server)
        self.assertEqual(cache.read_bytes(), before)

    def test_seed_does_not_change_a_permanent_custom_host_to_expiring(self):
        self.server['upstream']['service_cidrs'] = ['8.8.8.8']
        self.routing.configure(self.server)
        self.commands.clear()
        self.routing.apply_seed_addresses(self.server, self.result(['8.8.8.8']))
        self.assertFalse(any(command.startswith('ipset add') for command in self.commands))

    def test_apply_rejects_unvalidated_addresses_before_shell_invocation(self):
        for address in ('8.8.8.8;echo bad', '127.0.0.1', '::1', '203.0.113.1', None):
            with self.subTest(address=address), self.assertRaises(ValueError):
                self.routing.apply_seed_addresses(self.server, self.result([address]))
        self.assertEqual(self.commands, [])

    def test_cleanup_owns_only_its_pools_and_retains_seed_cache_for_restart(self):
        self.routing.apply_seed_addresses(self.server, self.result(['8.8.8.8']))
        cache = Path(self.directory.name, 'seed-addresses-wg1.json')
        before = cache.read_bytes()
        self.commands.clear()
        self.routing.cleanup(self.server)
        self.assertIn('ipset destroy awgpool_201 2>/dev/null || true', self.commands)
        self.assertEqual(cache.read_bytes(), before)
        self.assertFalse(any('awgpool_202' in command for command in self.commands))

    def test_corrupt_seed_cache_is_ignored_without_breaking_configuration(self):
        Path(self.directory.name, 'seed-addresses-wg1.json').write_text('not json')
        self.routing.configure(self.server)
        self.assertTrue(any(command.startswith('ipset add awgpool_201 160.79.') for command in self.commands))

    def test_atomic_cache_write_failure_keeps_previous_snapshot(self):
        self.routing.apply_seed_addresses(self.server, self.result(['8.8.8.8']))
        cache = Path(self.directory.name, 'seed-addresses-wg1.json')
        before = cache.read_bytes()
        with patch('routing_policy.os.replace', side_effect=OSError('disk error')):
            with self.assertRaises(OSError):
                self.routing.apply_seed_addresses(self.server, self.result(['1.1.1.1']))
        self.assertEqual(cache.read_bytes(), before)
        self.assertEqual(list(Path(self.directory.name).glob('*.tmp')), [])


if __name__ == '__main__':
    unittest.main()
