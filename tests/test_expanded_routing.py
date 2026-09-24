"""Broad destination coverage preserves live routing and remains opt-in."""
import copy
from pathlib import Path
import shlex
import tempfile
import unittest
from unittest.mock import patch

import test_routing_diagnostics as diagnostic_fixture
import test_upstream_management as upstream_fixture
from routing_policy import SelectiveRouting, service_destination_networks


class ProviderPoolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.server = {'interface': 'wg1', 'subnet': '10.1.0.0/24', 'server_ip': '10.1.0.1',
                       'upstream': {'table_id': 201, 'fwmark': 41001,
                                    'service_ip_profile': 'expanded'}}
        self.commands, self.restores = [], []
        self.sets = {'awgwide_201': {'104.18.0.0/16'}, 'awgwide_202': {'151.101.0.0/16'}}
        self.fail_restore = self.fail_swap = False
        self.routing = SelectiveRouting(self.execute, self.directory.name)
        self.networks = ['172.64.0.0/13', '95.100.0.0/15']
        patcher = patch('routing_policy.load_expanded_networks', return_value=self.networks)
        self.loader = patcher.start()
        self.addCleanup(patcher.stop)

    def execute(self, command):
        self.commands.append(command)
        fields = shlex.split(command)
        if fields[:2] == ['ipset', 'create']:
            self.sets.setdefault(fields[2], set())
        elif fields[:2] == ['ipset', 'destroy']:
            self.sets.pop(fields[2], None)
        elif fields[:2] == ['ipset', 'restore']:
            # Model a partial kernel restore: its staging set may be modified,
            # but the currently referenced set must survive until a swap.
            text = Path(fields[3]).read_text()
            self.restores.append(text)
            for line in text.splitlines():
                parts = line.split()
                if parts[0] == 'create':
                    self.sets[parts[1]] = set()
                elif parts[0] == 'add':
                    self.sets[parts[1]].add(parts[2])
                    if self.fail_restore:
                        return None
            self.assertEqual(self.sets['awgwide_201'], {'104.18.0.0/16'})
        elif fields[:2] == ['ipset', 'swap']:
            if self.fail_swap:
                return None
            self.sets[fields[2]], self.sets[fields[3]] = self.sets[fields[3]], self.sets[fields[2]]
        return ''

    def test_complete_staging_set_is_swapped_once_and_other_entry_is_untouched(self):
        self.routing.refresh_provider_pool(self.server)
        self.assertEqual(self.sets['awgwide_201'], set(self.networks))
        self.assertEqual(self.sets['awgwide_202'], {'151.101.0.0/16'})
        self.assertNotIn('awgwtmp_201', self.sets)
        self.assertEqual(sum(command.startswith('ipset swap ') for command in self.commands), 1)
        self.assertFalse(list(Path(self.directory.name).glob('provider-*.restore')))
        self.assertNotIn('flush', '\n'.join(self.commands))

    def test_partial_restore_failure_keeps_live_pool_and_removes_staging_files(self):
        self.fail_restore = True
        with self.assertRaises(RuntimeError):
            self.routing.refresh_provider_pool(self.server)
        self.assertEqual(self.sets['awgwide_201'], {'104.18.0.0/16'})
        self.assertNotIn('awgwtmp_201', self.sets)
        self.assertFalse(any(command.startswith('ipset swap ') for command in self.commands))
        self.assertFalse(list(Path(self.directory.name).glob('provider-*.restore')))

    def test_swap_failure_keeps_previous_live_pool(self):
        self.fail_swap = True
        with self.assertRaises(RuntimeError):
            self.routing.refresh_provider_pool(self.server)
        self.assertEqual(self.sets['awgwide_201'], {'104.18.0.0/16'})
        self.assertNotIn('awgwtmp_201', self.sets)

    def test_legacy_profile_does_not_load_or_install_broad_destinations(self):
        self.server['upstream'].pop('service_ip_profile')
        self.routing.refresh_provider_pool(self.server)
        self.loader.assert_not_called()
        self.assertEqual(self.commands, [])
        self.assertEqual(service_destination_networks(self.server['upstream']), ['160.79.104.0/23'])
        self.loader.assert_not_called()

    def test_expanded_preserves_builtin_and_administrator_ranges(self):
        self.server['upstream']['service_cidrs'] = ['45.67.89.10']
        networks = service_destination_networks(self.server['upstream'], self.directory.name)
        self.assertTrue({'160.79.104.0/23', '45.67.89.10/32', *self.networks} <= set(networks))

    def test_seed_expands_to_adjacent_subnet_only_for_explicit_expanded_profile(self):
        result = {'addresses': ['45.67.89.10', '45.67.89.20'], 'errors': [],
                  'resolved_hosts': 2, 'queried_hosts': 2}
        for profile in ('standard', 'expanded'):
            with self.subTest(profile=profile):
                self.commands.clear()
                self.server['upstream']['service_ip_profile'] = profile
                self.routing.apply_seed_addresses(self.server, result)
                additions = [command for command in self.commands if command.startswith('ipset add awgpool_201')]
                if profile == 'expanded':
                    self.assertEqual(len(additions), 1)
                    self.assertIn('45.67.89.0/24 timeout ', additions[0])
                else:
                    self.assertEqual(len(additions), 2)
                    self.assertTrue(all('/32 timeout ' in command for command in additions))

    def test_standard_downgrade_removes_expanded_seed_subnets_and_provider_rule(self):
        self.server['upstream']['service_ip_profile'] = 'standard'
        self.routing.apply_seed_addresses(self.server, {'addresses': ['45.67.89.10'], 'errors': []})
        self.commands.clear()

        def existing_pool(command):
            self.commands.append(command)
            if command == 'ipset list -n':
                return 'awgwide_201\nawgpool_201\nawgsel_201\n'
            if command == 'ipset save awgpool_201':
                return ('add awgpool_201 45.67.89.0/24 timeout 900\n'
                        'add awgpool_201 160.79.104.0/23 timeout 0\n')
            return ''

        self.routing.run = existing_pool
        self.routing.configure(self.server)
        self.assertIn('ipset del awgpool_201 45.67.89.0/24 -exist', self.commands)
        self.assertTrue(any('ipset add awgpool_201 45.67.89.10/32 timeout ' in c for c in self.commands))
        self.assertTrue(any('-D AWGSEL_201 -m set --match-set awgwide_201' in c for c in self.commands))
        self.assertFalse(any('ipset del awgpool_201 160.79.104.0/23' in c for c in self.commands))
        self.loader.assert_not_called()

    def test_failed_broad_rule_removal_aborts_standard_downgrade(self):
        self.server['upstream']['service_ip_profile'] = 'standard'

        def failing_delete(command):
            if command == 'ipset list -n':
                return 'awgwide_201\n'
            if 'iptables -t mangle -D AWGSEL_201 -m set --match-set awgwide_201' in command:
                return None
            return ''

        self.routing.run = failing_delete
        with self.assertRaises(RuntimeError):
            self.routing.configure(self.server)


class ExpandedDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        diagnostic_fixture.RoutingDiagnosticsTests.setUp(self)
        self.server['upstream']['service_ip_profile'] = 'expanded'

    def execute(self, command):
        if command.startswith('ipset test awgwide_201 '):
            self.commands.append(command)
            return 'matched' if '172.64.155.209' in command else ''
        if (command.startswith('iptables -t mangle -C ')
                and 'match-set awgwide_201' in command and self.missing_rule == 'provider'):
            self.commands.append(command)
            return ''
        return diagnostic_fixture.RoutingDiagnosticsTests.execute(self, command)

    def test_provider_match_uses_actual_kernel_mark_rule(self):
        result = self.manager.get_upstream_diagnostics('entry', '172.64.155.209')
        target = result['destinations'][0]
        self.assertTrue(target['provider_match'])
        self.assertTrue(target['pool_match'])
        self.assertFalse(target['dns_match'])
        self.assertEqual(target['route'], 'upstream')
        self.resolver.assert_not_called()

    def test_provider_membership_without_its_mark_rule_reports_local(self):
        self.missing_rule = 'provider'
        result = self.manager.get_upstream_diagnostics('entry', '172.64.155.209')
        self.assertTrue(result['destinations'][0]['provider_match'])
        self.assertFalse(result['classifier']['rules_attached'])
        self.assertEqual(result['destinations'][0]['route'], 'local')

    def test_standard_profile_ignores_stale_broad_pool(self):
        self.server['upstream']['service_ip_profile'] = 'standard'
        result = self.manager.get_upstream_diagnostics('entry', '172.64.155.209')
        self.assertFalse(result['destinations'][0]['provider_match'])
        self.assertFalse(result['destinations'][0]['matched'])
        self.assertEqual(result['destinations'][0]['route'], 'local')
        self.assertFalse(any('awgwide_' in command for command in self.commands))


class ExpandedUpstreamManagementTests(unittest.TestCase):
    server = upstream_fixture.UpstreamManagementTests.server
    client = upstream_fixture.UpstreamManagementTests.client
    setUp = upstream_fixture.UpstreamManagementTests.setUp
    execute = upstream_fixture.UpstreamManagementTests.execute
    imported_config = staticmethod(upstream_fixture.UpstreamManagementTests.imported_config)
    provision = upstream_fixture.UpstreamManagementTests.provision
    attach = upstream_fixture.UpstreamManagementTests.attach
    assert_entry_unchanged = upstream_fixture.UpstreamManagementTests.assert_entry_unchanged

    def test_import_preserves_profile_across_policy_edit_and_replacement(self):
        server = self.provision()
        self.attach(server, routing_mode='ai_tiktok', service_ip_profile='expanded')
        self.assertEqual(server['upstream']['service_ip_profile'], 'expanded')
        self.assert_entry_unchanged(server)
        self.manager.update_server_upstream(server['id'], {'routing_mode': 'ru_split'})
        self.assertEqual(server['upstream']['service_ip_profile'], 'expanded')
        self.manager.update_server_upstream(server['id'], {
            'import_config': self.imported_config('3'), 'routing_mode': 'ai_tiktok'})
        self.assertEqual(server['upstream']['service_ip_profile'], 'expanded')
        self.assert_entry_unchanged(server)
        self.manager.update_server_upstream(server['id'], {'service_ip_profile': 'standard'})
        self.assertEqual(server['upstream']['service_ip_profile'], 'standard')

    def test_legacy_import_defaults_to_standard(self):
        server = self.provision()
        self.attach(server, routing_mode='ai_tiktok')
        self.assertEqual(server['upstream']['service_ip_profile'], 'standard')

    def test_invalid_profile_rejected_before_changing_live_server(self):
        server = self.provision()
        self.attach(server, routing_mode='ai_tiktok', service_ip_profile='expanded')
        before = copy.deepcopy(self.manager.config)
        self.commands.clear()
        for value in ('all', 'Expanded', '0.0.0.0/0', {}, True):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.manager.update_server_upstream(server['id'], {'service_ip_profile': value})
            self.assertEqual(self.manager.config, before)
        self.assertEqual(self.commands, [])


if __name__ == '__main__':
    unittest.main()
