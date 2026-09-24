"""Broad provider refresh lifecycle without network or host firewall access."""
import copy
import os
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

import test_awg_manager as fixture
from test_destination_worker import ObservedLock


class ServiceNetworkWorkerTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.manager = fixture.AmneziaManager.__new__(fixture.AmneziaManager)
        self.manager.config_lock = ObservedLock()
        self.manager.stop_expiration_worker = threading.Event()
        self.manager.config = {'servers': [self.server()]}
        self.manager.is_interface_running = Mock(return_value=True)
        self.manager._write_xray_config = Mock(side_effect=self.require_lock)
        self.routing = Mock()
        self.routing.refresh_provider_pool.side_effect = self.require_lock
        self.manager._selective_routing = Mock(return_value=self.routing)
        self.now = 100000
        self.networks = ['104.16.0.0/13', '160.79.104.0/23']
        self.status = {'networks': 2, 'last_attempt': None, 'last_success': None, 'errors': 0}
        self.refresh_hook = None
        self.patch('CONFIG_DIR', self.directory.name, create=True)
        self.status_reader = self.patch('expanded_network_status', side_effect=self.read_status)
        self.loader = self.patch('load_expanded_networks', side_effect=self.load_networks)
        self.refresher = self.patch('refresh_expanded_networks', side_effect=self.refresh)
        clock = patch.object(fixture.time, 'time', side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)

    def patch(self, name, *args, **kwargs):
        patcher = patch.object(fixture, name, *args, **kwargs)
        result = patcher.start()
        self.addCleanup(patcher.stop)
        return result

    @staticmethod
    def server(identifier='one', **changes):
        result = {
            'id': identifier, 'interface': f'wg-{identifier}', 'protocol': 'wireguard',
            'mode': 'edge_linked', 'upstream': {
                'interface': f'up-{identifier}', 'table_id': 1001,
                'routing_mode': 'ai_tiktok', 'service_ip_profile': 'expanded',
            },
        }
        result.update(changes)
        return result

    @staticmethod
    def identity(server):
        return (server['id'], server.get('protocol'), server.get('interface'), server['upstream']['table_id'])

    def require_lock(self, *_):
        self.assertEqual(self.manager.config_lock.depth, 1, 'live policy writes require the config lock')

    def read_status(self, directory):
        self.assertEqual(self.manager.config_lock.depth, 0)
        self.assertEqual(directory, os.path.join(self.directory.name, 'routing'))
        return copy.deepcopy(self.status)

    def load_networks(self, directory):
        self.assertEqual(self.manager.config_lock.depth, 0)
        return list(self.networks)

    def refresh(self, directory):
        self.assertEqual(self.manager.config_lock.depth, 0, 'provider downloads must not hold the config lock')
        self.assertEqual(directory, os.path.join(self.directory.name, 'routing'))
        self.status.update(last_attempt=self.now, last_success=self.now)
        if self.refresh_hook:
            self.refresh_hook()
        return copy.deepcopy(self.status)

    def tick(self):
        self.manager.service_network_tick()

    def test_refresh_off_lock_apply_under_lock_and_unchanged_revision_is_skipped(self):
        server = self.manager.config['servers'][0]
        self.tick()
        self.refresher.assert_called_once()
        self.routing.refresh_provider_pool.assert_called_once_with(server)
        self.assertIn(self.identity(server), self.manager._provider_applied)
        self.now += 60
        self.tick()
        self.refresher.assert_called_once()
        self.routing.refresh_provider_pool.assert_called_once()
        self.assertEqual(self.manager.config_lock.depth, 0)

    def test_legacy_standard_inactive_and_nonselective_servers_do_not_download(self):
        for kind in ('legacy', 'standard', 'inactive', 'all', 'ru_split', 'standalone'):
            with self.subTest(kind=kind):
                server = self.server()
                if kind == 'legacy':
                    del server['upstream']['service_ip_profile']
                elif kind == 'standard':
                    server['upstream']['service_ip_profile'] = 'standard'
                elif kind in ('all', 'ru_split'):
                    server['upstream']['routing_mode'] = kind
                elif kind == 'standalone':
                    server.update(mode='standalone', upstream=None)
                self.manager.config['servers'] = [server]
                self.manager.is_interface_running.return_value = kind != 'inactive'
                self.tick()
        self.status_reader.assert_not_called()
        self.refresher.assert_not_called()
        self.loader.assert_not_called()
        self.routing.refresh_provider_pool.assert_not_called()

    def test_multiple_servers_share_download_and_vless_uses_one_config_write(self):
        second = self.server('two')
        vless_one = self.server('v1', protocol='vless', interface=None)
        vless_two = self.server('v2', protocol='vless', interface=None)
        self.manager.config['servers'].extend([second, vless_one, vless_two])
        self.tick()
        self.refresher.assert_called_once()
        self.assertEqual(self.routing.refresh_provider_pool.call_count, 2)
        self.manager._write_xray_config.assert_called_once_with()
        self.assertEqual(len(self.manager._provider_applied), 4)
        self.manager.is_interface_running.assert_any_call('wg-one')
        self.assertNotIn(None, [call.args[0] for call in self.manager.is_interface_running.call_args_list])

    def test_daily_download_and_hourly_error_retry_do_not_reapply_unchanged_sets(self):
        self.tick()
        self.now += 86399
        self.tick()
        self.refresher.assert_called_once()
        self.now += 1
        self.tick()
        self.assertEqual(self.refresher.call_count, 2)
        self.routing.refresh_provider_pool.assert_called_once()
        self.status['errors'] = 1
        self.now += 3599
        self.tick()
        self.assertEqual(self.refresher.call_count, 2)
        self.now += 1
        self.tick()
        self.assertEqual(self.refresher.call_count, 3)
        self.routing.refresh_provider_pool.assert_called_once()

    def test_new_revision_replaces_every_current_policy(self):
        self.tick()
        original_revision = self.manager._provider_applied[self.identity(self.manager.config['servers'][0])]
        self.now += 86400
        self.refresh_hook = lambda: self.networks.append('151.101.0.0/16')
        self.tick()
        self.assertEqual(self.routing.refresh_provider_pool.call_count, 2)
        self.assertNotEqual(self.manager._provider_applied[self.identity(self.manager.config['servers'][0])], original_revision)

    def test_server_removed_detached_stopped_or_opted_out_during_download_is_not_reapplied(self):
        for kind in ('removed', 'detached', 'stopped', 'standard', 'all'):
            with self.subTest(kind=kind):
                self.manager.config['servers'] = [self.server()]
                self.manager.is_interface_running.return_value = True
                self.status['last_attempt'] = None
                self.routing.reset_mock()

                def change_configuration():
                    with self.manager.config_lock:
                        if kind == 'removed':
                            self.manager.config['servers'].clear()
                            return
                        server = copy.deepcopy(self.manager.config['servers'][0])
                        if kind == 'detached':
                            server.update(mode='standalone', upstream=None)
                        elif kind == 'stopped':
                            self.manager.is_interface_running.return_value = False
                        elif kind == 'standard':
                            server['upstream']['service_ip_profile'] = 'standard'
                        else:
                            server['upstream']['routing_mode'] = 'all'
                        self.manager.config['servers'][0] = server

                self.refresh_hook = change_configuration
                self.tick()
                self.routing.refresh_provider_pool.assert_not_called()
                self.assertEqual(self.manager._provider_applied, {})

    def test_replaced_server_uses_current_table_and_removes_stale_identity(self):
        self.tick()
        old_identity = self.identity(self.manager.config['servers'][0])
        self.now += 86400

        def replace_server():
            with self.manager.config_lock:
                replacement = self.server('one', interface='wg-new')
                replacement['upstream']['table_id'] = 1002
                self.manager.config['servers'][0] = replacement

        self.refresh_hook = replace_server
        self.tick()
        current = self.manager.config['servers'][0]
        self.assertIs(self.routing.refresh_provider_pool.call_args.args[0], current)
        self.assertNotIn(old_identity, self.manager._provider_applied)
        self.assertIn(self.identity(current), self.manager._provider_applied)

    def test_apply_failure_retries_without_redownload_and_does_not_block_other_servers(self):
        first = self.manager.config['servers'][0]
        second = self.server('two')
        self.manager.config['servers'].append(second)
        self.routing.refresh_provider_pool.side_effect = [RuntimeError('ipset restore failed'), None]
        self.tick()
        self.assertNotIn(self.identity(first), self.manager._provider_applied)
        self.assertIn(self.identity(second), self.manager._provider_applied)
        self.routing.refresh_provider_pool.side_effect = self.require_lock
        self.now += 60
        self.tick()
        self.refresher.assert_called_once()
        self.assertEqual(self.routing.refresh_provider_pool.call_count, 3)
        self.routing.refresh_provider_pool.assert_called_with(first)
        self.assertEqual(len(self.manager._provider_applied), 2)

    def test_xray_failure_retries_without_losing_successful_awg_apply(self):
        vless = self.server('v1', protocol='vless', interface=None)
        self.manager.config['servers'].append(vless)
        self.manager._write_xray_config.side_effect = RuntimeError('config reload failed')
        self.tick()
        self.assertNotIn(self.identity(vless), self.manager._provider_applied)
        self.assertIn(self.identity(self.manager.config['servers'][0]), self.manager._provider_applied)
        self.manager._write_xray_config.side_effect = self.require_lock
        self.now += 60
        self.tick()
        self.refresher.assert_called_once()
        self.routing.refresh_provider_pool.assert_called_once()
        self.assertEqual(self.manager._write_xray_config.call_count, 2)
        self.assertIn(self.identity(vless), self.manager._provider_applied)

    def test_shutdown_before_or_during_download_skips_live_policy_changes(self):
        self.manager.stop_expiration_worker.set()
        self.tick()
        self.refresher.assert_not_called()
        self.routing.refresh_provider_pool.assert_not_called()
        self.manager.stop_expiration_worker.clear()
        self.refresh_hook = self.manager.stop_expiration_worker.set
        self.tick()
        self.refresher.assert_called_once()
        self.routing.refresh_provider_pool.assert_not_called()
        self.manager._write_xray_config.assert_not_called()

    def test_xray_reported_write_failure_is_retried_without_downloading_again(self):
        server = self.server('v1', protocol='vless', interface=None)
        self.manager.config['servers'] = [server]
        self.manager._write_xray_config.side_effect = None
        self.manager._write_xray_config.return_value = False
        self.tick()
        self.assertNotIn(self.identity(server), self.manager._provider_applied)
        self.manager._write_xray_config.return_value = True
        self.now += 60
        self.tick()
        self.refresher.assert_called_once()
        self.assertEqual(self.manager._write_xray_config.call_count, 2)
        self.assertIn(self.identity(server), self.manager._provider_applied)

    def test_background_loop_survives_refresh_exception_and_waits_before_retry(self):
        self.manager.service_network_tick = Mock(side_effect=[RuntimeError('feed unavailable'), None])
        stop = Mock()
        stop.is_set.side_effect = [False, False, True]
        self.manager.stop_expiration_worker = stop
        self.manager.service_network_worker()
        self.assertEqual(self.manager.service_network_tick.call_count, 2)
        self.assertEqual([call.args for call in stop.wait.call_args_list], [(60,), (60,)])


if __name__ == '__main__':
    unittest.main()
