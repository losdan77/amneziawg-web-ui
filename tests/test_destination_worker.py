"""Exercise the destination worker lifecycle through the real AST-loaded manager.

No DNS, host firewall or background worker is started. Resolver callbacks model
configuration changes made while a network lookup is outside the manager lock.
"""
import copy
import threading
import unittest
from unittest.mock import Mock, patch

import test_awg_manager as fixture


class ObservedLock:
    def __init__(self):
        self.lock = threading.RLock()
        self.depth = 0

    def __enter__(self):
        self.lock.acquire()
        self.depth += 1
        return self

    def __exit__(self, *args):
        self.depth -= 1
        self.lock.release()


class DestinationWorkerTests(unittest.TestCase):
    def setUp(self):
        self.manager = fixture.AmneziaManager.__new__(fixture.AmneziaManager)
        self.manager.config_lock = ObservedLock()
        self.manager.stop_expiration_worker = threading.Event()
        self.manager.config = {'servers': [self.server()]}
        self.manager.is_interface_running = Mock(return_value=True)
        self.routing = Mock()
        self.manager._selective_routing = Mock(return_value=self.routing)
        self.last_refresh = {}
        self.now = 1000
        self.answer = {'addresses': ['160.79.104.1'], 'errors': [], 'resolved_hosts': 1, 'queried_hosts': 1}
        clock = patch.object(fixture.time, 'monotonic', side_effect=lambda: self.now)
        clock.start()
        self.addCleanup(clock.stop)
        resolver = patch.object(fixture, 'resolve_service_hosts', side_effect=self.resolve)
        self.resolver = resolver.start()
        self.addCleanup(resolver.stop)

    @staticmethod
    def server(identifier='one', **changes):
        result = {
            'id': identifier, 'interface': f'wg-{identifier}', 'protocol': 'wireguard',
            'mode': 'edge_linked', 'upstream': {
                'interface': f'up-{identifier}', 'table_id': 1001, 'routing_mode': 'ai_tiktok',
            },
        }
        result.update(changes)
        return result

    def resolve(self):
        self.assertEqual(self.manager.config_lock.depth, 0, 'network lookup must not hold the configuration lock')
        return copy.deepcopy(self.answer)

    def tick(self):
        self.manager.destination_cache_tick(self.last_refresh)

    def identity(self, server):
        return (server['id'], server['interface'], server['upstream']['table_id'])

    def test_snapshot_and_apply_are_locked_but_dns_is_not(self):
        def require_lock(*_):
            self.assertEqual(self.manager.config_lock.depth, 1)

        self.routing.save_addresses.side_effect = require_lock
        self.routing.apply_seed_addresses.side_effect = require_lock
        self.tick()
        server = self.manager.config['servers'][0]
        self.resolver.assert_called_once_with()
        self.routing.save_addresses.assert_called_once_with(server)
        self.routing.apply_seed_addresses.assert_called_once_with(server, self.answer)
        self.assertEqual(self.last_refresh, {self.identity(server): 1000})
        self.assertEqual(self.manager.config_lock.depth, 0)

    def test_snapshots_continue_between_throttled_refreshes(self):
        self.tick()
        self.now = 1599
        self.tick()
        self.assertEqual(self.routing.save_addresses.call_count, 2,
                         'learned client DNS addresses must survive container recreation even between seed refreshes')
        self.assertEqual(self.resolver.call_count, 1)
        self.assertEqual(self.routing.apply_seed_addresses.call_count, 1)
        self.now = 1600
        self.tick()
        self.assertEqual(self.routing.save_addresses.call_count, 3)
        self.assertEqual(self.resolver.call_count, 2)
        self.assertEqual(self.routing.apply_seed_addresses.call_count, 2)

    def test_multiple_due_servers_share_one_dns_lookup(self):
        first = self.manager.config['servers'][0]
        second = self.server('two')
        self.manager.config['servers'].append(second)
        self.tick()
        self.resolver.assert_called_once_with()
        self.assertEqual(self.routing.apply_seed_addresses.call_count, 2)
        self.assertEqual(self.last_refresh, {self.identity(first): 1000, self.identity(second): 1000})

    def test_partial_or_empty_dns_answers_retry_after_a_minute(self):
        for incomplete in (
            {'addresses': ['160.79.104.1'], 'errors': ['chatgpt.com'], 'resolved_hosts': 1, 'queried_hosts': 2},
            {'addresses': [], 'errors': ['chatgpt.com'], 'resolved_hosts': 0, 'queried_hosts': 1},
            {'addresses': [], 'errors': [], 'resolved_hosts': 0, 'queried_hosts': 0},
        ):
            with self.subTest(result=incomplete):
                self.now = 1000
                self.last_refresh.clear()
                self.resolver.reset_mock()
                self.routing.reset_mock()
                self.answer = incomplete
                self.tick()
                self.routing.apply_seed_addresses.assert_called_once_with(self.manager.config['servers'][0], incomplete)
                self.now = 1059
                self.tick()
                self.assertEqual(self.resolver.call_count, 1, 'partial failures must not cause an immediate retry loop')
                self.assertEqual(self.routing.save_addresses.call_count, 2, 'client DNS snapshots continue during retry backoff')
                self.now = 1060
                self.answer = {'addresses': ['160.79.104.1'], 'errors': [], 'resolved_hosts': 1, 'queried_hosts': 1}
                self.tick()
                self.assertEqual(self.resolver.call_count, 2, 'partial or empty answers retry without waiting ten minutes')
                self.now = 1659
                self.tick()
                self.assertEqual(self.resolver.call_count, 2, 'successful retry restores the normal refresh cadence')
                self.now = 1660
                self.tick()
                self.assertEqual(self.resolver.call_count, 3)

    def test_skips_inactive_nonselective_standalone_and_vless_servers(self):
        for kind in ('inactive', 'all', 'ru_split', 'standalone', 'vless'):
            with self.subTest(kind=kind):
                server = self.server()
                if kind in ('all', 'ru_split'):
                    server['upstream']['routing_mode'] = kind
                elif kind == 'standalone':
                    server.update(mode='standalone', upstream=None)
                elif kind == 'vless':
                    server['protocol'] = 'vless'
                self.manager.config['servers'] = [server]
                self.manager.is_interface_running.return_value = kind != 'inactive'
                self.tick()
        self.resolver.assert_not_called()
        self.routing.save_addresses.assert_not_called()
        self.routing.apply_seed_addresses.assert_not_called()
        self.assertEqual(self.last_refresh, {})

    def test_does_not_apply_to_stale_server_after_lookup(self):
        for kind in ('removed', 'detached', 'nonselective', 'interface_changed', 'table_changed', 'stopped', 'vless'):
            with self.subTest(kind=kind):
                self.manager.config['servers'] = [self.server()]
                self.manager.is_interface_running.return_value = True
                self.routing.reset_mock()
                self.last_refresh.clear()

                def resolve_while_config_changes():
                    answer = self.resolve()
                    with self.manager.config_lock:
                        # Swap the config record, as update/detach operations do.
                        replacement = copy.deepcopy(self.manager.config['servers'][0])
                        if kind == 'removed':
                            self.manager.config['servers'].clear()
                            return answer
                        if kind == 'detached':
                            replacement.update(mode='standalone', upstream=None)
                        elif kind == 'nonselective':
                            replacement['upstream']['routing_mode'] = 'all'
                        elif kind == 'interface_changed':
                            replacement['interface'] = 'wg-replaced'
                        elif kind == 'table_changed':
                            replacement['upstream']['table_id'] = 1002
                        elif kind == 'stopped':
                            self.manager.is_interface_running.return_value = False
                        elif kind == 'vless':
                            replacement['protocol'] = 'vless'
                        self.manager.config['servers'][0] = replacement
                    return answer

                self.resolver.side_effect = resolve_while_config_changes
                self.tick()
                self.routing.save_addresses.assert_called_once()
                self.routing.apply_seed_addresses.assert_not_called()
                self.assertEqual(self.last_refresh, {}, 'discarded results must not throttle the replacement server')

    def test_server_added_during_lookup_waits_until_next_tick(self):
        def resolve_with_new_server():
            answer = self.resolve()
            with self.manager.config_lock:
                self.manager.config['servers'].append(self.server('two'))
            return answer

        self.resolver.side_effect = resolve_with_new_server
        self.tick()
        self.assertEqual(self.routing.apply_seed_addresses.call_count, 1)
        self.assertEqual(self.routing.apply_seed_addresses.call_args.args[0]['id'], 'one')
        self.resolver.side_effect = self.resolve
        self.tick()
        self.assertEqual(self.routing.apply_seed_addresses.call_count, 2)
        self.assertEqual(self.routing.apply_seed_addresses.call_args.args[0]['id'], 'two')

    def test_one_failed_snapshot_does_not_prevent_other_server_refresh(self):
        self.manager.config['servers'].append(self.server('two'))
        self.routing.save_addresses.side_effect = [RuntimeError('ipset unavailable'), None]
        self.tick()
        self.routing.apply_seed_addresses.assert_called_once()
        self.assertEqual(self.routing.apply_seed_addresses.call_args.args[0]['id'], 'two')
        self.assertNotIn(self.identity(self.manager.config['servers'][0]), self.last_refresh)

    def test_apply_failure_is_not_marked_fresh_and_retries(self):
        self.routing.apply_seed_addresses.side_effect = RuntimeError('ipset unavailable')
        self.tick()
        self.assertEqual(self.last_refresh, {})
        self.routing.apply_seed_addresses.side_effect = None
        self.tick()
        self.assertEqual(self.resolver.call_count, 2)
        self.assertEqual(self.routing.apply_seed_addresses.call_count, 2)
        self.assertEqual(len(self.last_refresh), 1)

    def test_stopping_worker_skips_new_network_requests(self):
        self.manager.stop_expiration_worker.set()
        self.tick()
        self.resolver.assert_not_called()
        self.routing.apply_seed_addresses.assert_not_called()


if __name__ == '__main__':
    unittest.main()
