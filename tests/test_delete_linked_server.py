"""Deleting a linked entry must never orphan live clients or owned routing."""
import copy
import json
import unittest
from pathlib import Path
from unittest.mock import Mock

import test_awg_manager as manager_module


class DeleteLinkedServerTests(unittest.TestCase):
    server = manager_module.ManagerTests.server
    client = manager_module.ManagerTests.client

    def setUp(self):
        manager_module.ManagerTests.setUp(self)
        self.entry = self.server(awg_version='2')
        self.client(self.entry)
        self.upstream_path = Path(self.directory.name, self.entry['interface'] + '-up.conf')
        self.upstream_path.write_text('retained upstream config')
        self.entry.update(mode='edge_linked', status='stopped', egress_interface=self.entry['interface'] + '-up',
                          upstream={'interface': self.entry['interface'] + '-up', 'config_path': str(self.upstream_path),
                                    'routing_mode': 'ai_tiktok', 'table_id': 201})
        self.manager.save_config()
        self.before = copy.deepcopy(self.manager.config)
        self.entry_content = Path(self.entry['config_path']).read_bytes()
        self.live = set()
        self.manager.is_interface_running = Mock(side_effect=lambda interface: interface in self.live)
        self.manager.stop_server = Mock(side_effect=self.stop_entry)
        self.manager.stop_upstream_link = Mock(return_value=True)
        self.manager.cleanup_iptables = Mock(return_value=True)

    def stop_entry(self, server_id):
        self.live.discard(self.entry['interface'])
        return True

    def assert_retained(self):
        self.assertEqual(self.manager.config, self.before)
        self.assertEqual(Path(self.entry['config_path']).read_bytes(), self.entry_content)
        self.assertEqual(self.upstream_path.read_text(), 'retained upstream config')
        self.assertEqual(json.loads(Path(manager_module.CONFIG_FILE).read_text()), self.before)

    def assert_deleted(self):
        self.assertEqual(self.manager.config['servers'], [])
        self.assertEqual(self.manager.config['clients'], {})
        self.assertFalse(Path(self.entry['config_path']).exists())
        self.assertFalse(self.upstream_path.exists())
        self.assertEqual(json.loads(Path(manager_module.CONFIG_FILE).read_text()), self.manager.config)

    def test_stale_stopped_status_cannot_skip_live_entry_shutdown(self):
        # This is the state exposed by old get_server_status after uplink loss.
        self.live.add(self.entry['interface'])
        self.assertTrue(self.manager.delete_server(self.entry['id']))
        self.manager.stop_server.assert_called_once_with(self.entry['id'])
        self.manager.stop_upstream_link.assert_called_once_with(self.entry)
        self.manager.cleanup_iptables.assert_called_once()
        self.assertFalse(self.live)
        self.assert_deleted()

    def test_stopped_entry_still_cleans_stray_upstream_and_forwarding_resources(self):
        self.assertTrue(self.manager.delete_server(self.entry['id']))
        self.manager.stop_server.assert_not_called()
        self.manager.stop_upstream_link.assert_called_once_with(self.entry)
        self.manager.cleanup_iptables.assert_called_once_with(
            self.entry['interface'], self.entry['subnet'], self.entry['egress_interface'])
        self.assert_deleted()

    def test_entry_shutdown_failure_preserves_metadata_clients_and_both_files(self):
        self.live.add(self.entry['interface'])
        self.manager.stop_server.side_effect = None
        self.manager.stop_server.return_value = False
        self.assertFalse(self.manager.delete_server(self.entry['id']))
        self.manager.stop_upstream_link.assert_not_called()
        self.assert_retained()

    def test_entry_remaining_live_despite_successful_stop_is_not_forgotten(self):
        self.live.add(self.entry['interface'])
        self.manager.stop_server.side_effect = None
        self.manager.stop_server.return_value = True
        self.assertFalse(self.manager.delete_server(self.entry['id']))
        self.manager.stop_upstream_link.assert_not_called()
        self.assert_retained()

    def test_upstream_cleanup_failure_preserves_files_for_recovery(self):
        self.manager.stop_upstream_link.return_value = False
        self.assertFalse(self.manager.delete_server(self.entry['id']))
        self.manager.cleanup_iptables.assert_not_called()
        self.assert_retained()

    def test_dns_shutdown_exception_preserves_files_for_recovery(self):
        self.manager.stop_upstream_link.side_effect = RuntimeError('The selective DNS resolver did not stop')
        self.assertFalse(self.manager.delete_server(self.entry['id']))
        self.assert_retained()

    def test_forwarding_cleanup_failure_preserves_files_for_recovery(self):
        self.manager.cleanup_iptables.return_value = False
        self.assertFalse(self.manager.delete_server(self.entry['id']))
        self.assert_retained()

    def test_stale_standalone_metadata_does_not_orphan_a_recorded_upstream(self):
        self.entry['mode'] = 'standalone'
        self.assertTrue(self.manager.delete_server(self.entry['id']))
        self.manager.stop_upstream_link.assert_called_once_with(self.entry)
        self.assert_deleted()

    def test_vless_failed_upstream_shutdown_preserves_metadata_and_files(self):
        self.entry['protocol'] = 'vless'
        self.manager.save_config()
        self.before = copy.deepcopy(self.manager.config)
        self.manager.stop_upstream_link.return_value = False
        self.assertFalse(self.manager.delete_server(self.entry['id']))
        self.assert_retained()


if __name__ == '__main__':
    unittest.main()
