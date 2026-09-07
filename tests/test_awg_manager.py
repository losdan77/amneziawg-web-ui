"""Exercise the actual manager class without starting nginx, workers or host VPNs.

Only the class and its lock decorator are loaded from the AST. Network and key
commands are mocked; config generation, JSON persistence and migration are real.
"""
import ast
import base64
import calendar
import copy
import ipaddress
import json
import os
import random
import re
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-ui'))
from awg_protocol import *
from test_awg_protocol import LEGACY

DEFAULT_MTU, DEFAULT_PORT = 1280, 51820
DEFAULT_SUBNET, DNS_SERVERS = '10.0.0.0/24', ['1.1.1.1']
ENABLE_OBFUSCATION, AUTO_START_SERVERS = True, False
tree = ast.parse((Path(__file__).resolve().parents[1] / 'web-ui/app.py').read_text(encoding='utf-8'))
tree.body = [node for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))
             and node.name in ('AmneziaManager', 'synchronized_config')]
exec(compile(tree, 'web-ui/app.py', 'exec'), globals())


class ManagerTests(unittest.TestCase):
    def setUp(self):
        global CONFIG_DIR, CONFIG_FILE, WIREGUARD_CONFIG_DIR
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        CONFIG_DIR = WIREGUARD_CONFIG_DIR = self.directory.name
        CONFIG_FILE = os.path.join(CONFIG_DIR, 'web_config.json')
        self.manager = AmneziaManager.__new__(AmneziaManager)
        self.manager.config_lock = threading.RLock()
        self.manager.config = {'servers': [], 'clients': {}}
        self.manager.public_ip = '192.0.2.1'
        self.manager.generate_wireguard_keys = Mock(return_value={'private_key': 'private', 'public_key': 'public'})
        self.manager.generate_preshared_key = Mock(return_value='psk')
        self.manager.execute_command = Mock(return_value='public')
        self.manager.start_server = Mock(return_value=True)
        self.manager.apply_live_config = Mock(return_value=True)
        self.manager.apply_bandwidth_limit = Mock(return_value=True)
        self.manager.simulate_server_operation = Mock()

    def server(self, **kwargs):
        return self.manager.create_wireguard_server(dict(name='Test', auto_start=False, **kwargs))

    def imported_config(self, params):
        return ('[Interface]\nPrivateKey = private\nAddress = 10.8.0.2/32\nMTU = 1280\n'
                + render_params(params) + '[Peer]\nPublicKey = public\nEndpoint = 192.0.2.5:51820\n'
                'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 15-30\n')

    def client(self, server):
        client = dict(id='c1', name='Client', server_id=server['id'], client_private_key='private-client',
                      client_public_key='public-client', client_ip='10.0.0.2', preshared_key='psk',
                      expires_at=1999999999, bandwidth_tier='vip', obfuscation_enabled=True,
                      obfuscation_params=copy.deepcopy(server['obfuscation_params']))
        server['clients'].append(copy.deepcopy(client))
        self.manager.config['clients'][client['id']] = client
        self.manager.save_config()
        return client

    def test_new_server_and_client_have_matching_awg3(self):
        server = self.server(obfuscation_params=LEGACY)
        client = self.client(server)
        server_text = Path(server['config_path']).read_text()
        client_text = self.manager.generate_wireguard_client_config(server, client, False)
        self.assertEqual(server['awg_version'], '3')
        self.assertIn(render_params(server['obfuscation_params']), server_text)
        self.assertIn(render_params(server['obfuscation_params']), client_text)

    def test_legacy_server_survives_reload_without_new_fields(self):
        server = self.server(awg_version='2', obfuscation_params=LEGACY)
        client = self.client(server)
        before = self.manager.generate_wireguard_client_config(server, client, False)
        self.manager.config = self.manager.load_config()
        reloaded = self.manager.config['servers'][0]
        after = self.manager.generate_wireguard_client_config(reloaded, self.manager.config['clients']['c1'], False)
        self.assertEqual(before, after)
        self.assertNotIn('HeaderProtectionKey', before)

    def test_plain_wireguard_still_has_no_obfuscation(self):
        server = self.server(obfuscation=False)
        self.assertEqual(server['awg_version'], 'wireguard')
        self.assertNotIn('HeaderProtectionKey', Path(server['config_path']).read_text())

    def test_linked_awg3_entry_preserves_legacy_upstream(self):
        server = self.server(mode='edge_linked', upstream={'import_config': self.imported_config(LEGACY)})
        self.assertEqual(server['awg_version'], '3')
        self.assertEqual(server['upstream']['obfuscation_params'], LEGACY)
        self.assertNotIn('HeaderProtectionKey', Path(server['upstream']['config_path']).read_text())

    def test_vless_upstream_builder_retains_all_awg3_fields(self):
        params = dict(generate_params(), I1='<b 0xaabb><r 16>')
        upstream, _, _, imported = self.manager.build_imported_upstream_config(
            server_id='abcdef', upstream_interface='vl-test-up',
            upstream_data={'import_config': self.imported_config(params)}, mtu=1280)
        self.assertEqual(imported, params)
        self.assertIn(render_params(params), self.manager.generate_upstream_config_content(upstream, 1280))
        self.assertEqual(upstream['persistent_keepalive'], '15-30')

    def test_upgrade_preserves_peers_keys_clients_and_expiry(self):
        server = self.server(awg_version='2', obfuscation_params=LEGACY)
        client = self.client(server)
        before = copy.deepcopy(client)
        path = Path(server['config_path'])
        peer = '\n# Test peer\n[Peer]\nPublicKey = public-client\nPresharedKey = psk\nAllowedIPs = 10.0.0.2/32\n'
        path.write_text(path.read_text() + peer)
        with patch.object(subprocess, 'run', return_value=Mock(returncode=1, stderr='Device does not exist.')):
            upgraded = self.manager.upgrade_server_awg3(server['id'])
        self.assertTrue(path.read_text().endswith(peer))
        for key in before.keys() - {'obfuscation_params'}:
            self.assertEqual(self.manager.config['clients']['c1'][key], before[key])
        self.assertEqual(upgraded['clients'][0]['obfuscation_params'], self.manager.config['clients']['c1']['obfuscation_params'])
        backup = Path(upgraded['awg3_backup_path'])
        self.assertNotIn('HeaderProtectionKey', (backup / path.name).read_text())
        self.assertNotIn('HeaderProtectionKey', (backup / 'web_config.json').read_text())
        self.assertFalse(Path(CONFIG_DIR, 'awg3-upgrade.pending.json').exists())
        self.assertEqual(self.manager.upgrade_server_awg3(server['id']), upgraded)

    def test_upgrade_refuses_running_interface_even_with_stale_status(self):
        server = self.server(awg_version='2', obfuscation_params=LEGACY)
        with patch.object(subprocess, 'run', return_value=Mock(returncode=0)):
            with self.assertRaisesRegex(ValueError, 'still active'):
                self.manager.upgrade_server_awg3(server['id'])

    def test_failed_write_rolls_back_both_configs(self):
        server = self.server(awg_version='2', obfuscation_params=LEGACY)
        old_state = copy.deepcopy(self.manager.config)
        old_text = Path(server['config_path']).read_text()
        real_save = self.manager.save_config
        self.manager.save_config = Mock(side_effect=[OSError('disk error'), None])
        with patch.object(subprocess, 'run', return_value=Mock(returncode=1, stderr='Device does not exist.')):
            with self.assertRaises(OSError):
                self.manager.upgrade_server_awg3(server['id'])
        self.assertEqual(self.manager.config, old_state)
        self.assertEqual(Path(server['config_path']).read_text(), old_text)
        self.manager.save_config = real_save

    def test_interrupted_upgrade_recovers_before_loading(self):
        server = self.server(awg_version='2', obfuscation_params=LEGACY)
        original = Path(server['config_path']).read_text()
        backup = Path(CONFIG_DIR, 'backup.conf')
        backup.write_text(original)
        Path(server['config_path']).write_text('partially upgraded')
        Path(CONFIG_DIR, 'awg3-upgrade.pending.json').write_text(json.dumps({'files': {server['config_path']: str(backup)}}))
        self.manager.load_config()
        self.assertEqual(Path(server['config_path']).read_text(), original)


if __name__ == '__main__':
    unittest.main()
