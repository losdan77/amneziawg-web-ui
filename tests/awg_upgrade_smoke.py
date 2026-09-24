"""Persisted-volume upgrade test. Run create with the old source, then verify
with the new source, in separate disposable containers sharing /etc/amnezia.
Never run against production data. APP_SOURCE selects the web-ui directory.
"""
import copy
import json
import os
from pathlib import Path
import sys

os.environ.update(AUTO_START_SERVERS='false', RU_SPLIT_AUTO_FETCH='false',
                  XRAY_UPSTREAM_HOST='127.0.0.1')
sys.path.insert(0, os.environ.get('APP_SOURCE', '/workspace/web-ui'))
import app as web
from awg_protocol import generate_params, render_params

manager = web.amnezia_manager
manager.stop_expiration_worker.set()
snapshot_path = Path('/etc/amnezia/upgrade-test-snapshot.json')


def exports():
    result = {}
    for server in manager.config['servers']:
        for client in server['clients']:
            result[client['id']] = (manager.generate_vless_client_link(server, client)
                                   if server['protocol'] == 'vless' else
                                   manager.generate_wireguard_client_config(server, client, False))
    return result


def upstream(index, version):
    client_keys = manager.generate_wireguard_keys()
    remote_keys = manager.generate_wireguard_keys()
    return (f"[Interface]\nPrivateKey = {client_keys['private_key']}\n"
            f'Address = 10.200.{index}.2/32\nMTU = 1280\n'
            + render_params(generate_params(version=version))
            + f"[Peer]\nPublicKey = {remote_keys['public_key']}\n"
              f'Endpoint = 127.0.0.1:{53100 + index}\n'
              'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n')


def create():
    assert not manager.config['servers'], 'Use an empty disposable test volume'
    legacy = dict(Jc=4, Jmin=8, Jmax=80, S1=50, S2=60,
                  H1=1000, H2=2000, H3=3000, H4=4000)
    cases = [dict(name='AWG1', awg_version='2', obfuscation_params=legacy),
             dict(name='AWG2', awg_version='2'), dict(name='AWG3', awg_version='3'),
             dict(name='Linked all', awg_version='2', mode='edge_linked',
                  upstream={'import_config': upstream(1, '2'), 'split_ru_local': False}),
             dict(name='Linked RU', awg_version='3', mode='edge_linked',
                  upstream={'import_config': upstream(2, '3'), 'split_ru_local': True})]
    for index, data in enumerate(cases):
        server = manager.create_wireguard_server(dict(data, auto_start=False,
                 subnet=f'10.{100 + index}.0.0/24', port=54100 + index))
        manager.add_wireguard_client(server['id'], 'existing client', 'forever')
        server['auto_start'] = True
    vless = manager.create_vless_server(dict(name='Existing VLESS', domain='vpn.example.com',
                                            transport='ws', path='/existing', auto_start=False))
    manager.add_vless_client(vless['id'], 'existing VLESS client', 'forever')
    manager.save_config()
    files = {str(path): path.read_text() for path in Path(web.WIREGUARD_CONFIG_DIR).glob('*.conf')}
    snapshot_path.write_text(json.dumps({'config': manager.config, 'files': files, 'exports': exports()}))
    os.chmod(snapshot_path, 0o600)
    print('PASS old version created persistent AWG1/2/3, linked all/RU, VLESS and client profiles')


def verify():
    snapshot = json.loads(snapshot_path.read_text())
    previous = snapshot['config']
    expected = copy.deepcopy(previous)
    for server in expected['servers']:
        link = server.get('upstream')
        if link:
            link['routing_mode'] = 'ru_split' if link.get('split_ru_local', True) else 'all'
    assert manager.config == expected, 'Upgrade unexpectedly changed persisted server/client fields'
    assert exports() == snapshot['exports'], 'Existing client exports changed'
    for name, content in snapshot['files'].items():
        assert Path(name).read_text() == content, 'An existing AWG config changed'
    manager.auto_start_servers()
    for server in manager.config['servers']:
        if server['protocol'] != 'vless':
            assert manager.get_server_status(server['id']) == 'running', 'Existing entry did not start'
            assert manager.stop_server(server['id']), 'Existing entry did not stop'
    assert exports() == snapshot['exports'], 'Start/stop changed client exports'
    for name, content in snapshot['files'].items():
        assert Path(name).read_text() == content, 'Start/stop rewrote an AWG config'
    print('PASS recreated container: all persisted records, keys, configs, exports retained; AWG1/2/3 and old linked servers start/stop')


if __name__ == '__main__':
    {'create': create, 'verify': verify}[sys.argv[1]]()
