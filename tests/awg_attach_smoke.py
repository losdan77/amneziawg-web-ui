"""Live attach/replace/detach against real AWG entries and remote peers.

Run only in the disposable Linux container described in AWG_TUNNELS.md.
All traffic stays inside randomly named network namespaces. Configuration files
under /etc/amnezia/amneziawg use unique names and are removed on exit.
"""
import copy
import json
import os
import sys
import tempfile
from pathlib import Path

from awg_routing_smoke import Lab, ROOT, command, load_manager
from awg_protocol import generate_params, render_params


def keys():
    private = command('awg', 'genkey').stdout.strip()
    public = command('awg', 'pubkey', input=private).stdout.strip()
    return private, public


def private_file(path, content):
    path.write_text(content, encoding='utf-8')
    path.chmod(0o600)
    return path


def remote_profile(lab, version):
    """A real destination server and the exact client profile copied into the UI."""
    private, public = keys()
    client_private, client_public = keys()
    params = generate_params(version=version)
    octet = 231 if version == '2' else 232
    port = 53010 + int(version)
    remote = (f'[Interface]\nPrivateKey = {private}\nAddress = 10.{octet}.0.2/24\n'
              f'ListenPort = {port}\nMTU = 1280\nTable = off\n'
              + render_params(params)
              + f'[Peer]\nPublicKey = {client_public}\nAllowedIPs = 10.{octet}.0.1/32\n')
    path = private_file(lab.directory / f'exit{version}.conf', remote)
    lab.ns('remote', 'awg-quick', 'up', str(path))
    return (f'[Interface]\nPrivateKey = {client_private}\nAddress = 10.{octet}.0.1/32\n'
            'MTU = 1280\n' + render_params(params)
            + f'[Peer]\nPublicKey = {public}\nEndpoint = 198.18.0.6:{port}\n'
            f'AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = {"15-30" if version == "3" else "25"}\n')


def live_entry(lab, manager, version, config_dir):
    private, public = keys()
    client_private, client_public = keys()
    psk = command('awg', 'genpsk').stdout.strip()
    params = generate_params(version=version)
    iface = 'e' + lab.prefix + version
    client_iface = 'client' + version
    client_id = 'client-' + version
    entry_text = ('# Preserve this existing server configuration byte for byte.\n'
                  f'[Interface]\nPrivateKey = {private}\nAddress = 10.240.0.1/24\n'
                  'ListenPort = 54000\nMTU = 1280\nTable = off\n'
                  + render_params(params)
                  + f'\n# Retained existing user\n[Peer]\nPublicKey = {client_public}\n'
                  f'PresharedKey = {psk}\nAllowedIPs = 10.240.0.2/32\n')
    client_text = (f'[Interface]\nPrivateKey = {client_private}\nAddress = 10.240.0.2/32\n'
                   'ListenPort = 54001\nMTU = 1280\nTable = off\n'
                   + render_params(params)
                   + f'[Peer]\nPublicKey = {public}\nPresharedKey = {psk}\n'
                   'Endpoint = 10.230.1.1:54000\nAllowedIPs = 0.0.0.0/0\n'
                   f'PersistentKeepalive = {"15-30" if version == "3" else "25"}\n')
    entry_path = private_file(config_dir / f'{iface}.conf', entry_text)
    client_path = private_file(lab.directory / f'{client_iface}.conf', client_text)
    client = dict(id=client_id, name='Retained user', server_id=iface,
                  client_private_key=client_private, client_public_key=client_public,
                  client_ip='10.240.0.2', preshared_key=psk,
                  expires_at=None, bandwidth_tier='vip', obfuscation_enabled=True,
                  obfuscation_params=copy.deepcopy(params), persistent_keepalive=25)
    server = dict(id=iface, name=f'Existing AWG {version}', interface=iface,
                  protocol='wireguard', awg_version=version, mode='standalone',
                  subnet='10.240.0.0/24', server_ip='10.240.0.1', mtu=1280,
                  port=54000, public_ip='10.230.1.1', dns=['198.18.0.1'],
                  server_private_key=private, server_public_key=public,
                  config_path=str(entry_path), status='running',
                  obfuscation_enabled=True, obfuscation_params=params,
                  egress_interface='eth+', clients=[copy.deepcopy(client)])
    manager.config = {'servers': [server], 'clients': {client_id: copy.deepcopy(client)}}
    manager.save_config()
    lab.ns('router', 'awg-quick', 'up', str(entry_path))
    lab.ns('client-a', 'awg-quick', 'up', str(client_path))
    for subnet in ('203.0.113.0/24', '9.9.9.9/32', '10.240.0.1/32'):
        lab.ns('client-a', 'ip', 'route', 'add', subnet, 'dev', client_iface)
    assert manager.setup_iptables(iface, server['subnet'])
    lab.ns('client-a', 'ping', '-c', '1', '-W', '5', '10.240.0.1')
    return server, client, entry_path, client_path


def run_smoke():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Run in a disposable privileged Linux container; see AWG_TUNNELS.md.')
    with tempfile.TemporaryDirectory(prefix='awg-attach-smoke-') as directory:
        lab = Lab(directory)
        manager = load_manager(directory)
        scope = manager.save_config.__func__.__globals__
        config_dir = Path('/etc/amnezia/amneziawg')
        config_dir.mkdir(parents=True, exist_ok=True)
        scope.update(WIREGUARD_CONFIG_DIR=str(config_dir),
                     CONFIG_FILE=str(lab.directory / 'web_config.json'))
        tracked_files = []

        def execute(shell_command):
            result = lab.ns('router', 'sh', '-c', shell_command, check=False)
            if result.returncode and '2>/dev/null' not in shell_command:
                # Never print command strings: key derivation legitimately contains a key.
                print(f'Linux command failed: {result.stderr.strip()}', file=sys.stderr)
            return result.stdout.strip() if result.returncode == 0 else None

        manager.execute_command = execute
        try:
            lab.setup()
            profiles = {version: remote_profile(lab, version) for version in ('2', '3')}
            for entry_version in ('2', '3'):
                server, client, entry_path, client_path = live_entry(
                    lab, manager, entry_version, config_dir)
                tracked_files.append(entry_path)
                entry_bytes, client_bytes = entry_path.read_bytes(), client_path.read_bytes()
                initial = copy.deepcopy(server)
                entry_index = json.loads(lab.ns('router', 'ip', '-j', 'link',
                                               'show', server['interface']).stdout)[0]['ifindex']
                initial_live = lab.ns('router', 'awg', 'showconf', server['interface']).stdout

                def unchanged():
                    assert entry_path.read_bytes() == entry_bytes, 'Entry configuration changed'
                    assert client_path.read_bytes() == client_bytes, 'Client configuration changed'
                    assert server['clients'] == initial['clients'], 'Client records changed'
                    assert manager.config['clients'][client['id']] == client, 'Global client changed'
                    for field in ('server_private_key', 'server_public_key', 'subnet', 'server_ip',
                                  'mtu', 'port', 'awg_version', 'obfuscation_params'):
                        assert server[field] == initial[field], f'Entry {field} changed'
                    current_index = json.loads(lab.ns('router', 'ip', '-j', 'link',
                                                     'show', server['interface']).stdout)[0]['ifindex']
                    assert current_index == entry_index, 'Entry interface was recreated'
                    assert lab.ns('router', 'awg', 'showconf', server['interface']).stdout == initial_live, 'Live entry parameters changed'
                    handshake = lab.ns('router', 'awg', 'show', server['interface'], 'latest-handshakes').stdout.split()
                    assert len(handshake) == 2 and int(handshake[-1]) > 0, 'Client handshake missing'
                    lab.ns('client-a', 'ping', '-c', '1', '-W', '3', '10.240.0.1')
                    saved = json.loads(Path(scope['CONFIG_FILE']).read_text())
                    assert saved == manager.config, 'Persisted configuration does not match memory'
                    assert 'awg-upstream-change' not in lab.ns('router', 'iptables-save').stdout, 'Traffic guard leaked'

                lab.http('client-a', '203.0.113.10', 'direct')
                manager.update_server_upstream(server['id'], {
                    'import_config': profiles['2'], 'routing_mode': 'all', 'failover_mode': 'fail_close'})
                upstream_path = Path(server['upstream']['config_path'])
                tracked_files.append(upstream_path)
                assert server['upstream']['awg_version'] == '2'
                unchanged()
                lab.http('client-a', '203.0.113.10', 'remote')
                lab.http('client-a', '203.0.113.20', 'remote')

                # Force exactly one operating-system command to fail; restoration
                # still executes every real route/firewall/AWG/disk operation.
                before = copy.deepcopy(manager.config)
                old_upstream_bytes = upstream_path.read_bytes()
                failed = False

                def fail_dns_once(shell_command):
                    nonlocal failed
                    if not failed and shell_command.startswith('dnsmasq --conf-file='):
                        failed = True
                        return None
                    return execute(shell_command)

                manager.execute_command = fail_dns_once
                try:
                    try:
                        manager.update_server_upstream(server['id'], {
                            'import_config': profiles['3'], 'routing_mode': 'ai_tiktok'})
                    except RuntimeError as error:
                        assert 'previous configuration was restored' in str(error), str(error)
                    else:
                        raise AssertionError('A failed DNS startup did not fail the change')
                finally:
                    manager.execute_command = execute
                assert failed, 'DNS failure injection was not reached'
                assert manager.config == before, 'Rollback changed stored metadata'
                assert upstream_path.read_bytes() == old_upstream_bytes, 'Rollback changed upstream file'
                unchanged()
                lab.http('client-a', '203.0.113.10', 'remote')
                lab.http('client-a', '203.0.113.20', 'remote')

                manager.update_server_upstream(server['id'], {
                    'import_config': profiles['3'], 'routing_mode': 'ai_tiktok'})
                assert server['upstream']['awg_version'] == '3'
                unchanged()
                assert lab.dns('client-a', 'chatgpt.com')['answers'] > 0
                assert lab.dns('client-a', 'tiktok.com', tcp=True)['answers'] > 0
                lab.http('client-a', '203.0.113.10', 'remote')
                lab.http('client-a', '203.0.113.11', 'remote')
                lab.http('client-a', '203.0.113.20', 'direct')

                # Change only the routing policy, preserving imported AWG 3 keys.
                imported_bytes = upstream_path.read_bytes()
                manager.ru_split_cidrs = ['203.0.113.20/32']
                manager.update_server_upstream(server['id'], {'routing_mode': 'ru_split'})
                assert upstream_path.read_bytes() == imported_bytes, 'Policy edit changed upstream keys'
                unchanged()
                lab.http('client-a', '203.0.113.10', 'remote')
                lab.http('client-a', '203.0.113.20', 'direct')

                upstream_iface = server['upstream']['interface']
                manager.remove_server_upstream(server['id'])
                unchanged()
                assert not upstream_path.exists(), 'Detached tunnel configuration remains'
                assert not manager.is_interface_running(upstream_iface), 'Detached interface remains'
                lab.http('client-a', '203.0.113.10', 'direct')
                lab.http('client-a', '203.0.113.20', 'direct')
                assert manager.cleanup_iptables(server['interface'], server['subnet'])
                lab.ns('client-a', 'awg-quick', 'down', str(client_path))
                lab.ns('router', 'awg-quick', 'down', str(entry_path))
                print(f'PASS live AWG {entry_version} entry: attach AWG2, failed-replacement rollback, '
                      'replace AWG3, AI split, RU split, detach; client and entry preserved', flush=True)
        finally:
            try:
                for server in manager.config.get('servers', []):
                    if server.get('upstream') and 'router' in lab.names:
                        path = Path(server['upstream']['config_path'])
                        tracked_files.append(path)
                        manager.stop_upstream_link(server)
            finally:
                lab.cleanup()
                for path in set(tracked_files):
                    path.unlink(missing_ok=True)


if __name__ == '__main__':
    run_smoke()
