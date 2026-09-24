"""Exercise real selective routing in an isolated privileged Linux container.

Uses the production manager and DNS classifier with real AWG 2/3 uplinks.
No external network, production configuration, or pre-existing namespace is used.
See AWG_TUNNELS.md for the disposable-container invocation.
"""
import ast
import copy
import functools
import http.client
import http.server
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'web-ui'))

# These public addresses exist only as loopback aliases in disposable network
# namespaces. They cannot send packets to real third-party destinations.
SEED_ADDRESS = '104.18.31.77'
BUILTIN_POOL_ADDRESS = '160.79.104.10'
CUSTOM_POOL_ADDRESS = '45.67.89.10'
PROVIDER_ADDRESSES = ('172.64.155.209', '95.100.248.88')


def command(*args, check=True, input=None, timeout=20):
    result = subprocess.run(args, input=input, text=True, capture_output=True,
                            timeout=timeout)
    if check and result.returncode:
        # Config input may contain ephemeral private keys: do not log it.
        raise RuntimeError(f'{args[0]} failed ({result.returncode}): {result.stderr.strip()}')
    return result


def load_manager(state_dir):
    """Load only definitions; importing app.py would start application workers."""
    from awg_protocol import generate_params, render_params
    import awg_protocol
    import routing_policy
    source = ast.parse((ROOT / 'web-ui/app.py').read_text(encoding='utf-8'))
    source.body = [node for node in source.body
                   if (isinstance(node, (ast.ClassDef, ast.FunctionDef))
                       and node.name in ('AmneziaManager', 'synchronized_config'))
                   or (isinstance(node, ast.ImportFrom)
                       and node.module in ('awg_protocol', 'routing_policy'))]
    scope = dict(globals(), wraps=functools.wraps, DEFAULT_PORT=51820,
                 DEFAULT_MTU=1280, CONFIG_DIR=state_dir,
                 WIREGUARD_CONFIG_DIR=state_dir,
                 DNS_SERVERS=['198.18.0.1'],
                 generate_params=generate_params, render_params=render_params)
    # Keep the harness independent of which public helpers app.py imports.
    scope.update({k: v for mod in (awg_protocol, routing_policy)
                  for k, v in vars(mod).items() if not k.startswith('_')})
    exec(compile(source, str(ROOT / 'web-ui/app.py'), 'exec'), scope)
    manager = scope['AmneziaManager'].__new__(scope['AmneziaManager'])
    manager.config_lock = threading.RLock()
    manager.config = {'servers': [], 'clients': {}}
    manager.ru_split_cidrs = []
    return manager


class Lab:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.prefix = 'ar' + uuid.uuid4().hex[:7]
        self.names = {}
        self.processes = []
        self.logs = []

    def ns(self, name, *args, **kwargs):
        return command('ip', 'netns', 'exec', self.names[name], *args, **kwargs)

    def add_namespace(self, name):
        actual = f'{self.prefix}-{name}'
        command('ip', 'netns', 'add', actual)
        self.names[name] = actual
        self.ns(name, 'ip', 'link', 'set', 'lo', 'up')
        for key in ('all', 'default'):
            self.ns(name, 'sysctl', '-qw', f'net.ipv4.conf.{key}.rp_filter=0')

    def link(self, left, left_if, left_ip, right, right_if, right_ip, index):
        # Create directly in namespaces, so failed setup cannot leave host veths.
        temporary = f'v{self.prefix}{index}'
        self.ns(left, 'ip', 'link', 'add', left_if, 'type', 'veth',
                'peer', 'name', temporary, 'netns', self.names[right])
        self.ns(right, 'ip', 'link', 'set', temporary, 'name', right_if)
        for name, iface, address in ((left, left_if, left_ip), (right, right_if, right_ip)):
            self.ns(name, 'ip', 'addr', 'add', address, 'dev', iface)
            self.ns(name, 'ip', 'link', 'set', iface, 'up')

    def start(self, name, *args):
        log = open(self.directory / f'process-{len(self.processes)}.log', 'w+')
        self.logs.append(log)
        process = subprocess.Popen(('ip', 'netns', 'exec', self.names[name], *args),
                                   stdout=log, stderr=log, text=True)
        self.processes.append(process)
        return process

    def setup(self):
        for name in ('router', 'client-a', 'client-b', 'direct', 'remote'):
            self.add_namespace(name)
        self.setup_router()
        self.link('direct', 'transport', '198.18.0.5/30',
                  'remote', 'eth0', '198.18.0.6/30', 4)
        self.ns('direct', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
        self.ns('remote', 'ip', 'route', 'add', 'default', 'via', '198.18.0.5')
        for name in ('direct', 'remote'):
            for address in ('203.0.113.10/32', '203.0.113.11/32', '203.0.113.20/32',
                            SEED_ADDRESS + '/32', BUILTIN_POOL_ADDRESS + '/32',
                            CUSTOM_POOL_ADDRESS + '/32',
                            *(address + '/32' for address in PROVIDER_ADDRESSES)):
                self.ns(name, 'ip', 'addr', 'add', address, 'dev', 'lo')
            self.start(name, sys.executable, str(Path(__file__).resolve()), '--serve-http', name)
        self.start('direct', 'dnsmasq', '--keep-in-foreground', '--conf-file=/dev/null',
                   '--no-resolv', '--no-hosts', '--bind-interfaces',
                   '--listen-address=198.18.0.1', '--port=53',
                   '--address=/chatgpt.com/203.0.113.10',
                   '--address=/chatgpt.com/2001:db8::10',
                   '--address=/tiktok.com/203.0.113.11',
                   '--address=/ordinary.example/203.0.113.20',
                   '--local=/chatgpt.com/tiktok.com/ordinary.example/',
                   '--pid-file=' + str(self.directory / 'fixture-dns.pid'))

    def setup_router(self):
        self.link('router', 'awg-in-a', '10.230.1.1/24',
                  'client-a', 'eth0', '10.230.1.2/24', 1)
        self.link('router', 'awg-in-b', '10.230.2.1/24',
                  'client-b', 'eth0', '10.230.2.2/24', 2)
        self.link('router', 'eth-test', '198.18.0.2/30',
                  'direct', 'eth0', '198.18.0.1/30', 3)
        self.ns('router', 'sysctl', '-qw', 'net.ipv4.ip_forward=1')
        self.ns('router', 'ip', 'route', 'add', 'default', 'via', '198.18.0.1')
        for name, gateway in (('client-a', '10.230.1.1'), ('client-b', '10.230.2.1')):
            self.ns(name, 'ip', 'route', 'add', 'default', 'via', gateway)
        for iface, subnet in (('awg-in-a', '10.230.1.0/24'), ('awg-in-b', '10.230.2.0/24')):
            self.ns('router', 'sh', str(ROOT / 'scripts/setup_iptables.sh'), iface, subnet)

    def recreate_router(self):
        """Drop kernel state without the application's graceful cleanup hook."""
        namespace = self.names['router']
        for pid in command('ip', 'netns', 'pids', namespace).stdout.split():
            try:
                os.kill(int(pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
        deadline = time.monotonic() + 3
        while command('ip', 'netns', 'pids', namespace).stdout.strip():
            if time.monotonic() >= deadline:
                raise RuntimeError('Router namespace processes failed to stop')
            time.sleep(0.025)
        command('ip', 'netns', 'del', namespace)
        self.names.pop('router')
        # ip-netns may defer the final network-device release while a daemon's
        # socket is closing. Remove only this fixture's surviving peer ends.
        for name in ('client-a', 'client-b', 'direct'):
            self.ns(name, 'ip', 'link', 'del', 'eth0', check=False)
        self.add_namespace('router')
        self.setup_router()

    def upstream(self, version):
        from awg_protocol import generate_params, render_params
        params = generate_params(version=version)
        private = [command('awg', 'genkey').stdout.strip() for _ in range(2)]
        public = [command('awg', 'pubkey', input=value).stdout.strip() for value in private]
        for index, name in enumerate(('router', 'remote')):
            peer = 1 - index
            iface = 'awg-out' if index == 0 else 'awg-exit'
            config = (f'[Interface]\nPrivateKey = {private[index]}\n'
                      f'Address = 10.231.0.{index + 1}/30\n'
                      f'ListenPort = {53010 + index}\nMTU = 1280\nTable = off\n'
                      + render_params(params)
                      + f'[Peer]\nPublicKey = {public[peer]}\nAllowedIPs = 0.0.0.0/0\n'
                      f'Endpoint = 198.18.0.{6 if index == 0 else 2}:{53010 + peer}\n'
                      f'PersistentKeepalive = {"15-30" if version == "3" else "25"}\n')
            path = self.directory / f'{iface}.conf'
            path.write_text(config)
            path.chmod(0o600)
            self.ns(name, 'awg-quick', 'up', str(path))
        self.ns('router', 'ping', '-c', '1', '-W', '5', '10.231.0.2')

    def stop_upstream(self):
        for name, iface in (('router', 'awg-out'), ('remote', 'awg-exit')):
            if name in self.names:
                self.ns(name, 'awg-quick', 'down', str(self.directory / f'{iface}.conf'), check=False)

    def http(self, client, target, expected):
        result = self.ns(client, sys.executable, str(Path(__file__).resolve()),
                         '--request-http', target, check=False)
        if expected is None:
            assert result.returncode != 0, f'{client}: blocked target leaked: {result.stdout}'
        else:
            assert result.returncode == 0 and result.stdout.strip() == expected, (
                f'{client} -> {target}: expected {expected}, got {result.stdout} {result.stderr}')

    def dns(self, client, name, tcp=False, qtype=1):
        # 9.9.9.9 is intentionally unreachable. Production DNS interception must catch it.
        return json.loads(self.ns(client, sys.executable, str(Path(__file__).resolve()),
                                 '--request-dns', '9.9.9.9', name,
                                 'tcp' if tcp else 'udp', str(qtype)).stdout)

    def cleanup(self):
        for name in reversed(list(self.names)):
            result = command('ip', 'netns', 'pids', self.names[name], check=False)
            for pid in result.stdout.split():
                try:
                    os.kill(int(pid), signal.SIGTERM)
                except ProcessLookupError:
                    pass
            command('ip', 'netns', 'del', self.names[name], check=False)
        for process in self.processes:
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        for log in self.logs:
            log.close()


def request_dns(resolver, name, tcp=False, qtype=1):
    labels = b''.join(bytes([len(label)]) + label.encode('ascii') for label in name.split('.'))
    query = struct.pack('!6H', 12031, 0x0100, 1, 0, 0, 0) + labels + b'\0' + struct.pack('!HH', qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        if tcp:
            sock.connect((resolver, 53))
            sock.sendall(struct.pack('!H', len(query)) + query)
            data = b''
            while len(data) < 2:
                packet = sock.recv(2 - len(data))
                if not packet:
                    raise RuntimeError('DNS TCP response closed before length')
                data += packet
            length = struct.unpack('!H', data)[0]
            data = b''
            while len(data) < length:
                packet = sock.recv(length - len(data))
                if not packet:
                    raise RuntimeError('DNS TCP response closed early')
                data += packet
        else:
            sock.sendto(query, (resolver, 53))
            data = sock.recv(4096)
    identity, flags, _, answers, _, _ = struct.unpack('!6H', data[:12])
    assert identity == 12031 and flags & 0x8000 and flags & 15 == 0, 'DNS query failed'
    return {'answers': answers}


def run_smoke():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Run inside a disposable privileged Linux container; see AWG_TUNNELS.md.')
    for executable in ('ip', 'iptables', 'ipset', 'dnsmasq', 'awg', 'awg-quick', 'ping', 'sysctl'):
        if not shutil.which(executable):
            raise SystemExit(f'Missing required test dependency: {executable}')
    with tempfile.TemporaryDirectory(prefix='awg-routing-smoke-') as directory:
        lab = Lab(directory)
        manager = load_manager(directory)

        def execute(shell_command):
            result = lab.ns('router', 'sh', '-c', shell_command, check=False)
            if result.returncode and '2>/dev/null' not in shell_command:
                print(f'Routing command failed: {result.stderr.strip()}', file=sys.stderr)
            return result.stdout if result.returncode == 0 else None

        manager.execute_command = execute
        server = {'id': 'smoke-a', 'name': 'Smoke A', 'protocol': 'wireguard',
                  'mode': 'edge_linked',
                  'interface': 'awg-in-a', 'subnet': '10.230.1.0/24',
                  'server_ip': '10.230.1.1', 'dns': ['198.18.0.1'],
                  'linked_failover_mode': 'fail_close', 'routing_state': 'upstream',
                  'upstream': {'interface': 'awg-out', 'endpoint': '198.18.0.6:53011',
                               'table_id': 210, 'fwmark': 210,
                               'service_cidrs': [CUSTOM_POOL_ADDRESS + '/32'],
                               'routing_mode': 'ai_tiktok', 'split_ru_local': False}}
        manager.config['servers'] = [server]
        try:
            lab.setup()
            for version in ('2', '3'):
                server['upstream']['service_ip_profile'] = 'standard'
                lab.upstream(version)
                # Use the actual project firewall helper, including both egress NAT rules.
                lab.ns('router', 'sh', str(ROOT / 'scripts/setup_iptables.sh'),
                       server['interface'], server['subnet'], 'awg-out')
                assert manager.configure_upstream_routing(server) is not False
                # Seeded destinations and explicit pools must work even when a
                # client has cached its DNS answer or uses encrypted DNS.
                classifier = manager._selective_routing()
                classifier.apply_seed_addresses(server, {'addresses': [SEED_ADDRESS],
                    'errors': [], 'resolved_hosts': 1, 'queried_hosts': 1})
                for target in (SEED_ADDRESS, BUILTIN_POOL_ADDRESS, CUSTOM_POOL_ADDRESS):
                    lab.http('client-a', target, 'remote')
                    lab.http('client-b', target, 'direct')
                lab.http('client-a', '203.0.113.20', 'direct')
                # Removing an explicit range must update the existing kernel
                # pool while preserving dynamically seeded destinations.
                server['upstream']['service_cidrs'] = []
                assert manager.configure_upstream_routing(server) is not False
                assert lab.ns('router', 'ipset', 'test', 'awgpool_210',
                              CUSTOM_POOL_ADDRESS, check=False).returncode != 0
                lab.http('client-a', CUSTOM_POOL_ADDRESS, 'direct')
                lab.http('client-a', SEED_ADDRESS, 'remote')
                server['upstream']['service_cidrs'] = [CUSTOM_POOL_ADDRESS + '/32']
                assert manager.configure_upstream_routing(server) is not False
                lab.http('client-a', CUSTOM_POOL_ADDRESS, 'remote')
                # Actual DNS query/response populates ipset; do not seed target IPs by hand.
                assert lab.dns('client-a', 'chatgpt.com')['answers'] > 0
                assert lab.dns('client-a', 'tiktok.com', tcp=True)['answers'] > 0
                assert lab.dns('client-a', 'ordinary.example')['answers'] > 0
                assert lab.dns('client-a', 'chatgpt.com', qtype=28)['answers'] == 0
                for target in ('203.0.113.10', '203.0.113.11'):
                    lab.ns('router', 'ipset', 'test', 'awgsel_210', target)
                    lab.http('client-a', target, 'remote')
                    lab.http('client-b', target, 'direct')
                lab.http('client-a', '203.0.113.20', 'direct')
                # The read-only diagnostics must agree with actual HTTP egress
                # for both a seeded destination and an ordinary destination.
                diagnostic = manager.get_upstream_diagnostics(server['id'], SEED_ADDRESS)
                assert diagnostic['classifier']['dns_running']
                assert diagnostic['classifier']['rules_attached']
                assert diagnostic['classifier']['dns_entries'] >= 2
                assert diagnostic['classifier']['pool_entries'] >= 3
                assert diagnostic['destinations'][0]['route'] == 'upstream', diagnostic
                assert diagnostic['destinations'][0]['pool_match'], diagnostic
                ordinary = manager.get_upstream_diagnostics(server['id'], '8.8.4.4')
                assert ordinary['destinations'][0]['route'] == 'local', ordinary
                # A populated set and an upstream route are insufficient if
                # the actual incoming classifier jump has been removed.
                lab.ns('router', 'iptables', '-t', 'mangle', '-D', 'PREROUTING',
                       '-i', server['interface'], '-s', server['subnet'], '-j', 'AWGSEL_210')
                diagnostic = manager.get_upstream_diagnostics(server['id'], SEED_ADDRESS)
                assert diagnostic['destinations'][0]['pool_match'], diagnostic
                assert not diagnostic['classifier']['rules_attached'], diagnostic
                assert diagnostic['destinations'][0]['route'] == 'local', diagnostic
                lab.http('client-a', SEED_ADDRESS, 'direct')
                assert manager.configure_upstream_routing(server) is not False
                diagnostic = manager.get_upstream_diagnostics(server['id'], SEED_ADDRESS)
                assert diagnostic['classifier']['rules_attached'], diagnostic
                assert diagnostic['destinations'][0]['route'] == 'upstream', diagnostic
                lab.http('client-a', SEED_ADDRESS, 'remote')
                # Fail-open keeps DNS alive and preserves learned destinations,
                # allowing recovery even while applications cache their answers.
                assert manager.configure_wireguard_local_routing(server) is not False
                assert lab.dns('client-a', 'ordinary.example')['answers'] > 0
                lab.http('client-a', '203.0.113.10', 'direct')
                lab.http('client-a', '203.0.113.20', 'direct')
                assert manager.configure_upstream_routing(server) is not False
                lab.http('client-a', '203.0.113.10', 'remote')
                # Reapplying a policy must not duplicate rules or flush learned targets.
                before = [re.sub(r'\[\d+:\d+\]', '[counters]', line)
                          for line in lab.ns('router', 'iptables-save').stdout.splitlines()
                          if not line.startswith('#')]
                assert manager.configure_upstream_routing(server) is not False
                after = [re.sub(r'\[\d+:\d+\]', '[counters]', line)
                         for line in lab.ns('router', 'iptables-save').stdout.splitlines()
                         if not line.startswith('#')]
                assert after == before
                lab.http('client-a', '203.0.113.10', 'remote')
                # Periodic snapshots, not graceful teardown, must preserve
                # destinations across a container/namespace restart.
                classifier.save_addresses(server)
                lab.stop_upstream()
                lab.recreate_router()
                lab.upstream(version)
                lab.ns('router', 'sh', str(ROOT / 'scripts/setup_iptables.sh'),
                       server['interface'], server['subnet'], 'awg-out')
                assert manager.configure_upstream_routing(server) is not False
                for target in (SEED_ADDRESS, BUILTIN_POOL_ADDRESS, CUSTOM_POOL_ADDRESS,
                               '203.0.113.10', '203.0.113.11'):
                    lab.http('client-a', target, 'remote')
                    lab.http('client-b', target, 'direct')
                lab.http('client-a', '203.0.113.20', 'direct')
                # Both selectors must bind DNS independently; removing A must leave B working.
                other = copy.deepcopy(server)
                other.update(id='smoke-b', name='Smoke B', interface='awg-in-b',
                             subnet='10.230.2.0/24', server_ip='10.230.2.1')
                other['upstream'].update(table_id=211, fwmark=211)
                lab.ns('router', 'sh', str(ROOT / 'scripts/setup_iptables.sh'),
                       other['interface'], other['subnet'], 'awg-out')
                assert manager.configure_upstream_routing(other) is not False
                assert lab.dns('client-b', 'chatgpt.com')['answers'] > 0
                lab.http('client-b', '203.0.113.10', 'remote')
                # Broad coverage comes from the bundled provider snapshot;
                # these destinations have never appeared in client DNS or
                # seed inputs. B stays on the standard policy, despite sharing
                # the same physical exit interface.
                server['upstream']['service_ip_profile'] = 'expanded'
                assert manager.configure_upstream_routing(server) is not False
                for target in PROVIDER_ADDRESSES:
                    lab.http('client-a', target, 'remote')
                    lab.http('client-b', target, 'direct')
                    diagnostic = manager.get_upstream_diagnostics(server['id'], target)
                    assert diagnostic['destinations'][0]['provider_match'], diagnostic
                    assert diagnostic['destinations'][0]['route'] == 'upstream', diagnostic
                for client in ('client-a', 'client-b'):
                    lab.http(client, '203.0.113.20', 'direct')
                # A live downgrade must remove both broad rules and the
                # temporary /24 seed entries without disturbing standard B.
                server['upstream']['service_ip_profile'] = 'standard'
                assert manager.configure_upstream_routing(server) is not False
                for target in PROVIDER_ADDRESSES:
                    lab.http('client-a', target, 'direct')
                    lab.http('client-b', target, 'direct')
                assert lab.ns('router', 'ipset', 'list', 'awgwide_210', check=False).returncode != 0
                lab.http('client-b', '203.0.113.10', 'remote')
                assert manager.cleanup_upstream_routing(server) is not False
                lab.http('client-a', '203.0.113.10', 'direct')
                lab.http('client-b', '203.0.113.10', 'remote')
                assert manager.cleanup_upstream_routing(other) is not False
                lab.http('client-b', '203.0.113.10', 'direct')
                server['upstream']['service_ip_profile'] = 'expanded'
                assert manager.configure_upstream_routing(server) is not False
                # A replacement/restart also restores the recorded set; no new
                # client DNS query should be necessary for its cached address.
                lab.http('client-a', '203.0.113.10', 'remote')
                for hostname in ('chatgpt.com', 'tiktok.com'):
                    assert lab.dns('client-a', hostname)['answers'] > 0
                lab.http('client-a', '203.0.113.10', 'remote')
                # Removing the device tests immediate fail-close before health polling runs.
                lab.ns('router', 'ip', 'link', 'del', 'awg-out')
                lab.http('client-a', '203.0.113.10', None)
                for target in PROVIDER_ADDRESSES:
                    lab.http('client-a', target, None)
                    lab.http('client-b', target, 'direct')
                lab.http('client-a', '203.0.113.20', 'direct')
                assert manager.configure_wireguard_fail_closed_routing(server) is not False
                lab.http('client-a', '203.0.113.11', None)
                lab.http('client-b', '203.0.113.11', 'direct')
                # Cleanup is the fail-open/detach path: every destination is direct again.
                assert manager.cleanup_upstream_routing(server) is not False
                lab.http('client-a', '203.0.113.10', 'direct')
                rules = lab.ns('router', 'ip', 'rule', 'show').stdout
                assert 'lookup 210' not in rules, rules
                assert lab.ns('router', 'ipset', 'list', 'awgsel_210', check=False).returncode != 0
                assert lab.ns('router', 'ipset', 'list', 'awgpool_210', check=False).returncode != 0
                assert lab.ns('router', 'ipset', 'list', 'awgwide_210', check=False).returncode != 0
                assert 'AWGSEL_210' not in lab.ns('router', 'iptables-save').stdout
                lab.stop_upstream()
                print(f'PASS AWG {version}: DNS UDP/TCP, target egress, ordinary direct, '
                      'other server isolation, fail-open/recovery, fail-close, '
                      'pre-DNS seeded/static destinations, live pool replacement, abrupt namespace restart, '
                      'cached destination restore, broad provider subnets without DNS, standard downgrade, '
                      'real route diagnostics, idempotence, cleanup', flush=True)
        finally:
            try:
                if 'router' in lab.names:
                    try:
                        manager.cleanup_upstream_routing(server)
                    finally:
                        lab.stop_upstream()
            finally:
                lab.cleanup()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--serve-http':
        label = sys.argv[2]

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(label.encode('ascii'))

            def log_message(self, *_args):
                pass

        http.server.HTTPServer(('0.0.0.0', 18080), Handler).serve_forever()
    elif len(sys.argv) > 1 and sys.argv[1] == '--request-http':
        connection = http.client.HTTPConnection(sys.argv[2], 18080, timeout=2)
        connection.request('GET', '/')
        print(connection.getresponse().read().decode('ascii'))
        connection.close()
    elif len(sys.argv) > 1 and sys.argv[1] == '--request-dns':
        print(json.dumps(request_dns(sys.argv[2], sys.argv[3], sys.argv[4] == 'tcp', int(sys.argv[5]))))
    else:
        run_smoke()
