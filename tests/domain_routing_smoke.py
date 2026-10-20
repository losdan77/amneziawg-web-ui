"""Real service routing through AWG2/3 in disposable Linux namespaces.

Run only in a privileged disposable container (no host network). The fixture
has no Internet dependency: the local and European exits deliberately serve the
same destination IP, and private test DNS returns that shared IP for every host.
"""
import copy
import http.client
import http.server
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import time

from awg_routing_smoke import Lab, ROOT, command, load_manager

SELF = str(Path(__file__).resolve())
SHARED_IP = '203.0.113.10'
DNS_IP = '203.0.113.53'
FAKE_POOL = '198.19.0.0/16'


class ServiceLab(Lab):
    def setup(self):
        super().setup()
        certificate = str(self.directory / 'server.pem')
        # Public fixture credentials avoid OpenSSL or package downloads in the test.
        shutil.copyfile(ROOT / 'tests/fixtures/domain-routing-tls.pem', certificate)
        os.chmod(certificate, 0o600)
        key = certificate
        for name in ('direct', 'remote'):
            self.ns(name, 'ip', 'addr', 'add', DNS_IP + '/32', 'dev', 'lo')
            self.start(name, 'dnsmasq', '--keep-in-foreground', '--conf-file=/dev/null',
                       '--no-resolv', '--no-hosts', '--bind-interfaces',
                       '--listen-address=' + DNS_IP, '--port=53',
                       '--address=/#/' + SHARED_IP,
                       '--pid-file=' + str(self.directory / ('dns-' + name + '.pid')))
            self.start(name, sys.executable, SELF, '--serve-tls', name, certificate, key)
            self.start(name, sys.executable, SELF, '--serve-opaque', name)
            self.start(name, sys.executable, SELF, '--serve-udp', name)

    def request(self, client, address, hostname, expected, protocol='http'):
        result = self.ns(client, sys.executable, SELF, '--request',
                         protocol, address, hostname, check=False)
        if expected is None:
            assert result.returncode != 0, f'{protocol} blocked target leaked: {result.stdout}'
        else:
            assert result.returncode == 0 and result.stdout.strip() == expected, (
                f'{client} {protocol} {hostname} at {address}: '
                f'expected {expected}, got {result.stdout!r} {result.stderr}')

    def query(self, client, hostname, tcp=False, qtype=1):
        result = self.ns(client, sys.executable, SELF, '--dns', hostname,
                         'tcp' if tcp else 'udp', str(qtype))
        return json.loads(result.stdout)


def request_dns(hostname, tcp=False, qtype=1):
    labels = b''.join(bytes([len(label)]) + label.encode('ascii') for label in hostname.split('.'))
    query = struct.pack('!6H', 21013, 0x100, 1, 0, 0, 0) + labels + b'\0' + struct.pack('!HH', qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        if tcp:
            sock.connect(('9.9.9.9', 53))
            sock.sendall(struct.pack('!H', len(query)) + query)
            header = sock.recv(2, socket.MSG_WAITALL)
            assert len(header) == 2, 'DNS TCP did not return its length'
            data = sock.recv(struct.unpack('!H', header)[0], socket.MSG_WAITALL)
        else:
            sock.sendto(query, ('9.9.9.9', 53))
            data = sock.recv(4096)
    identity, flags, questions, answers, _, _ = struct.unpack('!6H', data[:12])
    assert identity == 21013 and flags & 0x8000 and not flags & 15, 'DNS failed'

    def skip_name(offset):
        while data[offset]:
            if data[offset] & 0xc0 == 0xc0:
                return offset + 2
            offset += data[offset] + 1
        return offset + 1

    offset = 12
    for _ in range(questions):
        offset = skip_name(offset) + 4
    addresses = []
    for _ in range(answers):
        offset = skip_name(offset)
        kind, _, _, length = struct.unpack('!HHIH', data[offset:offset + 10])
        offset += 10
        if kind == 1 and length == 4:
            addresses.append(socket.inet_ntoa(data[offset:offset + 4]))
        offset += length
    return {'answers': answers, 'addresses': addresses}


def client_request(protocol, address, hostname):
    if protocol in ('opaque', 'udp'):
        kind = socket.SOCK_DGRAM if protocol == 'udp' else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, kind) as sock:
            sock.settimeout(3)
            sock.connect((address, 18083 if protocol == 'udp' else 18082))
            sock.sendall(b'opaque fixture payload\n')
            print(sock.recv(64).decode('ascii'))
        return
    if protocol == 'tls':
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((address, 18443), timeout=3) as transport:
            with context.wrap_socket(transport, server_hostname=hostname) as sock:
                sock.sendall(('GET / HTTP/1.0\r\nHost: ' + hostname + '\r\n\r\n').encode('ascii'))
                response = http.client.HTTPResponse(sock)
                response.begin()
                print(response.read().decode('ascii'))
        return
    connection = http.client.HTTPConnection(address, 18080, timeout=3)
    connection.putrequest('GET', '/', skip_host=True)
    connection.putheader('Host', hostname)
    connection.endheaders()
    print(connection.getresponse().read().decode('ascii'))
    connection.close()


def exercise(directory, names, version, cache_phase=None):
    # This driver runs inside the router namespace so production /proc/net
    # readiness checks inspect the actual sing-box listener namespace.
    import domain_proxy
    domain_proxy.FAKEIP_NETWORK = FAKE_POOL
    original_build = domain_proxy.DomainProxy.build_config

    def fixture_config(self, server):
        config = original_build(self, server)
        config['log']['level'] = 'debug'
        for resolver in config['dns']['servers']:
            if resolver['tag'] != 'fakeip':
                resolver.update(type='udp', server=DNS_IP)
                resolver.pop('tls', None)
        return config

    domain_proxy.DomainProxy.build_config = fixture_config
    lab = ServiceLab(directory)
    lab.names = names
    manager = load_manager(directory)
    manager.save_config.__func__.__globals__['CONFIG_FILE'] = str(Path(directory) / 'manager.json')

    def execute(shell_command):
        shell_command = shell_command.replace('/app/scripts/', str(ROOT / 'scripts') + '/')
        result = command('sh', '-c', shell_command, check=False)
        if result.returncode and '2>/dev/null' not in shell_command:
            print('Routing command failed: ' + result.stderr.strip(), file=sys.stderr)
        return result.stdout if result.returncode == 0 else None

    manager.execute_command = execute
    server = {
        'id': 'domain-a', 'name': 'Service A', 'protocol': 'wireguard', 'mode': 'edge_linked',
        'interface': 'awg-in-a', 'subnet': '10.230.1.0/24', 'server_ip': '10.230.1.1',
        'dns': ['198.18.0.1'], 'egress_interface': 'awg-out', 'linked_failover_mode': 'fail_close', 'routing_state': 'upstream',
        'upstream': {'interface': 'awg-out', 'endpoint': '198.18.0.6:53011',
                     'table_id': 210, 'fwmark': 210, 'service_cidrs': [],
                     'config_path': str(Path(directory) / 'awg-out.conf'),
                     'routing_mode': 'selected_services',
                     'selected_services': ['chatgpt', 'codex', 'claude', 'tiktok']},
    }
    manager.config['servers'] = [server]
    proxy = manager._domain_proxy()
    other = None
    try:
        lab.ns('router', 'sh', str(ROOT / 'scripts/setup_iptables.sh'),
               server['interface'], server['subnet'], 'awg-out')
        assert manager.configure_upstream_routing(server) is not False
        assert proxy.status(server)['running'] and proxy.status(server)['capture_ready']
        print(f'AWG{version}: transparent process and kernel capture ready', flush=True)

        if cache_phase == 'prime':
            fake = lab.query('client-a', 'chatgpt.com')['addresses'][0]
            assert ipaddress.ip_address(fake) in ipaddress.ip_network(FAKE_POOL)
            Path(directory, 'container-fakeip.json').write_text(json.dumps({'chatgpt': fake}))
            print('PRIMED: cached ChatGPT FakeIP; exiting container without graceful proxy shutdown', flush=True)
            # Only the explicit disposable-container test calls this branch.
            # Skip the driver's finally: PID 1 then exits and Docker kills
            # every fixture process, including sing-box, without a flush.
            os._exit(0)
        if cache_phase == 'check':
            fake = json.loads(Path(directory, 'container-fakeip.json').read_text())['chatgpt']
            # No DNS allocation or sniffable request may precede this check.
            lab.request('client-a', fake, 'unused', 'remote', 'opaque')
            lab.request('client-a', fake, 'unused', 'remote', 'udp')
            new_fake = lab.query('client-a', 'claude.ai')['addresses'][0]
            assert new_fake != fake, 'Container restart recycled an existing FakeIP'
            assert lab.query('client-a', 'chatgpt.com')['addresses'] == [fake]
            lab.request('client-a', SHARED_IP, 'www.youtube.com', 'direct', 'tls')
            print('PASS: cached FakeIP survives actual container replacement without address reuse', flush=True)
            return

        # The same actual IP must split by HTTP Host or TLS SNI, even without
        # any preceding client DNS query (cached DNS / encrypted DNS fallback).
        for protocol in ('http', 'tls'):
            for hostname, expected in (
                ('chatgpt.com', 'remote'), ('api.openai.com', 'remote'),
                ('claude.ai', 'remote'), ('www.tiktok.com', 'remote'),
                ('www.youtube.com', 'direct'), ('r1.video.googlevideo.com', 'direct'),
                ('ordinary.example', 'direct'),
            ):
                lab.request('client-a', SHARED_IP, hostname, expected, protocol)
            lab.request('client-b', SHARED_IP, 'chatgpt.com', 'direct', protocol)
        print(f'AWG{version}: shared-IP HTTP/TLS service identity and YouTube local verified', flush=True)

        fake = lab.query('client-a', 'chatgpt.com')['addresses'][0]
        assert ipaddress.ip_address(fake) in ipaddress.ip_network(FAKE_POOL), fake
        assert lab.query('client-a', 'chatgpt.com', tcp=True)['addresses'] == [fake]
        assert lab.query('client-a', 'chatgpt.com', qtype=28)['answers'] == 0
        assert lab.query('client-a', 'chatgpt.com', qtype=65)['answers'] == 0
        assert lab.query('client-a', 'www.youtube.com', tcp=True)['addresses'] == [SHARED_IP]
        assert lab.query('client-a', 'ordinary.example')['addresses'] == [SHARED_IP]
        # No HTTP host or TLS SNI exists in either opaque transport. Only the
        # FakeIP association can select the correct exit.
        for protocol in ('http', 'tls', 'opaque', 'udp'):
            lab.request('client-a', fake, 'chatgpt.com', 'remote', protocol)
        lab.request('client-a', SHARED_IP, 'unused', 'direct', 'udp')
        print(f'AWG{version}: UDP/TCP DNS, FakeIP opaque TCP/UDP and IPv6/hint filtering verified', flush=True)

        old_pid = proxy._pid(210)
        proxy.configure(server)
        assert proxy._pid(210) == old_pid, 'Unchanged configuration restarted live sessions'
        for _ in range(2):
            os.kill(proxy._pid(210), signal.SIGKILL)
            proxy.ensure_running(server)
            assert proxy._pid(210) != old_pid
            old_pid = proxy._pid(210)
            # Reuse the cached address BEFORE any DNS query or sniffable
            # request. The second crash occurs without a new allocation.
            lab.request('client-a', fake, 'unused', 'remote', 'opaque')
        new_fake = lab.query('client-a', 'claude.ai')['addresses'][0]
        assert new_fake != fake, 'Restart reused an allocated FakeIP for another service'
        assert lab.query('client-a', 'chatgpt.com')['addresses'] == [fake]
        lab.request('client-a', new_fake, 'unused', 'remote', 'opaque')
        print(f'AWG{version}: cached FakeIP survives repeated SIGKILL without address reuse', flush=True)

        server['upstream']['selected_services'] = ['claude']
        assert manager.configure_upstream_routing(server) is not False
        for hostname, expected in (('claude.ai', 'remote'), ('chatgpt.com', 'direct'),
                                   ('www.tiktok.com', 'direct'), ('www.youtube.com', 'direct')):
            lab.request('client-a', SHARED_IP, hostname, expected, 'tls')
        lab.request('client-a', fake, 'unused', 'direct', 'opaque')
        server['upstream']['selected_services'] = []
        assert manager.configure_upstream_routing(server) is not False
        lab.request('client-a', SHARED_IP, 'claude.ai', 'direct', 'tls')
        lab.request('client-a', fake, 'unused', 'direct', 'opaque')
        assert lab.query('client-a', 'chatgpt.com')['addresses'] == [SHARED_IP]
        server['upstream']['selected_services'] = ['chatgpt', 'codex', 'claude', 'tiktok']
        assert manager.configure_upstream_routing(server) is not False
        lab.request('client-a', fake, 'unused', 'remote', 'opaque')
        print(f'AWG{version}: service selection, empty selection and cached FakeIP changes verified', flush=True)

        other = copy.deepcopy(server)
        other.update(id='domain-b', interface='awg-in-b', subnet='10.230.2.0/24', server_ip='10.230.2.1')
        other['upstream'].update(table_id=211, fwmark=211, selected_services=['claude'])
        manager.config['servers'].append(other)
        assert manager.configure_upstream_routing(other) is not False
        other_fake = lab.query('client-b', 'claude.ai')['addresses'][0]
        lab.request('client-b', other_fake, 'unused', 'remote', 'opaque')
        lab.request('client-b', SHARED_IP, 'chatgpt.com', 'direct', 'tls')
        assert manager.cleanup_upstream_routing(server) is not False
        lab.request('client-a', SHARED_IP, 'chatgpt.com', 'direct', 'tls')
        lab.request('client-b', other_fake, 'unused', 'remote', 'opaque')
        assert manager.cleanup_upstream_routing(other) is not False
        assert manager.configure_upstream_routing(server) is not False

        # Remove the actual AWG device: the kernel must block selected flows
        # immediately, without relying on the periodic health worker.
        lab.ns('router', 'ip', 'link', 'del', 'awg-out')
        lab.request('client-a', SHARED_IP, 'chatgpt.com', None, 'tls')
        lab.request('client-a', SHARED_IP, 'www.youtube.com', 'direct', 'tls')
        assert manager.configure_wireguard_fail_closed_routing(server) is not False
        lab.request('client-a', fake, 'unused', None, 'opaque')
        lab.request('client-a', SHARED_IP, 'ordinary.example', 'direct')
        assert manager.switch_server_egress(server, 'local') is not False
        lab.request('client-a', fake, 'unused', 'direct', 'opaque')
        lab.request('client-a', SHARED_IP, 'chatgpt.com', 'direct', 'tls')
        lab.stop_upstream()
        lab.upstream(version)
        assert manager.switch_server_egress(server, 'upstream') is not False
        lab.request('client-a', fake, 'unused', 'remote', 'opaque')
        print(f'AWG{version}: entry isolation, immediate fail-close, fail-open and recovery verified', flush=True)

        assert manager.cleanup_upstream_routing(server) is not False
        assert not proxy._pid(210)
        assert 'AWGDOM_210' not in command('iptables-save').stdout
        assert 'lookup 50210' not in command('ip', '-4', 'rule', 'show').stdout
        # The previous mode remains usable as an explicit choice.
        server['upstream']['routing_mode'] = 'ai_tiktok'
        server['upstream']['service_ip_profile'] = 'standard'
        assert manager.configure_upstream_routing(server) is not False
        assert lab.dns('client-a', 'chatgpt.com')['answers'] > 0
        lab.request('client-a', SHARED_IP, 'chatgpt.com', 'remote')
        assert manager.cleanup_upstream_routing(server) is not False
        server['upstream']['routing_mode'] = 'selected_services'
        assert manager.configure_upstream_routing(server) is not False
        lab.request('client-a', fake, 'unused', 'remote', 'opaque')
        lab.request('client-a', SHARED_IP, 'www.youtube.com', 'direct', 'tls')
        print(f'PASS AWG{version}: legacy mode switch and full domain-routing recovery', flush=True)
    except Exception:
        for logfile in Path(directory).rglob('domain-*.log'):
            print(f'Proxy log {logfile.name}:\n{logfile.read_text()[-12000:]}', file=sys.stderr)
        print(command('ip', '-4', 'rule', 'show').stdout, file=sys.stderr)
        print(command('iptables-save').stdout, file=sys.stderr)
        raise
    finally:
        for entry in (server, other):
            if entry:
                manager.cleanup_upstream_routing(entry)



def container_cache(phase, directory):
    """Two separate disposable containers share only a fresh test volume.

    Invoke --container-cache-prime /state, then --container-cache-check /state
    in a new container with that same volume. Never mount production state.
    """
    if sys.platform != 'linux' or os.geteuid() != 0 or not Path('/.dockerenv').exists():
        raise SystemExit('Container cache test requires a disposable privileged Docker container.')
    Path(directory).mkdir(parents=True, exist_ok=True)
    lab = ServiceLab(directory)
    primed = False
    try:
        lab.setup()
        lab.upstream('3')
        result = lab.ns('router', sys.executable, SELF, '--exercise', directory,
                        json.dumps(lab.names), '3', phase, check=False, timeout=60)
        print(result.stdout, end='', flush=True)
        if result.returncode:
            print(result.stderr, file=sys.stderr)
            raise RuntimeError('Container FakeIP persistence ' + phase + ' failed')
        primed = phase == 'prime'
    finally:
        if not primed:
            lab.stop_upstream()
            lab.cleanup()
    # On successful priming intentionally leave namespace helpers running.
    # Exiting this disposable container's PID 1 gives the cache an abrupt stop.


def run_smoke():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Use a disposable privileged Linux container, without host networking.')
    for executable in ('ip', 'iptables', 'dnsmasq', 'awg', 'awg-quick', 'sing-box'):
        if not shutil.which(executable):
            raise SystemExit('Missing test executable: ' + executable)
    for version in ('2', '3'):
        with tempfile.TemporaryDirectory(prefix='domain-routing-smoke-') as directory:
            lab = ServiceLab(directory)
            try:
                lab.setup()
                lab.upstream(version)
                result = lab.ns('router', sys.executable, SELF, '--exercise', directory,
                                json.dumps(lab.names), version, check=False, timeout=240)
                print(result.stdout, end='', flush=True)
                if result.returncode:
                    print(result.stderr, file=sys.stderr)
                    raise RuntimeError('Domain-routing namespace test failed for AWG' + version)
            finally:
                lab.stop_upstream()
                lab.cleanup()


if __name__ == '__main__':
    mode = sys.argv[1] if len(sys.argv) > 1 else ''
    if mode == '--dns':
        print(json.dumps(request_dns(sys.argv[2], sys.argv[3] == 'tcp', int(sys.argv[4]))))
    elif mode == '--request':
        client_request(*sys.argv[2:5])
    elif mode == '--exercise':
        exercise(sys.argv[2], json.loads(sys.argv[3]), sys.argv[4],
                 sys.argv[5] if len(sys.argv) > 5 else None)
    elif mode in ('--container-cache-prime', '--container-cache-check'):
        container_cache(mode.rsplit('-', 1)[1], sys.argv[2])
    elif mode == '--serve-tls':
        label, certificate, key = sys.argv[2:5]

        class HttpHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(label.encode('ascii'))

            def log_message(self, *_args):
                pass

        service = http.server.ThreadingHTTPServer(('0.0.0.0', 18443), HttpHandler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, key)
        service.socket = context.wrap_socket(service.socket, server_side=True)
        service.serve_forever()
    elif mode == '--serve-opaque':
        label = sys.argv[2]

        class OpaqueHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.recv(4096)
                self.request.sendall(label.encode('ascii'))

        socketserver.ThreadingTCPServer(('0.0.0.0', 18082), OpaqueHandler).serve_forever()
    elif mode == '--serve-udp':
        label = sys.argv[2]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as service:
            service.bind((SHARED_IP, 18083))
            while True:
                _, source = service.recvfrom(4096)
                service.sendto(label.encode('ascii'), source)
    else:
        run_smoke()
