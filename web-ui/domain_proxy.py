"""Domain-aware transparent routing for IPv4 AWG clients.

Each entry interface has its own sing-box process, FakeIP database and TPROXY
socket. Only that interface's TCP/UDP traffic is captured. Service selection
uses domain identity, never an entire shared CDN's address range.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import signal
import tempfile
import time

from service_domains import (selected_service_rules, youtube_service_rules,
                             chatgpt_voice_rules)


FAKEIP_NETWORK = '198.18.0.0/15'
# DNS is captured before these exclusions; the local panel and LAN traffic
# otherwise keep their existing kernel forwarding path.
LOCAL_NETWORKS = (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16',
    '224.0.0.0/4', '240.0.0.0/4',
)


class DomainProxy:
    def __init__(self, run_command, state_dir):
        self.run = run_command
        self.directory = Path(state_dir)

    @staticmethod
    def _context(server):
        upstream = server['upstream']
        table = int(upstream['table_id'])
        mark = int(upstream.get('fwmark') or table)
        if (not 200 <= table <= 9999 or not 1 <= mark <= 0xffffffff
                or 0x40000000 + 200 <= mark <= 0x40000000 + 9999):
            raise ValueError('Invalid service-routing table or mark')
        interface = server['interface']
        if not isinstance(interface, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', interface):
            raise ValueError('Invalid AWG interface name')
        subnet = ipaddress.IPv4Network(server['subnet'], strict=False)
        address = ipaddress.IPv4Address(server['server_ip'])
        if address not in subnet:
            raise ValueError('AWG server address must belong to its subnet')
        fake_network = ipaddress.IPv4Network(FAKEIP_NETWORK)
        if subnet.overlaps(fake_network):
            raise ValueError('AWG subnet overlaps the reserved service-routing FakeIP range')
        if upstream.get('local_address'):
            upstream_network = ipaddress.IPv4Interface(upstream['local_address']).network
            if upstream_network.overlaps(fake_network):
                raise ValueError('Upstream address overlaps the reserved service-routing FakeIP range')
        return {
            'table': table, 'mark': mark, 'interface': interface,
            'subnet': str(subnet), 'port': 20000 + table,
            'capture_mark': 0x40000000 + table,
            'capture_table': 50000 + table, 'priority': 1000 + table,
            'chain': f'AWGDOM_{table}',
        }

    def _paths(self, table):
        return {
            kind: self.directory / f'domain-{table}.{extension}'
            for kind, extension in (
                ('config', 'json'), ('pid', 'pid'), ('cache', 'db'),
                ('log', 'log'),
            )
        }

    def _checked(self, command):
        output = self.run(command)
        if output is None:
            raise RuntimeError('Could not configure domain routing; check server logs')
        return output

    def _write(self, path, content):
        self.directory.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=path.name + '.', dir=self.directory)
        try:
            with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def build_config(self, server):
        context = self._context(server)
        paths = self._paths(context['table'])
        selected = {key: value for key, value in selected_service_rules(server['upstream']).items() if value}
        youtube = {key: value for key, value in youtube_service_rules().items() if value}
        voice = chatgpt_voice_rules(server['upstream'])
        dns_rules = [
            # These AWG profiles carry IPv4 only. Do not offer an IPv6 path
            # outside the tunnel to clients that use the intercepted resolver.
            {'query_type': ['AAAA'], 'action': 'predefined', 'rcode': 'NOERROR'},
        ]
        if youtube:
            dns_rules.append({**youtube, 'action': 'route', 'server': 'local-dns'})
        if selected:
            dns_rules.extend([
                # HTTPS/SVCB hints can hand clients real addresses or ECH keys
                # outside FakeIP's domain mapping. Restrict this to services.
                {**selected, 'query_type': ['HTTPS', 'SVCB'],
                 'action': 'predefined', 'rcode': 'NOERROR'},
                {**selected, 'query_type': ['A'], 'action': 'route',
                 'server': 'fakeip', 'rewrite_ttl': 60},
                {**selected, 'action': 'route', 'server': 'tunnel-dns'},
            ])
        route_rules = [
            {'port': 53, 'action': 'hijack-dns'},
            {'action': 'sniff', 'sniffer': ['http', 'tls', 'quic'], 'timeout': '300ms'},
        ]
        if youtube:
            route_rules.append({**youtube, 'action': 'route', 'outbound': 'local'})
        if voice:
            route_rules.append({**voice, 'action': 'route', 'outbound': 'tunnel'})
        if selected:
            route_rules.append({**selected, 'action': 'route', 'outbound': 'tunnel'})
        route_rules.append({
            # A stale FakeIP with no recovered domain must never be forwarded
            # onto the public network. Mapped but deselected domains stay local.
            'type': 'logical', 'mode': 'and',
            'rules': [
                {'ip_cidr': [FAKEIP_NETWORK]},
                {'domain_regex': ['.+'], 'invert': True},
            ],
            'action': 'reject',
        })
        return {
            'log': {'level': 'warn', 'timestamp': True},
            'experimental': {'cache_file': {
                'enabled': True, 'path': str(paths['cache']),
                'cache_id': f"awg-{context['table']}", 'store_fakeip': True,
            }},
            'dns': {
                'servers': [
                    {'type': 'https', 'tag': 'local-dns', 'server': '1.1.1.1',
                     'tls': {'enabled': True, 'server_name': 'cloudflare-dns.com'},
                     'connect_timeout': '5s'},
                    {'type': 'https', 'tag': 'tunnel-dns', 'server': '1.1.1.1',
                     'tls': {'enabled': True, 'server_name': 'cloudflare-dns.com'},
                     'routing_mark': context['mark'], 'connect_timeout': '5s'},
                    {'type': 'fakeip', 'tag': 'fakeip', 'inet4_range': FAKEIP_NETWORK},
                ],
                'rules': dns_rules, 'final': 'local-dns', 'strategy': 'ipv4_only',
            },
            'inbounds': [{
                'type': 'tproxy', 'tag': 'awg', 'listen': '127.0.0.1',
                'listen_port': context['port'],
            }],
            'outbounds': [
                {'type': 'direct', 'tag': 'local',
                 'domain_resolver': {'server': 'local-dns', 'strategy': 'ipv4_only'}},
                {'type': 'direct', 'tag': 'tunnel', 'routing_mark': context['mark'],
                 'domain_resolver': {'server': 'tunnel-dns', 'strategy': 'ipv4_only'}},
            ],
            'route': {'rules': route_rules, 'final': 'local'},
        }

    def _pid(self, table):
        paths = self._paths(table)
        try:
            pid = int(paths['pid'].read_text().strip())
            if pid <= 1:
                return None
            arguments = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
            if (Path(os.fsdecode(arguments[0])).name == 'sing-box'
                    and len(arguments) >= 4 and arguments[1:3] == [b'run', b'-c']
                    and arguments[3] == os.fsencode(str(paths['config']))):
                return pid
        except (OSError, ValueError, IndexError):
            pass
        return None

    def _stop(self, table):
        pid = self._pid(table)
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                return
            deadline = time.monotonic() + 3
            while self._pid(table) == pid and time.monotonic() < deadline:
                time.sleep(0.025)
            if self._pid(table) == pid:
                raise RuntimeError('The domain routing process did not stop')
        self._paths(table)['pid'].unlink(missing_ok=True)

    def _start(self, table):
        paths = self._paths(table)
        # Bound the diagnostics file across restarts without logging payloads.
        try:
            if paths['log'].stat().st_size > 2 * 1024 * 1024:
                paths['log'].write_text('', encoding='utf-8')
        except FileNotFoundError:
            pass
        config, logfile, pidfile = (shlex.quote(str(paths[key])) for key in ('config', 'log', 'pid'))
        self._checked(
            f"umask 077; nohup sing-box run -c {config} </dev/null >>{logfile} 2>&1 & "
            f"domain_pid=$!; printf '%s\\n' \"$domain_pid\" >{pidfile}"
        )
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self._pid(table) and self._listening(20000 + table):
                return
            time.sleep(0.05)
        raise RuntimeError('The domain routing process could not start; check server logs')

    def _listening(self, port):
        # Both sockets must be ready before client traffic is captured.
        for protocol in ('tcp', 'udp'):
            try:
                lines = Path(f'/proc/net/{protocol}').read_text().splitlines()[1:]
                if not any(line.split()[1] == f'0100007F:{port:04X}'
                           and (protocol != 'tcp' or line.split()[3] == '0A')
                           for line in lines if len(line.split()) >= 4):
                    return False
            except OSError:
                return False
        return True

    @staticmethod
    def _jump(context):
        return f"-i {context['interface']} -s {context['subnet']} -j {context['chain']}"

    @staticmethod
    def _input_rule(context, protocol):
        return (f"-i {context['interface']} -s {context['subnet']} -p {protocol} "
                f"-m mark --mark {context['capture_mark']} -j ACCEPT")

    @staticmethod
    def _target(context):
        return (f"-j TPROXY --on-ip 127.0.0.1 --on-port {context['port']} "
                f"--tproxy-mark {context['capture_mark']}/0xffffffff")

    @staticmethod
    def _policy_pattern(context):
        return (f"^{context['priority']}:[[:space:]]+from all fwmark "
                f"{hex(context['capture_mark'])} lookup {context['capture_table']}$")

    def _capture(self, context):
        chain, mark = context['chain'], context['capture_mark']
        self._checked(f"ip -4 route replace local 0.0.0.0/0 dev lo table {context['capture_table']}")
        pattern = self._policy_pattern(context)
        self._checked(
            f"ip -4 rule show | grep -qE {shlex.quote(pattern)} || "
            f"ip -4 rule add fwmark {mark} table {context['capture_table']} priority {context['priority']}"
        )
        self._checked(f'iptables -t mangle -N {chain} 2>/dev/null || iptables -t mangle -S {chain} >/dev/null')
        target = self._target(context)
        rules = [f'-p {protocol} --dport 53 {target}' for protocol in ('udp', 'tcp')]
        rules.append('-m addrtype --dst-type LOCAL -j RETURN')
        rules.extend(f'-d {network} -j RETURN' for network in LOCAL_NETWORKS)
        rules.extend(f'-p {protocol} {target}' for protocol in ('tcp', 'udp'))
        for rule in rules:
            self._checked(f'iptables -t mangle -C {chain} {rule} 2>/dev/null || iptables -t mangle -A {chain} {rule}')
        for protocol in ('tcp', 'udp'):
            rule = self._input_rule(context, protocol)
            self._checked(f'iptables -C INPUT {rule} 2>/dev/null || iptables -A INPUT {rule}')
        jump = self._jump(context)
        self._checked(f'iptables -t mangle -C PREROUTING {jump} 2>/dev/null || iptables -t mangle -I PREROUTING 1 {jump}')

    def configure(self, server):
        context = self._context(server)
        paths = self._paths(context['table'])
        content = json.dumps(self.build_config(server), ensure_ascii=True, sort_keys=True, indent=2) + '\n'
        previous = paths['config'].read_text(encoding='utf-8') if paths['config'].exists() else None
        if previous != content:
            stage = paths['config'].with_suffix('.check.json')
            self._write(stage, content)
            try:
                self._checked(f'sing-box check -c {shlex.quote(str(stage))}')
            finally:
                stage.unlink(missing_ok=True)
            self._stop(context['table'])
            try:
                self._write(paths['config'], content)
                self._start(context['table'])
            except Exception:
                self._stop(context['table'])
                if previous is not None:
                    self._write(paths['config'], previous)
                    self._start(context['table'])
                else:
                    paths['config'].unlink(missing_ok=True)
                raise
        elif not self._pid(context['table']) or not self._listening(context['port']):
            self._stop(context['table'])
            self._start(context['table'])
        self._capture(context)

    def ensure_running(self, server):
        """Repair a crashed process or removed rules without restarting healthy flows."""
        self.configure(server)

    def restart(self, server):
        """Close old sockets when failover changes their physical egress path."""
        self._stop(self._context(server)['table'])
        self.configure(server)

    def status(self, server):
        context = self._context(server)
        running = bool(self._pid(context['table'])) and self._listening(context['port'])
        checks = [
            f'iptables -t mangle -C PREROUTING {self._jump(context)} 2>/dev/null',
            f"ip -4 rule show | grep -qE {shlex.quote(self._policy_pattern(context))}",
            f"ip -4 route show table {context['capture_table']} | grep -qE '^local (default|0.0.0.0/0) dev lo( |$)'",
        ]
        for protocol in ('tcp', 'udp'):
            checks.extend([
                f"iptables -t mangle -C {context['chain']} -p {protocol} {self._target(context)} 2>/dev/null",
                f"iptables -t mangle -C {context['chain']} -p {protocol} --dport 53 {self._target(context)} 2>/dev/null",
                f'iptables -C INPUT {self._input_rule(context, protocol)} 2>/dev/null',
            ])
        capture = all(self.run(command) is not None for command in checks)
        return {'running': running, 'capture_ready': capture, 'port': context['port'],
                'engine': 'sing-box', 'fakeip_persistent': True}

    def cleanup(self, server):
        context = self._context(server)
        chain, jump = context['chain'], self._jump(context)
        self.run(f'iptables -t mangle -D PREROUTING {jump} 2>/dev/null || true')
        self.run(f'iptables -t mangle -F {chain} 2>/dev/null || true')
        self.run(f'iptables -t mangle -X {chain} 2>/dev/null || true')
        for protocol in ('tcp', 'udp'):
            self.run(f'iptables -D INPUT {self._input_rule(context, protocol)} 2>/dev/null || true')
        self.run(
            f"ip -4 rule del fwmark {context['capture_mark']} table {context['capture_table']} "
            f"priority {context['priority']} 2>/dev/null || true"
        )
        self.run(f"ip -4 route flush table {context['capture_table']} 2>/dev/null || true")
        self._stop(context['table'])
        paths = self._paths(context['table'])
        paths['config'].unlink(missing_ok=True)
        paths['pid'].unlink(missing_ok=True)
        # Keep the FakeIP store: existing clients may still cache those addresses
        # if this tunnel is re-enabled or the container is recreated.
