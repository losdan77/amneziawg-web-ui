"""Shared destination policy and DNS-assisted IPv4 routing for AWG clients.

AWG carries IP packets, not domain names. dnsmasq learns addresses from ordinary
DNS and populates a private ipset before returning the answer to the client.
Encrypted DNS and shared CDN addresses are inherent limitations of this mode.
"""
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import signal
import time


# Domain suffixes, deliberately avoiding entire shared CDNs/google.com.
# Keep this single list shared by dnsmasq and Xray.
AI_TIKTOK_DOMAINS = (
    'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com',
    'chat.com', 'sora.com',
    'anthropic.com', 'claude.ai', 'claude.com', 'claudeusercontent.com',
    'gemini.google.com', 'aistudio.google.com', 'generativelanguage.googleapis.com',
    'aiplatform.googleapis.com', 'alkalimakersuite-pa.clients6.google.com',
    'makersuite.google.com', 'notebooklm.google.com', 'notebooklm.google',
    'copilot.microsoft.com', 'copilot.cloud.microsoft', 'copilot.github.com',
    'githubcopilot.com', 'githubcopilot.net',
    'perplexity.ai', 'pplx.ai', 'grok.com', 'x.ai',
    'deepseek.com', 'mistral.ai', 'huggingface.co', 'hf.co',
    'poe.com', 'cursor.com', 'cursor.sh', 'cursorapi.com',
    'windsurf.com', 'codeium.com', 'codeiumdata.com',
    'midjourney.com', 'runwayml.com', 'suno.com', 'suno.ai',
    'elevenlabs.io',
    'tiktok.com', 'tiktokv.com', 'tiktokv.us', 'tiktokcdn.com',
    'tiktokcdn-us.com', 'tiktokcdn-eu.com', 'tiktokd.net',
    'tiktokrow-cdn.com', 'tiktokshop.com', 'musical.ly',
    'muscdn.com', 'byteoversea.com', 'ibytedtos.com', 'ibyteimg.com',
    'ipstatp.com', 'isnssdk.com', 'sgpstatp.com',
)


def normalize_routing_policy(data):
    """Retain the legacy checkbox semantics unless an explicit mode is given."""
    mode = data.get('routing_mode')
    if mode is None:
        enabled = data.get('split_ru_local', True)
        if enabled is None:
            enabled = True
        if isinstance(enabled, str):
            enabled = enabled.strip().lower() in ('true', '1', 'yes', 'on')
        return 'ru_split' if enabled else 'all'
    if mode not in ('all', 'ru_split', 'ai_tiktok'):
        raise ValueError('routing_mode must be all, ru_split or ai_tiktok')
    return mode


class SelectiveRouting:
    """Own only rules/processes belonging to one AWG server at a time."""

    def __init__(self, run_command, state_dir):
        self.run = run_command
        self.directory = Path(state_dir)

    def _checked(self, command):
        if self.run(command) is None:
            raise RuntimeError('Could not configure selective routing; check server logs')

    def _context(self, server):
        upstream = server['upstream']
        table = int(upstream['table_id'])
        mark = int(upstream.get('fwmark') or table)
        interface = server['interface']
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', interface):
            raise ValueError('Invalid AWG interface name')
        subnet = str(ipaddress.IPv4Network(server['subnet'], strict=False))
        address = str(ipaddress.IPv4Address(server['server_ip']))
        return table, mark, interface, subnet, address

    def _paths(self, table):
        return self.directory / f'dns-{table}.conf', self.directory / f'dns-{table}.pid'

    def _cache_path(self, server):
        _, _, interface, _, _ = self._context(server)
        return self.directory / f'addresses-{interface}.json'

    def _save_addresses(self, server):
        table, _, _, _, _ = self._context(server)
        output = self.run(f'ipset save awgsel_{table} 2>/dev/null') or ''
        addresses = {}
        now = time.time()
        for line in output.splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[:2] == ['add', f'awgsel_{table}'] and fields[3] == 'timeout':
                try:
                    address = str(ipaddress.IPv4Address(fields[2]))
                    ttl = min(86400, int(fields[4]))
                    if ttl > 0:
                        addresses[address] = now + ttl
                except ValueError:
                    continue
        if addresses:
            self.directory.mkdir(parents=True, exist_ok=True)
            self._cache_path(server).write_text(json.dumps(addresses), encoding='utf-8')

    def _restore_addresses(self, server):
        table, _, _, _, _ = self._context(server)
        try:
            addresses = json.loads(self._cache_path(server).read_text(encoding='utf-8'))
            if not isinstance(addresses, dict):
                return
            for address, expiry in addresses.items():
                address = str(ipaddress.IPv4Address(address))
                ttl = min(86400, int(float(expiry) - time.time()))
                if ttl > 0:
                    self._checked(f'ipset add awgsel_{table} {address} timeout {ttl} -exist')
        except (OSError, ValueError, TypeError):
            # A missing or expired cache simply needs a fresh client DNS lookup.
            return

    def _dns_pid(self, table):
        config, pidfile = self._paths(table)
        try:
            pid = int(pidfile.read_text().strip())
            if pid <= 1:
                return None
            args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
            if os.fsencode(f'--conf-file={config}') in args and b'dnsmasq' in Path(os.fsdecode(args[0])).name.encode():
                return pid
        except (OSError, ValueError):
            pass
        return None

    def ensure_dns(self, server):
        table, _, _, _, address = self._context(server)
        config, pidfile = self._paths(table)
        if self._dns_pid(table):
            return
        self.directory.mkdir(parents=True, exist_ok=True)
        resolvers = server.get('dns') or ['1.1.1.1', '8.8.8.8']
        # The resolver is local and deliberately remains usable during an
        # upstream outage, so ordinary local destinations continue to resolve.
        resolvers = [str(ipaddress.IPv4Address(value)) for value in resolvers
                     if ':' not in value and str(value) != address]
        if not resolvers:
            resolvers = ['1.1.1.1', '8.8.8.8']
        text = '\n'.join([
            'port=5353', f'listen-address={address}', 'bind-interfaces',
            'user=root', 'no-resolv', 'no-hosts', 'domain-needed',
            'filter-AAAA', 'cache-size=1000', 'max-cache-ttl=300', 'max-ttl=300',
            f'pid-file={pidfile}', f'log-facility={self.directory / ("dns-" + str(table) + ".log")}',
            *[f'server={value}' for value in resolvers],
            f"ipset=/{'/'.join(AI_TIKTOK_DOMAINS)}/awgsel_{table}", '',
        ])
        config.write_text(text, encoding='utf-8')
        os.chmod(config, 0o600)
        self._checked(f'dnsmasq --conf-file={shlex.quote(str(config))}')

    def configure(self, server):
        table, mark, interface, subnet, _ = self._context(server)
        chain, ipset = f'AWGSEL_{table}', f'awgsel_{table}'
        # The timeout exceeds the resolver cache TTL; connmarks retain the
        # route for long-lived connections after a DNS entry expires.
        existing_sets = (self.run('ipset list -n') or '').splitlines()
        self._checked(f'ipset create {ipset} hash:ip family inet timeout 86400 -exist')
        if ipset not in existing_sets:
            self._restore_addresses(server)
        self.ensure_dns(server)
        self._checked(f'iptables -t mangle -N {chain} 2>/dev/null || iptables -t mangle -S {chain} >/dev/null')
        rules = [
            f'-m connmark --mark {mark} -j CONNMARK --restore-mark',
            f'-m set --match-set {ipset} dst -j MARK --set-mark {mark}',
            f'-m mark --mark {mark} -j CONNMARK --save-mark',
        ]
        for rule in rules:
            self._checked(f'iptables -t mangle -C {chain} {rule} 2>/dev/null || iptables -t mangle -A {chain} {rule}')
        rule = f'-i {interface} -s {subnet} -j {chain}'
        self._checked(f'iptables -t mangle -C PREROUTING {rule} 2>/dev/null || iptables -t mangle -A PREROUTING {rule}')
        for protocol in ('udp', 'tcp'):
            rule = f'-i {interface} -s {subnet} -p {protocol} --dport 53 -j REDIRECT --to-ports 5353'
            self._checked(f'iptables -t nat -C PREROUTING {rule} 2>/dev/null || iptables -t nat -A PREROUTING {rule}')

    def cleanup(self, server):
        table, _, interface, subnet, _ = self._context(server)
        chain = f'AWGSEL_{table}'
        self._save_addresses(server)
        for protocol in ('udp', 'tcp'):
            self.run(f'iptables -t nat -D PREROUTING -i {interface} -s {subnet} -p {protocol} --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null || true')
        self.run(f'iptables -t mangle -D PREROUTING -i {interface} -s {subnet} -j {chain} 2>/dev/null || true')
        self.run(f'iptables -t mangle -F {chain} 2>/dev/null || true')
        self.run(f'iptables -t mangle -X {chain} 2>/dev/null || true')
        pid = self._dns_pid(table)
        if pid:
            try:
                os.kill(pid, signal.SIGTERM)
                # Wait for the socket to close before a replacement daemon is
                # started on the same address. Ignore stale/recycled PID files.
                deadline = time.monotonic() + 2
                while self._dns_pid(table) == pid and time.monotonic() < deadline:
                    time.sleep(0.025)
                if self._dns_pid(table) == pid:
                    raise RuntimeError('The selective DNS resolver did not stop')
            except ProcessLookupError:
                pass
        self.run(f'ipset destroy awgsel_{table} 2>/dev/null || true')
        for path in self._paths(table):
            path.unlink(missing_ok=True)
