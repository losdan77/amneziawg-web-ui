"""Shared destination policy and hybrid IPv4 routing for AWG clients.

AWG carries IP packets, not domain names. dnsmasq learns addresses from ordinary
DNS and populates a private ipset before returning the answer to the client.
A separate IP/network pool covers pre-resolved hosts and explicit public CIDRs.
Unknown encrypted-DNS answers and shared CDN IPs remain limitations of this mode.
"""
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
from pathlib import Path
import re
import shlex
import signal
import tempfile
import time

import requests
from service_networks import (normalize_service_ip_profile, load_expanded_networks,
                              refresh_expanded_networks, expanded_network_status)


# Domain suffixes, deliberately avoiding entire shared CDNs/google.com.
# Keep this single list shared by dnsmasq and Xray.
AI_TIKTOK_DOMAINS = (
    'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com',
    'chat.com', 'sora.com', 'oaistatsig.com', 'cdn.openaimerge.com',
    'anthropic.com', 'claude.ai', 'claude.com', 'claudeusercontent.com',
    'claudemcpclient.com', 'claudemcpcontent.com',
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
    'tik-tokapi.com', 'tiktok-row.net', 'tiktokd.org', 'tiktokeu-cdn.com',
    'tiktokv.eu', 'tiktokw.eu', 'tiktokw.us', 'ttcdn-us.com', 'ttlivecdn.com',
    'ttoverseaus.net', 'ttwstatic.com', 'tiktokcdn.com.akamaized.net',
    'tiktokv.com.edgekey.net',
)

# Anthropic's published API range. This is not a complete range for Claude's
# website, and shared CDN ranges must never be inferred from an ASN owner.
SERVICE_IP_NETWORKS = ('160.79.104.0/23',)
BUILTIN_SERVICE_CIDRS = SERVICE_IP_NETWORKS
SERVICE_SEED_HOSTS = (
    'chatgpt.com', 'www.chatgpt.com', 'auth.openai.com', 'auth0.openai.com',
    'api.openai.com', 'platform.openai.com', 'ab.chatgpt.com',
    'android.chat.openai.com', 'ios.chat.openai.com',
    'ws.chatgpt.com', 'chat.openai.com', 'cdn.oaistatic.com',
    'files.oaiusercontent.com', 'claude.ai', 'www.claude.ai',
    'api.anthropic.com', 'console.anthropic.com',
    'www.tiktok.com', 'm.tiktok.com', 'tiktok.com', 'www.tiktokv.com',
    'api16-normal-c-useast1a.tiktokv.com', 'api16-normal-c-useast2a.tiktokv.com',
    'api16-normal-c-alisg.tiktokv.com',
)
SEED_TTL = 3600
MAX_SERVICE_CIDRS = 256
_NON_PUBLIC_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
))


def normalize_service_cidrs(value):
    """Validate optional public IPv4 networks without broad or private routes."""
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > MAX_SERVICE_CIDRS:
        raise ValueError('service_cidrs must be a list of at most 256 IPv4 addresses or networks')
    networks = set()
    for item in value:
        if not isinstance(item, str) or not item or item != item.strip() or re.search(r'\s', item):
            raise ValueError('Each service_cidrs entry must be one IPv4 address or network')
        try:
            network = ipaddress.IPv4Network(item, strict=False)
        except ValueError as error:
            raise ValueError('service_cidrs only supports IPv4 addresses or networks') from error
        if network.prefixlen < 8 or any(network.overlaps(other) for other in _NON_PUBLIC_NETWORKS):
            raise ValueError('service_cidrs must contain public IPv4 networks with prefix /8 or narrower')
        networks.add(network)
    return [str(network) for network in sorted(networks)]


def _public_ipv4(value):
    if not isinstance(value, str):
        return None
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        return None
    if not address.is_global or address.is_multicast or address.is_reserved:
        return None
    return str(address)


def _resolve_host_doh(host):
    response = requests.get('https://dns.google/resolve', params={'name': host, 'type': 'A'},
                            timeout=(3, 5))
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or payload.get('Status') != 0:
        raise ValueError('DNS query failed')
    return [answer.get('data') for answer in payload.get('Answer', [])
            if isinstance(answer, dict) and answer.get('type') == 1]


def resolve_service_hosts(hosts=SERVICE_SEED_HOSTS, resolver=None):
    """Resolve known exact hosts without requiring a client DNS lookup.

    The resolver callback accepts one host and returns IPv4 address strings.
    A failed host is reported without discarding other or previously cached
    destinations. This function performs no configuration or routing writes.
    """
    hosts = tuple(dict.fromkeys(hosts))
    if len(hosts) > 256 or any(not isinstance(host, str) or
                             not re.fullmatch(r'[a-z0-9]+(?:[.-][a-z0-9]+)+', host)
                             for host in hosts):
        raise ValueError('Invalid service seed hosts')
    resolver = resolver or _resolve_host_doh
    addresses, errors = set(), []
    resolved = 0
    with ThreadPoolExecutor(max_workers=6) as executor:
        pending = {executor.submit(resolver, host): host for host in hosts}
        for future in as_completed(pending):
            try:
                values = future.result()
                if isinstance(values, str):
                    values = [values]
                valid = {address for value in values if (address := _public_ipv4(value))}
                if not valid:
                    raise ValueError('No public IPv4 DNS answers')
                addresses.update(valid)
                resolved += 1
            except Exception:
                errors.append(pending[future])
    return {'addresses': sorted(addresses, key=ipaddress.IPv4Address),
            'errors': sorted(errors), 'resolved_hosts': resolved, 'queried_hosts': len(hosts)}


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


def service_destination_networks(upstream, state_dir=None):
    networks = list(BUILTIN_SERVICE_CIDRS) + normalize_service_cidrs(upstream.get('service_cidrs'))
    if normalize_service_ip_profile(upstream.get('service_ip_profile')) == 'expanded':
        networks += load_expanded_networks(state_dir)
    return networks


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

    def _seed_path(self, server):
        _, _, interface, _, _ = self._context(server)
        return self.directory / f'seed-addresses-{interface}.json'

    def _seed_status_path(self, server):
        _, _, interface, _, _ = self._context(server)
        return self.directory / f'seed-status-{interface}.json'

    def _write_json(self, path, content):
        self.directory.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                             dir=self.directory, prefix=path.name + '.',
                                             suffix='.tmp', delete=False) as stream:
                temporary = stream.name
                os.chmod(temporary, 0o600)
                json.dump(content, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary:
                Path(temporary).unlink(missing_ok=True)

    def seed_status(self, server):
        try:
            result = json.loads(self._seed_status_path(server).read_text(encoding='utf-8'))
            return result if isinstance(result, dict) else {}
        except (OSError, ValueError):
            return {}

    def _seed_addresses(self, server):
        now = time.time()
        try:
            values = json.loads(self._seed_path(server).read_text(encoding='utf-8'))
        except (OSError, ValueError):
            return {}
        if not isinstance(values, dict):
            return {}
        result = {}
        for address, expiry in values.items():
            validated = _public_ipv4(address)
            try:
                ttl = int(float(expiry) - now)
            except (ValueError, TypeError, OverflowError):
                continue
            if validated and ttl > 0:
                result[validated] = now + min(SEED_TTL, ttl)
        return result

    def _static_networks(self, server):
        return list(BUILTIN_SERVICE_CIDRS) + normalize_service_cidrs(server['upstream'].get('service_cidrs'))

    def refresh_provider_pool(self, server):
        """Replace the broad provider set atomically, without a traffic gap."""
        table, _, _, _, _ = self._context(server)
        if normalize_service_ip_profile(server['upstream'].get('service_ip_profile')) != 'expanded':
            return
        networks = load_expanded_networks(self.directory)
        if not networks:
            raise RuntimeError('Expanded service networks are unavailable')
        live, staging = f'awgwide_{table}', f'awgwtmp_{table}'
        self._checked(f'ipset create {live} hash:net family inet maxelem 262144 -exist')
        # The old set remains referenced by iptables until the complete new set
        # is populated. An interrupted restore never replaces the live set.
        self.run(f'ipset destroy {staging} 2>/dev/null || true')
        self.directory.mkdir(parents=True, exist_ok=True)
        path = None
        try:
            with tempfile.NamedTemporaryFile(mode='w', encoding='ascii', dir=self.directory,
                                             prefix='provider-', suffix='.restore', delete=False) as stream:
                path = stream.name
                os.chmod(path, 0o600)
                stream.write(f'create {staging} hash:net family inet maxelem 262144\n')
                for network in networks:
                    # Validate again at the command boundary; source files are data.
                    network = str(ipaddress.IPv4Network(network))
                    stream.write(f'add {staging} {network}\n')
            self._checked(f'ipset restore < {shlex.quote(path)}')
            self._checked(f'ipset swap {staging} {live}')
        finally:
            self.run(f'ipset destroy {staging} 2>/dev/null || true')
            if path:
                Path(path).unlink(missing_ok=True)

    def _add_seed_pool(self, server, values):
        table, _, _, _, _ = self._context(server)
        static = tuple(ipaddress.IPv4Network(network) for network in self._static_networks(server))
        expanded = normalize_service_ip_profile(server['upstream'].get('service_ip_profile')) == 'expanded'
        entries = {}
        for address, expiry in values.items():
            ttl = min(SEED_TTL, int(expiry - time.time()))
            target = ipaddress.IPv4Network(f'{address}/{24 if expanded else 32}', strict=False)
            # In the explicit broad profile, also cover adjacent addresses for
            # hosts outside the provider feeds. Never weaken a permanent range.
            if ttl > 0 and not any(target.subnet_of(network) for network in static):
                entries[str(target)] = max(ttl, entries.get(str(target), 0))
        for network, ttl in entries.items():
            self._checked(f'ipset add awgpool_{table} {network} timeout {ttl} -exist')

    def apply_seed_addresses(self, server, result):
        """Apply a completed refresh under the manager's configuration lock."""
        self._context(server)
        if not isinstance(result, dict) or not isinstance(result.get('addresses'), list):
            raise ValueError('Invalid service resolution result')
        values = self._seed_addresses(server)
        now = time.time()
        for address in result['addresses']:
            validated = _public_ipv4(address)
            if validated is None:
                raise ValueError('Service resolution returned a non-public IPv4 address')
            values[validated] = now + SEED_TTL
        self._add_seed_pool(server, values)
        self._write_json(self._seed_path(server), values)
        previous = self.seed_status(server)
        status = {'last_attempt': now,
                  'last_success': now if result['addresses'] else previous.get('last_success'),
                  'addresses': len(values),
                  'errors': [host for host in result.get('errors', []) if isinstance(host, str)],
                  'resolved_hosts': result.get('resolved_hosts', 0),
                  'queried_hosts': result.get('queried_hosts', 0)}
        self._write_json(self._seed_status_path(server), status)
        return status

    def _configure_pool(self, server):
        table, _, _, _, _ = self._context(server)
        pool = f'awgpool_{table}'
        desired = set(self._static_networks(server))
        self._checked(f'ipset create {pool} hash:net family inet timeout {SEED_TTL} -exist')
        # Keep current dynamic targets, but drop broad seed /24 entries when
        # returning to standard coverage, as well as obsolete custom ranges.
        existing = self.run(f'ipset save {pool}') or ''
        expanded = normalize_service_ip_profile(server['upstream'].get('service_ip_profile')) == 'expanded'
        for line in existing.splitlines():
            fields = line.split()
            if len(fields) < 5 or fields[:2] != ['add', pool] or fields[3] != 'timeout':
                continue
            try:
                network = str(ipaddress.IPv4Network(fields[2], strict=False))
            except ValueError:
                continue
            permanent = fields[4] == '0'
            obsolete = (permanent and network not in desired) or (not permanent and not expanded and '/' in network and not network.endswith('/32'))
            if obsolete:
                self._checked(f'ipset del {pool} {network} -exist')
        for network in sorted(desired):
            self._checked(f'ipset add {pool} {network} timeout 0 -exist')
        self._add_seed_pool(server, self._seed_addresses(server))

    def _save_addresses(self, server):
        table, _, _, _, _ = self._context(server)
        output = self.run(f'ipset save awgsel_{table} 2>/dev/null')
        if output is None:
            # A transient command failure must not replace a useful snapshot.
            return
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
        self._write_json(self._cache_path(server), addresses)

    def save_addresses(self, server):
        """Periodically persist learned DNS targets even without a clean stop."""
        self._save_addresses(server)

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
            *[f'ipset=/{domain}/awgsel_{table}' for domain in AI_TIKTOK_DOMAINS], '',
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
        self._configure_pool(server)
        self.refresh_provider_pool(server)
        self.ensure_dns(server)
        self._checked(f'iptables -t mangle -N {chain} 2>/dev/null || iptables -t mangle -S {chain} >/dev/null')
        rules = [
            f'-m connmark --mark {mark} -j CONNMARK --restore-mark',
            f'-m set --match-set {ipset} dst -j MARK --set-mark {mark}',
            f'-m mark --mark {mark} -j CONNMARK --save-mark',
        ]
        for rule in rules:
            self._checked(f'iptables -t mangle -C {chain} {rule} 2>/dev/null || iptables -t mangle -A {chain} {rule}')
        # Older live chains already have SAVE as their last rule. Insert the
        # new classifier after RESTORE, so its mark is saved for later packets.
        pool_rule = f'-m set --match-set awgpool_{table} dst -j MARK --set-mark {mark}'
        self._checked(f'iptables -t mangle -C {chain} {pool_rule} 2>/dev/null || iptables -t mangle -I {chain} 2 {pool_rule}')
        provider_rule = f'-m set --match-set awgwide_{table} dst -j MARK --set-mark {mark}'
        if normalize_service_ip_profile(server['upstream'].get('service_ip_profile')) == 'expanded':
            self._checked(f'iptables -t mangle -C {chain} {provider_rule} 2>/dev/null || iptables -t mangle -I {chain} 2 {provider_rule}')
        elif f'awgwide_{table}' in existing_sets:
            # Also handle an in-place downgrade without keeping a broad rule.
            self._checked(f'if iptables -t mangle -C {chain} {provider_rule} 2>/dev/null; then iptables -t mangle -D {chain} {provider_rule}; fi')
            self.run(f'ipset destroy awgwide_{table} 2>/dev/null || true')
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
        self.run(f'ipset destroy awgpool_{table} 2>/dev/null || true')
        self.run(f'ipset destroy awgwide_{table} 2>/dev/null || true')
        self.run(f'ipset destroy awgwtmp_{table} 2>/dev/null || true')
        for path in self._paths(table):
            path.unlink(missing_ok=True)
