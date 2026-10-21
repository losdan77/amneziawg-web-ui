"""Service-specific domain rules for the optional transparent routing mode.

The bundled GeoSite source snapshot is MIT-licensed and works offline. We keep
suffix, exact-host and regular-expression rules distinct: flattening them into
IP sets would reintroduce the shared-CDN ambiguity this mode avoids.
"""
from functools import lru_cache
import ipaddress
import json
from pathlib import Path
import re


DATA_PATH = Path(__file__).resolve().parent / 'data' / 'service_domains'
CATALOG_REVISION = '275abb3bfb908a7883f1e839a62424e6cd8cd184'
CATALOG_DATE = '2026-10-20'
DEFAULT_SELECTED_SERVICES = ('chatgpt', 'codex', 'claude', 'tiktok')
# Keep missing selections backward compatible when adding opt-in services.
SELECTABLE_SERVICE_IDS = (*DEFAULT_SELECTED_SERVICES, 'strava')
SERVICE_LABELS = {
    'chatgpt': 'ChatGPT', 'codex': 'Codex', 'claude': 'Claude', 'tiktok': 'TikTok',
    'strava': 'Strava',
}
_SERVICE_GROUPS = {
    'chatgpt': 'openai', 'codex': 'openai', 'claude': 'anthropic', 'tiktok': 'tiktok',
    'strava': 'strava',
}
_RULE_KINDS = ('domain_suffix', 'domain', 'domain_regex')
_DOMAIN_LABEL = re.compile(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z')
# These distinct products occur in the upstream OpenAI category, but are not
# selected here. Shared openai.com/chatgpt.com endpoints remain inseparable.
_OPENAI_EXCLUDED_SUFFIXES = frozenset(('sora.com', 'crixet.com'))
# Exact authentication/static dependencies from OpenAI's published network
# allowlist. Avoid wildcard cloudflare.net, workos.com, Google or Azure rules.
_OPENAI_DEPENDENCIES = (
    'cdn.openaimerge.com', 'cdn.workos.com', 'challenges.cloudflare.com',
    'forwarder.workos.com', 'frontend-apps-multi-region.workos.com',
    'images.workoscdn.com', 'setup.workos.com', 'workos.imgix.net',
    'humb.apple.com', 'register.appattest.apple.com',
)


def normalize_selected_services(value):
    """Validate saved/API selection; None is the new mode's default, [] is local."""
    if value is None:
        return list(DEFAULT_SELECTED_SERVICES)
    if not isinstance(value, list):
        raise ValueError('Selected services must be a list of service identifiers')
    result = []
    for service in value:
        if not isinstance(service, str) or service not in _SERVICE_GROUPS:
            raise ValueError('Unknown selected service; use ' + ', '.join(SELECTABLE_SERVICE_IDS))
        if service not in result:
            result.append(service)
    return result


def _hostname(value):
    if not isinstance(value, str) or not value:
        return None
    try:
        hostname = value.rstrip('.').encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        return None
    if len(hostname) > 253 or not all(_DOMAIN_LABEL.fullmatch(part)
                                    for part in hostname.split('.')):
        return None
    return hostname


def _parse_geosite(text):
    """Parse the finite supported GeoSite source syntax; never broaden unknowns."""
    rules = {kind: [] for kind in _RULE_KINDS}
    for original in text.splitlines():
        line = original.split('#', 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if '@ads' in parts[1:]:
            continue
        item = parts[0]
        if item.startswith('regexp:'):
            value, kind = item[7:], 'domain_regex'
            re.compile(value)
        else:
            kind = 'domain' if item.startswith('full:') else 'domain_suffix'
            if item.startswith(('full:', 'domain:')):
                item = item.split(':', 1)[1]
            value = _hostname(item)
            if value is None:
                raise ValueError('Unsupported or invalid bundled GeoSite rule: ' + item)
        if value not in rules[kind]:
            rules[kind].append(value)
    return tuple(tuple(rules[kind]) for kind in _RULE_KINDS)


@lru_cache(maxsize=5)
def _catalog(group):
    if group not in ('openai', 'anthropic', 'tiktok', 'strava', 'youtube'):
        raise ValueError('Unknown bundled service catalog')
    result = _parse_geosite((DATA_PATH / (group + '.txt')).read_text(encoding='utf-8'))
    if group == 'openai':
        result = (
            tuple(rule for rule in result[0] if rule not in _OPENAI_EXCLUDED_SUFFIXES),
            tuple(dict.fromkeys((*result[1], *_OPENAI_DEPENDENCIES))),
            result[2],
        )
    return result


def _merge_groups(groups):
    result = {kind: [] for kind in _RULE_KINDS}
    for group in dict.fromkeys(groups):
        for kind, values in zip(_RULE_KINDS, _catalog(group)):
            result[kind].extend(value for value in values if value not in result[kind])
    return result


def _selection(upstream):
    if not isinstance(upstream, dict):
        raise ValueError('Upstream configuration must be an object')
    return normalize_selected_services(upstream.get('selected_services'))


def selected_service_rules(upstream):
    """Return fresh sing-box domain rule lists for the chosen service groups."""
    return _merge_groups(_SERVICE_GROUPS[service] for service in _selection(upstream))


def selected_domain_suffixes(ids):
    """Suffix-only view; exact and regexp rules require selected_service_rules."""
    return selected_service_rules({'selected_services': ids})['domain_suffix']


def _xray_rules(rules):
    return (['domain:' + value for value in rules['domain_suffix']]
            + ['full:' + value for value in rules['domain']]
            + ['regexp:' + value for value in rules['domain_regex']])


def selected_domain_rules(upstream):
    """Equivalent Xray rules for VLESS entries using the same service selection."""
    return _xray_rules(selected_service_rules(upstream))


def youtube_service_rules():
    """YouTube is always local and must be matched before tunnel rules."""
    return _merge_groups(('youtube',))


def youtube_domain_rules():
    return _xray_rules(youtube_service_rules())


YOUTUBE_DOMAINS = tuple(youtube_service_rules()['domain_suffix'])


def _matches(rules, hostname):
    return (hostname in rules['domain']
            or any(hostname == suffix or hostname.endswith('.' + suffix)
                   for suffix in rules['domain_suffix'])
            or any(re.search(pattern, hostname) for pattern in rules['domain_regex']))


def selected_domain_matches(upstream, hostname):
    """Domain-only diagnostic prediction, including the YouTube local override.

This does not claim a live connection exposed a domain to the proxy. Encrypted
DNS plus ECH can hide it; the engine's connection logs are the runtime evidence.
"""
    rules = selected_service_rules(upstream)
    hostname = _hostname(hostname)
    return bool(hostname and not _matches(youtube_service_rules(), hostname)
                and _matches(rules, hostname))


@lru_cache(maxsize=1)
def _voice_networks():
    document = json.loads((DATA_PATH / 'chatgpt-voice.json').read_text(encoding='utf-8'))
    networks = []
    for record in document['prefixes']:
        network = ipaddress.ip_network(record['ipv4Prefix'], strict=True)
        if network.version != 4 or network.prefixlen != 32 or not network.is_global:
            raise ValueError('ChatGPT Voice fallback must contain public individual IPv4 hosts')
        if str(network) not in networks:
            networks.append(str(network))
    if not networks:
        raise ValueError('Empty ChatGPT Voice host list')
    return tuple(networks)


def chatgpt_voice_rules(upstream):
    """Raw STUN needs a narrow IP+port match because it has no hostname."""
    if 'chatgpt' not in _selection(upstream):
        return {}
    return {'ip_cidr': list(_voice_networks()), 'port': [3478], 'network': 'udp'}
