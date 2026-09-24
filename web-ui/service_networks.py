"""Offline-first, opt-in broad destination networks from fixed public sources.

These providers also host unrelated sites. The expanded profile intentionally
accepts that over-routing to cover clients whose encrypted DNS cannot be seen.
Only this module downloads updates; loading a routing policy never does I/O to
the network. A failed source retains its last successfully validated prefixes.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
from datetime import datetime, timezone
from functools import lru_cache
import html
import io
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import tempfile
import time
import zipfile

import requests


BUNDLED_PATH = Path(__file__).resolve().parent / 'data' / 'expanded_service_networks.json'
CACHE_FILENAME = 'expanded-service-networks.json'
STATUS_FILENAME = 'expanded-service-networks-status.json'
MAX_BODY_BYTES = 32 * 1024 * 1024
MAX_NETWORKS = 50000
MAX_CANDIDATES = 250000
AZURE_DISCOVERY_URL = 'https://www.microsoft.com/en-us/download/details.aspx?id=56519'
_AZURE_DOWNLOAD = re.compile(
    r'https://download\.microsoft\.com/download/[A-Za-z0-9/_-]+/'
    r'ServiceTags_Public_(\d{8})\.json')


# URLs are owned by the application, never taken from user input or the cache.
SOURCE_SPECS = (
    {'id': 'cloudflare', 'name': 'Cloudflare', 'format': 'text',
     'url': 'https://www.cloudflare.com/ips-v4'},
    {'id': 'fastly', 'name': 'Fastly', 'format': 'fastly',
     'url': 'https://api.fastly.com/public-ip-list'},
    {'id': 'aws', 'name': 'Amazon Web Services', 'format': 'aws',
     'url': 'https://ip-ranges.amazonaws.com/ip-ranges.json'},
    {'id': 'google', 'name': 'Google', 'format': 'google',
     'url': 'https://www.gstatic.com/ipranges/goog.json'},
    {'id': 'azure', 'name': 'Microsoft Azure', 'format': 'azure',
     'url': AZURE_DISCOVERY_URL},
    {'id': 'oracle', 'name': 'Oracle Cloud', 'format': 'oracle',
     'url': 'https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json'},
    *({'id': identifier, 'name': name, 'format': 'ripe',
       'url': f'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn}&min_peers_seeing=1'}
      for identifier, name, asn in (
          ('bytedance_as396986', 'ByteDance AS396986', 396986),
          ('bytedance_as138699', 'ByteDance AS138699', 138699),
          ('tiktok_as11983', 'TikTok AS11983', 11983),
          ('akamai_as20940', 'Akamai AS20940', 20940),
          ('akamai_as16625', 'Akamai AS16625', 16625),
          ('cdn77_as60068', 'CDN77 AS60068', 60068),
          ('gcore_as199524', 'Gcore AS199524', 199524),
          ('digitalocean_as14061', 'DigitalOcean AS14061', 14061),
          ('zenlayer_as21859', 'Zenlayer AS21859', 21859))),
    {'id': 'akamai_published', 'name': 'Akamai published ranges', 'format': 'zip_text',
     'url': 'https://techdocs.akamai.com/property-manager/pdfs/akamai_ipv4_ipv6_CIDRs-txt.zip'},
)
_SOURCE_BY_ID = {source['id']: source for source in SOURCE_SPECS}
_NON_PUBLIC_NETWORKS = tuple(ipaddress.IPv4Network(value) for value in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
    '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
    '192.88.99.0/24', '192.168.0.0/16', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4',
))


def normalize_service_ip_profile(value):
    """Old configurations stay on their existing, narrower routing policy."""
    if value is None:
        return 'standard'
    if value not in ('standard', 'expanded'):
        raise ValueError('service_ip_profile must be standard or expanded')
    return value


def _normalize_networks(values, *, allow_ipv6=False):
    if not isinstance(values, (list, tuple)) or len(values) > MAX_CANDIDATES:
        raise ValueError('Invalid or oversized provider network list')
    networks = set()
    for value in values:
        if not isinstance(value, str) or not value or value != value.strip():
            raise ValueError('Provider network must be a CIDR string')
        if '/' not in value or re.search(r'\s', value):
            raise ValueError('Provider network must be a CIDR string')
        network = ipaddress.ip_network(value, strict=False)
        if network.version != 4:
            if allow_ipv6:
                continue
            raise ValueError('Cached provider networks must be IPv4')
        if network.prefixlen < 8 or any(network.overlaps(other) for other in _NON_PUBLIC_NETWORKS):
            raise ValueError('Provider networks must be public IPv4 with prefix /8 or narrower')
        networks.add(network)
        if len(networks) > MAX_NETWORKS:
            raise ValueError('Too many provider networks')
    if not networks:
        raise ValueError('Provider returned no public IPv4 networks')
    # Collapsing adjacent /8s must not turn a validated public list into an
    # entry broader than the validation contract, even if coverage is equal.
    collapsed = []
    for network in ipaddress.collapse_addresses(networks):
        collapsed.extend(network.subnets(new_prefix=8) if network.prefixlen < 8 else [network])
    return [str(network) for network in collapsed]


def _union(sources):
    return _normalize_networks([network for source in sources for network in source['ipv4_networks']])


def _validate_source(source):
    if not isinstance(source, dict):
        raise ValueError('Invalid source entry')
    spec = _SOURCE_BY_ID.get(source.get('id'))
    if spec is None or source.get('format') != spec['format']:
        raise ValueError('Unknown provider source')
    url = source.get('url')
    if not isinstance(url, str) or (not _AZURE_DOWNLOAD.fullmatch(url) if spec['id'] == 'azure'
                                    else url != spec['url']):
        raise ValueError('Untrusted provider source URL')
    networks = _normalize_networks(source.get('ipv4_networks'))
    result = dict(spec, url=url, ipv4_networks=networks)
    for field in ('retrieved_at', 'source_updated_at'):
        value = source.get(field)
        if value is not None:
            if not isinstance(value, str) or len(value) > 128:
                raise ValueError('Invalid provider source timestamp')
            result[field] = value
    if spec['id'] == 'azure':
        result['discovery_url'] = AZURE_DISCOVERY_URL
    return result


def _validate_snapshot(payload):
    if not isinstance(payload, dict) or payload.get('schema_version') != 1:
        raise ValueError('Invalid network cache schema')
    sources = payload.get('sources')
    if not isinstance(sources, list) or not sources or len(sources) > len(SOURCE_SPECS):
        raise ValueError('Invalid network cache sources')
    validated = [_validate_source(source) for source in sources]
    if len({source['id'] for source in validated}) != len(validated):
        raise ValueError('Duplicate provider source')
    networks = _union(validated)
    if _normalize_networks(payload.get('ipv4_networks')) != networks:
        raise ValueError('Cached network union does not match its sources')
    return {'schema_version': 1, 'generated_at': payload.get('generated_at'),
            'sources': validated, 'ipv4_networks': networks}


@lru_cache(maxsize=16)
def _read_snapshot_cached(path, modified_ns, size):
    del modified_ns
    if size > MAX_BODY_BYTES:
        raise ValueError('Oversized network cache')
    with open(path, 'rb') as handle:
        body = handle.read(MAX_BODY_BYTES + 1)
    if len(body) > MAX_BODY_BYTES:
        raise ValueError('Oversized network cache')
    return _validate_snapshot(json.loads(body))


def _read_snapshot(path):
    info = path.stat()
    return _read_snapshot_cached(str(path.resolve()), info.st_mtime_ns, info.st_size)


def _effective_snapshot(state_dir=None):
    baseline = _read_snapshot(BUNDLED_PATH)
    if state_dir is None:
        return baseline
    try:
        cached = _read_snapshot(Path(state_dir) / CACHE_FILENAME)
    except (OSError, ValueError, TypeError, KeyError):
        return baseline
    # A valid older cache can predate a newly bundled provider. Introduce new
    # sources immediately while keeping updates already fetched for old ones.
    sources = {source['id']: source for source in baseline['sources']}
    sources.update({source['id']: source for source in cached['sources']})
    if len(sources) == len(cached['sources']):
        return cached
    return dict(cached, sources=list(sources.values()), ipv4_networks=_union(sources.values()))


def load_expanded_networks(state_dir=None):
    """Return validated ranges instantly, including when all providers are down."""
    return list(_effective_snapshot(state_dir)['ipv4_networks'])


def _fetch_bytes(url):
    """A per-read timeout, wall deadline and body cap bound trusted downloads."""
    deadline = time.monotonic() + 30
    with requests.get(url, timeout=(3, 10), stream=True, allow_redirects=False) as response:
        if not 200 <= response.status_code < 300:
            raise ValueError('Provider download failed')
        length = response.headers.get('Content-Length')
        if length and int(length) > MAX_BODY_BYTES:
            raise ValueError('Provider response too large')
        body = bytearray()
        for chunk in response.iter_content(chunk_size=65536):
            if time.monotonic() > deadline or len(body) + len(chunk) > MAX_BODY_BYTES:
                raise ValueError('Provider download exceeded its limit')
            body.extend(chunk)
    return bytes(body)


def _body_bytes(value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    if not isinstance(value, bytes) or len(value) > MAX_BODY_BYTES:
        raise ValueError('Invalid or oversized provider response')
    return value


def _parse_networks(body, source_format):
    body = _body_bytes(body)
    if source_format == 'zip_text':
        values, total = [], 0
        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            entries = [entry for entry in archive.infolist() if not entry.is_dir()
                       and not entry.filename.startswith('__MACOSX/')]
            if not entries or len(entries) > 20:
                raise ValueError('Invalid provider archive')
            for entry in entries:
                total += entry.file_size
                if total > MAX_BODY_BYTES or not entry.filename.lower().endswith('.txt'):
                    raise ValueError('Invalid or oversized provider archive')
                content = archive.read(entry).decode('utf-8-sig')
                values.extend(re.findall(r'(?<![\w.:])(?:[0-9A-Fa-f.:]+)/(?:\d+)(?!\w)', content))
    else:
        content = body.decode('utf-8-sig')
        if source_format == 'text':
            values = [line.strip() for line in content.splitlines() if line.strip()]
        elif source_format == 'csv':
            values = [row[0].strip() for row in csv.reader(io.StringIO(content)) if row and row[0].strip()]
            if values and values[0].lower() in ('network', 'prefix', 'ip_prefix'):
                values.pop(0)
        else:
            payload = json.loads(content)
            if source_format == 'fastly':
                values = payload['addresses']
            elif source_format == 'aws':
                values = [entry['ip_prefix'] for entry in payload['prefixes']]
            elif source_format == 'google':
                values = [entry['ipv4Prefix'] for entry in payload['prefixes'] if 'ipv4Prefix' in entry]
            elif source_format == 'azure':
                values = [prefix for entry in payload['values'] if entry['name'] == 'AzureCloud'
                          for prefix in entry['properties']['addressPrefixes']]
            elif source_format == 'oracle':
                values = [entry['cidr'] for region in payload['regions'] for entry in region['cidrs']]
            elif source_format == 'ripe':
                if payload.get('status') not in (None, 'ok'):
                    raise ValueError('RIPE query failed')
                values = [entry['prefix'] for entry in payload['data']['prefixes']]
            else:
                raise ValueError('Unknown provider format')
    return _normalize_networks(values, allow_ipv6=True)


def _refresh_source(spec, fetcher, timestamp):
    url = spec['url']
    if spec['id'] == 'azure':
        page = html.unescape(_body_bytes(fetcher(AZURE_DISCOVERY_URL)).decode('utf-8'))
        matches = list(_AZURE_DOWNLOAD.finditer(page))
        if not matches:
            raise ValueError('Azure published feed URL not found')
        url = max(matches, key=lambda match: match.group(1)).group(0)
    networks = _parse_networks(fetcher(url), spec['format'])
    return _validate_source(dict(spec, url=url, ipv4_networks=networks, retrieved_at=timestamp))


def _atomic_json(path, payload):
    path.parent.mkdir(parents=True, exist_ok=True)
    filename = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=path.parent,
                                         prefix=path.name + '.', suffix='.tmp', delete=False) as handle:
            filename = handle.name
            json.dump(payload, handle, sort_keys=True, separators=(',', ':'))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(filename, path)
    finally:
        if filename and os.path.exists(filename):
            os.unlink(filename)


def _timestamp(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and value >= 0 else None


def expanded_network_status(state_dir=None):
    status = {'networks': len(load_expanded_networks(state_dir)), 'last_attempt': None,
              'last_success': None, 'errors': 0}
    if state_dir is None:
        return status
    try:
        path = Path(state_dir) / STATUS_FILENAME
        if path.stat().st_size > 4096:
            return status
        saved = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(saved, dict):
            return status
        status['last_attempt'] = _timestamp(saved.get('last_attempt'))
        status['last_success'] = _timestamp(saved.get('last_success'))
        errors = saved.get('errors')
        if isinstance(errors, int) and not isinstance(errors, bool) and 0 <= errors <= len(SOURCE_SPECS):
            status['errors'] = errors
    except (OSError, ValueError, TypeError):
        pass
    return status


def refresh_expanded_networks(state_dir, fetcher=None):
    """Refresh fixed providers outside the caller's configuration lock.

    ``fetcher(url)`` may be injected for deterministic tests and returns bytes or
    text. Every provider is independent: failure keeps that source's old data.
    """
    if state_dir is None:
        raise ValueError('A persistent directory is required for network refresh')
    previous = _effective_snapshot(state_dir)
    previous_status = expanded_network_status(state_dir)
    sources = {source['id']: source for source in previous['sources']}
    now = time.time()
    timestamp = datetime.fromtimestamp(now, timezone.utc).isoformat().replace('+00:00', 'Z')
    fetcher = fetcher or _fetch_bytes
    errors, refreshed = 0, 0
    with ThreadPoolExecutor(max_workers=4) as executor:
        pending = {executor.submit(_refresh_source, spec, fetcher, timestamp): spec['id']
                   for spec in SOURCE_SPECS}
        for future in as_completed(pending):
            try:
                source = future.result()
                sources[source['id']] = source
                refreshed += 1
            except Exception:
                errors += 1
    snapshot = {'schema_version': 1, 'generated_at': timestamp,
                'sources': sorted(sources.values(), key=lambda source: source['id'])}
    snapshot['ipv4_networks'] = _union(snapshot['sources'])
    status = {'networks': len(snapshot['ipv4_networks']), 'last_attempt': now,
              'last_success': now if refreshed else previous_status['last_success'], 'errors': errors}
    directory = Path(state_dir)
    _atomic_json(directory / CACHE_FILENAME, snapshot)
    _atomic_json(directory / STATUS_FILENAME, status)
    return status
