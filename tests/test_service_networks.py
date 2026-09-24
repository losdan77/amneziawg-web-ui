"""Trusted broad-network feeds, offline startup and partial update recovery."""
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-ui'))
import service_networks as networks


class ExpandedNetworkTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        self.specs = tuple(source for source in networks.SOURCE_SPECS
                           if source['id'] in ('cloudflare', 'fastly'))
        self.baseline = self.snapshot([
            dict(self.specs[0], ipv4_networks=['104.16.0.0/13']),
            dict(self.specs[1], ipv4_networks=['151.101.0.0/16']),
        ])
        self.baseline_path = self.path / 'baseline.json'
        self.baseline_path.write_text(json.dumps(self.baseline), encoding='utf-8')
        self.addCleanup(patch.stopall)
        patch.object(networks, 'BUNDLED_PATH', self.baseline_path).start()
        patch.object(networks, 'SOURCE_SPECS', self.specs).start()

    @staticmethod
    def snapshot(sources):
        return {'schema_version': 1, 'generated_at': '2026-09-24T00:00:00Z',
                'sources': sources, 'ipv4_networks': networks._union(sources)}

    def write_cache(self, value):
        (self.path / networks.CACHE_FILENAME).write_text(json.dumps(value), encoding='utf-8')

    def test_profile_defaults_preserve_old_configs_and_reject_unknown_values(self):
        self.assertEqual(networks.normalize_service_ip_profile(None), 'standard')
        for value in ('standard', 'expanded'):
            self.assertEqual(networks.normalize_service_ip_profile(value), value)
        for value in ('all', '', 'EXPANDED', {}, ['expanded'], 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                networks.normalize_service_ip_profile(value)

    def test_offline_startup_uses_bundled_networks_without_any_request(self):
        with patch.object(networks.requests, 'get', side_effect=AssertionError('network called')):
            self.assertEqual(networks.load_expanded_networks(self.path),
                             ['104.16.0.0/13', '151.101.0.0/16'])
            self.assertEqual(networks.expanded_network_status(self.path), {
                'networks': 2, 'last_attempt': None, 'last_success': None, 'errors': 0})

    def test_valid_cache_supersedes_old_source_but_keeps_new_bundled_sources(self):
        self.write_cache(self.snapshot([dict(self.specs[0], ipv4_networks=['8.8.8.0/24'])]))
        self.assertEqual(networks.load_expanded_networks(self.path), ['8.8.8.0/24', '151.101.0.0/16'])

    def test_corrupt_or_untrusted_cache_falls_back_without_following_its_url(self):
        for mutate in (
            lambda value: value.update(schema_version=2),
            lambda value: value['sources'][0].update(url='http://169.254.169.254/metadata'),
            lambda value: value['sources'][0].update(id='untrusted'),
            lambda value: value['sources'][0].update(format='ripe'),
            lambda value: value.update(ipv4_networks=['0.0.0.0/0']),
            lambda value: value.update(ipv4_networks=['8.8.8.0/24']),
            lambda value: value['sources'].append(value['sources'][0]),
        ):
            value = json.loads(json.dumps(self.baseline))
            mutate(value)
            self.write_cache(value)
            with patch.object(networks.requests, 'get', side_effect=AssertionError('network called')):
                self.assertEqual(networks.load_expanded_networks(self.path), self.baseline['ipv4_networks'])
        (self.path / networks.CACHE_FILENAME).write_text('{incomplete', encoding='utf-8')
        self.assertEqual(networks.load_expanded_networks(self.path), self.baseline['ipv4_networks'])

    def test_partial_refresh_retains_failed_source_then_all_failure_keeps_last_success(self):
        def partial(url):
            if url == self.specs[0]['url']:
                return '8.8.8.0/25\n8.8.8.128/25\n'
            raise TimeoutError('temporarily unavailable')
        with patch.object(networks.time, 'time', return_value=1000):
            result = networks.refresh_expanded_networks(self.path, partial)
        self.assertEqual(result, {'networks': 2, 'last_attempt': 1000, 'last_success': 1000, 'errors': 1})
        self.assertEqual(networks.load_expanded_networks(self.path), ['8.8.8.0/24', '151.101.0.0/16'])
        with patch.object(networks.time, 'time', return_value=2000):
            result = networks.refresh_expanded_networks(self.path, Mock(side_effect=TimeoutError))
        self.assertEqual(result, {'networks': 2, 'last_attempt': 2000, 'last_success': 1000, 'errors': 2})
        self.assertEqual(networks.expanded_network_status(self.path), result)
        self.assertEqual(networks.load_expanded_networks(self.path), ['8.8.8.0/24', '151.101.0.0/16'])
        self.assertEqual(list(self.path.glob('*.tmp')), [])

    def test_empty_and_malformed_downloads_never_replace_existing_networks(self):
        for body in ('', '203.0.113.0/24', '0.0.0.0/0', 'not a network', '[]', '{}'):
            with self.subTest(body=body):
                result = networks.refresh_expanded_networks(self.path, lambda _: body)
                self.assertEqual(result['errors'], 2)
                self.assertIsNone(result['last_success'])
                self.assertEqual(networks.load_expanded_networks(self.path), self.baseline['ipv4_networks'])

    def test_failed_atomic_replace_keeps_old_snapshot_and_cleans_temporary_file(self):
        self.write_cache(self.baseline)
        before = (self.path / networks.CACHE_FILENAME).read_bytes()
        with patch.object(networks.os, 'replace', side_effect=OSError('disk unavailable')):
            with self.assertRaises(OSError):
                networks.refresh_expanded_networks(self.path, Mock(side_effect=TimeoutError))
        self.assertEqual((self.path / networks.CACHE_FILENAME).read_bytes(), before)
        self.assertEqual(list(self.path.glob('*.tmp')), [])

    def test_memory_cache_invalidates_after_atomic_snapshot_replacement(self):
        self.assertEqual(networks.load_expanded_networks(self.path), self.baseline['ipv4_networks'])
        replacement = self.snapshot([dict(self.specs[0], ipv4_networks=['9.9.9.0/24'])])
        networks._atomic_json(self.path / networks.CACHE_FILENAME, replacement)
        result = networks.load_expanded_networks(self.path)
        self.assertIn('9.9.9.0/24', result)
        result.clear()
        self.assertIn('9.9.9.0/24', networks.load_expanded_networks(self.path))

    def test_status_ignores_corrupt_negative_or_nonfinite_fields(self):
        status_path = self.path / networks.STATUS_FILENAME
        for value in ('bad json', json.dumps({'last_attempt': -1, 'last_success': float('nan'), 'errors': 999}), '[]'):
            status_path.write_text(value, encoding='utf-8')
            self.assertEqual(networks.expanded_network_status(self.path), {
                'networks': 2, 'last_attempt': None, 'last_success': None, 'errors': 0})


class ProviderParserTests(unittest.TestCase):
    def test_each_json_feed_extracts_only_relevant_ipv4_networks(self):
        cases = {
            'fastly': {'addresses': ['8.8.8.0/24'], 'ipv6_addresses': ['2001:4860::/32']},
            'aws': {'prefixes': [{'ip_prefix': '8.8.8.0/24'}], 'ipv6_prefixes': []},
            'google': {'prefixes': [{'ipv4Prefix': '8.8.8.0/24'}, {'ipv6Prefix': '2001:4860::/32'}]},
            'azure': {'values': [{'name': 'AzureCloud', 'properties': {'addressPrefixes': ['8.8.8.0/24', '2001:4860::/32']}},
                                  {'name': 'OtherService', 'properties': {'addressPrefixes': ['9.9.9.0/24']}}]},
            'oracle': {'regions': [{'cidrs': [{'cidr': '8.8.8.0/24'}]}]},
            'ripe': {'status': 'ok', 'data': {'prefixes': [{'prefix': '8.8.8.0/24'}, {'prefix': '2001:4860::/32'}]}},
        }
        for kind, value in cases.items():
            with self.subTest(kind=kind):
                self.assertEqual(networks._parse_networks(json.dumps(value), kind), ['8.8.8.0/24'])
        self.assertEqual(networks._parse_networks('8.8.8.0/25\n8.8.8.128/25\n', 'text'), ['8.8.8.0/24'])
        self.assertEqual(networks._parse_networks('prefix,country\n8.8.8.0/24,US\n', 'csv'), ['8.8.8.0/24'])

    def test_public_networks_reject_private_bogons_and_broad_ranges(self):
        for value in ('0.0.0.0/0', '8.0.0.0/7', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
                      '169.254.0.0/16', '172.16.0.0/12', '192.168.0.0/16', '192.0.2.0/24',
                      '198.18.0.0/15', '224.0.0.0/4', '240.0.0.0/4', '8.8.8.8', ' 8.8.8.0/24'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                networks._normalize_networks([value])
        self.assertEqual(networks._normalize_networks(['8.0.0.0/8', '9.0.0.0/8']),
                         ['8.0.0.0/8', '9.0.0.0/8'])

    def test_response_and_network_count_bounds_apply_before_persistence(self):
        with patch.object(networks, 'MAX_BODY_BYTES', 8), self.assertRaises(ValueError):
            networks._parse_networks(b'8.8.8.0/24', 'text')
        with patch.object(networks, 'MAX_NETWORKS', 1), self.assertRaises(ValueError):
            networks._normalize_networks(['8.8.8.0/24', '9.9.9.0/24'])
        with patch.object(networks, 'MAX_CANDIDATES', 1), self.assertRaises(ValueError):
            networks._normalize_networks(['8.8.8.0/24', '8.8.8.0/24'])

    def test_akamai_archive_ignores_mac_metadata_and_filters_ipv6(self):
        body = io.BytesIO()
        with zipfile.ZipFile(body, 'w') as archive:
            archive.writestr('akamai_ipv4_CIDRs.txt', '8.8.8.0/24\n')
            archive.writestr('akamai_ipv6_CIDRs.txt', '2001:4860::/32\n')
            archive.writestr('__MACOSX/._akamai_ipv4_CIDRs.txt', b'\xffmetadata')
        self.assertEqual(networks._parse_networks(body.getvalue(), 'zip_text'), ['8.8.8.0/24'])
        with patch.object(networks, 'MAX_BODY_BYTES', len(body.getvalue()) - 1), self.assertRaises(ValueError):
            networks._parse_networks(body.getvalue(), 'zip_text')

    def test_azure_discovery_uses_only_latest_trusted_download_url(self):
        spec = next(source for source in networks.SOURCE_SPECS if source['id'] == 'azure')
        older = 'https://download.microsoft.com/download/a/b/c/ServiceTags_Public_20260914.json'
        latest = 'https://download.microsoft.com/download/a/b/c/ServiceTags_Public_20260921.json'
        calls = []
        def fetch(url):
            calls.append(url)
            if url == networks.AZURE_DISCOVERY_URL:
                return f'<a href="{older}">old</a><a href="{latest}">latest</a>'
            return json.dumps({'values': [{'name': 'AzureCloud', 'properties': {'addressPrefixes': ['8.8.8.0/24']}}]})
        source = networks._refresh_source(spec, fetch, '2026-09-24T00:00:00Z')
        self.assertEqual(source['url'], latest)
        self.assertEqual(calls, [networks.AZURE_DISCOVERY_URL, latest])
        for url in ('http://download.microsoft.com/download/a/ServiceTags_Public_20260921.json',
                    'https://download.microsoft.com.evil.example/download/a/ServiceTags_Public_20260921.json',
                    'https://127.0.0.1/download/a/ServiceTags_Public_20260921.json'):
            with self.subTest(url=url), self.assertRaises(ValueError):
                networks._refresh_source(spec, lambda _: url, '2026-09-24T00:00:00Z')

    def test_download_disables_redirects_and_bounds_timeout_and_response_size(self):
        response = Mock(status_code=200, headers={})
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.iter_content.return_value = [b'8.8.8.0/24\n']
        with patch.object(networks.requests, 'get', return_value=response) as get:
            self.assertEqual(networks._fetch_bytes('https://www.cloudflare.com/ips-v4'), b'8.8.8.0/24\n')
        self.assertEqual(get.call_args.kwargs, {'timeout': (3, 10), 'stream': True, 'allow_redirects': False})
        response.status_code = 302
        with patch.object(networks.requests, 'get', return_value=response), self.assertRaises(ValueError):
            networks._fetch_bytes('https://www.cloudflare.com/ips-v4')
        response.status_code = 200
        response.headers = {'Content-Length': str(networks.MAX_BODY_BYTES + 1)}
        with patch.object(networks.requests, 'get', return_value=response), self.assertRaises(ValueError):
            networks._fetch_bytes('https://www.cloudflare.com/ips-v4')

    def test_real_bundled_snapshot_covers_core_clouds_without_including_private_ranges(self):
        values = networks.load_expanded_networks()
        self.assertGreater(len(values), 1000)
        sources = networks._read_snapshot(networks.BUNDLED_PATH)['sources']
        self.assertEqual({source['id'] for source in sources}, {source['id'] for source in networks.SOURCE_SPECS})
        self.assertEqual(values, networks._normalize_networks(values))


if __name__ == '__main__':
    unittest.main()
