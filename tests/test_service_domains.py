"""Service catalog selection and domain boundaries for transparent routing."""
import ipaddress
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-ui'))
import service_domains as domains


class ServiceDomainTests(unittest.TestCase):
    def test_default_empty_deduplicated_and_invalid_selections(self):
        self.assertEqual(domains.normalize_selected_services(None),
                         ['chatgpt', 'codex', 'claude', 'tiktok'])
        self.assertEqual(domains.normalize_selected_services([]), [])
        self.assertEqual(domains.normalize_selected_services(['claude', 'tiktok', 'claude']),
                         ['claude', 'tiktok'])
        for value in ('claude', ('claude',), {}, False, 1, ['youtube'],
                      ['CLAUDE'], ['claude', {}], [None]):
            with self.subTest(value=value), self.assertRaises(ValueError):
                domains.normalize_selected_services(value)

    def test_selected_services_route_only_their_domains(self):
        upstream = {'selected_services': ['claude']}
        for host in ('claude.ai', 'api.anthropic.com', 'www.claude.com',
                     'asset.claudeusercontent.com', 'sandbox.claudemcpcontent.com'):
            with self.subTest(host=host):
                self.assertTrue(domains.selected_domain_matches(upstream, host))
        for host in ('chatgpt.com', 'www.tiktok.com', 'example.org'):
            with self.subTest(host=host):
                self.assertFalse(domains.selected_domain_matches(upstream, host))
        self.assertFalse(domains.selected_domain_matches({'selected_services': []}, 'claude.ai'))

    def test_chatgpt_mobile_and_codex_share_the_openai_catalog(self):
        for selection in (['chatgpt'], ['codex']):
            for host in ('android.chat.openai.com', 'ios.chat.openai.com',
                         'chatgpt.com', 'ws.chatgpt.com', 'auth.openai.com',
                         'files.oaiusercontent.com', 'api.openai.com'):
                with self.subTest(selection=selection, host=host):
                    self.assertTrue(domains.selected_domain_matches(
                        {'selected_services': selection}, host))
        self.assertEqual(domains.selected_service_rules({'selected_services': ['chatgpt']}),
                         domains.selected_service_rules({'selected_services': ['codex']}))

    def test_youtube_video_mobile_and_country_domains_stay_local(self):
        for host in ('youtube.com', 'm.youtube.com', 'youtube.co.uk',
                     'youtubei.googleapis.com', 'r1---sn-example.googlevideo.com',
                     'i.ytimg.com', 'yt3.googleusercontent.com', 'youtu.be'):
            with self.subTest(host=host):
                self.assertTrue(domains._matches(domains.youtube_service_rules(), host))
                self.assertFalse(domains.selected_domain_matches({}, host))

    def test_youtube_override_wins_even_if_a_service_catalog_overlaps(self):
        overlapping = {'domain_suffix': ['googlevideo.com'], 'domain': [], 'domain_regex': []}
        with patch.object(domains, 'selected_service_rules', return_value=overlapping):
            self.assertFalse(domains.selected_domain_matches({}, 'video.googlevideo.com'))

    def test_no_cloud_provider_wildcards_or_other_openai_products(self):
        for host in ('www.google.com', 'storage.googleapis.com', 'cloudflare.com',
                     'unrelated.azureedge.net', 'unrelated.blob.core.windows.net',
                     'other.akamaized.net', 'tenant.workos.com', 'sora.com', 'crixet.com'):
            with self.subTest(host=host):
                self.assertFalse(domains.selected_domain_matches({}, host))

    def test_tiktok_media_domains_and_exact_shared_cdn_tenants(self):
        for host in ('www.tiktok.com', 'api.tiktokv.com', 'video.tiktokcdn-eu.com',
                     'video.tiktokcdn-us.com', 'v.tiktokcdn.com.akamaized.net',
                     'p16-tiktok-dm-sticker-sign-sg.ibyteimg.com'):
            with self.subTest(host=host):
                self.assertTrue(domains.selected_domain_matches({'selected_services': ['tiktok']}, host))
        self.assertFalse(domains.selected_domain_matches({}, 'random.ibyteimg.com'))

    def test_strava_is_opt_in_and_does_not_capture_shared_cdn_neighbors(self):
        upstream = {'selected_services': ['strava']}
        self.assertEqual(domains.normalize_selected_services(['strava', 'strava']), ['strava'])
        for host in ('strava.com', 'www.strava.com', 'api.strava.com',
                     'web-assets.strava.com', 'd21y75miwcfqoq.cloudfront.net',
                     'd3nn82uaxijpm6.cloudfront.net'):
            with self.subTest(host=host):
                self.assertTrue(domains.selected_domain_matches(upstream, host))
                self.assertFalse(domains.selected_domain_matches({}, host))
                self.assertFalse(domains.selected_domain_matches({'selected_services': []}, host))
        for host in ('notstrava.com', 'strava.com.evil.test',
                     'sub.d21y75miwcfqoq.cloudfront.net',
                     'd21y75miwcfqoq.cloudfront.net.evil.test',
                     'other.cloudfront.net', 'youtube.com', 'video.googlevideo.com',
                     'accounts.google.com', 'chatgpt.com'):
            with self.subTest(host=host):
                self.assertFalse(domains.selected_domain_matches(upstream, host))
        rules = domains.selected_domain_rules(upstream)
        self.assertIn('domain:strava.com', rules)
        self.assertIn('full:d21y75miwcfqoq.cloudfront.net', rules)
        self.assertNotIn('domain:cloudfront.net', rules)

    def test_exact_hosts_suffix_boundaries_and_regex_are_preserved(self):
        self.assertTrue(domains.selected_domain_matches({}, 'chatgpt-async-webps-prod-east-1.webpubsub.azure.com'))
        self.assertFalse(domains.selected_domain_matches({}, 'chatgpt-async-webps-prod-east-1.webpubsub.azure.com.evil.test'))
        self.assertTrue(domains.selected_domain_matches({}, 'openaiassets.blob.core.windows.net'))
        self.assertFalse(domains.selected_domain_matches({}, 'sub.openaiassets.blob.core.windows.net'))
        self.assertTrue(domains.selected_domain_matches({}, 'API.ANTHROPIC.COM.'))
        for host in ('notclaude.ai', 'claude.ai.evil.test', 'https://claude.ai', '', None):
            with self.subTest(host=host):
                self.assertFalse(domains.selected_domain_matches({}, host))
        rules = domains.selected_domain_rules({})
        self.assertIn('domain:claude.ai', rules)
        self.assertIn('full:openaiassets.blob.core.windows.net', rules)
        self.assertTrue(any(rule.startswith('regexp:^chatgpt-async-') for rule in rules))

    def test_returned_lists_do_not_mutate_catalog_or_other_requests(self):
        first = domains.selected_service_rules({})
        first['domain_suffix'].append('evil.test')
        self.assertFalse(domains.selected_domain_matches({}, 'evil.test'))
        local = domains.youtube_service_rules()
        local['domain_suffix'].clear()
        self.assertIn('googlevideo.com', domains.youtube_service_rules()['domain_suffix'])

    def test_parser_never_widens_unsupported_source_syntax(self):
        parsed = domains._parse_geosite('example.com @!cn\nfull:cdn.example.net\n# ignored\ntracker.net @ads')
        self.assertEqual(parsed, (('example.com',), ('cdn.example.net',), ()))
        for text in ('include:other-service', 'keyword:openai', '8.8.8.0/24', 'https://example.com'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                domains._parse_geosite(text)

    def test_voice_only_uses_individual_public_hosts_on_udp3478(self):
        rule = domains.chatgpt_voice_rules({'selected_services': ['chatgpt']})
        self.assertEqual(rule['port'], [3478])
        self.assertEqual(rule['network'], 'udp')
        self.assertGreater(len(rule['ip_cidr']), 0)
        for value in rule['ip_cidr']:
            network = ipaddress.ip_network(value)
            self.assertEqual(network.prefixlen, 32)
            self.assertTrue(network.is_global)
        self.assertEqual(domains.chatgpt_voice_rules({'selected_services': ['codex']}), {})
        self.assertEqual(domains.chatgpt_voice_rules({'selected_services': []}), {})


if __name__ == '__main__':
    unittest.main()
