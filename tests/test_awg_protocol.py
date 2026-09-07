import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-ui'))
from awg_protocol import (generate_params, import_params, normalize_keepalive,
                          normalize_params, protocol_version, render_params,
                          replace_interface_params, upgrade_params)

LEGACY = dict(Jc=4, Jmin=8, Jmax=80, S1=50, S2=60,
              H1=1000, H2=2000, H3=3000, H4=4000)


class ProtocolTests(unittest.TestCase):
    def test_default_is_real_awg3_with_unique_shared_keys(self):
        keys = set()
        for _ in range(50):
            params = generate_params()
            self.assertEqual(normalize_params(params, 1280), params)
            self.assertEqual(protocol_version(params), '3')
            self.assertTrue(all(params[f'S{i}'] >= 12 for i in range(1, 5)))
            self.assertEqual(len(base64.b64decode(params['HeaderProtectionKey'])), 32)
            keys.add(params['HeaderProtectionKey'])
        self.assertEqual(len(keys), 50)

    def test_legacy_is_not_implicitly_upgraded(self):
        self.assertEqual(normalize_params(LEGACY, 1280), LEGACY)
        self.assertNotIn('HeaderProtectionKey', render_params(LEGACY))
        self.assertNotIn('S3 =', render_params(LEGACY))
        self.assertEqual(protocol_version(generate_params(version='2')), '2')

    def test_awg2_and_3_import_roundtrip(self):
        for params in [dict(LEGACY, S3=0, S4=0, H1='1000-1100'), generate_params()]:
            params.update(I1='<b 0xaabb><r 8><t>', I2='<rc 4><rd 2>', I3='', I4='<dz 2>', I5='<d><ds>')
            parsed = dict(line.split(' = ', 1) for line in render_params(params).splitlines())
            actual = import_params(parsed, 1280)
            self.assertEqual(render_params(actual), render_params(params))

    def test_omitted_upstream_fields_and_zero_keepalive(self):
        self.assertEqual(import_params({'H1': '100-200'}, 1280), {'H1': '100-200'})
        self.assertEqual(normalize_keepalive(0), 0)
        self.assertEqual(normalize_keepalive('off'), 0)
        self.assertEqual(normalize_keepalive('15-30'), '15-30')

    def test_rejects_unsafe_and_incompatible_params(self):
        cases = [dict(LEGACY, H1='1000-2000'), dict(LEGACY, H1='5-4'),
                 dict(LEGACY, H1=4294967296), dict(LEGACY, S1=-1),
                 dict(LEGACY, Jmin=-1), dict(LEGACY, S1=12.5),
                 dict(LEGACY, I1='<r -1>'), dict(LEGACY, I1='<b 0xabc>'),
                 dict(LEGACY, I1='<r 1281>'), dict(LEGACY, I1='<bad 5>'),
                 dict(LEGACY, I1='<r 8>\nPostUp = dangerous'),
                 dict(LEGACY, RekeyTimeout='1-65536'),
                 dict(LEGACY, HeaderProtectionKey='bad'),
                 dict(LEGACY, HeaderProtectionKey=base64.b64encode(bytes(32)).decode()),
                 dict(generate_params(), S3=11), dict(LEGACY, UnknownField='a')]
        for params in cases:
            with self.subTest(params=list(params)):
                with self.assertRaises(ValueError):
                    normalize_params(params, 1280)
        with self.assertRaisesRegex(ValueError, '3.1'):
            import_params(dict(LEGACY, RandomTrailers='true'), 1280)

    def test_explicit_upgrade_preserves_values_and_is_idempotent(self):
        upgraded = upgrade_params(dict(LEGACY, S3=0, S4=0), 1280)
        for key, value in LEGACY.items():
            self.assertEqual(upgraded[key], value)
        self.assertEqual(upgrade_params(upgraded, 1280), upgraded)
        peer = '\n# client\n[Peer]\nPublicKey = unchanged\nAllowedIPs = 10.0.0.2/32\n'
        config = '[Interface]\nPrivateKey = unchanged\n' + render_params(LEGACY) + peer
        result = replace_interface_params(config, upgraded)
        self.assertTrue(result.endswith(peer))
        self.assertIn('PrivateKey = unchanged', result)
        self.assertEqual(result.count('HeaderProtectionKey ='), 1)


if __name__ == '__main__':
    unittest.main()
