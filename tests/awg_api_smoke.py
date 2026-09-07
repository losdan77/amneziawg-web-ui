"""Full Flask/API smoke test; run in an empty disposable AWG Docker container."""
import base64
import os
import sys
from pathlib import Path

os.environ.update(AUTO_START_SERVERS='false', RU_SPLIT_AUTO_FETCH='false')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'web-ui'))
import app as web

client = web.app.test_client()
headers = {'Authorization': 'Basic ' + base64.b64encode(b'admin:changeme').decode()}


def request(method, url, data=None, status=200):
    response = client.open(url, method=method, json=data, headers=headers)
    assert response.status_code == status, (url, response.status_code, response.get_json())
    return response


assert client.post('/api/servers/missing/upgrade-awg3').status_code == 401
assert b'AWG 3.0' in request('GET', '/').data
legacy = dict(Jc=4, Jmin=8, Jmax=80, S1=50, S2=60, H1=1000, H2=2000, H3=3000, H4=4000)
server = request('POST', '/api/servers', dict(name='legacy', awg_version='2',
                 auto_start=False, obfuscation_params=legacy)).get_json()
sid = server['id']
result = request('POST', f'/api/servers/{sid}/clients', dict(name='test', duration='1m')).get_json()
old_client = result['client']
cid = old_client['id']
assert 'HeaderProtectionKey' not in result['clean_config']
upgraded = request('POST', f'/api/servers/{sid}/upgrade-awg3').get_json()
assert upgraded['awg_version'] == '3'
export = request('GET', f'/api/servers/{sid}/clients/{cid}/config-both').get_json()
assert 'HeaderProtectionKey' in str(export)
updated_client = web.amnezia_manager.config['clients'][cid]
for key in ('client_private_key', 'client_public_key', 'preshared_key', 'client_ip', 'expires_at'):
    assert updated_client[key] == old_client[key], key
request('POST', f'/api/servers/{sid}/start')
# Live syncconf after adding a peer must accept every AWG3 field.
request('POST', f'/api/servers/{sid}/clients', dict(name='second', duration='1m'))
request('POST', f'/api/servers/{sid}/stop')
new = request('POST', '/api/servers', dict(name='new', auto_start=False, subnet='10.4.0.0/24')).get_json()
assert new['awg_version'] == '3'
request('POST', f"/api/servers/{new['id']}/start")
request('POST', f"/api/servers/{new['id']}/stop")
request('POST', '/api/servers', dict(name='invalid', auto_start=False, obfuscation_params=dict(legacy, S3=0)), status=400)
print('PASS Flask API: auth, page, legacy export, migration, client preservation, AWG3 start/stop and live peer update')
