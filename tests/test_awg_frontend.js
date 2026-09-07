const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const context = vm.createContext({ document: { addEventListener() {} }, console });
const source = fs.readFileSync(path.join(__dirname, '../web-ui/static/js/app.js'), 'utf8');
vm.runInContext(source + '\nthis.TestApp = AmneziaApp;', context);
const app = Object.create(context.TestApp.prototype);
app.getElement = () => ({ value: '3' });
const params = { Jc: 4, Jmin: 8, Jmax: 80, S1: 50, S2: 60, S3: 12, S4: 12,
    H1: '1000-1100', H2: '2000', H3: '3000', H4: '4000' };
assert.equal(app.validateObfuscationParamsJS(params, 1280).length, 0);
assert.ok(app.validateObfuscationParamsJS({ ...params, S3: 0 }, 1280).length);
assert.ok(app.validateObfuscationParamsJS({ ...params, H1: '1000-2000' }, 1280).length);
assert.equal(app.getAwgVersion({ obfuscation_params: { HeaderProtectionKey: 'key' } }), '3.0');
assert.equal(app.getAwgVersion({ obfuscation_params: { S4: 0 } }), '2.0');
assert.equal(app.getAwgVersion({ obfuscation_params: { H1: 1000 } }), '1.x');
const imported = app.parseAmneziaConfigPreview('[Interface]\nPrivateKey = secret\nAddress = 10.0.0.2/32\nS3 = 12\nHeaderProtectionKey = shared==\nH1 = 100-200\n[Peer]\nPublicKey = public\nEndpoint = example.com:51820\nPersistentKeepalive = 15-30');
assert.equal(imported.interface.HeaderProtectionKey, 'shared==');
assert.equal(imported.interface.H1, '100-200');
assert.equal(imported.peer.PersistentKeepalive, '15-30');
console.log('PASS AWG frontend: version display, ranges, validation and import preview');
