const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

// Small DOM double: exercise the actual dialog handlers and request lifecycle.
const elements = new Map();
const documentListeners = new Map();
let insertedHtml = '';
const document = {
    activeElement: null,
    addEventListener(name, callback) { documentListeners.set(name, callback); },
    removeEventListener(name) { documentListeners.delete(name); },
    getElementById(id) { return elements.get(id) || null; },
    body: {
        insertAdjacentHTML(_, html) {
            insertedHtml = html;
            const dialogIds = [];
            for (const match of html.matchAll(/<(\w+)\b([^>]*\bid="([^"]+)"[^>]*)>/g)) {
                const element = makeElement(match[3], '', match[1]);
                const classes = /class="([^"]*)"/.exec(match[2]);
                (classes?.[1].split(/\s+/) || []).forEach(value => element.classList.add(value));
                dialogIds.push(match[3]);
            }
            const modal = elements.get('upstreamTunnelModal');
            modal.remove = () => dialogIds.forEach(id => elements.delete(id));
            modal.querySelectorAll = selector => dialogIds.map(id => elements.get(id)).filter(element =>
                ['button', 'select', 'textarea'].includes(element.tag) && (!selector.includes(':disabled') || !element.disabled));
        }
    }
};

function makeElement(id, value = '', tag = 'input') {
    const classes = new Set();
    const element = {
        tag, value, disabled: false, checked: false, textContent: '', innerHTML: '',
        listeners: new Map(), attributes: {},
        classList: {
            add(value) { classes.add(value); },
            remove(value) { classes.delete(value); },
            contains(value) { return classes.has(value); },
            toggle(value, force) {
                const enabled = force === undefined ? !classes.has(value) : force;
                if (enabled) classes.add(value); else classes.delete(value);
                return enabled;
            }
        },
        addEventListener(name, callback) { this.listeners.set(name, callback); },
        setAttribute(name, value) { this.attributes[name] = value; },
        focus() { document.activeElement = this; },
        remove() { elements.delete(id); }
    };
    elements.set(id, element);
    return element;
}

const context = vm.createContext({ document, console: { log() {}, error() {}, warn() {} } });
const source = fs.readFileSync(path.join(__dirname, '../web-ui/static/js/app.js'), 'utf8');
vm.runInContext(source + '\nthis.TestApp = AmneziaApp;', context);
const app = Object.create(context.TestApp.prototype);
app.getElement = id => document.getElementById(id);
const notifications = [];
let reloads = 0;
app.showTempMessage = (message, type) => notifications.push({ message, type });
app.loadServers = () => { reloads += 1; };
const config2 = '[Interface]\nPrivateKey = dedicated-secret\nAddress = 10.0.0.2/32\nS3 = 12\nS4 = 12\n[Peer]\nPublicKey = public\nEndpoint = exit.example.com:51820';
const config3 = config2.replace('S3 = 12', 'HeaderProtectionKey = header-secret\nS3 = 12');
const requests = [];
context.fetch = async (url, options) => {
    requests.push({ url, ...options });
    return { ok: true, json: async () => ({ success: true }) };
};
const normalFetch = context.fetch;

function open(server) {
    server = { obfuscation_enabled: true, ...server };
    app.serversById = new Map([[server.id, server]]);
    app.openUpstreamDialog(server.id);
}

async function run() {
    assert.equal(app.getUpstreamRoutingMode({ split_ru_local: true }), 'ru_split');
    assert.equal(app.getUpstreamRoutingMode({ split_ru_local: false }), 'all');
    assert.equal(app.getUpstreamRoutingMode({}), 'all');
    assert.equal(app.getUpstreamRoutingMode({ routing_mode: 'ai_tiktok', split_ru_local: true }), 'ai_tiktok');
    assert.match(app.getUpstreamRoutingLabel({ routing_mode: 'ai_tiktok' }), /all other traffic locally/);

    const serversList = makeElement('serversList');
    app.updateClientFilterSummary = () => {};
    app.renderServerClients = () => '';
    app.loadServerClients = () => {};
    app.renderServers([
        { id: 'awg2-card', name: 'AWG2', obfuscation_enabled: true, obfuscation_params: { S3: 12 }, clients: [] },
        { id: 'awg3-card', name: 'AWG3', obfuscation_enabled: true, obfuscation_params: { HeaderProtectionKey: 'key' }, clients: [] },
        { id: 'plain-card', name: 'Plain WireGuard', obfuscation_enabled: false, clients: [] },
        { id: 'vless-card', name: 'VLESS', protocol: 'vless', clients: [] }
    ]);
    assert.match(serversList.innerHTML, /openUpstreamDialog\('awg2-card'\)/);
    assert.match(serversList.innerHTML, /openUpstreamDialog\('awg3-card'\)/);
    assert.ok(!serversList.innerHTML.includes("openUpstreamDialog('plain-card')"));
    assert.ok(!serversList.innerHTML.includes("openUpstreamDialog('vless-card')"));
    open({ id: 'plain', name: 'Plain WireGuard', obfuscation_enabled: false });
    assert.ok(!elements.has('upstreamTunnelModal'), 'plain WireGuard tunnel API is not exposed');

    makeElement('serverProtocol', 'wireguard');
    makeElement('upstreamRoutingMode', 'ai_tiktok');
    const hint = makeElement('upstreamSelectiveDnsHint');
    app.updateUpstreamRoutingHint();
    assert.equal(hint.classList.contains('hidden'), false);
    elements.get('serverProtocol').value = 'vless';
    app.updateUpstreamRoutingHint();
    assert.equal(hint.classList.contains('hidden'), true);

    for (const [version, config] of [['2', config2], ['3', config3]]) {
        const trigger = makeElement('trigger');
        trigger.focus();
        open({ id: `awg-${version}`, name: '<img src=x onerror=alert(1)>', mode: 'standalone', awg_version: version });
        assert.ok(elements.get('upstreamTunnelModal'));
        assert.equal(elements.get('tunnelImportConfig').required, true);
        assert.equal(elements.get('tunnelRoutingMode').value, 'ru_split');
        assert.ok(!elements.has('removeUpstreamTunnel'));
        assert.match(insertedHtml, /&lt;img src=x onerror=alert\(1\)&gt;/);
        const before = requests.length;
        await app.saveUpstreamTunnel();
        assert.equal(requests.length, before, 'empty attach must not call API');
        assert.match(elements.get('tunnelFormError').textContent, /dedicated client config/);
        elements.get('tunnelImportConfig').value = '[Interface]\nPrivateKey = invalid';
        await app.saveUpstreamTunnel();
        assert.equal(requests.length, before, 'incomplete config must not call API');

        elements.get('tunnelImportConfig').value = config;
        elements.get('tunnelImportConfig').listeners.get('input')();
        assert.match(elements.get('tunnelConfigPreview').textContent, new RegExp(`AWG ${version}\\.0`));
        assert.ok(!elements.get('tunnelConfigPreview').textContent.includes('secret'));
        elements.get('tunnelRoutingMode').value = 'ai_tiktok';
        elements.get('tunnelRoutingMode').listeners.get('change')();
        assert.equal(elements.get('tunnelSelectiveDnsHint').classList.contains('hidden'), false);
        elements.get('tunnelFailoverMode').value = 'fail_close';
        await app.saveUpstreamTunnel();
        const request = requests.at(-1);
        assert.equal(request.url, `/api/servers/awg-${version}/upstream`);
        assert.equal(request.method, 'PUT');
        assert.deepEqual(JSON.parse(request.body), { routing_mode: 'ai_tiktok', failover_mode: 'fail_close', import_config: config });
        assert.ok(!elements.has('upstreamTunnelModal'));
        assert.equal(document.activeElement, trigger, 'focus returns to trigger');
        assert.ok(!documentListeners.has('keydown'));
    }

    const linked = { id: 'existing', name: 'Existing AWG', mode: 'edge_linked', linked_failover_mode: 'fail_open',
        upstream: { split_ru_local: true, endpoint: '<script>bad</script>', private_key: 'must-not-render' } };
    open(linked);
    assert.equal(elements.get('tunnelRoutingMode').value, 'ru_split');
    assert.equal(elements.get('tunnelFailoverMode').value, 'fail_open');
    assert.equal(elements.get('tunnelImportConfig').required, false);
    assert.equal(elements.get('tunnelImportConfig').value, '');
    assert.match(insertedHtml, /&lt;script&gt;bad&lt;\/script&gt;/);
    assert.ok(!insertedHtml.includes('must-not-render'));
    elements.get('tunnelRoutingMode').value = 'all';
    await app.saveUpstreamTunnel();
    assert.deepEqual(JSON.parse(requests.at(-1).body), { routing_mode: 'all', failover_mode: 'fail_open' }, 'editing routing preserves stored credentials');

    open(linked);
    elements.get('tunnelImportConfig').value = config3;
    context.fetch = async () => ({ ok: false, status: 400, json: async () => ({ error: 'Imported address overlaps with an existing network' }) });
    await app.saveUpstreamTunnel();
    assert.ok(elements.has('upstreamTunnelModal'), 'failure keeps the dialog open');
    assert.equal(elements.get('tunnelImportConfig').value, config3, 'failure keeps pasted config');
    assert.equal(elements.get('saveUpstreamTunnel').disabled, false);
    assert.match(elements.get('tunnelFormError').textContent, /overlaps/);
    assert.equal(elements.get('tunnelFormError').classList.contains('hidden'), false);
    context.fetch = async () => { throw new Error('Network unavailable'); };
    await app.saveUpstreamTunnel();
    assert.equal(elements.get('tunnelFormError').textContent, 'Network unavailable');
    assert.equal(app.upstreamDialogBusy, false);

    let completeRequest;
    let pendingCount = 0;
    context.fetch = () => { pendingCount += 1; return new Promise(resolve => { completeRequest = resolve; }); };
    const pending = app.saveUpstreamTunnel();
    assert.equal(elements.get('tunnelImportConfig').disabled, true);
    assert.equal(elements.get('upstreamTunnelModal').attributes['aria-busy'], 'true');
    app.closeUpstreamDialog();
    assert.ok(elements.has('upstreamTunnelModal'), 'pending request cannot lose its dialog');
    await app.saveUpstreamTunnel();
    assert.equal(pendingCount, 1, 'duplicate submission is blocked');
    completeRequest({ ok: true, json: async () => ({ success: true }) });
    await pending;
    assert.ok(!elements.has('upstreamTunnelModal'));

    context.fetch = normalFetch;
    open(linked);
    const beforeDelete = requests.length;
    app.removeUpstreamTunnel();
    assert.equal(requests.length, beforeDelete);
    assert.ok(elements.has('upstreamTunnelModal'));
    assert.equal(elements.get('tunnelRemoveConfirmation').classList.contains('hidden'), false);
    elements.get('keepUpstreamTunnel').listeners.get('click')();
    assert.equal(elements.get('tunnelRemoveConfirmation').classList.contains('hidden'), true);
    assert.equal(requests.length, beforeDelete, 'keeping tunnel does not call API');
    app.removeUpstreamTunnel();
    await app.confirmRemoveUpstreamTunnel();
    assert.equal(requests.at(-1).method, 'DELETE');
    assert.equal(requests.at(-1).url, '/api/servers/existing/upstream');
    assert.equal(requests.at(-1).body, undefined);
    assert.ok(!elements.has('upstreamTunnelModal'));

    open({ id: 'vless', protocol: 'vless', name: 'VLESS' });
    assert.ok(!elements.has('upstreamTunnelModal'), 'existing VLESS tunnel API is not exposed');

    app.validateForm = () => true;
    app.setCreateButtonState = () => {};
    app.showFormStatus = () => {};
    app.toggleProtocolFields = () => {};
    app.toggleUpstreamSettings = () => {};
    makeElement('serverMode', 'edge_linked');
    makeElement('upstreamImportConfig', config3);
    makeElement('upstreamFailoverMode', 'fail_close');
    makeElement('upstreamRoutingMode', 'ai_tiktok');
    makeElement('vlessUseUpstream').checked = true;
    for (const protocol of ['wireguard', 'vless']) {
        makeElement('serverProtocol', protocol);
        app.createServer();
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(requests.at(-1).url, '/api/servers');
        const payload = JSON.parse(requests.at(-1).body);
        assert.equal(payload.protocol, protocol);
        assert.equal(payload.upstream.routing_mode, 'ai_tiktok');
        assert.equal(payload.upstream.import_config, config3);
        assert.ok(!Object.hasOwn(payload.upstream, 'split_ru_local'));
    }
    assert.ok(reloads >= 6);
    console.log('PASS upstream frontend: AWG2/AWG3 attach, edit, detach, routing modes, credentials, errors, busy state and VLESS creation');
}

run().catch(error => { console.error(error); process.exitCode = 1; });
