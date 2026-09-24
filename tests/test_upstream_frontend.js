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
                ['button', 'input', 'select', 'textarea'].includes(element.tag) && (!selector.includes(':disabled') || !element.disabled));
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
        closest() { return this.hiddenParent || null; },
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
        assert.equal(elements.get('tunnelServiceCidrsGroup').classList.contains('hidden'), false);
        elements.get('tunnelFailoverMode').value = 'fail_close';
        await app.saveUpstreamTunnel();
        const request = requests.at(-1);
        assert.equal(request.url, `/api/servers/awg-${version}/upstream`);
        assert.equal(request.method, 'PUT');
        assert.deepEqual(JSON.parse(request.body), { routing_mode: 'ai_tiktok', failover_mode: 'fail_close', service_cidrs: [], import_config: config });
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

    const selective = { ...linked, upstream: { ...linked.upstream, routing_mode: 'ai_tiktok', service_cidrs: ['160.79.104.0/23', '8.8.8.8/32'] } };
    open(selective);
    assert.equal(elements.get('tunnelServiceCidrs').value, '160.79.104.0/23\n8.8.8.8/32', 'saved addresses remain visible for editing');
    elements.get('tunnelRoutingMode').value = 'all';
    elements.get('tunnelRoutingMode').listeners.get('change')();
    assert.equal(elements.get('tunnelServiceCidrsGroup').classList.contains('hidden'), true);
    assert.equal(elements.get('tunnelServiceCidrs').value, '160.79.104.0/23\n8.8.8.8/32', 'temporarily changing mode does not erase addresses');
    await app.saveUpstreamTunnel();
    assert.ok(!Object.hasOwn(JSON.parse(requests.at(-1).body), 'service_cidrs'), 'nonselective updates preserve the stored pool on the backend');

    open(selective);
    elements.get('tunnelServiceCidrs').value = ' 160.79.104.0/23\n8.8.8.8/32, 1.1.1.1  \n160.79.104.0/23 ';
    await app.saveUpstreamTunnel();
    assert.deepEqual(JSON.parse(requests.at(-1).body).service_cidrs, ['160.79.104.0/23', '8.8.8.8/32', '1.1.1.1']);
    open(selective);
    elements.get('tunnelServiceCidrs').value = '';
    await app.saveUpstreamTunnel();
    assert.deepEqual(JSON.parse(requests.at(-1).body).service_cidrs, [], 'clearing the textarea removes custom addresses');

    open(selective);
    elements.get('tunnelServiceCidrs').value = '0.0.0.0/0';
    context.fetch = async () => ({ ok: false, status: 400, json: async () => ({ error: 'Only public IPv4 service networks are allowed' }) });
    await app.saveUpstreamTunnel();
    assert.equal(elements.get('tunnelServiceCidrs').value, '0.0.0.0/0', 'validation failure preserves the user input');
    assert.match(elements.get('tunnelFormError').textContent, /Only public IPv4/);

    const diagnostics = {
        protocol: 'awg2', routing_mode: 'ai_tiktok', routing_state: 'upstream', failover_mode: 'fail_close',
        upstream: { interface: 'wg-up-test', healthy: true, handshake_age_seconds: 12, private_key: 'must-not-render' },
        classifier: { dns_running: true, dns_entries: 15, pool_entries: 8, matched_packets: 123,
            seed_status: { resolved_hosts: 20, queried_hosts: 23, errors: 3, addresses: 42, last_attempt: 1720000000, last_success: 1719999900, private_key: 'must-not-render' } },
        destinations: [{ address: '160.79.104.1', matched: true, dns_match: false, pool_match: true, route: 'upstream', egress: 'wg-up-test', secret: 'must-not-render' }],
        warnings: ['<img src=x onerror=alert(1)>', { private_key: 'must-not-render' }],
        private_key: 'must-not-render'
    };
    context.fetch = async (url, options) => {
        requests.push({ url, ...options });
        return { ok: true, json: async () => diagnostics };
    };
    open(selective);
    const beforeDiagnostics = requests.length;
    await app.checkUpstreamDiagnostics();
    assert.equal(requests.length, beforeDiagnostics + 1);
    assert.equal(requests.at(-1).url, '/api/servers/existing/upstream/diagnostics?destination=chatgpt.com');
    assert.equal(requests.at(-1).body, undefined, 'diagnostics do not submit pasted credentials or pending settings');
    const diagnosticResult = elements.get('tunnelDiagnosticResult');
    assert.match(diagnosticResult.textContent, /learned addresses: 15/);
    assert.match(diagnosticResult.textContent, /matched packets: 123/);
    assert.match(diagnosticResult.textContent, /resolved hosts: 20\/23; errors: 3; cached addresses: 42/);
    assert.match(diagnosticResult.textContent, /Last seed attempt \(UTC\): 2024-07-03T09:46:40\.000Z/);
    assert.match(diagnosticResult.textContent, /Last seed address update \(UTC\): 2024-07-03T09:45:00\.000Z/);
    assert.match(diagnosticResult.textContent, /160\.79\.104\.1 — matched: yes/);
    assert.match(diagnosticResult.textContent, /egress interface: wg-up-test/);
    assert.match(diagnosticResult.textContent, /<img src=x onerror=alert\(1\)>/);
    assert.equal(diagnosticResult.innerHTML, '', 'server messages are displayed as text, never HTML');
    assert.ok(!diagnosticResult.textContent.includes('must-not-render'), 'unknown response fields are not exposed');
    assert.equal(elements.get('tunnelDiagnosticDestination').disabled, false);
    elements.get('tunnelDiagnosticDestination').value = ' 160.79.104.1 ';
    await app.checkUpstreamDiagnostics();
    assert.equal(requests.at(-1).url, '/api/servers/existing/upstream/diagnostics?destination=160.79.104.1');
    elements.get('tunnelDiagnosticDestination').value = 'chatgpt.com&other=value';
    await app.checkUpstreamDiagnostics();
    assert.ok(requests.at(-1).url.endsWith('destination=chatgpt.com%26other%3Dvalue'), 'destination cannot inject other query parameters');
    context.fetch = async () => ({ ok: false, status: 400, json: async () => ({ error: '<script>invalid destination</script>' }) });
    await app.checkUpstreamDiagnostics();
    assert.equal(diagnosticResult.textContent, 'Diagnostics failed: <script>invalid destination</script>');
    assert.equal(diagnosticResult.innerHTML, '');
    assert.equal(elements.get('checkUpstreamDiagnostics').disabled, false);

    let finishDiagnostics;
    let diagnosticRequests = 0;
    context.fetch = () => { diagnosticRequests += 1; return new Promise(resolve => { finishDiagnostics = resolve; }); };
    const checking = app.checkUpstreamDiagnostics();
    assert.equal(elements.get('tunnelDiagnosticDestination').disabled, true);
    assert.equal(elements.get('saveUpstreamTunnel').disabled, true);
    await app.checkUpstreamDiagnostics();
    await app.saveUpstreamTunnel();
    assert.equal(diagnosticRequests, 1, 'diagnostics cannot race with duplicate checks or changing saved settings');
    finishDiagnostics({ ok: true, json: async () => diagnostics });
    await checking;
    assert.equal(elements.get('saveUpstreamTunnel').disabled, false);

    let keyboardCheck = false;
    let preventedSubmit = false;
    const checkDiagnostics = app.checkUpstreamDiagnostics;
    app.checkUpstreamDiagnostics = () => { keyboardCheck = true; };
    elements.get('tunnelDiagnosticDestination').listeners.get('keydown')({ key: 'Enter', preventDefault() { preventedSubmit = true; } });
    assert.equal(keyboardCheck, true);
    assert.equal(preventedSubmit, true, 'Enter in the diagnostics destination must not save tunnel settings');
    app.checkUpstreamDiagnostics = checkDiagnostics;
    context.fetch = normalFetch;

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
    console.log('PASS upstream frontend: AWG2/AWG3 tunnels, service address pools, safe diagnostics, errors, busy state and VLESS creation');
}

run().catch(error => { console.error(error); process.exitCode = 1; });
