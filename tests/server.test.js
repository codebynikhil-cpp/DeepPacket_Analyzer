const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-api-'));
process.env.DPA_RULE_TOKEN = 'test-only-rule-token';
process.env.DPA_RULES_FILE = path.join(dir, 'rules.json');
process.env.DPA_DATA_FILE = path.join(dir, 'output.json');
process.env.DPA_CRITICAL_FILE = path.join(dir, 'critical_websites.json');
fs.writeFileSync(process.env.DPA_RULES_FILE, JSON.stringify({
    blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: []
}));
fs.writeFileSync(process.env.DPA_CRITICAL_FILE, JSON.stringify({ websites: [] }));

const { app, normalizeRule, snapshotStatus } = require('../server');

test('rule values reject malformed inputs', () => {
    assert.equal(normalizeRule('ip', '999.1.2.3'), null);
    assert.equal(normalizeRule('port', '443junk'), null);
    assert.equal(normalizeRule('port', '65536'), null);
    assert.equal(normalizeRule('domain', "x.example.com' onclick='alert(1)"), null);
    assert.equal(normalizeRule('domain', '*.Example.com'), '*.example.com');
    assert.equal(snapshotStatus({ generated_at: new Date().toISOString(), mode: 'live' }), 'live');
    assert.equal(snapshotStatus({ generated_at: '2000-01-01T00:00:00Z', mode: 'live' }), 'stale');
});

test('API protects writes and reports telemetry state', async () => {
    const server = app.listen(0, '127.0.0.1');
    await new Promise(resolve => server.once('listening', resolve));
    const base = `http://127.0.0.1:${server.address().port}`;
    const rule = { type: 'domain', value: '*.example.com' };
    try {
        let response = await fetch(`${base}/data`);
        assert.equal(response.status, 503);
        fs.writeFileSync(process.env.DPA_DATA_FILE, '[]');
        response = await fetch(`${base}/data`);
        assert.equal(response.status, 503);
        fs.writeFileSync(process.env.DPA_DATA_FILE, '{incomplete');
        response = await fetch(`${base}/data`);
        assert.equal(response.status, 503);

        response = await fetch(`${base}/rules`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(rule) });
        assert.equal(response.status, 401);

        response = await fetch(`${base}/rules`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-rule-token': process.env.DPA_RULE_TOKEN }, body: JSON.stringify({ type: 'port', value: '70000' }) });
        assert.equal(response.status, 400);

        response = await fetch(`${base}/rules`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-rule-token': process.env.DPA_RULE_TOKEN }, body: JSON.stringify(rule) });
        assert.equal(response.status, 200);
        assert.equal((await response.json()).state, 'saved');
        assert.deepEqual(JSON.parse(fs.readFileSync(process.env.DPA_RULES_FILE)).blocked_domains, ['*.example.com']);
        response = await fetch(`${base}/rules/status`);
        assert.equal((await response.json()).state, 'saved');

        fs.writeFileSync(process.env.DPA_DATA_FILE, JSON.stringify({ mode: 'live', generated_at: '2000-01-01T00:00:00Z', packets: 5 }));
        response = await fetch(`${base}/data`);
        assert.equal((await response.json()).status, 'stale');
    } finally {
        await new Promise(resolve => server.close(resolve));
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
