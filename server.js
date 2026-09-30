const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createHealthMonitor } = require('./lib/health');

const app = express();
const HOST = process.env.DPA_HOST || '127.0.0.1';
const PORT = Number(process.env.DPA_PORT || 3000);
const DATA_FILE = process.env.DPA_DATA_FILE || path.join(__dirname, 'output.json');
const RULES_FILE = process.env.DPA_RULES_FILE || path.join(__dirname, 'rules.json');
const RULES_DIR = path.dirname(RULES_FILE);
const REVISION_FILE = path.join(RULES_DIR, 'rules_revision.txt');
const APPLIED_FILE = path.join(RULES_DIR, 'rules_applied.txt');
const RELOAD_FLAG = path.join(RULES_DIR, 'rules_reload.flag');
const CRITICAL_FILE = process.env.DPA_CRITICAL_FILE || path.join(__dirname, 'critical_websites.json');
const SYNTHETIC_DEMO = process.env.DPA_SYNTHETIC_DEMO === '1';
const RULE_TOKEN = process.env.DPA_RULE_TOKEN || crypto.randomBytes(24).toString('hex');
const EMPTY_RULES = { blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] };
const KEY_BY_TYPE = { ip: 'blocked_ips', domain: 'blocked_domains', app: 'blocked_apps', port: 'blocked_ports' };
// Match the names returned by appTypeToString() in src/types.cpp.
const KNOWN_APPS = new Set([
    'HTTP', 'HTTPS', 'DNS', 'TLS', 'QUIC', 'Google', 'Microsoft', 'Apple', 'Amazon', 'Cloudflare',
    'Facebook', 'Instagram', 'WhatsApp', 'Twitter/X', 'Telegram', 'TikTok', 'Discord', 'Reddit',
    'LinkedIn', 'Snapchat', 'Pinterest', 'YouTube', 'Netflix', 'Spotify', 'Twitch', 'Disney+',
    'Hulu', 'SoundCloud', 'ChatGPT/OpenAI', 'Notion', 'Zoom', 'Slack', 'Microsoft Teams', 'Canva',
    'Figma', 'Trello', 'GitHub', 'GitLab', 'Bitbucket', 'StackOverflow', 'LeetCode', 'Wikipedia',
    'Coursera', 'Medium', 'npm Registry', 'Docker', 'Hugging Face', 'Kaggle', 'GeeksforGeeks',
    'CodeChef', 'HackerRank', 'Steam', 'Roblox', 'Epic Games', 'Riot Games', 'eBay', 'AliExpress',
    'PayPal', 'Uber'
]);

app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));
app.get('/vendor/chart.js', (_req, res) => res.sendFile(path.join(__dirname, 'node_modules/chart.js/dist/chart.umd.js')));
app.use(express.static(path.join(__dirname, 'public')));

function readJson(file, fallback) {
    try { return JSON.parse(fs.readFileSync(file, 'utf8')); }
    catch { return fallback; }
}

function writeJson(file, data) {
    writeText(file, JSON.stringify(data, null, 2));
}

function writeText(file, value) {
    const temp = `${file}.${process.pid}.tmp`;
    try {
        fs.writeFileSync(temp, value);
        fs.renameSync(temp, file);
    } finally {
        if (fs.existsSync(temp)) fs.unlinkSync(temp);
    }
}

function snapshotStatus(data) {
    if (!data || typeof data !== 'object' || data.error) return 'unavailable';
    const generated = Date.parse(data.generated_at);
    if (!Number.isFinite(generated)) return 'stale';
    if (data.engine_state === 'stopped' || data.mode === 'offline') return 'offline';
    return Math.abs(Date.now() - generated) <= 3000 ? 'live' : 'stale';
}

app.get('/data', (_req, res) => {
    res.set('Cache-Control', 'no-store');
    const data = readJson(DATA_FILE, null);
    if (!data || typeof data !== 'object' || Array.isArray(data) || !Number.isFinite(data.packets))
        return res.status(503).json({ error: 'No valid engine telemetry', status: 'unavailable' });
    res.json({ ...data, status: snapshotStatus(data), ...(SYNTHETIC_DEMO ? { data_source:'synthetic_fixture' } : {}) });
});

app.get('/mode', (_req, res) => {
    const data = readJson(DATA_FILE, null);
    res.json({ mode: data?.mode || 'unknown', source_name: data?.source_name || '', status: snapshotStatus(data),
        capture_drops: data?.capture_drops || 0, processing_drops: data?.processing_drops || 0 });
});

app.get('/rules', (_req, res) => res.json(readJson(RULES_FILE, EMPTY_RULES)));
app.get('/rules/status', (_req, res) => {
    const revision = fs.existsSync(REVISION_FILE) ? fs.readFileSync(REVISION_FILE, 'utf8').trim() : '';
    const applied = fs.existsSync(APPLIED_FILE) ? fs.readFileSync(APPLIED_FILE, 'utf8').trim() : '';
    const data = readJson(DATA_FILE, null);
    res.json({ state: revision && revision === applied ? 'loaded' : revision ? 'saved' : 'unknown',
        revision, engine_status: snapshotStatus(data), wfp_active: snapshotStatus(data) === 'live' && Boolean(data?.wfp?.active) });
});

function authorized(req, res, next) {
    const supplied = req.get('x-rule-token') || '';
    const expected = Buffer.from(RULE_TOKEN);
    const actual = Buffer.from(supplied);
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) {
        return res.status(401).json({ error: 'Rule token required or incorrect' });
    }
    next();
}

function validIPv4(value) {
    const parts = value.split('.');
    return parts.length === 4 && parts.every(part => /^(0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
}

function normalizeRule(type, value) {
    if (!Object.hasOwn(KEY_BY_TYPE, type)) return null;
    if (type === 'port') {
        if (!/^[0-9]{1,5}$/.test(String(value))) return null;
        const port = Number(value);
        return port >= 1 && port <= 65535 ? port : null;
    }
    if (typeof value !== 'string') return null;
    const trimmed = value.trim();
    if (type === 'ip') return validIPv4(trimmed) ? trimmed : null;
    if (type === 'domain') {
        const domain = trimmed.toLowerCase();
        const bare = domain.startsWith('*.') ? domain.slice(2) : domain;
        return bare.length <= 253 && bare.includes('.') && bare.split('.').every(label =>
            label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label)) ? domain : null;
    }
    return KNOWN_APPS.has(trimmed) ? trimmed : null;
}

function changeRule(req, res, remove) {
    const type = req.body?.type;
    const key = KEY_BY_TYPE[type];
    const value = normalizeRule(type, req.body?.value);
    if (!key || value === null) return res.status(400).json({ error: 'Invalid rule type or value' });
    const rules = readJson(RULES_FILE, fs.existsSync(RULES_FILE) ? null : structuredClone(EMPTY_RULES));
    if (!rules) return res.status(500).json({ error: 'Rules file is invalid' });
    if (!Array.isArray(rules[key])) return res.status(500).json({ error: 'Rules file is invalid' });
    if (remove) rules[key] = rules[key].filter(item => item !== value);
    else if (!rules[key].includes(value)) rules[key].push(value);
    try {
        writeJson(RULES_FILE, rules);
        const revision = crypto.randomUUID();
        writeText(REVISION_FILE, revision);
        writeText(RELOAD_FLAG, revision);
        res.json({ success: true, state: 'saved', revision, rules });
    } catch (error) {
        console.error('Could not save rule:', error);
        res.status(500).json({ error: 'Could not save rule' });
    }
}

app.post('/rules', authorized, (req, res) => changeRule(req, res, false));
app.delete('/rules', authorized, (req, res) => changeRule(req, res, true));

app.get('/critical-websites', (_req, res) => res.json(readJson(CRITICAL_FILE, { websites: [] })));

const getHealth = createHealthMonitor();
app.get('/health', async (_req, res, next) => {
    try {
        res.set('Cache-Control', 'no-store');
        res.json(await getHealth(readJson(CRITICAL_FILE, { websites: [] }), readJson(RULES_FILE, EMPTY_RULES)));
    } catch (error) { next(error); }
});

app.use((error, _req, res, _next) => {
    const status = error.status === 413 ? 413 : error.type === 'entity.parse.failed' ? 400 : 500;
    res.status(status).json({ error: status === 413 ? 'Request body is too large' : status === 400 ? 'Invalid JSON body' : 'Server could not complete the request' });
});

if (require.main === module) {
    app.listen(PORT, HOST, error => {
        if (error) {
            console.error(`Cannot start dashboard on ${HOST}:${PORT}: ${error.message}`);
            process.exitCode = 1;
            return;
        }
        console.log(`DeepPacket dashboard: http://${HOST}:${PORT}`);
        console.log(`Rule management token: ${RULE_TOKEN}`);
    });
}

module.exports = { app, normalizeRule, snapshotStatus };
