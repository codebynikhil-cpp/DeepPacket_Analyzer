const https = require('node:https');

function probeHttps(domain, timeoutMs = 4000) {
    return new Promise(resolve => {
        const start = Date.now();
        let timer;
        let finished = false;
        const finish = result => {
            if (finished) return;
            finished = true;
            clearTimeout(timer);
            resolve(result);
        };
        const request = https.get(`https://${domain}`, { headers: { 'User-Agent': 'DeepPacket-HealthChecker/1.0' } }, response => {
            response.resume();
            finish({ status: response.statusCode < 500 ? 'UP' : 'DOWN', latency_ms: Date.now() - start, reason: `HTTP ${response.statusCode}` });
        });
        timer = setTimeout(() => {
            finish({ status: 'DOWN', latency_ms: null, reason: 'timeout' });
            request.destroy();
        }, timeoutMs);
        request.on('error', error => finish({ status: 'DOWN', latency_ms: null, reason: error.code || 'Connection failed' }));
    });
}

function domainMatches(domain, rule) {
    if (typeof rule !== 'string') return false;
    const normalized = rule.toLowerCase();
    return normalized.startsWith('*.') ? domain === normalized.slice(2) || domain.endsWith(normalized.slice(1)) : domain === normalized;
}

function createHealthMonitor({ probe = probeHttps, cacheMs = 10000, concurrency = 4 } = {}) {
    let cached;
    let inFlight;
    let inFlightKey;
    return async (config, rules) => {
        const sites = (Array.isArray(config?.websites) ? config.websites : []).slice(0, 50);
        const blocked = Array.isArray(rules?.blocked_domains) ? rules.blocked_domains : [];
        const key = JSON.stringify([sites, blocked]);
        if (cached?.key === key && Date.now() - cached.at < cacheMs) return cached.data;
        if (inFlight && inFlightKey === key) return inFlight;
        inFlightKey = key;
        const task = (async () => {
            const rows = new Array(sites.length);
            let next = 0;
            await Promise.all(Array.from({ length: Math.min(concurrency, sites.length) }, async () => {
                while (next < sites.length) {
                    const index = next++;
                    const site = sites[index];
                    const domain = typeof site?.domains?.[0] === 'string' ? site.domains[0].replace(/^\*\./, '').toLowerCase() : '';
                    if (!domain || !/^[a-z0-9.-]+$/.test(domain)) continue;
                    const policyMatch = blocked.some(rule => domainMatches(domain, rule));
                    const result = policyMatch ? { status: 'POLICY MATCH', latency_ms: null, reason: 'Probe skipped: domain rule matched' } : await probe(domain);
                    rows[index] = { name: String(site.name || domain), domain, category: site.category || 'website', state: result.status,
                        latency_ms: result.latency_ms, reason: result.reason || '', last_checked: new Date().toISOString() };
                }
            }));
            const data = { last_updated: new Date().toISOString(), websites: Object.fromEntries(rows.filter(Boolean).map(site => [site.name, site])) };
            cached = { key, at: Date.now(), data };
            return data;
        })();
        inFlight = task;
        try { return await task; }
        finally { if (inFlight === task) inFlight = null; }
    };
}

module.exports = { createHealthMonitor, domainMatches };
