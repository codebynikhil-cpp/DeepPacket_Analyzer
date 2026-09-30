const test = require('node:test');
const assert = require('node:assert/strict');
const { createHealthMonitor, domainMatches } = require('../lib/health');

test('health checks share in-flight work, bound concurrency, and invalidate on rule changes', async () => {
    let calls = 0, active = 0, peak = 0;
    const monitor = createHealthMonitor({ concurrency: 2, probe: async () => {
        calls++; peak = Math.max(peak, ++active);
        await new Promise(resolve => setTimeout(resolve, 5));
        active--;
        return { status: 'UP', latency_ms: 1 };
    }});
    const config = { websites: Array.from({ length: 6 }, (_, i) => ({ name: `Site ${i}`, domains: [`site${i}.example.com`] })) };
    const rules = { blocked_domains: [] };
    const [a, b] = await Promise.all([monitor(config, rules), monitor(config, rules)]);
    assert.deepEqual(a, b);
    assert.equal(calls, 6);
    assert.equal(peak, 2);
    await monitor(config, rules);
    assert.equal(calls, 6);
    const changed = await monitor(config, { blocked_domains: ['*.example.com'] });
    assert.equal(changed.websites['Site 0'].state, 'POLICY MATCH');
    assert.equal(calls, 6);
    assert.equal(domainMatches('sub.example.com', 'example.com'), false);
    assert.equal(domainMatches('sub.example.com', '*.example.com'), true);
    assert.equal(domainMatches('otherexample.com', '*.example.com'), false);
});
