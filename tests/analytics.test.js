const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { analyzeFixture } = require('./helpers/traffic-fixture');

test('mixed capture keeps bounded records and consistent packet, byte, and timeline totals', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(),'deeppacket-analytics-'));
    try {
        const data = analyzeFixture(dir,5000);
        const a = data.analysis;
        assert.equal(data.packets,5000);
        assert.equal(data.parse_errors,0);
        assert.deepEqual(data.alerts,[], 'Offline processing speed is not a live traffic alert');
        assert.equal(a.recent_packets.length,300);
        assert.equal(a.recent_packets[0].id,4701);
        assert.equal(a.recent_packets.at(-1).id,5000);
        assert.ok(a.timeline.length <= 300);
        assert.ok(a.capture_duration_ms > 300000);
        assert.equal(a.size_distribution.reduce((sum,bin) => sum + bin.packets,0),5000);
        assert.equal(a.top_talkers.reduce((sum,host) => sum + host.sent_bytes,0),data.bytes);
        assert.equal(a.top_talkers.reduce((sum,host) => sum + host.received_bytes,0),data.bytes);
        assert.ok(data.flows.every(flow => flow.packets > 0 && flow.bytes > 0));
        assert.ok(a.recent_packets.some(packet => packet.protocol === 'UDP' && packet.dst_port === 53));
        assert.ok(a.recent_packets.some(packet => packet.domain === 'github.com'));
        assert.ok(a.recent_packets.some(packet => packet.domain === 'example.com' && packet.dst_port === 443));
        assert.ok(a.recent_packets.every(packet => packet.src_mac && packet.dst_mac && !Object.hasOwn(packet,'payload_data')));
        assert.ok(JSON.stringify(data).length < 400000,'Telemetry must remain bounded for a large input');
    } finally {
        fs.rmSync(dir,{recursive:true,force:true});
    }
});
