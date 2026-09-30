const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const executable = require('../scripts/engine-path');

function fixturePcap() {
    const payload = Buffer.from('GET / HTTP/1.1\r\nHost: github.com\r\n\r\n');
    const ethernet = Buffer.alloc(14);
    ethernet.writeUInt16BE(0x0800, 12);
    const ip = Buffer.alloc(20);
    ip[0] = 0x45;
    ip.writeUInt16BE(20 + 20 + payload.length, 2);
    ip[8] = 64;
    ip[9] = 6;
    Buffer.from([10, 0, 0, 1]).copy(ip, 12);
    Buffer.from([1, 1, 1, 1]).copy(ip, 16);
    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(49152, 0);
    tcp.writeUInt16BE(80, 2);
    tcp[12] = 0x50;
    tcp[13] = 0x18;
    const packet = Buffer.concat([ethernet, ip, tcp, payload]);
    const global = Buffer.alloc(24);
    global.writeUInt32LE(0xa1b2c3d4, 0);
    global.writeUInt16LE(2, 4);
    global.writeUInt16LE(4, 6);
    global.writeUInt32LE(65535, 16);
    global.writeUInt32LE(1, 20);
    const header = Buffer.alloc(16);
    header.writeUInt32LE(1, 0);
    header.writeUInt32LE(packet.length, 8);
    header.writeUInt32LE(packet.length, 12);
    return Buffer.concat([global, header, packet]);
}

function ipv6FixturePcap() {
    const packets = [0x01, 0x02].map(secondByte => {
        const ethernet = Buffer.alloc(14);
        ethernet.writeUInt16BE(0x86dd, 12);
        const ip = Buffer.alloc(40);
        ip[0] = 0x60;
        ip.writeUInt16BE(8, 4);
        ip[6] = 17;
        ip[7] = 64;
        ip[8] = 0x20;
        ip[9] = secondByte;
        ip[23] = 1;
        ip[24] = 0x20;
        ip[25] = 0x01;
        ip[39] = 2;
        const udp = Buffer.alloc(8);
        udp.writeUInt16BE(12345, 0);
        udp.writeUInt16BE(53, 2);
        udp.writeUInt16BE(8, 4);
        return Buffer.concat([ethernet, ip, udp]);
    });
    const withExtension = Buffer.from(packets[0]);
    withExtension.writeUInt16BE(16, 14 + 4); // IPv6 payload includes hop-by-hop + UDP
    withExtension[14 + 6] = 0; // Hop-by-Hop Options
    const hopByHop = Buffer.alloc(8);
    hopByHop[0] = 17; // UDP follows
    const udp = Buffer.alloc(8);
    udp.writeUInt16BE(23456, 0);
    udp.writeUInt16BE(53, 2);
    udp.writeUInt16BE(8, 4);
    packets.push(Buffer.concat([withExtension.subarray(0, 54), hopByHop, udp]));
    const global = Buffer.alloc(24);
    global.writeUInt32LE(0xa1b2c3d4, 0);
    global.writeUInt16LE(2, 4);
    global.writeUInt16LE(4, 6);
    global.writeUInt32LE(65535, 16);
    global.writeUInt32LE(1, 20);
    return Buffer.concat([global, ...packets.flatMap(packet => {
        const header = Buffer.alloc(16);
        header.writeUInt32LE(packet.length, 8);
        header.writeUInt32LE(packet.length, 12);
        return [header, packet];
    })]);
}

function malformedFixturePcap() {
    function record(packet) {
        const header = Buffer.alloc(16);
        header.writeUInt32LE(packet.length, 8);
        header.writeUInt32LE(packet.length, 12);
        return Buffer.concat([header, packet]);
    }
    const ethernet = Buffer.alloc(14);
    ethernet.writeUInt16BE(0x0800, 12);
    const invalid = Buffer.alloc(20);
    invalid[0] = 0x45;
    invalid.writeUInt16BE(10, 2); // smaller than the IPv4 header
    const fragment = Buffer.alloc(40);
    fragment[0] = 0x45;
    fragment.writeUInt16BE(40, 2);
    fragment.writeUInt16BE(1, 6); // noninitial fragment: no TCP header
    fragment[9] = 6;
    Buffer.from([10, 0, 0, 9]).copy(fragment, 12);
    Buffer.from([8, 8, 8, 8]).copy(fragment, 16);
    return Buffer.concat([fixturePcap(), record(Buffer.concat([ethernet, invalid])), record(Buffer.concat([ethernet, fragment]))]);
}

function tlsFixturePcap(hostname = 'github.com') {
    const host = Buffer.from(hostname);
    const name = Buffer.concat([Buffer.from([0, 0, host.length]), host]);
    const serverNames = Buffer.concat([Buffer.from([0, name.length]), name]);
    const sni = Buffer.concat([Buffer.from([0, 0, 0, serverNames.length]), serverNames]);
    const extensions = Buffer.concat([Buffer.from([0, sni.length]), sni]);
    const body = Buffer.concat([
        Buffer.from([3, 3]), Buffer.alloc(32), Buffer.from([0]),
        Buffer.from([0, 2, 0x13, 0x01]), Buffer.from([1, 0]), extensions
    ]);
    const handshakeHeader = Buffer.alloc(4);
    handshakeHeader[0] = 1;
    handshakeHeader.writeUIntBE(body.length, 1, 3);
    const handshake = Buffer.concat([handshakeHeader, body]);
    const recordHeader = Buffer.alloc(5);
    recordHeader[0] = 0x16;
    recordHeader.writeUInt16BE(0x0301, 1);
    recordHeader.writeUInt16BE(handshake.length, 3);
    const payload = Buffer.concat([recordHeader, handshake]);
    const ethernet = Buffer.alloc(14);
    ethernet.writeUInt16BE(0x0800, 12);
    const ip = Buffer.alloc(20);
    ip[0] = 0x45;
    ip.writeUInt16BE(40 + payload.length, 2);
    ip[8] = 64;
    ip[9] = 6;
    Buffer.from([10, 0, 0, 1]).copy(ip, 12);
    Buffer.from([1, 1, 1, 1]).copy(ip, 16);
    const tcp = Buffer.alloc(20);
    tcp.writeUInt16BE(49153, 0);
    tcp.writeUInt16BE(443, 2);
    tcp[12] = 0x50;
    const packet = Buffer.concat([ethernet, ip, tcp, payload]);
    const global = Buffer.from(fixturePcap().subarray(0, 24));
    const header = Buffer.alloc(16);
    header.writeUInt32LE(packet.length, 8);
    header.writeUInt32LE(packet.length, 12);
    return Buffer.concat([global, header, packet]);
}

function dnsFixturePcap(hostname = 'github.com') {
    const labels = hostname.split('.').flatMap(label => [Buffer.from([Buffer.byteLength(label)]), Buffer.from(label)]);
    const question = Buffer.concat([...labels, Buffer.from([0, 0, 1, 0, 1])]);
    const dns = Buffer.concat([Buffer.from([0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]), question]);
    const ethernet = Buffer.alloc(14);
    ethernet.writeUInt16BE(0x0800, 12);
    const ip = Buffer.alloc(20);
    ip[0] = 0x45;
    ip.writeUInt16BE(28 + dns.length, 2);
    ip[8] = 64;
    ip[9] = 17;
    Buffer.from([10, 0, 0, 1]).copy(ip, 12);
    Buffer.from([1, 1, 1, 1]).copy(ip, 16);
    const udp = Buffer.alloc(8);
    udp.writeUInt16BE(49154, 0);
    udp.writeUInt16BE(53, 2);
    udp.writeUInt16BE(8 + dns.length, 4);
    const packet = Buffer.concat([ethernet, ip, udp, dns]);
    const global = Buffer.from(fixturePcap().subarray(0, 24));
    const header = Buffer.alloc(16);
    header.writeUInt32LE(packet.length, 8);
    header.writeUInt32LE(packet.length, 12);
    return Buffer.concat([global, header, packet]);
}

test('offline PCAP produces a complete classified telemetry snapshot', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-pcap-'));
    try {
        const input = path.join(dir, 'fixture.pcap');
        fs.writeFileSync(input, fixturePcap());
        fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] }));
        fs.writeFileSync(path.join(dir, 'rules_revision.txt'), 'fixture-revision');
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const data = JSON.parse(fs.readFileSync(path.join(dir, 'output.json'), 'utf8'));
        assert.equal(data.schema_version, 1);
        assert.equal(data.engine_state, 'stopped');
        assert.equal(data.mode, 'offline');
        assert.equal(data.packets, 1);
        assert.ok(data.generated_at);
        assert.ok(data.session_id);
        assert.equal(data.analysis.recent_packets.length, 1);
        assert.equal(data.analysis.recent_packets[0].src_port, 49152);
        assert.equal(data.analysis.recent_packets[0].dst_port, 80);
        assert.equal(data.analysis.recent_packets[0].ttl, 64);
        assert.equal(data.analysis.top_talkers.length, 2);
        assert.equal(data.analysis.timeline[0].packets, 1);
        assert.equal(data.analysis.size_distribution.reduce((sum, bin) => sum + bin.packets, 0), 1);
        assert.equal(data.flows[0].packets, 1);
        assert.equal(data.flows[0].bytes, fixturePcap().length - 40);
        assert.equal(fs.readFileSync(path.join(dir, 'rules_applied.txt'), 'utf8'), 'fixture-revision');
        assert.ok(data.flows.some(flow => flow.domain === 'github.com' && flow.method === 'HTTP Host' && flow.confidence === 'high'),
            'HTTP Host evidence should appear on the flow');
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('saved domain rule matches an offline flow with an explicit reason', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-rule-'));
    try {
        const input = path.join(dir, 'fixture.pcap');
        fs.writeFileSync(input, fixturePcap());
        fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({
            blocked_ips: [], blocked_domains: ['*.github.com'], blocked_apps: [], blocked_ports: []
        })); // compact JSON must work just like the API's pretty-printed JSON
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const data = JSON.parse(fs.readFileSync(path.join(dir, 'output.json'), 'utf8'));
        assert.equal(data.dropped, 1);
        assert.ok(data.flows.some(flow => flow.domain === 'github.com' && flow.policy === 'DROP' &&
            flow.policy_reason.includes('github.com') && flow.enforcement === 'MONITOR ONLY'));
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('filtered PCAP export has a valid global header and can be read again', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-export-'));
    try {
        const input = path.join(dir, 'input.pcap');
        const output = path.join(dir, 'filtered.pcap');
        fs.writeFileSync(input, fixturePcap());
        const result = spawnSync(executable, ['--pcap', input, output], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(result.status, 0, result.stderr);
        const exported = fs.readFileSync(output);
        assert.equal(exported.readUInt32LE(0), 0xa1b2c3d4);
        assert.equal(exported.readUInt32LE(20), 1);
        const replay = spawnSync(executable, ['--pcap', output], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(replay.status, 0, replay.stderr);
        assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'output.json'))).packets, 1);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('IPv6 flow keys retain full addresses', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-ipv6-'));
    try {
        const input = path.join(dir, 'ipv6.pcap');
        fs.writeFileSync(input, ipv6FixturePcap());
        fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] }));
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const data = JSON.parse(fs.readFileSync(path.join(dir, 'output.json'), 'utf8'));
        assert.equal(data.connections, 3);
        assert.equal(new Set(data.flows.map(flow => flow.src_ip)).size, 2);
        assert.ok(data.flows.every(flow => flow.src_ip.includes(':')));
        assert.ok(data.flows.some(flow => flow.src_port === 23456), 'IPv6 extension header must be skipped before UDP');
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('malformed IPv4 is rejected and later fragments are not parsed as TCP', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-malformed-'));
    try {
        const input = path.join(dir, 'malformed.pcap');
        fs.writeFileSync(input, malformedFixturePcap());
        fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] }));
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const data = JSON.parse(fs.readFileSync(path.join(dir, 'output.json'), 'utf8'));
        assert.equal(data.packets, 2); // valid HTTP plus fragment; invalid header rejected
        assert.ok(data.flows.some(flow => flow.src_ip === '10.0.0.9' && flow.src_port === 0));
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('unsupported PCAP link types fail explicitly', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-linktype-'));
    try {
        const input = path.join(dir, 'unsupported.pcap');
        const pcap = fixturePcap();
        pcap.writeUInt32LE(101, 20); // raw IP, not Ethernet
        fs.writeFileSync(input, pcap);
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /Unsupported PCAP link type/);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('TLS ClientHello SNI is recorded as direct flow evidence', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-tls-'));
    try {
        const input = path.join(dir, 'tls.pcap');
        fs.writeFileSync(input, tlsFixturePcap());
        fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] }));
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const data = JSON.parse(fs.readFileSync(path.join(dir, 'output.json'), 'utf8'));
        assert.ok(data.flows.some(flow => flow.domain === 'github.com' && flow.method === 'TLS SNI' && flow.confidence === 'high'));
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('DNS query is retained when the domain maps to a known application', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-dns-'));
    try {
        const input = path.join(dir, 'dns.pcap');
        fs.writeFileSync(input, dnsFixturePcap());
        fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] }));
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const data = JSON.parse(fs.readFileSync(path.join(dir, 'output.json'), 'utf8'));
        assert.ok(data.dns.includes('github.com'));
        assert.ok(data.flows.some(flow => flow.domain === 'github.com' && flow.method === 'DNS Query'));
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('application evidence retains multiple websites observed through one reused DNS flow', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-dns-reuse-'));
    try {
        const input = path.join(dir, 'dns-reuse.pcap');
        const first = dnsFixturePcap('youtube.com');
        const second = dnsFixturePcap('small-independent-site.example');
        fs.writeFileSync(input, Buffer.concat([first, second.subarray(24)]));
        fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] }));
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const data = JSON.parse(fs.readFileSync(path.join(dir, 'output.json'), 'utf8'));
        assert.equal(data.applications.YouTube, 1);
        assert.equal(data.applications['small-independent-site.example'], 1);
        assert.equal(data.domains['youtube.com'], 1);
        assert.equal(data.domains['small-independent-site.example'], 1);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});

test('short brand domains do not match inside unrelated hostnames', { skip: !fs.existsSync(executable) && 'Build PacketInspector first' }, () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-domain-boundary-'));
    try {
        const input = path.join(dir, 'microsoft.pcap');
        fs.writeFileSync(input, tlsFixturePcap('mobile.events.data.microsoft.com'));
        fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] }));
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 10000 });
        assert.equal(result.status, 0, result.stderr || result.stdout);
        const data = JSON.parse(fs.readFileSync(path.join(dir, 'output.json'), 'utf8'));
        assert.equal(data.applications.Microsoft, 1);
        assert.equal(data.applications['Twitter/X'], undefined);
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
});
