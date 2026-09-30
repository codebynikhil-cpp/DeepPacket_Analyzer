// Reproducible offline throughput baseline. The synthetic capture repeats one
// HTTP flow, so this measures parser throughput rather than classification mix.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { spawnSync } = require('node:child_process');

const executable = require('./engine-path');
if (!fs.existsSync(executable)) throw new Error('Build PacketInspector in build/ first');

const payload = Buffer.from('GET / HTTP/1.1\r\nHost: github.com\r\n\r\n');
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
tcp.writeUInt16BE(49152, 0);
tcp.writeUInt16BE(80, 2);
tcp[12] = 0x50;
const packet = Buffer.concat([ethernet, ip, tcp, payload]);
const recordHeader = Buffer.alloc(16);
recordHeader.writeUInt32LE(packet.length, 8);
recordHeader.writeUInt32LE(packet.length, 12);
const record = Buffer.concat([recordHeader, packet]);
const globalHeader = Buffer.alloc(24);
globalHeader.writeUInt32LE(0xa1b2c3d4, 0);
globalHeader.writeUInt16LE(2, 4);
globalHeader.writeUInt16LE(4, 6);
globalHeader.writeUInt32LE(65535, 16);
globalHeader.writeUInt32LE(1, 20);

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-benchmark-'));
try {
    fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] }));
    console.log(JSON.stringify({ platform: process.platform, arch: process.arch, node: process.version, benchmark: 'repeated HTTP flow' }));
    for (const count of [1000, 10000, 50000]) {
        const input = path.join(dir, `${count}.pcap`);
        fs.writeFileSync(input, Buffer.concat([globalHeader, ...Array(count).fill(record)]));
        const start = performance.now();
        const result = spawnSync(executable, ['--pcap', input], { cwd: dir, encoding: 'utf8', timeout: 120000 });
        const elapsedMs = performance.now() - start;
        if (result.status !== 0) throw new Error(result.stderr || result.stdout || `Exit ${result.status}`);
        const data = JSON.parse(fs.readFileSync(path.join(dir, 'output.json'), 'utf8'));
        if (data.packets !== count) throw new Error(`Expected ${count} packets, got ${data.packets}`);
        console.log(JSON.stringify({ packets: count, elapsed_ms: Math.round(elapsedMs), packets_per_second: Math.round(count * 1000 / elapsedMs), processing_drops: data.processing_drops }));
    }
} finally {
    const resolved = fs.realpathSync(dir);
    if (path.dirname(resolved) !== fs.realpathSync(os.tmpdir())) throw new Error('Unexpected benchmark temporary path');
    fs.rmSync(resolved, { recursive: true, force: true });
}
