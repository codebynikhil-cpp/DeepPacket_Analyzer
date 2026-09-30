const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const { spawnSync } = require('node:child_process');
const { createTrafficPcap, emptyRules } = require('../tests/helpers/traffic-fixture');
const executable = require('./engine-path');
if (!fs.existsSync(executable)) throw new Error('Build PacketInspector first');
const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-mixed-benchmark-'));
try {
    fs.writeFileSync(path.join(directory, 'rules.json'), JSON.stringify(emptyRules));
    fs.writeFileSync(path.join(directory, 'critical_websites.json'), JSON.stringify({ websites:[] }));
    for (const packets of [10000,100000]) {
        const input = path.join(directory, 'mixed-synthetic.pcap');
        fs.writeFileSync(input, createTrafficPcap(packets));
        const start = performance.now();
        const result = spawnSync(executable, ['--pcap',input], { cwd:directory, encoding:'utf8', timeout:120000, windowsHide:true });
        const elapsed = performance.now() - start;
        if (result.status !== 0) throw new Error(result.stderr || result.stdout);
        const data = JSON.parse(fs.readFileSync(path.join(directory,'output.json')));
        if (data.packets !== packets) throw new Error(`Expected ${packets} packets, received ${data.packets}`);
        console.log(JSON.stringify({ packets, elapsed_ms:Math.round(elapsed), packets_per_second:Math.round(packets * 1000 / elapsed),
            parse_errors:data.parse_errors, retained_packets:data.analysis.recent_packets.length, recent_flows:data.flows.length,
            timeline_seconds:data.analysis.timeline.length, telemetry_bytes:fs.statSync(path.join(directory,'output.json')).size }));
    }
} finally {
    const resolved = fs.realpathSync(directory);
    if (path.dirname(resolved) !== fs.realpathSync(os.tmpdir())) throw new Error('Unexpected benchmark directory');
    fs.rmSync(resolved,{recursive:true,force:true});
}
