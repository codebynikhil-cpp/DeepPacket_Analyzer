// Brief monitor-only Npcap check. Pass an interface index from --list-interfaces.
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn } = require('node:child_process');

const index = process.argv[2];
if (!/^[1-9][0-9]*$/.test(index || '')) throw new Error('Usage: npm run smoke:live -- <interface-index>');
const executable = require('./engine-path');
if (!fs.existsSync(executable)) throw new Error('Build PacketInspector first');

const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'deeppacket-live-'));
fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: [], blocked_apps: [], blocked_ports: [] }));
fs.writeFileSync(path.join(dir, 'critical_websites.json'), JSON.stringify({ websites: [] }));

async function run() {
    let output = '';
    const child = spawn(executable, ['--interface', index], { cwd: dir, windowsHide: true });
    child.stdout.on('data', chunk => { output = (output + chunk).slice(-4000); });
    child.stderr.on('data', chunk => { output = (output + chunk).slice(-4000); });
    const exit = new Promise((resolve, reject) => {
        child.once('error', reject);
        child.once('exit', resolve);
    });
    await new Promise(resolve => setTimeout(resolve, 1000));
    const revision = `smoke-${Date.now()}`;
    // Exercise reload in this temporary monitor-only workspace.
    fs.writeFileSync(path.join(dir, 'rules.json'), JSON.stringify({ blocked_ips: [], blocked_domains: ['*.capture-test.invalid'], blocked_apps: [], blocked_ports: [] }));
    fs.writeFileSync(path.join(dir, 'rules_revision.txt'), revision);
    fs.writeFileSync(path.join(dir, 'rules_reload.flag'), revision);
    await new Promise(resolve => setTimeout(resolve, 4000));
    child.kill();
    await exit;
    const telemetry = path.join(dir, 'output.json');
    if (!fs.existsSync(telemetry)) throw new Error(`No live telemetry produced. Engine output:\n${output}`);
    const data = JSON.parse(fs.readFileSync(telemetry, 'utf8'));
    if (data.mode !== 'live') throw new Error(`Unexpected mode: ${data.mode}`);
    if (!Array.isArray(data.analysis?.recent_packets) || data.analysis.recent_packets.length > 300)
        throw new Error('Live packet metadata is unavailable or exceeded its limit');
    const acknowledged = fs.readFileSync(path.join(dir, 'rules_applied.txt'), 'utf8') === revision;
    if (!acknowledged) throw new Error('Engine did not acknowledge the saved rule revision');
    console.log(JSON.stringify({ interface_index: index, mode: data.mode, packets: data.packets,
        capture_drops: data.capture_drops, processing_drops: data.processing_drops,
        parse_errors: data.parse_errors, retained_packets: data.analysis.recent_packets.length,
        rule_reload_acknowledged: acknowledged, generated_at: data.generated_at, wfp_active: data.wfp?.active }));
}

run().catch(error => { console.error(error.message); process.exitCode = 1; }).finally(() => {
    const resolved = fs.realpathSync(dir);
    if (path.dirname(resolved) !== fs.realpathSync(os.tmpdir())) throw new Error('Unexpected smoke-test temporary path');
    fs.rmSync(resolved, { recursive: true, force: true });
});
