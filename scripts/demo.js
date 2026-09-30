const path = require('node:path');
const { analyzeFixture } = require('../tests/helpers/traffic-fixture');
const directory = path.resolve(__dirname, '../artifacts/demo');
const data = analyzeFixture(directory);
process.env.DPA_DATA_FILE = path.join(directory, 'output.json');
process.env.DPA_RULES_FILE = path.join(directory, 'rules.json');
process.env.DPA_CRITICAL_FILE = path.join(directory, 'critical_websites.json');
process.env.DPA_RULE_TOKEN = process.env.DPA_RULE_TOKEN || 'synthetic-demo-only';
process.env.DPA_SYNTHETIC_DEMO = '1';
const port = Number(process.env.DPA_PORT || 3001);
require('../server').app.listen(port, '127.0.0.1', error => {
    if (error) throw error;
    console.log(`Synthetic demonstration: ${data.packets} engine-processed test packets. This is not a real network capture.`);
    console.log(`Open http://127.0.0.1:${port}`);
    console.log(`Rule management token: ${process.env.DPA_RULE_TOKEN}`);
    console.log('Rules and telemetry are isolated in artifacts/demo. Stop with Ctrl+C.');
});
