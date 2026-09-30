// Isolated browser-test workspace. The user's captures and rules are untouched.
const path = require('node:path');
const { analyzeFixture } = require('../tests/helpers/traffic-fixture');
const directory = path.resolve(__dirname, '../artifacts/ui-fixture');
analyzeFixture(directory);
process.env.DPA_DATA_FILE = path.join(directory, 'output.json');
process.env.DPA_RULES_FILE = path.join(directory, 'rules.json');
process.env.DPA_CRITICAL_FILE = path.join(directory, 'critical_websites.json');
process.env.DPA_RULE_TOKEN = 'browser-test-token';
process.env.DPA_SYNTHETIC_DEMO = '1';
require('../server').app.listen(3101, '127.0.0.1', error => {
    if (error) throw error;
    console.log('Browser test server: http://127.0.0.1:3101 (synthetic PCAP fixture)');
});
