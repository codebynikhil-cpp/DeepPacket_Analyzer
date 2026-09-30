const { defineConfig } = require('@playwright/test');
module.exports = defineConfig({
    testDir:'./tests/browser',
    fullyParallel:false,
    workers:1,
    timeout:30000,
    reporter:'list',
    use:{
        baseURL:'http://127.0.0.1:3101',
        channel:process.env.DPA_BROWSER || (process.platform === 'win32' ? 'chrome' : undefined),
        viewport:{ width:1440, height:1050 },
        screenshot:'only-on-failure',
        trace:'retain-on-failure'
    },
    webServer:{ command:'node scripts/ui-test-server.js', url:'http://127.0.0.1:3101', timeout:60000, reuseExistingServer:false }
});
