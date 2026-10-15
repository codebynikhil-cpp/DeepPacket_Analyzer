const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');

async function capture() {
    const outDir = path.resolve(__dirname, '../research_paper');
    if (!fs.existsSync(outDir)) {
        fs.mkdirSync(outDir, { recursive: true });
    }

    const browser = await chromium.launch({ channel: 'msedge', headless: true });
    const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });

    console.log('Navigating to http://127.0.0.1:3001 ...');
    await page.goto('http://127.0.0.1:3001', { waitUntil: 'networkidle' });
    await page.waitForTimeout(1500);

    // 1. WebDashboard.png - Full Overview
    const webDashPath = path.join(outDir, 'WebDashboard.png');
    await page.screenshot({ path: webDashPath, fullPage: false });
    console.log('Saved:', webDashPath);

    // 2. ThroughputChart.png - Focus on timeline / chart panel
    const chartPanel = await page.$('.timeline-panel');
    const chartPath = path.join(outDir, 'ThroughputChart.png');
    if (chartPanel) {
        await chartPanel.screenshot({ path: chartPath });
        console.log('Saved:', chartPath);
    } else {
        await page.screenshot({ path: chartPath });
    }

    // 3. ResultsDashboard.png - Packet Explorer or Connections view
    console.log('Navigating to Packets view...');
    await page.click('a[href="#packets"]');
    await page.waitForTimeout(1500);

    // If there is a table row, click to open inspector modal if possible
    const firstRow = await page.$('#packetTable tbody tr');
    if (firstRow) {
        await firstRow.click();
        await page.waitForTimeout(600);
    }

    const resultsDashPath = path.join(outDir, 'ResultsDashboard.png');
    await page.screenshot({ path: resultsDashPath, fullPage: false });
    console.log('Saved:', resultsDashPath);

    await browser.close();
    console.log('Dashboard screenshots successfully generated!');
}

capture().catch(err => {
    console.error('Error during capture:', err);
    process.exit(1);
});
