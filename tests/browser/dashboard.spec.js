const { test, expect } = require('@playwright/test');
const fs = require('node:fs');

test('overview renders measured charts and an interactive communication graph without browser errors', async ({ page }) => {
    const errors = [];
    page.on('pageerror',error => errors.push(error.message));
    page.on('console',message => { if (message.type() === 'error') errors.push(message.text()); });
    const requests = [];
    page.on('request',request => requests.push(request.url()));
    await page.goto('/');
    await expect(page.locator('#kpiPackets')).toHaveText('900');
    await expect(page.locator('#modeBadge')).toHaveText('OFFLINE CAPTURE');
    await expect(page.locator('#throughputEmpty')).toBeHidden();
    await expect(page.locator('#sizeEmpty')).toBeHidden();
    expect(await page.locator('.graph-node').count()).toBeGreaterThan(1);
    expect(await page.evaluate(() => Chart.getChart('throughputChart').data.datasets[0].data.length)).toBeGreaterThan(10);
    await page.locator('#chartMetric').selectOption('bytes');
    await expect(page.locator('#timelineSubtitle')).toHaveText('bytes in visible interval');
    await page.locator('#chartRange').selectOption('60');
    expect(await page.evaluate(() => Chart.getChart('throughputChart').data.datasets[0].data.length)).toBeLessThanOrEqual(60);
    await page.locator('#zoomIn').click();
    await expect(page.locator('#graphViewport')).toHaveAttribute('transform',/scale\(1.2\)/);
    await page.locator('#resetGraph').click();
    await expect(page.locator('#graphViewport')).toHaveAttribute('transform',/scale\(1\)/);
    fs.mkdirSync('artifacts',{recursive:true});
    await page.screenshot({path:'artifacts/overview-desktop.png',fullPage:true});
    const snapshotDownload = page.waitForEvent('download');
    await page.locator('#exportSnapshot').click();
    const snapshot = JSON.parse(fs.readFileSync(await (await snapshotDownload).path(),'utf8'));
    expect(snapshot.packets).toBe(900);
    expect(snapshot.analysis.recent_packets).toHaveLength(300);
    const host = page.locator('.graph-node').first();
    const ip = await host.getAttribute('data-ip');
    await host.click();
    await expect(page.locator('#packetIp')).toHaveValue(ip);
    await page.locator('.nav-link[href="#overview"]').click();
    await page.locator('#protoStats [data-protocol="UDP"]').click();
    await expect(page.locator('#packets')).toBeVisible();
    await expect(page.locator('#packetProtocol')).toHaveValue('UDP');
    expect(await page.locator('#packetsTbody tr').count()).toBeLessThanOrEqual(25);
    expect(requests.every(url => url.startsWith('http://127.0.0.1:3101'))).toBe(true);
    expect(errors).toEqual([]);
});

test('packet filters, pagination, sorting, details and CSV export operate on retained engine records', async ({ page }) => {
    await page.goto('/#packets');
    await expect(page.locator('#packetCount')).toHaveText('300 retained');
    await expect(page.locator('#packetsTbody tr')).toHaveCount(25);
    await page.locator('#packetNext').click();
    await expect(page.locator('#packetPage')).toHaveText('2 / 12');
    await page.locator('#packetProtocol').selectOption('TCP');
    await page.locator('#packetPort').fill('80');
    await page.locator('#packetSearch').fill('github.com');
    await expect(page.locator('#packetsTbody tr').first()).toContainText('github.com');
    expect(await page.locator('#packetsTbody tr').count()).toBeGreaterThan(0);
    await page.locator('[data-sort="length"]').click();
    await expect(page.locator('[data-sort="length"]').locator('..')).toHaveAttribute('aria-sort','ascending');
    await page.locator('#packetsTbody button').first().click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.locator('#inspectorBody')).toContainText('Time to live');
    await expect(page.locator('#inspectorBody')).toContainText('github.com');
    await expect(page.locator('#inspectorBody')).toContainText('Sequence number');
    await page.screenshot({path:'artifacts/packet-inspector.png'});
    await page.keyboard.press('Escape');
    await expect(page.getByRole('dialog')).toBeHidden();
    const pendingDownload = page.waitForEvent('download');
    await page.locator('#exportPackets').click();
    const download = await pendingDownload;
    const csv = fs.readFileSync(await download.path(),'utf8');
    expect(csv).toContain('timestamp_us,src_ip');
    expect(csv).toContain('github.com');
    expect(csv).not.toContain('example.com');
    await page.locator('#clearPacketFilters').click();
    await page.locator('#packetIp').fill('203.0.113.250');
    await expect(page.locator('#packetsTbody')).toContainText('No packets match');
    await page.locator('#clearPacketFilters').click();
    await page.locator('#packetTime').selectOption('10');
    await expect(page.locator('#packetPageInfo')).not.toContainText('of 300');
    await page.keyboard.press('Control+k');
    await expect(page.locator('#packetSearch')).toBeFocused();
});

test('flow evidence connects to the related packet filter and every navigation view opens', async ({ page }) => {
    await page.goto('/#flows');
    await expect(page.locator('#flowsTbody button').first()).toBeVisible();
    await page.locator('#flowsTbody button').first().click();
    await expect(page.locator('#inspectorBody')).toContainText('Classification evidence');
    await page.locator('#relatedPackets').click();
    await expect(page.locator('#flowFilterBanner')).toBeVisible();
    await expect(page.locator('#packets')).toBeVisible();
    for (const id of ['apps','domains','traffic','alerts','diagnostics','health']) {
        await page.locator(`.nav-link[href="#${id}"]`).click();
        await expect(page.locator(`#${id}`)).toBeVisible();
    }
    await expect(page.locator('#healthGrid')).toContainText('No websites configured');
});

test('rules show authentication errors and save/delete feedback through the real API', async ({ page }) => {
    await page.goto('/#rules');
    await page.locator('#ruleValue').fill('*.ui-test.example.com');
    await page.locator('#ruleToken').fill('incorrect-test-token');
    await page.locator('#saveRule').click();
    await expect(page.locator('#ruleMessage')).toContainText('Rule token required or incorrect');
    await page.locator('#ruleToken').fill('browser-test-token');
    await page.locator('#saveRule').click();
    await expect(page.locator('#domainRules')).toContainText('*.ui-test.example.com');
    await expect(page.locator('#rulesState')).toContainText('waiting for the engine');
    await page.getByRole('button',{name:'Remove domain rule *.ui-test.example.com',exact:true}).click();
    await expect(page.locator('#domainRules')).not.toContainText('*.ui-test.example.com');
});

test('pause, resume, stale data and unavailable data have distinct states', async ({ page, request }) => {
    const data = await (await request.get('/data')).json();
    let packets = data.packets;
    await page.route('**/data',route => route.fulfill({json:{...data,packets,status:'live',engine_state:'running',mode:'live',generated_at:new Date().toISOString()}}));
    await page.goto('/');
    await expect(page.locator('#modeBadge')).toHaveText('LIVE CAPTURE');
    await page.locator('#pauseUpdates').click();
    packets += 10;
    await page.waitForTimeout(1300);
    await expect(page.locator('#kpiPackets')).toHaveText('900');
    await expect(page.locator('#statusBanner')).toContainText('capture continues');
    await page.locator('#pauseUpdates').click();
    await expect(page.locator('#kpiPackets')).toHaveText('910');
    await page.unroute('**/data');
    await page.route('**/data',route => route.fulfill({json:{...data,status:'stale'}}));
    await expect(page.locator('#modeBadge')).toHaveText('TELEMETRY STALE');
    await page.unroute('**/data');
    await page.route('**/data',route => route.fulfill({status:503,json:{error:'No valid engine telemetry',status:'unavailable'}}));
    await expect(page.locator('#statusBanner')).toContainText('Previously received data');
    await expect(page.locator('#modeBadge')).toHaveText('DATA UNAVAILABLE');
});

test('old snapshots and unavailable charts keep the rest of the workspace usable', async ({ page, request }) => {
    const data = await (await request.get('/data')).json();
    delete data.analysis;
    await page.route('**/data',route => route.fulfill({json:data}));
    await page.route('**/vendor/chart.js',route => route.fulfill({status:200,contentType:'application/javascript',body:'/* library intentionally unavailable in this test */'}));
    await page.goto('/');
    await expect(page.locator('#kpiPackets')).toHaveText('900');
    await expect(page.locator('#throughputEmpty')).toContainText('Chart library unavailable');
    await page.locator('.nav-link[href="#packets"]').click();
    await expect(page.locator('#packetsTbody')).toContainText('Packet metadata is not in this snapshot');
});

test('desktop, tablet and mobile layouts avoid horizontal page overflow', async ({ page }) => {
    for (const width of [1440,1024,768,390,360]) {
        await page.setViewportSize({width,height:900});
        await page.goto('/');
        await expect(page.locator('#kpiPackets')).toHaveText('900');
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),`Overview overflow at ${width}px`).toBe(true);
        await page.goto('/#packets');
        await expect(page.locator('#packetCount')).toHaveText('300 retained');
        expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),`Packet explorer overflow at ${width}px`).toBe(true);
        if (width === 390) await page.screenshot({path:'artifacts/packets-mobile.png',fullPage:true});
    }
});
