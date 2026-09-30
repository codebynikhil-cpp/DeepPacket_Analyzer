import { $, text, html, escapeHtml as esc, number, compact, bytes, duration, renderIcons, getJson, toast, download } from './js/dom.js';
import { TrafficCharts } from './js/charts.js';
import { Inspector, PacketExplorer, FlowExplorer } from './js/explorer.js';
import { NetworkGraph } from './js/network.js';
import { RulesPanel } from './js/rules.js';

renderIcons();
const pages = {
    overview:['Overview','Network overview','A clear view of every observed connection.'],
    packets:['Packet explorer','Packet explorer','Inspect the frames behind your network activity.'],
    flows:['Connections','Connection intelligence','Follow a connection from observation to classification.'],
    apps:['Applications','Application intelligence','Understand the applications behind observed traffic.'],
    domains:['Domains','Domain activity','Explore the names your network communicates with.'],
    traffic:['DNS & HTTP','Visible application traffic','Inspect the names and requests observed in your capture.'],
    rules:['Firewall rules','Traffic policy','Manage block rules and verify their loading state.'],
    health:['Website health','Service availability','Reachability checks from this computer.'],
    alerts:['Alerts','Events to investigate','Review signals in the observed traffic.'],
    diagnostics:['Diagnostics','Engine diagnostics','Understand capture health, data scope, and limitations.']
};
let currentView = 'overview', latest = null, paused = false, sample = null, lastSignature = null;
let healthRunning = false;
const inspector = new Inspector(flow => navigatePackets({ flow }));
const packets = new PacketExplorer(inspector);
const flows = new FlowExplorer(inspector);
const charts = new TrafficCharts(protocol => navigatePackets({ protocol }));
const network = new NetworkGraph(ip => navigatePackets({ ip }), flow => inspector.connection(flow));
const rules = new RulesPanel();

function navigate(view) {
    if (location.hash === `#${view}`) showView(view);
    else location.hash = view;
}
function navigatePackets(filter) { packets.filter(filter); navigate('packets'); }
function showView(view) {
    const requested = view || location.hash.slice(1);
    currentView = requested === 'protocols' ? 'overview' : Object.hasOwn(pages, requested) ? requested : 'overview';
    document.querySelectorAll('.view').forEach(section => { section.hidden = section.id !== currentView; });
    document.querySelectorAll('.nav-link').forEach(link => {
        const active = link.hash === `#${currentView}`;
        link.classList.toggle('active', active);
        if (active) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
        link.title = link.textContent.trim();
    });
    const [label, title, description] = pages[currentView];
    text('breadcrumbCurrent', label);
    html('pageTitle', `${esc(title)}<span class="title-dot">.</span>`);
    text('pageDescription', description);
    document.title = `${label} \u00b7 DeepPacket Analyzer`;
    if (currentView === 'overview') requestAnimationFrame(() => charts.resize());
    if (currentView === 'health') fetchHealth();
    window.scrollTo({ top:0, behavior:'instant' });
}
window.addEventListener('hashchange', () => showView());
document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && !$('inspector').open) {
        event.preventDefault(); navigate('packets'); requestAnimationFrame(() => $('packetSearch').focus());
    }
});

function banner(message, info = false) {
    $('statusBanner').hidden = !message;
    $('statusBanner').classList.toggle('info', info);
    text('statusBanner', message);
}
function updateStatus(data) {
    const status = data.status || 'stale';
    const labels = { live:'LIVE CAPTURE', offline:data.mode === 'live' ? 'CAPTURE STOPPED' : 'OFFLINE CAPTURE', stale:'TELEMETRY STALE', unavailable:'UNAVAILABLE' };
    text('modeBadge', labels[status] || 'STATUS UNKNOWN');
    $('modeBadge').className = `status-tag ${status === 'live' ? 'live' : status === 'stale' ? 'stale' : ''}`;
    $('sidebarDot').className = `status-dot ${status}`;
    text('statusText', status === 'live' ? 'Capture live' : status === 'offline' ? 'Saved capture' : 'Telemetry stale');
    text('apiStatus', paused ? 'Updates paused' : 'API connected');
    $('apiStatus').classList.add('connected');
    const source = String(data.source_name || 'Source not available');
    text('sourceName', source.split(/[\\/]/).pop());
    $('sourceName').title = source;
    const generated = Date.parse(data.generated_at);
    text('lastUpdate', Number.isFinite(generated) ? `Snapshot ${new Date(generated).toLocaleTimeString()} \u00b7 ${new Date(generated).toLocaleDateString()}` : 'Snapshot time unavailable');
    if (paused) banner('Dashboard updates are paused. Packet capture continues in the engine. Resume to see the latest data.', true);
    else if (data.data_source === 'synthetic_fixture') banner('Synthetic demonstration capture. All values were computed by the engine from generated test frames; this is not a recording of a real network.', true);
    else if (status === 'live') banner('');
    else if (status === 'offline') banner(data.mode === 'live' ? 'Capture has stopped. Showing the last saved snapshot.' : 'Offline capture \u00b7 showing analyzed file data. The timeline uses timestamps from the capture.', true);
    else banner('The engine is not reporting fresh telemetry. Showing the last saved data; rates and enforcement state are unavailable.');
    text('kpiWfpStatus', status === 'live' ? data.wfp?.active ? 'Active \u00b7 IPv4' : data.protection_requested ? data.wfp?.status || 'Protection unavailable' : 'Monitor only' : 'Not live');
}
function updateRate(data) {
    const time = Date.parse(data.generated_at);
    const session = data.session_id || data.source_name;
    let rate = null;
    const reset = !sample || sample.session !== session || data.packets < sample.packets;
    if (data.status === 'live' && sample?.session === session && time > sample.time && data.packets >= sample.packets) rate = (data.packets - sample.packets) * 1000 / (time - sample.time);
    if (Number.isFinite(time) && (!sample || sample.session !== session || time > sample.time || data.packets < sample.packets)) sample = { time, packets:data.packets, session };
    if (data.status !== 'live') { text('kpiRate','\u2014'); text('kpiRateSub','Available during live capture'); }
    else if (rate !== null) { text('kpiRate', `${compact(Math.round(rate))}/s`); text('kpiRateSub','Between engine snapshots'); }
    else if (reset) { text('kpiRate','\u2014'); text('kpiRateSub','Waiting for a second sample'); }
}
function renderTalkers(analysis) {
    const entries = (analysis?.top_talkers || []).slice(0,6);
    const maximum = Math.max(1, ...entries.map(item => item.sent_bytes + item.received_bytes));
    html('topTalkers', entries.length ? entries.map((item, index) => `<button class="talker" type="button" data-ip="${esc(item.ip)}" title="Sent: ${number(item.sent_packets)} packets, ${bytes(item.sent_bytes)}. Received: ${number(item.received_packets)} packets, ${bytes(item.received_bytes)}."><span class="talker-top"><span class="talker-ip"><span class="rank">${String(index + 1).padStart(2,'0')}</span>${esc(item.ip)}</span><span class="talker-volume">${bytes(item.sent_bytes + item.received_bytes)}</span></span><span class="talker-track"><span class="talker-fill" style="width:${(item.sent_bytes + item.received_bytes) / maximum * 100}%"></span></span></button>`).join('') : '<p class="empty-inline">No endpoint totals available.<br>Run the updated engine to measure traffic.</p>');
    const ports = (analysis?.ports || []).slice(0,6);
    const maxCount = Math.max(1, ...ports.map(item => item.source_packets + item.destination_packets));
    html('portActivity', ports.length ? ports.map(item => `<button class="port-row" type="button" data-port="${item.port}" data-protocol="${esc(item.protocol)}" title="${number(item.source_packets)} source observations \u00b7 ${number(item.destination_packets)} destination observations"><span>${esc(item.protocol)} <b>${item.port}</b></span><span class="port-track"><span style="width:${(item.source_packets + item.destination_packets) / maxCount * 100}%"></span></span><span>${compact(item.source_packets + item.destination_packets)} pkts</span></button>`).join('') : '<p class="empty-inline">No measured port activity yet.</p>');
}
$('topTalkers').addEventListener('click', event => { const button = event.target.closest('[data-ip]'); if (button) navigatePackets({ ip:button.dataset.ip }); });
$('portActivity').addEventListener('click', event => { const button = event.target.closest('[data-port]'); if (button) navigatePackets({ port:button.dataset.port, protocol:button.dataset.protocol }); });

// Paginate classifications too: large captures can contain thousands of names.
const rankings = {};
for (const kind of ['apps','domains']) {
    const panel = $(kind).querySelector('.panel');
    const controls = document.createElement('div'); controls.className = 'filter-bar';
    controls.innerHTML = `<label class="search-field"><input id="${kind}Search" type="search" placeholder="Search ${kind}..." aria-label="Search ${kind}"></label>`;
    panel.querySelector('.panel-head').after(controls);
    const footer = document.createElement('div'); footer.className = 'table-footer';
    footer.innerHTML = `<span id="${kind}PageInfo"></span><div class="pagination"><button class="icon-button" type="button" id="${kind}Prev" aria-label="Previous ${kind} page">&larr;</button><span id="${kind}Page"></span><button class="icon-button" type="button" id="${kind}Next" aria-label="Next ${kind} page">&rarr;</button></div>`;
    panel.append(footer);
    rankings[kind] = { page:0, values:{} };
    $(`${kind}Search`).addEventListener('input', () => { rankings[kind].page = 0; renderRanking(kind); });
    $(`${kind}Prev`).addEventListener('click', () => { rankings[kind].page--; renderRanking(kind); });
    $(`${kind}Next`).addEventListener('click', () => { rankings[kind].page++; renderRanking(kind); });
    $(`${kind}Tbody`).addEventListener('click', event => {
        const button = event.target.closest('[data-flow-query]');
        if (button) { $('flowSearch').value = button.dataset.flowQuery; $('flowProtocol').value = 'all'; $('flowPolicy').value = 'all'; flows.page = 0; flows.render(); navigate('flows'); }
    });
}
function renderRanking(kind, values) {
    const state = rankings[kind]; if (values) state.values = values;
    const all = Object.entries(state.values).filter(([,count]) => Number.isFinite(count)).sort((a,b) => b[1] - a[1]);
    const total = all.reduce((sum,[,count]) => sum + count, 0);
    const query = $(`${kind}Search`).value.toLowerCase();
    const filtered = all.filter(([name]) => name.toLowerCase().includes(query));
    const pages = Math.max(1, Math.ceil(filtered.length / 25));
    state.page = Math.max(0, Math.min(state.page, pages - 1));
    const visible = filtered.slice(state.page * 25,state.page * 25 + 25);
    text(kind === 'apps' ? 'appBadge' : 'domainBadge', `${all.length} ${kind}`);
    text(`${kind}PageInfo`, `${filtered.length} matching names \u00b7 share of ${number(total)} classification observations`);
    text(`${kind}Page`, `${state.page + 1} / ${pages}`);
    $(`${kind}Prev`).disabled = state.page === 0; $(`${kind}Next`).disabled = state.page + 1 >= pages;
    html(`${kind}Tbody`, visible.length ? visible.map(([name,count],i) => `<tr><td class="mono dim">${String(state.page * 25 + i + 1).padStart(2,'0')}</td><td><button type="button" class="text-link ${kind === 'domains' ? 'mono' : ''}" data-flow-query="${esc(name)}">${esc(name)}</button></td><td class="number mono">${number(count)}</td><td class="mono dim">${total ? (count / total * 100).toFixed(1) : 0}%</td><td style="width:32%"><div class="share-track"><span style="width:${total ? count / total * 100 : 0}%"></span></div></td></tr>`).join('') : '<tr><td colspan="5" class="table-empty">No matching classification data.</td></tr>');
}
function renderEvents(data) {
    text('dnsPill', data.dns?.length || 0); text('httpPill', data.http?.length || 0);
    html('dnsList', data.dns?.length ? data.dns.map(name => `<li><span class="protocol-badge udp">DNS</span><span class="event-text">${esc(name)}</span></li>`).join('') : '<li class="empty-inline">No DNS names observed.</li>');
    html('httpList', data.http?.length ? data.http.map(request => { const split = request.indexOf(' '); return `<li><span class="protocol-badge tcp">${esc(split > 0 ? request.slice(0,split) : 'HTTP')}</span><span class="event-text">${esc(split > 0 ? request.slice(split + 1) : request)}</span></li>`; }).join('') : '<li class="empty-inline">No visible HTTP requests observed.</li>');
    const alerts = Array.isArray(data.alerts) ? data.alerts : [];
    text('alertsBadge', `${alerts.length} events`); text('alertNavBadge', alerts.length); $('alertNavBadge').hidden = !alerts.length;
    html('alertsList', alerts.length ? alerts.map(message => `<li><span class="decision match">REVIEW</span><span class="event-text">${esc(message)}</span></li>`).join('') : '<li class="empty-inline">No heuristic events in this snapshot. This does not establish that the traffic is safe.</li>');
}
function renderDiagnostics(data) {
    const fields = [['Capture mode',data.mode || 'Unknown'],['Source',data.source_name || 'Unknown'],['Snapshot state',data.status || 'Unknown'],['Engine state',data.engine_state || 'Unknown'],['Session',data.session_id || 'Legacy snapshot'],['Capture drops',number(data.capture_drops)],['Queue drops',number(data.processing_drops)],['Parse errors',number(data.parse_errors)],['Queue depth',number(data.queue_size)],['Peak queue depth',number(data.max_queue_depth)],['WFP reported state',data.wfp?.status || 'Unknown'],['Kernel filters in snapshot',number(data.wfp?.total_filters)],['Endpoint limit reached',data.analysis ? data.analysis.endpoints_limited ? 'Yes \u00b7 partial endpoint statistics' : 'No' : 'Unknown'],['Port limit reached',data.analysis ? data.analysis.ports_limited ? 'Yes \u00b7 partial port statistics' : 'No' : 'Unknown']];
    html('engineDiagnostics',fields.map(([name,value]) => `<dt>${esc(name)}</dt><dd>${esc(value)}</dd>`).join(''));
}
function updateDashboard(data) {
    updateStatus(data);
    updateRate(data);
    // Old snapshots may have no timestamp; their contents form the stable signature.
    const signature = data.generated_at ? `${data.session_id || ''}:${data.generated_at}` : JSON.stringify(data);
    if (signature === lastSignature) { latest = data; renderDiagnostics(data); return; }
    if (latest?.session_id && data.session_id && latest.session_id !== data.session_id) { packets.selected = null; packets.page = 0; flows.page = 0; }
    latest = data;
    lastSignature = signature;
    text('kpiPackets',number(data.packets)); text('kpiBytes',bytes(data.bytes)); text('kpiConns',number(data.connections)); text('kpiDropped',number(data.dropped));
    text('kpiCapDrops',number(data.capture_drops)); text('kpiProcDrops',number(data.processing_drops)); text('parseErrors',number(data.parse_errors));
    text('kpiEndpoints',number(data.analysis?.tracked_endpoints));
    text('endpointScope',data.analysis?.endpoints_limited ? 'Limit reached \u00b7 partial inventory' : 'Unique observed addresses');
    text('captureDuration',duration(data.analysis?.capture_duration_ms));
    text('footerScope',data.analysis ? `${data.analysis.recent_packets.length} retained packets \u00b7 ${data.flows?.length || 0} recent flows` : 'Legacy snapshot \u00b7 extended metadata unavailable');
    charts.update(data); network.update(data.flows); packets.update(data); flows.update(data.flows); renderTalkers(data.analysis);
    renderRanking('apps',data.applications || {}); renderRanking('domains',data.domains || {}); renderEvents(data); renderDiagnostics(data);
    $('exportSnapshot').disabled = false;
}
let dataRunning = false;
async function fetchData() {
    if (dataRunning || paused) return;
    dataRunning = true;
    try {
        const data = await getJson('/data',8000);
        if (!paused) updateDashboard(data);
    } catch (error) {
        text('apiStatus','Data unavailable'); $('apiStatus').classList.remove('connected');
        text('statusText','Data unavailable'); $('sidebarDot').className = 'status-dot stale';
        text('modeBadge','DATA UNAVAILABLE'); $('modeBadge').className = 'status-tag stale';
        text('kpiRate','\u2014'); text('kpiWfpStatus','Unknown');
        banner(`${error.message}. ${latest ? 'Previously received data is still displayed.' : 'Start the engine or open a PCAP from the terminal to populate the workspace.'}`);
    } finally { dataRunning = false; }
}
async function pollData() { await fetchData(); setTimeout(pollData, document.hidden ? 3000 : 1000); }
async function pollRules() { await rules.load(); setTimeout(pollRules,5000); }
async function fetchHealth() {
    if (healthRunning || currentView !== 'health') return;
    healthRunning = true;
    try {
        text('healthBadge','Checking...');
        const data = await getJson('/health',60000);
        const sites = Object.values(data.websites || {});
        html('healthGrid',sites.length ? sites.map(site => `<article class="health-card"><div class="health-card-head"><h3>${esc(site.name)}</h3><span class="subtle-badge">${esc(site.category || 'website')}</span></div><p class="health-domain">${esc(site.domain)}</p><div class="health-state ${site.state === 'DOWN' ? 'down' : site.state === 'POLICY MATCH' ? 'policy' : ''}"><strong>${esc(site.state)}</strong><span>${site.latency_ms != null ? `${number(site.latency_ms)} ms` : '\u2014'}</span></div><p class="health-reason">${esc(site.reason || 'HTTPS response received')}</p></article>`).join('') : '<p class="empty-inline">No websites configured in critical_websites.json.</p>');
        text('healthBadge',`Checked ${new Date(data.last_updated).toLocaleTimeString()}`);
    } catch (error) { text('healthBadge','Probe unavailable'); html('healthGrid',`<p class="empty-inline">Website probes could not complete: ${esc(error.message)}</p>`); }
    finally { healthRunning = false; }
}
async function pollHealth() { await fetchHealth(); setTimeout(pollHealth,15000); }
$('pauseUpdates').addEventListener('click', () => {
    paused = !paused; $('pauseUpdates').setAttribute('aria-pressed',String(paused));
    $('pauseUpdates').innerHTML = `<span data-icon="${paused ? 'play' : 'pause'}"></span><span>${paused ? 'Resume updates' : 'Pause updates'}</span>`;
    renderIcons($('pauseUpdates'));
    if (latest) updateStatus(latest);
    if (!paused) { sample = null; text('kpiRate','\u2014'); fetchData(); }
    else banner('Dashboard updates are paused. Packet capture continues in the engine. Resume to see the latest data.',true);
});
$('exportSnapshot').disabled = true;
$('exportSnapshot').addEventListener('click', () => {
    if (!latest) return;
    download(JSON.stringify(latest,null,2),'application/json','deeppacket-snapshot.json');
    toast('Exported the current telemetry snapshot, including its retention limits.');
});
showView();
renderRanking('apps'); renderRanking('domains'); renderEvents({}); renderDiagnostics({});
pollData(); pollRules(); pollHealth();
