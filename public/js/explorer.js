import { $, html, text, escapeHtml as esc, number, bytes, captureTime, fullTime, endpoint, protocolBadge, download, toast } from './dom.js';

const empty = (columns, title, description = '') => `<tr><td colspan="${columns}" class="table-empty"><strong>${esc(title)}</strong>${esc(description)}</td></tr>`;
const matchesProtocol = (actual, selected) => selected === 'all' || actual === selected || (selected === 'ICMP' && actual === 'ICMPv6') || (selected === 'Other' && !['TCP','UDP','ICMP','ICMPv6','ARP'].includes(actual));
const decision = policy => policy === 'DROP' ? '<span class="decision match">Rule matched</span>' : '<span class="decision pass">No match</span>';
const detailFields = fields => `<dl class="detail-fields">${fields.map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value ?? 'Not available')}</dd>`).join('')}</dl>`;
const group = (title, fields, open = true) => `<details${open ? ' open' : ''}><summary>${esc(title)}</summary>${detailFields(fields)}</details>`;

export class Inspector {
    constructor(onRelated) {
        this.onRelated = onRelated;
        $('closeInspector').addEventListener('click', () => $('inspector').close());
        $('inspector').addEventListener('close', () => {
            if (this.returnFocus?.isConnected) this.returnFocus.focus();
            else if (!$('packets').hidden) $('packetSearch').focus();
            else $('main').focus();
        });
        $('inspector').addEventListener('click', event => { if (event.target === $('inspector') && event.clientX < $('inspector').getBoundingClientRect().left) $('inspector').close(); });
        $('relatedPackets').addEventListener('click', () => { $('inspector').close(); onRelated(this.flow); });
    }
    show() { if (!$('inspector').open) { this.returnFocus = document.activeElement; $('inspector').showModal(); } }
    packet(packet) {
        if (!packet) return;
        text('inspectorType', 'PACKET INSPECTION');
        text('inspectorTitle', `Packet #${number(packet.id)}`);
        $('relatedPackets').hidden = true;
        const ip = packet.ip_version != null;
        html('inspectorBody', `<div class="inspector-summary">${protocolBadge(packet.protocol)} ${decision(packet.policy)}<p class="endpoints">${esc(endpoint(packet.src_ip || packet.src_mac, packet.src_port))}<br><span class="arrow">→</span>${esc(endpoint(packet.dst_ip || packet.dst_mac, packet.dst_port))}</p></div>` +
            group('Frame', [['Packet number', packet.id], ['Captured at (UTC)', fullTime(packet.timestamp_us)], ['Original length', bytes(packet.length)], ['Captured length', bytes(packet.captured_length)], ['Capture truncated', packet.captured_length < packet.length ? 'Yes' : 'No']]) +
            group('Ethernet', [['Source MAC', packet.src_mac], ['Destination MAC', packet.dst_mac], ['EtherType', packet.ether_type == null ? null : `0x${Number(packet.ether_type).toString(16).padStart(4, '0')}`]], false) +
            (ip ? group(`Internet Protocol v${packet.ip_version}`, [['Source address', packet.src_ip], ['Destination address', packet.dst_ip], [packet.ip_version === 6 ? 'Hop limit' : 'Time to live', packet.ttl], ['Protocol number', packet.protocol_number], ['Later fragment', packet.fragment ? 'Yes · transport header unavailable' : 'No']]) : '') +
            (packet.src_port != null ? group(packet.protocol === 'TCP' ? 'Transmission Control Protocol' : 'User Datagram Protocol', [['Source port', packet.src_port], ['Destination port', packet.dst_port], ...(packet.protocol === 'TCP' ? [['Flags', packet.tcp_flags], ['Sequence number', packet.sequence], ['Acknowledgment', packet.acknowledgment]] : [])]) : '') +
            group('Application & payload metadata', [['Application classification', packet.application || 'Unknown'], ['Classification method', packet.method || 'Not available'], ['Directly observed name', packet.domain || 'Not observed on this packet'], ['Information', packet.info], ['Payload length', bytes(packet.payload_length)], ['Rule decision', packet.policy === 'DROP' ? 'Matched a saved rule' : 'No matching rule']]) +
            '<p class="inspector-note">Payload content is not retained in dashboard telemetry. Port-based labels are heuristics; flow inspection shows the available classification evidence. A rule match does not prove Windows denied this packet.</p>');
        this.show();
    }
    connection(flow) {
        if (!flow) return;
        this.flow = flow;
        text('inspectorType', 'CONNECTION EVIDENCE');
        text('inspectorTitle', flow.application || flow.protocol || 'Connection');
        $('relatedPackets').hidden = false;
        html('inspectorBody', `<div class="inspector-summary">${protocolBadge(flow.protocol)} ${decision(flow.policy)}<p class="endpoints">${esc(endpoint(flow.src_ip, flow.src_port))}<br><span class="arrow">→</span>${esc(endpoint(flow.dst_ip, flow.dst_port))}</p></div>` +
            group('Observed flow', [['First seen (UTC)', fullTime(flow.first_seen_us)], ['Last seen (UTC)', fullTime(flow.last_seen_us)], ['Packets', number(flow.packets)], ['Frame bytes', bytes(flow.bytes)]]) +
            group('Classification evidence', [['Domain', flow.domain || 'Unknown'], ['Application', flow.application || 'Unknown'], ['Method', flow.method || 'Unknown'], ['Evidence strength', flow.confidence || 'Not available']]) +
            group('Policy & enforcement', [['Rule decision', flow.policy === 'DROP' ? 'Rule matched' : 'No rule matched'], ['Matching rule', flow.policy_reason || 'None'], ['WFP state when observed', flow.enforcement || 'Unknown']]) +
            '<p class="inspector-note">Evidence strength is qualitative. DNS correlation infers a domain from an observed DNS answer. WFP active describes engine state; individual Windows connection denials are not measured here.</p>');
        this.show();
    }
}

export class PacketExplorer {
    constructor(inspector) {
        this.inspector = inspector; this.packets = []; this.page = 0; this.sort = 'id'; this.ascending = false;
        for (const id of ['packetSearch','packetIp','packetPort']) $(id).addEventListener('input', () => { this.page = 0; this.render(); });
        for (const id of ['packetProtocol','packetTime','packetPageSize']) $(id).addEventListener('change', () => { this.page = 0; this.render(); });
        $('clearPacketFilters').addEventListener('click', () => this.clear());
        $('packetPrev').addEventListener('click', () => { this.page--; this.render(); });
        $('packetNext').addEventListener('click', () => { this.page++; this.render(); });
        $('packetTable').querySelector('thead').addEventListener('click', event => {
            const button = event.target.closest('[data-sort]'); if (!button) return;
            this.ascending = this.sort === button.dataset.sort ? !this.ascending : true;
            this.sort = button.dataset.sort; this.page = 0; this.render();
            $('packetTable').querySelectorAll('th').forEach(th => th.removeAttribute('aria-sort'));
            button.closest('th').setAttribute('aria-sort', this.ascending ? 'ascending' : 'descending');
        });
        $('packetsTbody').addEventListener('click', event => {
            const row = event.target.closest('[data-packet-id]'); if (!row) return;
            this.selected = Number(row.dataset.packetId);
            this.render();
            $('packetsTbody').querySelector(`[data-packet-id="${this.selected}"] button`)?.focus();
            this.inspector.packet(this.packets.find(packet => packet.id === this.selected));
        });
        $('exportPackets').addEventListener('click', () => this.export());
        this.render();
    }
    update(data) {
        this.available = Array.isArray(data.analysis?.recent_packets);
        this.packets = data.analysis?.recent_packets || [];
        this.endTime = data.analysis?.capture_end_us;
        this.mode = data.mode;
        this.limit = data.analysis?.packet_limit || 300;
        this.render();
    }
    clear() {
        for (const id of ['packetSearch','packetIp','packetPort']) $(id).value = '';
        $('packetProtocol').value = 'all'; $('packetTime').value = 'all';
        this.flow = null; this.page = 0; this.render();
    }
    filter({ protocol, ip, search, port, flow } = {}) {
        this.clear();
        if (protocol) $('packetProtocol').value = protocol;
        if (ip) $('packetIp').value = ip;
        if (search) $('packetSearch').value = search;
        if (port != null) $('packetPort').value = port;
        this.flow = flow || null;
        this.render();
    }
    matching() {
        const query = $('packetSearch').value.trim().toLowerCase();
        const ip = $('packetIp').value.trim().toLowerCase();
        const portInput = $('packetPort').value;
        const port = portInput ? Number(portInput) : null;
        const protocol = $('packetProtocol').value;
        const time = $('packetTime').value;
        const filtered = this.packets.filter(packet => {
            if (!matchesProtocol(packet.protocol, protocol)) return false;
            if (query && ![packet.src_ip, packet.dst_ip, packet.src_mac, packet.dst_mac, packet.domain, packet.application, packet.info, packet.src_port, packet.dst_port].some(value => String(value ?? '').toLowerCase().includes(query))) return false;
            if (ip && ![packet.src_ip, packet.dst_ip].some(value => String(value || '').toLowerCase().includes(ip))) return false;
            if (port !== null && packet.src_port !== port && packet.dst_port !== port) return false;
            if (time !== 'all' && Number.isFinite(this.endTime) && packet.timestamp_us < this.endTime - Number(time) * 1e6) return false;
            if (this.flow) {
                const f = this.flow;
                const direct = packet.src_ip === f.src_ip && packet.dst_ip === f.dst_ip && (packet.src_port ?? 0) === f.src_port && (packet.dst_port ?? 0) === f.dst_port;
                const reverse = packet.src_ip === f.dst_ip && packet.dst_ip === f.src_ip && (packet.src_port ?? 0) === f.dst_port && (packet.dst_port ?? 0) === f.src_port;
                if (packet.protocol !== f.protocol || !(direct || reverse)) return false;
            }
            return true;
        });
        const key = this.sort;
        filtered.sort((a, b) => {
            const x = a[key] ?? '', y = b[key] ?? '';
            const delta = typeof x === 'number' && typeof y === 'number' ? x - y : String(x).localeCompare(String(y));
            return (delta || a.id - b.id) * (this.ascending ? 1 : -1);
        });
        return filtered;
    }
    render() {
        const filtered = this.matching();
        const pageSize = Number($('packetPageSize').value);
        const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
        this.page = Math.max(0, Math.min(this.page, pages - 1));
        const visible = filtered.slice(this.page * pageSize, (this.page + 1) * pageSize);
        text('packetCount', `${number(this.packets.length)} retained`);
        text('packetScope', `Latest ${this.limit || 300} parsed packets. ${this.mode === 'live' ? 'Live capture is not archived by this dashboard.' : 'Full capture remains in your source PCAP.'}`);
        text('packetPageInfo', filtered.length ? `${this.page * pageSize + 1}–${this.page * pageSize + visible.length} of ${number(filtered.length)} matching packets` : `${number(this.packets.length)} retained · no matches`);
        text('packetPage', `${this.page + 1} / ${pages}`);
        $('packetPrev').disabled = this.page === 0; $('packetNext').disabled = this.page + 1 >= pages;
        $('exportPackets').disabled = !filtered.length;
        $('flowFilterBanner').hidden = !this.flow;
        if (this.flow) text('flowFilterBanner', `Connection filter: ${endpoint(this.flow.src_ip, this.flow.src_port)} ↔ ${endpoint(this.flow.dst_ip, this.flow.dst_port)}. Clear filters to explore all retained packets.`);
        const fallback = this.packets.length ? empty(7, 'No packets match these filters', 'Try a different IP, protocol, or time range. The packet window is bounded.') : this.available ? empty(7, 'No packet data available yet', 'Run a capture from the engine terminal to begin.') : empty(7, 'Packet metadata is not in this snapshot', 'Run the updated engine to populate this view. Existing aggregate data remains available.');
        html('packetsTbody', visible.length ? visible.map(packet => `<tr data-packet-id="${packet.id}"${packet.id === this.selected ? ' class="selected"' : ''}><td class="mono"><button type="button" class="text-link" aria-label="Inspect packet ${packet.id}">${number(packet.id)}</button></td><td class="mono dim">${captureTime(packet.timestamp_us)}</td><td class="mono" title="${esc(endpoint(packet.src_ip || packet.src_mac, packet.src_port))}">${esc(endpoint(packet.src_ip || packet.src_mac, packet.src_port))}</td><td class="mono" title="${esc(endpoint(packet.dst_ip || packet.dst_mac, packet.dst_port))}">${esc(endpoint(packet.dst_ip || packet.dst_mac, packet.dst_port))}</td><td>${protocolBadge(packet.protocol)}</td><td class="number mono">${number(packet.length)}</td><td title="${esc([packet.domain, packet.info].filter(Boolean).join(' · '))}">${esc([packet.domain, packet.info].filter(Boolean).join(' · '))}</td></tr>`).join('') : fallback);
    }
    export() {
        const packets = this.matching();
        const columns = ['id','timestamp_us','src_ip','src_port','dst_ip','dst_port','protocol','length','captured_length','application','domain','info','policy'];
        const cell = value => {
            let safe = String(value ?? '');
            if (/^[\s]*[=+@-]/.test(safe)) safe = `'${safe}`;
            return `"${safe.replaceAll('"', '""')}"`;
        };
        download([columns.join(','), ...packets.map(packet => columns.map(column => cell(packet[column])).join(','))].join('\r\n'), 'text/csv;charset=utf-8', 'deeppacket-filtered-metadata.csv');
        toast(`Exported ${packets.length} matching packets from the retained window.`);
    }
}

export class FlowExplorer {
    constructor(inspector) {
        this.inspector = inspector; this.flows = []; this.page = 0;
        $('flowSearch').addEventListener('input', () => { this.page = 0; this.render(); });
        for (const id of ['flowProtocol','flowPolicy']) $(id).addEventListener('change', () => { this.page = 0; this.render(); });
        $('flowPrev').addEventListener('click', () => { this.page--; this.render(); });
        $('flowNext').addEventListener('click', () => { this.page++; this.render(); });
        $('flowsTbody').addEventListener('click', event => {
            const button = event.target.closest('[data-flow]');
            if (button) this.inspector.connection(this.flows[Number(button.dataset.flow)]);
        });
        this.render();
    }
    update(flows) { this.flows = Array.isArray(flows) ? flows : []; this.render(); }
    render() {
        const query = $('flowSearch').value.trim().toLowerCase();
        const protocol = $('flowProtocol').value, policy = $('flowPolicy').value;
        const filtered = this.flows.map((flow, index) => ({ flow, index })).filter(({ flow }) => matchesProtocol(flow.protocol, protocol) && (policy === 'all' || flow.policy === policy) && (!query || [flow.src_ip, flow.dst_ip, flow.domain, flow.application, flow.src_port, flow.dst_port].some(value => String(value ?? '').toLowerCase().includes(query)))).reverse();
        const pages = Math.max(1, Math.ceil(filtered.length / 25));
        this.page = Math.max(0, Math.min(this.page, pages - 1));
        const visible = filtered.slice(this.page * 25, this.page * 25 + 25);
        text('flowsBadge', `${this.flows.length} recorded`);
        text('flowPageInfo', `${filtered.length} matching flows · ${visible.length} shown`);
        text('flowPage', `${this.page + 1} / ${pages}`);
        $('flowPrev').disabled = !this.page; $('flowNext').disabled = this.page + 1 >= pages;
        html('flowsTbody', visible.length ? visible.map(({ flow:f, index }) => `<tr><td><div class="flow-endpoints"><span>${esc(endpoint(f.src_ip, f.src_port))}</span><span class="dim">→ ${esc(endpoint(f.dst_ip, f.dst_port))}</span></div></td><td>${protocolBadge(f.protocol)}</td><td><span class="flow-domain">${esc(f.domain || 'Unknown')}</span><span class="flow-app">${esc(f.application || 'Unknown')}</span></td><td><span class="subtle-badge">${esc(f.method || 'Unknown')}</span></td><td class="number mono">${number(f.packets)}</td><td class="number mono">${bytes(f.bytes)}</td><td>${decision(f.policy)}</td><td><button class="button ghost" type="button" data-flow="${index}" aria-label="Inspect connection ${esc(f.src_ip)} to ${esc(f.dst_ip)}">Inspect</button></td></tr>`).join('') : empty(8, this.flows.length ? 'No flows match these filters' : 'No observed connections yet'));
    }
}
