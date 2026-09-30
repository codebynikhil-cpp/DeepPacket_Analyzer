import { $, text, number, bytes } from './dom.js';

const namespace = 'http://www.w3.org/2000/svg';
const svgElement = (name, attributes, value) => {
    const element = document.createElementNS(namespace, name);
    Object.entries(attributes).forEach(([key, content]) => element.setAttribute(key, content));
    if (value !== undefined) element.textContent = value;
    return element;
};
export class NetworkGraph {
    constructor(onIp, onFlow) {
        this.onIp = onIp; this.onFlow = onFlow;
        this.scale = 1; this.x = 0; this.y = 0;
        const svg = $('networkGraph');
        $('zoomIn').addEventListener('click', () => this.zoom(1.2));
        $('zoomOut').addEventListener('click', () => this.zoom(1 / 1.2));
        $('resetGraph').addEventListener('click', () => this.reset());
        svg.addEventListener('wheel', event => { event.preventDefault(); this.zoom(event.deltaY < 0 ? 1.08 : 1 / 1.08); }, { passive:false });
        svg.addEventListener('pointerdown', event => {
            if (event.target.closest('[data-ip],[data-flow]')) return;
            this.drag = { x:event.clientX, y:event.clientY, originX:this.x, originY:this.y };
            svg.setPointerCapture(event.pointerId);
        });
        svg.addEventListener('pointermove', event => {
            if (!this.drag) return;
            const bounds = svg.getBoundingClientRect();
            const factor = Math.max(720 / bounds.width, 320 / bounds.height);
            this.x = this.drag.originX + (event.clientX - this.drag.x) * factor;
            this.y = this.drag.originY + (event.clientY - this.drag.y) * factor;
            this.transform();
        });
        const stop = () => { this.drag = null; };
        svg.addEventListener('pointerup', stop); svg.addEventListener('pointercancel', stop);
        const select = event => {
            const node = event.target.closest('[data-ip]');
            if (node) return onIp(node.dataset.ip);
            const edge = event.target.closest('[data-flow]');
            if (edge) onFlow(this.flows[Number(edge.dataset.flow)]);
        };
        svg.addEventListener('click', select);
        svg.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); select(event); } });
    }
    zoom(factor) { this.scale = Math.max(.6, Math.min(3, this.scale * factor)); this.transform(); }
    reset() { this.scale = 1; this.x = 0; this.y = 0; this.transform(); }
    transform() { $('graphViewport').setAttribute('transform', `translate(${360 + this.x} ${160 + this.y}) scale(${this.scale}) translate(-360 -160)`); }
    update(flows) {
        this.flows = Array.isArray(flows) ? flows : [];
        const map = new Map();
        for (const flow of this.flows) {
            if (!flow.src_ip || !flow.dst_ip) continue;
            for (const ip of new Set([flow.src_ip, flow.dst_ip])) {
                if (!map.has(ip)) map.set(ip, { ip, connections:0, bytes:0, packets:0, measured:false });
                const node = map.get(ip); node.connections++;
                if (Number.isFinite(flow.bytes)) { node.bytes += flow.bytes; node.packets += flow.packets || 0; node.measured = true; }
            }
        }
        const nodes = [...map.values()].sort((a, b) => b.connections - a.connections || b.bytes - a.bytes || a.ip.localeCompare(b.ip)).slice(0, 18);
        nodes.forEach((node, i) => {
            const angle = ((i - 1) / Math.max(1, nodes.length - 1)) * Math.PI * 2 - Math.PI / 2;
            node.x = i === 0 ? 360 : 360 + Math.cos(angle) * 242;
            node.y = i === 0 ? 150 : 150 + Math.sin(angle) * 111;
        });
        const visible = new Map(nodes.map(node => [node.ip, node]));
        const fragment = document.createDocumentFragment();
        let links = 0;
        this.flows.map((flow, index) => ({ flow, index })).sort((a, b) => (b.flow.bytes || 0) - (a.flow.bytes || 0)).forEach(({ flow, index }) => {
            const source = visible.get(flow.src_ip), target = visible.get(flow.dst_ip);
            if (!source || !target || links >= 40) return;
            const color = flow.protocol === 'TCP' ? '#6e9ddf' : flow.protocol === 'UDP' ? '#a796df' : '#c5ad7b';
            const line = svgElement('path', { d:`M${source.x} ${source.y} Q${(source.x + target.x) / 2 + 9} ${(source.y + target.y) / 2 - 13} ${target.x} ${target.y}`, stroke:color, 'stroke-width':Math.min(3, .8 + Math.log10((flow.bytes || 0) + 1) / 4), opacity:'.45', fill:'none', class:'graph-edge', 'data-flow':index, tabindex:'0', role:'button', 'aria-label':`Inspect ${flow.protocol} connection from ${flow.src_ip} to ${flow.dst_ip}` });
            line.append(svgElement('title', {}, `${flow.src_ip} ↔ ${flow.dst_ip}\n${flow.protocol} · ${number(flow.packets)} packets · ${bytes(flow.bytes)}`));
            fragment.append(line); links++;
        });
        const maxBytes = Math.max(1, ...nodes.map(node => node.bytes));
        nodes.forEach((node, index) => {
            const radius = index === 0 ? 22 : 7 + Math.sqrt(node.bytes / maxBytes) * 8;
            const group = svgElement('g', { class:'graph-node', 'data-ip':node.ip, tabindex:'0', role:'button', 'aria-label':`Filter packets for ${node.ip}. ${node.connections} recorded flows.` });
            group.append(svgElement('title', {}, `${node.ip}\n${node.connections} recorded flows\n${node.measured ? `${number(node.packets)} packets · ${bytes(node.bytes)}` : 'Traffic volume unavailable in this snapshot'}`));
            if (index === 0) group.append(svgElement('circle', { cx:node.x, cy:node.y, r:32, fill:'none', stroke:'#385d8a', 'stroke-width':1, opacity:.6 }));
            group.append(svgElement('circle', { cx:node.x, cy:node.y, r:radius, fill:index === 0 ? '#254567' : '#233249', stroke:index === 0 ? '#8db8ef' : '#6586b3', 'stroke-width':1.2 }));
            if (index === 0) group.append(svgElement('path', { d:`M${node.x - 8} ${node.y - 6}h16v11h-16Zm4 14h8`, fill:'none', stroke:'#b3d0f4', 'stroke-width':1.4 }));
            const short = node.ip.length > 23 ? `${node.ip.slice(0, 12)}…${node.ip.slice(-8)}` : node.ip;
            group.append(svgElement('text', { x:node.x, y:node.y + radius + 15, 'text-anchor':'middle' }, short));
            fragment.append(group);
        });
        $('graphViewport').replaceChildren(fragment);
        $('networkEmpty').hidden = nodes.length > 0;
        text('networkCount', `${links} links`);
        this.transform();
    }
}
