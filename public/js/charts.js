import { $, html, text, number, compact, bytes } from './dom.js';

const colors = ['#82acff','#b49bfb','#e9be72','#64d4b6','#63758e'];
const names = ['TCP','UDP','ICMP','ARP','Other'];
export class TrafficCharts {
    constructor(onProtocol) {
        this.charts = {};
        this.onProtocol = onProtocol;
        $('chartRange').addEventListener('change', () => this.renderTimeline());
        $('chartMetric').addEventListener('change', () => this.renderTimeline());
        $('protoStats').addEventListener('click', event => {
            const button = event.target.closest('[data-protocol]');
            if (button) onProtocol(button.dataset.protocol);
        });
    }
    create(id, config) {
        if (!window.Chart) return null;
        window.Chart.defaults.color = '#9aa9be';
        window.Chart.defaults.font.family = 'Segoe UI, system-ui, sans-serif';
        window.Chart.defaults.font.size = 10;
        window.Chart.defaults.animation = false;
        if (!this.charts[id]) this.charts[id] = new window.Chart($(id), config);
        return this.charts[id];
    }
    update(data) {
        this.data = data;
        this.renderProtocol(); this.renderTimeline(); this.renderSizes();
    }
    renderProtocol() {
        const protocols = this.data?.protocols || {};
        const total = this.data?.packets || 0;
        const values = names.slice(0, 4).map(name => protocols[name] || 0);
        values.push(Math.max(0, total - values.reduce((a, b) => a + b, 0)));
        text('protocolTotal', compact(total));
        $('protoChart').setAttribute('aria-label', `Protocol distribution: ${names.map((name, i) => `${name} ${number(values[i])}`).join(', ')}`);
        const chart = this.create('protoChart', {
            type:'doughnut', data:{ labels:names, datasets:[{ data:values, backgroundColor:colors, borderWidth:3, borderColor:'#131a25', hoverOffset:4, borderRadius:3 }] },
            options:{ responsive:true, maintainAspectRatio:false, cutout:'79%',
                onClick:(_event, elements) => { if (elements[0]) this.onProtocol(names[elements[0].index]); },
                plugins:{ legend:{ display:false }, tooltip:{ backgroundColor:'#23344d', padding:11, callbacks:{ label:item => `${item.label}: ${number(item.raw)} packets` } } } }
        });
        if (chart) { chart.data.datasets[0].data = values; chart.update('none'); }
        html('protoStats', total ? names.map((name, i) => values[i] ? `<button type="button" class="protocol-item" data-protocol="${name}" aria-label="Filter ${name} packets"><i class="legend-dot" style="background:${colors[i]}"></i><span>${name === 'ICMP' ? 'ICMP / v6' : name}</span><span class="count">${number(values[i])}</span><span class="percent">${(values[i] / total * 100).toFixed(1)}%</span></button>` : '').join('') : '<p class="empty-inline">No protocol data available.</p>');
    }
    renderTimeline() {
        const history = this.data?.analysis?.timeline || [];
        const metric = $('chartMetric').value;
        const last = history.at(-1)?.time_ms;
        const range = Number($('chartRange').value) * 1000;
        const samples = history.filter(sample => sample.time_ms > last - range);
        const total = samples.reduce((sum, sample) => sum + sample[metric], 0);
        text('timelineTotal', samples.length ? metric === 'bytes' ? bytes(total) : number(total) : '—');
        text('timelineSubtitle', samples.length ? `${metric === 'bytes' ? 'bytes' : 'packets'} in visible interval` : 'No measured timeline yet');
        text('timelineScope', samples.length ? `${samples.length} observed seconds · latest interval may be partial` : 'Up to 300 observed seconds · run a new capture to populate');
        const points = [];
        samples.forEach((sample, i) => {
            if (i && sample.time_ms - samples[i - 1].time_ms > 1000) points.push({ x:sample.time_ms - 1, y:null });
            points.push({ x:sample.time_ms, y:sample[metric] });
        });
        const chart = this.create('throughputChart', {
            type:'line', data:{ datasets:[{ label:'Observed traffic', data:points, parsing:false, borderColor:'#82acff', backgroundColor:'rgba(77,123,205,.13)', borderWidth:2, fill:true, pointRadius:0, pointHitRadius:12, pointHoverRadius:4, tension:.2, spanGaps:false }] },
            options:{ responsive:true, maintainAspectRatio:false, interaction:{ mode:'nearest', intersect:false, axis:'x' },
                plugins:{ legend:{ display:false }, tooltip:{ backgroundColor:'#23344d', padding:12, displayColors:false,
                    callbacks:{ title:items => new Date(items[0].parsed.x).toLocaleTimeString(), label:item => metric === 'bytes' ? `${bytes(item.parsed.y)} / captured second` : `${number(item.parsed.y)} packets / captured second` } } },
                scales:{ x:{ type:'linear', grid:{ color:'#24314750', drawTicks:false }, border:{ display:false }, ticks:{ maxTicksLimit:6, font:{ size:9 }, callback:value => new Date(value).toLocaleTimeString('en-GB', { hour12:false }) } },
                    y:{ beginAtZero:true, grid:{ color:'#29364b70' }, border:{ display:false }, ticks:{ maxTicksLimit:5, padding:8, callback:value => metric === 'bytes' ? bytes(value) : compact(value) } } } }
        });
        $('throughputEmpty').hidden = Boolean(samples.length && chart);
        $('throughputChart').style.visibility = samples.length && chart ? 'visible' : 'hidden';
        if (!chart) text('throughputEmpty', 'Chart library unavailable. Packet tables and summaries remain available.');
        if (chart) {
            chart.data.datasets[0].data = points;
            chart.options.plugins.tooltip.callbacks.label = item => metric === 'bytes' ? `${bytes(item.parsed.y)} / captured second` : `${number(item.parsed.y)} packets / captured second`;
            chart.options.scales.y.ticks.callback = value => metric === 'bytes' ? bytes(value) : compact(value);
            chart.options.scales.x.min = samples.length === 1 ? samples[0].time_ms - 500 : undefined;
            chart.options.scales.x.max = samples.length === 1 ? samples[0].time_ms + 500 : undefined;
            chart.update('none');
        }
    }
    renderSizes() {
        const bins = this.data?.analysis?.size_distribution || [];
        const values = bins.map(bin => bin.packets);
        $('sizeChart').setAttribute('aria-label', `Packet size distribution: ${bins.map(bin => `${bin.label} bytes: ${number(bin.packets)} packets`).join(', ')}`);
        const chart = this.create('sizeChart', {
            type:'bar', data:{ labels:bins.map(bin => bin.label), datasets:[{ data:values, backgroundColor:'#668ed1', hoverBackgroundColor:'#92b8ff', borderRadius:3, barPercentage:.55 }] },
            options:{ responsive:true, maintainAspectRatio:false, plugins:{ legend:{ display:false }, tooltip:{ backgroundColor:'#23344d', callbacks:{ label:item => `${number(item.raw)} packets` } } },
                scales:{ x:{ grid:{ display:false }, border:{ display:false }, ticks:{ font:{ size:9 } } }, y:{ beginAtZero:true, grid:{ color:'#29364b70' }, border:{ display:false }, ticks:{ maxTicksLimit:4, callback:compact } } } }
        });
        $('sizeEmpty').hidden = Boolean(chart && values.some(value => value > 0));
        $('sizeChart').style.visibility = $('sizeEmpty').hidden ? 'visible' : 'hidden';
        if (chart) { chart.data.labels = bins.map(bin => bin.label); chart.data.datasets[0].data = values; chart.update('none'); }
    }
    resize() { Object.values(this.charts).forEach(chart => chart.resize()); }
}
