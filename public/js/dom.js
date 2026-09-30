export const $ = id => document.getElementById(id);
export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;' })[character]);
export const number = value => Number.isFinite(value) ? value.toLocaleString() : '—';
export const compact = value => Number.isFinite(value) ? Intl.NumberFormat(undefined, { notation:'compact', maximumFractionDigits:1 }).format(value) : '—';
export const bytes = value => {
    if (!Number.isFinite(value)) return '—';
    if (value < 1024) return `${value.toLocaleString()} B`;
    const units = ['KiB', 'MiB', 'GiB', 'TiB'];
    let scaled = value / 1024, index = 0;
    while (scaled >= 1024 && index < units.length - 1) { scaled /= 1024; index++; }
    return `${scaled.toFixed(scaled >= 100 ? 0 : 1)} ${units[index]}`;
};
export const duration = milliseconds => {
    if (!Number.isFinite(milliseconds)) return '—';
    const seconds = Math.floor(milliseconds / 1000);
    if (seconds < 60) return `${(milliseconds / 1000).toFixed(1)}s`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
    return `${Math.floor(seconds / 3600)}h ${Math.floor(seconds / 60) % 60}m`;
};
export const captureTime = microseconds => {
    if (!Number.isFinite(microseconds)) return '—';
    const date = new Date(microseconds / 1000);
    return `${date.toLocaleTimeString('en-GB', { hour12:false })}.${String(Math.floor(microseconds / 1000) % 1000).padStart(3, '0')}`;
};
export const fullTime = microseconds => Number.isFinite(microseconds) ? new Date(microseconds / 1000).toISOString() : 'Not available';
export const endpoint = (ip, port) => ip ? `${ip.includes(':') ? `[${ip}]` : ip}${port != null ? `:${port}` : ''}` : 'Not available';
export function text(id, value) { const element = $(id); if (element && element.textContent !== String(value)) element.textContent = value; }
const rendered = new WeakMap();
export function html(id, value) { const element = $(id); if (element && rendered.get(element) !== value) { element.innerHTML = value; rendered.set(element, value); } }
export function toast(message, error = false) {
    const element = document.createElement('div');
    element.className = `toast${error ? ' error' : ''}`;
    element.textContent = message;
    $('toastRegion').append(element);
    setTimeout(() => element.remove(), 5000);
}
export async function getJson(url, timeout = 12000) {
    const response = await fetch(url, { cache:'no-store', signal:AbortSignal.timeout(timeout) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
    return data;
}
export function download(content, type, filename) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url; link.download = filename; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
export const protocolBadge = protocol => {
    const kind = ['TCP','UDP','ICMP','ICMPv6','ARP'].includes(protocol) ? protocol.toLowerCase() : 'other';
    return `<span class="protocol-badge ${kind}">${escapeHtml(protocol || 'Other')}</span>`;
};

const icons = {
    overview:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
    packets:'<path d="M4 4h16v4H4zM4 10h16v4H4zM4 16h16v4H4zM7 6h.01M7 12h.01M7 18h.01"/>',
    network:'<circle cx="12" cy="5" r="3"/><circle cx="5" cy="18" r="3"/><circle cx="19" cy="18" r="3"/><path d="m10.5 8-4 7m7-7 4 7M8 18h8"/>',
    layers:'<path d="m12 3 10 5-10 5L2 8Zm-10 9 10 5 10-5M2 16l10 5 10-5"/>',
    globe:'<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
    terminal:'<rect x="3" y="4" width="18" height="16" rx="2"/><path d="m7 9 3 3-3 3m6 0h4"/>',
    shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6Z"/><path d="m8 12 3 3 5-6"/>',
    pulse:'<path d="M2 12h4l3-7 5 14 3-7h5"/>',
    bell:'<path d="M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9M10 21h4"/>',
    settings:'<path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3" fill="currentColor" stroke="none"/><circle cx="16" cy="17" r="3" fill="currentColor" stroke="none"/>',
    pause:'<path d="M8 5v14M16 5v14"/>', play:'<path d="m8 4 12 8-12 8Z"/>',
    download:'<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',
    transfer:'<path d="M7 3v17m-4-4 4 4 4-4M17 21V4m-4 4 4-4 4 4"/>',
    clock:'<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    arrow:'<path d="M4 12h16m-6-6 6 6-6 6"/>',
    expand:'<path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5"/>',
    search:'<circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/>',
    plus:'<path d="M12 4v16M4 12h16"/>'
};
export function renderIcons(root = document) {
    root.querySelectorAll('[data-icon]').forEach(element => {
        element.innerHTML = `<svg viewBox="0 0 24 24" aria-hidden="true">${icons[element.dataset.icon] || icons.layers}</svg>`;
        element.setAttribute('aria-hidden', 'true');
    });
}
