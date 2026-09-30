import { $, getJson, html, text, escapeHtml as esc, toast } from './dom.js';

export class RulesPanel {
    constructor() {
        this.busy = false;
        $('ruleForm').addEventListener('submit', event => { event.preventDefault(); this.change(false, $('ruleType').value, $('ruleValue').value.trim()); });
        $('ruleType').addEventListener('change', () => {
            const values = { domain:['e.g. *.example.com','Matches the domain and its subdomains.'], ip:['e.g. 192.0.2.10','IPv4 rules can match either endpoint in monitor mode. WFP filters remote IPv4 addresses.'], app:['e.g. GitHub','Use an application name recognized by the engine.'], port:['e.g. 443','Enter a port from 1 to 65535.'] };
            const [placeholder, hint] = values[$('ruleType').value];
            $('ruleValue').placeholder = placeholder;
            text('ruleHint', `${hint} The management token stays in this page only.`);
        });
        $('rules').addEventListener('click', event => {
            const button = event.target.closest('[data-remove-rule]');
            if (button) this.change(true, button.dataset.type, button.dataset.value);
        });
    }
    async load() {
        if (this.loading || this.busy) return;
        this.loading = true;
        try {
            const [rules, state] = await Promise.all([getJson('/rules'), getJson('/rules/status')]);
            this.render(rules);
            text('rulesState', state.state === 'loaded' ? state.engine_status === 'live' ? `Loaded by engine · ${state.wfp_active ? 'WFP active for supported IPv4 rules' : 'monitor mode'}` : 'Loaded in a previous engine run · engine is offline' : state.state === 'saved' ? 'Saved · waiting for the engine to reload' : 'No revision acknowledgment from the engine');
        } catch (error) { text('rulesState', `Rules unavailable: ${error.message}`); }
        finally { this.loading = false; }
    }
    render(rules) {
        const lists = [['domain','blocked_domains','domainRules','domainPill'],['ip','blocked_ips','ipRules','ipPill'],['app','blocked_apps','appRules','appPill'],['port','blocked_ports','portRules','portPill']];
        let total = 0;
        for (const [type, key, list, pill] of lists) {
            const values = Array.isArray(rules[key]) ? rules[key] : [];
            total += values.length;
            text(pill, values.length);
            html(list, values.length ? values.map(value => `<li><span>${esc(value)}</span><button class="remove-rule" type="button" data-remove-rule data-type="${type}" data-value="${esc(value)}" aria-label="Remove ${esc(type)} rule ${esc(value)}">Remove</button></li>`).join('') : '<li class="empty-inline">No rules configured</li>');
        }
        text('rulesBadge', `${total} saved rule${total === 1 ? '' : 's'}`);
    }
    async change(remove, type, value) {
        if (this.busy) return;
        const token = $('ruleToken').value;
        if (!token) { text('ruleMessage', 'Enter the management token from the server terminal to change rules.'); $('ruleMessage').classList.add('error'); $('ruleToken').focus(); return; }
        this.busy = true;
        $('saveRule').disabled = true;
        document.querySelectorAll('[data-remove-rule]').forEach(button => { button.disabled = true; });
        $('ruleMessage').classList.remove('error');
        text('ruleMessage', 'Saving policy…');
        try {
            const response = await fetch('/rules', { method:remove ? 'DELETE' : 'POST', headers:{ 'content-type':'application/json', 'x-rule-token':token }, body:JSON.stringify({ type, value }), signal:AbortSignal.timeout(10000) });
            const result = await response.json();
            if (!response.ok) { if (response.status === 401) $('ruleToken').value = ''; throw new Error(result.error || 'Could not save rule'); }
            this.render(result.rules);
            if (!remove) $('ruleValue').value = '';
            text('rulesState', 'Saved · waiting for the engine to reload');
            text('ruleMessage', remove ? 'Rule removed from saved policy. Waiting for engine acknowledgment.' : 'Rule saved. Waiting for engine acknowledgment.');
            toast(remove ? 'Rule removed from saved policy.' : 'Rule saved for engine reload.');
        } catch (error) {
            $('ruleMessage').classList.add('error');
            text('ruleMessage', error.message);
        } finally {
            this.busy = false;
            $('saveRule').disabled = false;
            document.querySelectorAll('[data-remove-rule]').forEach(button => { button.disabled = false; });
        }
    }
}
