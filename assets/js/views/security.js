/** Security Centre: account status, sessions, login history, security events, devices, API tokens. */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { store } from '../core/store.js';
import { relative, dateTime, plural } from '../core/format.js';
import { toast, confirm, modal, passwordPrompt, errorState, skeleton, copyText } from '../core/ui.js';

export default {
  title: 'Security Centre',
  mount(el) {
    const overview = h('div.kpis');
    const sessions = h('div.card');
    const logins = h('div.card');
    const tokens = h('div.card');
    const events = h('div.card');
    el.append(h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Security Centre' }), h('div.view-sub', { text: 'Where you are signed in, recent sign-ins and your API tokens.' }))),
      overview,
      h('div.section-gap', h('div.row', { style: { marginBottom: '8px' } }, h('h2', { style: { fontSize: '16px' }, text: 'Active sessions' }), h('span.grow'), h('button.btn.btn-sm.btn-danger', { type: 'button', on: { click: logoutAll } }, icon('logout', 14), 'Sign out all other devices')), sessions),
      h('div.section-gap', h('h2', { style: { fontSize: '16px', marginBottom: '8px' }, text: 'Sign-in history' }), logins),
      h('div.section-gap', h('h2', { style: { fontSize: '16px', marginBottom: '8px' }, text: 'Security events' }), events),
      h('div.section-gap', h('div.row', { style: { marginBottom: '8px' } }, h('h2', { style: { fontSize: '16px' }, text: 'API tokens' }), h('span.grow'), h('button.btn.btn-sm', { type: 'button', on: { click: createToken } }, icon('plus', 14), 'New token')), tokens));

    const kpi = (label, value, cls) => h('div.kpi', h('div.kpi-value' + (cls ? '.' + cls : ''), { text: String(value) }), h('div.kpi-label', { text: label }));
    async function loadOverview() {
      try {
        const { data: o } = await api.get('/security/overview');
        clear(overview).append(
          kpi('Account', o.account_status || store.get('user').status),
          kpi('Two-factor', o.two_factor ? 'On' : 'Off'),
          kpi('Password changed', o.password?.changed_at ? relative(o.password.changed_at) : '—'),
          kpi('Active sessions', o.sessions_count ?? '—'),
          kpi('Active share links', o.active_links ?? '—'),
          kpi('Links expiring soon', o.expiring_links ?? '—'),
          kpi('Suspicious sign-ins (30 days)', o.suspicious_logins_30d ?? 0),
          kpi('API tokens', o.api_tokens ?? 0));
        if (o.password?.weak) overview.append(h('div.banner', icon('warning', 18), h('span', { text: 'Your password is weak. Change it in Settings.' })));
      } catch (e) { clear(overview).append(errorState(e, loadOverview)); }
    }
    async function loadSessions() {
      clear(sessions).append(skeleton(2));
      try {
        const { data } = await api.get('/security/sessions');
        clear(sessions).append(h('div.list', ...(data || []).map((s) => h('div.list-item', icon('device', 20),
          h('div.li-main', h('div.li-title', { text: (s.device || 'Unknown device') + (s.current ? ' — this device' : '') }), h('div.li-sub', { text: (s.ip || '') + ' · last active ' + relative(s.last_seen_at) + ' · signed in ' + dateTime(s.created_at) })),
          s.current ? h('span.pill.ok', { text: 'Current' }) : h('button.btn.btn-sm', { type: 'button', on: { click: () => revoke(s) } }, 'Sign out')))));
      } catch (e) { clear(sessions).append(errorState(e, loadSessions)); }
    }
    async function revoke(s) {
      try { await api.del('/security/sessions/' + s.id); toast('Signed out that device', { type: 'ok' }); loadSessions(); loadOverview(); } catch (e) { toast(e.message, { type: 'err' }); }
    }
    async function logoutAll() {
      if (!(await confirm({ title: 'Sign out all other devices?', message: 'Every other browser and device will need to sign in again, and your API tokens stop working (create new ones afterwards).', confirmText: 'Sign out others', danger: true }))) return;
      try {
        const { data } = await api.post('/security/sessions/revoke-all', { include_current: false });
        toast(revokeAllMessage(data), { type: 'ok', timeout: 5000 });
        loadSessions(); loadOverview(); loadTokens();
      } catch (e) { toast(e.message, { type: 'err' }); }
    }
    async function loadLogins() {
      clear(logins).append(skeleton(2));
      try {
        const { data } = await api.get('/security/logins', { per_page: 20 });
        clear(logins);
        if (!data || !data.length) { logins.append(h('p.text2', { text: 'No sign-ins recorded yet.' })); return; }
        logins.append(h('div.table-wrap', h('table.table.stack-mobile', h('thead', h('tr', ...['When', 'Result', 'IP', 'Device', ''].map((t) => h('th', { text: t })))),
          h('tbody', ...data.map((l) => h('tr',
            h('td', { 'data-label': 'When', text: dateTime(l.created_at) }),
            h('td', { 'data-label': 'Result' }, h('span.pill.' + (l.success ? 'ok' : 'bad'), { text: l.success ? 'Success' : 'Failed' })),
            h('td', { 'data-label': 'IP', text: l.ip || '' }),
            h('td', { 'data-label': 'Device', text: l.device || l.user_agent || '' }),
            h('td', l.suspicious ? h('span.pill.warn', { title: l.suspicious_reason || '', text: 'Suspicious' }) : null)))))));
      } catch (e) { clear(logins).append(errorState(e, loadLogins)); }
    }
    async function loadEvents() {
      try {
        const { data } = await api.get('/security/events', { per_page: 20 });
        clear(events);
        if (!data || !data.length) { events.append(h('p.text2', { text: 'No security events.' })); return; }
        events.append(h('div.list', ...data.map((e) => h('div.list-item', icon('shield', 18), h('div.li-main', h('div.li-title', { text: e.text || e.detail || e.action }), h('div.li-sub', { text: dateTime(e.created_at) + (e.ip ? ' · ' + e.ip : '') }))))));
      } catch (e) { clear(events).append(errorState(e, loadEvents)); }
    }
    async function loadTokens() {
      try {
        const { data } = await api.get('/security/tokens');
        clear(tokens);
        if (!data || !data.length) { tokens.append(h('p.text2', { text: 'No API tokens. Tokens let scripts use the FastTransfer API on your behalf.' })); return; }
        tokens.append(h('div.list', ...data.map((t) => h('div.list-item', icon('key', 18),
          h('div.li-main', h('div.li-title', { text: t.name }), h('div.li-sub', { text: t.token_prefix + '… · ' + (t.scopes === 'read' ? 'read-only' : 'full access') + ' · ' + (t.last_used_at ? 'used ' + relative(t.last_used_at) : 'never used') + (t.expires_at ? ' · expires ' + dateTime(t.expires_at) : '') })),
          h('button.btn.btn-sm.btn-danger', { type: 'button', on: { click: async () => { if (!(await confirm({ title: 'Revoke token?', message: 'Scripts using “' + t.name + '” stop working immediately.', confirmText: 'Revoke', danger: true }))) return; try { await api.del('/security/tokens/' + t.id); loadTokens(); } catch (e) { toast(e.message, { type: 'err' }); } } } }, 'Revoke')))));
      } catch (e) { clear(tokens).append(errorState(e, loadTokens)); }
    }
    async function createToken() {
      // Creating a token needs the current password (a token is a long-lived credential).
      const name = h('input.input', { maxlength: 200, placeholder: 'e.g. backup script', required: true });
      const data = await passwordPrompt({
        title: 'New API token', confirmText: 'Create token', message: '',
        extra: h('div.field', h('label', { text: 'Name' }), name),
        onConfirm: async (pw) => {
          const n = name.value.trim();
          if (!n) { name.focus(); throw new Error('Give the token a name, for example “backup script”.'); }
          return (await api.post('/security/tokens', { name: n, current_password: pw })).data;
        },
      });
      if (!data) return;
      modal({ title: 'Copy your token now', content: h('div.stack', h('p', { text: 'This is the only time the token is shown.' }), h('pre.text-preview', { text: data.token })), actions: [{ label: 'Copy', kind: 'primary', onClick: async () => { await copyText(data.token); toast('Token copied', { type: 'ok' }); } }] });
      loadTokens(); loadOverview();
    }
    loadOverview(); loadSessions(); loadLogins(); loadEvents(); loadTokens();
  },
};

/** Toast text for "Sign out all other devices" ({sessions_revoked|revoked, tokens_revoked?}). */
export function revokeAllMessage(d) {
  const sessions = Number(d?.sessions_revoked ?? d?.revoked ?? 0) || 0;
  const tokens = Number(d?.tokens_revoked ?? 0) || 0;
  const parts = [sessions ? 'Signed out ' + plural(sessions, 'other session', 'other sessions') : 'No other sessions were signed in'];
  if (tokens) parts.push('revoked ' + plural(tokens, 'API token', 'API tokens'));
  return parts.join(' and ') + '.';
}
