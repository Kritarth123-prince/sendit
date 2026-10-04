/**
 * Admin › System: settings, maintenance, legacy import, encryption upgrade, Web Push keys,
 * database updates, server info.
 */
import { api } from '../../core/api.js';
import { h, icon, clear } from '../../core/dom.js';
import { store } from '../../core/store.js';
import { dateTime } from '../../core/format.js';
import { toast, modal, errorState, skeleton, copyText } from '../../core/ui.js';

const GROUPS = [
  ['Storage and quotas', [['default_quota_bytes', 'Default quota for users (bytes)', 'number'], ['guest_quota_bytes', 'Guest quota (bytes)', 'number'], ['max_upload_bytes', 'Largest single upload (bytes)', 'number'], ['blocked_extensions', 'Blocked file extensions (comma-separated)', 'text'], ['dedup_scope', 'Deduplication', [['user', 'Per user (private)'], ['global', 'Across all users']]]]],
  ['Trash and retention', [['trash_retention_days', 'Empty Trash automatically after', [['7', '7 days'], ['30', '30 days'], ['60', '60 days'], ['90', '90 days'], ['0', 'Never']]], ['version_retention_count', 'Versions to keep per file', 'number'], ['version_retention_days', 'Delete old versions after (days, 0 = never)', 'number'], ['auto_expire_hours', 'Auto-delete files not kept forever after (hours, 0 = off)', 'number'], ['text_auto_expire_hours', 'Auto-delete saved texts after (hours, 0 = off)', 'number']]],
  ['Security', [['session_idle_minutes', 'Sign out after inactivity (minutes)', 'number'], ['remember_days', '“Keep me signed in” lasts (days)', 'number'], ['login_max_attempts', 'Failed sign-ins allowed', 'number'], ['login_window_minutes', '…within (minutes)', 'number']]],
  ['Notifications and integrations', [['quota_warning_percent', 'Warn users when storage reaches (%)', 'number'], ['slack_events', 'Slack events (comma-separated)', 'text'], ['slack_webhook_override', 'Slack webhook (overrides .env)', 'password'], ['ocr_enabled', 'OCR text search', [['1', 'On'], ['0', 'Off']]]]],
];

/** Show a freshly generated VAPID key pair once, with copy buttons. Nothing is kept afterwards. */
function showVapidKeys(d) {
  const pub = 'VAPID_PUBLIC_KEY=' + (d.public_key || '');
  const priv = 'VAPID_PRIVATE_KEY=' + (d.private_key || '');
  const both = pub + '\n' + priv;
  const copy = (text, what) => async () => {
    const ok = await copyText(text);
    toast(ok ? what + ' copied' : 'Could not copy. Select the text and copy it manually.', { type: ok ? 'ok' : 'warn', timeout: ok ? 1800 : 3500 });
  };
  const line = (text, what) => h('div.row', { style: { alignItems: 'flex-start', gap: '8px' } },
    h('code.grow', { style: { wordBreak: 'break-all', userSelect: 'all' }, text }),
    h('button.btn.btn-sm', { type: 'button', 'aria-label': 'Copy ' + what, title: 'Copy', on: { click: copy(text, what) } }, icon('copy', 14)));
  const m = modal({
    title: 'New Web Push keys', dismissible: false,
    content: h('div.stack',
      h('p', { text: 'Paste both lines into .env (replace any existing VAPID_PUBLIC_KEY and VAPID_PRIVATE_KEY lines), upload .env again and reload FastTransfer. Set VAPID_SUBJECT to a mailto: address or your site’s URL as well.' }),
      line(pub, 'Public key'), line(priv, 'Private key'),
      h('p.text2.small', { text: 'The private key is not stored anywhere and is shown only now. Keep it secret: anyone with it can send push messages as this site.' })),
    actions: [
      { label: 'Copy both lines', kind: 'ghost', close: false, onClick: copy(both, 'Both lines') },
      { label: 'I have saved them', kind: 'primary' },
    ],
  });
  return m;
}

export default {
  title: 'System',
  mount(el) {
    const settingsEl = h('div.card'); const ops = h('div.grid-cards'); const info = h('div.card');
    el.append(h('div.view-head', h('h1.view-title', { text: 'System' })), settingsEl, h('div.section-gap', ops), h('div.section-gap', info));

    async function loadSettings() {
      clear(settingsEl).append(skeleton(3));
      try {
        const { data: s } = await api.get('/admin/settings');
        const inputs = {};
        clear(settingsEl).append(h('div.card-title', 'Settings'));
        for (const [title, fields] of GROUPS) {
          settingsEl.append(h('h3', { style: { fontSize: '14px', margin: '14px 0 8px' }, text: title }));
          const grid = h('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(260px,1fr))', gap: '12px' } });
          for (const [key, label, type] of fields) {
            let input;
            if (Array.isArray(type)) input = h('select.select', ...type.map(([v, l]) => h('option', { value: v, text: l, selected: String(s[key]) === v })));
            else input = h('input.input', { type, value: type === 'password' ? '' : (s[key] ?? ''), placeholder: type === 'password' && s[key] ? 'Set — type to replace' : '' });
            inputs[key] = input;
            grid.append(h('div.field', h('label', { text: label }), input));
          }
          settingsEl.append(grid);
        }
        settingsEl.append(h('div.row', { style: { marginTop: '14px' } }, h('button.btn.btn-primary', { type: 'button', text: 'Save settings', on: { click: async () => {
          const body = {};
          for (const [k, inp] of Object.entries(inputs)) { if (inp.type === 'password' && inp.value === '') continue; body[k] = inp.value; }
          try { await api.put('/admin/settings', body); toast('Settings saved', { type: 'ok' }); } catch (e) { toast(e.message, { type: 'err' }); }
        } } }), h('button.btn', { type: 'button', on: { click: testSlack } }, 'Send Slack test')));
      } catch (e) { clear(settingsEl).append(errorState(e, loadSettings)); }
    }
    async function testSlack() { try { await api.post('/admin/slack/test', {}); toast('Test message sent to Slack', { type: 'ok' }); } catch (e) { toast(e.message, { type: 'err' }); } }

    const opCard = (title, text, label, fn) => { const out = h('div.small.text2'); const b = h('button.btn', { type: 'button', text: label, on: { click: async () => { b.disabled = true; try { await fn(out); } finally { b.disabled = false; } } } }); return h('div.card.stack', h('div.card-title', { text: title }), h('p.text2.small', { text }), h('div', b), out); };
    ops.append(
      opCard('Maintenance', 'Clean up expired shares, old uploads, Trash past its retention, old versions and unused storage. Runs automatically in the background too.', 'Run now', async (out) => {
        const { data } = await api.post('/admin/maintenance/run', {});
        out.textContent = Object.entries(data?.tasks || data || {}).map(([k, v]) => k + ': ' + (v.items ?? v.status ?? JSON.stringify(v))).join(' · ') || 'Done';
      }),
      opCard('Import from the old version', 'Copies files, folders, share links, comments, texts and history from the pre-upgrade uploads/ folder. Safe to run more than once.', 'Run import', async (out) => {
        let done = false, guard = 0;
        while (!done && guard++ < 200) {
          const { data } = await api.post('/admin/legacy-import', {});
          done = !!data?.done;
          out.textContent = (done ? 'Finished. ' : 'Working… ') + Object.entries(data?.counts || {}).map(([k, v]) => k + ': ' + v).join(' · ');
          if (data?.temporary_passwords && Object.keys(data.temporary_passwords).length) {
            modal({ title: 'Temporary passwords for imported users', content: h('pre.text-preview', { text: Object.entries(data.temporary_passwords).map(([u, p]) => u + ': ' + p).join('\n') }) });
          }
        }
      }),
      opCard('Encryption upgrade', 'Re-encrypts files from the old AES-256-CBC format (and unencrypted files, if encryption is on) with AES-256-GCM. Each file is verified before the old copy is removed.', 'Upgrade files', async (out) => {
        let done = false, guard = 0;
        while (!done && guard++ < 200) {
          const { data } = await api.post('/admin/encryption/migrate', {});
          done = !!data?.done || !(data?.remaining > 0);
          out.textContent = 'Converted ' + (data?.converted ?? 0) + ', remaining ' + (data?.remaining ?? 0) + (data?.errors ? ', errors ' + data.errors : '');
        }
      }),
      opCard('Web Push keys', 'Push notifications need a VAPID key pair in .env. Generate a new pair here, paste both lines into .env and upload it again. Replacing existing keys means everyone has to turn push on again on their devices.', 'Generate Web Push keys', async () => {
        const { data } = await api.post('/admin/vapid/generate', {});
        showVapidKeys(data || {});
      }),
      opCard('Database updates', 'After you upload a new version that brings database updates, the site sends every visitor to /install until they are applied: add a temporary INSTALL_TOKEN to .env, open /install, choose “Upgrade now”, then remove the token again. This button applies updates that are pending while the app is running (a backup is made first).', 'Apply updates', async (out) => {
        const { data } = await api.post('/admin/migrations/run', {});
        out.textContent = (data?.applied || []).length ? 'Applied: ' + data.applied.join(', ') : 'Already up to date.';
      }));

    async function loadInfo() {
      clear(info).append(skeleton(3));
      try {
        const { data: s } = await api.get('/admin/system');
        const cap = s.capabilities || {};
        const row = (k, v) => h('div.row', h('span.text2', { style: { width: '220px' }, text: k }), h('span.grow', { text: String(v ?? '—') }));
        const canary = h('span', { text: 'checking…' });
        clear(info).append(h('div.card-title', 'Server'),
          row('FastTransfer', store.get('config')?.version), row('PHP', cap.php_version), row('Database', s.database?.version),
          row('Real-time mode', cap.can_hold ? 'Live connection (SSE / long-poll)' : 'Polling (host cannot hold connections)'),
          row('Max request size', cap.max_request_bytes ? Math.round(cap.max_request_bytes / 1048576) + ' MB' : ''),
          row('Background jobs', s.jobs ? s.jobs.pending + ' pending, ' + s.jobs.failed + ' failed' : ''),
          row('Last maintenance', s.last_maintenance?.started_at ? dateTime(s.last_maintenance.started_at) : (s.pseudo_cron?.last_run ? dateTime(s.pseudo_cron.last_run) : 'Not yet')),
          h('div.row', h('span.text2', { style: { width: '220px' }, text: 'Storage folder private' }), canary));
        fetch((store.get('config')?.base || '/') + 'storage/canary.json', { cache: 'no-store' }).then((r) => { canary.textContent = r.ok ? '✗ PUBLICLY READABLE — fix .htaccess!' : '✓ Yes (blocked from the web)'; canary.style.color = r.ok ? 'var(--red)' : 'var(--green)'; }).catch(() => { canary.textContent = '✓ Yes'; });
      } catch (e) { clear(info).append(errorState(e, loadInfo)); }
    }
    loadSettings(); loadInfo();
  },
};
