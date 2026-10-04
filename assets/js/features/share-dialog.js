/**
 * Share dialog: link or people, permission level (Viewer / Downloader / Commenter / Editor) with
 * fine-grained toggles, expiry, download limit, password, message; Copy + QR for links;
 * the existing shares of the item with revoke.
 * @module features/share-dialog
 */
import { api } from '../core/api.js';
import { h, icon, clear, debounce } from '../core/dom.js';
import { modal, toast, copyText } from '../core/ui.js';
import { dateTime } from '../core/format.js';
import { realtime } from '../core/realtime.js';
import { renderQr, qrPngDataUrl } from './qr.js';

const LEVELS = [
  ['viewer', 'Viewer', 'Can preview and see details'],
  ['downloader', 'Downloader', 'Can preview and download'],
  ['commenter', 'Commenter', 'Can preview, download and comment'],
  ['editor', 'Editor', 'Can also rename, edit and upload new versions'],
];
const LVL = { viewer: 1, downloader: 2, commenter: 3, editor: 4 };
const EXPIRY = [['', 'Never'], ['3600', '1 hour'], ['86400', '1 day'], ['604800', '7 days'], ['2592000', '30 days'], ['custom', 'Choose a date…']];

/** Show a QR for any URL (used by "Shared by me"). */
export function showQr(url) {
  const box = h('div', { style: { display: 'flex', justifyContent: 'center' } });
  renderQr(box, url, { size: 260 }).catch((e) => { box.textContent = e.message; });
  modal({ title: 'QR code', size: 'sm', content: h('div.stack', box, h('code.small', { style: { wordBreak: 'break-all' }, text: url })),
    actions: [
      { label: 'Copy link', onClick: async () => { await copyText(url); toast('Link copied', { type: 'ok' }); return false; } },
      { label: 'Download QR', kind: 'primary', onClick: async () => { const a = h('a', { href: await qrPngDataUrl(url), download: 'fasttransfer-qr.png' }); a.click(); return false; } },
    ] });
}

/** @param {{files?:Object[], folder?:Object|null}} target */
export function openShareDialog({ files = [], folder = null } = {}) {
  const title = folder ? folder.name : files.length === 1 ? files[0].name : files.length + ' files';
  let tab = 'link';
  const tabs = h('div.seg', { role: 'tablist', style: { marginBottom: '14px' } },
    h('button.active', { type: 'button', role: 'tab', text: 'Link', on: { click: (e) => sw('link', e) } }),
    h('button', { type: 'button', role: 'tab', text: 'People', on: { click: (e) => sw('user', e) } }));

  const level = h('select.select', ...LEVELS.map(([v, l, d]) => h('option', { value: v, text: l + ' — ' + d, selected: v === 'downloader' })));
  const flags = { allow_preview: tog('Allow preview', true), allow_download: tog('Allow download', true), allow_comments: tog('Allow comments', false), allow_edit: tog('Allow editing', false), allow_reshare: tog('Allow re-sharing', false) };
  const syncFlags = () => {
    const l = LVL[level.value];
    setTog(flags.allow_download, l >= 2, l >= 2); setTog(flags.allow_comments, l >= 3, l >= 3); setTog(flags.allow_edit, l >= 4, l >= 4);
  };
  level.addEventListener('change', syncFlags);
  const expiry = h('select.select', ...EXPIRY.map(([v, l]) => h('option', { value: v, text: l })));
  const expiryDate = h('input.input', { type: 'datetime-local', hidden: true });
  expiry.addEventListener('change', () => { expiryDate.hidden = expiry.value !== 'custom'; });
  const maxDl = h('input.input', { type: 'number', min: 1, placeholder: 'Unlimited' });
  const password = h('input.input', { type: 'password', autocomplete: 'new-password', placeholder: 'Optional — at least 8 characters', minlength: 8, maxlength: 200 });
  const message = h('input.input', { maxlength: 500, placeholder: 'Optional note for the recipient' });

  // people picker
  const chosen = new Map();
  const people = h('div.row.wrap');
  const lookup = h('input.input', { placeholder: 'Type a name or username…', autocomplete: 'off', 'aria-label': 'Find people' });
  const suggestions = h('div.list');
  lookup.addEventListener('input', debounce(async () => {
    const q = lookup.value.trim();
    clear(suggestions);
    if (q.length < 2) return;
    try {
      const { data } = await api.get('/users/lookup', { q });
      (data || []).filter((u) => !chosen.has(u.id)).forEach((u) => suggestions.append(h('button.list-item', { type: 'button', style: { width: '100%' }, on: { click: () => { chosen.set(u.id, u); paintPeople(); lookup.value = ''; clear(suggestions); lookup.focus(); } } }, icon('user', 16), h('span', { text: (u.display_name || u.username) + ' (@' + u.username + ')' }))));
    } catch { /* ignore */ }
  }, 250));
  function paintPeople() { clear(people); chosen.forEach((u) => people.append(h('span.chip', u.display_name || u.username, h('button', { type: 'button', 'aria-label': 'Remove ' + u.username, on: { click: () => { chosen.delete(u.id); paintPeople(); } } }, icon('x', 12))))); }
  const peopleBox = h('div.stack', { hidden: true }, h('div.field', h('label', { text: 'Share with' }), lookup, suggestions, people), h('div.field', h('label', { text: 'Message' }), message));

  const linkOpts = h('div.stack',
    h('div', { style: { display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(200px,1fr))', gap: '12px' } },
      h('div.field', h('label', { text: 'Expires' }), expiry, expiryDate),
      h('div.field', h('label', { text: 'Maximum downloads' }), maxDl),
      h('div.field', h('label', { text: 'Password' }), password)));
  const result = h('div');
  const existing = h('div');
  const form = h('div.stack', tabs, h('div.field', h('label', { text: 'Permission' }), level), h('div.row.wrap', ...Object.values(flags).map((f) => f.el)), linkOpts, peopleBox, result, h('hr.divider'), existing);

  function sw(t, e) { tab = t; tabs.querySelectorAll('button').forEach((b) => b.classList.remove('active')); e.currentTarget.classList.add('active'); linkOpts.hidden = t !== 'link'; peopleBox.hidden = t !== 'user'; createBtn.textContent = t === 'link' ? 'Create link' : 'Share'; }

  const m = modal({ title: 'Share “' + title + '”', size: 'lg', content: form, actions: [{ label: 'Close', kind: 'ghost' }] });
  const createBtn = h('button.btn.btn-primary', { type: 'button', text: 'Create link', on: { click: create } });
  m.el.querySelector('.modal-foot').append(createBtn);

  async function create() {
    const body = { kind: tab, permission: level.value };
    Object.entries(flags).forEach(([k, f]) => { body[k] = f.input.checked; });
    if (folder) body.folder_id = folder.id; else body.file_ids = files.map((f) => f.id);
    if (tab === 'link') {
      if (expiry.value === 'custom') { if (!expiryDate.value) { toast('Choose an expiry date.', { type: 'warn' }); return; } body.expires_at = new Date(expiryDate.value).toISOString(); } else if (expiry.value) body.expires_in = parseInt(expiry.value, 10);
      if (maxDl.value) body.max_downloads = parseInt(maxDl.value, 10);
      if (password.value) {
        if (password.value.length < 8) { toast('Use at least 8 characters for the link password.', { type: 'warn' }); password.focus(); return; }
        body.password = password.value;
      }
    } else {
      if (!chosen.size) { toast('Choose at least one person.', { type: 'warn' }); return; }
      body.recipients = [...chosen.keys()];
      if (message.value.trim()) body.message = message.value.trim();
    }
    createBtn.disabled = true;
    try {
      const { data } = await api.post('/shares', body);
      const list = Array.isArray(data) ? data : [data];
      realtime.nudge();
      if (tab === 'link' && list[0]?.url) showLink(list[0]);
      else { toast('Shared with ' + chosen.size + (chosen.size === 1 ? ' person' : ' people'), { type: 'ok' }); chosen.clear(); paintPeople(); }
      loadExisting();
    } catch (e) { toast(e.message, { type: 'err' }); } finally { createBtn.disabled = false; }
  }

  function showLink(s) {
    const qrBox = h('div', { style: { display: 'flex', justifyContent: 'center' } });
    const url = h('input.input', { value: s.url, readonly: true, 'aria-label': 'Share link', on: { focus: (e) => e.target.select() } });
    clear(result).append(h('div.card.stack', { style: { borderColor: 'var(--accent)' } },
      h('div.row', url, h('button.btn.btn-primary', { type: 'button', on: { click: async () => { await copyText(s.url); toast('Link copied', { type: 'ok' }); } } }, icon('copy', 15), 'Copy')),
      h('div.row.wrap',
        h('button.btn.btn-sm', { type: 'button', on: { click: () => { renderQr(qrBox, s.url, { size: 220 }).catch((e) => { qrBox.textContent = e.message; }); } } }, icon('qr', 15), 'Generate QR'),
        h('button.btn.btn-sm', { type: 'button', on: { click: async () => { try { const a = h('a', { href: await qrPngDataUrl(s.url), download: 'fasttransfer-share-qr.png' }); a.click(); } catch (e) { toast(e.message, { type: 'err' }); } } } }, icon('download', 15), 'Download QR'),
        s.has_password ? h('span.small.text2', { text: 'Send the password separately — it is not in the link or QR code.' }) : null),
      qrBox));
    copyText(s.url).then((ok) => ok && toast('Link created and copied', { type: 'ok' }));
  }

  async function loadExisting() {
    clear(existing);
    try {
      const path = folder ? null : files.length === 1 ? '/files/' + files[0].id + '/shares' : null;
      if (!path) return;
      const { data } = await api.get(path);
      if (!data || !data.length) return;
      existing.append(h('div.label', { text: 'Existing shares' }), h('div.list', ...data.map((s) => h('div.list-item', icon(s.kind === 'link' ? 'link' : 'user', 16),
        h('div.li-main', h('div.li-title', { text: s.kind === 'link' ? 'Link' + (s.has_password ? ' (password)' : '') : (s.recipient?.display_name || s.recipient?.username || 'User') }),
          h('div.li-sub', { text: s.permission + ' · ' + s.status + (s.expires_at ? ' · expires ' + dateTime(s.expires_at) : '') + ' · ' + (s.download_count || 0) + ' downloads' })),
        s.url && s.status === 'active' ? h('button.btn.btn-sm', { type: 'button', 'aria-label': 'Copy link', on: { click: async () => { await copyText(s.url); toast('Link copied', { type: 'ok' }); } } }, icon('copy', 14)) : null,
        s.url && s.status === 'active' ? h('button.btn.btn-sm', { type: 'button', 'aria-label': 'QR code', on: { click: () => showQr(s.url) } }, icon('qr', 14)) : null,
        s.status === 'active' ? h('button.btn.btn-sm.btn-danger', { type: 'button', text: 'Revoke', on: { click: async () => { try { await api.del('/shares/' + s.id); toast('Share revoked', { type: 'ok' }); realtime.nudge(); loadExisting(); } catch (e) { toast(e.message, { type: 'err' }); } } } }) : null))));
    } catch { /* no permission to list */ }
  }
  syncFlags();
  loadExisting();
}

function tog(label, on) {
  const input = h('input', { type: 'checkbox', checked: on });
  const el = h('label.toggle', { style: { marginRight: '10px' } }, input, h('span.track'), h('span.small', { text: label }));
  return { el, input };
}
function setTog(t, checked, enabled) { t.input.checked = checked; t.input.disabled = !enabled; t.el.style.opacity = enabled ? '1' : '.5'; }
