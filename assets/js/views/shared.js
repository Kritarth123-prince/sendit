/** Shared With Me / Shared by me. */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { bus } from '../core/bus.js';
import { dateTime, relative } from '../core/format.js';
import { toast, confirm, emptyState, errorState, skeleton, copyText } from '../core/ui.js';
import { realtime } from '../core/realtime.js';
import * as A from './_actions.js';

let offs = [];
const PERM = { viewer: 'Viewer', downloader: 'Downloader', commenter: 'Commenter', editor: 'Editor' };

export default {
  title: 'Shared With Me',
  mount(el, params, query) {
    let tab = query.tab === 'mine' ? 'mine' : 'with-me';
    const body = h('div');
    const tabs = h('div.seg', { role: 'tablist' },
      h('button', { type: 'button', role: 'tab', class: tab === 'with-me' ? 'active' : '', text: 'Shared with me', on: { click: (e) => sw('with-me', e) } }),
      h('button', { type: 'button', role: 'tab', class: tab === 'mine' ? 'active' : '', text: 'Shared by me', on: { click: (e) => sw('mine', e) } }));
    el.append(h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Shared' }), h('div.view-sub', { text: 'Files and folders other people shared with you, and links you created.' })), tabs), body);
    function sw(t, e) { tab = t; tabs.querySelectorAll('button').forEach((b) => b.classList.remove('active')); e.currentTarget.classList.add('active'); load(); }

    async function load() {
      clear(body).appendChild(skeleton(4));
      try {
        if (tab === 'with-me') {
          const { data } = await api.get('/shares/with-me', { per_page: 200 });
          clear(body);
          if (!data || !data.length) return body.appendChild(emptyState({ icon: 'users', title: 'Nothing shared with you yet', text: 'When someone shares a file or folder with you, it appears here.' }));
          body.appendChild(h('div.table-wrap', h('table.table.stack-mobile', h('thead', h('tr', ...['Name', 'Owner', 'Permission', 'Shared', 'Expires', 'Last opened', ''].map((t) => h('th', { text: t })))),
            h('tbody', ...data.map((row) => {
              const it = row.item || {}; const s = row.share || {};
              return h('tr',
                h('td', { 'data-label': 'Name' }, h('a', { href: '#', on: { click: (e) => { e.preventDefault(); A.openItem({ ...it, type: it.type || 'file' }); } } }, icon(it.type === 'folder' ? 'folder' : 'file', 16), ' ', it.name || s.title || 'Item')),
                h('td', { 'data-label': 'Owner', text: s.owner?.display_name || s.owner?.username || '' }),
                h('td', { 'data-label': 'Permission' }, h('span.pill.info', { text: PERM[s.permission] || s.permission })),
                h('td', { 'data-label': 'Shared', text: relative(row.shared_at || s.created_at) }),
                h('td', { 'data-label': 'Expires', text: s.expires_at ? dateTime(s.expires_at) : 'Never' }),
                h('td', { 'data-label': 'Last opened', text: row.last_accessed_at ? relative(row.last_accessed_at) : '—' }),
                h('td', it.type !== 'folder' && (it.access?.download ?? true) ? h('button.btn.btn-sm', { type: 'button', on: { click: () => A.download({ ...it, type: 'file' }) } }, icon('download', 14)) : null));
            })))));
        } else {
          const { data } = await api.get('/shares', { status: 'all', per_page: 200 });
          clear(body);
          if (!data || !data.length) return body.appendChild(emptyState({ icon: 'link', title: 'You have not shared anything yet', text: 'Use “Share” on any file or folder to create a link or share with people.' }));
          body.appendChild(h('div.table-wrap', h('table.table.stack-mobile', h('thead', h('tr', ...['Item', 'Type', 'With', 'Permission', 'Status', 'Downloads', 'Expires', ''].map((t) => h('th', { text: t })))),
            h('tbody', ...data.map((s) => h('tr',
              h('td', { 'data-label': 'Item', text: s.title || 'Item' }),
              h('td', { 'data-label': 'Type', text: s.kind === 'link' ? 'Link' : 'People' }),
              h('td', { 'data-label': 'With', text: s.recipient ? (s.recipient.display_name || s.recipient.username) : (s.has_password ? 'Anyone with the link + password' : 'Anyone with the link') }),
              h('td', { 'data-label': 'Permission', text: PERM[s.permission] || s.permission }),
              h('td', { 'data-label': 'Status' }, h('span.pill.' + (s.status === 'active' ? 'ok' : s.status === 'revoked' ? 'bad' : 'warn'), { text: s.status })),
              h('td', { 'data-label': 'Downloads', text: String(s.download_count ?? 0) + (s.max_downloads ? ' / ' + s.max_downloads : '') }),
              h('td', { 'data-label': 'Expires', text: s.expires_at ? dateTime(s.expires_at) : 'Never' }),
              h('td', h('div.row',
                s.url && s.status === 'active' ? h('button.btn.btn-sm', { type: 'button', title: 'Copy link', 'aria-label': 'Copy link', on: { click: async () => { await copyText(s.url); toast('Link copied', { type: 'ok' }); } } }, icon('copy', 14)) : null,
                s.url && s.status === 'active' ? h('button.btn.btn-sm', { type: 'button', title: 'QR code', 'aria-label': 'Show QR code', on: { click: () => import('../features/share-dialog.js').then((m) => m.showQr ? m.showQr(s.url) : null).catch(() => toast('QR codes are coming soon.', { type: 'info' })) } }, icon('qr', 14)) : null,
                s.status === 'active' ? h('button.btn.btn-sm.btn-danger', { type: 'button', on: { click: () => revoke(s) } }, 'Revoke') : null))))))));
        }
      } catch (e) { clear(body).appendChild(errorState(e, load)); }
    }
    async function revoke(s) {
      if (!(await confirm({ title: 'Stop sharing?', message: 'People using this share lose access immediately.', confirmText: 'Revoke', danger: true }))) return;
      try { await api.del('/shares/' + s.id); toast('Share revoked', { type: 'ok' }); realtime.nudge(); load(); } catch (e) { toast(e.message, { type: 'err' }); }
    }
    offs = ['share.created', 'share.updated', 'share.revoked', 'share.expired', 'sync.reset'].map((t) => bus.on(t, () => load()));
    // #/shared?file=<id>&tab=comments (notification deep links for files shared with you)
    load().finally(() => A.openDetailsFromQuery(query));
  },
  unmount() { offs.forEach((o) => o()); },
};
