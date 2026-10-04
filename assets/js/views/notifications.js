/** Notification centre with per-category channel preferences (in-app / push / e-mail). */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { bus } from '../core/bus.js';
import { store } from '../core/store.js';
import { relative, dateTime } from '../core/format.js';
import { toast, emptyState, errorState, skeleton } from '../core/ui.js';

let offs = [];

/** Details-panel tab a notification about a file opens on, or null. */
export function detailsTab(n) {
  const c = String(n?.category || ''), t = String(n?.type || '');
  if (c === 'comment' || t.startsWith('comment.')) return 'comments';
  if (c === 'version' || t.startsWith('version.') || t === 'file.version') return 'versions';
  return null;
}

/**
 * Where "Open" goes. Comment and version notifications open the file's details panel on the
 * right tab (#/files/<folder>?file=<id>&tab=comments); others follow data.link. Only in-app hash
 * routes are used as links.
 */
export function notificationHref(n) {
  const d = (n && n.data) || {};
  const link = typeof d.link === 'string' && /^#\/[^\s]*$/.test(d.link) ? d.link : null;
  const tab = detailsTab(n);
  const id = parseInt(String(d.file_id ?? ''), 10);
  if (!tab || !(id > 0)) return link;
  const base = link && /^#\/(files|shared)(\/\d+)?(\?|$)/.test(link) ? link.split('?')[0] : '#/files';
  return base + '?file=' + id + '&tab=' + tab;
}

export default {
  title: 'Notifications',
  mount(el) {
    let filter = 'all';
    const listEl = h('div.card');
    const prefsEl = h('div.card');
    const seg = h('div.seg', h('button.active', { type: 'button', text: 'All', on: { click: (e) => setF('all', e) } }), h('button', { type: 'button', text: 'Unread', on: { click: (e) => setF('unread', e) } }));
    el.append(h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Notifications' })), seg,
      h('button.btn', { type: 'button', on: { click: readAll } }, icon('check', 16), 'Mark all as read')),
      listEl, h('div.section-gap', h('h2', { style: { fontSize: '16px', marginBottom: '8px' }, text: 'Notification preferences' }), prefsEl));
    function setF(f, e) { filter = f; seg.querySelectorAll('button').forEach((b) => b.classList.remove('active')); e.currentTarget.classList.add('active'); load(); }

    async function load() {
      clear(listEl).appendChild(skeleton(4));
      try {
        const { data, meta } = await api.get('/notifications', { unread: filter === 'unread' ? 1 : undefined, per_page: 100 });
        if (typeof meta.unread_count === 'number') store.set('unread', meta.unread_count);
        clear(listEl);
        if (!data || !data.length) { listEl.appendChild(emptyState({ icon: 'bell', title: filter === 'unread' ? 'You are all caught up' : 'No notifications yet', text: 'Shares, comments, downloads and security alerts appear here.' })); return; }
        listEl.appendChild(h('div.list', ...data.map((n) => h('div.list-item' + (n.read ? '' : '.unread'),
          h('div.li-main', h('div.li-title', { text: n.title }), n.body ? h('div.li-sub', { text: n.body }) : null, h('div.li-sub', { title: dateTime(n.created_at), text: relative(n.created_at) })),
          notificationHref(n) ? h('a.btn.btn-sm', { href: notificationHref(n), on: { click: () => { if (!n.read) markRead(n); } } }, 'Open') : null,
          n.data && n.data.file_id ? h('button.btn.btn-sm.btn-ghost', { type: 'button', 'aria-label': 'File details', title: 'File details', on: { click: () => openFile(n) } }, icon('info', 14)) : null,
          !n.read ? h('button.btn.btn-sm.btn-ghost', { type: 'button', 'aria-label': 'Mark as read', on: { click: () => markRead(n).then(load) } }, icon('check', 14)) : null,
          h('button.btn.btn-sm.btn-ghost', { type: 'button', 'aria-label': 'Delete notification', on: { click: () => api.del('/notifications/' + n.id).then(load).catch((e) => toast(e.message, { type: 'err' })) } }, icon('x', 14))))));
      } catch (e) { clear(listEl).appendChild(errorState(e, load)); }
    }
    async function markRead(n) { try { await api.post('/notifications/' + n.id + '/read'); } catch { /* ignore */ } }
    function openFile(n) {
      const tab = { comment: 'comments', version: 'versions', download: 'activity', share: 'info' }[n.category] || 'info';
      if (!n.read) markRead(n).then(load);
      import('../features/details.js').then((m) => m.openDetails(n.data.file_id, tab)).catch((e) => toast(e.message, { type: 'err' }));
    }
    async function readAll() { try { await api.post('/notifications/read-all'); store.set('unread', 0); load(); } catch (e) { toast(e.message, { type: 'err' }); } }

    async function loadPrefs() {
      clear(prefsEl).appendChild(skeleton(2));
      try {
        const { data } = await api.get('/notifications/preferences');
        const cfg = store.get('config') || {};
        clear(prefsEl);
        const rows = (data || []).map((p) => {
          const box = (ch, enabled) => h('input', { type: 'checkbox', checked: !!p[ch], disabled: !enabled, 'aria-label': p.label + ' — ' + ch, on: { change: (e) => { p[ch] = e.target.checked; save(); } } });
          return h('tr', h('td', { text: p.label || p.category }), h('td', box('in_app', true)), h('td', box('push', !!cfg.features?.push)), h('td', box('email', !!cfg.features?.email)));
        });
        prefsEl.append(h('div.table-wrap', h('table.table', h('thead', h('tr', h('th', { text: 'Category' }), h('th', { text: 'In-app' }), h('th', { text: 'Push' }), h('th', { text: 'E-mail' }))), h('tbody', ...rows))),
          !cfg.features?.push ? h('p.hint', { style: { marginTop: '8px' }, text: 'Push notifications are not configured on this server.' }) : h('div.row', { style: { marginTop: '10px' } }, h('button.btn.btn-sm', { type: 'button', on: { click: enablePush } }, icon('bell', 14), 'Enable push on this device')));
        async function save() { try { await api.put('/notifications/preferences', { preferences: data }); toast('Preferences saved', { type: 'ok', timeout: 1500 }); } catch (e) { toast(e.message, { type: 'err' }); } }
      } catch (e) { clear(prefsEl).appendChild(errorState(e, loadPrefs)); }
    }
    async function enablePush() {
      const key = store.get('config')?.vapid_public_key;
      if (!('serviceWorker' in navigator) || !('PushManager' in window) || !key) { toast('Push notifications are not supported here.', { type: 'warn' }); return; }
      try {
        if ((await Notification.requestPermission()) !== 'granted') { toast('Notifications are blocked in your browser settings.', { type: 'warn' }); return; }
        const reg = await navigator.serviceWorker.ready;
        const pad = '='.repeat((4 - (key.length % 4)) % 4);
        const raw = atob((key + pad).replace(/-/g, '+').replace(/_/g, '/'));
        const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: Uint8Array.from(raw, (c) => c.charCodeAt(0)) });
        const j = sub.toJSON();
        await api.post('/push/subscribe', { endpoint: j.endpoint, keys: j.keys });
        toast('Push notifications enabled on this device', { type: 'ok' });
      } catch (e) { toast(e.message || 'Could not enable push notifications.', { type: 'err' }); }
    }
    offs = [bus.on('notification.created', load), bus.on('sync.reset', load)];
    load(); loadPrefs();
  },
  unmount() { offs.forEach((o) => o()); },
};
