/** Admin › Storage: totals, deduplication savings, per-user usage, all users' trash. */
import { api } from '../../core/api.js';
import { h, clear } from '../../core/dom.js';
import { bytes, percent, relative } from '../../core/format.js';
import { toast, confirm, errorState, skeleton } from '../../core/ui.js';

export default {
  title: 'Storage',
  mount(el) {
    const top = h('div.kpis'); const users = h('div'); const trash = h('div');
    el.append(h('div.view-head', h('h1.view-title', { text: 'Storage' })), top, h('div.section-gap', h('h2', { style: { fontSize: '16px', marginBottom: '8px' }, text: 'Usage by user' }), users), h('div.section-gap', h('h2', { style: { fontSize: '16px', marginBottom: '8px' }, text: 'Trash (all users)' }), trash));
    const tile = (l, v) => h('div.kpi', h('div.kpi-value', { text: v }), h('div.kpi-label', { text: l }));
    async function load() {
      users.append(skeleton(3));
      try {
        const { data: s } = await api.get('/admin/storage');
        const t = s.totals || s;
        clear(top).append(tile('Logical storage', bytes(t.logical_bytes ?? t.used_bytes ?? 0)), tile('Physical storage', bytes(t.physical_bytes ?? 0)), tile('Saved by deduplication', bytes(t.dedup_saved_bytes ?? 0)), tile('In Trash', bytes(t.trash_bytes ?? 0)), tile('Old versions', bytes(t.version_bytes ?? 0)), tile('Capacity', t.capacity_bytes ? bytes(t.capacity_bytes) : 'Not set'));
        clear(users).append(h('div.table-wrap', h('table.table.stack-mobile', h('thead', h('tr', ...['User', 'Used', 'Quota', 'Files', 'Trash', 'Versions'].map((x) => h('th', { text: x })))),
          h('tbody', ...(s.users || []).map((u) => h('tr', h('td', { 'data-label': 'User', text: u.display_name || u.username }),
            h('td', { 'data-label': 'Used' }, u.quota_bytes ? h('div.quota-bar', { style: { minWidth: '100px' } }, h('span', { style: { width: percent(u.used_bytes, u.quota_bytes) + '%' } })) : null, h('span.small', { text: bytes(u.used_bytes) })),
            h('td', { 'data-label': 'Quota', text: u.quota_bytes ? bytes(u.quota_bytes) : 'Unlimited' }), h('td', { 'data-label': 'Files', text: String(u.files ?? 0) }),
            h('td', { 'data-label': 'Trash', text: bytes(u.trash_bytes ?? 0) }), h('td', { 'data-label': 'Versions', text: bytes(u.version_bytes ?? 0) })))))));
      } catch (e) { clear(users).append(errorState(e, load)); }
      try {
        const { data } = await api.get('/admin/trash', { per_page: 100 });
        clear(trash).append((data || []).length ? h('div.table-wrap', h('table.table.stack-mobile', h('thead', h('tr', ...['Item', 'Owner', 'Size', 'Deleted', ''].map((x) => h('th', { text: x })))),
          h('tbody', ...data.map((f) => h('tr', h('td', { 'data-label': 'Item', text: f.name }), h('td', { 'data-label': 'Owner', text: f.owner?.display_name || '' }), h('td', { 'data-label': 'Size', text: f.size ? bytes(f.size) : '' }), h('td', { 'data-label': 'Deleted', text: relative(f.trash?.deleted_at) }),
            h('td', h('div.row', h('button.btn.btn-sm', { type: 'button', text: 'Restore', on: { click: () => act('restore', f) } }), h('button.btn.btn-sm.btn-danger', { type: 'button', text: 'Delete', on: { click: () => act('purge', f) } })))))))) : h('p.text2', { text: 'Trash is empty for everyone.' }));
      } catch (e) { clear(trash).append(errorState(e)); }
    }
    async function act(kind, f) {
      const q = f.type === 'folder' ? '?kind=folder' : '';
      try {
        if (kind === 'restore') await api.post('/trash/' + f.id + '/restore' + q);
        else { if (!(await confirm({ title: 'Delete permanently?', message: '“' + f.name + '” will be deleted forever.', confirmText: 'Delete', danger: true }))) return; await api.del('/trash/' + f.id + q); }
        toast('Done', { type: 'ok' }); load();
      } catch (e) { toast(e.message, { type: 'err' }); }
    }
    load();
  },
};
