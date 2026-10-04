/** Admin › Shares: every share on the server, with revoke. */
import { api } from '../../core/api.js';
import { h, clear } from '../../core/dom.js';
import { dateTime } from '../../core/format.js';
import { toast, confirm, errorState, skeleton, emptyState } from '../../core/ui.js';

export default {
  title: 'Shares',
  mount(el) {
    const status = h('select.select', { style: { width: 'auto' }, 'aria-label': 'Status' }, ...[['active', 'Active'], ['expired', 'Expired'], ['revoked', 'Revoked'], ['all', 'All']].map(([v, l]) => h('option', { value: v, text: l })));
    const body = h('div');
    el.append(h('div.view-head', h('h1.view-title.grow', { text: 'All shares' }), status), body);
    status.addEventListener('change', load);
    async function load() {
      clear(body).append(skeleton(4));
      try {
        const { data } = await api.get('/admin/shares', { status: status.value, per_page: 200 });
        clear(body);
        if (!data || !data.length) { body.append(emptyState({ icon: 'link', title: 'No shares' })); return; }
        body.append(h('div.table-wrap', h('table.table.stack-mobile', h('thead', h('tr', ...['Item', 'Owner', 'Type', 'Permission', 'Status', 'Downloads', 'Expires', ''].map((x) => h('th', { text: x })))),
          h('tbody', ...data.map((s) => h('tr', h('td', { 'data-label': 'Item', text: s.title || '' }), h('td', { 'data-label': 'Owner', text: s.owner?.display_name || '' }),
            h('td', { 'data-label': 'Type', text: s.kind === 'link' ? 'Link' : 'User: ' + (s.recipient?.display_name || '') }), h('td', { 'data-label': 'Permission', text: s.permission }),
            h('td', { 'data-label': 'Status' }, h('span.pill.' + (s.status === 'active' ? 'ok' : 'warn'), { text: s.status })),
            h('td', { 'data-label': 'Downloads', text: String(s.download_count ?? 0) }), h('td', { 'data-label': 'Expires', text: s.expires_at ? dateTime(s.expires_at) : 'Never' }),
            h('td', s.status === 'active' ? h('button.btn.btn-sm.btn-danger', { type: 'button', text: 'Revoke', on: { click: () => revoke(s) } }) : null)))))));
      } catch (e) { clear(body).append(errorState(e, load)); }
    }
    async function revoke(s) {
      if (!(await confirm({ title: 'Revoke this share?', confirmText: 'Revoke', danger: true }))) return;
      try { await api.del('/shares/' + s.id); toast('Share revoked', { type: 'ok' }); load(); } catch (e) { toast(e.message, { type: 'err' }); }
    }
    load();
  },
};
