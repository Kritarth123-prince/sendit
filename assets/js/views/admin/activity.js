/** Admin › Activity: audit log with filters; new entries appear live. */
import { api } from '../../core/api.js';
import { h, clear, debounce } from '../../core/dom.js';
import { bus } from '../../core/bus.js';
import { dateTime } from '../../core/format.js';
import { errorState, skeleton, emptyState } from '../../core/ui.js';

let offs = [];
export default {
  title: 'Activity',
  mount(el) {
    const cat = h('select.select', { style: { width: 'auto' }, 'aria-label': 'Category' }, ...[['', 'All categories'], ['activity', 'File activity'], ['security', 'Security'], ['admin', 'Admin'], ['system', 'System']].map(([v, l]) => h('option', { value: v, text: l })));
    const q = h('input.input', { type: 'search', placeholder: 'Search…', style: { maxWidth: '240px' } });
    const body = h('div');
    let page = 1;
    el.append(h('div.view-head', h('h1.view-title.grow', { text: 'Activity log' }), cat, q), body);
    cat.addEventListener('change', () => { page = 1; load(); });
    q.addEventListener('input', debounce(() => { page = 1; load(); }, 300));
    async function load() {
      if (!body.children.length) body.append(skeleton(5));
      try {
        const { data, meta } = await api.get('/admin/activity', { category: cat.value || undefined, q: q.value.trim() || undefined, page, per_page: 50 });
        clear(body);
        if (!data || !data.length) { body.append(emptyState({ icon: 'activity', title: 'No activity found' })); return; }
        body.append(h('div.table-wrap', h('table.table.stack-mobile', h('thead', h('tr', ...['When', 'Who', 'Action', 'Detail', 'IP'].map((x) => h('th', { text: x })))),
          h('tbody', ...data.map((a) => h('tr', h('td', { 'data-label': 'When', text: dateTime(a.created_at) }), h('td', { 'data-label': 'Who', text: a.actor?.display_name || a.actor_label || 'System' }),
            h('td', { 'data-label': 'Action' }, h('span.pill.info', { text: a.action })), h('td', { 'data-label': 'Detail', text: a.text || a.detail || '' }), h('td', { 'data-label': 'IP', text: a.ip || '' })))))),
          h('div.row', { style: { marginTop: '10px', justifyContent: 'center' } },
            page > 1 ? h('button.btn.btn-sm', { type: 'button', text: '← Newer', on: { click: () => { page--; load(); } } }) : null,
            meta.has_more ? h('button.btn.btn-sm', { type: 'button', text: 'Older →', on: { click: () => { page++; load(); } } }) : null));
      } catch (e) { clear(body).append(errorState(e, load)); }
    }
    offs = ['file.created', 'file.deleted', 'share.created', 'share.revoked', 'user.created', 'user.updated'].map((t) => bus.on(t, debounce(() => { if (page === 1) load(); }, 1200)));
    load();
  },
  unmount() { offs.forEach((o) => o()); },
};
