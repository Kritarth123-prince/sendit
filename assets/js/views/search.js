/** Search with filters: type, owner, date, size, folder, tag, shared, favourite, trash. Keyword-only. */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { router } from '../core/router.js';
import { createFileList } from '../core/filelist.js';
import * as A from './_actions.js';

let list = null;
export default {
  title: 'Search',
  mount(el, params, query) {
    const q = { ...query };
    const input = h('input.input', { type: 'search', value: q.q || '', placeholder: 'Search names, tags and text inside files…', 'aria-label': 'Search' });
    const sel = (name, opts) => h('select.select', { 'aria-label': name, style: { width: 'auto' }, on: { change: (e) => { q[name] = e.target.value; run(); } } }, ...opts.map(([v, l]) => h('option', { value: v, text: l, selected: (q[name] || '') === v })));
    const chk = (name, label) => h('label.chip', h('input', { type: 'checkbox', checked: q[name] === '1', style: { accentColor: 'var(--accent)' }, on: { change: (e) => { q[name] = e.target.checked ? '1' : ''; run(); } } }), label);
    const filters = h('div.toolbar',
      sel('kind', [['', 'Any type'], ['image', 'Images'], ['video', 'Video'], ['audio', 'Audio'], ['pdf', 'PDF'], ['document', 'Documents'], ['spreadsheet', 'Spreadsheets'], ['code', 'Code'], ['text', 'Text'], ['archive', 'Archives']]),
      sel('date_from', [['', 'Any date'], [iso(1), 'Last 24 hours'], [iso(7), 'Last 7 days'], [iso(30), 'Last 30 days'], [iso(365), 'Last year']]),
      sel('size_min', [['', 'Any size'], ['1048576', '> 1 MB'], ['52428800', '> 50 MB'], ['524288000', '> 500 MB']]),
      chk('shared', 'Shared'), chk('favorite', 'Favourites'), chk('trash', 'In Trash'));
    const wrap = h('div');
    const form = h('form', { role: 'search', on: { submit: (e) => { e.preventDefault(); q.q = input.value.trim(); run(); } } }, h('div.row', input, h('button.btn.btn-primary', { type: 'submit' }, icon('search', 16), 'Search')));
    el.append(h('div.view-head', h('h1.view-title', { text: 'Search' })), form, h('div', { style: { height: '12px' } }), filters, wrap);
    function iso(days) { return new Date(Date.now() - days * 86400000).toISOString().slice(0, 10); }
    function run() {
      const clean = Object.fromEntries(Object.entries(q).filter(([, v]) => v));
      const hash = '/search?' + new URLSearchParams(clean).toString();
      if (location.hash !== '#' + hash) history.replaceState(null, '', '#' + hash);
      load();
    }
    function load() {
      list && list.destroy();
      if (!q.q && !q.kind && !q.shared && !q.favorite && !q.trash && !q.tag) {
        clear(wrap).appendChild(h('div.empty-state', icon('search', 44), h('h3', { text: 'Search your files' }), h('p', { text: 'Type a name, extension, tag or words inside documents and scanned images.' })));
        return;
      }
      list = createFileList(wrap, {
        variant: q.trash ? 'trash' : 'search', mode: 'list',
        source: async ({ page, perPage }) => { const { data, meta } = await api.get('/search', { ...q, page, per_page: perPage }); return { items: (data || []).map((f) => ({ ...f, type: f.type || 'file' })), meta }; },
        extraMeta: (it) => (it.match && it.match.field !== 'name' ? '“…' + (it.match.snippet || '') + '…” in ' + it.match.field : null),
        emptyState: { icon: 'search', title: 'No results', text: 'Try fewer words or different filters.' },
        onOpen: (it) => A.openItem(it, list.items()),
        itemActions: (it) => (q.trash ? [{ label: 'Restore', icon: 'restore', onClick: () => A.restore([it]) }] : A.itemActions(it)),
      });
    }
    load();
    setTimeout(() => input.focus(), 50);
  },
  unmount() { list && list.destroy(); list = null; },
};
