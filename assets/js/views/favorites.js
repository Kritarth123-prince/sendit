/** Favourites: starred files (your own and ones shared with you). */
import { api } from '../core/api.js';
import { h } from '../core/dom.js';
import { store } from '../core/store.js';
import { bus } from '../core/bus.js';
import { createFileList } from '../core/filelist.js';
import { liveList } from './_live.js';
import * as A from './_actions.js';

let list = null, off = null, off2 = null;
export default {
  title: 'Favourites',
  mount(el) {
    const wrap = h('div');
    el.append(h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Favourites' }), h('div.view-sub', { text: 'Files you starred. Use ★ in any file’s menu to add one.' }))), wrap);
    list = createFileList(wrap, {
      variant: 'favorites', mode: store.get('user')?.preferences?.view || 'grid',
      source: async ({ page, perPage }) => { const { data, meta } = await api.get('/files', { view: 'favorites', page, per_page: perPage }); return { items: (data || []).map((f) => ({ ...f, type: 'file' })), meta }; },
      emptyState: { icon: 'star', title: 'No favourites yet', text: 'Star files you use often to find them here quickly.' },
      onOpen: (it) => A.openItem(it, list.items()),
      itemActions: (it) => A.itemActions(it, { onChanged: () => list.reload() }),
    });
    off = liveList(list, { belongs: (f) => f.favorite !== false && !f.deleted_at && list.get(f.id) !== undefined });
    off2 = bus.on('file.updated', (e) => { if (e.data?.changes?.includes?.('favorite')) list.reload(); });
  },
  unmount() { off && off(); off2 && off2(); list && list.destroy(); },
};
