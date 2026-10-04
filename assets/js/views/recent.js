/** Recent: your most recently changed files. */
import { api } from '../core/api.js';
import { h } from '../core/dom.js';
import { store } from '../core/store.js';
import { createFileList } from '../core/filelist.js';
import { liveList } from './_live.js';
import * as A from './_actions.js';

let list = null, off = null;
export default {
  title: 'Recent',
  mount(el) {
    const me = store.get('user');
    const wrap = h('div');
    el.append(h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Recent' }), h('div.view-sub', { text: 'Files you uploaded or changed most recently.' }))), wrap);
    list = createFileList(wrap, {
      variant: 'recent', mode: store.get('user')?.preferences?.view || 'grid',
      source: async ({ page, perPage }) => { const { data, meta } = await api.get('/files', { view: 'recent', page, per_page: perPage }); return { items: (data || []).map((f) => ({ ...f, type: 'file' })), meta }; },
      emptyState: { icon: 'clock', title: 'Nothing recent', text: 'Files you upload or change appear here.' },
      onOpen: (it) => A.openItem(it, list.items()),
      itemActions: (it) => A.itemActions(it),
      batchActions: (sel) => [h('button.btn.btn-sm.btn-danger', { type: 'button', text: 'Move to Trash', on: { click: () => A.trash(sel) } })],
    });
    off = liveList(list, { belongs: (f) => f.type !== 'folder' && !f.deleted_at && f.owner?.id === me.id });
  },
  unmount() { off && off(); list && list.destroy(); },
};
