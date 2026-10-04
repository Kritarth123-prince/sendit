/** Trash: restore or permanently delete; shows original location, deletion date and days left. */
import { api } from '../core/api.js';
import { h, icon } from '../core/dom.js';
import { store } from '../core/store.js';
import { bus } from '../core/bus.js';
import { bytes } from '../core/format.js';
import { createFileList } from '../core/filelist.js';
import { confirm, toast } from '../core/ui.js';
import { realtime } from '../core/realtime.js';
import * as A from './_actions.js';

let list = null, offs = [];
export default {
  title: 'Trash',
  mount(el) {
    const info = h('div.view-sub', { text: 'Deleted files stay here until you remove them.' });
    const emptyBtn = h('button.btn.btn-danger', { type: 'button', on: { click: emptyTrash } }, icon('trash', 16), 'Empty Trash');
    const wrap = h('div');
    el.append(h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Trash' }), info), emptyBtn), wrap);
    list = createFileList(wrap, {
      variant: 'trash', mode: 'list',
      source: async ({ page, perPage }) => {
        const { data, meta } = await api.get('/trash', { page, per_page: perPage });
        const days = meta.retention_days ?? store.get('config')?.trash_retention_days;
        info.textContent = (days ? 'Items are deleted for good after ' + days + ' days.' : 'Items stay here until you delete them.') + (meta.total_bytes ? ' Using ' + bytes(meta.total_bytes) + '.' : '');
        return { items: (data || []).map((x) => ({ ...x, type: x.type || 'file' })), meta };
      },
      emptyState: { icon: 'trash', title: 'Trash is empty', text: 'Files you delete appear here so you can restore them.' },
      onOpen: () => {},
      itemActions: (it) => [
        { label: 'Restore', icon: 'restore', onClick: () => A.restore([it]) },
        '-',
        { label: 'Delete permanently', icon: 'trash', danger: true, onClick: () => A.purge([it]) },
      ],
      batchActions: (sel) => [
        h('button.btn.btn-sm', { type: 'button', on: { click: () => A.restore(sel) } }, icon('restore', 15), 'Restore'),
        h('button.btn.btn-sm.btn-danger', { type: 'button', on: { click: () => A.purge(sel) } }, icon('trash', 15), 'Delete forever'),
      ],
    });
    const reload = () => list.reload();
    offs = [
      bus.on('file.deleted', reload), bus.on('folder.deleted', reload),
      bus.on('file.restored', (e) => list.remove(e.file_id ?? e.data?.file?.id, 'file')),
      bus.on('folder.restored', (e) => list.remove(e.folder_id ?? e.data?.folder?.id, 'folder')),
      bus.on('file.purged', (e) => list.remove(e.data?.file_id ?? e.file_id, 'file')),
      bus.on('folder.purged', (e) => list.remove(e.data?.folder_id ?? e.folder_id, 'folder')),
      bus.on('trash.emptied', reload), bus.on('sync.reset', reload),
    ];
    async function emptyTrash() {
      if (!(await confirm({ title: 'Empty Trash?', message: 'Everything in Trash will be deleted forever. This cannot be undone.', confirmText: 'Empty Trash', danger: true }))) return;
      try {
        const { data } = await api.del('/trash');
        toast('Trash emptied' + (data?.freed_bytes ? ' — freed ' + bytes(data.freed_bytes) : ''), { type: 'ok' });
        realtime.nudge(); list.reload();
      } catch (e) { toast(e.message, { type: 'err' }); }
    }
  },
  unmount() { offs.forEach((o) => o()); list && list.destroy(); },
};
