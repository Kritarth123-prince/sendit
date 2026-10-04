/**
 * My Files: folder browsing with breadcrumbs, grid/list, sorting, kind filter, selection,
 * batch actions, drag-and-drop moves and real-time updates.
 */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { store } from '../core/store.js';
import { bus } from '../core/bus.js';
import { createFileList } from '../core/filelist.js';
import { toast } from '../core/ui.js';
import { liveList } from './_live.js';
import * as A from './_actions.js';

let list = null;
let off = null;

const KINDS = [['', 'All'], ['image', 'Images'], ['video', 'Video'], ['audio', 'Audio'], ['pdf', 'PDFs'], ['document', 'Documents'], ['code', 'Code'], ['archive', 'Archives']];

export default {
  title: 'My Files',
  async mount(el, params, query) {
    const folderId = params.folderId ? parseInt(params.folderId, 10) : null;
    const prefs = store.get('user')?.preferences || {};
    const state = { sort: query.sort || prefs.sort || 'name', order: query.order || prefs.order || 'asc', kind: query.kind || '', mode: prefs.view || 'grid' };
    const user = store.get('user');
    const canUpload = (user.permissions || []).includes('files.upload');
    let deepLinked = false; // ?file=<id>&tab=<tab>: open the details panel once the list has loaded

    const crumbs = h('nav.crumbs', { 'aria-label': 'Folder path' }, h('span.current', { text: 'My Files' }));
    const title = h('h1.view-title', { text: 'My Files' });
    const head = h('div.view-head', h('div.grow', title, crumbs));
    const newFolderBtn = h('button.btn', { type: 'button', on: { click: () => A.newFolder(folderId) } }, icon('folder-plus', 17), h('span.btn-label', { text: 'New folder' }));
    const uploadBtn = h('button.btn.btn-primary', { type: 'button', on: { click: () => bus.emit('upload:open-picker', { extra: { folderId } }) } }, icon('upload', 17), h('span.btn-label', { text: 'Upload' }));
    const cameraBtn = h('button.btn', { type: 'button', title: 'Take a photo', 'aria-label': 'Take a photo', on: { click: () => bus.emit('upload:open-picker', { accept: 'image/*', capture: 'environment', extra: { folderId } }) } }, icon('camera', 17));
    if (canUpload || folderId) head.append(newFolderBtn, cameraBtn, uploadBtn);

    const sortSel = h('select.select', { 'aria-label': 'Sort by', style: { width: 'auto' } },
      ...[['name', 'Name'], ['updated_at', 'Modified'], ['created_at', 'Uploaded'], ['size', 'Size'], ['kind', 'Type']].map(([v, l]) => h('option', { value: v, text: l, selected: state.sort === v })));
    const orderBtn = h('button.btn.btn-sm', { type: 'button', 'aria-label': 'Toggle sort order', on: { click: () => { state.order = state.order === 'asc' ? 'desc' : 'asc'; orderBtn.textContent = state.order === 'asc' ? '↑' : '↓'; savePrefs(); list.reload(); } } }, state.order === 'asc' ? '↑' : '↓');
    sortSel.addEventListener('change', () => { state.sort = sortSel.value; savePrefs(); list.reload(); });
    const modeSeg = h('div.seg', { role: 'group', 'aria-label': 'View' },
      h('button', { type: 'button', 'aria-label': 'Grid view', class: state.mode === 'grid' ? 'active' : '', on: { click: (e) => setMode('grid', e) } }, icon('grid', 16)),
      h('button', { type: 'button', 'aria-label': 'List view', class: state.mode === 'list' ? 'active' : '', on: { click: (e) => setMode('list', e) } }, icon('list', 16)));
    const chips = h('div.row.wrap', ...KINDS.map(([k, l]) => h('button.chip' + (state.kind === k ? '.active' : ''), { type: 'button', 'aria-pressed': state.kind === k ? 'true' : 'false', text: l, on: { click: (e) => { state.kind = k; chips.querySelectorAll('.chip').forEach((c) => { c.classList.remove('active'); c.setAttribute('aria-pressed', 'false'); }); e.currentTarget.classList.add('active'); e.currentTarget.setAttribute('aria-pressed', 'true'); list.reload(); } } })));
    const toolbar = h('div.toolbar', chips, h('span.spacer'), sortSel, orderBtn, modeSeg);
    const listWrap = h('div');
    el.append(head, toolbar, listWrap);

    function setMode(m, e) { state.mode = m; modeSeg.querySelectorAll('button').forEach((b) => b.classList.remove('active')); e.currentTarget.classList.add('active'); list.setMode(m); savePrefs(); }
    function savePrefs() {
      const p = { ...(store.get('user')?.preferences || {}), view: state.mode, sort: state.sort, order: state.order };
      store.update('user', (u) => ({ ...u, preferences: p }));
      api.patch('/user', { preferences: p }).catch(() => {});
    }

    list = createFileList(listWrap, {
      variant: 'files', mode: state.mode,
      source: async ({ page, perPage }) => {
        const q = { page, per_page: perPage, sort: state.sort, order: state.order, kind: state.kind || undefined };
        if (folderId) q.folder_id = folderId; else q.root = 1;
        const { data, meta } = await api.get('/files', q);
        const folders = page === 1 && !state.kind ? (meta.folders || []).map((f) => ({ ...f, type: 'folder' })) : [];
        if (page === 1) paintHead(meta);
        if (!deepLinked) { deepLinked = true; setTimeout(() => A.openDetailsFromQuery(query), 0); }
        return { items: [...folders, ...(data || []).map((f) => ({ ...f, type: f.type || 'file' }))], meta };
      },
      emptyState: { icon: 'folder', title: folderId ? 'This folder is empty' : 'No files yet', text: 'Drop files anywhere on this page, paste a screenshot, or use Upload.', action: canUpload || folderId ? { label: 'Upload files', icon: 'upload', onClick: () => bus.emit('upload:open-picker', { extra: { folderId } }) } : null },
      onOpen: (it) => A.openItem(it, list.items()),
      itemActions: (it) => A.itemActions(it),
      onMove: (items, folder) => A.moveTo(items, folder.id),
      batchActions: (sel) => [
        h('button.btn.btn-sm', { type: 'button', on: { click: () => zip(sel) } }, icon('download', 15), 'Download'),
        h('button.btn.btn-sm', { type: 'button', on: { click: () => A.share(sel) } }, icon('share', 15), 'Share'),
        h('button.btn.btn-sm', { type: 'button', on: { click: () => A.move(sel) } }, icon('move', 15), 'Move'),
        h('button.btn.btn-sm.btn-danger', { type: 'button', on: { click: async () => { if (await A.trash(sel)) list.clearSelection(); } } }, icon('trash', 15), 'Trash'),
      ],
      accept: (it) => (it.type === 'folder' ? (it.parent_id ?? null) === folderId : (it.folder_id ?? null) === folderId && (!state.kind || it.kind === state.kind)),
    });
    off = liveList(list, { belongs: (it) => (it.type === 'folder' ? (it.parent_id ?? null) === folderId : (it.folder_id ?? null) === folderId && (!state.kind || it.kind === state.kind) && !it.deleted_at) });

    function paintHead(meta) {
      if (!folderId) return;
      const f = meta.folder;
      if (f) title.textContent = f.name;
      clear(crumbs);
      crumbs.append(h('a', { href: '#/files', text: 'My Files' }));
      (meta.breadcrumbs || []).forEach((b, i, arr) => {
        crumbs.append(h('span.sep', icon('chevron-right', 14)));
        crumbs.append(i === arr.length - 1 ? h('span.current', { text: b.name }) : h('a', { href: '#/files/' + b.id, text: b.name }));
      });
    }

    function zip(sel) {
      if (sel.length === 1 && sel[0].type !== 'folder') { A.download(sel[0]); return; }
      // Post into a hidden frame: a successful ZIP downloads; an error (JSON) is shown as a toast
      // instead of replacing the page with raw JSON.
      const name = 'zipframe' + Date.now();
      const frame = h('iframe', { name, hidden: true, title: 'download' });
      frame.addEventListener('load', () => {
        try {
          const text = frame.contentDocument?.body?.textContent || '';
          const j = text ? JSON.parse(text) : null;
          if (j && j.success === false) toast(j.error?.message || 'Could not create the ZIP.', { type: 'err' });
        } catch { /* binary download or cross-origin: nothing to report */ }
        setTimeout(() => frame.remove(), 60000);
      });
      const form = h('form', { method: 'POST', action: api.url('/files/zip'), target: name, hidden: true },
        h('input', { type: 'hidden', name: '_csrf', value: api.csrf }),
        ...sel.filter((x) => x.type !== 'folder').map((x) => h('input', { type: 'hidden', name: 'file_ids[]', value: String(x.id) })),
        ...sel.filter((x) => x.type === 'folder').map((x) => h('input', { type: 'hidden', name: 'folder_ids[]', value: String(x.id) })));
      document.body.append(frame, form); form.submit(); form.remove();
      toast('Preparing ZIP…', { type: 'info' });
    }
  },
  unmount() { off && off(); list && list.destroy(); list = null; off = null; },
};
