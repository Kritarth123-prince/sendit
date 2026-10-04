/**
 * Dashboard: greeting, storage, quick actions, drag-and-drop share zone, recent files,
 * recently shared with me. Live-updating.
 */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { store } from '../core/store.js';
import { bus } from '../core/bus.js';
import { bytes, percent, relative } from '../core/format.js';
import { createFileList } from '../core/filelist.js';
import { liveList } from './_live.js';
import * as A from './_actions.js';

let list = null, off = null, offQuota = null;

export default {
  title: 'Dashboard',
  async mount(el) {
    const u = store.get('user');
    const hour = new Date().getHours();
    const greet = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
    const canUpload = (u.permissions || []).includes('files.upload');

    const storageCard = h('div.card');
    const paintQuota = (q) => {
      clear(storageCard);
      storageCard.append(h('div.card-title', icon('server', 17), 'Storage'));
      if (!q) return;
      if (q.quota_bytes === null || q.quota_bytes === undefined) {
        storageCard.append(h('div.kpi-value', { text: bytes(q.used_bytes) }), h('div.text2.small', { text: 'used · unlimited storage' }));
        return;
      }
      const pct = percent(q.used_bytes, q.quota_bytes);
      storageCard.append(
        h('div.quota-bar', { role: 'progressbar', 'aria-valuenow': Math.round(pct), 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-label': 'Storage used' }, h('span', { style: { width: pct + '%' } })),
        h('div.row', { style: { marginTop: '8px' } }, h('strong', { text: Math.round(pct) + '%' }), h('span.text2', { text: bytes(q.used_bytes) + ' / ' + bytes(q.quota_bytes) + ' used' })));
    };
    paintQuota(store.get('quota'));
    offQuota = store.on('quota', paintQuota);

    const quick = h('div.card', h('div.card-title', icon('bolt', 17), 'Quick actions'),
      h('div.row.wrap',
        canUpload ? h('button.btn.btn-primary', { type: 'button', on: { click: () => bus.emit('upload:open-picker') } }, icon('upload', 16), 'Upload') : null,
        canUpload ? h('button.btn', { type: 'button', on: { click: () => bus.emit('upload:open-picker', { accept: 'image/*', capture: 'environment' }) } }, icon('camera', 16), 'Camera') : null,
        canUpload ? h('button.btn', { type: 'button', on: { click: () => A.newFolder(null) } }, icon('folder-plus', 16), 'New folder') : null,
        h('a.btn', { href: '#/clipboard' }, icon('clipboard', 16), 'Save text'),
        h('a.btn', { href: '#/shared' }, icon('users', 16), 'Shared with me')));

    const drop = canUpload ? h('div.dropzone', { tabIndex: 0, role: 'button', dataset: { dropzone: '1' }, 'aria-label': 'Drop a file here to upload and share it' },
      icon('share', 36), h('div', { style: { fontWeight: 600, color: 'var(--text)' }, text: 'Drag a file here to share it' }), h('div.small', { text: 'It uploads, then you choose who gets access and copy the link.' })) : null;
    if (drop) {
      const pick = () => bus.emit('upload:open-picker', { extra: { shareAfter: true } });
      drop.addEventListener('click', pick);
      drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pick(); } });
      drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
      drop.addEventListener('dragleave', () => drop.classList.remove('over'));
      drop.addEventListener('drop', (e) => {
        e.preventDefault(); e.stopPropagation(); drop.classList.remove('over');
        const ov = document.getElementById('drop-overlay'); if (ov) ov.hidden = true;
        const files = Array.from(e.dataTransfer?.files || []);
        if (files.length) bus.emit('upload:files', { files, extra: { shareAfter: true } });
      });
    }

    const sharedCard = h('div.card', h('div.card-title', icon('users', 17), 'Recently shared with you'), h('div.text2.small', { text: 'Loading…' }));
    api.get('/shares/with-me', { per_page: 5 }).then(({ data }) => {
      const body = sharedCard.lastChild; body.remove();
      const items = (data || []).slice(0, 5);
      if (!items.length) { sharedCard.append(h('div.text2.small', { text: 'Nothing has been shared with you yet.' })); return; }
      sharedCard.append(h('div.list', ...items.map((s) => {
        const it = s.item || {};
        return h('a.list-item', { href: it.type === 'folder' ? '#/files/' + it.id : '#/shared' }, icon(it.type === 'folder' ? 'folder' : 'file', 18),
          h('div.li-main', h('div.li-title.ellipsis', { text: it.name || s.share?.title || 'Shared item' }), h('div.li-sub', { text: (s.share?.owner?.display_name || '') + ' · ' + relative(s.shared_at) })));
      })));
    }).catch(() => { sharedCard.lastChild.textContent = 'Shared items will appear here.'; });

    const recentWrap = h('div');
    el.append(
      h('div.view-head', h('div.grow', h('h1.view-title', { text: greet + ', ' + (u.display_name || u.username) }), h('div.view-sub', { text: 'Your files, synced across all your devices.' }))),
      h('div.grid-cards', storageCard, quick, sharedCard),
      drop ? h('div.section-gap', drop) : null,
      h('div.section-gap', h('div.row', { style: { marginBottom: '10px' } }, h('h2', { style: { fontSize: '17px' }, text: 'Recent files' }), h('span.grow'), h('a.btn.btn-sm.btn-ghost', { href: '#/recent' }, 'See all', icon('chevron-right', 14))), recentWrap));

    list = createFileList(recentWrap, {
      variant: 'recent', mode: 'grid', perPage: 12, selectable: false,
      source: async ({ page }) => {
        if (page > 1) return { items: [], meta: { has_more: false } };
        const { data } = await api.get('/files', { view: 'recent', per_page: 12 });
        return { items: (data || []).slice(0, 12).map((f) => ({ ...f, type: 'file' })), meta: { has_more: false } };
      },
      emptyState: { icon: 'clock', title: 'No recent files', text: 'Files you upload or change show up here.' },
      onOpen: (it) => A.openItem(it, list.items()),
      itemActions: (it) => A.itemActions(it),
    });
    off = liveList(list, { belongs: (f) => !f.deleted_at && f.owner?.id === u.id });
  },
  unmount() { off && off(); offQuota && offQuota(); list && list.destroy(); list = off = offQuota = null; },
};
