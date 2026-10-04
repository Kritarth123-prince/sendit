/** Uploads: this device's queue plus uploads running on your other devices (live). */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { bus } from '../core/bus.js';
import { store } from '../core/store.js';
import { bytes, percent, relative } from '../core/format.js';
import { emptyState } from '../core/ui.js';

let offs = [];
export default {
  title: 'Uploads',
  mount(el) {
    const local = h('div.card');
    const remote = h('div.card');
    const pick = (kind, label, ic, accept, capture) => h('button.btn', { type: 'button', on: { click: () => bus.emit('upload:open-picker', { accept, capture }) } }, icon(ic, 16), label);
    el.append(
      h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Uploads' }), h('div.view-sub', { text: 'Uploads continue while this page is open. If your connection drops they resume automatically.' }))),
      h('div.card', h('div.row.wrap', pick('any', 'Choose files', 'upload'), pick('photo', 'Photos', 'image', 'image/*'), pick('video', 'Videos', 'video', 'video/*'), pick('camera', 'Take photo', 'camera', 'image/*', 'environment'), pick('rec', 'Record video', 'video', 'video/*', 'environment'))),
      h('div.section-gap', h('h2', { style: { fontSize: '16px', marginBottom: '8px' }, text: 'On this device' }), local),
      h('div.section-gap', h('h2', { style: { fontSize: '16px', marginBottom: '8px' }, text: 'On your other devices' }), remote));

    const paintLocal = (items) => {
      clear(local);
      if (!items || !items.length) { local.appendChild(h('p.text2', { text: 'No uploads in progress here. Use the buttons above, drag files onto the page, or paste a screenshot.' })); return; }
      items.forEach((it) => local.appendChild(h('div.up-item', h('div.row', h('span.up-name.grow.ellipsis', { text: it.name }), h('span.pill', { text: it.status })),
        h('div.progress', h('span', { style: { width: percent(Math.min(it.sent, it.size), it.size) + '%' } })),
        h('div.up-meta', h('span', { text: bytes(Math.min(it.sent, it.size)) + ' / ' + bytes(it.size) }), h('span', { text: Math.round(percent(Math.min(it.sent, it.size), it.size)) + '%' })))));
    };
    paintLocal(store.get('uploads'));
    offs.push(store.on('uploads', paintLocal));

    const others = new Map();
    const paintRemote = () => {
      clear(remote);
      const list = [...others.values()].filter((u) => u.client_id !== api.clientId);
      if (!list.length) { remote.appendChild(emptyState({ icon: 'device', title: 'No uploads on other devices', text: 'Uploads you start on your phone or another computer show up here live.' })); return; }
      list.forEach((u) => remote.appendChild(h('div.up-item', h('div.row', h('span.up-name.grow.ellipsis', { text: u.name }), h('span.small.text2', { text: u.status === 'active' ? 'Uploading…' : u.status })),
        h('div.progress', h('span', { style: { width: percent(u.received_bytes || 0, u.size) + '%' } })),
        h('div.up-meta', h('span', { text: bytes(u.received_bytes || 0) + ' / ' + bytes(u.size) }), h('span', { text: u.updated_at ? relative(u.updated_at) : '' })))));
    };
    api.get('/uploads', { status: 'active' }).then(({ data }) => { (data || []).forEach((u) => others.set(u.id, u)); paintRemote(); }).catch(() => paintRemote());
    const upd = (e) => {
      const d = e.data || {}; if (!d.upload_id) return;
      const u = others.get(d.upload_id) || { id: d.upload_id, name: d.name, size: d.size, status: 'active' };
      if (e.origin && e.origin === api.clientId) return;
      if (e.type === 'upload.completed' || e.type === 'upload.failed') others.delete(d.upload_id);
      else others.set(d.upload_id, { ...u, received_bytes: d.received_bytes ?? u.received_bytes, status: 'active', updated_at: e.timestamp });
      paintRemote();
    };
    ['upload.started', 'upload.progress', 'upload.completed', 'upload.failed'].forEach((t) => offs.push(bus.on(t, upd)));
  },
  unmount() { offs.forEach((o) => o()); offs = []; },
};
