/**
 * Wire a file list to real-time events. Returns an unsubscribe function.
 * - file.created / file.updated / file.renamed / file.restored / version.created → upsert if it belongs here
 * - file.deleted / file.purged / file.moved (out of this folder) → remove
 * - folder.* likewise; sync.reset → reload
 */
import { bus } from '../core/bus.js';
import { api } from '../core/api.js';
import { store } from '../core/store.js';

export function liveList(list, { belongs, onCount } = {}) {
  const me = () => store.get('user');
  const withAccess = async (f) => {
    if (!f) return null;
    if (f.access) return f;
    if (f.owner && f.owner.id === me()?.id) return { ...f, access: { role: 'owner', preview: true, download: true, comment: true, edit: true, share: true, delete: true, move: true, versions: true, activity: true, manage: true } };
    try { return (await api.get('/files/' + f.id)).data; } catch { return null; }
  };
  const upsertFile = async (e) => {
    const f = await withAccess(e.data?.file);
    if (!f) return;
    if (!belongs || belongs(f, e)) list.upsert(f); else list.remove(f.id, 'file');
    onCount && onCount();
  };
  const offs = [
    bus.on('file.created', upsertFile),
    bus.on('file.updated', upsertFile),
    bus.on('file.renamed', upsertFile),
    bus.on('file.restored', upsertFile),
    bus.on('version.created', upsertFile),
    bus.on('file.moved', upsertFile),
    bus.on('file.deleted', (e) => { list.remove(e.data?.file_id ?? e.file_id, 'file'); onCount && onCount(); }),
    bus.on('file.purged', (e) => { list.remove(e.data?.file_id ?? e.file_id, 'file'); onCount && onCount(); }),
    bus.on('folder.created', (e) => { const d = e.data?.folder; if (d && (!belongs || belongs({ ...d, type: 'folder' }, e))) list.upsert({ ...d, type: 'folder' }); }),
    bus.on('folder.updated', (e) => { const d = e.data?.folder; if (!d) return; if (!belongs || belongs({ ...d, type: 'folder' }, e)) list.upsert({ ...d, type: 'folder' }); else list.remove(d.id, 'folder'); }),
    bus.on('folder.restored', (e) => { const d = e.data?.folder; if (d && (!belongs || belongs({ ...d, type: 'folder' }, e))) list.upsert({ ...d, type: 'folder' }); }),
    bus.on('folder.deleted', (e) => list.remove(e.data?.folder_id ?? e.folder_id, 'folder')),
    bus.on('folder.purged', (e) => list.remove(e.data?.folder_id ?? e.folder_id, 'folder')),
    bus.on('upload.local.completed', ({ file }) => { if (file && (!belongs || belongs(file, null))) list.upsert(file); }),
    bus.on('sync.reset', () => list.reload()),
  ];
  return () => offs.forEach((off) => off());
}
