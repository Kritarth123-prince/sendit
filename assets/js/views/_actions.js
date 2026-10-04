/**
 * File/folder actions shared by the views (open, preview, edit, download, rename, move, share,
 * favourite, details/activity/comments/versions, trash, restore, delete permanently, new folder).
 */
import { api } from '../core/api.js';
import { h, icon } from '../core/dom.js';
import { toast, modal, confirm, prompt, copyText } from '../core/ui.js';
import { router } from '../core/router.js';
import { realtime } from '../core/realtime.js';
import { bytes, dateTime } from '../core/format.js';

const DETAIL_TABS = ['info', 'activity', 'comments', 'versions', 'sharing'];

/**
 * Deep link into the details panel: a view's hash route may carry ?file=<id>&tab=<tab>
 * (e.g. #/files/12?file=345&tab=comments from a notification). Opens the panel for that file;
 * returns true when the query asked for it. The panel loads the file itself and shows "not
 * found" for files the user cannot see.
 */
export function openDetailsFromQuery(query) {
  const id = parseInt(String(query?.file ?? ''), 10);
  if (!(id > 0) || String(id) !== String(query.file).trim()) return false;
  const tab = DETAIL_TABS.includes(query.tab) ? query.tab : 'info';
  import('../features/details.js').then((m) => m.openDetails(id, tab)).catch((e) => toast(e.message, { type: 'err' }));
  return true;
}

export function downloadUrl(item) {
  return item.type === 'folder' ? api.url('/folders/' + item.id + '/zip') : api.url('/files/' + item.id + '/download');
}

export function download(item) {
  const a = h('a', { href: downloadUrl(item), download: '', hidden: true });
  document.body.appendChild(a); a.click(); a.remove();
}

export async function openItem(item, list = []) {
  if (item.type === 'folder') { router.go('/files/' + item.id); return; }
  try {
    const m = await import('../features/preview.js');
    const files = list.filter((x) => x.type !== 'folder');
    m.openPreview(item, { list: files.length ? files : [item], index: Math.max(0, files.findIndex((x) => x.id === item.id)) });
  } catch (e) {
    console.error(e);
    download(item);
  }
}

export async function rename(item) {
  const name = await prompt({ title: 'Rename', label: 'New name', value: item.name, validate: (v) => (!v ? 'Enter a name.' : v.length > 255 ? 'That name is too long.' : null) });
  if (!name || name === item.name) return;
  try {
    const path = item.type === 'folder' ? '/folders/' + item.id : '/files/' + item.id;
    await api.patch(path, { name });
    toast('Renamed to “' + name + '”', { type: 'ok' });
    realtime.nudge();
  } catch (e) { toast(e.message, { type: 'err' }); }
}

/** Folder picker. Resolves to a folder id, null (= My Files root) or undefined (cancelled). */
export async function pickFolder({ title = 'Move to…', excludeIds = [] } = {}) {
  let tree = [];
  try { tree = (await api.get('/folders/tree')).data || []; } catch (e) { toast(e.message, { type: 'err' }); return undefined; }
  const byParent = new Map();
  tree.forEach((f) => { const k = f.parent_id ?? 0; if (!byParent.has(k)) byParent.set(k, []); byParent.get(k).push(f); });
  let chosen = null, result;
  const listEl = h('div.list', { role: 'listbox', 'aria-label': 'Folders' });
  const opt = (id, label, depth) => {
    const b = h('button.list-item', { type: 'button', role: 'option', style: { paddingLeft: 8 + depth * 18 + 'px', width: '100%', textAlign: 'left' }, on: { click: () => { chosen = id; listEl.querySelectorAll('.list-item').forEach((x) => x.classList.remove('selected')); b.classList.add('selected'); b.style.background = 'var(--accent-a20)'; listEl.querySelectorAll('.list-item').forEach((x) => { if (x !== b) x.style.background = ''; }); } } },
      icon(id === null ? 'home' : 'folder', 17), h('span', { text: label }));
    listEl.appendChild(b);
  };
  opt(null, 'My Files', 0);
  const walk = (pid, depth) => (byParent.get(pid) || []).sort((a, b) => a.name.localeCompare(b.name)).forEach((f) => { if (excludeIds.includes(f.id)) return; opt(f.id, f.name, depth); walk(f.id, depth + 1); });
  walk(0, 1);
  return new Promise((resolve) => {
    modal({ title, content: listEl, actions: [{ label: 'Cancel', kind: 'ghost' }, { label: 'Move here', kind: 'primary', onClick: () => { result = chosen; } }], onClose: () => resolve(result === undefined ? undefined : result) });
  });
}

export async function move(items) {
  const folderIds = items.filter((i) => i.type === 'folder').map((i) => i.id);
  const target = await pickFolder({ excludeIds: folderIds });
  if (target === undefined) return;
  await moveTo(items, target);
}

export async function moveTo(items, folderId) {
  let ok = 0;
  for (const it of items) {
    try {
      if (it.type === 'folder') await api.patch('/folders/' + it.id, { parent_id: folderId });
      else await api.patch('/files/' + it.id, { folder_id: folderId });
      ok++;
    } catch (e) { toast(it.name + ': ' + e.message, { type: 'err' }); }
  }
  if (ok) toast('Moved ' + (ok === 1 ? '“' + items[0].name + '”' : ok + ' items'), { type: 'ok' });
  realtime.nudge();
}

export async function trash(items) {
  const n = items.length;
  const okGo = await confirm({ title: 'Move to Trash?', message: n === 1 ? '“' + items[0].name + '” will be moved to Trash. You can restore it from there.' : n + ' items will be moved to Trash. You can restore them from there.', confirmText: 'Move to Trash', danger: true });
  if (!okGo) return false;
  let ok = 0;
  for (const it of items) {
    try { await api.del(it.type === 'folder' ? '/folders/' + it.id : '/files/' + it.id); ok++; } catch (e) { toast(it.name + ': ' + e.message, { type: 'err' }); }
  }
  if (ok) toast((ok === 1 ? '“' + items[0].name + '”' : ok + ' items') + ' moved to Trash', { type: 'ok', action: { label: 'Undo', onClick: () => restore(items.slice(0, ok)) } });
  realtime.nudge();
  return ok > 0;
}

export async function restore(items) {
  let ok = 0;
  for (const it of items) {
    try { await api.post('/trash/' + it.id + '/restore' + (it.type === 'folder' ? '?kind=folder' : '')); ok++; } catch (e) { toast(it.name + ': ' + e.message, { type: 'err' }); }
  }
  if (ok) toast('Restored ' + (ok === 1 ? '“' + items[0].name + '”' : ok + ' items'), { type: 'ok' });
  realtime.nudge();
}

export async function purge(items) {
  const okGo = await confirm({ title: 'Delete permanently?', message: (items.length === 1 ? '“' + items[0].name + '”' : items.length + ' items') + ' will be deleted forever. This cannot be undone.', confirmText: 'Delete forever', danger: true });
  if (!okGo) return;
  let ok = 0;
  for (const it of items) {
    try { await api.del('/trash/' + it.id + (it.type === 'folder' ? '?kind=folder' : '')); ok++; } catch (e) { toast(it.name + ': ' + e.message, { type: 'err' }); }
  }
  if (ok) toast('Deleted permanently', { type: 'ok' });
  realtime.nudge();
}

export async function toggleFavourite(item) {
  try {
    await api.patch('/files/' + item.id, { favorite: !item.favorite });
    toast(item.favorite ? 'Removed from favourites' : '★ Added to favourites', { type: 'ok', timeout: 2000 });
    realtime.nudge();
    return !item.favorite;
  } catch (e) { toast(e.message, { type: 'err' }); return item.favorite; }
}

export async function share(items) {
  try {
    const m = await import('../features/share-dialog.js');
    const folder = items.length === 1 && items[0].type === 'folder' ? items[0] : null;
    m.openShareDialog(folder ? { folder } : { files: items.filter((i) => i.type !== 'folder') });
  } catch {
    // Minimal fallback: create a download link and copy it.
    try {
      const body = items.length === 1 && items[0].type === 'folder'
        ? { kind: 'link', folder_id: items[0].id, permission: 'downloader' }
        : { kind: 'link', file_ids: items.map((i) => i.id), permission: 'downloader' };
      const { data } = await api.post('/shares', body);
      const s = Array.isArray(data) ? data[0] : data;
      if (s?.url) { await copyText(s.url); toast('Share link copied: ' + s.url, { type: 'ok', timeout: 6000 }); }
    } catch (e) { toast(e.message, { type: 'err' }); }
  }
}

export async function newFolder(parentId) {
  const name = await prompt({ title: 'New folder', label: 'Folder name', placeholder: 'e.g. Projects', confirmText: 'Create' });
  if (!name) return null;
  try {
    const { data } = await api.post('/folders', { name, parent_id: parentId || null });
    toast('Folder “' + name + '” created', { type: 'ok' });
    realtime.nudge();
    return data;
  } catch (e) { toast(e.message, { type: 'err' }); return null; }
}

/** Text and code files up to 2 MB open in the in-browser editor. */
export function isEditable(item) {
  return item && item.type !== 'folder' && ['text', 'code'].includes(item.kind) && (Number(item.size) || 0) <= 2097152;
}

export async function edit(item) {
  try {
    const m = await import('../features/editor.js');
    m.openEditor(item);
  } catch (e) { console.error(e); toast('The editor could not be opened.', { type: 'err' }); }
}

/** Open the details panel on a tab: info | activity | comments | versions | sharing. */
export async function details(item, tab = 'info') {
  try {
    const m = await import('../features/details.js');
    m.openDetails(item.id, tab);
  } catch (e) { console.error(e); if (tab === 'info') showInfo(item, true); }
}

export async function showInfo(item, simple = false) {
  if (!simple) {
    try {
      const m = await import('../features/details.js');
      m.openDetails(item.id, 'info');
      return;
    } catch { /* fall back to a simple info dialog */ }
  }
  let f = item;
  try { f = (await api.get('/files/' + item.id)).data || item; } catch { /* use list data */ }
  const row = (k, v) => (v === null || v === undefined || v === '' ? null : h('div.row', h('span.text2', { style: { width: '120px' }, text: k }), h('span.grow', { text: String(v) })));
  modal({ title: f.name, content: h('div.stack', row('Type', (f.ext || f.kind || '').toUpperCase()), row('Size', bytes(f.size)), row('Owner', f.owner?.display_name), row('Created', dateTime(f.created_at)), row('Modified', dateTime(f.updated_at)), row('Version', f.version), row('Downloads', f.download_count), row('Tags', (f.tags || []).join(', '))) });
}

/** Standard context-menu items for a file or folder. */
export function itemActions(item, { onChanged } = {}) {
  const a = item.access || {};
  const isFolder = item.type === 'folder';
  const can = (k) => a[k] !== false && (a[k] || a.role === 'owner' || a.role === 'admin' || a.role === undefined);
  return [
    { label: isFolder ? 'Open' : 'Preview', icon: isFolder ? 'folder' : 'eye', onClick: () => openItem(item) },
    !isFolder && isEditable(item) && can('edit') ? { label: 'Edit', icon: 'code', onClick: () => edit(item) } : null,
    { label: 'Download', icon: 'download', onClick: () => download(item), disabled: !isFolder && a.download === false },
    can('share') ? { label: 'Share', icon: 'share', onClick: () => share([item]) } : null,
    !isFolder ? { label: item.favorite ? 'Remove from favourites' : 'Add to favourites', icon: 'star', onClick: async () => { await toggleFavourite(item); onChanged && onChanged(); } } : null,
    '-',
    can('edit') ? { label: 'Rename', icon: 'edit', onClick: () => rename(item) } : null,
    can('move') ? { label: 'Move', icon: 'move', onClick: () => move([item]) } : null,
    !isFolder ? '-' : null,
    !isFolder ? { label: 'Details', icon: 'info', onClick: () => details(item, 'info') } : null,
    !isFolder && can('activity') ? { label: 'Activity', icon: 'activity', onClick: () => details(item, 'activity') } : null,
    !isFolder ? { label: 'Comments' + (item.comment_count ? ' (' + item.comment_count + ')' : ''), icon: 'comment', onClick: () => details(item, 'comments') } : null,
    !isFolder && can('versions') ? { label: 'Versions', icon: 'history', onClick: () => details(item, 'versions') } : null,
    can('delete') ? '-' : null,
    can('delete') ? { label: 'Move to Trash', icon: 'trash', danger: true, onClick: () => trash([item]) } : null,
  ].filter(Boolean);
}
