/**
 * Upload manager: resumable chunked uploads with per-file progress, pause/resume, retry and
 * cancel. Works with mobile camera/photo pickers, drag-and-drop and paste (see app.js).
 *
 * Protocol (server §8.4): POST /uploads → PUT /uploads/{id}/chunks/{n} (raw bytes) →
 * POST /uploads/{id}/complete. Resuming asks GET /uploads/{id} which chunks already arrived.
 * @module features/uploader
 */
import { api, ApiError } from '../core/api.js';
import { bus } from '../core/bus.js';
import { store } from '../core/store.js';
import { h, icon, clear } from '../core/dom.js';
import { bytes, percent } from '../core/format.js';
import { toast } from '../core/ui.js';
import { realtime } from '../core/realtime.js';

const cfg = () => store.get('config')?.upload || {};
const items = [];      // upload items
let seq = 0;
let collapsed = false;
let wakeLock = null;

function makeItem(file, opts) {
  return {
    key: 'u' + (++seq), file, name: file.name || 'file', size: file.size,
    folderId: opts.folderId ?? null, fileId: opts.fileId ?? null, tags: opts.tags || [],
    isPermanent: opts.isPermanent ?? true, onConflict: opts.onConflict || 'rename', shareAfter: !!opts.shareAfter,
    status: 'queued', // queued | uploading | paused | assembling | done | failed | cancelled
    uploadId: null, chunkSize: 0, total: 0, sent: 0, error: null, result: null,
    started: 0, abort: null, retries: 0, speed: 0,
  };
}

function maxParallel() { return Math.max(1, Math.min(4, cfg().max_parallel || 2)); }

function pump() {
  const active = items.filter((i) => i.status === 'uploading' || i.status === 'assembling').length;
  let free = maxParallel() - active;
  for (const it of items) {
    if (free <= 0) break;
    if (it.status === 'queued') { free--; run(it); }
  }
  updateWakeLock();
  paint();
}

async function run(it) {
  it.status = 'uploading';
  it.error = null;
  it.started = it.started || Date.now();
  paint();
  try {
    if (!it.uploadId) {
      const blocked = (cfg().blocked_extensions || []).map((x) => String(x).toLowerCase());
      const ext = (it.name.split('.').pop() || '').toLowerCase();
      if (blocked.includes(ext)) throw new ApiError('BLOCKED_FILE_TYPE', 'This file type is not allowed.');
      if (cfg().max_upload_bytes && it.size > cfg().max_upload_bytes) throw new ApiError('PAYLOAD_TOO_LARGE', 'File is larger than the ' + bytes(cfg().max_upload_bytes) + ' limit.');
      const { data } = await api.post('/uploads', {
        name: it.name, size: it.size, folder_id: it.folderId, file_id: it.fileId, mime: it.file.type || undefined,
        tags: it.tags, is_permanent: it.isPermanent, on_conflict: it.onConflict, last_modified: it.file.lastModified || undefined,
      });
      it.uploadId = data.id;
      it.chunkSize = data.chunk_size;
      it.total = data.total_chunks;
      it.received = new Set(data.received || []);
    } else {
      // resume: ask which chunks the server already has
      const { data } = await api.get('/uploads/' + it.uploadId);
      if (data.status === 'completed' && data.result_file_id) { return finish(it, null); }
      it.received = new Set(data.received || []);
    }
    for (let n = 0; n < it.total; n++) {
      if (it.status !== 'uploading') return; // paused / cancelled
      if (it.received.has(n)) continue;
      const start = n * it.chunkSize;
      const blob = it.file.slice(start, Math.min(start + it.chunkSize, it.size));
      const ctrl = new AbortController();
      it.abort = ctrl;
      const before = sentBytes(it);
      const t0 = performance.now();
      await api.raw('PUT', '/uploads/' + it.uploadId + '/chunks/' + n, {
        body: blob, headers: { 'Content-Type': 'application/octet-stream' }, signal: ctrl.signal,
        onUploadProgress: (loaded) => { it.sent = before + loaded; paintItem(it); },
      });
      it.received.add(n);
      it.sent = sentBytes(it);
      const secs = (performance.now() - t0) / 1000;
      if (secs > 0) it.speed = blob.size / secs;
      it.retries = 0;
      paintItem(it);
    }
    if (it.status !== 'uploading') return;
    it.status = 'assembling';
    paintItem(it);
    const { data } = await api.post('/uploads/' + it.uploadId + '/complete', {});
    finish(it, data);
  } catch (e) {
    if (e && e.name === 'AbortError') return; // paused or cancelled
    if (it.status === 'cancelled') return;
    const transient = !(e instanceof ApiError) || ['NETWORK', 'HOST_CHALLENGE', 'RATE_LIMITED', 'SERVER_ERROR', 'HTTP_502', 'HTTP_503', 'HTTP_504'].includes(e.code);
    if (transient && it.retries < 6) {
      it.retries++;
      it.status = 'queued';
      it.error = 'Retrying…';
      paintItem(it);
      setTimeout(pump, Math.min(30000, 1000 * 2 ** it.retries));
      return;
    }
    it.status = 'failed';
    it.error = e.message || 'Upload failed';
    toast('Failed: ' + it.name + ' — ' + it.error, { type: 'err', timeout: 7000 });
  } finally {
    it.abort = null;
    pump();
  }
}

function sentBytes(it) {
  if (!it.received) return 0;
  let s = 0;
  for (const n of it.received) s += Math.min(it.chunkSize, it.size - n * it.chunkSize);
  return s;
}

function finish(it, file) {
  it.status = 'done';
  it.sent = it.size;
  it.result = file;
  if (file) bus.emit('upload.local.completed', { file, folderId: it.folderId });
  realtime.nudge();
  const doneCount = items.filter((i) => i.status === 'done').length;
  if (!items.some((i) => ['queued', 'uploading', 'assembling', 'paused'].includes(i.status))) {
    toast(doneCount === 1 ? '✓ ' + it.name + ' uploaded' : '✓ ' + doneCount + ' files uploaded', { type: 'ok' });
    setTimeout(() => { for (let i = items.length - 1; i >= 0; i--) if (items[i].status === 'done') items.splice(i, 1); paint(); }, 6000);
  }
  if (it.shareAfter && file) {
    import('./share-dialog.js').then((m) => m.openShareDialog({ files: [file] })).catch(() => toast('Uploaded. Sharing is not available yet.', { type: 'info' }));
  }
}

// ------------------------------------------------------------------ public API

export const uploader = {
  /**
   * @param {File[]|FileList} files
   * @param {{folderId?:number|null, fileId?:number, tags?:string[], isPermanent?:boolean, onConflict?:string, shareAfter?:boolean}} [opts]
   */
  add(files, opts = {}) {
    const list = Array.from(files || []);
    if (!list.length) return;
    // Resume support: a re-selected file that matches a paused/failed item continues it.
    for (const f of list) {
      const prior = items.find((i) => (i.status === 'failed' || i.status === 'paused') && i.name === f.name && i.size === f.size && i.uploadId);
      if (prior) { prior.file = f; prior.status = 'queued'; prior.retries = 0; continue; }
      items.push(makeItem(f, opts));
    }
    collapsed = false;
    pump();
  },
  pause(key) { const it = find(key); if (it && it.status === 'uploading') { it.status = 'paused'; it.abort && it.abort.abort(); paint(); pump(); } },
  resume(key) { const it = find(key); if (it && (it.status === 'paused' || it.status === 'failed')) { it.status = 'queued'; it.retries = 0; pump(); } },
  retry(key) { this.resume(key); },
  async cancel(key) {
    const it = find(key);
    if (!it) return;
    const prev = it.status;
    it.status = 'cancelled';
    it.abort && it.abort.abort();
    if (it.uploadId && prev !== 'done') api.del('/uploads/' + it.uploadId).catch(() => {});
    items.splice(items.indexOf(it), 1);
    pump();
  },
  items: () => items.slice(),
  /** Open the device file/camera picker. kind: 'any'|'photo'|'video'|'camera' */
  pick(kind = 'any', extra = {}) {
    const attrs = { type: 'file', multiple: kind !== 'camera', hidden: true };
    if (kind === 'photo') attrs.accept = 'image/*';
    if (kind === 'video') attrs.accept = 'video/*';
    if (kind === 'camera') { attrs.accept = 'image/*'; attrs.capture = 'environment'; }
    const i = h('input', attrs);
    i.addEventListener('change', () => { uploader.add(Array.from(i.files || []), extra); i.remove(); });
    document.body.appendChild(i);
    i.click();
  },
};

function find(key) { return items.find((i) => i.key === key); }

// ------------------------------------------------------------------ tray UI

function tray() { return document.getElementById('upload-tray'); }

function paint() {
  const t = tray();
  if (!t) return;
  store.set('uploads', items.slice());
  const badge = document.querySelector('[data-uploads-badge]');
  const activeCount = items.filter((i) => ['queued', 'uploading', 'assembling', 'paused'].includes(i.status)).length;
  if (badge) { badge.textContent = String(activeCount); badge.hidden = !activeCount; }
  clear(t);
  if (!items.length) return;
  const totalSize = items.reduce((s, i) => s + i.size, 0);
  const totalSent = items.reduce((s, i) => s + Math.min(i.size, i.sent), 0);
  const head = h('div.up-head', icon('upload', 16),
    h('span.grow', { text: activeCount ? 'Uploading ' + activeCount + ' of ' + items.length + ' · ' + Math.round(percent(totalSent, totalSize)) + '%' : 'Uploads finished' }),
    h('button.icon-btn.sm', { type: 'button', 'aria-label': collapsed ? 'Expand uploads' : 'Collapse uploads', on: { click: () => { collapsed = !collapsed; paint(); } } }, icon(collapsed ? 'chevron-down' : 'chevron-down', 16)),
    !activeCount ? h('button.icon-btn.sm', { type: 'button', 'aria-label': 'Close', on: { click: () => { items.length = 0; paint(); } } }, icon('x', 16)) : null);
  t.appendChild(head);
  if (collapsed) return;
  const list = h('div.up-list');
  items.forEach((it) => list.appendChild(itemEl(it)));
  t.appendChild(list);
}

function itemEl(it) {
  const pct = it.size ? percent(Math.min(it.sent, it.size), it.size) : (it.status === 'done' ? 100 : 0);
  const statusText = {
    queued: it.error || 'Waiting…', uploading: bytes(Math.min(it.sent, it.size)) + ' / ' + bytes(it.size) + (it.speed ? ' · ' + bytes(it.speed) + '/s' : ''),
    paused: 'Paused · ' + bytes(Math.min(it.sent, it.size)) + ' / ' + bytes(it.size), assembling: 'Finishing…', done: 'Done', failed: it.error || 'Failed', cancelled: 'Cancelled',
  }[it.status];
  const actions = [];
  if (it.status === 'uploading') actions.push(btn('pause', 'Pause', () => uploader.pause(it.key)));
  if (it.status === 'paused') actions.push(btn('play', 'Resume', () => uploader.resume(it.key)));
  if (it.status === 'failed') actions.push(btn('retry', 'Retry', () => uploader.retry(it.key)));
  if (it.status !== 'done') actions.push(btn('x', 'Cancel', () => uploader.cancel(it.key)));
  return h('div.up-item' + (it.status === 'done' ? '.done' : it.status === 'failed' ? '.failed' : ''), { dataset: { key: it.key } },
    h('div.row', h('span.up-name.grow.ellipsis', { text: it.name, title: it.name }), ...actions),
    h('div.progress', { role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': Math.round(pct), 'aria-label': 'Upload progress for ' + it.name }, h('span', { style: { width: pct + '%' } })),
    h('div.up-meta', h('span', { text: statusText }), h('span', { text: Math.round(pct) + '%' })));
}

function btn(ic, label, fn) {
  return h('button.icon-btn.sm', { type: 'button', 'aria-label': label, title: label, on: { click: fn } }, icon(ic, 15));
}

let paintQueued = false;
function paintItem(it) {
  // throttle repaints to one per frame
  if (paintQueued) return;
  paintQueued = true;
  requestAnimationFrame(() => {
    paintQueued = false;
    const el = tray()?.querySelector('[data-key="' + it.key + '"]');
    if (el && !collapsed) el.replaceWith(itemEl(it)); else paint();
    const head = tray()?.querySelector('.up-head .grow');
    if (head) {
      const totalSize = items.reduce((s, i) => s + i.size, 0);
      const totalSent = items.reduce((s, i) => s + Math.min(i.size, i.sent), 0);
      const active = items.filter((i) => ['queued', 'uploading', 'assembling', 'paused'].includes(i.status)).length;
      head.textContent = active ? 'Uploading ' + active + ' of ' + items.length + ' · ' + Math.round(percent(totalSent, totalSize)) + '%' : 'Uploads finished';
    }
  });
}

async function updateWakeLock() {
  const active = items.some((i) => i.status === 'uploading' || i.status === 'assembling');
  try {
    if (active && !wakeLock && 'wakeLock' in navigator && document.visibilityState === 'visible') {
      wakeLock = await navigator.wakeLock.request('screen');
      wakeLock.addEventListener('release', () => { wakeLock = null; });
    } else if (!active && wakeLock) { await wakeLock.release(); wakeLock = null; }
  } catch { wakeLock = null; }
}

window.addEventListener('beforeunload', (e) => {
  if (items.some((i) => ['queued', 'uploading', 'assembling'].includes(i.status))) { e.preventDefault(); e.returnValue = ''; }
});
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') updateWakeLock(); });
