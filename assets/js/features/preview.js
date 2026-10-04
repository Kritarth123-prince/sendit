/**
 * File previewer (§12.4): one full-height dialog with previous/next across the list.
 *  - Images: zoom (buttons, wheel, pinch), rotate, pan, double-click/tap to zoom, swipe for
 *    previous/next on touch, dimensions and EXIF date/camera for JPEG photos.
 *  - PDF: pdf.js viewer (features/viewers/pdf.js) — pages, zoom, fit width, search.
 *  - Text/code: highlighted source with line numbers, copy and find (features/viewers/code.js).
 *  - Video/audio: native players with ±10 s buttons.
 * Uploaded content is never executed: HTML, SVG and scripts are shown as source.
 * @module features/preview
 */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { modal, spinner, errorState } from '../core/ui.js';
import { bytes, dateTime } from '../core/format.js';
import { fetchBytes } from './viewers/common.js';
import { parseExif, exifDate, cameraLine } from './viewers/exif.js';

const TEXT_EXT = ['txt', 'md', 'markdown', 'log', 'csv', 'tsv', 'json', 'xml', 'svg', 'html', 'htm', 'xhtml', 'yaml', 'yml', 'ini', 'conf', 'cfg', 'sql', 'sh', 'bash', 'diff', 'patch', 'env', 'toml', 'properties'];
const EDIT_MAX = 2 * 1024 * 1024;

const isTextLike = (f) => ['text', 'code'].includes(f.kind) || TEXT_EXT.includes(String(f.ext || '').toLowerCase()) || String(f.mime || '').startsWith('text/');
const canEdit = (f) => ['text', 'code'].includes(f.kind) && !!(f.access && f.access.edit) && (Number(f.size) || 0) <= EDIT_MAX;

function toolBtn(ic, label, onClick, { text, cls = '' } = {}) {
  return h('button.btn.btn-sm' + (text ? '' : '.pv-icon') + cls, { type: 'button', 'aria-label': label, title: label, on: { click: onClick } },
    icon(ic, 16), text ? h('span.pv-lbl', { text }) : null);
}

/**
 * @param {Object} file FileSummary
 * @param {{list?:Object[], index?:number, shareToken?:string}} [o]
 */
export function openPreview(file, { list = [file], index = 0 } = {}) {
  list = (list || []).filter((x) => x && x.type !== 'folder');
  if (!list.length) list = [file];
  let i = Math.min(list.length - 1, Math.max(0, index));
  if (list[i] && list[i].id !== file.id) { const k = list.findIndex((x) => x.id === file.id); i = k >= 0 ? k : 0; if (k < 0) { list = [file]; } }
  let viewer = null;
  let ctrl = null;
  let current = list[i];

  const stage = h('div.pv-stage');
  const meta = h('span.pv-meta');
  const tools = h('div.pv-tools');
  const prev = toolBtn('chevron-left', 'Previous file', () => go(-1));
  const next = toolBtn('chevron-right', 'Next file', () => go(1));
  const editBtn = toolBtn('edit', 'Edit', () => { const f = current; m.close(); import('./editor.js').then((mod) => mod.openEditor(f)); }, { text: 'Edit' });
  const infoBtn = toolBtn('info', 'Details', () => { const f = current; m.close(); import('./details.js').then((mod) => mod.openDetails(f.id, 'info')); });
  const fsBtn = toolBtn('maximize', 'Full screen', toggleFullscreen);
  const dl = h('a.btn.btn-sm.btn-primary', { href: '#', download: '', 'aria-label': 'Download' }, icon('download', 16), h('span.pv-lbl', { text: 'Download' }));
  if (!document.fullscreenEnabled) fsBtn.hidden = true;
  const bar = h('div.pv-bar', h('div.pv-nav', prev, next), meta, tools, h('div.pv-actions', editBtn, infoBtn, fsBtn, dl));
  const m = modal({ title: file.name, content: h('div.pv', bar, stage), size: 'xl', onClose: cleanup });
  m.el.classList.add('pv-modal');
  const overlay = m.el.parentElement;
  overlay.classList.add('pv-overlay');

  const onKey = (e) => {
    const tops = document.querySelectorAll('.modal-overlay');
    if (tops[tops.length - 1] !== overlay) return;
    const t = e.target;
    if (e.ctrlKey || e.metaKey) { if ((e.key === 'f' || e.key === 'F') && viewer && viewer.onKey) viewer.onKey(e); return; }
    if (e.altKey) return;
    if (t && t.closest && t.closest('input, textarea, select, [contenteditable], video, audio')) return;
    if (viewer && viewer.onKey && viewer.onKey(e)) return;
    if (e.key === 'ArrowLeft') { e.preventDefault(); go(-1); }
    else if (e.key === 'ArrowRight') { e.preventDefault(); go(1); }
  };
  const onFs = () => {
    const on = document.fullscreenElement === m.el;
    clear(fsBtn).appendChild(icon(on ? 'minimize' : 'maximize', 16));
    fsBtn.setAttribute('aria-label', on ? 'Exit full screen' : 'Full screen');
    fsBtn.title = fsBtn.getAttribute('aria-label');
  };
  document.addEventListener('keydown', onKey);
  document.addEventListener('fullscreenchange', onFs);

  function toggleFullscreen() {
    if (document.fullscreenElement) document.exitFullscreen().catch(() => {});
    else if (m.el.requestFullscreen) m.el.requestFullscreen().catch(() => {});
  }

  function cleanup() {
    document.removeEventListener('keydown', onKey);
    document.removeEventListener('fullscreenchange', onFs);
    if (document.fullscreenElement === m.el) document.exitFullscreen().catch(() => {});
    teardown();
  }

  function teardown() {
    if (viewer && viewer.destroy) { try { viewer.destroy(); } catch (e) { console.error(e); } }
    viewer = null;
    if (ctrl) ctrl.abort();
    ctrl = null;
  }

  function go(d) {
    if (list.length < 2) return;
    i = (i + d + list.length) % list.length;
    show(list[i]);
  }

  function show(f) {
    teardown();
    current = f;
    ctrl = new AbortController();
    clear(tools);
    clear(stage);
    m.el.querySelector('.modal-title').textContent = f.name;
    dl.href = api.url('/files/' + f.id + '/download');
    dl.hidden = !!(f.access && f.access.download === false);
    editBtn.hidden = !canEdit(f);
    meta.textContent = [(f.ext || '').toUpperCase(), bytes(f.size), f.updated_at ? dateTime(f.updated_at) : '', list.length > 1 ? (i + 1) + ' of ' + list.length : ''].filter(Boolean).join(' · ');
    prev.hidden = next.hidden = list.length < 2;
    const src = api.url('/files/' + f.id + '/content', { v: f.version || 1 });
    const ext = String(f.ext || '').toLowerCase();
    const kind = f.kind || 'other';
    const ctx = { url: src, file: f, signal: ctrl.signal, go };
    if (f.access && f.access.preview === false) { stage.appendChild(message('lock', 'Preview is not allowed', 'The owner did not allow previews of this file.')); return; }
    if (ext === 'svg' || (kind !== 'image' && kind !== 'pdf' && isTextLike(f))) return mountLazy(() => import('./viewers/code.js').then((mod) => mod.mountCode(stage, ctx)));
    if (kind === 'pdf' || ext === 'pdf') return mountLazy(() => import('./viewers/pdf.js').then((mod) => mod.mountPdf(stage, ctx)));
    if (kind === 'image') return mount(imageViewer(stage, ctx));
    if (kind === 'video' || kind === 'audio') return mount(mediaViewer(stage, ctx, kind));
    stage.appendChild(message(kindIcon(kind), 'No preview available', 'Download the file to open it on your device.'));
  }

  function mount(v) {
    viewer = v;
    (v.tools || []).forEach((t) => tools.appendChild(t));
  }

  function mountLazy(load) {
    const token = ctrl;
    stage.appendChild(h('div.pv-loading', spinner(), h('span', { text: 'Loading…' })));
    load().then((v) => {
      if (token !== ctrl) { v && v.destroy && v.destroy(); return; }
      mount(v);
    }).catch((e) => {
      if (token !== ctrl) return;
      console.error(e);
      clear(stage).appendChild(h('div.pv-col.pv-pad', errorState(e)));
    });
  }

  show(current);
  return { close: m.close };
}

function kindIcon(kind) {
  return { document: 'file-text', spreadsheet: 'table', presentation: 'slides', archive: 'archive' }[kind] || 'file';
}

function message(ic, title, text) {
  return h('div.empty-state.pv-col.pv-center', icon(ic, 56), h('h3', { text: title }), h('p', { text }));
}

// ------------------------------------------------------------------ images

function imageViewer(stage, { url, file, signal, go }) {
  let scale = 1, rot = 0, tx = 0, ty = 0;
  const pointers = new Map();
  let g = null;
  const img = h('img.pv-img', { src: url, alt: file.name, draggable: false, decoding: 'async' });
  const wrap = h('div.pv-img-wrap', img);
  const info = h('div.pv-imginfo', { 'aria-live': 'polite' });
  stage.append(h('div.pv-col', wrap, info));

  const label = h('span.pv-count', { text: '100%' });
  const apply = (animate = true) => {
    img.style.transition = animate ? 'transform .15s ease' : 'none';
    img.style.transform = `translate(${tx}px,${ty}px) scale(${scale}) rotate(${rot}deg)`;
    label.textContent = Math.round(scale * 100) + '%';
    wrap.classList.toggle('zoomed', scale > 1);
  };
  const zoomTo = (s, animate = true) => { scale = Math.min(8, Math.max(0.25, s)); if (scale <= 1) { tx = 0; ty = 0; } apply(animate); };
  const reset = () => { scale = 1; rot = 0; tx = ty = 0; apply(); };
  const tools = [
    h('div.pv-group',
      toolBtn('zoom-out', 'Zoom out', () => zoomTo(scale / 1.25)), label,
      toolBtn('zoom-in', 'Zoom in', () => zoomTo(scale * 1.25))),
    toolBtn('rotate', 'Rotate', () => { rot = (rot + 90) % 360; apply(); }),
    toolBtn('fit-width', 'Reset view', reset),
  ];

  wrap.addEventListener('wheel', (e) => { e.preventDefault(); zoomTo(scale * (e.deltaY < 0 ? 1.15 : 1 / 1.15)); }, { passive: false });
  wrap.addEventListener('dblclick', () => { if (scale > 1) reset(); else zoomTo(2); });
  const dist = () => { const [a, b] = [...pointers.values()]; return Math.hypot(a.x - b.x, a.y - b.y) || 1; };
  wrap.addEventListener('pointerdown', (e) => {
    if (e.button !== undefined && e.button > 0) return;
    try { wrap.setPointerCapture(e.pointerId); } catch { /* ignore */ }
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (pointers.size === 1) g = { type: scale > 1 ? 'pan' : 'swipe', x0: e.clientX, y0: e.clientY, tx0: tx, ty0: ty, t0: Date.now() };
    else if (pointers.size === 2) g = { type: 'pinch', d0: dist(), s0: scale };
  });
  wrap.addEventListener('pointermove', (e) => {
    if (!pointers.has(e.pointerId) || !g) return;
    pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (g.type === 'pinch' && pointers.size === 2) zoomTo(g.s0 * (dist() / g.d0), false);
    else if (g.type === 'pan') { tx = g.tx0 + (e.clientX - g.x0); ty = g.ty0 + (e.clientY - g.y0); apply(false); }
  });
  const end = (e) => {
    if (!pointers.has(e.pointerId)) return;
    const p = pointers.get(e.pointerId);
    pointers.delete(e.pointerId);
    if (g && g.type === 'swipe' && e.type === 'pointerup' && e.pointerType !== 'mouse') {
      const dx = p.x - g.x0, dy = p.y - g.y0;
      if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5 && Date.now() - g.t0 < 800) go(dx < 0 ? 1 : -1);
    }
    if (pointers.size === 1 && g && g.type === 'pinch') {
      const [q] = [...pointers.values()];
      g = { type: scale > 1 ? 'pan' : 'swipe', x0: q.x, y0: q.y, tx0: tx, ty0: ty, t0: Date.now() };
    } else if (!pointers.size) { g = null; apply(); }
  };
  wrap.addEventListener('pointerup', end);
  wrap.addEventListener('pointercancel', end);

  img.addEventListener('load', () => {
    const parts = [img.naturalWidth + ' × ' + img.naturalHeight + ' px'];
    info.textContent = parts.join(' · ');
    const ext = String(file.ext || '').toLowerCase();
    if (['jpg', 'jpeg'].includes(ext) || file.mime === 'image/jpeg') {
      fetchBytes(url, { signal, range: [0, 65535] }).then(({ buffer }) => {
        const x = parseExif(buffer);
        if (!x) return;
        const when = exifDate(x.dateTimeOriginal || x.dateTime);
        if (when) parts.push('Taken ' + dateTime(when));
        const cam = cameraLine(x);
        if (cam) parts.push(cam);
        if (x.lensModel) parts.push(x.lensModel);
        info.textContent = parts.join(' · ');
      }).catch(() => { /* metadata is optional */ });
    }
  });
  img.addEventListener('error', () => {
    clear(stage).appendChild(message('image', 'This image could not be shown', 'Your browser cannot display this format. Download the file to open it.'));
  });
  apply(false);

  return {
    tools,
    onKey(e) {
      if (e.key === '+' || e.key === '=') { zoomTo(scale * 1.25); return true; }
      if (e.key === '-') { zoomTo(scale / 1.25); return true; }
      if (e.key === '0') { reset(); return true; }
      if (e.key === 'r' || e.key === 'R') { rot = (rot + 90) % 360; apply(); return true; }
      return false;
    },
    destroy() { img.removeAttribute('src'); },
  };
}

// ------------------------------------------------------------------ video & audio

function mediaViewer(stage, { url, file }, kind) {
  const el = h(kind + '.pv-media', { src: url, controls: true, preload: 'metadata', playsInline: true });
  const seek = (d) => {
    if (!isFinite(el.duration) && d > 0) return;
    el.currentTime = Math.max(0, Math.min(isFinite(el.duration) ? el.duration : Infinity, el.currentTime + d));
  };
  el.addEventListener('error', () => {
    if (!el.error) return;
    clear(stage).appendChild(message(kind === 'video' ? 'video' : 'music', 'This file cannot be played here', 'Your browser does not support this format. Download the file to play it on your device.'));
  });
  if (kind === 'audio') stage.append(h('div.pv-col.pv-center.pv-audio', icon('music', 72), h('div.pv-audio-name', { text: file.name }), el));
  else stage.append(h('div.pv-col.pv-center', el));
  const tools = [h('div.pv-group',
    toolBtn('rewind', 'Back 10 seconds', () => seek(-10), { text: '10 s' }),
    toolBtn('forward', 'Forward 10 seconds', () => seek(10), { text: '10 s' }))];
  return {
    tools,
    onKey(e) {
      if (e.key === 'j' || e.key === 'J') { seek(-10); return true; }
      if (e.key === 'l' || e.key === 'L') { seek(10); return true; }
      if (e.key === 'k' || e.key === 'K') { if (el.paused) el.play().catch(() => {}); else el.pause(); return true; }
      return false;
    },
    destroy() { try { el.pause(); el.removeAttribute('src'); el.load(); } catch { /* ignore */ } },
  };
}
