/**
 * PDF viewer built on pdf.js 3.11.174 (cdnjs, loaded on demand): continuous pages rendered
 * lazily around the visible area, page navigation, zoom and fit-to-width, a selectable text
 * layer and search across the whole document with a list of hits.
 *
 * The bytes are fetched with the user's session from the same-origin content endpoint and
 * handed to pdf.js as data (the CSP's connect-src stays 'self'); pdf.js runs without eval.
 * @module features/viewers/pdf
 */
import { h, icon, clear, debounce } from '../../core/dom.js';
import { prompt, spinner, errorState } from '../../core/ui.js';
import { bytes } from '../../core/format.js';
import { loadLib, LIBS } from '../lib-loader.js';
import { fetchBytes, findAll, locate } from './common.js';

const ZOOMS = [0.5, 0.75, 1, 1.25, 1.5, 2, 3];
const MIN = 0.25, MAX = 5;
const KEEP = 5;            // rendered pages kept on each side of the current one
const MAX_HITS = 2000;
const LIST_HITS = 300;
const GAP = 12;            // px between pages

/**
 * @param {HTMLElement} stage
 * @param {{url:string, file:Object, signal:AbortSignal}} o
 * @returns {{tools:HTMLElement[], destroy:Function, onKey:(e:KeyboardEvent)=>boolean}}
 */
export function mountPdf(stage, { url, file, signal }) {
  let lib = null, task = null, doc = null, n = 0, destroyed = false;
  let scale = 1, mode = 'fit';
  let baseW = 612;
  const pages = [];
  const pageCache = new Map();
  const textCache = new Map();
  let tops = [];
  let current = 1;
  let query = '', hits = [], hitIdx = -1, searchSeq = 0, pendingScroll = -1;

  // ---------------------------------------------------------------- DOM
  const scroller = h('div.pdf-scroll', { tabIndex: 0, role: 'document', 'aria-label': file.name });
  const pagesEl = h('div.pdf-pages');
  scroller.appendChild(pagesEl);
  const statusText = h('span', { text: 'Loading PDF viewer…' });
  const status = h('div.pv-loading', spinner(), statusText);

  const findInput = h('input.input.pv-find-input', { type: 'search', placeholder: 'Search in document', 'aria-label': 'Search in document', enterkeyhint: 'search', autocomplete: 'off' });
  const count = h('span.pv-count', { 'aria-live': 'polite' });
  const hitsEl = h('div.pdf-hits', { role: 'list', 'aria-label': 'Search results' });
  const searchPanel = h('div.pdf-search', { hidden: true },
    h('div.pv-find', { role: 'search' }, icon('search', 15), findInput, count,
      h('button.btn.btn-sm.pv-icon', { type: 'button', 'aria-label': 'Previous match', title: 'Previous match (Shift+Enter)', on: { click: () => stepHit(-1) } }, icon('chevron-up', 16)),
      h('button.btn.btn-sm.pv-icon', { type: 'button', 'aria-label': 'Next match', title: 'Next match (Enter)', on: { click: () => stepHit(1) } }, icon('chevron-down', 16)),
      h('button.btn.btn-sm.pv-icon', { type: 'button', 'aria-label': 'Close search', on: { click: () => toggleSearch(false) } }, icon('x', 15))),
    hitsEl);
  clear(stage).append(h('div.pv-col', searchPanel, status, scroller));
  scroller.hidden = true;

  // ---------------------------------------------------------------- tools
  const prevBtn = h('button.btn.btn-sm.pv-icon', { type: 'button', 'aria-label': 'Previous page', title: 'Previous page', on: { click: () => goto(current - 1) } }, icon('chevron-left', 16));
  const nextBtn = h('button.btn.btn-sm.pv-icon', { type: 'button', 'aria-label': 'Next page', title: 'Next page', on: { click: () => goto(current + 1) } }, icon('chevron-right', 16));
  const pageInput = h('input.input.pdf-page-input', { type: 'text', inputmode: 'numeric', value: '1', 'aria-label': 'Page number', autocomplete: 'off' });
  const pageTotal = h('span.pv-count', { text: '/ …' });
  pageInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); goto(parseInt(pageInput.value, 10) || current); pageInput.blur(); } });
  pageInput.addEventListener('change', () => goto(parseInt(pageInput.value, 10) || current));
  pageInput.addEventListener('focus', () => pageInput.select());
  const zoomSel = h('select.select.pdf-zoom', { 'aria-label': 'Zoom' });
  const fillZoom = () => {
    clear(zoomSel);
    zoomSel.append(h('option', { value: 'fit', text: 'Fit width', selected: mode === 'fit' }));
    const opts = [...ZOOMS];
    if (mode !== 'fit' && !ZOOMS.some((z) => Math.abs(z - scale) < 0.001)) opts.push(scale);
    opts.sort((a, b) => a - b).forEach((z) => zoomSel.append(h('option', { value: String(z), text: Math.round(z * 100) + '%', selected: mode !== 'fit' && Math.abs(z - scale) < 0.001 })));
  };
  zoomSel.addEventListener('change', () => { if (zoomSel.value === 'fit') fit(); else setScale(parseFloat(zoomSel.value), 'manual'); });
  const zoomOut = h('button.btn.btn-sm.pv-icon.pdf-zbtn', { type: 'button', 'aria-label': 'Zoom out', title: 'Zoom out (−)', on: { click: () => setScale(scale / 1.25, 'manual') } }, icon('zoom-out', 16));
  const zoomIn = h('button.btn.btn-sm.pv-icon.pdf-zbtn', { type: 'button', 'aria-label': 'Zoom in', title: 'Zoom in (+)', on: { click: () => setScale(scale * 1.25, 'manual') } }, icon('zoom-in', 16));
  const searchBtn = h('button.btn.btn-sm.pv-icon', { type: 'button', 'aria-label': 'Search in document', title: 'Search (Ctrl+F)', 'aria-pressed': 'false', on: { click: () => toggleSearch(searchPanel.hidden) } }, icon('search', 16));
  const pageGroup = h('div.pv-group', prevBtn, pageInput, pageTotal, nextBtn);
  const zoomGroup = h('div.pv-group', zoomOut, zoomSel, zoomIn);
  const tools = [pageGroup, zoomGroup, searchBtn];
  const setEnabled = (on) => [prevBtn, nextBtn, pageInput, zoomSel, zoomOut, zoomIn, searchBtn].forEach((b) => { b.disabled = !on; });
  setEnabled(false);
  fillZoom();

  findInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (findInput.value !== query) runSearch(findInput.value);
      else stepHit(e.shiftKey ? -1 : 1);
    }
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); toggleSearch(false); }
  });
  findInput.addEventListener('input', debounce(() => { if (findInput.value !== query) runSearch(findInput.value); }, 450));

  // ---------------------------------------------------------------- loading
  const setStatus = (t) => { statusText.textContent = t; };
  load();

  async function load() {
    try {
      lib = await loadLib('pdfjs');
      if (destroyed) return;
      if (!lib.GlobalWorkerOptions.workerSrc) lib.GlobalWorkerOptions.workerSrc = LIBS.pdfjs.worker;
      setStatus('Downloading…');
      const { buffer } = await fetchBytes(url, { signal, onProgress: (l, t) => setStatus(t ? 'Downloading… ' + Math.round((l / t) * 100) + '%' : 'Downloading… ' + bytes(l)) });
      if (destroyed) return;
      setStatus('Opening…');
      task = lib.getDocument({ data: new Uint8Array(buffer), isEvalSupported: false, enableXfa: false, useSystemFonts: true, verbosity: 0 });
      task.onPassword = async (update, reason) => {
        const pw = await prompt({ title: reason === 2 ? 'Wrong password — try again' : 'This PDF is protected', label: 'Enter the document password', type: 'password', confirmText: 'Open' });
        if (pw === null) { fail(new Error('The document is password-protected.')); try { task.destroy(); } catch { /* ignore */ } } else update(pw);
      };
      doc = await task.promise;
      if (destroyed) { doc.destroy(); return; }
      n = doc.numPages;
      const first = await getPage(1);
      const vp = first.getViewport({ scale: 1 });
      baseW = vp.width;
      for (let i = 1; i <= n; i++) {
        const el = h('div.pdf-page', { dataset: { page: String(i) } });
        pages[i] = { el, w: vp.width, h: vp.height, known: i === 1, rendered: 0, busy: false, renderTask: null, textTask: null, textDivs: null, marked: [] };
        pagesEl.appendChild(el);
      }
      pageTotal.textContent = '/ ' + n;
      status.remove();
      scroller.hidden = false;
      scale = fitScale();
      layout();
      fillZoom();
      setEnabled(true);
      scroller.addEventListener('scroll', onScroll, { passive: true });
      scroller.addEventListener('wheel', onWheel, { passive: false });
      if ('ResizeObserver' in window) { ro = new ResizeObserver(debounce(() => { if (mode === 'fit' && !destroyed) setScale(fitScale(), 'fit'); }, 150)); ro.observe(scroller); }
      update();
    } catch (e) {
      if (destroyed || (e && e.name === 'AbortError')) return;
      fail(e && e.name === 'PasswordException' ? new Error('The document is password-protected.') : (e && e.name === 'InvalidPDFException' ? new Error('This file is not a valid PDF document.') : e));
    }
  }
  let ro = null;

  function fail(e) {
    clear(stage).appendChild(h('div.pv-col.pv-pad', errorState(e)));
  }

  function getPage(i) {
    if (!pageCache.has(i)) pageCache.set(i, doc.getPage(i));
    return pageCache.get(i);
  }

  async function textContent(i) {
    if (textCache.has(i)) return textCache.get(i);
    const page = await getPage(i);
    const raw = await page.getTextContent();
    const items = raw.items.filter((it) => typeof it.str === 'string');
    let text = '';
    const starts = [];
    for (const it of items) { starts.push(text.length); text += it.str; if (it.hasEOL) text += ' '; }
    const v = { raw, items, text, starts };
    textCache.set(i, v);
    return v;
  }

  // ---------------------------------------------------------------- layout & rendering
  function fitScale() {
    const w = Math.max(120, scroller.clientWidth - GAP * 2);
    return Math.min(MAX, Math.max(MIN, w / baseW));
  }

  function layout() {
    for (let i = 1; i <= n; i++) {
      const p = pages[i];
      p.el.style.width = Math.floor(p.w * scale) + 'px';
      p.el.style.height = Math.floor(p.h * scale) + 'px';
      p.el.style.setProperty('--scale-factor', String(scale));
    }
    measure();
  }

  function measure() {
    tops = [0];
    for (let i = 1; i <= n; i++) tops[i] = pages[i].el.offsetTop;
  }

  function setScale(s, m) {
    if (!doc) return;
    s = Math.min(MAX, Math.max(MIN, s));
    mode = m;
    if (Math.abs(s - scale) < 0.0005) { fillZoom(); return; }
    // keep the same spot of the current page in view
    const i = current;
    const frac = (scroller.scrollTop - tops[i]) / Math.max(1, pages[i].el.offsetHeight);
    scale = s;
    layout();
    scroller.scrollTop = tops[i] + frac * pages[i].el.offsetHeight;
    fillZoom();
    update();
  }
  function fit() { setScale(fitScale(), 'fit'); fillZoom(); }

  function goto(i) {
    if (!n) return;
    i = Math.min(n, Math.max(1, i));
    current = i;
    pageInput.value = String(i);
    scroller.scrollTop = Math.max(0, tops[i] - GAP);
    update();
  }

  let raf = 0;
  function onScroll() {
    if (raf) return;
    raf = requestAnimationFrame(() => { raf = 0; update(); });
  }

  function onWheel(e) {
    if (!(e.ctrlKey || e.metaKey)) return;
    e.preventDefault();
    setScale(scale * (e.deltaY < 0 ? 1.1 : 1 / 1.1), 'manual');
  }

  /** Recompute the current page, render what is visible and drop far-away pages. */
  function update() {
    if (!n || destroyed) return;
    const top = scroller.scrollTop;
    const bottom = top + scroller.clientHeight;
    const probe = top + scroller.clientHeight * 0.3;
    let first = Math.max(1, locate(tops, top));
    let cur = Math.max(1, locate(tops, probe));
    current = cur;
    if (document.activeElement !== pageInput) pageInput.value = String(cur);
    prevBtn.disabled = cur <= 1;
    nextBtn.disabled = cur >= n;
    const want = [];
    for (let i = first; i <= n && tops[i] < bottom + scroller.clientHeight; i++) want.push(i);
    if (first > 1) want.push(first - 1);
    want.forEach((i) => { if (pages[i].rendered !== scale) renderPage(i); });
    for (let i = 1; i <= n; i++) {
      if (pages[i].rendered && Math.abs(i - cur) > KEEP && !want.includes(i)) unrender(i);
    }
  }

  function unrender(i) {
    const p = pages[i];
    try { p.renderTask && p.renderTask.cancel(); } catch { /* ignore */ }
    try { p.textTask && p.textTask.cancel(); } catch { /* ignore */ }
    clear(p.el);
    p.rendered = 0;
    p.textDivs = null;
    p.marked = [];
  }

  async function renderPage(i) {
    const p = pages[i];
    if (p.busy) return;
    p.busy = true;
    const s = scale;
    try {
      const page = await getPage(i);
      if (destroyed || s !== scale) return;
      if (!p.known) {
        const v1 = page.getViewport({ scale: 1 });
        p.known = true;
        if (Math.abs(v1.width - p.w) > 0.5 || Math.abs(v1.height - p.h) > 0.5) {
          p.w = v1.width; p.h = v1.height;
          p.el.style.width = Math.floor(p.w * scale) + 'px';
          p.el.style.height = Math.floor(p.h * scale) + 'px';
          measure();
        }
      }
      const vp = page.getViewport({ scale: s });
      let dpr = Math.min(window.devicePixelRatio || 1, 2);
      const area = vp.width * vp.height;
      if (area * dpr * dpr > 16e6) dpr = Math.max(0.5, Math.sqrt(16e6 / area));
      const canvas = h('canvas.pdf-canvas', { 'aria-hidden': 'true' });
      canvas.width = Math.floor(vp.width * dpr);
      canvas.height = Math.floor(vp.height * dpr);
      const ctx = canvas.getContext('2d', { alpha: false });
      p.renderTask = page.render({ canvasContext: ctx, viewport: vp, transform: dpr !== 1 ? [dpr, 0, 0, dpr, 0, 0] : null });
      await p.renderTask.promise;
      p.renderTask = null;
      if (destroyed || s !== scale) return;
      const tc = await textContent(i);
      if (destroyed || s !== scale) return;
      const layer = h('div.textLayer');
      clear(p.el).append(canvas, layer);
      const textDivs = [];
      p.textTask = lib.renderTextLayer({ textContentSource: tc.raw, container: layer, viewport: vp, textDivs });
      await p.textTask.promise;
      p.textTask = null;
      p.textDivs = textDivs;
      p.marked = [];
      p.rendered = s;
      highlightPage(i);
    } catch (e) {
      if (!(e && (e.name === 'RenderingCancelledException' || e.name === 'AbortException'))) {
        if (!destroyed) clear(p.el).appendChild(h('div.pdf-page-error', { text: 'This page could not be displayed.' }));
      }
    } finally {
      p.busy = false;
      if (!destroyed && p.rendered !== scale) requestAnimationFrame(update);
    }
  }

  // ---------------------------------------------------------------- search
  function toggleSearch(on) {
    searchPanel.hidden = !on;
    searchBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
    if (on) { findInput.focus(); findInput.select(); } else { scroller.focus({ preventScroll: true }); }
  }

  async function runSearch(q) {
    const my = ++searchSeq;
    query = q.trim();
    hits = [];
    hitIdx = -1;
    pendingScroll = -1;
    clear(hitsEl);
    for (let i = 1; i <= n; i++) if (pages[i].textDivs) highlightPage(i);
    if (!query) { count.textContent = ''; return; }
    for (let i = 1; i <= n && hits.length < MAX_HITS; i++) {
      if (my !== searchSeq || destroyed) return;
      if (i === 1 || i % 5 === 0) count.textContent = 'Searching ' + i + ' of ' + n + '…';
      let tc;
      try { tc = await textContent(i); } catch { continue; }
      for (const [s, e] of findAll(tc.text, query, MAX_HITS - hits.length)) hits.push({ page: i, s, e });
    }
    if (my !== searchSeq || destroyed) return;
    if (!hits.length) { count.textContent = 'No matches'; hitsEl.appendChild(h('div.pdf-hit.muted', { text: 'No matches for “' + query + '”.' })); return; }
    hits.slice(0, LIST_HITS).forEach((hit, k) => {
      const t = textCache.get(hit.page).text;
      const a = Math.max(0, hit.s - 40), b = Math.min(t.length, hit.e + 50);
      hitsEl.appendChild(h('button.pdf-hit', { type: 'button', role: 'listitem', dataset: { k: String(k) }, on: { click: () => gotoHit(k) } },
        h('span.pdf-hit-page', { text: 'p. ' + hit.page }),
        h('span.pdf-hit-text', (a > 0 ? '…' : '') + t.slice(a, hit.s), h('mark', { text: t.slice(hit.s, hit.e) }), t.slice(hit.e, b) + (b < t.length ? '…' : ''))));
    });
    if (hits.length > LIST_HITS) hitsEl.appendChild(h('div.pdf-hit.muted', { text: 'Showing the first ' + LIST_HITS + ' of ' + hits.length + (hits.length >= MAX_HITS ? '+' : '') + ' matches.' }));
    gotoHit(0);
  }

  function stepHit(d) {
    if (findInput.value.trim() !== query) { runSearch(findInput.value); return; }
    if (!hits.length) return;
    gotoHit((hitIdx + d + hits.length) % hits.length);
  }

  function gotoHit(k) {
    const prev = hits[hitIdx];
    hitIdx = k;
    const hit = hits[k];
    count.textContent = (k + 1) + ' of ' + hits.length + (hits.length >= MAX_HITS ? '+' : '');
    hitsEl.querySelectorAll('.pdf-hit.current').forEach((b) => b.classList.remove('current'));
    const btn = hitsEl.querySelector('[data-k="' + k + '"]');
    if (btn) { btn.classList.add('current'); btn.scrollIntoView({ block: 'nearest' }); }
    pendingScroll = k;
    if (prev && prev.page !== hit.page && pages[prev.page].textDivs) highlightPage(prev.page);
    if (pages[hit.page].rendered === scale && pages[hit.page].textDivs) highlightPage(hit.page);
    else goto(hit.page);
  }

  function highlightPage(i) {
    const p = pages[i];
    const tc = textCache.get(i);
    if (!p.textDivs || !tc) return;
    for (const k of p.marked) { const d = p.textDivs[k]; if (d) d.textContent = tc.items[k].str; }
    p.marked = [];
    if (!query || !hits.length) return;
    const byItem = new Map();
    hits.forEach((hit, idx) => {
      if (hit.page !== i) return;
      for (let k = locate(tc.starts, hit.s); k < tc.items.length && tc.starts[k] < hit.e; k++) {
        const st = tc.starts[k];
        const a = Math.max(hit.s, st) - st;
        const b = Math.min(hit.e, st + tc.items[k].str.length) - st;
        if (b <= a) continue;
        if (!byItem.has(k)) byItem.set(k, []);
        byItem.get(k).push([a, b, idx === hitIdx]);
      }
    });
    for (const [k, list] of byItem) {
      const d = p.textDivs[k];
      if (!d) continue;
      const str = tc.items[k].str;
      clear(d);
      let pos = 0;
      list.sort((x, y) => x[0] - y[0]).forEach(([a, b, isCur]) => {
        if (a < pos) return;
        if (a > pos) d.append(str.slice(pos, a));
        d.append(h('mark.pdf-hl' + (isCur ? '.current' : ''), { text: str.slice(a, b) }));
        pos = b;
      });
      if (pos < str.length) d.append(str.slice(pos));
      p.marked.push(k);
    }
    if (pendingScroll === hitIdx && hits[hitIdx] && hits[hitIdx].page === i) {
      const m = p.el.querySelector('mark.pdf-hl.current');
      if (m) {
        pendingScroll = -1;
        const r = m.getBoundingClientRect();
        const sr = scroller.getBoundingClientRect();
        scroller.scrollTop += (r.top - sr.top) - sr.height / 2;
        if (r.left < sr.left || r.right > sr.right) scroller.scrollLeft += (r.left - sr.left) - sr.width / 2;
      }
    }
  }

  return {
    tools,
    onKey(e) {
      if (!n) return false;
      if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'F')) { e.preventDefault(); toggleSearch(true); return true; }
      if (e.key === 'ArrowLeft') { goto(current - 1); return true; }
      if (e.key === 'ArrowRight') { goto(current + 1); return true; }
      if (e.key === '+' || e.key === '=') { setScale(scale * 1.25, 'manual'); return true; }
      if (e.key === '-') { setScale(scale / 1.25, 'manual'); return true; }
      if (e.key === 'F3') { e.preventDefault(); stepHit(e.shiftKey ? -1 : 1); return true; }
      return false;
    },
    destroy() {
      destroyed = true;
      ro && ro.disconnect();
      if (raf) cancelAnimationFrame(raf);
      pages.forEach((p) => { if (p) { try { p.renderTask && p.renderTask.cancel(); } catch { /* ignore */ } } });
      try { task && task.destroy(); } catch { /* ignore */ }
    },
  };
}
