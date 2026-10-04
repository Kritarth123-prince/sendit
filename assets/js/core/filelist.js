/**
 * Reusable file/folder list: grid or list mode, infinite scroll, selection, context menus,
 * drag-to-folder moves and live upsert/remove for real-time events.
 * @module core/filelist
 */
import { h, icon, clear } from './dom.js';
import { api } from './api.js';
import { bytes, relative, dateTime, countdown } from './format.js';
import { kindIconName } from './icons.js';
import { menu, emptyState, errorState, spinner } from './ui.js';

const MAX_DOM = 400;

/**
 * @param {HTMLElement} container
 * @param {{
 *   source: (p:{page:number, perPage:number}) => Promise<{items:Array, meta:Object}>,
 *   variant?: 'files'|'trash'|'shared'|'search'|'recent'|'favorites',
 *   mode?: 'grid'|'list', selectable?: boolean, perPage?: number,
 *   emptyState?: Object, onOpen?: (item:Object) => void,
 *   itemActions?: (item:Object) => Array, batchActions?: (items:Array) => Array<HTMLElement>,
 *   onMove?: (items:Array, folder:Object) => void, accept?: (item:Object) => boolean,
 *   onLoaded?: (meta:Object) => void, extraMeta?: (item:Object) => (string|null)
 * }} o
 */
export function createFileList(container, o) {
  const opt = { variant: 'files', mode: 'grid', selectable: true, perPage: 60, ...o };
  const items = new Map(); // key -> item
  const order = [];        // keys in display order
  const selected = new Set();
  let page = 0, hasMore = true, loading = false, destroyed = false, lastClicked = null;

  const root = h('div.fl');
  const listEl = h('div', { role: opt.mode === 'grid' ? 'grid' : 'listbox', 'aria-multiselectable': opt.selectable ? 'true' : 'false' });
  const status = h('div');
  const sentinel = h('div.fl-sentinel');
  const moreWrap = h('div.fl-more');
  root.append(listEl, status, moreWrap, sentinel);
  clear(container).appendChild(root);
  let batchBar = null;

  const key = (it) => (it.type === 'folder' ? 'd' : 'f') + it.id;
  setMode(opt.mode);

  const io = 'IntersectionObserver' in window ? new IntersectionObserver((ents) => {
    if (ents.some((e) => e.isIntersecting)) loadMore();
  }, { rootMargin: '600px' }) : null;
  io && io.observe(sentinel);

  function setMode(m) {
    opt.mode = m;
    listEl.className = m === 'grid' ? 'fl-grid' : 'fl-list';
    listEl.setAttribute('role', m === 'grid' ? 'grid' : 'listbox');
    order.forEach((k) => { const el = listEl.querySelector('[data-key="' + k + '"]'); if (el) el.replaceWith(renderItem(items.get(k))); });
  }

  async function loadMore() {
    if (loading || !hasMore || destroyed) return;
    loading = true;
    clear(moreWrap).appendChild(spinner());
    try {
      const { items: list, meta } = await opt.source({ page: page + 1, perPage: opt.perPage });
      if (destroyed) return;
      page++;
      hasMore = !!(meta && (meta.has_more ?? (meta.total_pages ? page < meta.total_pages : false)));
      (list || []).forEach((it) => add(it, false));
      opt.onLoaded && opt.onLoaded(meta || {}, page);
      clear(status);
      if (!order.length) status.appendChild(emptyState(opt.emptyState || {}));
      trimDom();
    } catch (e) {
      clear(status).appendChild(errorState(e, () => { clear(status); loadMore(); }));
      hasMore = false;
    } finally {
      loading = false;
      clear(moreWrap);
      if (hasMore && !io) moreWrap.appendChild(h('button.btn', { type: 'button', text: 'Load more', on: { click: loadMore } }));
    }
  }

  function add(it, prepend) {
    const k = key(it);
    if (items.has(k)) { replace(it); return; }
    items.set(k, it);
    const el = renderItem(it);
    if (prepend) {
      // folders stay before files
      const firstFile = it.type === 'folder' ? null : order.find((x) => x[0] === 'f');
      const idx = it.type === 'folder' ? 0 : (firstFile ? order.indexOf(firstFile) : order.length);
      const before = it.type === 'folder' ? order[0] : firstFile;
      order.splice(idx, 0, k);
      const ref = before ? listEl.querySelector('[data-key="' + before + '"]') : null;
      listEl.insertBefore(el, ref);
    } else {
      order.push(k);
      listEl.appendChild(el);
    }
  }

  function replace(it) {
    const k = key(it);
    const prev = items.get(k) || {};
    const merged = { ...prev, ...it };
    if (it.access === undefined && prev.access) merged.access = prev.access;
    if (it.favorite === undefined && prev.favorite !== undefined) merged.favorite = prev.favorite;
    items.set(k, merged);
    const old = listEl.querySelector('[data-key="' + k + '"]');
    if (old) old.replaceWith(renderItem(merged));
  }

  function trimDom() {
    // Keep the DOM bounded for very large folders: drop the oldest rendered cards beyond MAX_DOM.
    while (order.length > MAX_DOM * 2) {
      const k = order.shift();
      items.delete(k);
      listEl.querySelector('[data-key="' + k + '"]')?.remove();
    }
  }

  function thumbFor(it) {
    const kind = it.type === 'folder' ? 'folder' : (it.kind || 'other');
    const t = h('div.fi-thumb');
    if (it.type !== 'folder' && it.has_thumbnail && opt.variant !== 'trash') {
      const img = h('img', { alt: '', loading: 'lazy', decoding: 'async', src: api.url('/files/' + it.id + '/thumbnail', { v: it.version || 1 }) });
      img.addEventListener('error', () => img.replaceWith(icon(kindIconName(kind), 40)));
      t.appendChild(img);
    } else {
      t.appendChild(icon(kindIconName(kind), 40));
      if (it.type === 'folder') t.style.color = 'var(--accent2)';
    }
    if (it.type !== 'folder' && it.ext) t.appendChild(h('span.ext', { text: it.ext }));
    return t;
  }

  function metaLine(it) {
    const parts = [];
    if (opt.variant === 'trash' && it.trash) {
      return h('div.trash-meta', h('span', { text: 'Deleted ' + relative(it.trash.deleted_at) }),
        it.trash.original_path ? h('div.ellipsis', { text: 'From ' + it.trash.original_path }) : null,
        it.trash.days_left !== null && it.trash.days_left !== undefined ? h('span.days-left', { text: it.trash.days_left + ' days left' }) : null);
    }
    if (it.type !== 'folder') parts.push(bytes(it.size));
    if (opt.variant === 'shared' && it.owner) parts.push(it.owner.display_name || it.owner.username);
    parts.push(relative(it.updated_at || it.created_at));
    if (it.type !== 'folder' && it.is_permanent === false && it.expires_at) parts.push('⏱ ' + countdown(it.expires_at));
    const extra = opt.extraMeta ? opt.extraMeta(it) : null;
    if (extra) parts.push(extra);
    return h('div.fi-meta', parts.map((p, i) => h('span' + (i > 0 && opt.mode === 'list' ? '.fi-col-hide' : ''), { text: p })));
  }

  function renderItem(it) {
    const k = key(it);
    const el = h('div.fi' + (selected.has(k) ? '.selected' : ''), {
      tabIndex: 0, dataset: { key: k }, role: opt.mode === 'grid' ? 'gridcell' : 'option',
      'aria-selected': selected.has(k) ? 'true' : 'false',
      'aria-label': (it.type === 'folder' ? 'Folder ' : '') + it.name,
      title: it.name + (it.updated_at ? ' — ' + dateTime(it.updated_at) : ''),
      draggable: it.type !== 'folder' && opt.variant === 'files' ? 'true' : undefined,
    });
    if (opt.selectable) {
      el.appendChild(h('button.fi-check', { type: 'button', 'aria-label': 'Select ' + it.name, tabIndex: -1, on: { click: (e) => { e.stopPropagation(); toggle(k, e); } } }, selected.has(k) ? icon('check', 14) : null));
    }
    const flags = h('div.fi-flags');
    if (it.favorite) flags.appendChild(h('span.fi-flag.fav', { title: 'Favourite' }, icon('star', 13)));
    if (it.is_shared) flags.appendChild(h('span.fi-flag', { title: 'Shared' }, icon('link', 13)));
    if (opt.mode === 'grid') el.appendChild(flags);
    el.appendChild(thumbFor(it));
    el.appendChild(h('div.fi-body', h('div.fi-name', { text: it.name }), metaLine(it), opt.mode === 'list' ? flags : null));
    if (opt.itemActions) {
      el.appendChild(h('button.icon-btn.sm.fi-more', { type: 'button', 'aria-label': 'Actions for ' + it.name, on: { click: (e) => { e.stopPropagation(); openMenu(it, e.currentTarget); } } }, icon('more', 16)));
    }
    el.addEventListener('click', (e) => {
      if (e.shiftKey || e.ctrlKey || e.metaKey || (selected.size > 0 && opt.selectable)) { toggle(k, e); return; }
      opt.onOpen && opt.onOpen(items.get(k));
    });
    el.addEventListener('contextmenu', (e) => { if (!opt.itemActions) return; e.preventDefault(); openMenu(items.get(k), { x: e.clientX, y: e.clientY }); });
    el.addEventListener('keydown', (e) => onKey(e, k));
    // long-press on touch
    let lp = null;
    el.addEventListener('touchstart', () => { lp = setTimeout(() => { lp = null; if (opt.itemActions) openMenu(items.get(k), el); }, 550); }, { passive: true });
    ['touchend', 'touchmove', 'touchcancel'].forEach((ev) => el.addEventListener(ev, () => { clearTimeout(lp); }, { passive: true }));
    // drag-to-folder move
    if (opt.variant === 'files') {
      el.addEventListener('dragstart', (e) => {
        if (!selected.has(k)) { selected.clear(); selected.add(k); refreshSelection(); }
        e.dataTransfer.setData('application/x-ft-items', JSON.stringify([...selected]));
        e.dataTransfer.effectAllowed = 'move';
      });
      if (it.type === 'folder') {
        el.addEventListener('dragover', (e) => { if (e.dataTransfer.types.includes('application/x-ft-items')) { e.preventDefault(); el.classList.add('drop-target'); } });
        el.addEventListener('dragleave', () => el.classList.remove('drop-target'));
        el.addEventListener('drop', (e) => {
          el.classList.remove('drop-target');
          const raw = e.dataTransfer.getData('application/x-ft-items');
          if (!raw) return;
          e.preventDefault(); e.stopPropagation();
          const moving = JSON.parse(raw).map((x) => items.get(x)).filter((x) => x && key(x) !== k);
          if (moving.length && opt.onMove) opt.onMove(moving, items.get(k));
        });
      }
    }
    return el;
  }

  function openMenu(it, anchor) {
    const acts = opt.itemActions(it) || [];
    if (acts.length) menu(anchor, acts);
  }

  function onKey(e, k) {
    const idx = order.indexOf(k);
    const focusAt = (i) => listEl.querySelector('[data-key="' + order[Math.max(0, Math.min(order.length - 1, i))] + '"]')?.focus();
    const cols = opt.mode === 'grid' ? Math.max(1, Math.round(listEl.clientWidth / 180)) : 1;
    if (e.key === 'ArrowRight') { e.preventDefault(); focusAt(idx + 1); }
    else if (e.key === 'ArrowLeft') { e.preventDefault(); focusAt(idx - 1); }
    else if (e.key === 'ArrowDown') { e.preventDefault(); focusAt(idx + cols); }
    else if (e.key === 'ArrowUp') { e.preventDefault(); focusAt(idx - cols); }
    else if (e.key === 'Enter') { e.preventDefault(); opt.onOpen && opt.onOpen(items.get(k)); }
    else if (e.key === ' ' && opt.selectable) { e.preventDefault(); toggle(k, e); }
    else if ((e.key === 'a' || e.key === 'A') && (e.ctrlKey || e.metaKey) && opt.selectable) { e.preventDefault(); order.forEach((x) => selected.add(x)); refreshSelection(); }
    else if (e.key === 'Escape') { clearSelection(); }
    else if ((e.key === 'ContextMenu' || (e.shiftKey && e.key === 'F10')) && opt.itemActions) { e.preventDefault(); openMenu(items.get(k), e.currentTarget); }
  }

  function toggle(k, e) {
    if (e && e.shiftKey && lastClicked && order.includes(lastClicked)) {
      const a = order.indexOf(lastClicked), b = order.indexOf(k);
      order.slice(Math.min(a, b), Math.max(a, b) + 1).forEach((x) => selected.add(x));
    } else if (selected.has(k)) selected.delete(k);
    else selected.add(k);
    lastClicked = k;
    refreshSelection();
  }

  function refreshSelection() {
    root.classList.toggle('selecting', selected.size > 0);
    listEl.querySelectorAll('.fi').forEach((el) => {
      const on = selected.has(el.dataset.key);
      el.classList.toggle('selected', on);
      el.setAttribute('aria-selected', on ? 'true' : 'false');
      const c = el.querySelector('.fi-check');
      if (c) { clear(c); if (on) c.appendChild(icon('check', 14)); }
    });
    renderBatch();
  }

  function renderBatch() {
    batchBar && batchBar.remove();
    batchBar = null;
    if (!selected.size || !opt.batchActions) return;
    const sel = [...selected].map((k) => items.get(k)).filter(Boolean);
    batchBar = h('div.batchbar', { role: 'toolbar', 'aria-label': 'Selection actions' },
      h('span.count', { text: sel.length + ' selected' }),
      ...opt.batchActions(sel),
      h('button.btn.btn-ghost.btn-sm', { type: 'button', on: { click: clearSelection } }, icon('x', 15), 'Clear'));
    document.body.appendChild(batchBar);
  }

  function clearSelection() { selected.clear(); refreshSelection(); }

  async function reload() {
    page = 0; hasMore = true; items.clear(); order.length = 0; selected.clear();
    clear(listEl); clear(status); renderBatch();
    await loadMore();
  }

  loadMore();

  return {
    reload,
    /** Insert or update an item (real-time). Returns false when the list does not accept it. */
    upsert(it) {
      if (opt.accept && !opt.accept(it)) { this.remove(it.id, it.type); return false; }
      const k = key(it);
      if (items.has(k)) replace(it);
      else { add(it, true); clear(status); }
      listEl.querySelector('[data-key="' + k + '"]')?.classList.add('flash');
      return true;
    },
    remove(id, type = 'file') {
      const k = (type === 'folder' ? 'd' : 'f') + id;
      if (!items.has(k)) return;
      items.delete(k);
      selected.delete(k);
      const i = order.indexOf(k); if (i >= 0) order.splice(i, 1);
      listEl.querySelector('[data-key="' + k + '"]')?.remove();
      if (!order.length) { clear(status); status.appendChild(emptyState(opt.emptyState || {})); }
      renderBatch();
    },
    get(id, type = 'file') { return items.get((type === 'folder' ? 'd' : 'f') + id); },
    items: () => order.map((k) => items.get(k)),
    selected: () => [...selected].map((k) => items.get(k)).filter(Boolean),
    clearSelection,
    setMode,
    destroy() { destroyed = true; io && io.disconnect(); batchBar && batchBar.remove(); },
  };
}
