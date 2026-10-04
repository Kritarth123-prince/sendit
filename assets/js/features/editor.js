/**
 * In-browser text/code editor (§9.4 "In-browser text editor & presence").
 *
 * - GET /files/{id}/text → {content, version, editable}; PUT {content, base_version} saves a new
 *   version (large texts go as raw text/plain with X-Base-Version). Nothing is ever lost: every
 *   save is a version in the history.
 * - Optimistic concurrency: a 409 VERSION_CONFLICT offers reload theirs / overwrite / keep editing.
 * - Presence: heartbeat every 10 s; avatars of the other people editing; {leave:true} on close.
 * - Another device saving: reload silently when there are no local edits, otherwise a banner.
 * - Line-number gutter kept in sync with the textarea; Tab inserts spaces; Ctrl/Cmd+S saves.
 * @module features/editor
 */
import { api } from '../core/api.js';
import { bus } from '../core/bus.js';
import { store } from '../core/store.js';
import { h, icon, clear } from '../core/dom.js';
import { modal, toast, spinner, errorState } from '../core/ui.js';
import { realtime } from '../core/realtime.js';
import { relative } from '../core/format.js';

const RAW_THRESHOLD = 1.5 * 1024 * 1024;
const HEARTBEAT_MS = 10000;
const TWO_SPACE = ['js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'json', 'html', 'htm', 'css', 'scss', 'less', 'yaml', 'yml', 'md', 'markdown', 'xml', 'svg', 'vue'];

const open = new Map(); // fileId -> editor (one editor per file per tab)

/** @param {Object} file FileSummary (needs id, name; ext/kind used for indentation) */
export function openEditor(file) {
  if (!file || !file.id) return null;
  const id = Number(file.id);
  if (open.has(id)) { open.get(id).focus(); return open.get(id); }
  const me = store.get('user') || {};
  const indent = TWO_SPACE.includes(String(file.ext || '').toLowerCase()) ? '  ' : '    ';
  let base = 0;
  let saved = '';
  let editable = false;
  let saving = false;
  let closed = false;
  let deleted = false;
  let others = [];
  let hb = null;
  const offs = [];

  // ---------------------------------------------------------------- DOM
  const ta = h('textarea.ed-text', { spellcheck: false, autocapitalize: 'off', autocomplete: 'off', wrap: 'off', 'aria-label': 'Contents of ' + file.name, disabled: true });
  ta.setAttribute('autocorrect', 'off');
  const gutterInner = h('div.ed-gutter-inner');
  const gutter = h('div.ed-gutter', { 'aria-hidden': 'true' }, gutterInner);
  const banner = h('div.ed-banner', { role: 'status', hidden: true });
  const loading = h('div.pv-loading', spinner(), h('span', { text: 'Opening…' }));
  const main = h('div.ed-main', { hidden: true }, gutter, ta);
  const posEl = h('span', { text: 'Ln 1, Col 1' });
  const linesEl = h('span');
  const verEl = h('span');
  const state = h('span.ed-state', { text: '' });
  const status = h('div.ed-status', posEl, linesEl, verEl, h('span.ed-hint', { text: 'Tab inserts spaces · Ctrl+S saves' }), h('span.grow'), state);
  const presence = h('div.ed-presence', { 'aria-live': 'polite' });
  const saveBtn = h('button.btn.btn-primary.btn-sm', { type: 'button', disabled: true, title: 'Save (Ctrl+S)', on: { click: () => save() } }, icon('save', 15), h('span.pv-lbl', { text: 'Save' }));
  const closeBtn = h('button.icon-btn', { type: 'button', 'aria-label': 'Close editor', title: 'Close', on: { click: () => requestClose() } }, icon('x', 18));

  const m = modal({ title: file.name, content: h('div.ed', banner, loading, main, status), size: 'full', dismissible: false });
  m.el.classList.add('ed-modal');
  const overlay = m.el.parentElement;
  overlay.classList.add('ed-overlay');
  const head = m.el.querySelector('.modal-head');
  head.querySelector('.modal-title').prepend(icon('edit', 16), ' ');
  head.append(presence, saveBtn, closeBtn);

  const api_ = {
    focus() { ta.focus(); },
    close: () => requestClose(),
  };
  open.set(id, api_);

  // ---------------------------------------------------------------- load
  load(true);

  async function load(first = false, { keepView = false } = {}) {
    try {
      const { data } = await api.get('/files/' + id + '/text');
      if (closed) return;
      const top = ta.scrollTop, left = ta.scrollLeft, s = ta.selectionStart, e = ta.selectionEnd;
      ta.value = data.content || '';
      saved = ta.value;
      base = Number(data.version) || 0;
      editable = !!data.editable && !deleted;
      ta.disabled = false;
      ta.readOnly = !editable;
      loading.remove();
      main.hidden = false;
      if (keepView) { ta.scrollTop = top; ta.scrollLeft = left; try { ta.setSelectionRange(Math.min(s, ta.value.length), Math.min(e, ta.value.length)); } catch { /* ignore */ } }
      paintLines(true);
      paintStatus();
      hideBanner();
      if (!editable) showBanner('Read-only: you can view this file but not change it.', [], 'info');
      if (first) {
        if (editable) { ta.focus(); ta.setSelectionRange(0, 0); ta.scrollTop = 0; }
        startPresence();
      }
    } catch (err) {
      if (closed) return;
      if (first) {
        clear(m.body).appendChild(h('div.pv-col.pv-pad', errorState(err)));
        head.append(closeBtn);
        saveBtn.hidden = true;
      } else toast(err.message, { type: 'err' });
    }
  }

  // ---------------------------------------------------------------- gutter & status
  let lineCount = 0;
  function countLines(t) {
    let n = 1;
    for (let i = t.indexOf('\n'); i !== -1; i = t.indexOf('\n', i + 1)) n++;
    return n;
  }
  function paintLines(force = false) {
    const n = countLines(ta.value);
    if (n !== lineCount || force) {
      lineCount = n;
      const nums = new Array(n);
      for (let i = 0; i < n; i++) nums[i] = i + 1;
      gutterInner.textContent = nums.join('\n');
      linesEl.textContent = n === 1 ? '1 line' : n.toLocaleString('en-GB') + ' lines';
    }
    syncScroll();
  }
  function syncScroll() { gutterInner.style.transform = 'translateY(' + -ta.scrollTop + 'px)'; }
  function paintStatus() {
    const pos = ta.selectionStart || 0;
    const before = ta.value.slice(0, pos);
    const line = countLines(before);
    const col = pos - before.lastIndexOf('\n');
    posEl.textContent = 'Ln ' + line + ', Col ' + col;
    verEl.textContent = 'Version ' + base;
    const dirty = isDirty();
    saveBtn.disabled = !editable || saving || !dirty;
    state.textContent = saving ? 'Saving…' : !editable ? 'Read-only' : dirty ? 'Unsaved changes' : 'All changes saved';
    state.className = 'ed-state' + (dirty && editable ? ' dirty' : '');
  }
  const isDirty = () => editable && ta.value !== saved;

  let raf = 0;
  const schedule = () => { if (!raf) raf = requestAnimationFrame(() => { raf = 0; paintLines(); paintStatus(); }); };
  ta.addEventListener('input', schedule);
  ta.addEventListener('scroll', syncScroll, { passive: true });
  ta.addEventListener('keyup', schedule);
  ta.addEventListener('click', schedule);
  ta.addEventListener('select', schedule);

  // ---------------------------------------------------------------- keys
  ta.addEventListener('keydown', (e) => {
    if (e.key === 'Tab' && !e.ctrlKey && !e.altKey && !e.metaKey && editable) {
      e.preventDefault();
      e.stopPropagation(); // the dialog's focus trap must not move focus away
      if (e.shiftKey) outdent(); else indentSel();
    } else if (e.key === 'Enter' && !e.ctrlKey && !e.metaKey && !e.altKey && editable) {
      // keep the current line's indentation
      const v = ta.value, s = ta.selectionStart;
      const ls = v.lastIndexOf('\n', s - 1) + 1;
      const ind = /^[ \t]*/.exec(v.slice(ls, s))[0];
      if (ind) { e.preventDefault(); insert('\n' + ind); }
    }
  });
  function insert(text) {
    ta.focus();
    // execCommand keeps the browser's undo history; fall back when it is unavailable
    let ok = false;
    try { ok = document.execCommand('insertText', false, text); } catch { ok = false; }
    if (!ok) { ta.setRangeText(text, ta.selectionStart, ta.selectionEnd, 'end'); ta.dispatchEvent(new Event('input')); }
  }
  function indentSel() {
    const v = ta.value, s = ta.selectionStart, e = ta.selectionEnd;
    if (s === e || v.slice(s, e).indexOf('\n') === -1) { insert(indent); return; }
    const ls = v.lastIndexOf('\n', s - 1) + 1;
    const block = v.slice(ls, e);
    const out = block.split('\n').map((l) => indent + l).join('\n');
    ta.setSelectionRange(ls, e);
    insert(out);
    ta.setSelectionRange(ls, ls + out.length);
  }
  function outdent() {
    const v = ta.value, s = ta.selectionStart, e = ta.selectionEnd;
    const ls = v.lastIndexOf('\n', s - 1) + 1;
    const block = v.slice(ls, e);
    const re = new RegExp('^( {1,' + indent.length + '}|\\t)');
    const out = block.split('\n').map((l) => l.replace(re, '')).join('\n');
    if (out === block) return;
    ta.setSelectionRange(ls, e);
    insert(out);
    ta.setSelectionRange(ls, ls + out.length);
  }

  const onDocKey = (e) => {
    const all = document.querySelectorAll('.modal-overlay');
    if (all[all.length - 1] !== overlay) return;
    if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === 's' || e.key === 'S')) { e.preventDefault(); save(); }
    else if (e.key === 'Escape') { e.preventDefault(); requestClose(); }
  };
  document.addEventListener('keydown', onDocKey);
  const onBeforeUnload = (e) => { if (isDirty()) { e.preventDefault(); e.returnValue = ''; } };
  window.addEventListener('beforeunload', onBeforeUnload);
  const onPageHide = () => leave(true);
  window.addEventListener('pagehide', onPageHide);

  // ---------------------------------------------------------------- save
  async function save({ baseVersion = base } = {}) {
    if (!editable || saving || deleted) return false;
    const content = ta.value;
    saving = true;
    paintStatus();
    try {
      const size = new TextEncoder().encode(content).length;
      const res = size > RAW_THRESHOLD
        ? await api.raw('PUT', '/files/' + id + '/text', { body: new Blob([content], { type: 'text/plain;charset=utf-8' }), headers: { 'Content-Type': 'text/plain; charset=utf-8', 'X-Base-Version': String(baseVersion) } })
        : await api.put('/files/' + id + '/text', { content, base_version: baseVersion });
      const f = res.data || {};
      base = Number(f.version) || base;
      saved = content;
      hideBanner();
      toast(f.changed === false ? 'No changes to save' : 'Saved — version ' + base, { type: 'ok', timeout: 2200, id: 'ed-save-' + id });
      realtime.nudge();
      return true;
    } catch (err) {
      if (err && err.code === 'VERSION_CONFLICT') conflict(err.details && err.details.current_version);
      else toast(err.message || 'Could not save.', { type: 'err', timeout: 6000 });
      return false;
    } finally {
      saving = false;
      paintStatus();
    }
  }

  function conflict(current) {
    const cur = Number(current) || null;
    modal({
      title: 'Someone else saved this file',
      size: 'sm',
      content: h('div.stack',
        h('p', { text: (cur ? 'Version ' + cur + ' was saved' : 'A newer version was saved') + ' while you were editing (you started from version ' + base + ').' }),
        h('p.text2', { text: 'Reload to see their changes, or overwrite them with yours. Nothing is lost either way: every saved version stays in the version history.' })),
      actions: [
        { label: 'Keep editing', kind: 'ghost' },
        { label: 'Reload theirs', onClick: () => { load(false, { keepView: true }); toast('Loaded the latest version', { type: 'info' }); } },
        { label: 'Overwrite with mine', kind: 'danger', onClick: async () => { if (cur) await save({ baseVersion: cur }); else { await load(false); } } },
      ],
    });
  }

  // ---------------------------------------------------------------- presence
  function startPresence() {
    beat();
    hb = setInterval(beat, HEARTBEAT_MS);
    offs.push(bus.on('presence.updated', (e) => { if (Number(e.data?.file_id ?? e.file_id) === id) paintPresence(e.data?.users || []); }));
  }
  async function beat() {
    if (closed) return;
    try { const { data } = await api.post('/files/' + id + '/presence', {}); if (!closed) paintPresence(data?.users || []); } catch { /* best effort */ }
  }
  function paintPresence(users) {
    others = (users || []).filter((u) => u && u.id !== me.id);
    clear(presence);
    if (!others.length) return;
    const names = others.map((u) => u.display_name || u.username);
    presence.title = names.join(', ') + (others.length === 1 ? ' is' : ' are') + ' also editing';
    others.slice(0, 4).forEach((u) => presence.appendChild(h('span.avatar.sm', { 'aria-hidden': 'true', text: (u.display_name || u.username || '?').slice(0, 1).toUpperCase() })));
    presence.appendChild(h('span.ed-presence-text', { text: others.length === 1 ? names[0] + ' is also editing' : others.length + ' others are editing' }));
  }
  function leave(beacon = false) {
    const url = api.url('/files/' + id + '/presence');
    const headers = { Accept: 'application/json', 'Content-Type': 'application/json', 'X-Client-Id': api.clientId };
    if (api.csrf) headers['X-CSRF-Token'] = api.csrf;
    try { fetch(url, { method: 'POST', credentials: 'same-origin', keepalive: beacon, headers, body: JSON.stringify({ leave: true }) }).catch(() => {}); } catch { /* ignore */ }
  }

  // ---------------------------------------------------------------- live changes from other devices
  const forThis = (e) => Number(e.file_id ?? e.data?.file_id ?? e.data?.file?.id) === id;
  const onNewVersion = (e) => {
    if (!forThis(e) || closed) return;
    const v = Number(e.data?.version ?? e.data?.file?.version) || 0;
    if (v && v <= base) return; // our own save (or older)
    if (e.origin === api.clientId && (saving || !v)) return; // our save, response still on its way
    const who = e.actor?.name || 'Someone';
    if (!isDirty()) {
      load(false, { keepView: true });
      toast(who + ' saved a new version — updated', { type: 'info', id: 'ed-remote-' + id });
    } else {
      showBanner(who + ' saved a newer version' + (v ? ' (version ' + v + ')' : '') + ' ' + relative(e.timestamp) + '.', [
        { label: 'Reload theirs', onClick: () => load(false, { keepView: true }) },
        { label: 'Keep mine', onClick: hideBanner },
      ], 'warn');
    }
  };
  offs.push(bus.on('version.created', onNewVersion));
  offs.push(bus.on('version.restored', onNewVersion));
  offs.push(bus.on('file.deleted', (e) => {
    if (!forThis(e)) return;
    deleted = true;
    editable = false;
    ta.readOnly = true;
    paintStatus();
    showBanner('This file was moved to the Trash, so it can no longer be saved. Copy your text if you need it.', [], 'warn');
  }));
  offs.push(bus.on('file.renamed', (e) => { if (forThis(e) && e.data?.file?.name) { const t = head.querySelector('.modal-title'); t.lastChild.textContent = e.data.file.name; } }));

  function showBanner(text, actions = [], kind = 'warn') {
    clear(banner);
    banner.className = 'ed-banner ' + kind;
    banner.append(icon(kind === 'info' ? 'info' : 'warning', 16), h('span.grow', { text }),
      ...actions.map((a) => h('button.btn.btn-sm', { type: 'button', text: a.label, on: { click: a.onClick } })));
    banner.hidden = false;
  }
  function hideBanner() { if (!editable && !deleted && !main.hidden) return; banner.hidden = true; clear(banner); }

  // ---------------------------------------------------------------- close
  async function requestClose() {
    if (closed) return;
    if (isDirty()) {
      const choice = await new Promise((resolve) => {
        let r = 'keep';
        modal({
          title: 'Save your changes?', size: 'sm',
          content: 'You have unsaved changes to “' + file.name + '”.',
          actions: [
            { label: 'Keep editing', kind: 'ghost' },
            { label: 'Discard', kind: 'danger', onClick: () => { r = 'discard'; } },
            { label: 'Save and close', kind: 'primary', onClick: () => { r = 'save'; } },
          ],
          onClose: () => resolve(r),
        });
      });
      if (choice === 'keep') { ta.focus(); return; }
      if (choice === 'save' && !(await save())) return;
    }
    doClose();
  }

  function doClose() {
    if (closed) return;
    closed = true;
    clearInterval(hb);
    offs.forEach((off) => off());
    document.removeEventListener('keydown', onDocKey);
    window.removeEventListener('beforeunload', onBeforeUnload);
    window.removeEventListener('pagehide', onPageHide);
    if (hb !== null) leave(false);
    open.delete(id);
    m.close();
  }

  return api_;
}
