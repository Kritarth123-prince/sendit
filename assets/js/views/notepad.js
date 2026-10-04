/**
 * Notepad: the legacy "Collaborative Notepad", now with team and private notepads.
 *
 * Several people and devices can type in the same notepad at once: text saves itself (about a
 * second after typing stops, at least every four seconds while typing), other people's saves
 * arrive live (notepad.updated) and are merged into what you are typing with a three-way merge
 * (features/notepad-merge.js), so nobody's words are lost. A save that raced someone else's is
 * refused with 409 VERSION_CONFLICT carrying their text, merged, and saved again.
 * While offline, unsaved text is kept on this device (localStorage) and merged on return.
 * Presence ("Rahul is here") uses a 20 s heartbeat that also reports the current version, so a
 * missed event is noticed. Routes: #/notepad (list) and #/notepad/<id>.
 */
import { api } from '../core/api.js';
import { h, icon, clear, debounce } from '../core/dom.js';
import { bus } from '../core/bus.js';
import { store } from '../core/store.js';
import { router } from '../core/router.js';
import { time, date, dateTime, bytes, dayLabel } from '../core/format.js';
import { toast, confirm, prompt, modal, menu, emptyState, errorState, skeleton } from '../core/ui.js';
import { loadEngine, merge3, mapOffset, countText, byteLength } from '../features/notepad-merge.js';

const MAX_BYTES = 1048576;
const SAVE_IDLE_MS = 1200;
const SAVE_MAX_MS = 4000;
const HEARTBEAT_MS = 20000;
const DRAFT_DAYS = 30;
const MONO_KEY = 'ft:notepad-mono';
const draftKey = (id) => 'ft:notepad-draft:' + id;

let listCache = null; // last list, so switching notepads renders the sidebar at once
let offs = [];
let session = null;

const ls = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, v); return true; } catch { return false; } },
  del(k) { try { localStorage.removeItem(k); } catch { /* ignore */ } },
};
const tabId = () => (crypto.randomUUID ? crypto.randomUUID() : 'np-' + Math.random().toString(36).slice(2, 14));
const isToday = (iso) => { const d = new Date(iso); return !Number.isNaN(d.getTime()) && d.toDateString() === new Date().toDateString(); };
const when = (iso) => (iso ? (isToday(iso) ? time(iso) : date(iso)) : '');
const wide = () => window.matchMedia('(min-width: 900px)').matches; // the shell's phone layout starts below 900 px

/** The view's stylesheet, loaded once (assets/css/notepad.css); resolves when applied or after 1.5 s. */
function ensureCss() {
  if (document.getElementById('np-css')) return Promise.resolve();
  const cfg = store.get('config') || {};
  const link = h('link', { id: 'np-css', rel: 'stylesheet', href: (cfg.base || '/') + 'assets/css/notepad.css?v=' + encodeURIComponent(cfg.version || '') });
  const ready = new Promise((resolve) => { link.addEventListener('load', resolve, { once: true }); link.addEventListener('error', resolve, { once: true }); setTimeout(resolve, 1500); });
  document.head.appendChild(link);
  return ready;
}

export default {
  title: 'Notepad',
  async mount(el, params) {
    const id = params.id ? parseInt(params.id, 10) : null;
    await ensureCss();
    const listEl = h('div.np-items');
    const listPane = h('aside.np-list', { 'aria-label': 'Notepads' },
      h('div.np-list-head',
        h('div.grow', h('h1.view-title', { text: 'Notepad' }), h('div.view-sub', { text: 'Write together in real time.' })),
        h('button.btn.btn-primary.btn-sm', { type: 'button', on: { click: createNotepad } }, icon('plus', 16), 'New')),
      listEl);
    const editorPane = h('section.np-editor', { 'aria-live': 'off' });
    const root = h('div.np', { dataset: { pane: id ? 'editor' : 'list' } }, listPane, editorPane);
    el.appendChild(root);

    // ------------------------------------------------------------------ list
    function renderList() {
      clear(listEl);
      const items = listCache || [];
      if (!items.length) { listEl.appendChild(emptyState({ icon: 'edit', title: 'No notepads yet', text: 'Create one to start writing.' })); return; }
      const group = (title, rows) => {
        if (!rows.length) return;
        listEl.appendChild(h('div.np-group', { text: title }));
        rows.forEach((n) => listEl.appendChild(item(n)));
      };
      group('Team', items.filter((n) => n.visibility === 'team'));
      group('Private', items.filter((n) => n.visibility === 'private'));
    }
    function item(n) {
      const meta = [n.updated_by ? n.updated_by.name : null, when(n.updated_at)].filter(Boolean).join(' · ');
      return h('a.np-item' + (n.id === id ? '.on' : ''), { href: '#/notepad/' + n.id, 'aria-current': n.id === id ? 'page' : undefined },
        h('span.np-item-ico', { 'aria-hidden': 'true' }, icon(n.visibility === 'private' ? 'lock' : 'users', 16)),
        h('span.np-item-main',
          h('span.np-item-title.ellipsis', { text: n.title }),
          h('span.np-item-meta.ellipsis', { text: n.size ? meta : 'Empty' })),
        n.present > 0 ? h('span.np-here', { title: n.present === 1 ? '1 person here now' : n.present + ' people here now' }, h('span.np-dot'), String(n.present)) : null);
    }
    async function loadList() {
      if (!listCache) listEl.appendChild(skeleton(4));
      try {
        const { data } = await api.get('/notepads');
        listCache = data || [];
        if (closed) return;
        renderList();
        if (!id && listCache.length && wide()) location.replace('#/notepad/' + listCache[0].id);
        if (!id && !listCache.length) editorPane.appendChild(emptyState({ icon: 'edit', title: 'No notepads', text: 'Create a notepad to start writing.' }));
      } catch (e) {
        if (closed) return;
        clear(listEl).appendChild(e.status === 403
          ? emptyState({ icon: 'lock', title: 'Not available', text: e.message })
          : errorState(e, loadList));
      }
    }
    const reloadList = debounce(loadList, 400);
    const patchList = (nid, patch) => {
      if (!listCache) return;
      const n = listCache.find((x) => x.id === nid);
      if (n) { Object.assign(n, patch); renderList(); }
    };

    async function createNotepad() {
      let visibility = 'team';
      const titleIn = h('input.input', { type: 'text', maxlength: 120, placeholder: 'Untitled notepad', 'aria-label': 'Title', autofocus: true });
      const choice = (value, label, hint, ic) => {
        const input = h('input', { type: 'radio', name: 'np-vis', value, checked: value === visibility, on: { change: () => { visibility = value; } } });
        return h('label.np-choice', input, h('span.np-choice-ico', icon(ic, 18)), h('span', h('strong', { text: label }), h('span.small.text2', { text: hint })));
      };
      const body = h('div.stack',
        h('div.field', h('label.label', { text: 'Title' }), titleIn),
        h('div.field', h('span.label', { text: 'Who can see it' }),
          h('div.np-choices', { role: 'radiogroup', 'aria-label': 'Who can see it' },
            choice('team', 'Team', 'Everyone in your workspace can read and edit it.', 'users'),
            choice('private', 'Private', 'Only you can see it.', 'lock'))));
      const m = modal({ title: 'New notepad', content: body, actions: [
        { label: 'Cancel', kind: 'ghost' },
        { label: 'Create', kind: 'primary', onClick: async () => {
          m.setBusy(true);
          try {
            const { data } = await api.post('/notepads', { title: titleIn.value.trim() || null, visibility });
            listCache = null;
            router.go('/notepad/' + data.id);
          } catch (e) { toast(e.message, { type: 'err' }); m.setBusy(false); return false; }
          return true;
        } },
      ] });
      titleIn.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); m.el.querySelector('.modal-foot .btn-primary')?.click(); } });
    }

    // ------------------------------------------------------------------ editor
    let closed = false;
    const s = session = {
      id, tab: tabId(), meta: null, server: null, saving: null, again: false, remotePending: false,
      idleTimer: 0, maxTimer: 0, beatTimer: 0, statusTimer: 0, engine: null,
    };
    const ta = h('textarea.np-text', {
      spellcheck: 'true', 'aria-label': 'Notepad text', autocomplete: 'off',
      on: { input: onInput, keydown: (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') { e.preventDefault(); saveNow(); } } },
    });
    if (ls.get(MONO_KEY) === '1') ta.classList.add('mono');
    const titleEl = h('h2.np-title.ellipsis');
    const visEl = h('span.np-vis');
    const presenceEl = h('div.np-presence', { 'aria-live': 'polite' });
    const statusEl = h('span.np-status', { role: 'status' });
    const countEl = h('span.np-count');
    const sizeEl = h('span.np-size');

    function setStatus(kind, text) {
      clearTimeout(s.statusTimer);
      statusEl.className = 'np-status ' + kind;
      clear(statusEl).append(icon({ saved: 'check', saving: 'retry', offline: 'wifi', error: 'warning', merged: 'users', editing: 'edit' }[kind] || 'check', 14), h('span', { text }));
    }
    const savedStatus = () => setStatus('saved', 'Saved ' + time(s.meta?.updated_at || new Date().toISOString()));
    function updateCounts() {
      const { words, chars } = countText(ta.value);
      countEl.textContent = words.toLocaleString('en-GB') + (words === 1 ? ' word' : ' words') + ' · ' + chars.toLocaleString('en-GB') + (chars === 1 ? ' character' : ' characters');
      const size = byteLength(ta.value);
      sizeEl.textContent = bytes(size) + ' of 1 MB';
      sizeEl.classList.toggle('warn', size > MAX_BYTES * 0.9);
    }
    function paintPresence(users) {
      clear(presenceEl);
      const me = store.get('user');
      const others = (users || []).filter((u) => Number(u.id) !== Number(me?.id));
      if (!others.length) return;
      const names = others.map((u) => u.display_name || u.username || 'Someone');
      presenceEl.title = names.join(', ') + (others.length === 1 ? ' is' : ' are') + ' here';
      others.slice(0, 4).forEach((u) => presenceEl.appendChild(h('span.avatar.sm', { 'aria-hidden': 'true', text: (u.display_name || u.username || '?').slice(0, 1).toUpperCase() })));
      presenceEl.appendChild(h('span.np-presence-text', { text: others.length === 1 ? names[0] + ' is here' : others.length + ' people here' }));
    }
    function paintMeta() {
      const m = s.meta;
      titleEl.textContent = m.title;
      titleEl.title = m.title;
      clear(visEl).append(icon(m.visibility === 'private' ? 'lock' : 'users', 14), h('span', { text: m.visibility === 'private' ? 'Private' : 'Team' }));
      visEl.className = 'np-vis ' + m.visibility;
      ta.placeholder = m.visibility === 'private'
        ? 'Start typing… only you can see this notepad. It saves by itself.'
        : 'Start typing… everyone in your team sees your changes live. It saves by itself.';
    }

    function renderEditor() {
      clear(editorPane).append(
        h('div.np-head',
          h('a.icon-btn.np-back', { href: '#/notepad', 'aria-label': 'All notepads' }, icon('arrow-left', 18)),
          h('div.np-head-main', h('div.row', titleEl, visEl), h('div.np-sub', presenceEl)),
          statusEl,
          h('button.icon-btn', { type: 'button', 'aria-label': 'History', title: 'History', on: { click: openHistory } }, icon('history', 18)),
          h('button.icon-btn', { type: 'button', 'aria-label': 'More actions', title: 'More', on: { click: (e) => openMenu(e.currentTarget) } }, icon('more', 18))),
        h('div.np-paper', ta),
        h('div.np-foot', countEl, h('span.grow'), sizeEl, h('span.np-hint', { text: 'Saves automatically · Ctrl+S to save now' })));
      paintMeta();
      updateCounts();
    }

    function openMenu(anchor) {
      const m = s.meta;
      const items = [];
      if (m.can_manage) {
        items.push({ label: 'Rename', icon: 'edit', onClick: rename });
        items.push(m.visibility === 'team'
          ? { label: 'Make private', icon: 'lock', onClick: () => setVisibility('private') }
          : { label: 'Share with team', icon: 'users', onClick: () => setVisibility('team') });
      }
      items.push({ label: ta.classList.contains('mono') ? 'Normal font' : 'Monospace font', icon: 'code', onClick: () => { const on = ta.classList.toggle('mono'); ls.set(MONO_KEY, on ? '1' : '0'); } });
      items.push({ label: 'Download as .txt', icon: 'download', onClick: download });
      items.push({ label: 'History', icon: 'history', onClick: openHistory });
      if (m.can_manage) items.push({ label: 'Delete notepad', icon: 'trash', danger: true, onClick: remove });
      menu(anchor, items);
    }

    // ---- saving
    function onInput() {
      updateCounts();
      setStatus('editing', 'Editing…');
      writeDraftSoon();
      clearTimeout(s.idleTimer);
      s.idleTimer = setTimeout(saveNow, SAVE_IDLE_MS);
      if (!s.maxTimer) s.maxTimer = setTimeout(saveNow, SAVE_MAX_MS);
    }
    function clearTimers() { clearTimeout(s.idleTimer); clearTimeout(s.maxTimer); s.idleTimer = 0; s.maxTimer = 0; }

    function put(text, base) {
      return api.raw('PUT', '/notepads/' + id + '/content', {
        body: new Blob([text], { type: 'text/plain;charset=utf-8' }),
        headers: { 'X-Base-Version': String(base), 'X-Notepad-Client': s.tab },
      });
    }

    /** Save the current text (no-op when nothing changed). Resolves when this save is done. */
    function saveNow() {
      clearTimers();
      if (!s.server) return Promise.resolve();
      if (s.saving) { s.again = true; return s.saving; }
      const text = ta.value;
      if (text === s.server.text) { clearDraft(); if (!closed) savedStatus(); return Promise.resolve(); }
      if (byteLength(text) > MAX_BYTES) {
        setStatus('error', 'Too long — a notepad holds up to 1 MB');
        return Promise.resolve();
      }
      if (!closed) setStatus('saving', 'Saving…');
      s.saving = put(text, s.server.version).then(({ data }) => {
        s.server = { version: data.version, text };
        if (s.meta) { s.meta.version = data.version; s.meta.updated_at = data.updated_at; }
        if (ta.value === text) clearDraft();
        if (!closed) { savedStatus(); patchList(id, { updated_at: data.updated_at, updated_by: data.updated_by, size: data.size }); }
      }).catch(async (e) => {
        if (e.status === 409 && e.code === 'VERSION_CONFLICT') {
          await absorb(e.details.content, e.details.current_version, e.details.updated_by?.name);
          s.again = true;
        } else if (e.code === 'NETWORK' || e.status === 0) {
          writeDraft();
          if (!closed) setStatus('offline', 'Offline — changes kept on this device');
        } else if (e.status === 404) {
          gone('This notepad was deleted or is no longer shared with you.');
        } else {
          writeDraft();
          if (!closed) setStatus('error', e.message || 'Could not save');
        }
      }).finally(() => {
        s.saving = null;
        if (closed && !s.again) return;
        if (s.again) { s.again = false; if (ta.value !== s.server?.text) saveNow(); }
        if (s.remotePending) { s.remotePending = false; refreshRemote(); }
      });
      return s.saving;
    }

    /** Take in someone else's text (version `version`), merging our unsaved edits into it. */
    async function absorb(theirs, version, by) {
      if (!s.engine) s.engine = await loadEngine();
      const base = s.server.text;
      const mine = ta.value; // read after the await: includes anything typed meanwhile
      const r = merge3(s.engine, base, mine, theirs);
      replaceText(r.text);
      s.server = { version, text: theirs };
      if (s.meta) s.meta.version = version;
      if (closed) return r;
      if (!r.clean) toast('Some of your changes overlapped with ' + (by || 'someone else') + '’s and were added at the end of the notepad.', { type: 'warn', timeout: 7000 });
      if (mine !== base && r.text !== theirs) {
        setStatus('merged', 'Merged with ' + (by || 'someone else') + '’s changes');
        clearTimeout(s.idleTimer);
        s.idleTimer = setTimeout(saveNow, 300);
      } else {
        setStatus('merged', by ? 'Updated by ' + by : 'Updated');
        s.statusTimer = setTimeout(() => { if (!closed && ta.value === s.server.text) savedStatus(); }, 4000);
      }
      return r;
    }

    /** Replace the text, keeping the caret, selection and scroll position where the person was. */
    function replaceText(next) {
      const before = ta.value;
      if (before === next) return;
      const focused = document.activeElement === ta;
      const { selectionStart: a, selectionEnd: b, scrollTop } = ta;
      ta.value = next;
      if (focused && s.engine) {
        ta.setSelectionRange(mapOffset(s.engine, before, next, a), mapOffset(s.engine, before, next, b));
      }
      ta.scrollTop = scrollTop;
      updateCounts();
    }

    /** Fetch the latest text after someone else saved (or a heartbeat showed a newer version). */
    async function refreshRemote() {
      if (closed || !s.server) return;
      if (s.saving) { s.remotePending = true; return; }
      try {
        const { data } = await api.get('/notepads/' + id);
        if (closed) return;
        s.meta = { ...s.meta, ...data };
        paintMeta();
        paintPresence(data.present_users);
        if (data.version > s.server.version) await absorb(data.content, data.version, data.updated_by?.name);
      } catch (e) {
        if (e.status === 404) gone('This notepad was deleted or is no longer shared with you.');
      }
    }

    // ---- drafts (offline safety net)
    function writeDraft() {
      if (!s.server || ta.value === s.server.text) return;
      const d = { v: s.server.version, base: s.server.text, text: ta.value, at: Date.now() };
      if (!ls.set(draftKey(id), JSON.stringify(d))) ls.set(draftKey(id), JSON.stringify({ ...d, base: null }));
    }
    const writeDraftSoon = debounce(writeDraft, 600);
    function clearDraft() { ls.del(draftKey(id)); }
    function readDraft() {
      try {
        const d = JSON.parse(ls.get(draftKey(id)) || 'null');
        if (!d || typeof d.text !== 'string' || Date.now() - (d.at || 0) > DRAFT_DAYS * 86400000) { clearDraft(); return null; }
        return d;
      } catch { clearDraft(); return null; }
    }

    // ---- presence
    async function heartbeat() {
      clearTimeout(s.beatTimer);
      if (closed) return;
      if (document.visibilityState === 'visible') {
        try {
          const { data } = await api.post('/notepads/' + id + '/presence', { client_id: s.tab });
          if (closed) return;
          paintPresence(data.users);
          if (s.server && data.version > s.server.version) refreshRemote();
        } catch (e) {
          if (e.status === 404) { gone('This notepad was deleted or is no longer shared with you.'); return; }
        }
      }
      if (!closed) s.beatTimer = setTimeout(heartbeat, HEARTBEAT_MS);
    }
    function leave() { api.del('/notepads/' + id + '/presence', { client_id: s.tab }).catch(() => {}); }

    // ---- actions
    async function rename() {
      const v = await prompt({ title: 'Rename notepad', value: s.meta.title, confirmText: 'Rename', validate: (x) => (x.trim() ? '' : 'Give the notepad a title.') });
      if (v === null) return;
      try { const { data } = await api.patch('/notepads/' + id, { title: v.trim() }); s.meta = { ...s.meta, ...data }; paintMeta(); patchList(id, { title: data.title }); } catch (e) { toast(e.message, { type: 'err' }); }
    }
    async function setVisibility(v) {
      const ok = await confirm(v === 'private'
        ? { title: 'Make this notepad private?', message: 'Only you will be able to open it. Other people lose access straight away.', confirmText: 'Make private' }
        : { title: 'Share with your team?', message: 'Everyone in your workspace will be able to read and edit it.', confirmText: 'Share with team' });
      if (!ok) return;
      try { const { data } = await api.patch('/notepads/' + id, { visibility: v }); s.meta = { ...s.meta, ...data }; paintMeta(); listCache = null; loadList(); } catch (e) { toast(e.message, { type: 'err' }); }
    }
    async function remove() {
      if (!(await confirm({ title: 'Delete “' + s.meta.title + '”?', message: 'The notepad and its history are deleted for everyone. This cannot be undone.', confirmText: 'Delete', danger: true }))) return;
      try { await api.del('/notepads/' + id); clearDraft(); listCache = null; toast('Notepad deleted', { type: 'ok' }); router.go('/notepad'); } catch (e) { toast(e.message, { type: 'err' }); }
    }
    function download() {
      const blob = new Blob([ta.value], { type: 'text/plain;charset=utf-8' });
      const a = h('a', { href: URL.createObjectURL(blob), download: (s.meta.title.replace(/[\\/:*?"<>|]+/g, ' ').trim() || 'Notepad') + '.txt' });
      document.body.appendChild(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(a.href), 4000);
    }
    async function openHistory() {
      await saveNow();
      const listBox = h('div.np-revs', skeleton(4));
      const m = modal({ title: 'History', content: h('div.stack', h('p.small.text2', { text: 'Saves are grouped per person and per 10 minutes. The last 50 are kept.' }), listBox), actions: [{ label: 'Close', kind: 'ghost' }], size: 'lg' });
      try {
        const { data } = await api.get('/notepads/' + id + '/revisions');
        clear(listBox);
        if (!data.length) { listBox.appendChild(emptyState({ icon: 'history', title: 'No history yet', text: 'Saved versions appear here.' })); return; }
        let day = '';
        data.forEach((r) => {
          const d = dayLabel(r.saved_at);
          if (d !== day) { listBox.appendChild(h('div.timeline-day', { text: d })); day = d; }
          listBox.appendChild(h('button.np-rev', { type: 'button', on: { click: () => preview(r, m) } },
            h('span.np-rev-time', { text: time(r.saved_at) }),
            h('span.np-rev-main', h('span', { text: r.user ? r.user.name : 'Imported' }),
              h('span.small.text2', { text: bytes(r.size) + (r.restored_from_version ? ' · restored from version ' + r.restored_from_version : '') })),
            r.current ? h('span.pill.ok', { text: 'Current' }) : icon('chevron-right', 16)));
        });
      } catch (e) { clear(listBox).appendChild(errorState(e, () => { m.close(); openHistory(); })); }
    }
    async function preview(r, parent) {
      try {
        const { data } = await api.get('/notepads/' + id + '/revisions/' + r.id);
        const pre = h('pre.np-preview', { text: data.content || '(empty)' });
        modal({ title: dateTime(r.saved_at) + (r.user ? ' · ' + r.user.name : ''), content: pre, size: 'lg', actions: r.current ? [{ label: 'Close', kind: 'ghost' }] : [
          { label: 'Close', kind: 'ghost' },
          { label: 'Restore this version', kind: 'primary', onClick: async () => {
            if (!(await confirm({ title: 'Restore this version?', message: 'The notepad goes back to this text for everyone. The current text stays in the history.', confirmText: 'Restore' }))) return false;
            try {
              await saveNow();
              const { data: d } = await api.post('/notepads/' + id + '/revisions/' + r.id + '/restore', { client_id: s.tab });
              s.server = { version: d.version, text: d.content };
              s.meta = { ...s.meta, ...d };
              replaceText(d.content);
              clearDraft();
              savedStatus();
              parent.close();
              toast('Version restored', { type: 'ok' });
            } catch (e) { toast(e.message, { type: 'err' }); return false; }
            return true;
          } },
        ] });
      } catch (e) { toast(e.message, { type: 'err' }); }
    }

    function gone(message) {
      if (closed) return;
      closed = true;
      clearTimers();
      clearTimeout(s.beatTimer);
      clearDraft();
      listCache = null;
      toast(message, { type: 'warn', timeout: 6000 });
      router.go('/notepad');
    }

    async function openNotepad() {
      editorPane.appendChild(h('div.np-loading', skeleton(6)));
      try {
        const { data } = await api.get('/notepads/' + id);
        if (closed) return;
        s.meta = data;
        s.server = { version: data.version, text: data.content };
        ta.value = data.content;
        renderEditor();
        paintPresence(data.present_users);
        savedStatus();
        const draft = readDraft();
        if (draft && draft.text !== data.content) {
          s.engine = await loadEngine();
          const base = draft.base ?? (draft.v === data.version ? data.content : '');
          const r = merge3(s.engine, base, draft.text, data.content);
          replaceText(r.text);
          if (r.text !== data.content) { toast('Restored the changes you made while offline.', { type: 'ok' }); saveNow(); }
          else clearDraft();
        } else if (draft) clearDraft();
        if (wide()) ta.focus({ preventScroll: true });
        heartbeat();
      } catch (e) {
        if (closed) return;
        clear(editorPane).appendChild(e.status === 404
          ? emptyState({ icon: 'edit', title: 'Notepad not found', text: 'It may have been deleted or made private.', action: { label: 'All notepads', onClick: () => router.go('/notepad') } })
          : errorState(e, () => { clear(editorPane); openNotepad(); }));
      }
    }

    // ------------------------------------------------------------------ live events & lifecycle
    const onVisible = () => { if (document.visibilityState === 'visible') heartbeat(); else { saveNow(); writeDraft(); } };
    const onOnline = () => { if (s.server && ta.value !== s.server.text) saveNow(); else refreshRemote(); };
    const onPageHide = () => writeDraft();
    document.addEventListener('visibilitychange', onVisible);
    window.addEventListener('online', onOnline);
    window.addEventListener('pagehide', onPageHide);
    offs = [
      () => document.removeEventListener('visibilitychange', onVisible),
      () => window.removeEventListener('online', onOnline),
      () => window.removeEventListener('pagehide', onPageHide),
      bus.on('notepad.updated', (e) => {
        const d = e?.data || {};
        patchList(Number(d.notepad_id), { updated_at: d.updated_at, updated_by: d.by ? { id: d.by.id, name: d.by.name } : null, size: d.size });
        if (id && Number(d.notepad_id) === id && d.client_id !== s.tab && s.server && Number(d.version) > s.server.version) refreshRemote();
      }),
      bus.on('notepad.presence', (e) => {
        const d = e?.data || {};
        patchList(Number(d.notepad_id), { present: (d.users || []).length });
        if (id && Number(d.notepad_id) === id) paintPresence(d.users);
      }),
      bus.on('notepad.created', reloadList),
      bus.on('notepad.renamed', (e) => {
        const n = e?.data?.notepad;
        reloadList();
        if (n && id && Number(n.id) === id && s.meta) { s.meta = { ...s.meta, title: n.title, visibility: n.visibility }; paintMeta(); }
      }),
      bus.on('notepad.deleted', (e) => {
        reloadList();
        if (id && Number(e?.data?.notepad_id) === id) gone('This notepad was deleted or made private by its owner.');
      }),
      bus.on('sync.reset', () => { reloadList(); refreshRemote(); }),
    ];

    if (listCache) renderList();
    loadList();
    if (id) openNotepad();
    else if (!wide()) editorPane.hidden = true;

    s.close = () => {
      if (closed) return;
      closed = true;
      clearTimeout(s.beatTimer);
      if (s.server && ta.value !== s.server.text) { writeDraft(); saveNow(); } // finishes in the background
      if (s.server) leave();
    };
  },
  unmount() {
    session?.close?.();
    session = null;
    offs.forEach((o) => o());
    offs = [];
  },
};
