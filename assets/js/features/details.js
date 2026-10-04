/**
 * File details panel (§12.4): a right-hand drawer on desktop, a full-height sheet on phones.
 * Tabs: Info (metadata, description, tags, "Keep forever"), Activity, Comments, Versions,
 * Sharing. Tabs and controls follow the file's capabilities (file.access); the open tab
 * refreshes live on file.*, version.*, comment.* and share.* events for the file.
 * @module features/details
 */
import { api } from '../core/api.js';
import { bus } from '../core/bus.js';
import { store } from '../core/store.js';
import { h, icon, clear, debounce } from '../core/dom.js';
import { toast, confirm, emptyState, errorState, skeleton, copyText } from '../core/ui.js';
import { bytes, dateTime, dayLabel, time, relative, countdown } from '../core/format.js';
import { kindIconName } from '../core/icons.js';
import { realtime } from '../core/realtime.js';

const TABS = [
  ['info', 'Info'],
  ['activity', 'Activity'],
  ['comments', 'Comments'],
  ['versions', 'Versions'],
  ['sharing', 'Sharing'],
];
const PERM = { viewer: 'Viewer', downloader: 'Downloader', commenter: 'Commenter', editor: 'Editor' };
const STATUS = { active: 'ok', expired: 'warn', exhausted: 'warn', revoked: 'bad' };

let panel = null;

/**
 * Open (or switch) the details panel.
 * @param {number|string} fileId
 * @param {'info'|'activity'|'comments'|'versions'|'sharing'} [tab]
 */
export function openDetails(fileId, tab = 'info') {
  if (!panel) panel = createPanel();
  panel.show(Number(fileId), tab);
  return panel;
}

export function closeDetails() { if (panel) panel.close(); }

function createPanel() {
  const me = () => store.get('user') || {};
  let id = 0;
  let file = null;
  let tab = 'info';
  let seq = 0;
  let isOpen = false;
  let prevFocus = null;
  let offs = [];
  let timer = null;
  let gone = false;

  const titleId = 'dp-title';
  const thumb = h('div.dp-thumb');
  const title = h('h2.dp-title', { id: titleId, text: 'Details' });
  const sub = h('div.dp-sub');
  const closeBtn = h('button.icon-btn', { type: 'button', 'aria-label': 'Close details', title: 'Close', on: { click: () => close() } }, icon('x', 18));
  const actions = h('div.dp-actions');
  const tabsEl = h('div.dp-tabs', { role: 'tablist', 'aria-label': 'File details' });
  const body = h('div.dp-body', { role: 'tabpanel', tabIndex: -1 });
  const notice = h('div.dp-notice', { role: 'status', hidden: true });
  const el = h('aside.dp', { role: 'dialog', 'aria-labelledby': titleId, 'aria-modal': 'false', tabIndex: -1 },
    h('div.dp-head', thumb, h('div.dp-head-text', title, sub), closeBtn),
    actions, notice, tabsEl, body);
  const scrim = h('div.dp-scrim', { on: { click: () => close() } });

  el.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !document.querySelector('.modal-overlay, .menu')) { e.preventDefault(); close(); }
  });
  tabsEl.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const btns = Array.from(tabsEl.querySelectorAll('[role=tab]'));
    const i = btns.indexOf(document.activeElement);
    if (i < 0) return;
    e.preventDefault();
    const b = btns[(i + (e.key === 'ArrowRight' ? 1 : -1) + btns.length) % btns.length];
    b.focus(); b.click();
  });

  // ---------------------------------------------------------------- capabilities
  const caps = () => (file && file.access) || {};
  const can = (k) => !!caps()[k];
  const perm = (p) => (me().permissions || []).includes(p);
  const tabAllowed = (t) => {
    if (!file) return t === 'info';
    if (t === 'activity') return can('activity');
    if (t === 'versions') return can('versions');
    if (t === 'sharing') return can('manage') || can('share');
    return true;
  };

  // ---------------------------------------------------------------- open / close
  async function show(fileId, wantTab) {
    const switching = fileId !== id;
    if (!isOpen) {
      prevFocus = document.activeElement;
      // A side panel next to the list on desktop; a modal full-height sheet on phones.
      el.setAttribute('aria-modal', window.matchMedia('(max-width: 599px)').matches ? 'true' : 'false');
      document.body.append(scrim, el);
      isOpen = true;
      document.body.classList.add('dp-open');
      subscribe();
      requestAnimationFrame(() => el.classList.add('in'));
    }
    if (switching) {
      id = fileId;
      file = null;
      gone = false;
      notice.hidden = true;
      title.textContent = 'Loading…';
      sub.textContent = '';
      clear(thumb).appendChild(icon('file', 26));
      clear(actions);
      clear(tabsEl);
      clear(body).appendChild(skeleton(4));
    }
    tab = wantTab || 'info';
    setTimeout(() => closeBtn.focus(), 30);
    if (switching || !file) await loadFile();
    else selectTab(tab);
  }

  function close() {
    if (!isOpen) return;
    isOpen = false;
    offs.forEach((off) => off());
    offs = [];
    clearInterval(timer);
    el.classList.remove('in');
    document.body.classList.remove('dp-open');
    const done = () => { el.remove(); scrim.remove(); };
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) done(); else setTimeout(done, 200);
    id = 0;
    file = null;
    if (prevFocus && prevFocus.isConnected && prevFocus.focus) prevFocus.focus();
  }

  async function loadFile({ quiet = false } = {}) {
    const my = ++seq;
    const fid = id;
    try {
      const { data } = await api.get('/files/' + fid);
      if (my !== seq || fid !== id || !isOpen) return;
      file = data;
      if (file.trash) { notice.textContent = 'This file is in the Trash.'; notice.hidden = false; } else if (!gone) notice.hidden = true;
      const allowed = tabAllowed(tab);
      if (!allowed) tab = 'info';
      paintHead();
      paintTabs();
      // Other tabs refresh from their own events; a quiet reload only repaints Info.
      if (!quiet || !allowed) selectTab(tab);
      else if (tab === 'info') paintInfo();
    } catch (e) {
      if (my !== seq || fid !== id) return;
      if (quiet && file) { if (e.code === 'FILE_NOT_FOUND') markGone('This file is no longer available.'); return; }
      title.textContent = 'Details';
      clear(body).appendChild(errorState(e.code === 'FILE_NOT_FOUND' ? { message: 'This file is no longer available to you.' } : e, e.code === 'FILE_NOT_FOUND' ? null : () => loadFile()));
    }
  }
  const reloadFile = debounce(() => { if (isOpen && id) loadFile({ quiet: true }); }, 350);

  function markGone(text) {
    gone = true;
    notice.textContent = text;
    notice.hidden = false;
    clear(actions);
  }

  // ---------------------------------------------------------------- header
  function paintHead() {
    title.textContent = file.name;
    title.title = file.name;
    const kind = file.kind || 'other';
    sub.textContent = [(file.ext || kind).toUpperCase(), bytes(file.size), file.owner && file.owner.id !== me().id ? 'Owned by ' + (file.owner.display_name || file.owner.username) : null].filter(Boolean).join(' · ');
    clear(thumb);
    if (file.has_thumbnail && !file.trash) {
      const img = h('img', { alt: '', src: api.url('/files/' + file.id + '/thumbnail', { v: file.version || 1 }) });
      img.addEventListener('error', () => img.replaceWith(icon(kindIconName(kind), 26)));
      thumb.appendChild(img);
    } else thumb.appendChild(icon(kindIconName(kind), 26));
    clear(actions);
    if (gone || file.trash) return;
    const act = (ic, label, fn, extra = {}) => h('button.btn.btn-sm', { type: 'button', title: label, on: { click: fn }, ...extra }, icon(ic, 15), h('span.dp-act-label', { text: label }));
    if (can('preview')) actions.appendChild(act('eye', 'Preview', () => import('./preview.js').then((m) => m.openPreview(file))));
    if (['text', 'code'].includes(file.kind) && can('edit') && (Number(file.size) || 0) <= 2097152) actions.appendChild(act('edit', 'Edit', () => import('./editor.js').then((m) => m.openEditor(file))));
    if (can('download')) actions.appendChild(h('a.btn.btn-sm', { href: api.url('/files/' + file.id + '/download'), download: '', title: 'Download' }, icon('download', 15), h('span.dp-act-label', { text: 'Download' })));
    if (can('share')) actions.appendChild(act('share', 'Share', openShare));
    const fav = act('star', file.favorite ? 'Favourite' : 'Add to favourites', toggleFavourite, { 'aria-pressed': file.favorite ? 'true' : 'false' });
    fav.classList.toggle('dp-fav-on', !!file.favorite);
    actions.appendChild(fav);
  }

  async function toggleFavourite() {
    try {
      const { data } = await api.patch('/files/' + id, { favorite: !file.favorite });
      file = { ...file, ...data, access: data.access || file.access };
      paintHead();
      toast(file.favorite ? '★ Added to favourites' : 'Removed from favourites', { type: 'ok', timeout: 1800 });
      realtime.nudge();
    } catch (e) { toast(e.message, { type: 'err' }); }
  }

  function openShare() {
    import('./share-dialog.js').then((m) => m.openShareDialog({ files: [file] })).catch((e) => toast(e.message, { type: 'err' }));
  }

  // ---------------------------------------------------------------- tabs
  function paintTabs() {
    clear(tabsEl);
    TABS.filter(([t]) => tabAllowed(t)).forEach(([t, label]) => {
      const count = t === 'comments' && file.comment_count ? h('span.dp-count', { text: String(file.comment_count) }) : null;
      tabsEl.appendChild(h('button.dp-tab', {
        type: 'button', role: 'tab', id: 'dp-tab-' + t, dataset: { tab: t },
        'aria-selected': t === tab ? 'true' : 'false', tabIndex: t === tab ? 0 : -1,
        on: { click: () => selectTab(t) },
      }, h('span', { text: label }), count));
    });
  }

  function selectTab(t) {
    if (!tabAllowed(t)) t = 'info';
    tab = t;
    tabsEl.querySelectorAll('[role=tab]').forEach((b) => {
      const on = b.dataset.tab === t;
      b.setAttribute('aria-selected', on ? 'true' : 'false');
      b.tabIndex = on ? 0 : -1;
      if (on) body.setAttribute('aria-labelledby', b.id);
    });
    clearInterval(timer);
    clear(body);
    body.scrollTop = 0;
    if (!file) return;
    ({ info: renderInfo, activity: renderActivity, comments: renderComments, versions: renderVersions, sharing: renderSharing })[t]();
  }

  // ---------------------------------------------------------------- Info
  let info = null;
  function renderInfo() {
    const rows = h('dl.dp-meta');
    const descWrap = h('div.dp-section');
    const tagsWrap = h('div.dp-section');
    const keepWrap = h('div.dp-section');
    const preview = h('div.dp-preview');
    body.append(preview, rows, keepWrap, tagsWrap, descWrap);
    info = { rows, descWrap, tagsWrap, keepWrap, preview, desc: null, tagInput: null };
    if (file.has_thumbnail && !file.trash && ['image', 'video', 'pdf'].includes(file.kind)) {
      const img = h('img', { alt: 'Thumbnail of ' + file.name, loading: 'lazy', src: api.url('/files/' + file.id + '/thumbnail', { v: file.version || 1 }) });
      img.addEventListener('error', () => preview.remove());
      if (can('preview')) {
        preview.appendChild(h('button.dp-preview-btn', { type: 'button', 'aria-label': 'Preview ' + file.name, on: { click: () => import('./preview.js').then((m) => m.openPreview(file)) } }, img));
      } else preview.appendChild(img);
    } else preview.remove();
    paintInfo();
    timer = setInterval(() => { if (tab === 'info' && info) paintKeep(); }, 30000);
  }

  function paintInfo() {
    if (!info || tab !== 'info') return;
    const f = file;
    const row = (k, v, node) => (v === null || v === undefined || v === '' ? null : [h('dt', { text: k }), h('dd', node || { text: String(v) })]);
    const folderLink = () => {
      const isOwn = f.owner && f.owner.id === me().id;
      const path = f.path || '/';
      if (!isOwn) return h('span', { text: path });
      return h('a', { href: '#/files' + (f.folder_id ? '/' + f.folder_id : ''), text: path === '/' ? 'My Files' : 'My Files' + path, on: { click: () => { if (window.matchMedia('(max-width: 599px)').matches) close(); } } });
    };
    clear(info.rows).append(...[
      row('Type', ((f.ext || '').toUpperCase() || 'File') + (f.mime ? ' · ' + f.mime : '')),
      row('Size', bytes(f.size)),
      row('Location', f.trash ? null : (f.path ?? '/'), f.trash ? null : folderLink()),
      row('Owner', f.owner ? (f.owner.display_name || f.owner.username) + (f.owner.id === me().id ? ' (you)' : '') : null),
      row('Your access', f.access && f.access.role ? ({ owner: 'Owner', admin: 'Administrator', editor: 'Editor', commenter: 'Commenter', downloader: 'Downloader', viewer: 'Viewer' })[f.access.role] || f.access.role : null),
      row('Uploaded', dateTime(f.created_at)),
      row('Modified', dateTime(f.updated_at)),
      row('Version', f.version ? 'Version ' + f.version + (f.versions_count > 1 ? ' (' + f.versions_count + ' in history)' : '') : null),
      row('Downloads', String(f.download_count ?? 0)),
      row('Shared', f.is_shared ? 'Yes' : 'No'),
      row('Encrypted', f.encrypted ? 'Yes, at rest' : 'No'),
    ].filter(Boolean).flat());
    paintKeep();
    paintTags();
    paintDescription();
  }

  function paintKeep() {
    const w = info && info.keepWrap;
    if (!w) return;
    clear(w);
    const f = file;
    const left = !f.is_permanent && f.expires_at ? countdown(f.expires_at) : null;
    const text = f.is_permanent ? 'Kept until you delete it.' : left ? (left === 'Expired' ? 'Expired — moving to the Trash soon.' : 'Moves to the Trash in ' + left + ' (' + dateTime(f.expires_at) + ').') : 'Kept until you delete it.';
    if (can('edit') && !f.trash && !gone) {
      const input = h('input', { type: 'checkbox', checked: !!f.is_permanent });
      input.addEventListener('change', async () => {
        input.disabled = true;
        try {
          const { data } = await api.patch('/files/' + id, { is_permanent: input.checked });
          file = { ...file, ...data, access: data.access || file.access };
          toast(input.checked ? 'This file will be kept forever' : 'This file will be deleted automatically', { type: 'ok', timeout: 2200 });
          realtime.nudge();
        } catch (e) { input.checked = !input.checked; toast(e.message, { type: 'err' }); }
        input.disabled = false;
        paintKeep();
      });
      w.append(h('label.toggle.dp-keep', input, h('span.track'), h('span', { text: 'Keep forever' })), h('div.hint' + (left && !f.is_permanent ? '.days-left' : ''), { text: text }));
    } else {
      w.append(h('div.label', { text: 'Retention' }), h('div' + (left && !f.is_permanent ? '.days-left' : ''), { text: text }));
    }
  }

  function paintTags() {
    const w = info && info.tagsWrap;
    if (!w) return;
    const editable = can('edit') && !file.trash && !gone;
    const focused = info.tagInput && document.activeElement === info.tagInput;
    const typed = info.tagInput ? info.tagInput.value : '';
    clear(w);
    const tags = file.tags || [];
    const chips = h('div.row.wrap.dp-tags', ...tags.map((t) => h('span.tag', t,
      editable ? h('button.dp-tag-x', { type: 'button', 'aria-label': 'Remove tag ' + t, on: { click: () => saveTags(tags.filter((x) => x !== t)) } }, icon('x', 11)) : null)));
    if (!tags.length) chips.appendChild(h('span.muted.small', { text: editable ? 'No tags yet.' : 'No tags.' }));
    w.append(h('div.label', { text: 'Tags' }), chips);
    if (editable) {
      const listId = 'dp-tag-list';
      const input = h('input.input', { type: 'text', placeholder: 'Add a tag and press Enter', maxlength: 50, 'aria-label': 'Add a tag', list: listId, enterkeyhint: 'done', autocomplete: 'off' });
      input.value = typed;
      const dl = h('datalist', { id: listId });
      input.addEventListener('focus', () => loadTagSuggestions(dl), { once: true });
      input.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ',') {
          e.preventDefault();
          const v = input.value.trim().replace(/,+$/, '');
          if (!v) return;
          if (tags.some((t) => t.toLowerCase() === v.toLowerCase())) { input.value = ''; return; }
          input.value = '';
          saveTags([...tags, v], true);
        } else if (e.key === 'Backspace' && !input.value && tags.length) {
          saveTags(tags.slice(0, -1), true);
        }
      });
      info.tagInput = input;
      w.append(input, dl);
      if (focused) setTimeout(() => input.focus(), 0);
    }
  }

  async function loadTagSuggestions(dl) {
    try {
      const { data } = await api.get('/tags');
      clear(dl).append(...(data || []).slice(0, 200).map((t) => h('option', { value: t.name || t })));
    } catch { /* suggestions are optional */ }
  }

  async function saveTags(tags, refocus = false) {
    try {
      const { data } = await api.patch('/files/' + id, { tags });
      file = { ...file, ...data, access: data.access || file.access };
      paintTags();
      if (refocus && info.tagInput) info.tagInput.focus();
      realtime.nudge();
    } catch (e) { toast(e.message, { type: 'err' }); }
  }

  function paintDescription() {
    const w = info && info.descWrap;
    if (!w) return;
    const editable = can('edit') && !file.trash && !gone;
    if (info.desc && editable && (document.activeElement === info.desc || info.desc.value !== (info.descSaved ?? ''))) return; // keep unsaved typing
    clear(w);
    w.append(h('div.label', { text: 'Description' }));
    if (!editable) {
      w.append(h('p.dp-desc', { text: file.description || 'No description.', class: file.description ? '' : 'muted' }));
      info.desc = null;
      return;
    }
    const ta = h('textarea.textarea.dp-desc-input', { maxlength: 1000, placeholder: 'Add a description…', 'aria-label': 'Description', rows: 3 });
    ta.value = file.description || '';
    info.descSaved = ta.value;
    const saveBtn = h('button.btn.btn-sm.btn-primary', { type: 'button', text: 'Save', hidden: true });
    const cancelBtn = h('button.btn.btn-sm.btn-ghost', { type: 'button', text: 'Cancel', hidden: true });
    const counter = h('span.hint', { text: '' });
    const sync = () => {
      const dirty = ta.value !== info.descSaved;
      saveBtn.hidden = cancelBtn.hidden = !dirty;
      counter.textContent = ta.value.length > 900 ? (1000 - ta.value.length) + ' characters left' : '';
    };
    ta.addEventListener('input', sync);
    ta.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); saveBtn.click(); } });
    cancelBtn.addEventListener('click', () => { ta.value = info.descSaved; sync(); });
    saveBtn.addEventListener('click', async () => {
      saveBtn.disabled = true;
      const value = ta.value.trim();
      try {
        const { data } = await api.patch('/files/' + id, { description: value === '' ? null : value });
        file = { ...file, ...data, access: data.access || file.access };
        info.descSaved = ta.value = file.description || '';
        toast('Description saved', { type: 'ok', timeout: 1800 });
        realtime.nudge();
      } catch (e) { toast(e.message, { type: 'err' }); }
      saveBtn.disabled = false;
      sync();
    });
    info.desc = ta;
    w.append(ta, h('div.row', counter, h('span.grow'), cancelBtn, saveBtn));
  }

  // ---------------------------------------------------------------- Activity
  async function renderActivity(quiet = false) {
    const fid = id;
    if (!quiet) body.appendChild(skeleton(5));
    let page = 1;
    const listEl = h('div.dp-timeline');
    const more = h('div.dp-more');
    let lastDay = '';
    const add = (items) => {
      items.forEach((a) => {
        const day = dayLabel(a.created_at);
        if (day !== lastDay) { listEl.appendChild(h('div.timeline-day', { text: day })); lastDay = day; }
        listEl.appendChild(h('div.timeline-item', { title: dateTime(a.created_at) },
          h('span.timeline-time', { text: time(a.created_at) }), h('span.grow', { text: a.text })));
      });
    };
    const loadPage = async () => {
      const { data, meta } = await api.get('/files/' + fid + '/activity', { page, per_page: 50 });
      if (fid !== id || tab !== 'activity') return false;
      add(data || []);
      clear(more);
      if (meta && meta.has_more) {
        more.appendChild(h('button.btn.btn-sm', { type: 'button', text: 'Show older activity', on: { click: async (e) => { e.currentTarget.disabled = true; page++; try { await loadPage(); } catch (err) { toast(err.message, { type: 'err' }); } } } }));
      }
      return true;
    };
    try {
      const ok = await loadPage();
      if (!ok) return;
      clear(body);
      if (!listEl.children.length) body.appendChild(emptyState({ icon: 'activity', title: 'No activity yet', text: 'Uploads, downloads, shares and changes to this file appear here.' }));
      else body.append(listEl, more);
    } catch (e) {
      if (fid !== id || tab !== 'activity') return;
      clear(body).appendChild(errorState(e, () => { clear(body); renderActivity(); }));
    }
  }
  const refreshActivity = debounce(() => { if (isOpen && tab === 'activity') renderActivity(true); }, 900);

  // ---------------------------------------------------------------- Comments
  let comments = null;
  async function renderComments() {
    const fid = id;
    const listEl = h('div.dp-comments', { role: 'log', 'aria-label': 'Comments', 'aria-live': 'polite' });
    const canPost = can('comment') && perm('files.comment') && !file.trash && !gone;
    const ta = h('textarea.textarea.dp-composer-input', { rows: 2, maxlength: 5000, placeholder: 'Write a comment…', 'aria-label': 'Write a comment' });
    const send = h('button.btn.btn-primary.btn-sm', { type: 'button', 'aria-label': 'Post comment', title: 'Post (Ctrl+Enter)', disabled: true }, icon('send', 15), h('span.dp-act-label', { text: 'Post' }));
    const composer = canPost ? h('div.dp-composer', ta, send) : h('div.dp-composer.muted.small', { text: can('comment') ? 'You cannot post comments.' : 'You can read comments but not add them.' });
    comments = { listEl, ids: new Set() };
    body.append(listEl, composer);
    listEl.appendChild(skeleton(3));
    ta.addEventListener('input', () => { send.disabled = !ta.value.trim(); ta.style.height = 'auto'; ta.style.height = Math.min(200, ta.scrollHeight + 2) + 'px'; });
    ta.addEventListener('keydown', (e) => { if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) { e.preventDefault(); post(); } });
    send.addEventListener('click', post);
    async function post() {
      const text = ta.value.trim();
      if (!text) return;
      send.disabled = true;
      try {
        const { data } = await api.post('/files/' + fid + '/comments', { body: text });
        ta.value = '';
        ta.style.height = '';
        if (data && !comments.ids.has(data.id)) bumpCount(1);
        addComment(data, true);
        realtime.nudge();
      } catch (e) { toast(e.message, { type: 'err' }); send.disabled = false; }
    }
    try {
      const { data } = await api.get('/files/' + fid + '/comments');
      if (fid !== id || tab !== 'comments') return;
      clear(listEl);
      (data || []).forEach((c) => addComment(c, false));
      paintEmptyComments();
      listEl.scrollTop = listEl.scrollHeight;
      body.scrollTop = body.scrollHeight;
    } catch (e) {
      if (fid !== id || tab !== 'comments') return;
      clear(listEl).appendChild(errorState(e, () => { clear(body); renderComments(); }));
    }
  }

  function paintEmptyComments() {
    if (!comments) return;
    const empty = comments.listEl.querySelector('.empty-state');
    if (comments.ids.size && empty) empty.remove();
    if (!comments.ids.size && !empty) comments.listEl.appendChild(emptyState({ icon: 'comment', title: 'No comments yet', text: can('comment') ? 'Start the conversation about this file.' : 'Nobody has commented on this file.' }));
  }

  function addComment(c, scroll) {
    if (!comments || !c || comments.ids.has(c.id)) return;
    comments.ids.add(c.id);
    const mine = c.author && c.author.id === me().id;
    const canDelete = c.can_delete ?? (mine || ['owner', 'admin'].includes(caps().role));
    const name = c.author ? (c.author.display_name || c.author.username) : (c.author_name || 'Someone');
    const item = h('div.dp-comment' + (mine ? '.mine' : ''), { dataset: { id: String(c.id) } },
      h('span.avatar.sm', { 'aria-hidden': 'true', text: name.slice(0, 1).toUpperCase() }),
      h('div.grow',
        h('div.dp-comment-head', h('strong', { text: name }), c.via_link ? h('span.pill', { text: 'via link' }) : null,
          h('time.small.muted', { datetime: c.created_at, title: dateTime(c.created_at), text: relative(c.created_at) }),
          canDelete ? h('button.icon-btn.sm.dp-comment-del', { type: 'button', 'aria-label': 'Delete comment by ' + name, title: 'Delete', on: { click: () => deleteComment(c) } }, icon('trash', 14)) : null),
        h('div.dp-comment-body', { text: c.body })));
    comments.listEl.appendChild(item);
    paintEmptyComments();
    if (scroll) item.scrollIntoView({ block: 'nearest' });
  }

  function removeComment(cid) {
    if (!comments) return;
    comments.ids.delete(cid);
    comments.listEl.querySelector('[data-id="' + cid + '"]')?.remove();
    paintEmptyComments();
  }

  async function deleteComment(c) {
    if (!(await confirm({ title: 'Delete this comment?', message: 'It will be removed for everyone.', confirmText: 'Delete', danger: true }))) return;
    try { await api.del('/comments/' + c.id); removeComment(c.id); bumpCount(-1); realtime.nudge(); } catch (e) { toast(e.message, { type: 'err' }); }
  }

  function bumpCount(d) {
    if (!file) return;
    file.comment_count = Math.max(0, (file.comment_count || 0) + d);
    const b = tabsEl.querySelector('[data-tab=comments]');
    if (!b) return;
    b.querySelector('.dp-count')?.remove();
    if (file.comment_count) b.appendChild(h('span.dp-count', { text: String(file.comment_count) }));
  }

  // ---------------------------------------------------------------- Versions
  async function renderVersions(quiet = false) {
    const fid = id;
    if (!quiet) body.appendChild(skeleton(4));
    try {
      const { data } = await api.get('/files/' + fid + '/versions');
      if (fid !== id || tab !== 'versions') return;
      clear(body);
      if (can('edit') && !file.trash && !gone) {
        const input = h('input', { type: 'file', hidden: true });
        input.addEventListener('change', async () => {
          const f = input.files && input.files[0];
          if (!f) return;
          try {
            const m = await import('./uploader.js');
            m.uploader.add([f], { fileId: fid });
            toast('Uploading a new version of “' + file.name + '”…', { type: 'info' });
          } catch (e) { toast(e.message, { type: 'err' }); }
          input.value = '';
        });
        body.append(h('div.dp-section.row.wrap', h('button.btn.btn-sm.btn-primary', { type: 'button', on: { click: () => input.click() } }, icon('upload', 15), 'Upload new version'),
          h('span.hint', { text: 'Older versions stay available to download or restore.' }), input));
      }
      const list = h('div.list.dp-versions');
      (data || []).forEach((v) => {
        const by = v.created_by ? (v.created_by.display_name || v.created_by.username) : null;
        list.appendChild(h('div.list-item',
          h('div.dp-ver', { text: 'v' + v.version }),
          h('div.li-main',
            h('div.li-title.row.wrap', h('span', { text: 'Version ' + v.version }), v.current ? h('span.pill.ok', { text: 'Current' }) : null),
            h('div.li-sub', { text: [bytes(v.size), by ? 'by ' + by : null, dateTime(v.created_at)].filter(Boolean).join(' · ') }),
            v.note || (v.name && v.name !== file.name) ? h('div.li-sub', { text: [v.note, v.name !== file.name ? '“' + v.name + '”' : null].filter(Boolean).join(' · ') }) : null),
          h('div.dp-ver-actions',
            can('download') ? h('a.btn.btn-sm', { href: api.url('/files/' + fid + '/versions/' + v.version + '/download'), download: '', 'aria-label': 'Download version ' + v.version, title: 'Download' }, icon('download', 14)) : null,
            can('edit') && !v.current && !file.trash && !gone ? h('button.btn.btn-sm', { type: 'button', title: 'Make this the current version', on: { click: () => restoreVersion(v) } }, icon('restore', 14), h('span.dp-act-label', { text: 'Restore' })) : null)));
      });
      if (!list.children.length) body.appendChild(emptyState({ icon: 'history', title: 'No versions', text: 'Earlier versions appear here when the file changes.' }));
      else body.appendChild(list);
    } catch (e) {
      if (fid !== id || tab !== 'versions') return;
      clear(body).appendChild(errorState(e, () => { clear(body); renderVersions(); }));
    }
  }

  async function restoreVersion(v) {
    if (!(await confirm({ title: 'Restore version ' + v.version + '?', message: 'It becomes a new current version. The current content stays in the history, so nothing is lost.', confirmText: 'Restore' }))) return;
    try {
      const { data } = await api.post('/files/' + id + '/versions/' + v.version + '/restore');
      if (data) file = { ...file, ...data, access: data.access || file.access };
      toast('Version ' + v.version + ' restored', { type: 'ok' });
      realtime.nudge();
      paintHead();
      if (tab === 'versions') renderVersions(true);
    } catch (e) { toast(e.message, { type: 'err' }); }
  }

  // ---------------------------------------------------------------- Sharing
  async function renderSharing(quiet = false) {
    const fid = id;
    const top = h('div.dp-section');
    if (can('share') && !file.trash && !gone) {
      top.append(h('button.btn.btn-primary.btn-sm', { type: 'button', on: { click: openShare } }, icon('share', 15), 'Share…'),
        h('p.hint', { text: 'Create a link or share with people, with expiry, password and download limits.' }));
    }
    if (!can('manage')) {
      clear(body).append(top, h('p.text2.small', { text: 'Only the owner can see everyone this file is shared with.' }));
      return;
    }
    if (!quiet) body.append(top, skeleton(3));
    try {
      const { data } = await api.get('/files/' + fid + '/shares', { status: 'all' });
      if (fid !== id || tab !== 'sharing') return;
      clear(body).append(top);
      const all = data || [];
      if (!all.length) { body.appendChild(emptyState({ icon: 'share', title: 'Not shared yet', text: 'Links and people you share this file with appear here.' })); return; }
      const order = { active: 0, exhausted: 1, expired: 2, revoked: 3 };
      all.sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9));
      body.appendChild(h('div.list.dp-shares', ...all.map((s) => {
        const who = s.kind === 'link' ? (s.has_password ? 'Anyone with the link and password' : 'Anyone with the link') : (s.recipient ? (s.recipient.display_name || s.recipient.username) : 'A person');
        const bits = [PERM[s.permission] || s.permission, s.expires_at ? (s.status === 'expired' ? 'expired ' : 'expires ') + dateTime(s.expires_at) : 'no expiry', (s.download_count || 0) + (s.max_downloads ? ' / ' + s.max_downloads : '') + ' downloads'];
        if (s.target_type && s.target_type !== 'file') bits.push(s.target_type === 'bundle' ? 'part of a bundle' : 'via folder');
        return h('div.list-item',
          icon(s.kind === 'link' ? 'link' : 'user', 17),
          h('div.li-main', h('div.li-title.row.wrap', h('span', { text: who }), h('span.pill.' + (STATUS[s.status] || 'info'), { text: s.status })),
            h('div.li-sub', { text: bits.join(' · ') })),
          h('div.dp-ver-actions',
            s.url && s.status === 'active' ? h('button.btn.btn-sm', { type: 'button', 'aria-label': 'Copy link', title: 'Copy link', on: { click: async () => { if (await copyText(s.url)) toast('Link copied', { type: 'ok' }); } } }, icon('copy', 14)) : null,
            s.url && s.status === 'active' ? h('button.btn.btn-sm', { type: 'button', 'aria-label': 'Show QR code', title: 'QR code', on: { click: () => import('./share-dialog.js').then((m) => m.showQr(s.url)) } }, icon('qr', 14)) : null,
            s.status === 'active' || s.status === 'exhausted' ? h('button.btn.btn-sm.btn-danger', { type: 'button', 'aria-label': 'Stop sharing with ' + who, title: 'Revoke', on: { click: () => revoke(s, who) } }, icon('x', 14)) : null));
      })));
    } catch (e) {
      if (fid !== id || tab !== 'sharing') return;
      clear(body).append(top, errorState(e, () => { clear(body); renderSharing(); }));
    }
  }

  async function revoke(s, who) {
    if (!(await confirm({ title: 'Stop sharing?', message: who + ' will lose access immediately.', confirmText: 'Revoke', danger: true }))) return;
    try { await api.del('/shares/' + s.id); toast('Share revoked', { type: 'ok' }); realtime.nudge(); renderSharing(true); } catch (e) { toast(e.message, { type: 'err' }); }
  }

  // ---------------------------------------------------------------- live updates
  function subscribe() {
    const fidOf = (e) => Number(e.file_id ?? e.data?.file_id ?? e.data?.file?.id ?? e.data?.comment?.file_id ?? 0);
    const forThis = (e) => isOpen && id && fidOf(e) === id;
    const shareForThis = (e) => isOpen && id && (fidOf(e) === id || (e.data?.share?.file_ids || []).includes(id) || e.data?.share?.file_id === id);
    const fileChanged = (e) => { if (!forThis(e)) return; reloadFile(); refreshActivity(); };
    offs = [
      bus.on('file.updated', fileChanged),
      bus.on('file.renamed', fileChanged),
      bus.on('file.moved', fileChanged),
      bus.on('file.restored', (e) => { if (forThis(e)) { gone = false; notice.hidden = true; reloadFile(); } }),
      bus.on('file.deleted', (e) => { if (forThis(e)) { markGone('This file was moved to the Trash.'); refreshActivity(); } }),
      bus.on('file.purged', (e) => { if (forThis(e)) markGone('This file was deleted permanently.'); }),
      bus.on('version.created', (e) => { if (!forThis(e)) return; reloadFile(); if (tab === 'versions') renderVersions(true); refreshActivity(); }),
      bus.on('version.restored', (e) => { if (!forThis(e)) return; reloadFile(); if (tab === 'versions') renderVersions(true); refreshActivity(); }),
      bus.on('comment.created', (e) => {
        if (!forThis(e)) return;
        const c = e.data?.comment;
        if (tab === 'comments' && comments) { if (c && !comments.ids.has(c.id)) { addComment(c, true); bumpCount(1); } } else bumpCount(1);
        refreshActivity();
      }),
      bus.on('comment.deleted', (e) => {
        if (!forThis(e)) return;
        const cid = Number(e.data?.comment_id);
        if (tab === 'comments' && comments) { if (comments.ids.has(cid)) { removeComment(cid); bumpCount(-1); } } else bumpCount(-1);
      }),
      ...['share.created', 'share.updated', 'share.revoked', 'share.expired'].map((t) => bus.on(t, (e) => { if (!shareForThis(e)) return; reloadFile(); if (tab === 'sharing') renderSharing(true); refreshActivity(); })),
      bus.on('upload.local.completed', ({ file: f }) => { if (f && Number(f.id) === id) { reloadFile(); if (tab === 'versions') renderVersions(true); } }),
      bus.on('sync.reset', () => { if (isOpen && id) loadFile({ quiet: true }); }),
      bus.on('route:changed', () => { if (isOpen && window.matchMedia('(max-width: 599px)').matches) close(); }),
      bus.on('auth:revoked', () => close()),
    ];
  }

  return { show, close, get fileId() { return id; } };
}
