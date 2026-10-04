/*
 * FastTransfer — public link page enhancements (/s/<token>).
 *
 * The page works without JavaScript (server-rendered, plain forms and links). This module only
 * improves it: theme toggle, local 24-hour times, in-page folder browsing, comments without a
 * reload (also on bundle/folder items), upload progress and an in-page preview dialog.
 *
 * Rules: untrusted data is only ever written with textContent / attributes (never innerHTML);
 * a JSON response without the X-FT-Api header means the host's browser check intercepted the
 * request (PHP never ran), so the visitor is asked to reload instead of seeing garbage.
 */

const dataEl = document.getElementById('ft-share-data');
const page = (() => {
  try {
    return JSON.parse(dataEl ? dataEl.textContent : '{}') || {};
  } catch (_) {
    return {};
  }
})();
const csrfMeta = document.querySelector('meta[name="csrf-token"]');
const csrf = csrfMeta ? csrfMeta.getAttribute('content') : '';

// ------------------------------------------------------------------ small helpers

const ICONS = {
  file: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z', 'M14 2v6h6'],
  folder: ['M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z'],
  download: ['M12 3v12', 'm7 10 5 5 5-5', 'M5 21h14'],
  eye: ['M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z', 'M12 9a3 3 0 1 0 0 6 3 3 0 1 0 0-6'],
  comment: ['M21 12a8 8 0 0 1-11.6 7.1L4 20l1.1-4.4A8 8 0 1 1 21 12z'],
  chevron: ['m9 6 6 6-6 6'],
};
const SVG_NS = 'http://www.w3.org/2000/svg';

function icon(name, size = 18) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', 'ic');
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  for (const d of ICONS[name] || ICONS.file) {
    const p = document.createElementNS(SVG_NS, 'path');
    p.setAttribute('d', d);
    svg.appendChild(p);
  }
  return svg;
}

/** h('a', {class: 'x', href: '…'}, child, 'text') — attributes are set, text goes in as text. */
function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === 'class') el.className = String(v);
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (k === 'text') el.textContent = String(v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return el;
}

const dateFmt = (() => {
  try {
    return new Intl.DateTimeFormat('en-GB', {
      day: '2-digit', month: 'short', year: 'numeric', hour: '2-digit', minute: '2-digit', hour12: false,
    });
  } catch (_) {
    return null;
  }
})();

function localTime(iso) {
  const d = new Date(iso);
  if (!dateFmt || Number.isNaN(d.getTime())) return null;
  return dateFmt.format(d);
}

function localiseTimes(root = document) {
  for (const t of root.querySelectorAll('time[data-local][datetime]')) {
    const s = localTime(t.getAttribute('datetime'));
    if (s) t.textContent = s;
  }
}

class PageError extends Error {
  constructor(message, code = 'ERROR', details = null) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

/** JSON request to this page's endpoints. Resolves to `data`, rejects with PageError. */
async function api(url, { method = 'GET', body = null, form = null } = {}) {
  const headers = { Accept: 'application/json' };
  let payload = null;
  if (body !== null) {
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(body);
  } else if (form !== null) {
    payload = form;
  }
  if (method !== 'GET' && csrf) headers['X-CSRF-Token'] = csrf;
  let res;
  try {
    res = await fetch(url, { method, headers, body: payload, credentials: 'same-origin', cache: 'no-store' });
  } catch (_) {
    throw new PageError('You appear to be offline. Check your connection and try again.', 'NETWORK');
  }
  if (!res.headers.get('X-FT-Api')) {
    throw new PageError('Your connection was interrupted. Please reload the page and try again.', 'HOST_CHALLENGE');
  }
  let json = null;
  try {
    json = await res.json();
  } catch (_) {
    json = null;
  }
  if (!res.ok || !json || json.success === false) {
    const err = (json && json.error) || {};
    const fields = err.details && err.details.fields ? Object.values(err.details.fields) : [];
    throw new PageError(fields[0] || err.message || 'Something went wrong. Please try again.', err.code || 'ERROR', err.details || null);
  }
  return json.data;
}

// ------------------------------------------------------------------ theme

function initTheme() {
  const btn = document.getElementById('theme-toggle');
  if (!btn) return;
  btn.addEventListener('click', () => {
    const root = document.documentElement;
    const next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    root.setAttribute('data-theme', next);
    try {
      localStorage.setItem('ft:theme', next);
    } catch (_) {
      /* private mode: the choice lasts for this page only */
    }
  });
}

// ------------------------------------------------------------------ comments

function commentItem(c) {
  const when = localTime(c.created_at) || '';
  return h('li', { class: 'comment' },
    h('div', { class: 'comment-head' },
      h('strong', { text: c.author_name || 'Someone' }),
      h('time', { datetime: c.created_at || '', text: when })),
    h('p', { class: 'comment-body', text: c.body || '' }));
}

function renderComments(list, comments) {
  list.replaceChildren();
  if (!comments.length) {
    list.appendChild(h('li', { class: 'comment-empty muted', text: 'No comments yet.' }));
    return;
  }
  for (const c of comments) list.appendChild(commentItem(c));
}

function bindCommentForm(form, list, fileId) {
  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const btn = form.querySelector('button[type="submit"]');
    const msg = form.querySelector('.form-msg');
    const name = form.elements.namedItem('name');
    const body = form.elements.namedItem('body');
    if (btn) btn.disabled = true;
    if (msg) msg.textContent = '';
    try {
      const c = await api(page.urls.comments, {
        method: 'POST',
        body: { file_id: fileId, name: name ? name.value : '', body: body ? body.value : '' },
      });
      const empty = list.querySelector('.comment-empty');
      if (empty) empty.remove();
      list.appendChild(commentItem(c));
      if (body) body.value = '';
      if (msg) msg.textContent = 'Comment added.';
    } catch (e) {
      if (msg) msg.textContent = e.message;
      else window.alert(e.message);
    } finally {
      if (btn) btn.disabled = false;
    }
  });
}

function initSingleFileComments() {
  const form = document.querySelector('form.js-comment');
  const list = document.querySelector('#comments .comment-list');
  if (!form || !list) return;
  const fileId = Number(list.dataset.fileId || 0);
  if (!form.querySelector('.form-msg')) {
    const foot = form.querySelector('.form-foot');
    if (foot) foot.prepend(h('span', { class: 'muted small form-msg', role: 'status' }));
  }
  bindCommentForm(form, list, fileId);
}

/** Bundle / folder rows: a "Comments" button opens a panel under the row. */
function initRowComments(root) {
  if (!page.can || !page.can.comment) return;
  const tpl = document.getElementById('tpl-comments');
  for (const btn of root.querySelectorAll('.js-comments')) {
    if (btn.dataset.bound) continue;
    btn.dataset.bound = '1';
    btn.hidden = false;
    btn.addEventListener('click', async () => {
      const row = btn.closest('.file-row');
      if (!row || !tpl) return;
      const open = row.querySelector('.comments-panel');
      if (open) {
        open.remove();
        btn.setAttribute('aria-expanded', 'false');
        return;
      }
      const panel = tpl.content.firstElementChild.cloneNode(true);
      row.appendChild(panel);
      btn.setAttribute('aria-expanded', 'true');
      const list = panel.querySelector('.comment-list');
      const fileId = Number(row.dataset.fileId || 0);
      list.appendChild(h('li', { class: 'comment-empty muted', text: 'Loading comments…' }));
      bindCommentForm(panel.querySelector('form'), list, fileId);
      try {
        const sep = page.urls.comments.includes('?') ? '&' : '?';
        renderComments(list, await api(page.urls.comments + sep + 'file=' + encodeURIComponent(String(fileId))));
      } catch (e) {
        list.replaceChildren(h('li', { class: 'comment-empty muted', text: e.message }));
      }
    });
  }
}

// ------------------------------------------------------------------ preview dialog

function initPreview(root) {
  const dialog = document.getElementById('preview-dialog');
  if (!dialog || typeof dialog.showModal !== 'function') return; // the link opens a new tab instead
  const body = dialog.querySelector('.dialog-body');
  const title = dialog.querySelector('.dialog-title');
  const close = dialog.querySelector('.js-close');
  if (!dialog.dataset.bound) {
    dialog.dataset.bound = '1';
    close.addEventListener('click', () => dialog.close());
    dialog.addEventListener('close', () => body.replaceChildren());
    dialog.addEventListener('click', (ev) => {
      if (ev.target === dialog) dialog.close();
    });
  }
  for (const link of root.querySelectorAll('a.js-preview')) {
    if (link.dataset.bound) continue;
    link.dataset.bound = '1';
    const row = link.closest('.file-row');
    const kind = row ? row.dataset.preview : '';
    if (!['image', 'video', 'audio', 'text'].includes(kind)) continue; // PDFs: new tab
    link.addEventListener('click', async (ev) => {
      ev.preventDefault();
      const url = link.getAttribute('href');
      title.textContent = row.dataset.name || 'Preview';
      body.replaceChildren();
      if (kind === 'image') {
        body.appendChild(h('img', { class: 'preview-media', src: url, alt: row.dataset.name || '' }));
      } else if (kind === 'video') {
        body.appendChild(h('video', { class: 'preview-media', src: url, controls: true, preload: 'metadata', playsinline: true }));
      } else if (kind === 'audio') {
        body.appendChild(h('audio', { src: url, controls: true, preload: 'metadata', style: 'width:100%' }));
      } else {
        const pre = h('pre', { class: 'preview-text', text: 'Loading…' });
        body.appendChild(pre);
        try {
          const res = await fetch(url, { credentials: 'same-origin', headers: { Range: 'bytes=0-262143' } });
          if (!res.ok) throw new Error('failed');
          pre.textContent = await res.text(); // text, never HTML
        } catch (_) {
          pre.textContent = 'The preview could not be loaded.';
        }
      }
      dialog.showModal();
    });
  }
}

// ------------------------------------------------------------------ folder browsing

function fileRow(f, can) {
  const thumb = f.thumb_url
    ? h('img', { src: f.thumb_url, alt: '', loading: 'lazy', decoding: 'async', width: 44, height: 44 })
    : icon('file', 22);
  const actions = h('div', { class: 'file-actions' });
  if (f.content_url) {
    actions.appendChild(h('a', { class: 'btn btn-ghost btn-sm js-preview', href: f.content_url, target: '_blank', rel: 'noopener' }, icon('eye', 16), h('span', { text: 'Preview' })));
  }
  if (can.comment) {
    actions.appendChild(h('button', { class: 'btn btn-ghost btn-sm js-comments', type: 'button' }, icon('comment', 16), h('span', { text: 'Comments' })));
  }
  if (can.download) {
    actions.appendChild(h('a', { class: 'btn btn-accent btn-sm', href: f.download_url, rel: 'nofollow' }, icon('download', 16), h('span', { text: 'Download' })));
  }
  return h('li', {
    class: 'file-row',
    dataset: { fileId: String(f.id), preview: f.preview || '', name: f.name },
  },
  h('div', { class: 'file-thumb' }, thumb),
  h('div', { class: 'file-main' },
    h('span', { class: 'file-name', title: f.name, text: f.name }),
    h('span', { class: 'file-meta' }, `${f.size_label} · `, h('time', { datetime: f.updated_at, text: localTime(f.updated_at) || f.updated_label }))),
  actions);
}

function renderFolder(view) {
  const section = document.getElementById('folder-view');
  if (!section) return;
  const crumbs = section.querySelector('.crumbs');
  const list = section.querySelector('#folder-list');
  crumbs.replaceChildren();
  view.breadcrumbs.forEach((c, i) => {
    if (i > 0) crumbs.appendChild(h('span', { class: 'crumb-sep' }, icon('chevron', 14)));
    crumbs.appendChild(h('a', {
      class: 'crumb js-folder', href: c.url, 'data-api': c.api,
      'aria-current': i === view.breadcrumbs.length - 1 ? 'page' : null, text: c.name,
    }));
  });
  list.replaceChildren();
  for (const d of view.folders) {
    list.appendChild(h('li', { class: 'file-row is-folder' },
      h('div', { class: 'file-thumb' }, icon('folder', 22)),
      h('div', { class: 'file-main' }, h('a', { class: 'file-name js-folder', href: d.url, 'data-api': d.api, text: d.name }))));
  }
  const can = { download: !!view.can_download, comment: !!view.can_comment };
  for (const f of view.files) list.appendChild(fileRow(f, can));
  if (!view.folders.length && !view.files.length) {
    list.appendChild(h('li', { class: 'file-empty muted', text: 'This folder is empty.' }));
  }
  const old = section.querySelector('.js-truncated');
  if (old) old.remove();
  if (view.truncated) section.appendChild(h('p', { class: 'muted small js-truncated', text: 'Only the first items are shown.' }));
  bindFolderLinks(section);
  initRowComments(section);
  initPreview(section);
}

async function openFolder(apiUrl, pageUrl, push) {
  const section = document.getElementById('folder-view');
  section.classList.add('is-loading');
  try {
    const view = await api(apiUrl);
    renderFolder(view);
    if (push) history.pushState({ api: apiUrl }, '', pageUrl);
    const heading = section.querySelector('[aria-current="page"]');
    if (heading) heading.focus({ preventScroll: true });
  } catch (e) {
    if (e.code === 'HOST_CHALLENGE' || e.code === 'NETWORK') window.alert(e.message);
    else window.location.assign(pageUrl); // let the server explain (e.g. the link expired)
  } finally {
    section.classList.remove('is-loading');
  }
}

function bindFolderLinks(root) {
  for (const a of root.querySelectorAll('a.js-folder[data-api]')) {
    if (a.dataset.bound) continue;
    a.dataset.bound = '1';
    a.addEventListener('click', (ev) => {
      if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.button !== 0) return;
      ev.preventDefault();
      openFolder(a.dataset.api, a.getAttribute('href'), true);
    });
  }
}

function initFolder() {
  const section = document.getElementById('folder-view');
  if (!section) return;
  const current = section.querySelector('.crumb[aria-current="page"]');
  history.replaceState({ api: current ? current.dataset.api : null }, '', window.location.href);
  window.addEventListener('popstate', (ev) => {
    if (ev.state && ev.state.api) openFolder(ev.state.api, window.location.href, false);
  });
  bindFolderLinks(section);
}

// ------------------------------------------------------------------ upload a new version

function initUpload() {
  const form = document.querySelector('form.js-upload');
  if (!form || typeof XMLHttpRequest === 'undefined') return;
  const bar = form.querySelector('.progress');
  const fill = form.querySelector('.progress-fill');
  const btn = form.querySelector('button[type="submit"]');
  const msg = h('p', { class: 'muted small', role: 'status' });
  form.appendChild(msg);
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const input = form.elements.namedItem('file');
    if (!input || !input.files || !input.files.length) {
      msg.textContent = 'Choose a file first.';
      return;
    }
    const data = new FormData();
    data.append('file', input.files[0]);
    const xhr = new XMLHttpRequest();
    xhr.open('POST', form.getAttribute('action'));
    xhr.setRequestHeader('Accept', 'application/json');
    xhr.setRequestHeader('X-CSRF-Token', csrf);
    xhr.upload.addEventListener('progress', (e) => {
      if (e.lengthComputable) fill.style.width = `${Math.round((e.loaded / e.total) * 100)}%`;
    });
    xhr.addEventListener('load', () => {
      btn.disabled = false;
      let json = null;
      try {
        json = JSON.parse(xhr.responseText);
      } catch (_) {
        json = null;
      }
      if (!xhr.getResponseHeader('X-FT-Api')) {
        msg.textContent = 'Your connection was interrupted. Please reload the page and try again.';
        return;
      }
      if (xhr.status >= 200 && xhr.status < 300 && json && json.success) {
        msg.textContent = `Uploaded — this is now version ${json.data.version}. Reloading…`;
        window.setTimeout(() => window.location.reload(), 900);
        return;
      }
      const err = (json && json.error) || {};
      const fields = err.details && err.details.fields ? Object.values(err.details.fields) : [];
      msg.textContent = fields[0] || err.message || 'The upload failed. Please try again.';
      bar.hidden = true;
    });
    xhr.addEventListener('error', () => {
      btn.disabled = false;
      bar.hidden = true;
      msg.textContent = 'The upload failed. Check your connection and try again.';
    });
    btn.disabled = true;
    bar.hidden = false;
    fill.style.width = '0%';
    msg.textContent = 'Uploading…';
    xhr.send(data);
  });
}

// ------------------------------------------------------------------ boot

initTheme();
localiseTimes();
if (page.state === 'share') {
  initSingleFileComments();
  initRowComments(document);
  initPreview(document);
  initFolder();
  initUpload();
}
