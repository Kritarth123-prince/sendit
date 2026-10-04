/**
 * FastTransfer web app entry point.
 * Reads the boot JSON, wires the shell (navigation, quota meter, live indicator, theme,
 * notifications badge, account menu, uploads, drag-and-drop) and starts the router + real-time sync.
 */
import { api, ApiError } from './core/api.js';
import { bus } from './core/bus.js';
import { store } from './core/store.js';
import { h, icon, clear, qs, qsa } from './core/dom.js';
import { hydrateIcons } from './core/icons.js';
import { bytes, percent } from './core/format.js';
import { toast, modal, menu, confirm } from './core/ui.js';
import { router } from './core/router.js';
import { realtime } from './core/realtime.js';
import { initTheme, currentTheme, setTheme } from './core/theme.js';

const boot = (() => { try { return JSON.parse(document.getElementById('ft-boot').textContent); } catch { return {}; } })();
const config = boot.config || {};
api.init(config, boot.csrf_token);
store.set('config', config);

if (boot.mode === 'login' || !boot.user) {
  renderLogin();
} else {
  startApp();
}

// ------------------------------------------------------------------ sign-in (fallback page)

function loginForm({ onSuccess, username = '' } = {}) {
  const err = h('div.login-err', { role: 'alert', hidden: true });
  const user = h('input.input', { name: 'username', autocomplete: 'username', required: true, value: username, placeholder: 'Username or e-mail' });
  const pass = h('input.input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true, placeholder: 'Password' });
  const remember = h('input', { type: 'checkbox', name: 'remember' });
  const code = h('input.input', { name: 'code', inputmode: 'numeric', autocomplete: 'one-time-code', placeholder: '6-digit code or recovery code', maxlength: 64 });
  const codeField = h('div.field', { hidden: true }, h('label', { text: 'Two-factor code' }), code);
  const btn = h('button.btn.btn-primary.btn-block', { type: 'submit', text: 'Sign in' });
  let challenge = null;
  const form = h('form.login-form', { novalidate: true },
    err,
    h('div.field', { }, h('label', { text: 'Username' }), user),
    h('div.field', { }, h('label', { text: 'Password' }), pass),
    codeField,
    h('label.check', remember, h('span', { text: 'Keep me signed in on this device' })),
    btn);
  const show = (m) => { err.textContent = m; err.hidden = !m; };
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    show('');
    btn.disabled = true;
    btn.textContent = 'Signing in…';
    try {
      let res;
      if (challenge) {
        const c = code.value.trim();
        res = await api.post('/auth/2fa', /^\d{6}$/.test(c) ? { challenge, code: c, remember: remember.checked } : { challenge, recovery_code: c, remember: remember.checked });
      } else {
        res = await api.post('/auth/login', { username: user.value.trim(), password: pass.value, remember: remember.checked });
      }
      const d = res.data || {};
      if (d.two_factor_required) {
        challenge = d.challenge;
        codeField.hidden = false;
        user.disabled = true; pass.disabled = true;
        code.focus();
        show('');
      } else {
        api.setCsrf(d.csrf_token);
        onSuccess(d);
      }
    } catch (ex) {
      show(ex instanceof ApiError ? ex.message : 'Could not sign in. Please try again.');
    } finally {
      btn.disabled = false;
      btn.textContent = challenge ? 'Verify' : 'Sign in';
    }
  });
  setTimeout(() => (username ? pass : user).focus(), 30);
  return form;
}

function renderLogin() {
  const box = qs('.login-box');
  const placeholder = qs('[data-login-placeholder]');
  if (!box) return;
  placeholder && placeholder.remove();
  const next = typeof boot.next === 'string' && boot.next.startsWith('/') ? boot.next : null;
  box.appendChild(loginForm({ onSuccess: () => { location.href = (config.base || '/') + (next ? '#' + next : ''); } }));
}

// ------------------------------------------------------------------ app shell

function startApp() {
  store.set('user', boot.user);
  store.set('quota', boot.user.quota);
  store.set('unread', boot.unread_notifications || 0);
  hydrateIcons(document);

  wireNav();
  wireQuota();
  wireUnread();
  wireLive();
  wireTheme();
  wireAccount();
  wireSearch();
  wireUploads();
  wireAuthEvents();
  wireShortcuts();
  registerRoutes();

  router.start(document.getElementById('view'));
  realtime.start({ userId: boot.user.id, lastEventId: config.realtime?.last_event_id || 0, isAdmin: boot.user.role === 'admin', realtime: config.realtime || {} });

  if (boot.user.must_change_password) setTimeout(() => forcePasswordChange(), 400);
  if ('serviceWorker' in navigator && config.pretty_urls !== false) {
    navigator.serviceWorker.register((config.base || '/') + 'service-worker.js', { scope: config.base || '/' }).catch(() => {});
    navigator.serviceWorker.addEventListener('message', onWorkerMessage);
  }
}

/** Messages from the service worker: notification clicks and Background Sync retries. */
function onWorkerMessage(e) {
  const d = e.data || {};
  if (d.type === 'ft:navigate' && typeof d.url === 'string') {
    try {
      const u = new URL(d.url, location.href);
      if (u.origin === location.origin && u.hash.startsWith('#/')) location.hash = u.hash;
    } catch { /* ignore malformed URLs */ }
  } else if (d.type === 'ft:retry-uploads') {
    uploaderModule().then((m) => m?.uploader?.items().filter((i) => i.status === 'failed' || i.status === 'paused').forEach((i) => m.uploader.resume(i.key)));
  }
}

function registerRoutes() {
  const v = (name) => () => import('./views/' + name + '.js');
  const R = [
    ['dashboard', '/', 'dashboard', 'Dashboard', 'dashboard'],
    ['files', '/files/:folderId?', 'files', 'My Files', 'files'],
    ['shared', '/shared', 'shared', 'Shared With Me', 'shared'],
    ['favorites', '/favorites', 'favorites', 'Favourites', 'favorites'],
    ['recent', '/recent', 'recent', 'Recent', 'recent'],
    ['trash', '/trash', 'trash', 'Trash', 'trash'],
    ['clipboard', '/clipboard', 'clipboard', 'Clipboard', 'clipboard'],
    ['notepad', '/notepad/:id?', 'notepad', 'Notepad', 'notepad'],
    ['uploads', '/uploads', 'uploads', 'Uploads', 'uploads'],
    ['search', '/search', 'search', 'Search', null],
    ['notifications', '/notifications', 'notifications', 'Notifications', 'notifications'],
    ['settings', '/settings', 'settings', 'Settings', 'settings'],
    ['security', '/security', 'security', 'Security Centre', 'security'],
    ['admin', '/admin', 'admin/dashboard', 'Admin', 'admin'],
    ['admin-users', '/admin/users', 'admin/users', 'Users', 'admin-users'],
    ['admin-storage', '/admin/storage', 'admin/storage', 'Storage', 'admin-storage'],
    ['admin-shares', '/admin/shares', 'admin/shares', 'Shares', 'admin-shares'],
    ['admin-activity', '/admin/activity', 'admin/activity', 'Activity', 'admin-activity'],
    ['admin-system', '/admin/system', 'admin/system', 'System', 'admin-system'],
  ];
  for (const [name, path, file, title, nav] of R) router.register(name, { path, load: v(file), title, nav });
}

function wireNav() {
  const app = document.getElementById('app');
  const setOpen = (open) => {
    app.classList.toggle('drawer-open', open);
    qs('.drawer-scrim').hidden = !open;
    qsa('[data-action="drawer-open"]').forEach((b) => b.setAttribute('aria-expanded', open ? 'true' : 'false'));
  };
  document.addEventListener('click', (e) => {
    const t = e.target.closest('[data-action]');
    if (!t) return;
    const a = t.dataset.action;
    if (a === 'drawer-open') setOpen(true);
    else if (a === 'drawer-close') setOpen(false);
  });
  qs('#nav')?.addEventListener('click', (e) => { if (e.target.closest('a')) setOpen(false); });
  store.on('route', (r) => {
    const nav = r?.nav;
    qsa('[data-nav]').forEach((a) => {
      const on = a.dataset.nav === nav || (nav === 'files' && a.dataset.nav === 'files');
      a.classList.toggle('active', on);
      if (on) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
  });
}

function wireQuota() {
  const el = qs('#quota-meter');
  const paint = (q) => {
    if (!el || !q) return;
    clear(el);
    const used = q.used_bytes || 0;
    if (q.quota_bytes === null || q.quota_bytes === undefined) {
      el.append(h('div.row', icon('server', 15), h('span', { text: bytes(used) + ' used' })), h('div.small.muted', { text: 'Unlimited storage' }));
      return;
    }
    const pct = percent(used, q.quota_bytes);
    el.classList.toggle('warn', pct >= (config.settings?.quota_warning_percent || 90) && pct < 100);
    el.classList.toggle('full', pct >= 100);
    el.append(
      h('div.row', icon('server', 15), h('span.grow', { text: 'Storage' }), h('strong', { text: Math.round(pct) + '%' })),
      h('div.quota-bar', { role: 'progressbar', 'aria-valuemin': 0, 'aria-valuemax': 100, 'aria-valuenow': Math.round(pct), 'aria-label': 'Storage used' }, h('span', { style: { width: pct + '%' } })),
      h('div.small', { text: bytes(used) + ' / ' + bytes(q.quota_bytes) + ' used' }));
  };
  paint(store.get('quota'));
  store.on('quota', paint);
  bus.on('quota.updated', (e) => { if (e.data?.quota) store.set('quota', e.data.quota); });
}

function wireUnread() {
  const paint = (n) => qsa('[data-unread-badge]').forEach((b) => { b.textContent = n > 99 ? '99+' : String(n); b.hidden = !n; });
  paint(store.get('unread'));
  store.on('unread', paint);
  bus.on('notification.created', (e) => {
    store.update('unread', (n) => (n || 0) + 1);
    const n = e.data?.notification;
    if (n && document.visibilityState === 'visible' && store.get('route')?.name !== 'notifications') {
      toast(n.title, { type: 'info', id: 'notif-' + n.id, timeout: 5000, action: { label: 'View', onClick: () => router.go('/notifications') } });
    }
  });
  bus.on('notification.read', (e) => { if (typeof e.data?.unread_count === 'number') store.set('unread', e.data.unread_count); });
}

function wireLive() {
  const el = qs('#live-indicator');
  const text = { connecting: 'Connecting…', connected: 'Live', reconnecting: 'Reconnecting…', reconnected: 'Live', disconnected: 'Offline' };
  store.on('live', (s) => {
    if (!el) return;
    el.dataset.state = s;
    const t = el.querySelector('.live-text');
    if (t) t.textContent = text[s] || s;
    el.title = s === 'connected' || s === 'reconnected' ? 'Live: changes from your other devices appear automatically' : (text[s] || s);
    if (s === 'reconnected') toast('Back online — changes synced', { type: 'ok', id: 'live', timeout: 2500 });
  });
}

/** Theme toggle in the top bar; the accent palette is chosen in Settings → Appearance (core/theme.js). */
function wireTheme() {
  const btn = qs('[data-action="theme"]');
  const paint = () => { if (btn) clear(btn).appendChild(icon(currentTheme() === 'light' ? 'moon' : 'sun')); };
  btn?.addEventListener('click', () => { setTheme(currentTheme() === 'light' ? 'dark' : 'light').catch(() => {}); });
  bus.on('ui:theme', paint);
  initTheme(boot.user);
}

function wireAccount() {
  const btn = qs('[data-action="avatar"]');
  btn?.addEventListener('click', () => {
    const u = store.get('user');
    menu(btn, [
      { label: (u.display_name || u.username) + ' (' + u.role + ')', icon: 'user', disabled: true, onClick() {} },
      '-',
      { label: 'Settings', icon: 'settings', onClick: () => router.go('/settings') },
      { label: 'Security Centre', icon: 'shield', onClick: () => router.go('/security') },
      '-',
      { label: 'Sign out', icon: 'logout', danger: true, onClick: signOut },
    ]);
  });
}

async function signOut() {
  try { await api.post('/auth/logout'); } catch { /* ignore */ }
  realtime.stop();
  location.href = config.base || '/';
}

function wireSearch() {
  const form = qs('#global-search');
  const input = qs('#search-input');
  form?.addEventListener('submit', (e) => {
    e.preventDefault();
    const q = input.value.trim();
    router.go('/search' + (q ? '?q=' + encodeURIComponent(q) : ''));
  });
  store.on('route', (r) => { if (r?.name === 'search' && input && document.activeElement !== input) input.value = r.query?.q || ''; });
}

// ------------------------------------------------------------------ uploads (drag & drop, paste, button)

async function uploaderModule() {
  try { return await import('./features/uploader.js'); } catch { return null; }
}
async function startUpload(files, extra = {}) {
  if (!files || !files.length) return;
  const mod = await uploaderModule();
  if (!mod || !mod.uploader) { toast('Uploads are not available yet.', { type: 'warn' }); return; }
  const r = store.get('route');
  const folderId = r?.name === 'files' && r.params?.folderId ? parseInt(r.params.folderId, 10) : null;
  mod.uploader.add(files, { folderId, ...extra });
}

function wireUploads() {
  const input = qs('#global-file-input');
  document.addEventListener('click', (e) => {
    if (e.target.closest('[data-action="upload"]')) { input.value = ''; input.click(); }
  });
  input?.addEventListener('change', () => startUpload(Array.from(input.files || [])));
  const overlay = qs('#drop-overlay');
  let depth = 0;
  const hasFiles = (e) => Array.from(e.dataTransfer?.types || []).includes('Files');
  window.addEventListener('dragenter', (e) => { if (!hasFiles(e)) return; depth++; overlay.hidden = false; });
  window.addEventListener('dragleave', (e) => { if (!hasFiles(e)) return; depth = Math.max(0, depth - 1); if (!depth) overlay.hidden = true; });
  window.addEventListener('dragover', (e) => { if (hasFiles(e)) e.preventDefault(); });
  window.addEventListener('drop', (e) => {
    if (!hasFiles(e)) return;
    e.preventDefault(); depth = 0; overlay.hidden = true;
    if (e.defaultPrevented && e.target.closest?.('[data-dropzone]')) return;
    startUpload(Array.from(e.dataTransfer.files || []));
  });
  document.addEventListener('paste', (e) => {
    if (e.target.closest('input, textarea, [contenteditable]')) return;
    const files = Array.from(e.clipboardData?.items || []).filter((i) => i.kind === 'file').map((i) => i.getAsFile()).filter(Boolean);
    if (!files.length) return;
    e.preventDefault();
    const stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
    const named = files.map((f, i) => (f.name && f.name !== 'image.png' ? f : new File([f], 'paste-' + stamp + (i ? '-' + i : '') + '.' + ((f.type.split('/')[1] || 'png').replace('jpeg', 'jpg')), { type: f.type })));
    startUpload(named);
    toast('Uploading pasted ' + (named.length === 1 ? 'file' : named.length + ' files') + '…', { type: 'info' });
  });
  bus.on('upload:open-picker', (opts = {}) => {
    const i = h('input', { type: 'file', multiple: true, accept: opts.accept || undefined, capture: opts.capture || undefined, hidden: true });
    i.addEventListener('change', () => { startUpload(Array.from(i.files || []), opts.extra || {}); i.remove(); });
    document.body.appendChild(i); i.click();
  });
  bus.on('upload:files', ({ files, extra }) => startUpload(files, extra || {}));
}

// ------------------------------------------------------------------ session / host events

function wireAuthEvents() {
  let open = false;
  bus.on('auth:expired', () => {
    if (open) return;
    open = true;
    const u = store.get('user');
    const m = modal({
      title: 'Please sign in again',
      dismissible: false,
      size: 'sm',
      content: h('div.stack', h('p.text2', { text: 'Your session has ended. Sign in to continue where you left off.' }),
        loginForm({ username: u?.username || '', onSuccess: (d) => { open = false; m.close(); if (d.user) { store.set('user', d.user); store.set('quota', d.user.quota); } toast('Signed in again', { type: 'ok' }); realtime.nudge(); } })),
    });
  });
  bus.on('auth:revoked', () => {
    realtime.stop();
    modal({ title: 'Signed out', dismissible: false, size: 'sm', content: 'This session was ended from another device or by an administrator.',
      actions: [{ label: 'Sign in', kind: 'primary', onClick: () => { location.href = config.base || '/'; } }] });
  });
  // The server refuses everything but a password change until the account has a new password
  // (403 PASSWORD_CHANGE_REQUIRED from any API call): open the dialog once, however many calls fail.
  bus.on('auth:password-change-required', () => forcePasswordChange({ fromServer: true }));
  bus.on('host:challenge', () => {
    const banner = qs('#banner');
    if (!banner || banner.querySelector('[data-host]')) return;
    banner.appendChild(h('div.banner', { dataset: { host: '1' } }, icon('warning', 18), h('span.grow', { text: 'The connection needs to be refreshed.' }),
      h('button.btn.btn-sm.btn-primary', { type: 'button', text: 'Reload', on: { click: () => location.reload() } })));
  });
}

let passwordDialog = null;

/**
 * The "choose a new password" dialog for accounts that must change their password (temporary
 * password from an administrator or the importer). Opened at start-up from the boot data and
 * whenever an API call answers 403 PASSWORD_CHANGE_REQUIRED; only ever one at a time.
 */
function forcePasswordChange({ fromServer = false } = {}) {
  if (passwordDialog) return passwordDialog;
  const cur = h('input.input', { type: 'password', autocomplete: 'current-password' });
  const nw = h('input.input', { type: 'password', autocomplete: 'new-password', minlength: 10 });
  const nw2 = h('input.input', { type: 'password', autocomplete: 'new-password', minlength: 10 });
  const err = h('div.form-error', { role: 'alert' });
  passwordDialog = modal({
    title: 'Choose a new password', dismissible: false, size: 'sm',
    content: h('div.stack', h('p.text2', { text: fromServer
      ? 'You need to choose a new password before you can continue.'
      : 'An administrator asked you to change your password before continuing.' }),
      h('div.field', h('label', { text: 'Current (temporary) password' }), cur),
      h('div.field', h('label', { text: 'New password (at least 10 characters)' }), nw),
      h('div.field', h('label', { text: 'Repeat new password' }), nw2), err),
    actions: [
      { label: 'Sign out', kind: 'ghost', onClick: () => { signOut(); return false; } },
      { label: 'Change password', kind: 'primary', onClick: async () => {
        err.textContent = '';
        if (nw.value !== nw2.value) { err.textContent = 'The new passwords do not match.'; nw2.focus(); return false; }
        try {
          const { data } = await api.post('/user/password', { current_password: cur.value, new_password: nw.value });
          cur.value = nw.value = nw2.value = '';
          toast('Password changed', { type: 'ok' });
          store.update('user', (u) => ({ ...u, ...(data?.user || {}), must_change_password: false }));
          // Views that failed while the password change was pending load again.
          router.refresh();
          return true;
        } catch (e) { err.textContent = e.message; return false; }
      } },
    ],
    onClose: () => { passwordDialog = null; },
  });
  return passwordDialog;
}

function wireShortcuts() {
  let g = false;
  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey || e.altKey) return;
    if (e.target.closest('input, textarea, select, [contenteditable]') || document.querySelector('.modal-overlay')) return;
    if (e.key === '/') { e.preventDefault(); qs('#search-input')?.focus(); return; }
    if (e.key === 'u' && !g) { qs('[data-action="upload"]')?.click(); return; }
    if (e.key === 'g') { g = true; setTimeout(() => { g = false; }, 900); return; }
    if (g) {
      const map = { f: '/files', s: '/shared', t: '/trash', h: '/', r: '/recent', n: '/notifications' };
      if (map[e.key]) { e.preventDefault(); router.go(map[e.key]); }
      g = false;
    }
  });
}

// Exposed for views that need to confirm before leaving etc.
export { confirm };
