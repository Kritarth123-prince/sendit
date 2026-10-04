/**
 * Theme (dark / light) and accent palette of the app shell.
 *
 * The first paint is decided before any module loads: views/app.php renders the profile's accent
 * as <html data-accent> and its nonce'd inline script applies the theme remembered on this device
 * (localStorage "ft_theme", else the ft_theme cookie). This module applies later changes,
 * remembers them on this device (localStorage "ft_theme" / "ft_accent" and the cookie), saves
 * them to the profile (PATCH /user {preferences}) and follows changes made in other tabs
 * (storage events) and on other devices (user.updated events with a "preferences" change).
 * The palettes themselves are CSS token sets on html[data-accent] in assets/css/app.css.
 * @module core/theme
 */
import { api } from './api.js';
import { bus } from './bus.js';
import { store } from './store.js';

/** The curated accent palettes, in picker order. Champagne is the default. */
export const ACCENTS = Object.freeze([
  { id: 'champagne', label: 'Champagne', hint: 'Default' },
  { id: 'platinum', label: 'Platinum' },
  { id: 'rose', label: 'Rose gold' },
  { id: 'aurora', label: 'Aurora' },
  { id: 'sapphire', label: 'Sapphire' },
  { id: 'violet', label: 'Violet (classic)' },
]);
export const DEFAULT_ACCENT = 'champagne';
const THEME_KEY = 'ft_theme';
const ACCENT_KEY = 'ft_accent';
/** When this browser (any tab) last changed the accent, so other tabs can tell an echo from news. */
const STAMP_KEY = 'ft_accent_at';
/**
 * A user.updated event this soon after a change made in this browser is (almost always) the echo
 * of that change. Generous because events can arrive a poll interval late (8 s on byethost), and
 * applying a stale echo would undo a newer choice in this tab and, through localStorage, in the others.
 */
const ECHO_MS = 15000;
let lastLocalChange = 0;
let saving = 0;

function stamp() {
  lastLocalChange = Date.now();
  remember(STAMP_KEY, String(lastLocalChange));
}
function recentLocalChange() {
  let t = 0;
  try { t = Number(localStorage.getItem(STAMP_KEY)) || 0; } catch { /* private mode */ }
  return Date.now() - Math.max(t, lastLocalChange) < ECHO_MS;
}

/** A known accent id, else the default. */
export const normaliseAccent = (a) => (ACCENTS.some((x) => x.id === a) ? a : DEFAULT_ACCENT);
/** "light" or "dark" (anything else is dark, the default). */
export const normaliseTheme = (t) => (t === 'light' ? 'light' : 'dark');

const root = () => document.documentElement;
export const currentTheme = () => normaliseTheme(root().getAttribute('data-theme'));
export const currentAccent = () => normaliseAccent(root().getAttribute('data-accent'));

function remember(key, value) {
  try { localStorage.setItem(key, value); } catch { /* private mode or storage disabled */ }
}

/** Browser chrome (theme-color) follows the page background of the current palette and theme. */
function paintChrome() {
  const meta = document.querySelector('meta[name="theme-color"]');
  const bg = getComputedStyle(root()).getPropertyValue('--bg').trim();
  if (meta && bg) meta.setAttribute('content', bg);
}

/** Keep the signed-in user's stored preferences in step (no request). */
function adopt(patch) {
  store.update('user', (u) => (u ? { ...u, preferences: { ...(u.preferences || {}), ...patch } } : u));
}

/** Apply a theme on this device (no save). Emits "ui:theme" when it changes. */
export function applyTheme(theme) {
  const t = normaliseTheme(theme);
  const changed = currentTheme() !== t;
  root().setAttribute('data-theme', t);
  remember(THEME_KEY, t);
  document.cookie = 'ft_theme=' + t + ';path=' + (store.get('config')?.base || '/') + ';max-age=31536000;samesite=Lax';
  paintChrome();
  if (changed) bus.emit('ui:theme', { theme: t });
  return t;
}

/** Apply an accent palette on this device (no save). Emits "ui:accent" when it changes. */
export function applyAccent(accent) {
  const a = normaliseAccent(accent);
  const changed = root().getAttribute('data-accent') !== a;
  root().setAttribute('data-accent', a);
  remember(ACCENT_KEY, a);
  paintChrome();
  if (changed) bus.emit('ui:accent', { accent: a });
  return a;
}

/** Save preference keys to the profile. Resolves with the fresh user; rejects with the ApiError. */
function save(patch) {
  stamp();
  adopt(patch);
  saving++;
  return api.patch('/user', { preferences: patch }).then(({ data }) => {
    stamp();
    if (data?.preferences) store.update('user', (u) => (u ? { ...u, preferences: data.preferences } : u));
    return data;
  }).finally(() => { saving--; });
}

/** Switch theme now, remember it on this device and save it to the profile. */
export function setTheme(theme) {
  return save({ theme: applyTheme(theme) });
}

/** Switch accent palette now, remember it on this device and save it to the profile. */
export function setAccent(accent) {
  return save({ accent: applyAccent(accent) });
}

/**
 * Start-up for a signed-in user: the profile's accent wins over what this device remembered
 * (and is remembered for the sign-in page); then follow other tabs and other devices.
 */
export function initTheme(user) {
  applyAccent(user?.preferences?.accent);
  paintChrome();
  window.addEventListener('storage', (e) => {
    if (e.key === ACCENT_KEY && e.newValue) adopt({ accent: applyAccent(e.newValue) });
    else if (e.key === THEME_KEY && (e.newValue === 'light' || e.newValue === 'dark')) applyTheme(e.newValue);
  });
  bus.on('user.updated', (e) => {
    const d = e?.data || {};
    const me = store.get('user');
    if (!me || !Array.isArray(d.changes) || !d.changes.includes('preferences')) return;
    if (d.user && Number(d.user.id) !== Number(me.id)) return;
    // A save still in flight, or a recent change in any tab of this browser: this is our own echo
    // (the server may not even have the newest choice yet). Only changes from other devices apply.
    if (saving > 0 || recentLocalChange()) return;
    api.get('/user').then(({ data }) => {
      if (!data || saving > 0 || recentLocalChange()) return;
      store.update('user', (u) => (u ? { ...u, preferences: data.preferences || {} } : u));
      applyAccent(data.preferences?.accent);
    }).catch(() => { /* next load picks it up */ });
  });
}
