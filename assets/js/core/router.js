/**
 * Hash router: #/files/12?sort=name. Views are lazily imported ES modules exporting
 * default { title?, mount(container, params, query), unmount?() }.
 * @module core/router
 */
import { store } from './store.js';
import { bus } from './bus.js';
import { h, clear } from './dom.js';
import { emptyState, errorState, skeleton } from './ui.js';

const routes = [];
let current = null;
let container = null;
let seq = 0;
const scrollPos = new Map();

/** Compile '/files/:folderId?' into a matcher. */
export function compile(path) {
  const keys = [];
  const re = path.replace(/\/:(\w+)(\?)?/g, (_, k, opt) => { keys.push(k); return opt ? '(?:/([^/]+))?' : '/([^/]+)'; });
  return { regex: new RegExp('^' + (re === '' ? '/' : re) + '/?$'), keys };
}

/** Parse location.hash into {path, query}. */
export function parseHash(hash) {
  let s = (hash || '').replace(/^#/, '');
  if (!s.startsWith('/')) s = '/' + s;
  const [p, q = ''] = s.split('?');
  return { path: p || '/', query: Object.fromEntries(new URLSearchParams(q)) };
}

export function matchRoute(list, path) {
  for (const r of list) {
    const m = r.compiled.regex.exec(path);
    if (m) {
      const params = {};
      r.compiled.keys.forEach((k, i) => { if (m[i + 1] !== undefined) params[k] = decodeURIComponent(m[i + 1]); });
      return { route: r, params };
    }
  }
  return null;
}

async function navigate() {
  const my = ++seq;
  const { path, query } = parseHash(location.hash);
  const found = matchRoute(routes, path);
  if (current?.key) scrollPos.set(current.key, window.scrollY);
  if (current?.view?.unmount) { try { current.view.unmount(); } catch (e) { console.error(e); } }
  current = null;
  clear(container);
  document.body.classList.remove('drawer-is-open');
  if (!found) {
    container.appendChild(emptyState({ icon: 'search', title: 'Page not found', text: 'That page does not exist.', action: { label: 'Go to Dashboard', icon: 'home', onClick: () => go('/') } }));
    document.title = 'Not found · FastTransfer';
    return;
  }
  const { route, params } = found;
  store.set('route', { name: route.name, nav: route.nav, path, params, query });
  container.appendChild(skeleton(3));
  try {
    const mod = await route.load();
    if (my !== seq) return;
    const view = mod.default || mod;
    clear(container);
    const key = location.hash;
    current = { view, key };
    document.title = (view.title || route.title || 'FastTransfer') + ' · FastTransfer';
    await view.mount(container, params, query);
    if (my === seq) window.scrollTo(0, scrollPos.get(key) || 0);
  } catch (e) {
    console.error(e);
    if (my !== seq) return;
    clear(container);
    container.appendChild(h('div', errorState(e, () => navigate())));
  }
  container.focus({ preventScroll: true });
  bus.emit('route:changed', store.get('route'));
}

export const router = {
  /** @param {string} name @param {{path:string, load:Function, title?:string, nav?:string}} def */
  register(name, def) { routes.push({ name, ...def, compiled: compile(def.path) }); },
  start(el) {
    container = el;
    window.addEventListener('hashchange', navigate);
    navigate();
  },
  go(path) { const target = '#' + (path.startsWith('/') ? path : '/' + path); if (location.hash === target) navigate(); else location.hash = target; },
  back() { history.length > 1 ? history.back() : this.go('/'); },
  current() { return store.get('route'); },
  refresh() { navigate(); },
};
