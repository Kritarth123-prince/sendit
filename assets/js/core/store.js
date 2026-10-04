/**
 * Tiny observable key/value store for app-wide state.
 * Keys: user, quota, unread, live, uploads, config, route.
 * @module core/store
 */
const state = new Map();
const subs = new Map();

export const store = {
  get(key) { return state.get(key); },
  set(key, value) {
    const prev = state.get(key);
    state.set(key, value);
    if (prev !== value) subs.get(key)?.forEach((fn) => { try { fn(value, prev); } catch (e) { console.error('[store]', key, e); } });
  },
  update(key, fn) { this.set(key, fn(state.get(key))); },
  /** @returns {() => void} */
  on(key, fn) {
    if (!subs.has(key)) subs.set(key, new Set());
    subs.get(key).add(fn);
    return () => subs.get(key)?.delete(fn);
  },
};
