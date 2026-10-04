/**
 * In-app publish/subscribe. Types may be exact ('file.created'), prefix wildcards ('file.*') or '*'.
 * @module core/bus
 */
const handlers = new Map();

export const bus = {
  /** @returns {() => void} unsubscribe */
  on(type, fn) {
    if (!handlers.has(type)) handlers.set(type, new Set());
    handlers.get(type).add(fn);
    return () => handlers.get(type)?.delete(fn);
  },
  once(type, fn) {
    const off = this.on(type, (p, t) => { off(); fn(p, t); });
    return off;
  },
  emit(type, payload) {
    const call = (key) => handlers.get(key)?.forEach((fn) => {
      try { fn(payload, type); } catch (e) { console.error('[bus]', type, e); }
    });
    call(type);
    const dot = type.indexOf('.');
    if (dot > 0) call(type.slice(0, dot) + '.*');
    call('*');
  },
};
