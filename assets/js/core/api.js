/**
 * REST client for /api/v1.
 * - Sends X-CSRF-Token, X-Client-Id, Accept: application/json.
 * - PUT/PATCH/DELETE go out as POST + X-HTTP-Method-Override when config.method_override is on
 *   (some shared hosts block those methods).
 * - A response without the `X-FT-Api: 1` header did not come from PHP (e.g. the host's JavaScript
 *   cookie check served an HTML page): PHP never ran, so it is safe to recover and retry once.
 * - 419 → refresh the CSRF token and retry once. 401 → bus 'auth:expired'.
 * - 403 PASSWORD_CHANGE_REQUIRED (the account must choose a new password before doing anything
 *   else) → bus 'auth:password-change-required'; the shell opens the change-password dialog.
 * @module core/api
 */
import { bus } from './bus.js';

export class ApiError extends Error {
  constructor(code, message, status = 0, details = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

let cfg = { api_base: '/api/v1', base: '/', method_override: true };
let csrf = '';

function makeClientId() {
  try {
    let id = localStorage.getItem('ft:client-id');
    if (!id) {
      id = (crypto.randomUUID ? crypto.randomUUID() : Array.from(crypto.getRandomValues(new Uint8Array(16)), (b) => b.toString(16).padStart(2, '0')).join(''));
      localStorage.setItem('ft:client-id', id);
    }
    return id;
  } catch {
    return 'tab-' + Math.random().toString(36).slice(2, 12);
  }
}
const clientId = makeClientId();

/** Build an absolute app URL for an API path, supporting both URL styles. */
function buildUrl(path, query) {
  const base = cfg.api_base;
  const p = path.startsWith('/') ? path : '/' + path;
  let url = base.includes('?') ? base + p : base.replace(/\/$/, '') + p;
  if (query) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined || v === null || v === '') continue;
      if (Array.isArray(v)) v.forEach((x) => qs.append(k, x));
      else qs.append(k, typeof v === 'boolean' ? (v ? '1' : '0') : String(v));
    }
    const s = qs.toString();
    if (s) url += (url.includes('?') ? '&' : '?') + s;
  }
  return url;
}

export const PASSWORD_CHANGE_REQUIRED = 'PASSWORD_CHANGE_REQUIRED';

/** Tell the shell when the server insists on a password change (any request may hit it). */
function notePasswordChange(err) {
  if (err instanceof ApiError && err.status === 403 && err.code === PASSWORD_CHANGE_REQUIRED) bus.emit('auth:password-change-required', err);
  return err;
}

let challengePromise = null;
/** Let the host's JS cookie check run in a hidden same-origin iframe (no page reload). */
function solveHostChallenge() {
  if (challengePromise) return challengePromise;
  challengePromise = new Promise((resolve) => {
    const f = document.createElement('iframe');
    f.style.cssText = 'position:absolute;width:1px;height:1px;opacity:0;border:0;left:-9999px';
    f.setAttribute('aria-hidden', 'true');
    let done = false;
    const finish = (ok) => { if (done) return; done = true; setTimeout(() => f.remove(), 100); challengePromise = null; resolve(ok); };
    let loads = 0;
    f.addEventListener('load', () => { loads++; if (loads >= 2) setTimeout(() => finish(true), 300); else setTimeout(() => finish(true), 2500); });
    setTimeout(() => finish(false), 10000);
    f.src = cfg.base + '?ft_ping=' + Date.now();
    document.body.appendChild(f);
  });
  return challengePromise;
}

async function parse(res) {
  if (res.status === 204) return { data: null, meta: {} };
  const ct = res.headers.get('Content-Type') || '';
  if (!ct.includes('application/json')) throw new ApiError('BAD_RESPONSE', 'Unexpected response from the server.', res.status);
  const json = await res.json();
  if (!res.ok || json.success === false) {
    const e = json.error || {};
    throw new ApiError(e.code || 'HTTP_' + res.status, e.message || 'Request failed.', res.status, e.details || {});
  }
  return { data: json.data, meta: json.meta || {} };
}

async function request(method, path, { body, query, headers = {}, signal, raw = false } = {}, attempt = 0) {
  const h = { Accept: 'application/json', 'X-Client-Id': clientId, ...headers };
  if (csrf) h['X-CSRF-Token'] = csrf;
  let m = method.toUpperCase();
  if (cfg.method_override && ['PUT', 'PATCH', 'DELETE'].includes(m)) {
    h['X-HTTP-Method-Override'] = m;
    m = 'POST';
  }
  let payload;
  if (body instanceof FormData || body instanceof Blob || body instanceof ArrayBuffer) payload = body;
  else if (body !== undefined) { h['Content-Type'] = 'application/json'; payload = JSON.stringify(body); }

  let res;
  try {
    res = await fetch(buildUrl(path, query), { method: m, headers: h, body: payload, credentials: 'same-origin', signal, cache: 'no-store' });
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new ApiError('NETWORK', 'You appear to be offline. Check your connection and try again.', 0);
  }
  if (res.headers.get('X-FT-Api') !== '1') {
    if (attempt === 0 && (await solveHostChallenge())) return request(method, path, { body, query, headers, signal, raw }, 1);
    bus.emit('host:challenge');
    throw new ApiError('HOST_CHALLENGE', 'The connection needs to be refreshed. Please reload the page.', res.status);
  }
  if (res.status === 419 && attempt === 0) {
    try { await refreshCsrf(); } catch { /* fall through */ }
    return request(method, path, { body, query, headers, signal, raw }, 1);
  }
  if (res.status === 401) {
    const parsed = await parse(res).catch((e) => e);
    if (parsed instanceof ApiError && parsed.code !== 'INVALID_CREDENTIALS' && parsed.code !== 'TOKEN_INVALID') bus.emit('auth:expired', parsed);
    if (parsed instanceof ApiError) throw parsed;
  }
  if (raw) {
    if (res.status === 403) {
      try { const j = await res.clone().json(); if (j?.error?.code === PASSWORD_CHANGE_REQUIRED) notePasswordChange(new ApiError(PASSWORD_CHANGE_REQUIRED, j.error.message || '', 403)); } catch { /* not JSON */ }
    }
    return res;
  }
  try {
    return await parse(res);
  } catch (e) {
    throw notePasswordChange(e);
  }
}

async function refreshCsrf() {
  const res = await fetch(buildUrl('/auth/csrf'), { headers: { Accept: 'application/json', 'X-Client-Id': clientId }, credentials: 'same-origin', cache: 'no-store' });
  const j = await res.json();
  if (j?.data?.csrf_token) csrf = j.data.csrf_token;
}

/** XHR upload with progress (fetch has no upload progress). */
function xhr(method, path, { body, query, headers = {}, signal, onUploadProgress } = {}) {
  return new Promise((resolve, reject) => {
    const x = new XMLHttpRequest();
    let m = method.toUpperCase();
    const h = { Accept: 'application/json', 'X-Client-Id': clientId, ...headers };
    if (csrf) h['X-CSRF-Token'] = csrf;
    if (cfg.method_override && ['PUT', 'PATCH', 'DELETE'].includes(m)) { h['X-HTTP-Method-Override'] = m; m = 'POST'; }
    x.open(m, buildUrl(path, query));
    x.withCredentials = true;
    for (const [k, v] of Object.entries(h)) x.setRequestHeader(k, v);
    if (onUploadProgress) x.upload.onprogress = (e) => { if (e.lengthComputable) onUploadProgress(e.loaded, e.total); };
    x.onload = () => {
      if (x.getResponseHeader('X-FT-Api') !== '1') { bus.emit('host:challenge'); return reject(new ApiError('HOST_CHALLENGE', 'The connection needs to be refreshed. Please reload the page.', x.status)); }
      let json = null;
      try { json = x.status === 204 ? { success: true, data: null } : JSON.parse(x.responseText); } catch { return reject(new ApiError('BAD_RESPONSE', 'Unexpected response from the server.', x.status)); }
      if (x.status >= 400 || json.success === false) {
        const e = json.error || {};
        if (x.status === 401) bus.emit('auth:expired');
        return reject(notePasswordChange(new ApiError(e.code || 'HTTP_' + x.status, e.message || 'Request failed.', x.status, e.details || {})));
      }
      resolve({ data: json.data, meta: json.meta || {} });
    };
    x.onerror = () => reject(new ApiError('NETWORK', 'Network error. Check your connection and try again.', 0));
    x.onabort = () => { const e = new DOMException('Aborted', 'AbortError'); reject(e); };
    if (signal) { if (signal.aborted) { x.abort(); return; } signal.addEventListener('abort', () => x.abort(), { once: true }); }
    if (body !== undefined && !(body instanceof Blob) && !(body instanceof FormData) && !(body instanceof ArrayBuffer)) {
      x.setRequestHeader('Content-Type', 'application/json');
      x.send(JSON.stringify(body));
    } else x.send(body ?? null);
  });
}

export const api = {
  /** Configure from boot data. */
  init(config, token) { cfg = { ...cfg, ...config }; if (token) csrf = token; },
  get: (path, query) => request('GET', path, { query }),
  post: (path, body) => request('POST', path, { body }),
  put: (path, body) => request('PUT', path, { body }),
  patch: (path, body) => request('PATCH', path, { body }),
  del: (path, body) => request('DELETE', path, { body }),
  /** Low-level: {body, headers, signal, onUploadProgress, query, raw} */
  raw(method, path, opts = {}) {
    return opts.onUploadProgress ? xhr(method, path, opts) : request(method, path, opts);
  },
  /** Absolute URL for <img src>, downloads, EventSource. */
  url: (path, query) => buildUrl(path, query),
  setCsrf(token) { csrf = token || ''; },
  get csrf() { return csrf; },
  clientId,
  refreshCsrf,
};
