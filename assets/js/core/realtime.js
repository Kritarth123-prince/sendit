/**
 * Real-time synchronisation client.
 *
 * - One "leader" tab per browser holds the network connection (navigator.locks, or a
 *   localStorage lease) and relays events to the other tabs (BroadcastChannel, or localStorage
 *   'storage' events). Every tab emits each server event on the bus under its type.
 * - Transport: SSE (hosts that can hold requests) → long-poll → short poll (byethost free).
 *   Short polls are adaptive: every poll_seconds (REALTIME_POLL_SECONDS, default 4 s) while in
 *   use, max(15 s, 2 × poll_seconds) when idle, max(60 s, 4 × poll_seconds) when hidden; at least
 *   1.15 s apart; immediate on focus, network return or a local change (realtime.nudge()).
 * - 429 answers are never shown as a disconnection: the client waits as asked (Retry-After).
 *   When the server refuses a held connection (SSE / long-poll answered 429, e.g. because another
 *   device of the account already holds one), the client quietly short-polls for a while and
 *   tries the held transport again later.
 * - After every (re)connect the client asks GET /events?after=<last id> so nothing is missed;
 *   if the history is gone the server says reset → bus 'sync.reset' (views refresh their data).
 * - Exponential back-off with jitter (1, 2, 4, 8, 16, 30 s).
 * @module core/realtime
 */
import { api } from './api.js';
import { bus } from './bus.js';
import { store } from './store.js';

// ---------------------------------------------------------------- pure helpers (unit-tested)

export const MIN_POLL_GAP_MS = 1150;
export const IDLE_AFTER_MS = 120000;

/** Bounded set of recently seen event ids. */
export class SeenSet {
  constructor(max = 500) { this.max = max; this.set = new Set(); }
  has(id) { return this.set.has(id); }
  add(id) {
    this.set.add(id);
    if (this.set.size > this.max) this.set.delete(this.set.values().next().value);
  }
}

/** Back-off delay in ms for attempt n (0-based), capped at 30 s, with ±20 % jitter. */
export function backoffDelay(n, rand = Math.random) {
  const base = [1, 2, 4, 8, 16, 30][Math.min(n, 5)] * 1000;
  return Math.round(base * (0.8 + rand() * 0.4));
}

/**
 * Poll interval (ms) for the current activity state: poll_seconds while in use (at least 2 s),
 * max(15 s, 2 × that) after 2 minutes idle, max(60 s, 4 × that) when hidden — so a larger
 * REALTIME_POLL_SECONDS never makes active polling slower than idle polling.
 */
export function pollInterval({ visible, idleMs, pollSeconds = 4 }) {
  const active = Math.max(2, Number(pollSeconds) || 4) * 1000;
  if (!visible) return Math.max(60000, 4 * active);
  if (idleMs > IDLE_AFTER_MS) return Math.max(15000, 2 * active);
  return active;
}

/** Seconds from a Retry-After value (delta-seconds or HTTP date), clamped to [min, max]. */
export function retryAfterSeconds(value, { min = 1, max = 30, now = Date.now() } = {}) {
  let s = NaN;
  const v = String(value ?? '').trim();
  if (/^\d+$/.test(v)) s = parseInt(v, 10);
  else if (v) { const t = Date.parse(v); if (!Number.isNaN(t)) s = Math.ceil((t - now) / 1000); }
  if (!Number.isFinite(s)) s = min;
  return Math.min(max, Math.max(min, s));
}

/** How long (ms) to short-poll after the n-th (0-based) refused held connection: 1, 2, 4 … 10 min. */
export function heldCooldown(n, retryAfter = 0) {
  const base = Math.min(600, 60 * 2 ** Math.min(n, 4));
  return Math.max(base, Math.min(600, retryAfter)) * 1000;
}

// ---------------------------------------------------------------- state

let opts = null;
let running = false;
let isLeader = false;
let releaseLeader = null;
let channel = null;
let lastId = 0;
const seen = new SeenSet();
let transport = null; // 'sse' | 'longpoll' | 'poll'
let es = null;
let pollTimer = null;
let pollAbort = null;
let attempt = 0;
let lastActivity = Date.now();
let tickTimer = null;
let wasDisconnected = false;
let lastPollAt = 0;
let resumeHeld = null;   // held transport to return to after a 429 ('sse' | 'longpoll')
let resumeAt = 0;
let heldStrikes = 0;

const lsKey = () => 'ft:last-event:' + opts.userId;
const setLive = (s) => store.set('live', s);

function saveLastId(id) {
  if (id > lastId) {
    lastId = id;
    try { localStorage.setItem(lsKey(), String(id)); } catch { /* private mode */ }
  }
}

/** Deliver one event to this tab's bus (deduplicated). */
function deliver(evt, relay) {
  if (!evt || typeof evt.event_id !== 'number' || typeof evt.type !== 'string') return;
  if (seen.has(evt.event_id)) return;
  seen.add(evt.event_id);
  saveLastId(evt.event_id);
  if (evt.type === 'session.revoked') {
    const me = store.get('user');
    const sid = evt.data && evt.data.session_id;
    if (sid === null || sid === undefined || (me && sid === me.session_id)) bus.emit('auth:revoked', evt);
  }
  bus.emit(evt.type, evt);
  bus.emit('event', evt);
  if (relay) relayToTabs({ kind: 'event', evt });
}

function relayToTabs(msg) {
  try {
    if (channel) channel.postMessage(msg);
    else localStorage.setItem('ft:relay:' + opts.userId, JSON.stringify({ ...msg, n: Math.random() }));
  } catch { /* ignore */ }
}

function onRelay(msg) {
  if (!msg) return;
  if (msg.kind === 'event') deliver(msg.evt, false);
  else if (msg.kind === 'status') setLive(msg.status);
  else if (msg.kind === 'reset') bus.emit('sync.reset', {});
  else if (msg.kind === 'nudge' && isLeader) schedulePoll(300);
}

// ---------------------------------------------------------------- leader election

function becomeLeader() {
  if (isLeader || !running) return;
  isLeader = true;
  connect();
  startTick();
}

function electLeader() {
  const name = 'ft-realtime-' + opts.userId;
  if (navigator.locks && navigator.locks.request) {
    navigator.locks.request(name, () => new Promise((resolve) => { releaseLeader = resolve; becomeLeader(); }));
    return;
  }
  // Fallback lease: the leader refreshes a timestamp every 3 s; others take over after 8 s.
  const key = 'ft:leader:' + opts.userId;
  const me = Math.random().toString(36).slice(2);
  const check = () => {
    if (!running) return;
    let cur = null;
    try { cur = JSON.parse(localStorage.getItem(key) || 'null'); } catch { cur = null; }
    const now = Date.now();
    if (!cur || cur.id === me || now - cur.t > 8000) {
      try { localStorage.setItem(key, JSON.stringify({ id: me, t: now })); } catch { /* ignore */ }
      becomeLeader();
    }
  };
  check();
  const iv = setInterval(check, 3000);
  window.addEventListener('beforeunload', () => {
    try { const cur = JSON.parse(localStorage.getItem(key) || 'null'); if (cur && cur.id === me) localStorage.removeItem(key); } catch { /* ignore */ }
  });
  releaseLeader = () => clearInterval(iv);
}

// ---------------------------------------------------------------- transports

function chooseTransport() {
  const rt = opts.realtime || {};
  const remembered = (() => { try { return localStorage.getItem('ft:transport'); } catch { return null; } })();
  if (rt.mode === 'poll' || !rt.can_hold) return 'poll';
  if (rt.mode === 'sse' || rt.mode === 'longpoll') return rt.mode;
  if (remembered === 'poll' || remembered === 'longpoll') return remembered;
  return typeof EventSource !== 'undefined' ? 'sse' : 'longpoll';
}

async function recover() {
  // Ask for anything missed while disconnected, in order, before resuming.
  let more = true;
  let guard = 0;
  while (more && guard++ < 20) {
    const { data, meta } = await api.get('/events', { after: lastId, limit: 200 });
    if (meta && meta.reset) {
      saveLastId(meta.last_id || 0);
      bus.emit('sync.reset', {});
      relayToTabs({ kind: 'reset' });
      return;
    }
    (data || []).forEach((e) => deliver(e, true));
    more = !!(meta && meta.has_more);
  }
}

async function connect() {
  if (!running || !isLeader) return;
  transport = transport || chooseTransport();
  setLive(attempt > 0 || wasDisconnected ? 'reconnecting' : 'connecting');
  try {
    await recover();
  } catch (e) {
    return fail(e);
  }
  if (transport === 'sse') openSse();
  else schedulePoll(0);
}

function connected() {
  const was = attempt > 0 || wasDisconnected;
  attempt = 0;
  wasDisconnected = false;
  const s = was ? 'reconnected' : 'connected';
  setLive(s);
  relayToTabs({ kind: 'status', status: s });
  if (s === 'reconnected') setTimeout(() => { if (store.get('live') === 'reconnected') { setLive('connected'); relayToTabs({ kind: 'status', status: 'connected' }); } }, 2500);
}

function fail(err) {
  if (!running) return;
  if (err && err.code === 'UNAUTHENTICATED') { stop(); return; }
  if (err && (err.status === 429 || err.code === 'PASSWORD_CHANGE_REQUIRED')) {
    // Rate limited (e.g. the recovery request), or the account must change its password first
    // (the shell shows that dialog): not a disconnection — wait, quietly.
    clearTimeout(pollTimer);
    pollTimer = setTimeout(connect, err.status === 429 ? retryAfterSeconds(err.details?.retry_after) * 1000 : 30000);
    return;
  }
  wasDisconnected = true;
  const delay = backoffDelay(attempt++);
  const s = navigator.onLine === false ? 'disconnected' : 'reconnecting';
  setLive(s);
  relayToTabs({ kind: 'status', status: s });
  clearTimeout(pollTimer);
  pollTimer = setTimeout(connect, delay);
}

function openSse() {
  closeSse();
  let opened = false;
  const url = api.url('/events/stream', { after: lastId });
  try { es = new EventSource(url, { withCredentials: true }); } catch (e) { transport = 'longpoll'; return schedulePoll(0); }
  const guard = setTimeout(() => {
    if (!opened) { // proxy buffering: fall back
      closeSse();
      transport = 'longpoll';
      try { localStorage.setItem('ft:transport', 'longpoll'); } catch { /* ignore */ }
      schedulePoll(0);
    }
  }, 8000);
  es.addEventListener('open', () => { opened = true; heldStrikes = 0; clearTimeout(guard); connected(); });
  es.addEventListener('ft', (m) => { try { deliver(JSON.parse(m.data), true); } catch { /* ignore */ } });
  es.addEventListener('reset', (m) => { try { saveLastId(JSON.parse(m.data).last_id || 0); } catch { /* ignore */ } bus.emit('sync.reset', {}); relayToTabs({ kind: 'reset' }); });
  es.addEventListener('bye', () => { closeSse(); setTimeout(openSse, 200); });
  es.onerror = () => {
    clearTimeout(guard);
    closeSse();
    if (opened) { fail(); return; }
    // The stream never opened. EventSource cannot see the status (a 429 for a held connection, a
    // 503 or a network error look the same), so let a long-poll find out: it falls back to short
    // polling on 429 and reports a real disconnection through fail() — no "Reconnecting" here.
    transport = 'longpoll';
    schedulePoll(0);
  };
}

/** The server refused a held connection (429): short-poll quietly, retry the held transport later. */
function holdOff(retryAfter) {
  if (transport !== 'poll') resumeHeld = transport;
  resumeAt = Date.now() + heldCooldown(heldStrikes++, retryAfter);
  transport = 'poll';
  closeSse();
}

function closeSse() { if (es) { try { es.close(); } catch { /* ignore */ } es = null; } }

function schedulePoll(delay) {
  if (!running || !isLeader || transport === 'sse') return;
  clearTimeout(pollTimer);
  pollTimer = setTimeout(pollOnce, delay);
}

let polling = false;    // a poll request is in flight
let pollQueued = false; // a poll was asked for meanwhile (nudge, focus, relay)

/**
 * Never two polls at once: a poll asked for while one is in flight runs MIN_POLL_GAP_MS after
 * that one's answer (unless the answer set its own delay: Retry-After, back-off, more events).
 */
async function pollOnce() {
  if (polling) { pollQueued = true; return; }
  polling = true;
  let normal = false;
  try {
    normal = await pollRequest();
  } finally {
    polling = false;
    if (pollQueued) {
      pollQueued = false;
      if (normal && running && isLeader && transport === 'poll') schedulePoll(MIN_POLL_GAP_MS);
    }
  }
}

/** One poll; true when it ended normally and scheduled the regular next poll. */
async function pollRequest() {
  if (!running || !isLeader) return false;
  // The server's no-database fast path (wait=0) allows one poll per second per session (else
  // 429): several quick nudges after local changes collapse into one poll. The gap is measured
  // from the previous answer, because a busy server may handle a queued poll late.
  const gap = Date.now() - lastPollAt;
  if (transport !== 'longpoll' && gap < MIN_POLL_GAP_MS) {
    clearTimeout(pollTimer);
    pollTimer = setTimeout(pollOnce, MIN_POLL_GAP_MS - gap);
    return false;
  }
  lastPollAt = Date.now();
  pollAbort = new AbortController();
  const wait = transport === 'longpoll' ? (opts.realtime?.hold_seconds || 20) : 0;
  try {
    const res = await api.raw('GET', '/events/poll', { query: { after: lastId, wait }, signal: pollAbort.signal, raw: true });
    lastPollAt = Date.now();
    if (res.status === 429) {
      if (wait > 0) {
        // No held connection for us right now: short-poll instead, without "Reconnecting".
        holdOff(retryAfterSeconds(res.headers.get('Retry-After'), { max: 600 }));
        schedulePoll(MIN_POLL_GAP_MS);
        return false;
      }
      // Too soon for the server's short-poll guard: wait as asked without reporting a disconnection.
      schedulePoll(retryAfterSeconds(res.headers.get('Retry-After')) * 1000);
      return false;
    }
    if (wait > 0 && (res.status === 204 || res.ok)) heldStrikes = 0;
    if (res.status === 204) {
      connected();
    } else if (res.ok) {
      const json = await res.json();
      if (json.meta && json.meta.reset) { saveLastId(json.meta.last_id || 0); bus.emit('sync.reset', {}); relayToTabs({ kind: 'reset' }); }
      (json.data || []).forEach((e) => deliver(e, true));
      connected();
      if (json.meta && json.meta.has_more) { schedulePoll(0); return false; }
    } else if (res.status === 401) {
      fail({ code: 'UNAUTHENTICATED' });
      return false;
    } else if (res.status === 403) {
      // e.g. PASSWORD_CHANGE_REQUIRED (api.js tells the shell): try again later, quietly.
      schedulePoll(30000);
      return false;
    } else if (res.status === 404 || res.status === 503) {
      if (transport === 'longpoll') transport = 'poll';
      fail();
      return false;
    } else {
      fail();
      return false;
    }
  } catch (e) {
    if (e && e.name !== 'AbortError') fail(e);
    return false;
  }
  if (transport === 'poll' && resumeHeld && Date.now() >= resumeAt) {
    // Cool-down over: try the held connection again (a new 429 extends the cool-down).
    transport = resumeHeld;
    resumeHeld = null;
    if (transport === 'sse') openSse(); else schedulePoll(100);
    return false;
  }
  const next = transport === 'longpoll' ? 100 : pollInterval({ visible: document.visibilityState === 'visible', idleMs: Date.now() - lastActivity, pollSeconds: opts.realtime?.poll_seconds || 4 });
  schedulePoll(next);
  return true;
}

function startTick() {
  // Background work on hosts without cron: the leader calls /tick about once a minute.
  clearInterval(tickTimer);
  tickTimer = setInterval(() => {
    if (document.visibilityState !== 'visible' || !isLeader) return;
    api.post('/tick').catch(() => { /* route may not exist yet */ });
  }, 60000);
}

// ---------------------------------------------------------------- public API

function onActivity() { lastActivity = Date.now(); }
function onVisible() {
  if (document.visibilityState === 'visible') { onActivity(); realtime.nudge(); }
}

export const realtime = {
  /** @param {{userId:number, lastEventId:number, isAdmin:boolean, realtime:Object}} o */
  start(o) {
    if (running) return;
    opts = o;
    running = true;
    let stored = 0;
    try { stored = parseInt(localStorage.getItem(lsKey()) || '0', 10) || 0; } catch { stored = 0; }
    lastId = Math.max(o.lastEventId || 0, stored);
    if (o.lastEventId && stored > o.lastEventId + 100000) lastId = o.lastEventId; // DB was reset
    try {
      if (typeof BroadcastChannel !== 'undefined') {
        channel = new BroadcastChannel('ft-events-' + o.userId);
        channel.onmessage = (m) => onRelay(m.data);
      } else {
        window.addEventListener('storage', (e) => {
          if (e.key === 'ft:relay:' + o.userId && e.newValue) { try { onRelay(JSON.parse(e.newValue)); } catch { /* ignore */ } }
        });
      }
    } catch { channel = null; }
    ['pointerdown', 'keydown', 'scroll'].forEach((ev) => window.addEventListener(ev, onActivity, { passive: true }));
    document.addEventListener('visibilitychange', onVisible);
    window.addEventListener('focus', onVisible);
    window.addEventListener('online', onOnline);
    window.addEventListener('offline', () => setLive('disconnected'));
    setLive('connecting');
    electLeader();
  },
  stop,
  status: () => store.get('live'),
  lastEventId: () => lastId,
  /** Poll soon (after a local change, focus or network return). */
  nudge() {
    if (!running) return;
    if (isLeader) {
      if (transport === 'sse') { if (!es) connect(); }
      // Skip only while a long-poll is genuinely in flight (it will deliver the change itself).
      // (pollAbort is never cleared, so it cannot tell whether a request is running.)
      else { clearTimeout(pollTimer); pollTimer = setTimeout(() => { if (polling && transport === 'longpoll') return; pollOnce(); }, 800); }
    } else relayToTabs({ kind: 'nudge' });
  },
  /** Share a locally-produced event with other tabs immediately (they dedupe by event_id). */
  broadcastLocal(evt) { relayToTabs({ kind: 'event', evt }); },
};

/**
 * The network came back: reconnect now instead of waiting out the back-off. connect() first
 * recovers every missed event (GET /events?after=…) and then reopens the best transport, so a
 * short outage that made SSE fall back to long-polling does not leave the device on the fallback.
 */
function onOnline() {
  attempt = 0;
  if (!running) return;
  if (!isLeader) { relayToTabs({ kind: 'nudge' }); return; }
  clearTimeout(pollTimer);
  if (Date.now() >= resumeAt) transport = null; // not inside a 429 hold-off: choose afresh (SSE again in auto mode)
  connect();
}

function stop() {
  running = false;
  isLeader = false;
  clearTimeout(pollTimer);
  clearInterval(tickTimer);
  pollAbort && pollAbort.abort();
  closeSse();
  if (releaseLeader) { releaseLeader(); releaseLeader = null; }
  if (channel) { try { channel.close(); } catch { /* ignore */ } channel = null; }
  setLive('disconnected');
}
