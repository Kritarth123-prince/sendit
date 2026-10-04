/**
 * Helpers shared by the previewer's viewers: safe content fetching and in-document find.
 * @module features/viewers/common
 */
import { ApiError } from '../../core/api.js';
import { bus } from '../../core/bus.js';

/**
 * Fetch file bytes from a same-origin API content URL.
 * A response without `X-FT-Api: 1` came from the host's cookie check, not from PHP: it is
 * reported as HOST_CHALLENGE and never shown as file content.
 * @param {string} url
 * @param {{signal?:AbortSignal, range?:[number,number], onProgress?:(loaded:number,total:number)=>void}} [o]
 * @returns {Promise<{buffer:ArrayBuffer, partial:boolean, total:number}>}
 */
export async function fetchBytes(url, { signal, range, onProgress } = {}) {
  const headers = {};
  if (range) headers.Range = 'bytes=' + range[0] + '-' + range[1];
  let res;
  try {
    res = await fetch(url, { credentials: 'same-origin', signal, headers, cache: 'no-store' });
  } catch (e) {
    if (e && e.name === 'AbortError') throw e;
    throw new ApiError('NETWORK', 'You appear to be offline. Check your connection and try again.', 0);
  }
  if (res.headers.get('X-FT-Api') !== '1') {
    bus.emit('host:challenge');
    throw new ApiError('HOST_CHALLENGE', 'The connection needs to be refreshed. Please reload the page.', res.status);
  }
  if (!res.ok) {
    let msg = 'The file could not be loaded.';
    let code = 'HTTP_' + res.status;
    try { const j = await res.json(); if (j && j.error) { msg = j.error.message || msg; code = j.error.code || code; } } catch { /* not JSON */ }
    throw new ApiError(code, msg, res.status);
  }
  const partial = res.status === 206;
  let total = parseInt(res.headers.get('Content-Length') || '0', 10) || 0;
  const cr = res.headers.get('Content-Range');
  if (cr && /\/(\d+)$/.test(cr)) total = parseInt(cr.split('/').pop(), 10);
  if (!onProgress || !res.body || !res.body.getReader) return { buffer: await res.arrayBuffer(), partial, total };
  const reader = res.body.getReader();
  const len = parseInt(res.headers.get('Content-Length') || '0', 10) || 0;
  const chunks = [];
  let loaded = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.byteLength;
    onProgress(loaded, len);
  }
  const out = new Uint8Array(loaded);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.byteLength; }
  return { buffer: out.buffer, partial, total };
}

export function escapeRe(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * All case-insensitive occurrences of query in text as [start, end) pairs.
 * @returns {Array<[number, number]>}
 */
export function findAll(text, query, max = 5000) {
  const out = [];
  if (!query) return out;
  const re = new RegExp(escapeRe(query), 'giu');
  let m;
  while ((m = re.exec(text)) && out.length < max) {
    out.push([m.index, m.index + m[0].length]);
    if (m[0].length === 0) re.lastIndex++;
  }
  return out;
}

/** Text nodes under root (in document order) with their start offsets in root's text. */
function textNodes(root) {
  const nodes = [];
  const starts = [];
  const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  let pos = 0;
  for (let n = w.nextNode(); n; n = w.nextNode()) {
    nodes.push(n);
    starts.push(pos);
    pos += n.nodeValue.length;
  }
  return { nodes, starts, length: pos };
}

/** Index of the last start <= pos (binary search). */
export function locate(starts, pos) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= pos) lo = mid; else hi = mid - 1;
  }
  return lo;
}

/**
 * Wrap text ranges of root in <mark class="find" data-i="n">. Ranges may span several text
 * nodes (e.g. across syntax-highlighting spans). Returns the marks grouped by range index.
 * @param {Element} root
 * @param {Array<[number,number]>} ranges sorted, non-overlapping
 * @returns {Array<HTMLElement[]>}
 */
export function wrapRanges(root, ranges, cls = 'find') {
  const groups = ranges.map(() => []);
  if (!ranges.length) return groups;
  const { nodes, starts } = textNodes(root);
  if (!nodes.length) return groups;
  // Work backwards so the offsets of everything before the current range stay valid.
  for (let r = ranges.length - 1; r >= 0; r--) {
    const [s, e] = ranges[r];
    let i = locate(starts, Math.max(0, e - 1));
    for (; i >= 0; i--) {
      const node = nodes[i];
      const ns = starts[i];
      const ne = ns + node.nodeValue.length;
      if (ne <= s) break;
      if (ns >= e) continue;
      const a = Math.max(s, ns) - ns;
      const b = Math.min(e, ne) - ns;
      if (b <= a) continue;
      const mid = a > 0 ? node.splitText(a) : node;
      if (b - a < mid.nodeValue.length) mid.splitText(b - a);
      const mark = document.createElement('mark');
      mark.className = cls;
      mark.dataset.i = String(r);
      mid.parentNode.insertBefore(mark, mid);
      mark.appendChild(mid);
      groups[r].unshift(mark);
    }
  }
  return groups;
}

/** Remove marks added by wrapRanges (text is kept). */
export function unwrapMarks(root, cls = 'find') {
  const marks = root.querySelectorAll('mark.' + cls);
  if (!marks.length) return;
  marks.forEach((m) => { m.replaceWith(...m.childNodes); });
  root.normalize();
}
