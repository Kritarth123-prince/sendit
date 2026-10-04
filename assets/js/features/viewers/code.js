/**
 * Text and code viewer: syntax highlighting (highlight.js from cdnjs, loaded on demand), line
 * numbers, copy, wrap and find-in-file with next/previous.
 *
 * Content is never executed or rendered: HTML, SVG and scripts are shown as highlighted source.
 * highlight.js output is parsed in an inert DOMParser document and only <span class="…"> and
 * text are copied into the page, so even a highlighter bug cannot inject markup.
 * @module features/viewers/code
 */
import { h, icon, clear, debounce } from '../../core/dom.js';
import { toast, copyText, spinner, errorState } from '../../core/ui.js';
import { bytes } from '../../core/format.js';
import { loadLib } from '../lib-loader.js';
import { fetchBytes, findAll, wrapRanges, unwrapMarks } from './common.js';

const LANG = {
  php: 'php', phtml: 'php', js: 'javascript', mjs: 'javascript', cjs: 'javascript', jsx: 'javascript',
  ts: 'typescript', tsx: 'typescript', py: 'python', java: 'java', c: 'c', h: 'c',
  cpp: 'cpp', cc: 'cpp', cxx: 'cpp', hpp: 'cpp', hh: 'cpp', html: 'xml', htm: 'xml', xhtml: 'xml',
  svg: 'xml', xml: 'xml', css: 'css', scss: 'scss', less: 'less', json: 'json', sql: 'sql',
  md: 'markdown', markdown: 'markdown', sh: 'bash', bash: 'bash', zsh: 'bash', yaml: 'yaml', yml: 'yaml',
  ini: 'ini', conf: 'ini', go: 'go', rs: 'rust', rb: 'ruby', kt: 'kotlin', swift: 'swift', cs: 'csharp',
  diff: 'diff', patch: 'diff', lua: 'lua', pl: 'perl',
};
const LABEL = { javascript: 'JavaScript', typescript: 'TypeScript', python: 'Python', xml: 'HTML/XML', markdown: 'Markdown', bash: 'Shell', cpp: 'C++', csharp: 'C#', php: 'PHP', css: 'CSS', json: 'JSON', sql: 'SQL', java: 'Java', c: 'C', yaml: 'YAML' };

/** highlight.js language for a file extension, or null for plain text. */
export function languageFor(ext) {
  return LANG[String(ext || '').toLowerCase()] || null;
}

const MAX_LOAD = 2 * 1024 * 1024;     // bytes fetched for the preview
const MAX_HIGHLIGHT = 512 * 1024;     // characters highlighted (bigger files stay plain text)
const CLASS_RE = /^[A-Za-z][\w-]*$/;

/** Copy highlight.js HTML into a fragment, keeping only <span class> and text. */
function sanitisedFragment(html) {
  const doc = new DOMParser().parseFromString('<div>' + html + '</div>', 'text/html');
  const root = doc.body.firstElementChild;
  if (!root) return null;
  const clean = (el) => {
    for (const child of Array.from(el.childNodes)) {
      if (child.nodeType === 3) continue;
      if (child.nodeType !== 1 || child.tagName !== 'SPAN') {
        child.replaceWith(doc.createTextNode(child.textContent || ''));
        continue;
      }
      const cls = (child.getAttribute('class') || '').split(/\s+/).filter((c) => CLASS_RE.test(c)).join(' ');
      for (const a of Array.from(child.attributes)) child.removeAttribute(a.name);
      if (cls) child.setAttribute('class', cls);
      clean(child);
    }
  };
  clean(root);
  const frag = document.createDocumentFragment();
  for (const n of Array.from(root.childNodes)) frag.appendChild(document.adoptNode(n));
  return frag;
}

/**
 * Mount the viewer into stage.
 * @param {HTMLElement} stage
 * @param {{url:string, file:Object, signal:AbortSignal}} o
 * @returns {{tools:HTMLElement[], destroy:Function, onKey:(e:KeyboardEvent)=>boolean}}
 */
export function mountCode(stage, { url, file, signal }) {
  const ext = String(file.ext || '').toLowerCase();
  const lang = languageFor(ext);
  let text = '';
  let ranges = [];
  let groups = [];
  let cur = -1;

  const view = h('div.code-view', { tabIndex: 0, role: 'region', 'aria-label': 'Contents of ' + file.name });
  const gutter = h('pre.code-gutter', { 'aria-hidden': 'true' });
  const code = h('code');
  const body = h('pre.code-body.hljs', code);
  const grid = h('div.code-grid', gutter, body);
  const notice = h('div.pv-notice', { hidden: true });
  const svgBox = h('div.pv-svg', { hidden: true });
  view.append(grid);
  clear(stage).append(h('div.pv-col', notice, h('div.pv-loading', spinner(), h('span', { text: 'Loading…' })), view, svgBox));
  view.hidden = true;

  // ---- tools
  const findInput = h('input.input.pv-find-input', { type: 'search', placeholder: 'Find in file', 'aria-label': 'Find in file', enterkeyhint: 'search', autocomplete: 'off', spellcheck: false });
  const count = h('span.pv-count', { 'aria-live': 'polite' });
  const prevBtn = h('button.btn.btn-sm.pv-icon', { type: 'button', 'aria-label': 'Previous match', title: 'Previous match (Shift+Enter)', on: { click: () => step(-1) } }, icon('chevron-up', 16));
  const nextBtn = h('button.btn.btn-sm.pv-icon', { type: 'button', 'aria-label': 'Next match', title: 'Next match (Enter)', on: { click: () => step(1) } }, icon('chevron-down', 16));
  const find = h('div.pv-find', { role: 'search' }, icon('search', 15), findInput, count, prevBtn, nextBtn);
  const wrapBtn = h('button.btn.btn-sm.pv-icon', { type: 'button', 'aria-pressed': 'false', 'aria-label': 'Wrap long lines', title: 'Wrap long lines', on: { click: toggleWrap } }, icon('wrap', 16));
  const copyBtn = h('button.btn.btn-sm', { type: 'button', title: 'Copy all text', on: { click: copyAll } }, icon('copy', 15), h('span.pv-lbl', { text: 'Copy' }));
  const svgBtn = ext === 'svg' ? h('button.btn.btn-sm', { type: 'button', 'aria-pressed': 'false', title: 'Show the drawing (scripts never run)', on: { click: toggleSvg } }, icon('image', 15), h('span.pv-lbl', { text: 'Image' })) : null;
  const tools = [find, wrapBtn, copyBtn, svgBtn].filter(Boolean);
  [find, wrapBtn, copyBtn].forEach((t) => { t.hidden = true; });

  findInput.addEventListener('input', debounce(runFind, 220));
  findInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); step(e.shiftKey ? -1 : 1); }
    if (e.key === 'Escape' && findInput.value) { e.preventDefault(); e.stopPropagation(); findInput.value = ''; runFind(); }
  });

  load();

  async function load() {
    try {
      const size = Number(file.size) || 0;
      const { buffer, partial, total } = await fetchBytes(url, { signal, range: size > MAX_LOAD ? [0, MAX_LOAD - 1] : undefined });
      text = new TextDecoder('utf-8').decode(buffer);
      if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
      const loading = stage.querySelector('.pv-loading');
      loading && loading.remove();
      const notes = [];
      if (partial || (size > MAX_LOAD && buffer.byteLength < size)) notes.push('Showing the first ' + bytes(buffer.byteLength) + ' of ' + bytes(total || size) + '. Download the file to see all of it.');
      paintGutter();
      let highlighted = false;
      if (lang && text.length <= MAX_HIGHLIGHT) {
        try {
          const hljs = await loadLib('hljs');
          if (signal.aborted) return;
          if (hljs.getLanguage(lang)) {
            const frag = sanitisedFragment(hljs.highlight(text, { language: lang, ignoreIllegals: true }).value);
            if (frag) { code.appendChild(frag); highlighted = true; }
          }
        } catch { /* fall back to plain text */ }
      } else if (lang) {
        notes.push('Syntax highlighting is off for large files.');
      }
      if (!highlighted) code.textContent = text;
      code.className = highlighted ? 'language-' + lang : '';
      view.dataset.lang = lang ? (LABEL[lang] || lang) : 'Plain text';
      if (notes.length) { notice.textContent = notes.join(' '); notice.hidden = false; }
      view.hidden = false;
      [find, wrapBtn, copyBtn].forEach((t) => { t.hidden = false; });
      if (!text.length) { notice.textContent = 'This file is empty.'; notice.hidden = false; }
    } catch (e) {
      if (e && e.name === 'AbortError') return;
      clear(stage).appendChild(h('div.pv-col.pv-pad', errorState(e)));
    }
  }

  function paintGutter() {
    let lines = 1;
    for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) lines++;
    const nums = new Array(lines);
    for (let i = 0; i < lines; i++) nums[i] = i + 1;
    gutter.textContent = nums.join('\n');
  }

  function runFind() {
    unwrapMarks(code);
    const q = findInput.value;
    ranges = q ? findAll(text, q) : [];
    groups = wrapRanges(code, ranges);
    cur = -1;
    if (!q) { count.textContent = ''; return; }
    if (!ranges.length) { count.textContent = 'No matches'; return; }
    step(1);
  }

  function step(d) {
    if (!ranges.length) { if (findInput.value && d) findInput.focus(); return; }
    if (cur >= 0) groups[cur].forEach((m) => m.classList.remove('current'));
    cur = (cur + d + ranges.length) % ranges.length;
    groups[cur].forEach((m) => m.classList.add('current'));
    count.textContent = (cur + 1) + ' of ' + ranges.length + (ranges.length >= 5000 ? '+' : '');
    groups[cur][0]?.scrollIntoView({ block: 'center', inline: 'nearest' });
  }

  function toggleWrap() {
    const on = !view.classList.contains('wrap');
    view.classList.toggle('wrap', on);
    wrapBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
  }

  async function copyAll() {
    if (await copyText(text)) toast('Copied ' + (text.length > 1 ? text.split('\n').length + ' lines' : 'text'), { type: 'ok', timeout: 1800 });
    else toast('Could not copy. Select the text and copy it manually.', { type: 'warn' });
  }

  function toggleSvg() {
    const on = svgBox.hidden;
    svgBox.hidden = !on;
    view.hidden = on;
    find.hidden = on;
    svgBtn.setAttribute('aria-pressed', on ? 'true' : 'false');
    if (on && !svgBox.firstChild) {
      // An SVG inside <img> cannot run scripts or load anything. A data: URL (not a blob: URL)
      // because "Open image in new tab" on a blob: URL would create a same-origin SVG document
      // whose scripts run with the app's origin; a data: document gets an opaque origin (and
      // browsers refuse top-level navigation to data: URLs anyway).
      svgBox.appendChild(h('img', { src: svgDataUrl(text), alt: file.name }));
    }
  }

  return {
    tools,
    onKey(e) {
      if ((e.ctrlKey || e.metaKey) && (e.key === 'f' || e.key === 'F')) { e.preventDefault(); findInput.focus(); findInput.select(); return true; }
      if (e.key === 'F3') { e.preventDefault(); step(e.shiftKey ? -1 : 1); return true; }
      return false;
    },
    destroy() { clear(svgBox); },
  };
}

/** data:image/svg+xml;base64,… for SVG source text (UTF-8, encoded in chunks). */
export function svgDataUrl(text) {
  const buf = new TextEncoder().encode(String(text));
  let bin = '';
  for (let i = 0; i < buf.length; i += 0x8000) bin += String.fromCharCode.apply(null, buf.subarray(i, i + 0x8000));
  return 'data:image/svg+xml;base64,' + btoa(bin);
}
