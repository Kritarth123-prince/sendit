/**
 * UI primitives: toasts, modals (bottom sheets on phones), confirm/prompt, menus, states.
 * All text goes through textContent — never innerHTML with untrusted data.
 * @module core/ui
 */
import { h, icon, clear } from './dom.js';

const MAX_TOASTS = 4;
const toastIds = new Map();
const isSmall = () => window.matchMedia('(max-width: 599px)').matches;
const isTouch = () => window.matchMedia('(hover: none)').matches;

/**
 * @param {string} message
 * @param {{type?:'ok'|'err'|'info'|'warn', timeout?:number, action?:{label:string,onClick:Function}, id?:string}} [o]
 */
export function toast(message, { type = 'ok', timeout = 3500, action, id } = {}) {
  const root = document.getElementById('toasts') || document.body.appendChild(h('div.toasts', { id: 'toasts' }));
  if (id && toastIds.has(id)) toastIds.get(id).remove();
  const names = { ok: 'check', err: 'warning', warn: 'warning', info: 'info' };
  const el = h('div.toast.' + type, { role: type === 'err' ? 'alert' : 'status' },
    icon(names[type] || 'info', 18),
    h('span.toast-msg', { text: message }),
    action ? h('button.toast-action', { type: 'button', text: action.label, on: { click: () => { action.onClick(); dismiss(); } } }) : null,
    h('button.icon-btn.sm', { type: 'button', 'aria-label': 'Dismiss', on: { click: () => dismiss() } }, icon('x', 14)));
  const dismiss = () => {
    if (!el.isConnected) return;
    el.classList.add('out');
    setTimeout(() => el.remove(), 250);
    if (id) toastIds.delete(id);
  };
  root.appendChild(el);
  while (root.children.length > MAX_TOASTS) root.firstChild.remove();
  if (id) toastIds.set(id, el);
  if (timeout > 0) setTimeout(dismiss, timeout);
  return { dismiss };
}

let modalStack = [];

/**
 * @param {{title:string, content:Node|string, actions?:Array<{label:string, kind?:'primary'|'danger'|'ghost', onClick?:(close:Function)=>any, autofocus?:boolean, close?:boolean}>, size?:'sm'|'md'|'lg'|'xl'|'full', onClose?:Function, dismissible?:boolean}} o
 * @returns {{el:HTMLElement, body:HTMLElement, close:Function, setBusy:(b:boolean)=>void}}
 */
export function modal({ title, content, actions = [], size = 'md', onClose, dismissible = true }) {
  const root = document.getElementById('modal-root') || document.body;
  const prevFocus = document.activeElement;
  const body = h('div.modal-body');
  if (content instanceof Node) body.appendChild(content);
  else if (content !== undefined) body.appendChild(h('p', { text: content }));
  const titleId = 'm' + Math.random().toString(36).slice(2, 8);
  const buttons = actions.map((a) => h('button.btn' + (a.kind === 'primary' ? '.btn-primary' : a.kind === 'danger' ? '.btn-danger' : a.kind === 'ghost' ? '.btn-ghost' : ''), {
    type: 'button', text: a.label, autofocus: a.autofocus || undefined,
    on: { click: async () => { if (a.onClick) { const r = await a.onClick(close); if (r === false) return; } if (a.close !== false) close(); } },
  }));
  const box = h('div.modal' + (size !== 'md' ? '.' + size : ''), { role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId },
    h('div.modal-head', h('h2.modal-title', { id: titleId, text: title }),
      dismissible ? h('button.icon-btn.sm', { type: 'button', 'aria-label': 'Close', on: { click: () => close() } }, icon('x', 16)) : null),
    body,
    buttons.length ? h('div.modal-foot', buttons) : null);
  const overlay = h('div.modal-overlay', { on: { mousedown: (e) => { if (dismissible && e.target === overlay) close(); } } }, box);
  const onKey = (e) => {
    if (modalStack[modalStack.length - 1] !== overlay) return;
    if (e.key === 'Escape' && dismissible) { e.preventDefault(); close(); }
    if (e.key === 'Tab') trapFocus(box, e);
  };
  let closed = false;
  function close() {
    if (closed) return;
    closed = true;
    document.removeEventListener('keydown', onKey);
    overlay.remove();
    modalStack = modalStack.filter((m) => m !== overlay);
    if (!modalStack.length) document.body.style.overflow = '';
    if (prevFocus && prevFocus.focus) prevFocus.focus();
    onClose && onClose();
  }
  document.addEventListener('keydown', onKey);
  root.appendChild(overlay);
  modalStack.push(overlay);
  document.body.style.overflow = 'hidden';
  setTimeout(() => {
    const f = box.querySelector('[autofocus], input:not([type=hidden]), textarea, select') || box.querySelector('.modal-foot .btn-primary') || box.querySelector('button');
    f && f.focus();
  }, 30);
  return {
    el: box, body, close,
    setBusy(b) { buttons.forEach((x) => { x.disabled = b; }); },
  };
}

function trapFocus(box, e) {
  if (e.defaultPrevented) return; // e.g. a code editor that uses Tab for indentation
  const f =Array.from(box.querySelectorAll('a[href],button:not([disabled]),input:not([disabled]):not([type=hidden]),select,textarea,[tabindex]:not([tabindex="-1"])')).filter((x) => x.offsetParent !== null);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
  else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
}

/** @returns {Promise<boolean>} */
export function confirm({ title = 'Are you sure?', message = '', confirmText = 'Confirm', danger = false } = {}) {
  return new Promise((resolve) => {
    let result = false;
    modal({
      title, content: message, size: 'sm',
      actions: [
        { label: 'Cancel', kind: 'ghost' },
        { label: confirmText, kind: danger ? 'danger' : 'primary', autofocus: true, onClick: () => { result = true; } },
      ],
      onClose: () => resolve(result),
    });
  });
}

/** @returns {Promise<string|null>} */
export function prompt({ title, label = '', value = '', placeholder = '', confirmText = 'Save', validate, type = 'text' } = {}) {
  return new Promise((resolve) => {
    let result = null;
    const input = h('input.input', { type, value, placeholder, 'aria-label': label || title });
    const err = h('div.form-error', { role: 'alert' });
    const submit = (close) => {
      const v = input.value.trim();
      const msg = validate ? validate(v) : (v === '' ? 'Please enter a value.' : null);
      if (msg) { err.textContent = msg; input.focus(); return false; }
      result = v;
      if (close) close();
      return true;
    };
    const m = modal({
      title, size: 'sm',
      content: h('div.field', label ? h('label', { text: label }) : null, input, err),
      actions: [{ label: 'Cancel', kind: 'ghost' }, { label: confirmText, kind: 'primary', onClick: () => submit() }],
      onClose: () => resolve(result),
    });
    input.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); if (submit()) m.close(); } });
    setTimeout(() => { input.focus(); input.select(); }, 40);
  });
}

let openMenu = null;
/**
 * Context menu anchored to an element (or a {x,y} point); a bottom sheet on touch/small screens.
 * @param {HTMLElement|{x:number,y:number}} anchor
 * @param {Array<{label:string, icon?:string, onClick:Function, danger?:boolean, disabled?:boolean}|'-'>} items
 */
export function menu(anchor, items) {
  closeMenu();
  const sheet = isSmall() || isTouch();
  const prevFocus = document.activeElement;
  const el = h('div.menu' + (sheet ? '.sheet' : ''), { role: 'menu' });
  for (const it of items) {
    if (it === '-' || !it) { if (it === '-') el.appendChild(h('hr')); continue; }
    el.appendChild(h('button' + (it.danger ? '.danger' : ''), {
      type: 'button', role: 'menuitem', disabled: it.disabled || undefined,
      on: { click: () => { closeMenu(); it.onClick && it.onClick(); } },
    }, it.icon ? icon(it.icon, 17) : null, h('span', { text: it.label })));
  }
  const scrim = h('div.menu-scrim', { on: { click: closeMenu, contextmenu: (e) => { e.preventDefault(); closeMenu(); } } });
  if (!sheet) scrim.style.background = 'transparent';
  document.body.append(scrim, el);
  if (!sheet) {
    const r = anchor instanceof Element ? anchor.getBoundingClientRect() : { left: anchor.x, right: anchor.x, top: anchor.y, bottom: anchor.y };
    const mw = el.offsetWidth, mh = el.offsetHeight;
    let left = Math.min(r.left, window.innerWidth - mw - 8);
    let top = r.bottom + 4;
    if (top + mh > window.innerHeight - 8) top = Math.max(8, r.top - mh - 4);
    el.style.left = Math.max(8, left) + 'px';
    el.style.top = top + 'px';
  }
  const btns = () => Array.from(el.querySelectorAll('button:not([disabled])'));
  el.addEventListener('keydown', (e) => {
    const list = btns(); const i = list.indexOf(document.activeElement);
    if (e.key === 'ArrowDown') { e.preventDefault(); list[(i + 1) % list.length]?.focus(); }
    if (e.key === 'ArrowUp') { e.preventDefault(); list[(i - 1 + list.length) % list.length]?.focus(); }
    if (e.key === 'Escape') { e.preventDefault(); closeMenu(); prevFocus?.focus?.(); }
  });
  openMenu = { el, scrim };
  btns()[0]?.focus();
}
export function closeMenu() {
  if (openMenu) { openMenu.el.remove(); openMenu.scrim.remove(); openMenu = null; }
}

export function emptyState({ icon: ic = 'folder', title = 'Nothing here yet', text = '', action } = {}) {
  return h('div.empty-state', icon(ic, 44), h('h3', { text: title }), text ? h('p', { text }) : null,
    action ? h('button.btn.btn-primary', { type: 'button', on: { click: action.onClick } }, action.icon ? icon(action.icon, 16) : null, action.label) : null);
}

export function errorState(err, onRetry) {
  return h('div.error-state', { role: 'alert' }, icon('warning', 20),
    h('span.grow', { text: (err && err.message) || 'Something went wrong.' }),
    onRetry ? h('button.btn.btn-sm', { type: 'button', text: 'Try again', on: { click: onRetry } }) : null);
}
/**
 * Ask for the current password before a sensitive action. onConfirm(password) runs while the
 * dialog stays open; if it throws, the error is shown inline and the user can try again.
 * Resolves with onConfirm's result, or null when cancelled. The password is never stored.
 * @param {{title:string, message?:string, confirmText?:string, danger?:boolean, extra?:Node, onConfirm:(password:string)=>Promise<any>}} o
 * @returns {Promise<any|null>}
 */
export function passwordPrompt({ title, message = 'Enter your current password to continue.', confirmText = 'Continue', danger = false, extra = null, onConfirm }) {
  return new Promise((resolve) => {
    let result = null;
    const input = h('input.input', { type: 'password', autocomplete: 'current-password', required: true });
    const err = h('div.form-error', { role: 'alert' });
    const submit = async (m) => {
      err.textContent = '';
      if (!input.value) { err.textContent = 'Enter your current password.'; input.focus(); return false; }
      m && m.setBusy(true);
      try {
        result = await onConfirm(input.value);
        input.value = '';
        return true;
      } catch (e) {
        const f = (e && e.details && e.details.fields) || {};
        err.textContent = f.current_password || f.password || (e && e.message) || 'That did not work. Please try again.';
        input.select();
        return false;
      } finally {
        m && m.setBusy(false);
      }
    };
    const m = modal({
      title, size: 'sm',
      content: h('div.stack', message ? h('p.text2', { text: message }) : null, extra,
        h('div.field', h('label', { text: 'Current password' }), input), err),
      actions: [{ label: 'Cancel', kind: 'ghost' }, { label: confirmText, kind: danger ? 'danger' : 'primary', onClick: () => submit(m) }],
      onClose: () => { input.value = ''; resolve(result); },
    });
    input.addEventListener('keydown', async (e) => { if (e.key === 'Enter') { e.preventDefault(); if (await submit(m)) m.close(); } });
  });
}

export function spinner() { return h('span.spinner', { 'aria-hidden': 'true' }); }

export function skeleton(rows = 3) {
  return h('div.view-loading', { 'aria-busy': 'true', 'aria-label': 'Loading' }, Array.from({ length: rows }, () => h('div.skel')));
}

/** Replace a container's content. */
export function render(container, ...nodes) {
  clear(container);
  nodes.flat().forEach((n) => n && container.appendChild(n));
}

/** Copy text to the clipboard with a fallback. */
export async function copyText(text) {
  try { await navigator.clipboard.writeText(text); return true; } catch {
    const t = h('textarea', { style: { position: 'fixed', left: '-9999px' } });
    t.value = text; document.body.appendChild(t); t.select();
    let ok = false; try { ok = document.execCommand('copy'); } catch { ok = false; }
    t.remove(); return ok;
  }
}
