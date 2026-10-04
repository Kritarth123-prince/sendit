/**
 * Clipboard: the legacy "Save Text or URL" feature — saved texts and links with rich previews,
 * copy, edit, "Keep forever" and auto-expiry countdowns. Live across devices.
 */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { bus } from '../core/bus.js';
import { dayLabel, time, countdown } from '../core/format.js';
import { toast, confirm, prompt, emptyState, errorState, skeleton, copyText } from '../core/ui.js';
import { realtime } from '../core/realtime.js';

let offs = [];
export default {
  title: 'Clipboard',
  mount(el) {
    const ta = h('textarea.textarea', { placeholder: 'Paste text or a link — links get a preview…', 'aria-label': 'Text or link to save', maxlength: 50000 });
    const keep = h('input', { type: 'checkbox' });
    const save = h('button.btn.btn-primary', { type: 'submit' }, icon('check', 16), 'Save');
    const form = h('form.card.stack', { on: { submit: async (e) => {
      e.preventDefault();
      const content = ta.value.trim();
      if (!content) return;
      save.disabled = true;
      try { await api.post('/texts', { content, is_permanent: keep.checked }); ta.value = ''; toast('Saved', { type: 'ok', timeout: 1800 }); realtime.nudge(); load(); } catch (ex) { toast(ex.message, { type: 'err' }); } finally { save.disabled = false; }
    } } }, ta, h('div.row.wrap', h('label.toggle', keep, h('span.track'), h('span', { text: 'Keep forever' })), h('span.grow'), save));
    const listEl = h('div');
    el.append(h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Clipboard' }), h('div.view-sub', { text: 'Save snippets and links and open them on any device.' }))), form, h('div.section-gap', listEl));

    async function load() {
      if (!listEl.children.length) listEl.appendChild(skeleton(3));
      try {
        const { data } = await api.get('/texts', { per_page: 200 });
        clear(listEl);
        if (!data || !data.length) { listEl.appendChild(emptyState({ icon: 'clipboard', title: 'Nothing saved yet', text: 'Paste some text or a link above to keep it handy on all your devices.' })); return; }
        let lastDay = '';
        data.forEach((t) => {
          const day = dayLabel(t.created_at);
          if (day !== lastDay) { listEl.appendChild(h('div.timeline-day', { text: day })); lastDay = day; }
          listEl.appendChild(card(t));
        });
      } catch (e) { clear(listEl).appendChild(errorState(e, load)); }
    }

    function card(t) {
      const meta = t.url_meta || null;
      const body = t.is_url
        ? h('a', { href: t.content, target: '_blank', rel: 'noopener noreferrer nofollow', style: { display: 'block' } },
          meta && meta.title ? h('strong', { text: meta.title }) : null,
          meta && meta.description ? h('div.small.text2', { text: meta.description }) : null,
          h('div.small.ellipsis', { text: t.content }))
        : h('div', { style: { whiteSpace: 'pre-wrap', wordBreak: 'break-word' }, text: t.content.length > 600 ? t.content.slice(0, 600) + '…' : t.content });
      const ttl = t.is_permanent ? h('span.pill.ok', icon('lock', 12), 'Kept') : (t.expires_at ? h('span.pill.warn', { title: 'Deleted automatically' }, icon('clock', 12), countdown(t.expires_at)) : null);
      return h('div.card', { style: { marginBottom: '10px' } }, body,
        h('div.row.wrap', { style: { marginTop: '10px' } }, h('span.small.text2', { text: time(t.created_at) }), ttl, h('span.grow'),
          h('button.btn.btn-sm', { type: 'button', on: { click: async () => { await copyText(t.content); toast('Copied', { type: 'ok', timeout: 1500 }); } } }, icon('copy', 14), 'Copy'),
          h('button.btn.btn-sm', { type: 'button', on: { click: () => edit(t) } }, icon('edit', 14), 'Edit'),
          h('button.btn.btn-sm', { type: 'button', on: { click: () => setPerm(t) } }, icon(t.is_permanent ? 'unlock' : 'lock', 14), t.is_permanent ? 'Auto-delete' : 'Keep forever'),
          h('button.btn.btn-sm.btn-danger', { type: 'button', 'aria-label': 'Delete', on: { click: () => del(t) } }, icon('trash', 14))));
    }
    async function edit(t) {
      const v = await prompt({ title: 'Edit text', value: t.content, confirmText: 'Save' });
      if (v === null) return;
      try { await api.patch('/texts/' + t.id, { content: v }); realtime.nudge(); load(); } catch (e) { toast(e.message, { type: 'err' }); }
    }
    async function setPerm(t) { try { await api.patch('/texts/' + t.id, { is_permanent: !t.is_permanent }); realtime.nudge(); load(); } catch (e) { toast(e.message, { type: 'err' }); } }
    async function del(t) {
      if (!(await confirm({ title: 'Delete this text?', confirmText: 'Delete', danger: true }))) return;
      try { await api.del('/texts/' + t.id); realtime.nudge(); load(); } catch (e) { toast(e.message, { type: 'err' }); }
    }
    offs = ['text.created', 'text.updated', 'text.deleted', 'sync.reset'].map((x) => bus.on(x, load));
    load();
  },
  unmount() { offs.forEach((o) => o()); },
};
