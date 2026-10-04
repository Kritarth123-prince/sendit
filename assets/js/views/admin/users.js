/** Admin › Users: create, edit, roles, quotas, enable/disable/suspend, reset password, sign out, delete. */
import { api } from '../../core/api.js';
import { h, icon, clear, debounce } from '../../core/dom.js';
import { bus } from '../../core/bus.js';
import { store } from '../../core/store.js';
import { bytes, percent, relative, dateTime } from '../../core/format.js';
import { toast, modal, confirm, menu, errorState, skeleton, copyText, emptyState } from '../../core/ui.js';

const QUOTAS = [['', 'Role default'], ['104857600', '100 MB'], ['524288000', '500 MB'], ['1073741824', '1 GB'], ['5368709120', '5 GB'], ['10737418240', '10 GB'], ['-1', 'Unlimited'], ['custom', 'Custom…']];
let offs = [];

export default {
  title: 'Users',
  mount(el) {
    const search = h('input.input', { type: 'search', placeholder: 'Search users…', 'aria-label': 'Search users', style: { maxWidth: '280px' } });
    const body = h('div');
    el.append(h('div.view-head', h('div.grow', h('h1.view-title', { text: 'Users' })), search, h('button.btn.btn-primary', { type: 'button', on: { click: () => edit(null) } }, icon('plus', 16), 'New user')), body);
    search.addEventListener('input', debounce(load, 300));

    async function load() {
      if (!body.children.length) body.append(skeleton(4));
      try {
        const { data } = await api.get('/admin/users', { q: search.value.trim() || undefined, per_page: 200 });
        clear(body);
        if (!data || !data.length) { body.append(emptyState({ icon: 'users', title: 'No users found' })); return; }
        body.append(h('div.table-wrap', h('table.table.stack-mobile', h('thead', h('tr', ...['User', 'Role', 'Status', 'Storage', 'Last sign-in', 'Created', ''].map((t) => h('th', { text: t })))),
          h('tbody', ...data.map((u) => {
            const q = u.quota || {};
            return h('tr',
              h('td', { 'data-label': 'User' }, h('strong', { text: u.display_name || u.username }), h('div.small.text2', { text: '@' + u.username + (u.email ? ' · ' + u.email : '') + (u.two_factor_enabled ? ' · 2FA' : '') })),
              h('td', { 'data-label': 'Role', text: u.role }),
              h('td', { 'data-label': 'Status' }, h('span.pill.' + (u.status === 'active' ? 'ok' : u.status === 'suspended' ? 'warn' : 'bad'), { text: u.status })),
              h('td', { 'data-label': 'Storage' }, h('div', { style: { minWidth: '120px' } }, q.quota_bytes ? h('div.quota-bar', h('span', { style: { width: percent(q.used_bytes, q.quota_bytes) + '%' } })) : null, h('div.small', { text: bytes(q.used_bytes || 0) + (q.quota_bytes ? ' / ' + bytes(q.quota_bytes) : ' · unlimited') }))),
              h('td', { 'data-label': 'Last sign-in', title: u.last_login_at ? dateTime(u.last_login_at) : '', text: u.last_login_at ? relative(u.last_login_at) : 'Never' }),
              h('td', { 'data-label': 'Created', text: dateTime(u.created_at) }),
              h('td', h('button.icon-btn.sm', { type: 'button', 'aria-label': 'Actions for ' + u.username, on: { click: (e) => actions(u, e.currentTarget) } }, icon('more', 16))));
          })))));
      } catch (e) { clear(body).append(errorState(e, load)); }
    }

    function actions(u, anchor) {
      const me = store.get('user');
      const act = (path, msg, body) => async () => { try { const { data } = await api.post('/admin/users/' + u.id + path, body || {}); toast(msg, { type: 'ok' }); load(); return data; } catch (e) { toast(e.message, { type: 'err' }); } };
      menu(anchor, [
        { label: 'Edit', icon: 'edit', onClick: () => edit(u) },
        { label: 'Activity', icon: 'activity', onClick: () => activity(u) },
        '-',
        u.status === 'active' ? { label: 'Disable', icon: 'lock', disabled: u.id === me.id, onClick: act('/disable', 'User disabled') } : { label: 'Enable', icon: 'unlock', onClick: act('/enable', 'User enabled') },
        u.status === 'active' ? { label: 'Suspend', icon: 'warning', disabled: u.id === me.id, onClick: act('/suspend', 'User suspended') } : null,
        { label: 'Reset password', icon: 'key', onClick: async () => { const d = await act('/reset-password', 'Password reset')(); if (d?.temporary_password) showTemp(u, d.temporary_password); } },
        { label: 'Sign out everywhere', icon: 'logout', onClick: act('/force-logout', 'User signed out on all devices') },
        u.two_factor_enabled ? { label: 'Turn off 2FA', icon: 'shield', onClick: act('/2fa/disable', 'Two-factor authentication turned off') } : null,
        '-',
        { label: 'Delete user', icon: 'trash', danger: true, disabled: u.id === me.id, onClick: async () => {
          if (!(await confirm({ title: 'Delete ' + u.username + '?', message: 'The account is closed, sessions end, their shares stop working and their files are deleted.', confirmText: 'Delete user', danger: true }))) return;
          try { await api.del('/admin/users/' + u.id); toast('User deleted', { type: 'ok' }); load(); } catch (e) { toast(e.message, { type: 'err' }); }
        } },
      ].filter(Boolean));
    }

    function showTemp(u, pw) {
      modal({ title: 'Temporary password for ' + u.username, size: 'sm', content: h('div.stack', h('p', { text: 'Give this to the user. They must choose a new password when they sign in. It is shown only once.' }), h('pre.text-preview', { text: pw })),
        actions: [{ label: 'Copy', kind: 'primary', onClick: async () => { await copyText(pw); toast('Copied', { type: 'ok' }); } }] });
    }

    function edit(u) {
      const isNew = !u;
      const username = h('input.input', { value: u?.username || '', disabled: !isNew, required: true, pattern: '[A-Za-z0-9._-]{3,32}' });
      const name = h('input.input', { value: u?.display_name || '' });
      const email = h('input.input', { type: 'email', value: u?.email || '' });
      const role = h('select.select', ...['user', 'admin', 'guest'].map((r) => h('option', { value: r, text: r[0].toUpperCase() + r.slice(1), selected: (u?.role || 'user') === r })));
      const cur = u?.quota_bytes_setting ?? (u?.quota_bytes === undefined ? '' : u?.quota_bytes);
      const quota = h('select.select', ...QUOTAS.map(([v, l]) => h('option', { value: v, text: l, selected: String(cur ?? '') === v })));
      const custom = h('input.input', { type: 'number', min: 1, placeholder: 'GB', hidden: true });
      quota.addEventListener('change', () => { custom.hidden = quota.value !== 'custom'; });
      const pw = h('input.input', { type: 'password', autocomplete: 'new-password', placeholder: 'Leave empty to generate one' });
      const fields = h('div.stack',
        h('div.field', h('label', { text: 'Username' }), username),
        h('div.field', h('label', { text: 'Display name' }), name),
        h('div.field', h('label', { text: 'E-mail' }), email),
        h('div.field', h('label', { text: 'Role' }), role),
        h('div.field', h('label', { text: 'Storage quota' }), quota, custom),
        isNew ? h('div.field', h('label', { text: 'Password' }), pw) : null);
      modal({ title: isNew ? 'New user' : 'Edit ' + u.username, content: fields, actions: [{ label: 'Cancel', kind: 'ghost' }, { label: isNew ? 'Create user' : 'Save', kind: 'primary', onClick: async () => {
        let qb = quota.value === '' ? null : quota.value === 'custom' ? Math.round(parseFloat(custom.value || '0') * 1073741824) : parseInt(quota.value, 10);
        const body = { display_name: name.value.trim(), email: email.value.trim() || null, role: role.value, quota_bytes: qb };
        try {
          if (isNew) {
            const { data } = await api.post('/admin/users', { ...body, username: username.value.trim(), password: pw.value || undefined, must_change_password: true });
            toast('User created', { type: 'ok' });
            if (data?.temporary_password) showTemp(data.user || { username: username.value }, data.temporary_password);
          } else { await api.patch('/admin/users/' + u.id, body); toast('User updated', { type: 'ok' }); }
          load(); return true;
        } catch (e) { toast(e.message, { type: 'err' }); return false; }
      } }] });
    }

    async function activity(u) {
      const box = h('div', skeleton(3));
      modal({ title: 'Activity — ' + u.username, size: 'lg', content: box });
      try {
        const { data } = await api.get('/admin/users/' + u.id + '/activity', { per_page: 50 });
        clear(box).append((data || []).length ? h('div.list', ...data.map((a) => h('div.list-item', h('div.li-main', h('div.li-title', { text: a.text || a.detail || a.action }), h('div.li-sub', { text: dateTime(a.created_at) + ' · ' + a.action }))))) : h('p.text2', { text: 'No activity yet.' }));
      } catch (e) { clear(box).append(errorState(e)); }
    }
    offs = ['user.created', 'user.updated', 'user.deleted'].map((t) => bus.on(t, debounce(load, 500)));
    load();
  },
  unmount() { offs.forEach((o) => o()); },
};
