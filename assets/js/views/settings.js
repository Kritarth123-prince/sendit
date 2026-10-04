/** Settings: profile, appearance, password, two-factor authentication, storage. */
import { api } from '../core/api.js';
import { h, icon, clear } from '../core/dom.js';
import { store } from '../core/store.js';
import { bytes, percent } from '../core/format.js';
import { toast, modal, passwordPrompt } from '../core/ui.js';
import { bus } from '../core/bus.js';
import { ACCENTS, currentAccent, currentTheme, setAccent, setTheme } from '../core/theme.js';

let offs = [];

export default {
  title: 'Settings',
  mount(el) {
    const u = store.get('user');
    const name = h('input.input', { value: u.display_name || '', maxlength: 100 });
    const email = h('input.input', { type: 'email', value: u.email || '', maxlength: 191 });
    const profile = h('form.card.stack', { on: { submit: async (e) => {
      e.preventDefault();
      const body = { display_name: name.value.trim(), email: email.value.trim() || null };
      const saved = (data) => { if (data) store.set('user', { ...store.get('user'), ...data }); toast('Profile saved', { type: 'ok' }); };
      try { saved((await api.patch('/user', body)).data); } catch (ex) {
        // Changing the e-mail address can need the current password (it receives reset links).
        if (ex.details && ex.details.fields && ex.details.fields.current_password) {
          await passwordPrompt({ title: 'Confirm your password', message: 'Changing your e-mail address needs your current password.', confirmText: 'Save profile',
            onConfirm: async (pw) => saved((await api.patch('/user', { ...body, current_password: pw })).data) });
        } else toast(ex.message, { type: 'err' });
      }
    } } }, h('div.card-title', icon('user', 17), 'Profile'),
      h('div.field', h('label', { text: 'Username' }), h('input.input', { value: u.username, disabled: true })),
      h('div.field', h('label', { text: 'Display name' }), name),
      h('div.field', h('label', { text: 'E-mail (for notifications and password reset)' }), email),
      h('div', h('button.btn.btn-primary', { type: 'submit', text: 'Save profile' })));

    const appearance = appearanceCard();

    const cur = h('input.input', { type: 'password', autocomplete: 'current-password' });
    const nw = h('input.input', { type: 'password', autocomplete: 'new-password', minlength: 10 });
    const nw2 = h('input.input', { type: 'password', autocomplete: 'new-password', minlength: 10 });
    const pw = h('form.card.stack', { on: { submit: async (e) => {
      e.preventDefault();
      if (nw.value !== nw2.value) { toast('The new passwords do not match.', { type: 'err' }); return; }
      try { await api.post('/user/password', { current_password: cur.value, new_password: nw.value }); cur.value = nw.value = nw2.value = ''; toast('Password changed. Your other devices were signed out and your API tokens revoked.', { type: 'ok', timeout: 5000 }); } catch (ex) { toast(ex.message, { type: 'err' }); }
    } } }, h('div.card-title', icon('lock', 17), 'Password'),
      h('div.field', h('label', { text: 'Current password' }), cur),
      h('div.field', h('label', { text: 'New password (at least 10 characters)' }), nw),
      h('div.field', h('label', { text: 'Repeat new password' }), nw2),
      h('div', h('button.btn.btn-primary', { type: 'submit', text: 'Change password' })));

    const tfa = h('div.card.stack');
    const paintTfa = () => {
      clear(tfa).append(h('div.card-title', icon('shield', 17), 'Two-factor authentication'));
      if (store.get('user').two_factor_enabled) {
        tfa.append(h('p', h('span.pill.ok', { text: 'On' }), ' Sign-in asks for a code from your authenticator app.'),
          h('div', h('button.btn.btn-danger', { type: 'button', on: { click: disableTfa } }, 'Turn off')));
      } else {
        tfa.append(h('p.text2', { text: 'Add a second step to sign-in with an authenticator app (Google Authenticator, Microsoft Authenticator, Authy, 1Password…).' }),
          h('div', h('button.btn.btn-primary', { type: 'button', on: { click: setupTfa } }, 'Set up two-factor authentication')));
      }
    };
    paintTfa();

    async function setupTfa() {
      // The server asks for the current password to start and to finish the set-up. It is kept
      // in this closure only for the few seconds of the set-up and never stored.
      let password = '';
      const setup = await passwordPrompt({ title: 'Set up two-factor authentication', confirmText: 'Continue',
        onConfirm: async (pw) => { const { data } = await api.post('/user/2fa/setup', { current_password: pw }); password = pw; return data; } });
      if (!setup) return;
      const code = h('input.input', { inputmode: 'numeric', maxlength: 6, autocomplete: 'one-time-code', placeholder: '123456' });
      const qrBox = h('div', { style: { background: '#fff', padding: '10px', borderRadius: '10px', width: 'fit-content' } });
      import('../features/qr.js').then((m) => m.renderQr(qrBox, setup.otpauth_uri, { size: 200 })).catch(() => { qrBox.remove(); });
      modal({ title: 'Set up two-factor authentication', content: h('div.stack',
        h('p', { text: '1. Scan this QR code with your authenticator app, or enter the key manually.' }), qrBox,
        h('code', { style: { wordBreak: 'break-all' }, text: setup.secret }),
        h('p', { text: '2. Enter the 6-digit code the app shows.' }), code),
      actions: [{ label: 'Cancel', kind: 'ghost' }, { label: 'Turn on', kind: 'primary', onClick: async () => {
        try {
          const { data } = await api.post('/user/2fa/enable', { code: code.value.trim(), current_password: password });
          password = '';
          store.update('user', (x) => ({ ...x, two_factor_enabled: true })); paintTfa();
          const codes = (data && data.recovery_codes) || [];
          modal({ title: 'Save your recovery codes', content: h('div.stack', h('p', { text: 'Each code works once if you lose your phone. Store them somewhere safe — they are shown only now.' }), h('pre.text-preview', { text: codes.join('\n') })), actions: [{ label: 'I have saved them', kind: 'primary' }] });
          return true;
        } catch (e) { toast(e.message, { type: 'err' }); return false; }
      } }], onClose: () => { password = ''; } });
    }
    async function disableTfa() {
      const p = h('input.input', { type: 'password', autocomplete: 'current-password' });
      const c = h('input.input', { inputmode: 'numeric', maxlength: 64 });
      modal({ title: 'Turn off two-factor authentication', size: 'sm', content: h('div.stack', h('div.field', h('label', { text: 'Password' }), p), h('div.field', h('label', { text: 'Authenticator code' }), c)),
        actions: [{ label: 'Cancel', kind: 'ghost' }, { label: 'Turn off', kind: 'danger', onClick: async () => {
          try { await api.post('/user/2fa/disable', { password: p.value, code: c.value.trim() }); store.update('user', (x) => ({ ...x, two_factor_enabled: false })); paintTfa(); toast('Two-factor authentication is off', { type: 'ok' }); return true; } catch (e) { toast(e.message, { type: 'err' }); return false; }
        } }] });
    }

    const q = store.get('quota') || {};
    const storage = h('div.card.stack', h('div.card-title', icon('server', 17), 'Storage'),
      q.quota_bytes ? h('div.quota-bar', h('span', { style: { width: percent(q.used_bytes, q.quota_bytes) + '%' } })) : null,
      h('p', { text: bytes(q.used_bytes || 0) + ' used' + (q.quota_bytes ? ' of ' + bytes(q.quota_bytes) : ' (unlimited)') + '. Files in Trash and older versions count towards your storage.' }));

    el.append(h('div.view-head', h('h1.view-title', { text: 'Settings' }), h('span.grow'), h('a.btn', { href: '#/security' }, icon('shield', 16), 'Security Centre')),
      h('div.grid-cards', { style: { gridTemplateColumns: 'repeat(auto-fill,minmax(320px,1fr))' } }, profile, appearance, pw, tfa, storage));
  },
  unmount() { offs.forEach((off) => off()); offs = []; },
};

/**
 * Appearance: theme and accent palette. A change applies at once, is remembered on this device
 * and saved to the profile, so other tabs and devices follow (core/theme.js).
 */
function appearanceCard() {
  const seg = h('div.seg', { role: 'group', 'aria-label': 'Theme' });
  for (const [id, label, ic] of [['dark', 'Dark', 'moon'], ['light', 'Light', 'sun']]) {
    seg.append(h('button', { type: 'button', dataset: { theme: id }, on: { click: () => { if (currentTheme() !== id) setTheme(id).catch(failed); } } }, icon(ic, 16), h('span', { text: label })));
  }
  const swatches = h('div.swatches', { role: 'radiogroup', 'aria-label': 'Accent colour' });
  for (const p of ACCENTS) {
    const input = h('input', { type: 'radio', name: 'accent', value: p.id, on: { change: () => { if (input.checked) setAccent(p.id).catch(failed); } } });
    swatches.append(h('label.swatch', input,
      h('span.swatch-dot', { dataset: { p: p.id }, 'aria-hidden': 'true' }, icon('check', 16)),
      h('span.swatch-name', { text: p.label }),
      p.hint ? h('span.swatch-hint', { text: p.hint }) : null));
  }
  const paint = () => {
    const t = currentTheme();
    const a = currentAccent();
    seg.querySelectorAll('button').forEach((b) => { const on = b.dataset.theme === t; b.classList.toggle('active', on); b.setAttribute('aria-pressed', on ? 'true' : 'false'); });
    swatches.querySelectorAll('.swatch').forEach((s) => { const i = s.querySelector('input'); i.checked = i.value === a; s.classList.toggle('on', i.checked); });
  };
  paint();
  offs.push(bus.on('ui:theme', paint), bus.on('ui:accent', paint));
  return h('div.card.stack.appearance', h('div.card-title', icon('eye', 17), 'Appearance'),
    h('div.field', h('span.label', { text: 'Theme' }), h('div', seg)),
    h('div.field', h('span.label', { text: 'Accent colour' }), swatches),
    h('p.hint', { text: 'Saved to your account, so your other devices follow.' }));
}

function failed(e) {
  toast((e && e.message) || 'Could not save your appearance settings.', { type: 'err' });
}
