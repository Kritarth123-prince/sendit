// FastTransfer sign-in page (A1) — progressive enhancement for views/login.php.
//
// Every step already works as a plain HTML form (POST /login). This module upgrades the
// credential and two-factor steps to the JSON API (/api/v1/auth/login, /auth/2fa) and the
// password-reset steps to /auth/password/*, so there is no full page reload and the browser's
// device id (X-Client-Id, shared with the app) is registered for the Security Centre.
//
// Hosting note: on byethost-style hosts a JavaScript cookie check can intercept fetch() and return
// an HTML page instead of JSON. A response without the `X-FT-Api: 1` marker therefore means
// "PHP never ran": we fall back to submitting the same form natively, which the browser handles.
//
// Rules: no innerHTML with data (textContent only), no inline handlers (strict CSP).

const CLIENT_ID_KEY = 'ft:client-id';
const STEPS = ['login', '2fa', 'forgot', 'reset', 'logout'];

const cfg = readConfig();
const box = document.getElementById('login-box');
const errorEl = document.getElementById('login-error');
const noticeEl = document.getElementById('login-notice');
const subEl = document.getElementById('login-sub');
const forms = {
  login: document.getElementById('login-form'),
  '2fa': document.getElementById('twofa-form'),
  forgot: document.getElementById('forgot-form'),
  reset: document.getElementById('reset-form'),
  logout: document.getElementById('logout-form'),
};
const subtitles = {
  login: 'Sign in to your private cloud drive',
  '2fa': 'Two-step verification',
  forgot: 'Reset your password',
  reset: 'Choose a new password',
  logout: 'Sign out',
};

/** Tracks forms that already fell back to a native submit, so a challenge page cannot loop. */
const nativeFallback = new WeakSet();

function readConfig() {
  try {
    const el = document.getElementById('ft-login-config');
    const data = JSON.parse((el && el.textContent) || '{}');
    return data && typeof data === 'object' ? data : {};
  } catch {
    return {};
  }
}

function storageGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function storageSet(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    // private mode or storage disabled: nothing to remember
  }
}

/** The per-browser id shared with the app (core/api.js uses the same localStorage key). */
function clientId() {
  let id = storageGet(CLIENT_ID_KEY);
  if (id && /^[A-Za-z0-9-]{8,64}$/.test(id)) {
    return id;
  }
  if (window.crypto && typeof window.crypto.randomUUID === 'function') {
    id = window.crypto.randomUUID();
  } else if (window.crypto && window.crypto.getRandomValues) {
    const bytes = new Uint8Array(16);
    window.crypto.getRandomValues(bytes);
    id = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  } else {
    return null;
  }
  storageSet(CLIENT_ID_KEY, id);
  return id;
}

/** Accent palettes (CSS tokens on html[data-accent] in login.css); Champagne is the default. */
const ACCENTS = ['champagne', 'platinum', 'rose', 'aurora', 'sapphire', 'violet'];

/**
 * Keep the theme and accent palette in step with what the app stored on this device
 * (localStorage wins over the cookie for the theme; the accent defaults to Champagne).
 */
function syncTheme() {
  const root = document.documentElement;
  const stored = storageGet('ft_theme');
  if ((stored === 'dark' || stored === 'light') && root.getAttribute('data-theme') !== stored) {
    root.setAttribute('data-theme', stored);
  }
  const accent = storageGet('ft_accent');
  const wanted = ACCENTS.includes(accent) ? accent : 'champagne';
  if (root.getAttribute('data-accent') !== wanted) {
    root.setAttribute('data-accent', wanted);
  }
}

function showError(message) {
  noticeEl.hidden = true;
  errorEl.textContent = message;
  errorEl.hidden = !message;
}

function showNotice(message) {
  errorEl.hidden = true;
  noticeEl.textContent = message;
  noticeEl.hidden = !message;
}

function clearMessages() {
  errorEl.hidden = true;
  noticeEl.hidden = true;
}

function goto(step, { focus = true } = {}) {
  if (!STEPS.includes(step) || !forms[step]) {
    return;
  }
  for (const [name, form] of Object.entries(forms)) {
    if (form) {
      form.hidden = name !== step;
    }
  }
  document.body.dataset.step = step;
  if (subEl) {
    subEl.textContent = subtitles[step] || '';
  }
  if (focus) {
    const first = forms[step].querySelector('input:not([type=hidden]):not([type=checkbox]), button[type=submit]');
    if (first) {
      first.focus();
    }
  }
}

function setBusy(form, busy) {
  form.classList.toggle('busy', busy);
  form.setAttribute('aria-busy', busy ? 'true' : 'false');
  const btn = form.querySelector('button[type=submit]');
  if (btn) {
    btn.disabled = busy;
  }
}

class RequestError extends Error {
  constructor(code, message, status = 0, details = {}) {
    super(message);
    this.code = code;
    this.status = status;
    this.details = details || {};
  }
}

async function postJson(path, body) {
  const headers = { Accept: 'application/json', 'Content-Type': 'application/json' };
  const id = clientId();
  if (id) {
    headers['X-Client-Id'] = id;
  }
  let res;
  try {
    res = await fetch((cfg.api_base || 'api/v1/') + path, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      credentials: 'same-origin',
      cache: 'no-store',
    });
  } catch {
    throw new RequestError('NETWORK', 'We could not reach FastTransfer. Check your connection and try again.');
  }
  if (res.headers.get('X-FT-Api') !== '1') {
    throw new RequestError('HOST_CHALLENGE', '');
  }
  let json = null;
  try {
    json = await res.json();
  } catch {
    json = null;
  }
  if (!json || typeof json !== 'object') {
    throw new RequestError('HOST_CHALLENGE', '');
  }
  if (!res.ok || json.success === false) {
    const err = json.error || {};
    throw new RequestError(err.code || 'SERVER_ERROR', err.message || 'Something went wrong. Please try again.', res.status, err.details || {});
  }
  return json.data;
}

function describe(err) {
  if (err.code === 'RATE_LIMITED') {
    const wait = Number(err.details.retry_after) || 60;
    const minutes = Math.max(1, Math.ceil(wait / 60));
    return `Too many attempts. Please wait ${minutes} ${minutes === 1 ? 'minute' : 'minutes'} and try again.`;
  }
  if (err.code === 'PASSWORD_TOO_WEAK' && Array.isArray(err.details.problems) && err.details.problems.length) {
    return err.details.problems.join(' ');
  }
  if (err.code === 'VALIDATION_FAILED' && err.details.fields && typeof err.details.fields === 'object') {
    const first = Object.values(err.details.fields).find((m) => typeof m === 'string' && m);
    if (first) {
      return first;
    }
  }
  if (err.status >= 500) {
    return 'Something went wrong on our side. Please try again.';
  }
  return err.message || 'Something went wrong. Please try again.';
}

/** Submit the form the old-fashioned way (used when the host intercepted our fetch). */
function submitNatively(form) {
  if (nativeFallback.has(form)) {
    return false;
  }
  nativeFallback.add(form);
  HTMLFormElement.prototype.submit.call(form);
  return true;
}

function leave() {
  window.location.replace(cfg.redirect || cfg.base || './');
}

async function run(form, fn) {
  if (form.classList.contains('busy')) {
    return;
  }
  clearMessages();
  setBusy(form, true);
  try {
    await fn();
  } catch (err) {
    if (err instanceof RequestError && err.code === 'HOST_CHALLENGE' && submitNatively(form)) {
      return; // the browser takes over (page navigation)
    }
    showError(err instanceof RequestError ? describe(err) : 'Something went wrong. Please try again.');
  } finally {
    setBusy(form, false);
  }
}

function enhanceLogin() {
  const form = forms.login;
  if (!form) {
    return;
  }
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const username = form.elements.username.value.trim();
    const password = form.elements.password.value;
    if (!username || !password) {
      showError('Enter your username and password.');
      (username ? form.elements.password : form.elements.username).focus();
      return;
    }
    const remember = form.elements.remember.checked;
    run(form, async () => {
      const data = await postJson('auth/login', { username, password, remember });
      if (data && data.two_factor_required) {
        form.elements.password.value = '';
        const tf = forms['2fa'];
        tf.elements.challenge.value = data.challenge || '';
        tf.dataset.remember = remember ? '1' : '0';
        goto('2fa');
        return;
      }
      leave();
    }).catch(() => {});
  });
}

function enhanceTwoFactor() {
  const form = forms['2fa'];
  if (!form) {
    return;
  }
  const codeInput = form.elements.code;
  const recoveryInput = form.elements.recovery_code;
  const details = document.getElementById('twofa-recovery');

  const submitTwoFactor = () => {
    const code = codeInput.value.replace(/\s+/g, '');
    const recovery = recoveryInput ? recoveryInput.value.trim() : '';
    const useRecovery = details && details.open && recovery !== '';
    if (!useRecovery && !/^\d{6}$/.test(code)) {
      showError('Enter the 6-digit code from your authenticator app, or a recovery code.');
      codeInput.focus();
      return;
    }
    const body = { challenge: form.elements.challenge.value, remember: form.dataset.remember === '1' };
    if (useRecovery) {
      body.recovery_code = recovery;
    } else {
      body.code = code;
    }
    run(form, async () => {
      try {
        await postJson('auth/2fa', body);
      } catch (err) {
        if (err instanceof RequestError && err.code === 'TWO_FACTOR_REQUIRED') {
          // The challenge expired or too many wrong codes: start again from the password.
          goto('login');
        } else if (err instanceof RequestError && err.code === 'TWO_FACTOR_INVALID') {
          codeInput.value = '';
          if (recoveryInput) {
            recoveryInput.value = '';
          }
          (useRecovery ? recoveryInput : codeInput).focus();
        }
        throw err;
      }
      leave();
    }).catch(() => {});
  };

  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    submitTwoFactor();
  });
  // Six digits typed or pasted: verify straight away (authenticator apps make this the norm).
  codeInput.addEventListener('input', () => {
    const digits = codeInput.value.replace(/\D+/g, '').slice(0, 6);
    if (codeInput.value !== digits) {
      codeInput.value = digits;
    }
    if (digits.length === 6 && !(details && details.open && recoveryInput.value.trim())) {
      submitTwoFactor();
    }
  });
  if (details) {
    details.addEventListener('toggle', () => {
      if (details.open && recoveryInput) {
        recoveryInput.focus();
      }
    });
  }
}

function enhanceForgot() {
  const form = forms.forgot;
  if (!form) {
    return;
  }
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const email = form.elements.email.value.trim();
    if (!email) {
      showError('Enter your e-mail address.');
      form.elements.email.focus();
      return;
    }
    run(form, async () => {
      const data = await postJson('auth/password/forgot', { email });
      showNotice((data && data.message) || 'If an account uses that address, we have sent instructions to reset the password.');
    }).catch(() => {});
  });
}

function enhanceReset() {
  const form = forms.reset;
  if (!form) {
    return;
  }
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    const token = form.elements.token.value.trim();
    const password = form.elements.password.value;
    const confirm = form.elements.password_confirm.value;
    if (!token || !password) {
      showError('Enter the reset code and choose a new password.');
      return;
    }
    if (password !== confirm) {
      showError('The two passwords do not match.');
      form.elements.password_confirm.focus();
      return;
    }
    run(form, async () => {
      const data = await postJson('auth/password/reset', { token, password });
      form.reset();
      goto('login');
      showNotice((data && data.message) || 'Your password has been changed. You can now sign in.');
      // Drop ?reset=… from the address bar so the used code is not left in history.
      try {
        const url = new URL(window.location.href);
        url.searchParams.delete('reset');
        window.history.replaceState(null, '', url.pathname + url.search + url.hash);
      } catch {
        // older browsers: harmless to leave it
      }
    }).catch(() => {});
  });
}

function enhancePasswordToggles() {
  for (const btn of box.querySelectorAll('[data-toggle-password]')) {
    const input = document.getElementById(btn.getAttribute('data-toggle-password'));
    if (!input) {
      continue;
    }
    btn.hidden = false;
    btn.addEventListener('click', () => {
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      btn.setAttribute('aria-pressed', show ? 'true' : 'false');
      btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      input.focus();
    });
  }
}

function enhanceStepLinks() {
  box.addEventListener('click', (ev) => {
    const link = ev.target instanceof Element ? ev.target.closest('a[data-goto]') : null;
    if (!link) {
      return;
    }
    const step = link.getAttribute('data-goto');
    if (!forms[step] || (step === '2fa' && !forms['2fa'].elements.challenge.value)) {
      return; // let the browser follow the link
    }
    ev.preventDefault();
    clearMessages();
    goto(step);
  });
}

syncTheme();
clientId();
if (box) {
  enhanceLogin();
  enhanceTwoFactor();
  enhanceForgot();
  enhanceReset();
  enhancePasswordToggles();
  enhanceStepLinks();
}
