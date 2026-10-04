<?php
/**
 * Sign-in page (A1). Rendered by FT\Controllers\Web\AuthPageController::render() with only $v in
 * scope. Every step is a plain HTML form that works without JavaScript; assets/js/login.js
 * enhances it. No inline event handlers (strict CSP): the only inline script is the nonce'd theme
 * bootstrap, and the JSON config block is data, never executed.
 *
 * Look and feel follow the original FastTransfer login (dark glass card, accent gradient,
 * Syne + DM Sans, bottom sheet on phones), with a light theme from the ft_theme cookie and the
 * accent palette this device last used in the app (localStorage ft_accent; Champagne by default).
 *
 * @var array<string,mixed> $v
 */
declare(strict_types=1);

$e = static fn (mixed $s): string => htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$step = (string) $v['step'];
$hidden = static fn (string $s): string => $step === $s ? '' : ' hidden';
$json = (string) json_encode($v['config'], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
$themeJs = (string) json_encode(['base' => $v['base'], 'accents' => ['champagne', 'platinum', 'rose', 'aurora', 'sapphire', 'violet']], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
$subtitles = [
    'login'  => 'Sign in to your private cloud drive',
    '2fa'    => 'Two-step verification',
    'forgot' => 'Reset your password',
    'reset'  => 'Choose a new password',
    'logout' => 'Sign out',
];
$titles = ['login' => 'Sign in', '2fa' => 'Verify it’s you', 'forgot' => 'Forgotten password', 'reset' => 'Reset password', 'logout' => 'Sign out'];
$icon = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><defs><linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>"
    . "<stop offset='0' stop-color='#ecd3a0'/><stop offset='1' stop-color='#c9a063'/></linearGradient></defs>"
    . "<rect width='64' height='64' rx='16' fill='url(#g)'/><path d='M36 8 16 36h14l-4 20 22-30H34z' fill='#1b150b'/></svg>";
$csrfField = '<input type="hidden" name="_csrf" value="' . $e($v['csrf']) . '">';
$nextField = $v['next'] !== '' ? '<input type="hidden" name="next" value="' . $e($v['next']) . '">' : '';
?><!doctype html>
<html lang="en-GB" data-theme="<?= $e($v['theme']) ?>" data-accent="champagne">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0c0c0f">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<title><?= $e($titles[$step] ?? 'Sign in') ?> · <?= $e($v['site_name']) ?></title>
<script nonce="<?= $e($v['nonce']) ?>">(function(){try{var c=<?= $themeJs ?>,d=document.documentElement,ls=null;try{ls=localStorage.getItem('ft_theme')}catch(x){}var m=document.cookie.match(/(?:^|;\s*)ft_theme=(dark|light)/),ck=m?m[1]:null;var t=(ls==='dark'||ls==='light')?ls:(ck||((window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark'));d.setAttribute('data-theme',t);if(ck!==t){document.cookie='ft_theme='+t+';path='+c.base+';max-age=31536000;samesite=Lax'}var a=null;try{a=localStorage.getItem('ft_accent')}catch(x){}d.setAttribute('data-accent',c.accents.indexOf(a)<0?'champagne':a)}catch(x){}})();</script>
<link rel="icon" href="data:image/svg+xml,<?= $e(rawurlencode($icon)) ?>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&amp;family=DM+Sans:wght@400;500;600&amp;display=swap">
<link rel="stylesheet" href="<?= $e($v['css_href']) ?>">
<script type="module" src="<?= $e($v['js_src']) ?>" nonce="<?= $e($v['nonce']) ?>"></script>
</head>
<body class="login-page" data-step="<?= $e($step) ?>">
<main class="box" id="login-box" aria-labelledby="login-title">
  <div class="logo">
    <div class="logo-icon" aria-hidden="true"><svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor" focusable="false"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div>
    <h1 id="login-title"><?= $e($v['site_name']) ?></h1>
    <p class="sub" id="login-sub"><?= $e($subtitles[$step] ?? '') ?></p>
  </div>

  <div class="msg err" id="login-error" role="alert"<?= $v['error'] === '' ? ' hidden' : '' ?>><?= $e($v['error']) ?></div>
  <div class="msg ok" id="login-notice" role="status" aria-live="polite"<?= $v['notice'] === '' ? ' hidden' : '' ?>><?= $e($v['notice']) ?></div>

  <!-- Step 1: username and password -->
  <form class="step" id="login-form" data-step="login" method="post" action="<?= $e($v['login_action']) ?>" autocomplete="on"<?= $hidden('login') ?>>
    <?= $csrfField ?><?= $nextField ?>
    <input type="hidden" name="step" value="login">
    <div class="field">
      <label class="lbl" for="login-username">Username or e-mail</label>
      <input type="text" id="login-username" name="username" value="<?= $e($v['username']) ?>" placeholder="username" required
             autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="191"<?= $step === 'login' ? ' autofocus' : '' ?>>
    </div>
    <div class="field">
      <label class="lbl" for="login-password">Password</label>
      <div class="pw-wrap">
        <input type="password" id="login-password" name="password" placeholder="••••••••" required autocomplete="current-password" maxlength="4096">
        <button type="button" class="pw-toggle" data-toggle-password="login-password" aria-controls="login-password" aria-pressed="false" aria-label="Show password" hidden>
          <span aria-hidden="true">👁</span>
        </button>
      </div>
    </div>
    <label class="rem" for="login-remember">
      <input type="checkbox" id="login-remember" name="remember" value="1">
      <span>Keep me signed in for <?= (int) $v['remember_days'] ?> days</span>
    </label>
    <button type="submit" class="primary">Sign in <span aria-hidden="true">→</span></button>
    <?php if ($v['reset_available']): ?>
    <p class="links"><a href="<?= $e($v['forgot_url']) ?>" data-goto="forgot">Forgotten your password?</a></p>
    <?php endif; ?>
  </form>

  <!-- Step 2: authenticator code or recovery code -->
  <form class="step" id="twofa-form" data-step="2fa" method="post" action="<?= $e($v['login_action']) ?>" autocomplete="off"<?= $hidden('2fa') ?>>
    <?= $csrfField ?><?= $nextField ?>
    <input type="hidden" name="step" value="2fa">
    <input type="hidden" name="challenge" id="twofa-challenge" value="<?= $e($v['challenge']) ?>">
    <p class="hint"><span aria-hidden="true">🔐</span> Enter the 6-digit code from your authenticator app.</p>
    <div class="field">
      <label class="lbl" for="twofa-code">Authenticator code</label>
      <input type="text" id="twofa-code" name="code" class="otp" placeholder="000000" inputmode="numeric" pattern="[0-9 ]{6,7}"
             maxlength="7" autocomplete="one-time-code" aria-describedby="twofa-help"<?= $step === '2fa' ? ' autofocus' : '' ?>>
      <p class="help" id="twofa-help">The code changes every 30 seconds.</p>
    </div>
    <details class="recovery" id="twofa-recovery">
      <summary>Use a recovery code instead</summary>
      <div class="field">
        <label class="lbl" for="twofa-recovery-code">Recovery code</label>
        <input type="text" id="twofa-recovery-code" name="recovery_code" placeholder="xxxxx-xxxxx" autocomplete="off"
               autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="32">
        <p class="help">Each recovery code works once.</p>
      </div>
    </details>
    <button type="submit" class="primary">Verify <span aria-hidden="true">→</span></button>
    <p class="links"><a href="<?= $e($v['login_url']) ?>" data-goto="login">Use a different account</a></p>
  </form>

  <?php if ($v['reset_available']): ?>
  <!-- Forgotten password: request a reset e-mail -->
  <form class="step" id="forgot-form" data-step="forgot" method="post" action="<?= $e($v['login_action']) ?>"<?= $hidden('forgot') ?>>
    <?= $csrfField ?><?= $nextField ?>
    <input type="hidden" name="step" value="forgot">
    <p class="hint">Enter the e-mail address on your account. If it matches, we will send you a link to choose a new password.</p>
    <div class="field">
      <label class="lbl" for="forgot-email">E-mail address</label>
      <input type="email" id="forgot-email" name="email" placeholder="you@example.com" required autocomplete="email" maxlength="191"<?= $step === 'forgot' ? ' autofocus' : '' ?>>
    </div>
    <button type="submit" class="primary">Send reset link <span aria-hidden="true">→</span></button>
    <p class="links">
      <a href="<?= $e($v['reset_url']) ?>" data-goto="reset">I have a reset code</a>
      <span aria-hidden="true">·</span>
      <a href="<?= $e($v['login_url']) ?>" data-goto="login">Back to sign in</a>
    </p>
  </form>

  <!-- Reset: code from the e-mail + new password -->
  <form class="step" id="reset-form" data-step="reset" method="post" action="<?= $e($v['login_action']) ?>" autocomplete="off"<?= $hidden('reset') ?>>
    <?= $csrfField ?><?= $nextField ?>
    <input type="hidden" name="step" value="reset">
    <div class="field">
      <label class="lbl" for="reset-token">Reset code</label>
      <input type="text" id="reset-token" name="token" value="<?= $e($v['reset_token']) ?>" required autocomplete="off"
             autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="100">
    </div>
    <div class="field">
      <label class="lbl" for="reset-password">New password</label>
      <div class="pw-wrap">
        <input type="password" id="reset-password" name="password" required minlength="10" maxlength="200" autocomplete="new-password" aria-describedby="reset-help">
        <button type="button" class="pw-toggle" data-toggle-password="reset-password" aria-controls="reset-password" aria-pressed="false" aria-label="Show password" hidden>
          <span aria-hidden="true">👁</span>
        </button>
      </div>
      <p class="help" id="reset-help">At least 10 characters. Avoid your username and common passwords.</p>
    </div>
    <div class="field">
      <label class="lbl" for="reset-confirm">Confirm new password</label>
      <input type="password" id="reset-confirm" name="password_confirm" required minlength="10" maxlength="200" autocomplete="new-password">
    </div>
    <button type="submit" class="primary">Change password <span aria-hidden="true">→</span></button>
    <p class="links"><a href="<?= $e($v['login_url']) ?>" data-goto="login">Back to sign in</a></p>
  </form>
  <?php endif; ?>

  <!-- Sign-out confirmation (shown when /logout was opened from another site) -->
  <form class="step" id="logout-form" data-step="logout" method="post" action="<?= $e($v['logout_action']) ?>"<?= $hidden('logout') ?>>
    <?= $csrfField ?>
    <p class="hint">Do you want to sign out of <?= $e($v['site_name']) ?> on this device?</p>
    <button type="submit" class="primary">Sign out</button>
    <p class="links"><a href="<?= $e($v['home_url']) ?>">Cancel</a></p>
  </form>
</main>
<script type="application/json" id="ft-login-config" nonce="<?= $e($v['nonce']) ?>"><?= $json ?></script>
</body>
</html>
