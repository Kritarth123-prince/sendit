<?php
/**
 * Offline fallback page (W2-ADMIN, §12.6). Rendered by FT\Controllers\Web\PwaController::offline
 * and cached by the service worker, which shows it when a navigation fails without a network.
 * Self-contained: inline styles, system fonts and an inline SVG (nothing to fetch while offline).
 *
 * Variables: $nonce, $base, $appName, $e (escaper).
 */
declare(strict_types=1);

/** @var callable $e */
$themeJs = json_encode(['base' => $base], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
?><!doctype html>
<html lang="en-GB" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0c0c0f">
<meta name="color-scheme" content="dark light">
<meta name="robots" content="noindex">
<title>Offline · <?= $e($appName) ?></title>
<script nonce="<?= $e($nonce) ?>">(function(){try{var t=localStorage.getItem('ft_theme');if(t!=='light'&&t!=='dark'){t=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark'}document.documentElement.setAttribute('data-theme',t)}catch(x){}})();</script>
<style>
:root{--bg:#0c0c0f;--card:rgba(255,255,255,.05);--border:rgba(255,255,255,.1);--text:#ece9e3;--text2:#b0aca3;--accent2:#f1dba8;--accent-g:linear-gradient(135deg,#ecd3a0,#c9a063);--on-accent:#1b150b;--accent-rgb:214,179,122;color-scheme:dark}
[data-theme="light"]{--bg:#f7f5f0;--card:rgba(255,255,255,.85);--border:rgba(60,48,28,.16);--text:#1d1a15;--text2:#4d473d;--accent2:#8a6730;--accent-g:linear-gradient(135deg,#e8cd98,#c39a5a);--accent-rgb:176,138,72;color-scheme:light}
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);display:flex;align-items:center;justify-content:center;padding:24px 16px;line-height:1.5;-webkit-font-smoothing:antialiased}
body::before{content:'';position:fixed;inset:0;background:radial-gradient(ellipse 80% 50% at 50% -10%,rgba(var(--accent-rgb),.16),transparent);pointer-events:none}
main{position:relative;width:100%;max-width:420px;text-align:center;background:var(--card);border:1px solid var(--border);border-radius:20px;padding:36px 26px}
.mark{width:56px;height:56px;margin:0 auto 18px;border-radius:16px;background:var(--accent-g);color:var(--on-accent);display:flex;align-items:center;justify-content:center;box-shadow:inset 0 1px 0 rgba(255,255,255,.3),0 8px 24px rgba(var(--accent-rgb),.3)}
h1{font-size:22px;font-weight:800;letter-spacing:-.01em;margin-bottom:8px}
p{color:var(--text2);font-size:14.5px}
.status{display:inline-flex;align-items:center;gap:8px;margin-top:16px;font-size:13px;color:var(--text2)}
.dot{width:8px;height:8px;border-radius:50%;background:#f87171}
.online .dot{background:#34d399}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;min-height:44px;margin-top:22px;padding:10px 22px;border-radius:10px;background:var(--accent-g);color:var(--on-accent);font-weight:600;font-size:15px;text-decoration:none;box-shadow:inset 0 1px 0 rgba(255,255,255,.28),0 4px 14px rgba(var(--accent-rgb),.24)}
.btn:focus-visible{outline:2px solid var(--accent2);outline-offset:3px}
.hint{margin-top:18px;font-size:12.5px}
</style>
</head>
<body>
<main>
  <div class="mark" aria-hidden="true"><svg width="28" height="28" viewBox="0 0 24 24" fill="currentColor"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div>
  <h1>You are offline</h1>
  <p><?= $e($appName) ?> needs a connection to load your files. Check your Wi-Fi or mobile data, then try again.</p>
  <div class="status" id="status" role="status"><span class="dot" aria-hidden="true"></span><span id="status-text">No connection</span></div>
  <div><a class="btn" href="<?= $e($base) ?>" id="retry">Try again</a></div>
  <p class="hint">Uploads that were in progress continue when you are back online.</p>
</main>
<script nonce="<?= $e($nonce) ?>">(function(){var c=<?= $themeJs ?>,s=document.getElementById('status'),t=document.getElementById('status-text');function paint(){var on=navigator.onLine!==false;s.className='status'+(on?' online':'');t.textContent=on?'Connection is back — reconnecting…':'No connection'}paint();window.addEventListener('offline',paint);window.addEventListener('online',function(){paint();setTimeout(function(){location.reload()},800)});document.getElementById('retry').addEventListener('click',function(ev){ev.preventDefault();if(location.pathname.replace(/\/+$/,'/')===c.base.replace(/\/+$/,'/')||location.pathname.indexOf('/offline')===-1){location.reload()}else{location.href=c.base}})})();</script>
</body>
</html>
