<?php
/**
 * App shell (FE-CORE). Rendered by FT\Controllers\Web\ShellController.
 *
 * Variables: $mode ('app'|'login'), $nonce, $bootJson (pre-escaped JSON), $base, $version,
 * $appName, $theme, $me (User(me) or null), $isAdmin, $canUpload, $pretty, $e (escaper).
 *
 * The markup is a static skeleton; assets/js/app.js hydrates icons, state and views. There are
 * no inline event handlers (CSP §12.5): the only inline script is the nonce'd theme bootstrap.
 */
declare(strict_types=1);

/** @var callable $e */
$asset = static fn (string $path): string => $e($base . 'assets/' . $path . '?v=' . rawurlencode((string) $version));
$manifest = $pretty ? 'manifest.webmanifest' : 'index.php?r=/manifest.webmanifest';
// Accent palette for the first paint (CSS tokens on html[data-accent], assets/css/app.css): the
// profile's choice when signed in, Champagne by default. The sign-in page has no profile, so its
// inline script uses the palette this device remembered (localStorage ft_accent).
$accents = ['champagne', 'platinum', 'rose', 'aurora', 'sapphire', 'violet'];
$prefs = $mode === 'app' && is_array($me['preferences'] ?? null) ? $me['preferences'] : [];
$accent = $mode === 'app' ? (in_array($prefs['accent'] ?? null, $accents, true) ? $prefs['accent'] : 'champagne') : null;
$themeJs = json_encode(['base' => $base, 'accent' => $accent, 'accents' => $accents], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES);
$isApp = $mode === 'app';
$display = $isApp ? (string) ($me['display_name'] ?? $me['username'] ?? '') : '';
$initial = $display !== '' ? mb_strtoupper(mb_substr($display, 0, 1)) : '?';

/** Sidebar groups exactly as docs/ARCHITECTURE.md §12.2. [nav key, hash, label, icon] */
$groups = [
    [['dashboard', '#/', 'Dashboard', 'home']],
    [
        ['files', '#/files', 'My Files', 'folder'],
        ['shared', '#/shared', 'Shared With Me', 'users'],
        ['favorites', '#/favorites', 'Favourites', 'star'],
        ['recent', '#/recent', 'Recent', 'clock'],
        ['trash', '#/trash', 'Trash', 'trash'],
        ['clipboard', '#/clipboard', 'Clipboard', 'clipboard'],
        ['notepad', '#/notepad', 'Notepad', 'edit'],
    ],
    [['uploads', '#/uploads', 'Uploads', 'upload']],
    [['notifications', '#/notifications', 'Notifications', 'bell']],
    [
        ['settings', '#/settings', 'Settings', 'settings'],
        ['security', '#/security', 'Security Centre', 'shield'],
    ],
];
$adminItems = [
    ['admin-users', '#/admin/users', 'Users', 'users'],
    ['admin-storage', '#/admin/storage', 'Storage', 'server'],
    ['admin-shares', '#/admin/shares', 'Shares', 'link'],
    ['admin-activity', '#/admin/activity', 'Activity', 'activity'],
    ['admin-system', '#/admin/system', 'System', 'settings'],
];
?><!doctype html>
<html lang="en-GB" data-theme="<?= $e($theme) ?>" data-accent="<?= $e($accent ?? 'champagne') ?>">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="theme-color" content="#0c0c0f">
<meta name="color-scheme" content="dark light">
<meta name="referrer" content="strict-origin-when-cross-origin">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="<?= $e($appName) ?>">
<title><?= $isApp ? 'Dashboard' : 'Sign in' ?> · <?= $e($appName) ?></title>
<script nonce="<?= $e($nonce) ?>">(function(){try{var c=<?= $themeJs ?>,d=document.documentElement,ls=null;try{ls=localStorage.getItem('ft_theme')}catch(x){}var m=document.cookie.match(/(?:^|;\s*)ft_theme=(dark|light)/),ck=m?m[1]:null;var t=(ls==='dark'||ls==='light')?ls:(ck||((window.matchMedia&&window.matchMedia('(prefers-color-scheme: light)').matches)?'light':'dark'));d.setAttribute('data-theme',t);if(ck!==t){document.cookie='ft_theme='+t+';path='+c.base+';max-age=31536000;samesite=Lax'}if(ls!==t){try{localStorage.setItem('ft_theme',t)}catch(x){}}var a=c.accent,la=null;try{la=localStorage.getItem('ft_accent')}catch(x){}if(!a){a=la}if(c.accents.indexOf(a)<0){a='champagne'}d.setAttribute('data-accent',a);if(la!==a){try{localStorage.setItem('ft_accent',a)}catch(x){}}}catch(x){}})();</script>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&amp;family=DM+Sans:opsz,wght@9..40,300;9..40,400;9..40,500;9..40,600&amp;display=swap">
<link rel="stylesheet" href="<?= $asset('css/app.css') ?>">
<link rel="manifest" href="<?= $e($base . $manifest) ?>" crossorigin="use-credentials">
<link rel="icon" href="<?= $asset('img/icon.svg') ?>" type="image/svg+xml">
<link rel="icon" href="<?= $e($base . 'assets/icons/favicon-32.png') ?>" type="image/png" sizes="32x32">
<link rel="apple-touch-icon" href="<?= $e($base . 'assets/icons/apple-touch-icon.png') ?>">
<script id="ft-boot" type="application/json"><?= $bootJson ?></script>
<script type="module" nonce="<?= $e($nonce) ?>" src="<?= $asset('js/app.js') ?>"></script>
</head>
<?php if (!$isApp): ?>
<body class="login-body">
<main class="login-page" id="login-root">
  <div class="login-box">
    <div class="login-logo"><div class="login-logo-icon" aria-hidden="true"><svg width="26" height="26" viewBox="0 0 24 24" fill="currentColor"><path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/></svg></div><h1><?= $e($appName) ?></h1><p class="login-sub">Enter your credentials</p></div>
    <noscript><p class="login-err">FastTransfer needs JavaScript. Please enable it and reload the page.</p></noscript>
    <div class="login-loading" data-login-placeholder><span class="spinner" aria-hidden="true"></span> Loading…</div>
  </div>
</main>
</body>
</html>
<?php return; endif; ?>
<body class="app-body">
<a class="skip-link" href="#view">Skip to content</a>
<div class="app" id="app">
  <aside class="sidebar" id="sidebar" aria-label="Main navigation">
    <div class="sidebar-head">
      <a class="brand" href="#/" aria-label="<?= $e($appName) ?> dashboard"><span class="brand-mark" aria-hidden="true"><span data-icon="bolt" data-size="18"></span></span><span class="brand-name"><?= $e($appName) ?></span></a>
      <button type="button" class="icon-btn drawer-close" data-action="drawer-close" aria-label="Close menu"><span data-icon="close"></span></button>
    </div>
    <nav class="nav" id="nav">
<?php foreach ($groups as $group): ?>
      <div class="nav-group">
<?php foreach ($group as [$key, $href, $label, $icon]): ?>
        <a class="nav-item" href="<?= $e($href) ?>" data-nav="<?= $e($key) ?>"><span class="nav-ico" data-icon="<?= $e($icon) ?>" aria-hidden="true"></span><span class="nav-label"><?= $e($label) ?></span><?php if ($key === 'notifications'): ?><span class="badge nav-badge" data-unread-badge hidden>0</span><?php endif; ?><?php if ($key === 'uploads'): ?><span class="badge nav-badge badge-accent" data-uploads-badge hidden>0</span><?php endif; ?></a>
<?php endforeach; ?>
      </div>
<?php endforeach; ?>
<?php if ($isAdmin): ?>
      <div class="nav-group nav-group-admin" role="group" aria-labelledby="nav-admin-label">
        <a class="nav-group-label" id="nav-admin-label" href="#/admin" data-nav="admin"><span class="nav-ico" data-icon="chart" aria-hidden="true"></span><span class="nav-label">Admin</span></a>
<?php foreach ($adminItems as [$key, $href, $label, $icon]): ?>
        <a class="nav-item nav-sub" href="<?= $e($href) ?>" data-nav="<?= $e($key) ?>"><span class="nav-ico" data-icon="<?= $e($icon) ?>" aria-hidden="true"></span><span class="nav-label"><?= $e($label) ?></span></a>
<?php endforeach; ?>
      </div>
<?php endif; ?>
    </nav>
    <div class="sidebar-foot">
      <div class="quota" id="quota-meter" data-quota aria-live="off"></div>
    </div>
  </aside>
  <div class="drawer-scrim" data-action="drawer-close" hidden></div>

  <div class="main-col">
    <header class="topbar">
      <button type="button" class="icon-btn topbar-menu" data-action="drawer-open" aria-label="Open menu" aria-controls="sidebar" aria-expanded="false"><span data-icon="menu"></span></button>
      <a class="brand brand-compact" href="#/" aria-label="<?= $e($appName) ?> dashboard"><span class="brand-mark" aria-hidden="true"><span data-icon="bolt" data-size="16"></span></span></a>
      <form class="search" id="global-search" role="search" action="#/search" autocomplete="off">
        <span class="search-ico" data-icon="search" aria-hidden="true"></span>
        <input type="search" name="q" id="search-input" placeholder="Search files…" aria-label="Search files" maxlength="200" enterkeyhint="search">
        <kbd class="search-kbd" aria-hidden="true">/</kbd>
      </form>
      <div class="topbar-actions">
        <span class="live" id="live-indicator" role="status" data-state="connecting"><span class="live-dot" aria-hidden="true"></span><span class="live-text">Connecting…</span></span>
<?php if ($canUpload): ?>
        <button type="button" class="btn btn-primary btn-upload" data-action="upload" aria-label="Upload files"><span data-icon="upload"></span><span class="btn-label">Upload</span></button>
<?php endif; ?>
        <a class="icon-btn bell" href="#/notifications" aria-label="Notifications" data-nav="notifications-bell"><span data-icon="bell"></span><span class="badge" data-unread-badge hidden>0</span></a>
        <button type="button" class="icon-btn" data-action="theme" aria-label="Switch theme"><span data-icon="<?= $theme === 'light' ? 'moon' : 'sun' ?>"></span></button>
        <button type="button" class="avatar-btn" data-action="avatar" aria-haspopup="menu" aria-label="Account menu for <?= $e($display) ?>"><span class="avatar" aria-hidden="true"><?= $e($initial) ?></span></button>
      </div>
    </header>
    <div class="banner-region" id="banner" aria-live="polite"></div>
    <main class="view" id="view" tabindex="-1">
      <div class="view-loading"><div class="skeleton-block"></div><div class="skeleton-block"></div><div class="skeleton-block short"></div></div>
      <noscript><p class="empty-state">FastTransfer needs JavaScript. Please enable it and reload the page.</p></noscript>
    </main>
  </div>

  <nav class="tabbar" aria-label="Quick navigation">
    <a href="#/" data-nav="dashboard"><span data-icon="home"></span><span class="tab-label">Home</span></a>
    <a href="#/files" data-nav="files"><span data-icon="folder"></span><span class="tab-label">Files</span></a>
    <a href="#/shared" data-nav="shared"><span data-icon="users"></span><span class="tab-label">Shared</span></a>
    <a href="#/notifications" data-nav="notifications"><span class="tab-ico-wrap"><span data-icon="bell"></span><span class="badge" data-unread-badge hidden>0</span></span><span class="tab-label">Notifications</span></a>
    <button type="button" data-action="drawer-open" aria-controls="sidebar" aria-expanded="false"><span data-icon="menu"></span><span class="tab-label">More</span></button>
  </nav>
</div>
<div class="upload-tray" id="upload-tray" aria-label="Uploads"></div>
<div class="toasts" id="toasts" aria-live="polite" aria-relevant="additions"></div>
<div id="modal-root"></div>
<div class="drop-overlay" id="drop-overlay" hidden><div class="drop-overlay-inner"><span data-icon="upload" data-size="48"></span><p>Drop files to upload</p></div></div>
<input type="file" id="global-file-input" multiple hidden>
</body>
</html>
