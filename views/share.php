<?php
/**
 * Public link page (A4). Rendered by FT\Controllers\Web\PublicShareController::render().
 *
 * States: "share" (file / bundle / folder), "password", "message", "unavailable".
 * Everything printed here goes through $e() (htmlspecialchars). No inline event handlers:
 * the only inline script is the nonce'd theme bootstrap; the page script is an ES module.
 *
 * @var array<string,mixed> $v
 */
declare(strict_types=1);

$e = static fn ($s): string => htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$state = (string) ($v['state'] ?? 'unavailable');
$app = (string) ($v['app'] ?? 'FastTransfer');
$nonce = (string) ($v['nonce'] ?? '');

/** Small inline SVG icons (stroke = currentColor). */
$icon = static function (string $name, int $size = 20): string {
    $paths = [
        'bolt'     => '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
        'file'     => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/>',
        'files'    => '<path d="M15 2H8a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7z"/><path d="M15 2v5h5"/><path d="M4 7v13a2 2 0 0 0 2 2h10"/>',
        'folder'   => '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
        'download' => '<path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/>',
        'upload'   => '<path d="M12 21V9"/><path d="m7 14 5-5 5 5"/><path d="M5 3h14"/>',
        'lock'     => '<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
        'unlink'   => '<path d="M9 17H7a5 5 0 0 1 0-10h2"/><path d="M15 7h2a5 5 0 0 1 4 8"/><path d="M8 12h4"/><path d="m3 3 18 18"/>',
        'eye'      => '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/>',
        'comment'  => '<path d="M21 12a8 8 0 0 1-11.6 7.1L4 20l1.1-4.4A8 8 0 1 1 21 12z"/>',
        'sun'      => '<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>',
        'moon'     => '<path d="M21 13A9 9 0 1 1 11 3a7 7 0 0 0 10 10z"/>',
        'info'     => '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
        'clock'    => '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
        'pdf'      => '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 15h1.5a1.5 1.5 0 0 0 0-3H8v5M13 12v5h1a2 2 0 0 0 2-2v-1a2 2 0 0 0-2-2z"/>',
        'chevron'  => '<path d="m9 6 6 6-6 6"/>',
        'external' => '<path d="M14 4h6v6"/><path d="M20 4 10 14"/><path d="M19 14v5a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V6a1 1 0 0 1 1-1h5"/>',
    ];
    $p = $paths[$name] ?? $paths['file'];
    return '<svg class="ic" width="' . $size . '" height="' . $size . '" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">' . $p . '</svg>';
};

$kindIcon = static function (array $f) use ($icon): string {
    return match ((string) ($f['kind'] ?? '')) {
        'pdf'   => $icon('pdf', 22),
        default => $icon('file', 22),
    };
};

/** Data for the page script (non-executable JSON block; CSP does not apply to it). */
$pageData = [
    'state'  => $state,
    'target' => $v['target'] ?? null,
    'urls'   => $v['urls'] ?? null,
    'can'    => [
        'preview'  => (bool) ($v['can_preview'] ?? false),
        'download' => (bool) ($v['can_download'] ?? false),
        'comment'  => (bool) ($v['can_comment'] ?? false),
        'upload'   => (bool) ($v['can_upload'] ?? false),
    ],
    'folder_id' => isset($v['folder']['folder']['id']) ? (int) $v['folder']['folder']['id'] : null,
];
$json = json_encode($pageData, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?: '{}';

$renderFileRow = static function (array $f, bool $canDownload, bool $canComment) use ($e, $icon, $kindIcon): string {
    ob_start(); ?>
    <li class="file-row" data-file-id="<?= (int) $f['id'] ?>" data-preview="<?= $e($f['preview'] ?? '') ?>" data-name="<?= $e($f['name']) ?>"<?= $f['content_url'] ? ' data-content-url="' . $e($f['content_url']) . '"' : '' ?>>
      <div class="file-thumb">
        <?php if (!empty($f['thumb_url'])): ?>
          <img src="<?= $e($f['thumb_url']) ?>" alt="" loading="lazy" decoding="async" width="44" height="44">
        <?php else: ?>
          <?= $kindIcon($f) ?>
        <?php endif; ?>
      </div>
      <div class="file-main">
        <span class="file-name" title="<?= $e($f['name']) ?>"><?= $e($f['name']) ?></span>
        <span class="file-meta"><?= $e($f['size_label']) ?> · <time datetime="<?= $e($f['updated_at']) ?>" data-local><?= $e($f['updated_label']) ?></time></span>
      </div>
      <div class="file-actions">
        <?php if (!empty($f['content_url'])): ?>
          <a class="btn btn-ghost btn-sm js-preview" href="<?= $e($f['content_url']) ?>" target="_blank" rel="noopener"><?= $icon('eye', 16) ?><span>Preview</span></a>
        <?php endif; ?>
        <?php if ($canComment): ?>
          <button class="btn btn-ghost btn-sm js-comments" type="button" hidden><?= $icon('comment', 16) ?><span>Comments</span></button>
        <?php endif; ?>
        <?php if ($canDownload): ?>
          <a class="btn btn-accent btn-sm" href="<?= $e($f['download_url']) ?>" rel="nofollow"><?= $icon('download', 16) ?><span>Download</span></a>
        <?php endif; ?>
      </div>
    </li>
    <?php return (string) ob_get_clean();
};
?><!DOCTYPE html>
<html lang="en-GB" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<meta name="robots" content="noindex, nofollow, noarchive">
<meta name="referrer" content="no-referrer">
<meta name="color-scheme" content="dark light">
<meta name="theme-color" content="#0c0c0f">
<?php if (!empty($v['csrf'])): ?><meta name="csrf-token" content="<?= $e($v['csrf']) ?>">
<?php endif; ?>
<title><?= $e($v['title'] ?? 'Shared link') ?> · <?= $e($app) ?></title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600;9..40,700&amp;family=Syne:wght@700;800&amp;display=swap">
<link rel="stylesheet" href="<?= $e($v['css'] ?? '') ?>">
<script nonce="<?= $e($nonce) ?>">try{var t=localStorage.getItem('ft:theme');if(t==='light'||t==='dark'){document.documentElement.setAttribute('data-theme',t)}}catch(_){}</script>
</head>
<body class="ft-public state-<?= $e($state) ?>">
<div class="bg-glow" aria-hidden="true"></div>
<header class="topbar">
  <a class="brand" href="<?= $e($v['base'] ?? './') ?>" rel="nofollow">
    <span class="logo"><?= $icon('bolt', 18) ?></span>
    <span class="brand-name"><?= $e($app) ?></span>
  </a>
  <button id="theme-toggle" class="icon-btn" type="button" aria-label="Switch between dark and light theme" title="Theme">
    <span class="when-dark"><?= $icon('sun', 18) ?></span><span class="when-light"><?= $icon('moon', 18) ?></span>
  </button>
</header>

<main class="wrap" id="main">
<?php if ($state === 'unavailable' || $state === 'message'): ?>
  <section class="card card-centre" role="alert">
    <div class="badge-icon <?= $state === 'unavailable' ? 'is-muted' : 'is-warn' ?>"><?= $icon($state === 'unavailable' ? 'unlink' : 'info', 30) ?></div>
    <h1 class="h1"><?= $e($v['heading'] ?? 'Link unavailable') ?></h1>
    <p class="lead"><?= $e($v['text'] ?? '') ?></p>
    <?php if (!empty($v['back_url'])): ?>
      <p><a class="btn btn-ghost" href="<?= $e($v['back_url']) ?>">Back to the shared page</a></p>
    <?php endif; ?>
  </section>

<?php elseif ($state === 'password'): ?>
  <section class="card card-centre card-narrow">
    <div class="badge-icon"><?= $icon('lock', 28) ?></div>
    <h1 class="h1"><?= $e($v['heading']) ?></h1>
    <p class="lead"><strong><?= $e($v['owner']) ?></strong> shared “<?= $e($v['item_title']) ?>” with a password. Enter it to continue.</p>
    <?php if (!empty($v['error'])): ?>
      <div class="alert alert-err" role="alert"><?= $e($v['error']) ?></div>
    <?php endif; ?>
    <form class="form" method="post" action="<?= $e($v['unlock_url']) ?>" autocomplete="off">
      <input type="hidden" name="_csrf" value="<?= $e($v['csrf']) ?>">
      <label class="label" for="share-password">Password</label>
      <input class="input" id="share-password" name="password" type="password" required autofocus maxlength="800" autocomplete="current-password" enterkeyhint="go">
      <button class="btn btn-primary btn-block" type="submit"><?= $icon('lock', 18) ?><span>Open link</span></button>
    </form>
  </section>

<?php else: ?>
  <?php if (!empty($v['flash'])): ?>
    <div class="alert <?= $v['flash']['type'] === 'ok' ? 'alert-ok' : 'alert-err' ?>" role="status"><?= $e($v['flash']['text']) ?></div>
  <?php endif; ?>

  <section class="card share-head">
    <div class="share-icon"><?= $icon($v['target'] === 'folder' ? 'folder' : ($v['target'] === 'bundle' ? 'files' : 'file'), 26) ?></div>
    <div class="share-text">
      <h1 class="share-title"><?= $e($v['heading']) ?></h1>
      <p class="meta">
        Shared by <strong><?= $e($v['owner']) ?></strong>
        <?php if (!empty($v['expires_label'])): ?>
          <span class="dot">·</span><span class="chip"><?= $icon('clock', 14) ?>Available until <time datetime="<?= $e($v['expires_at']) ?>" data-local><?= $e($v['expires_label']) ?></time></span>
        <?php endif; ?>
        <?php if ($v['downloads_left'] !== null && !$v['download_off']): ?>
          <span class="dot">·</span><span class="chip"><?= (int) $v['downloads_left'] ?> download<?= (int) $v['downloads_left'] === 1 ? '' : 's' ?> left</span>
        <?php endif; ?>
      </p>
    </div>
    <div class="share-actions">
      <?php if ($v['can_download'] && $v['target'] === 'file'): ?>
        <a class="btn btn-primary" href="<?= $e($v['file']['download_url']) ?>" rel="nofollow"><?= $icon('download', 18) ?><span>Download</span></a>
      <?php elseif ($v['can_download'] && !empty($v['zip_url'])): ?>
        <a class="btn btn-primary" href="<?= $e($v['zip_url']) ?>" rel="nofollow"><?= $icon('download', 18) ?><span>Download all (ZIP)</span></a>
      <?php endif; ?>
    </div>
    <?php if (!empty($v['message'])): ?>
      <blockquote class="note"><?= nl2br($e($v['message'])) ?></blockquote>
    <?php endif; ?>
    <?php if ($v['exhausted']): ?>
      <div class="alert alert-warn">This link has reached its download limit. You can still look at what was shared, but downloads are no longer possible.</div>
    <?php elseif ($v['download_off']): ?>
      <div class="alert alert-info">Viewing only — the person who shared this turned downloads off.</div>
    <?php endif; ?>
  </section>

  <?php if ($v['target'] === 'file'): $f = $v['file']; ?>
    <section class="card preview-card" aria-label="Preview">
      <?php if ($f['preview'] === 'image'): ?>
        <img class="preview-media preview-img" src="<?= $e($f['content_url']) ?>" alt="<?= $e($f['name']) ?>" decoding="async">
      <?php elseif ($f['preview'] === 'video'): ?>
        <video class="preview-media" src="<?= $e($f['content_url']) ?>" controls preload="metadata" playsinline></video>
      <?php elseif ($f['preview'] === 'audio'): ?>
        <div class="preview-audio"><?= $icon('file', 40) ?><audio src="<?= $e($f['content_url']) ?>" controls preload="metadata"></audio></div>
      <?php elseif ($f['preview'] === 'pdf'): ?>
        <div class="preview-empty">
          <?= $icon('pdf', 48) ?>
          <p>PDF document</p>
          <a class="btn btn-accent" href="<?= $e($f['content_url']) ?>" target="_blank" rel="noopener"><?= $icon('external', 16) ?><span>Open the PDF in a new tab</span></a>
        </div>
      <?php elseif ($f['preview'] === 'text' && $f['text'] !== null): ?>
        <pre class="preview-text" tabindex="0"><?= $e($f['text']) ?></pre>
        <?php if ($f['text_truncated']): ?><p class="muted small">Showing the beginning of the file only.<?= $v['can_download'] ? ' Download it to see everything.' : '' ?></p><?php endif; ?>
      <?php else: ?>
        <div class="preview-empty">
          <?= $kindIcon($f) ?>
          <p><?= $v['can_preview'] ? 'No preview is available for this type of file.' : 'Previews are turned off for this link.' ?></p>
        </div>
      <?php endif; ?>
      <div class="file-facts">
        <span class="file-name" title="<?= $e($f['name']) ?>"><?= $e($f['name']) ?></span>
        <span class="muted"><?= $e($f['size_label']) ?> · updated <time datetime="<?= $e($f['updated_at']) ?>" data-local><?= $e($f['updated_label']) ?></time></span>
      </div>
    </section>

    <?php if ($v['can_upload']): ?>
      <section class="card" id="upload">
        <h2 class="h2"><?= $icon('upload', 18) ?>Upload a new version</h2>
        <p class="muted small">Replaces “<?= $e($f['name']) ?>” with your file (the previous version is kept). Maximum <?= $e($v['upload_limit']) ?><?= $f['ext'] !== '' ? ', .' . $e($f['ext']) . ' files only' : '' ?>.</p>
        <form class="form js-upload" method="post" action="<?= $e($v['urls']['upload']) ?>" enctype="multipart/form-data">
          <input type="hidden" name="_csrf" value="<?= $e($v['csrf']) ?>">
          <input class="input" type="file" name="file" required<?= $f['ext'] !== '' ? ' accept=".' . $e($f['ext']) . '"' : '' ?>>
          <div class="progress" hidden><div class="progress-fill"></div></div>
          <button class="btn btn-accent" type="submit"><?= $icon('upload', 16) ?><span>Upload</span></button>
        </form>
      </section>
    <?php endif; ?>

    <?php if ($v['can_comment']): ?>
      <section class="card" id="comments">
        <h2 class="h2"><?= $icon('comment', 18) ?>Comments</h2>
        <ul class="comment-list" data-file-id="<?= (int) $v['comment_file_id'] ?>">
          <?php foreach ($v['comments'] as $c): ?>
            <li class="comment">
              <div class="comment-head"><strong><?= $e($c['author_name']) ?></strong><time datetime="<?= $e($c['created_at']) ?>" data-local><?= $e(gmdate('d M Y, H:i', (int) strtotime((string) $c['created_at'])) . ' UTC') ?></time></div>
              <p class="comment-body"><?= $e($c['body']) ?></p>
            </li>
          <?php endforeach; ?>
          <?php if ($v['comments'] === []): ?><li class="comment-empty muted">No comments yet.</li><?php endif; ?>
        </ul>
        <form class="form comment-form js-comment" method="post" action="<?= $e($v['urls']['comments']) ?>">
          <input type="hidden" name="_csrf" value="<?= $e($v['csrf']) ?>">
          <input type="hidden" name="file_id" value="<?= (int) $v['comment_file_id'] ?>">
          <label class="label" for="c-name">Your name</label>
          <input class="input" id="c-name" name="name" maxlength="60" required autocomplete="name">
          <label class="label" for="c-body">Comment</label>
          <textarea class="input" id="c-body" name="body" rows="3" maxlength="2000" required></textarea>
          <div class="form-foot"><span class="muted small">Visible to the owner and to everyone with this link.</span><button class="btn btn-accent" type="submit"><?= $icon('comment', 16) ?><span>Post comment</span></button></div>
        </form>
      </section>
    <?php endif; ?>

  <?php elseif ($v['target'] === 'bundle'): ?>
    <section class="card">
      <h2 class="h2"><?= $icon('files', 18) ?><?= count($v['files']) ?> file<?= count($v['files']) === 1 ? '' : 's' ?></h2>
      <ul class="file-list" id="file-list">
        <?php foreach ($v['files'] as $f): ?><?= $renderFileRow($f, $v['can_download'], $v['can_comment']) ?><?php endforeach; ?>
      </ul>
    </section>

  <?php else: $fv = $v['folder']; ?>
    <section class="card" id="folder-view">
      <nav class="crumbs" aria-label="Folder path">
        <?php foreach ($fv['breadcrumbs'] as $i => $c): ?>
          <?php if ($i > 0): ?><span class="crumb-sep"><?= $icon('chevron', 14) ?></span><?php endif; ?>
          <a class="crumb js-folder" href="<?= $e($c['url']) ?>" data-api="<?= $e($c['api']) ?>"<?= $i === count($fv['breadcrumbs']) - 1 ? ' aria-current="page"' : '' ?>><?= $e($c['name']) ?></a>
        <?php endforeach; ?>
      </nav>
      <ul class="file-list" id="folder-list">
        <?php foreach ($fv['folders'] as $d): ?>
          <li class="file-row is-folder">
            <div class="file-thumb"><?= $icon('folder', 22) ?></div>
            <div class="file-main"><a class="file-name js-folder" href="<?= $e($d['url']) ?>" data-api="<?= $e($d['api']) ?>"><?= $e($d['name']) ?></a></div>
          </li>
        <?php endforeach; ?>
        <?php foreach ($fv['files'] as $f): ?><?= $renderFileRow($f, $fv['can_download'], $fv['can_comment']) ?><?php endforeach; ?>
        <?php if ($fv['folders'] === [] && $fv['files'] === []): ?><li class="file-empty muted">This folder is empty.</li><?php endif; ?>
      </ul>
      <?php if ($fv['truncated']): ?><p class="muted small">Only the first items are shown.<?= $v['can_download'] ? ' Use “Download all” to get everything.' : '' ?></p><?php endif; ?>
    </section>
  <?php endif; ?>

  <template id="tpl-comments">
    <div class="comments-panel">
      <ul class="comment-list"></ul>
      <form class="form comment-form">
        <label class="label">Your name<input class="input" name="name" maxlength="60" required autocomplete="name"></label>
        <label class="label">Comment<textarea class="input" name="body" rows="3" maxlength="2000" required></textarea></label>
        <div class="form-foot"><span class="muted small form-msg" role="status"></span><button class="btn btn-accent btn-sm" type="submit">Post comment</button></div>
      </form>
    </div>
  </template>
  <dialog id="preview-dialog" class="dialog" aria-label="Preview">
    <div class="dialog-head"><span class="dialog-title"></span><button class="icon-btn js-close" type="button" aria-label="Close preview">✕</button></div>
    <div class="dialog-body"></div>
  </dialog>
<?php endif; ?>
</main>

<footer class="foot">
  <span>Shared securely with <?= $e($app) ?></span>
</footer>
<script type="application/json" id="ft-share-data"><?= $json ?></script>
<script type="module" src="<?= $e($v['js'] ?? '') ?>" nonce="<?= $e($nonce) ?>"></script>
</body>
</html>
