<?php
/**
 * Installer page. Variables: $s (state array from InstallController::state), $nonce.
 * Everything user- or environment-derived is escaped with $e().
 */
declare(strict_types=1);

$e = static fn ($v): string => htmlspecialchars((string) $v, ENT_QUOTES, 'UTF-8');
$csrf = '<input type="hidden" name="_csrf" value="' . $e($s['csrf']) . '">';
$upgrade = !empty($s['upgrade']);

// Which step is active
$step = 'token';
if ($s['ready'] && !$s['unlocked']) {
    $step = 'done';
} elseif ($s['unlocked']) {
    if (!$s['checks_ok']) {
        $step = 'checks';
    } elseif ($s['db_ok'] === false) {
        $step = 'database';
    } elseif ($s['pending'] !== []) {
        $step = 'migrate';
    } elseif ($s['admin_count'] === 0) {
        $step = 'admin';
    } else {
        $step = 'finish';
    }
}
$steps = [
    'token'    => 'Unlock',
    'checks'   => 'Server check',
    'database' => 'Database',
    'migrate'  => 'Create tables',
    'admin'    => 'Administrator',
    'finish'   => 'Import & finish',
];
$order = array_keys($steps);
$current = array_search($step === 'done' ? 'finish' : $step, $order, true);
?><!DOCTYPE html>
<html lang="en-GB" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= $upgrade ? 'Upgrade' : 'Install' ?> · FastTransfer</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600&family=Syne:wght@700;800&display=swap">
<link rel="stylesheet" href="<?= $e($s['base']) ?>assets/css/install.css?v=<?= $e(FT_VERSION) ?>">
</head>
<body>
<main class="wrap">
  <header class="brand">
    <div class="logo" aria-hidden="true">⚡</div>
    <div>
      <h1>FastTransfer <?= $upgrade ? 'upgrade' : 'setup' ?></h1>
      <p class="sub">Version <?= $e(FT_VERSION) ?></p>
    </div>
  </header>

  <?php if ($step !== 'done'): ?>
  <ol class="steps" aria-label="Progress">
    <?php foreach ($steps as $key => $label): $i = array_search($key, $order, true); ?>
      <li class="<?= $i < $current ? 'done' : ($i === $current ? 'now' : '') ?>"><span><?= $i + 1 ?></span><?= $e($label) ?></li>
    <?php endforeach; ?>
  </ol>
  <?php endif; ?>

  <?php foreach ($s['flash'] as $f): ?>
    <div class="msg <?= $f['type'] === 'ok' ? 'ok' : 'err' ?>" role="<?= $f['type'] === 'ok' ? 'status' : 'alert' ?>"><?= $e($f['message']) ?></div>
  <?php endforeach; ?>

  <section class="card">
  <?php if ($step === 'done'): ?>
    <h2>FastTransfer is installed</h2>
    <p>Everything is set up and the database is up to date.</p>
    <p class="actions"><a class="btn" href="<?= $e($s['base']) ?>">Open FastTransfer</a></p>
    <p class="hint">For security, remove <code>INSTALL_TOKEN</code> from <code>.env</code> now that installation is complete.</p>

  <?php elseif ($step === 'token'): ?>
    <h2>Unlock the installer</h2>
    <?php if (!$s['token_set']): ?>
      <p>Add an <code>INSTALL_TOKEN</code> line to your <code>.env</code> file, then reload this page. You can use this freshly generated value:</p>
      <pre class="code"><?= $e('INSTALL_TOKEN=' . ($s['suggestions']['INSTALL_TOKEN'] ?? '')) ?></pre>
    <?php else: ?>
      <?php if (empty($s['storage_ok'])): ?>
        <div class="msg err" role="alert"><?= $e($s['storage_help'] ?? '') ?></div>
      <?php endif; ?>
      <p>Enter the <code>INSTALL_TOKEN</code> from your <code>.env</code> file.</p>
      <form method="post" action="<?= $e($s['action']) ?>" class="form">
        <?= $csrf ?><input type="hidden" name="action" value="token">
        <label>Install token<input type="password" name="token" required autocomplete="off" autofocus></label>
        <button class="btn" type="submit">Continue</button>
      </form>
    <?php endif; ?>

  <?php elseif ($step === 'checks'): ?>
    <h2>Server check</h2>
    <p>Fix the items marked ✗, then reload this page.</p>
    <?php if ($s['suggestions']): ?>
      <p>Missing secrets — add these lines to <code>.env</code> (generated just now; keep a safe copy of <code>ENCRYPTION_KEY</code>):</p>
      <pre class="code"><?php foreach ($s['suggestions'] as $k => $v): ?><?= $e($k . '=' . $v) ?>
<?php endforeach; ?></pre>
    <?php endif; ?>

  <?php elseif ($step === 'database'): ?>
    <h2>Database connection</h2>
    <div class="msg err"><?= $e($s['db_error']) ?></div>
    <p>Update the <code>DATABASE_*</code> lines in <code>.env</code>, then reload this page.</p>
    <p class="actions"><a class="btn ghost" href="<?= $e($s['action']) ?>">Try again</a></p>

  <?php elseif ($step === 'migrate'): ?>
    <h2><?= $upgrade ? 'Upgrade the database' : 'Create the database tables' ?></h2>
    <p><?= count($s['pending']) ?> step(s) to apply. Existing data is backed up first<?= $upgrade ? '' : ' (if there is any)' ?>.</p>
    <form method="post" action="<?= $e($s['action']) ?>">
      <?= $csrf ?><input type="hidden" name="action" value="migrate">
      <button class="btn" type="submit"><?= $upgrade ? 'Upgrade now' : 'Create tables' ?></button>
    </form>

  <?php elseif ($step === 'admin'): ?>
    <h2>Create your administrator account</h2>
    <p>This account manages users, storage and settings. Choose a new password — do not reuse an old one.</p>
    <form method="post" action="<?= $e($s['action']) ?>" class="form">
      <?= $csrf ?><input type="hidden" name="action" value="admin">
      <label>Username<input name="username" required minlength="3" maxlength="32" pattern="[A-Za-z0-9._-]{3,32}" value="<?= $e($s['form']['username'] ?? 'admin') ?>" autocomplete="username"></label>
      <label>Display name <small>(optional)</small><input name="display_name" maxlength="100" value="<?= $e($s['form']['display_name'] ?? '') ?>"></label>
      <label>E-mail <small>(optional)</small><input type="email" name="email" maxlength="191" value="<?= $e($s['form']['email'] ?? '') ?>" autocomplete="email"></label>
      <label>Password <small>(at least 10 characters)</small><input type="password" name="password" required minlength="10" autocomplete="new-password"></label>
      <label>Confirm password<input type="password" name="password_confirm" required minlength="10" autocomplete="new-password"></label>
      <button class="btn" type="submit">Create administrator</button>
    </form>

  <?php else: /* finish */ ?>
    <h2><?= $upgrade ? 'Finish the upgrade' : 'Almost done' ?></h2>
    <?php if ($s['legacy']['found'] && !$upgrade): ?>
      <h3>Import files from the old version</h3>
      <p>Found the old <code><?= $e($s['legacy']['path']) ?>/</code> folder with <?= (int) $s['legacy']['files'] ?> file(s). Importing copies your files, folders, tags, favourites, versions, comments, share links (old links keep working), saved texts and history. The old folder is not changed.</p>
      <?php if ($s['importer']): ?>
        <?php if (is_array($s['import'])): ?>
          <div class="msg ok"><?= $e(!empty($s['import']['done']) ? 'Import complete.' : 'Import in progress…') ?>
            <?php if (!empty($s['import']['counts']) && is_array($s['import']['counts'])): ?><br><small><?= $e(implode(' · ', array_map(static fn ($k, $v) => $k . ': ' . (is_scalar($v) ? $v : json_encode($v)), array_keys($s['import']['counts']), $s['import']['counts']))) ?></small><?php endif; ?>
          </div>
          <?php if (!empty($s['import']['warnings']) && is_array($s['import']['warnings'])): ?>
            <div class="todo"><strong>Please check</strong><ul>
              <?php foreach (array_slice($s['import']['warnings'], 0, 50) as $w): ?><li><?= $e(is_scalar($w) ? $w : json_encode($w)) ?></li><?php endforeach; ?>
            </ul></div>
          <?php endif; ?>
        <?php endif; ?>
        <?php if (!empty($s['temp_passwords'])): ?>
          <div class="todo" role="alert">
            <strong>One-time passwords for the imported accounts — copy them now, they are shown only once</strong>
            <p class="hint">Give each person their password; they must choose a new one when they first sign in.</p>
            <pre class="code"><?php foreach ($s['temp_passwords'] as $u => $p): ?><?= $e($u . ': ' . $p) ?>
<?php endforeach; ?></pre>
          </div>
        <?php endif; ?>
        <?php if (!is_array($s['import']) || empty($s['import']['done'])): ?>
        <form method="post" action="<?= $e($s['action']) ?>" class="form" id="import-form" data-auto="<?= is_array($s['import']) && empty($s['import']['done']) && empty($s['temp_passwords']) ? '1' : '0' ?>">
          <?= $csrf ?><input type="hidden" name="action" value="import">
          <label class="check"><input type="checkbox" name="share_all" value="1" checked> Share imported files with every imported user (keeps the access everyone had before)</label>
          <label class="check"><input type="checkbox" name="create_users" value="1" checked> Create accounts for the old users (one-time passwords are shown afterwards)</label>
          <button class="btn" type="submit"><?= is_array($s['import']) ? 'Continue import' : 'Import old data' ?></button>
        </form>
        <?php endif; ?>
      <?php else: ?>
        <p class="hint">The importer is still being built. You can finish now and run the import later from <strong>Admin → System</strong>.</p>
      <?php endif; ?>
    <?php endif; ?>

    <h3>Finish</h3>
    <p>After finishing, sign in with your administrator account.</p>
    <form method="post" action="<?= $e($s['action']) ?>">
      <?= $csrf ?><input type="hidden" name="action" value="finish">
      <button class="btn" type="submit">Finish and open FastTransfer</button>
    </form>
    <div class="todo">
      <strong>Security checklist</strong>
      <ul>
        <li>Remove <code>INSTALL_TOKEN</code> from <code>.env</code> when you are done.</li>
        <li>Rotate the credentials that were written in the old source code: Slack webhook, OCR.space key, Web Push (VAPID) keys and every old password. Put the new values in <code>.env</code>.</li>
        <li>Delete <code>remember_tokens.json</code>, <code>push_subs.json</code> and <code>ft_config.json</code> from the app folder.</li>
        <li>Keep a backup copy of <code>ENCRYPTION_KEY</code> somewhere safe — without it, encrypted files cannot be read.</li>
      </ul>
    </div>
  <?php endif; ?>
  </section>

  <?php if ($s['unlocked'] && $step !== 'token'): ?>
  <details class="card checks" <?= $step === 'checks' ? 'open' : '' ?>>
    <summary>Server check details</summary>
    <ul class="checklist">
      <?php foreach ($s['checks'] as $c): ?>
        <li class="<?= $c['ok'] ? 'ok' : ($c['required'] ? 'bad' : 'warn') ?>">
          <span class="mark" aria-hidden="true"><?= $c['ok'] ? '✓' : ($c['required'] ? '✗' : '!') ?></span>
          <span><?= $e($c['label']) ?><?php if ($c['detail'] !== ''): ?> <small><?= $e($c['detail']) ?></small><?php endif; ?></span>
        </li>
      <?php endforeach; ?>
    </ul>
  </details>
  <?php endif; ?>
</main>
<script nonce="<?= $e($nonce) ?>">
// Keep long imports going automatically (each batch is time-boxed on the server).
(function () {
  var f = document.getElementById('import-form');
  if (f && f.dataset.auto === '1') { setTimeout(function () { f.submit(); }, 600); }
})();
</script>
</body>
</html>
