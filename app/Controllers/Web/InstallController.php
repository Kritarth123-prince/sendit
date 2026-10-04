<?php
declare(strict_types=1);

namespace FT\Controllers\Web;

use FT\Core\Audit;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Env;
use FT\Core\Logger;
use FT\Core\RequestContext;
use FT\Core\Secrets;
use FT\Database\Migrator;
use FT\Http\Request;
use FT\Http\Response;
use FT\Storage\Paths;
use FT\Support\Install;

/**
 * Web installer and upgrader (/install).
 *
 * Shared hosts have no SSH, so this page does what a CLI installer would: checks the server,
 * creates/updates the database schema, creates the first administrator, optionally imports the
 * pre-upgrade JSON data, and marks the installation complete.
 *
 * It runs before the database necessarily exists, so it uses its own session ("ft_install"),
 * its own CSRF token and a file-based attempt counter instead of the DB-backed middleware.
 * Access requires INSTALL_TOKEN from .env.
 */
final class InstallController
{
    private const SESSION = 'ft_install';
    private const MAX_ATTEMPTS = 10;
    private const ATTEMPT_WINDOW = 900;

    public function show(Request $req): Response
    {
        $this->startSession($req);
        try {
            $s = $this->state($req);
        } catch (\Throwable $e) {
            // Never fall through to the generic error page: the installer is where setup problems are fixed.
            Logger::exception('install', $e);
            $s = $this->fallbackState($req, $this->safeError($e));
        }
        return $this->render($req, $s);
    }

    public function act(Request $req): Response
    {
        $this->startSession($req);
        try {
            return $this->handle($req);
        } catch (\Throwable $e) {
            Logger::exception('install', $e, ['action' => (string) ($_POST['action'] ?? '')]);
            $this->flash('error', $this->safeError($e));
            return $this->back($req);
        }
    }

    private function handle(Request $req): Response
    {
        $action = (string) ($_POST['action'] ?? '');

        if (!hash_equals((string) ($_SESSION['csrf'] ?? ''), (string) ($_POST['_csrf'] ?? ''))) {
            $this->flash('error', 'Your session expired. Please try again.');
            return $this->back($req);
        }

        if ($action === 'token') {
            return $this->checkToken($req);
        }
        if (empty($_SESSION['ok'])) {
            $this->flash('error', 'Enter the install token first.');
            return $this->back($req);
        }

        try {
            switch ($action) {
                case 'migrate':
                    $this->requireDb();
                    $applied = Migrator::migrate(true);
                    $this->flash('ok', $applied === [] ? 'The database is already up to date.' : 'Database ready: applied ' . count($applied) . ' migration(s).');
                    break;
                case 'admin':
                    $this->requireDb();
                    $this->createAdmin($req);
                    break;
                case 'import':
                    $this->requireDb();
                    $this->runImport($req);
                    break;
                case 'finish':
                    $this->requireDb();
                    $this->finish($req);
                    return Response::redirect($req->basePath());
                case 'signout':
                    $_SESSION = [];
                    break;
                default:
                    $this->flash('error', 'Unknown action.');
            }
        } catch (\Throwable $e) {
            Logger::exception('install', $e, ['action' => $action]);
            $this->flash('error', $this->safeError($e));
        }
        return $this->back($req);
    }

    // ------------------------------------------------------------------ actions

    private function checkToken(Request $req): Response
    {
        $expected = (string) Config::get('install.token');
        if ($expected === '') {
            $this->flash('error', 'INSTALL_TOKEN is not set in .env. Add it, then reload this page.');
            return $this->back($req);
        }
        // Wrong tokens are counted in storage/; without it there is no brute-force limit, so refuse.
        if (!$this->storageWritable()) {
            return $this->back($req); // the token step already shows storageHelp() above the form
        }
        if ($this->tooManyAttempts($req->ip())) {
            $this->flash('error', 'Too many attempts. Please wait 15 minutes and try again.');
            return $this->back($req);
        }
        $given = (string) ($_POST['token'] ?? '');
        if ($given === '' || !hash_equals($expected, $given)) {
            $this->recordAttempt($req->ip());
            Logger::security('Installer: wrong install token');
            $this->flash('error', 'That install token is not correct.');
            return $this->back($req);
        }
        session_regenerate_id(true);
        $_SESSION['ok'] = true;
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
        return $this->back($req);
    }

    private function createAdmin(Request $req): void
    {
        if ($this->adminCount() > 0) {
            $this->flash('ok', 'An administrator account already exists.');
            return;
        }
        $username = trim((string) ($_POST['username'] ?? ''));
        $display = trim((string) ($_POST['display_name'] ?? ''));
        $email = trim((string) ($_POST['email'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');
        $confirm = (string) ($_POST['password_confirm'] ?? '');

        $errors = [];
        if (!preg_match('/^[A-Za-z0-9._-]{3,32}$/', $username)) {
            $errors[] = 'Username: 3–32 characters, letters, numbers, dot, dash or underscore.';
        }
        if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = 'Enter a valid e-mail address or leave it empty.';
        }
        if (mb_strlen($password) < 10) {
            $errors[] = 'Password: at least 10 characters.';
        } elseif ($username !== '' && str_contains(strtolower($password), strtolower($username))) {
            $errors[] = 'Password must not contain the username.';
        }
        if ($password !== $confirm) {
            $errors[] = 'The two passwords do not match.';
        }
        if ($errors !== []) {
            $_SESSION['form'] = ['username' => $username, 'display_name' => $display, 'email' => $email];
            $this->flash('error', implode(' ', $errors));
            return;
        }
        if (Db::value('SELECT id FROM users WHERE username = ?', [$username]) !== null) {
            $this->flash('error', 'That username is already taken.');
            return;
        }
        $now = Db::now();
        $id = Db::insert('users', [
            'username'            => $username,
            'email'               => $email !== '' ? $email : null,
            'display_name'        => $display !== '' ? mb_substr($display, 0, 100) : $username,
            'password_hash'       => password_hash($password, PASSWORD_DEFAULT),
            'role_id'             => 1,
            'status'              => 'active',
            'password_changed_at' => $now,
            'created_at'          => $now,
            'updated_at'          => $now,
        ]);
        Audit::log('admin.user_create', ['user_id' => $id, 'category' => 'admin', 'target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'detail' => 'First administrator created by the installer']);
        unset($_SESSION['form']);
        $this->flash('ok', 'Administrator "' . $username . '" created.');
    }

    private function runImport(Request $req): void
    {
        $importer = '\\FT\\Legacy\\LegacyImporter';
        if (!class_exists($importer) || !method_exists($importer, 'run')) {
            $this->flash('error', 'The importer is not available in this build yet. You can finish now and import later from Admin → System.');
            return;
        }
        $adminId = (int) Db::value('SELECT id FROM users WHERE role_id = 1 AND deleted_at IS NULL ORDER BY id LIMIT 1');
        $options = [
            'admin_user_id' => $adminId,
            'share_imported_with_all_users' => !empty($_POST['share_all']),
            'create_legacy_users' => !empty($_POST['create_users']),
        ];
        $result = $importer::run($options, 15.0);
        // Keep one-time passwords out of the long-lived import state; they are displayed once.
        $temp = (array) ($result['temporary_passwords'] ?? []); // the importer returns an object (JSON {})
        if ($temp !== []) {
            $_SESSION['temp_passwords'] = array_merge($_SESSION['temp_passwords'] ?? [], $temp);
        }
        unset($result['temporary_passwords']);
        $_SESSION['import'] = $result;
        $this->flash('ok', !empty($result['done']) ? 'Import finished.' : 'Import batch finished — continuing…');
    }

    private function finish(Request $req): void
    {
        if (Migrator::pending() !== []) {
            throw new \RuntimeException('Run the database step first.');
        }
        if ($this->adminCount() === 0) {
            throw new \RuntimeException('Create the administrator account first.');
        }
        Install::markInstalled(['installed_by' => 'web']);
        Audit::log('system.install', ['category' => 'system', 'detail' => 'Installation completed (schema ' . Install::latestMigration() . ')']);
        $_SESSION = [];
    }

    // ------------------------------------------------------------------ state & checks

    /** @return array<string,mixed> */
    private function state(Request $req): array
    {
        $tokenSet = (string) Config::get('install.token') !== '';
        $unlocked = !empty($_SESSION['ok']);
        $checks = $this->checks();
        $s = [
            'base'        => $req->basePath(),
            'action'      => $this->url($req),
            'csrf'        => (string) $_SESSION['csrf'],
            'flash'       => $this->takeFlash(),
            'form'        => $_SESSION['form'] ?? [],
            'token_set'   => $tokenSet,
            'unlocked'    => $unlocked,
            'checks'      => $checks,
            'checks_ok'   => !in_array(false, array_column(array_filter($checks, static fn ($c) => $c['required']), 'ok'), true),
            'suggestions' => $this->suggestions(),
            'ready'       => Install::isReady(),
            'marker'      => Install::marker(),
            // An upgrade = this same database was installed before (marker fingerprint matches).
            'upgrade'     => !Install::isReady() && hash_equals(Install::databaseFingerprint(), (string) (Install::marker()['db'] ?? '')),
            'db_ok'       => null,
            'db_error'    => null,
            'pending'     => [],
            'admin_count' => 0,
            'legacy'      => $this->legacyInfo(),
            'import'      => $_SESSION['import'] ?? null,
            // One-time passwords for imported legacy accounts: shown once, then forgotten.
            'temp_passwords' => $this->takeTempPasswords(),
            'importer'    => class_exists('\\FT\\Legacy\\LegacyImporter'),
            'storage_ok'  => $this->storageWritable(),
            'storage_help' => $this->storageHelp(),
        ];
        if ($unlocked && $s['checks_ok']) {
            $err = null;
            $s['db_ok'] = Db::canConnect($err);
            if ($s['db_ok']) {
                $s['pending'] = Migrator::pending();
                if ($s['pending'] === [] || $this->tableExists('users')) {
                    $s['admin_count'] = $this->tableExists('users') ? $this->adminCount() : 0;
                }
            } else {
                $s['db_error'] = $this->safeError(new \RuntimeException((string) $err));
            }
        }
        return $s;
    }

    /** @return array<int,array{label:string,ok:bool,required:bool,detail:string}> */
    private function checks(): array
    {
        $c = [];
        $add = static function (string $label, bool $ok, bool $required, string $detail = '') use (&$c): void {
            $c[] = ['label' => $label, 'ok' => $ok, 'required' => $required, 'detail' => $detail];
        };
        $add('PHP 8.1 or newer', PHP_VERSION_ID >= 80100, true, 'Running ' . PHP_VERSION);
        foreach (['pdo_mysql', 'openssl', 'mbstring', 'json', 'fileinfo', 'zlib'] as $ext) {
            $add('PHP extension: ' . $ext, extension_loaded($ext), true);
        }
        foreach (['curl' => 'Slack, OCR and push notifications', 'gd' => 'image thumbnails', 'zip' => 'reading ZIP files', 'sodium' => 'faster cryptography'] as $ext => $why) {
            $add('Optional extension: ' . $ext, extension_loaded($ext), false, 'Used for ' . $why);
        }
        $add('.env file found', Env::loadedFrom() !== null, true, Env::loadedFrom() !== null ? 'Loaded' : 'Copy .env.example to .env next to index.php and fill it in');
        $add('APP_KEY set (32+ bytes)', Secrets::isConfigured(), true, 'Encrypts 2FA secrets and secret settings');
        $encKey = (string) Config::get('encryption.key');
        $add('ENCRYPTION_KEY set', $this->validKey($encKey), true, 'Encrypts stored files. Keep a backup copy of this key.');
        $add('DATABASE_NAME set', (string) Config::get('db.name') !== '', true);
        $writable = $this->storageWritable();
        $add('Storage folder writable', $writable, true, $writable ? 'STORAGE_PATH = ' . basename((string) Config::get('storage.path')) : $this->storageHelp());
        $add('HTTPS', Request::capture()->isHttps(), false, 'Recommended for sign-in cookies; set FORCE_HTTPS=true once your certificate works');
        return $c;
    }

    /** @return array<string,string> generated values for missing secrets */
    private function suggestions(): array
    {
        $out = [];
        if (!Secrets::isConfigured()) {
            $out['APP_KEY'] = 'base64:' . base64_encode(random_bytes(32));
        }
        if (!$this->validKey((string) Config::get('encryption.key'))) {
            $out['ENCRYPTION_KEY'] = 'base64:' . base64_encode(random_bytes(32));
        }
        if ((string) Config::get('install.token') === '') {
            $out['INSTALL_TOKEN'] = Secrets::token(32);
        }
        if ((string) Config::get('maintenance.token') === '') {
            $out['MAINTENANCE_TOKEN'] = Secrets::token(32);
        }
        return $out;
    }

    /** @return array{found:bool,path:string,files:int} */
    private function legacyInfo(): array
    {
        $dir = (string) Config::get('legacy.uploads_path');
        $found = is_file($dir . '/metadata.json') || is_file($dir . '/shares.json') || is_file($dir . '/texts.json');
        $files = 0;
        if ($found) {
            foreach (scandir($dir) ?: [] as $f) {
                if ($f[0] !== '.' && is_file($dir . '/' . $f) && !str_ends_with($f, '.json')) {
                    $files++;
                }
            }
        }
        return ['found' => $found, 'path' => basename($dir), 'files' => $files];
    }

    private function validKey(string $k): bool
    {
        if (str_starts_with($k, 'base64:')) {
            $d = base64_decode(substr($k, 7), true);
            return $d !== false && strlen($d) === 32;
        }
        return (strlen($k) === 64 && ctype_xdigit($k)) || strlen($k) >= 32;
    }

    /** PHP can create and write files under storage/runtime/locks (sessions of the installer depend on it). */
    private function storageWritable(): bool
    {
        try {
            $probe = Paths::runtime('locks') . '/.write-test';
            $ok = @file_put_contents($probe, 'ok') !== false;
            @unlink($probe);
            return $ok;
        } catch (\Throwable) {
            return false;
        }
    }

    private function storageHelp(): string
    {
        $dir = basename(str_replace('\\', '/', (string) Config::get('storage.path'))) ?: 'storage';
        return 'PHP cannot write to the "' . $dir . '" folder (STORAGE_PATH in .env). Create it next to index.php if it is missing, '
            . 'give it write permission (755; use 777 only if your host requires it), check that STORAGE_PATH is a folder inside your site '
            . '(for example STORAGE_PATH=storage), then reload this page.';
    }

    /**
     * Minimal page state when building the normal state failed, so the installer still renders
     * (with the reason) instead of the generic error page.
     * @return array<string,mixed>
     */
    private function fallbackState(Request $req, string $error): array
    {
        $try = static function (callable $fn, $default) {
            try {
                return $fn();
            } catch (\Throwable) {
                return $default;
            }
        };
        $checks = $try(fn () => $this->checks(), []);
        return [
            'base'         => $req->basePath(),
            'action'       => $this->url($req),
            'csrf'         => (string) ($_SESSION['csrf'] ?? ''),
            'flash'        => array_merge($this->takeFlash(), [['type' => 'error', 'message' => $error]]),
            'form'         => [],
            'token_set'    => (string) Config::get('install.token') !== '',
            'unlocked'     => !empty($_SESSION['ok']),
            'checks'       => $checks,
            'checks_ok'    => false,
            'suggestions'  => $try(fn () => $this->suggestions(), []),
            'ready'        => false,
            'marker'       => null,
            'upgrade'      => false,
            'db_ok'        => null,
            'db_error'     => null,
            'pending'      => [],
            'admin_count'  => 0,
            'legacy'       => ['found' => false, 'path' => '', 'files' => 0],
            'import'       => null,
            'temp_passwords' => $this->takeTempPasswords(),
            'importer'     => false,
            'storage_ok'   => $this->storageWritable(),
            'storage_help' => $this->storageHelp(),
        ];
    }

    private function adminCount(): int
    {
        return (int) Db::value('SELECT COUNT(*) FROM users WHERE role_id = 1 AND deleted_at IS NULL');
    }

    private function tableExists(string $table): bool
    {
        return (int) Db::value('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?', [$table]) === 1;
    }

    private function requireDb(): void
    {
        $err = null;
        if (!Db::canConnect($err)) {
            throw new \RuntimeException((string) $err);
        }
    }

    /** Turn low-level errors into advice that is safe to show (no credentials, no paths). */
    private function safeError(\Throwable $e): string
    {
        $m = $e->getMessage();
        return match (true) {
            str_contains($m, '[2002]') || str_contains($m, 'timed out') || str_contains($m, 'did not properly respond')
                => 'Could not reach the database server. Check DATABASE_HOST/DATABASE_PORT. On byethost the database only accepts connections from byethost’s own servers, so for local testing use your local MySQL (DATABASE_HOST=127.0.0.1).',
            str_contains($m, '[1045]') => 'The database refused the user name or password. Check DATABASE_USER and DATABASE_PASSWORD.',
            str_contains($m, '[1049]') => 'That database does not exist. Create it first (e.g. in phpMyAdmin or VistaPanel → MySQL Databases) and check DATABASE_NAME.',
            str_contains($m, '[1044]') => 'The database user has no access to that database. Grant it access or check DATABASE_NAME.',
            str_contains($m, 'not configured') => 'DATABASE_NAME is empty in .env.',
            str_contains($m, 'Storage directory is not writable') => $this->storageHelp(),
            $e instanceof \Error && (str_contains($m, 'not found') || str_contains($m, 'undefined function') || str_contains($m, 'undefined method'))
                => 'A program file is missing or incomplete (' . $this->shortMessage($m) . '). Upload the app/, views/ and database/ folders again (all files), then reload this page.',
            $e instanceof \RuntimeException && !str_contains($m, 'SQLSTATE') => $m,
            $e instanceof \PDOException => 'The database returned an error (' . $this->shortMessage($m) . '). Details were written to the storage/logs folder (reference ' . RequestContext::id() . ').',
            default => 'Something went wrong (' . get_class($e) . ', reference ' . RequestContext::id() . '). Details were written to the storage/logs folder.',
        };
    }

    /** Error text without file system paths or quoted credentials, at most 160 characters. */
    private function shortMessage(string $m): string
    {
        $m = (string) preg_replace('~(?:[A-Za-z]:)?[\\\\/][^\s\'"()]*[\\\\/]([^\\\\/\s\'"()]+)~', '$1', $m); // paths → file name
        $m = (string) preg_replace("~'[^']*'@'[^']*'~", "'…'@'…'", $m);                                   // user@host
        return mb_substr(trim($m), 0, 160);
    }

    // ------------------------------------------------------------------ session, rate limit, rendering

    private function startSession(Request $req): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE && !headers_sent()) {
            ini_set('session.use_strict_mode', '1');
            ini_set('session.use_only_cookies', '1');
            session_name(self::SESSION);
            session_set_cookie_params(['lifetime' => 0, 'path' => $req->basePath(), 'secure' => $req->isHttps(), 'httponly' => true, 'samesite' => 'Lax']);
            session_start();
        }
        if (empty($_SESSION['csrf'])) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        }
    }

    private function attemptsFile(): string
    {
        return Paths::runtime('locks') . '/install-attempts.json';
    }

    private function tooManyAttempts(string $ip): bool
    {
        $data = json_decode((string) @file_get_contents($this->attemptsFile()), true) ?: [];
        $key = hash('sha256', $ip);
        $rec = $data[$key] ?? null;
        return is_array($rec) && $rec['since'] > time() - self::ATTEMPT_WINDOW && $rec['count'] >= self::MAX_ATTEMPTS;
    }

    private function recordAttempt(string $ip): void
    {
        $file = $this->attemptsFile();
        $data = json_decode((string) @file_get_contents($file), true) ?: [];
        $key = hash('sha256', $ip);
        $rec = $data[$key] ?? null;
        if (!is_array($rec) || $rec['since'] <= time() - self::ATTEMPT_WINDOW) {
            $rec = ['since' => time(), 'count' => 0];
        }
        $rec['count']++;
        $data[$key] = $rec;
        foreach ($data as $k => $r) { // forget old entries
            if (($r['since'] ?? 0) <= time() - self::ATTEMPT_WINDOW) {
                unset($data[$k]);
            }
        }
        $data[$key] = $rec;
        @file_put_contents($file, json_encode($data), LOCK_EX);
    }

    /** @return array<string,string> username => temporary password (removed from the session once read) */
    private function takeTempPasswords(): array
    {
        $p = $_SESSION['temp_passwords'] ?? [];
        unset($_SESSION['temp_passwords']);
        return is_array($p) ? $p : [];
    }

    private function flash(string $type, string $message): void
    {
        $_SESSION['flash'][] = ['type' => $type, 'message' => $message];
    }

    /** @return array<int,array{type:string,message:string}> */
    private function takeFlash(): array
    {
        $f = $_SESSION['flash'] ?? [];
        unset($_SESSION['flash']);
        return is_array($f) ? $f : [];
    }

    private function url(Request $req): string
    {
        return $req->basePath() . (Config::get('app.pretty_urls') ? 'install' : 'index.php?r=/install');
    }

    private function back(Request $req): Response
    {
        return new Response('', 303, ['Location' => $this->url($req)]);
    }

    private function render(Request $req, array $s): Response
    {
        $nonce = base64_encode(random_bytes(16));
        $view = FT_ROOT . '/views/install.php';
        if (!is_file($view)) { // a missing view is a fatal error PHP cannot catch: say what to re-upload
            return new Response('FastTransfer setup: the file views/install.php is missing. Upload the views/ folder (and app/, assets/, database/) again, then reload this page.', 500, ['Content-Type' => 'text/plain; charset=utf-8']);
        }
        ob_start();
        require $view;
        $html = (string) ob_get_clean();
        return Response::html($html, 200, [
            'Content-Security-Policy' => "default-src 'self'; script-src 'self' 'nonce-{$nonce}'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; form-action 'self'; frame-ancestors 'self'; base-uri 'self'; object-src 'none'",
            'X-Robots-Tag' => 'noindex, nofollow',
        ]);
    }
}
