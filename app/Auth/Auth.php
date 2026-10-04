<?php
declare(strict_types=1);

namespace FT\Auth;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\RequestContext;
use FT\Core\Secrets;
use FT\Core\Settings;
use FT\Core\Stats;
use FT\Events\EventBus;
use FT\Http\Request;
use FT\Security\Csrf;
use FT\Security\Policy;
use FT\Security\RateLimiter;
use FT\Support\UserAgent;

/**
 * Authentication: PHP session + one user_sessions row per signed-in device, optional
 * remember-me cookie (selector:validator, validator stored hashed and rotated on every use), and
 * Bearer API tokens (FT\Auth\ApiTokens). Every request re-validates the session row and the
 * account status, so disabling a user or revoking a session takes effect immediately.
 *
 * Hardening notes:
 *  - session fixation: the PHP session id is regenerated on every privilege change (sign-in,
 *    remember-me resume, password change) and the row is bound to sha256(session_id()).
 *  - remember-me theft: a cookie whose selector matches but whose validator is stale means the
 *    cookie was copied and used elsewhere → that session is revoked and the owner is told.
 *    A short grace window accepts the immediately previous validator so two tabs racing the
 *    rotation are not mistaken for theft.
 *  - brute force: per-IP and per-username buckets, plus users.locked_until after
 *    LOCK_THRESHOLD consecutive failures (no password oracle while locked).
 *  - read-only API tokens may only make GET/HEAD requests (enforced here, centrally).
 *  - must_change_password is enforced server-side: while it is set (session or token), only
 *    PASSWORD_CHANGE_ALLOWED may be called (Router → enforcePasswordChange()), and no API
 *    token can be issued at sign-in.
 *  - per-username sign-in limits are keyed on the account id when the account exists, so
 *    case/accent variants matched by the utf8mb4_unicode_ci collation share one allowance.
 *
 * The user array exposed to the rest of the app is the users row WITHOUT secrets
 * (password_hash, totp_secret_enc, recovery_codes_enc) plus 'role' (slug) and 'session_id'.
 */
final class Auth
{
    public const SESSION_NAME = 'ft_sess';
    public const REMEMBER_COOKIE = 'ft_remember';
    public const LOCK_THRESHOLD = 20;
    public const LOCK_MINUTES = 15;
    public const REMEMBER_GRACE_SECONDS = 60;
    public const CHALLENGE_TTL = 300;
    public const CHALLENGE_MAX_ATTEMPTS = 5;
    public const TOKEN_LOGIN_DAYS = 90;

    /**
     * What an account with must_change_password may still reach ("METHOD path" → true): its own
     * profile, the boot data, a CSRF token, the password change itself, sign-out, the real-time
     * channel (so the open app keeps working) and the HTML pages that host the change dialog.
     * /legacy only ever redirects (old single-file URLs, including "?logout").
     */
    public const PASSWORD_CHANGE_ALLOWED = [
        'GET /api/v1/user'          => true,
        'GET /api/v1/bootstrap'     => true,
        'GET /api/v1/auth/csrf'     => true,
        'POST /api/v1/user/password' => true,
        'POST /api/v1/auth/logout'  => true,
        'GET /api/v1/events'        => true,
        'GET /api/v1/events/poll'   => true,
        'GET /api/v1/events/stream' => true,
        'GET /'                     => true,
        'GET /login'                => true,
        'POST /login'               => true,
        'GET /logout'               => true,
        'POST /logout'              => true,
        'GET /install'              => true,
        'POST /install'             => true,
        'GET /legacy'               => true,
        'POST /legacy'              => true,
    ];

    private static ?array $user = null;
    private static ?int $sessionRowId = null;
    private static ?string $via = null;
    private static bool $resolved = false;
    private static bool $mustChangePassword = false;

    // ------------------------------------------------------------------ session plumbing

    /**
     * Open (or re-open) the PHP session with hardened cookie settings. Safe to call repeatedly:
     * after closeSession() it re-opens the same session (re-reading its data) so that code which
     * needs to write — sign-in, CSRF token creation, 2FA challenges — always can.
     */
    public static function startSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        if (headers_sent()) {
            return;
        }
        self::configureSession();
        @session_start();
    }

    /** Release the session lock early (long requests, downloads, parallel GETs). */
    public static function closeSession(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_write_close();
        }
    }

    /**
     * Read the signed-in ids from the PHP session WITHOUT a database query and without holding the
     * session lock (read_and_close). For the real-time short-poll fast path (A5), which must stay
     * cheap: the result is only a hint — run the full resolve() before returning any data.
     * @return array{uid:int,sid:int,role:string}|null
     */
    public static function peekSession(): ?array
    {
        $cookie = $_COOKIE[self::SESSION_NAME] ?? null;
        if (!is_string($cookie) || !preg_match('/^[A-Za-z0-9,-]{16,128}$/', $cookie)) {
            return null;
        }
        if (session_status() !== PHP_SESSION_ACTIVE) {
            if (headers_sent()) {
                return null;
            }
            // With strict mode PHP answers an unknown id by creating a NEW (empty) session file,
            // so a client sending random cookies to the hot short-poll path would create one file
            // per request. A session that has no file has no data either: skip it.
            if (self::sessionFileMissing($cookie)) {
                return null;
            }
            // No Settings lookup here (that would open a MySQL connection): the idle lifetime is
            // irrelevant for a read-only peek, and session GC is skipped so it cannot use the
            // wrong lifetime and delete other users' sessions.
            self::configureSession(false);
            if (!@session_start(['read_and_close' => true, 'gc_probability' => 0])) {
                return null;
            }
        }
        $uid = (int) ($_SESSION['ft_uid'] ?? 0);
        $sid = (int) ($_SESSION['ft_sid'] ?? 0);
        if ($uid <= 0 || $sid <= 0) {
            return null;
        }
        return ['uid' => $uid, 'sid' => $sid, 'role' => (string) ($_SESSION['ft_role'] ?? 'user')];
    }

    private static function configureSession(bool $withLifetime = true): void
    {
        $req = Request::capture();
        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_cookies', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.cookie_httponly', '1');
        if ($withLifetime) {
            ini_set('session.gc_maxlifetime', (string) max(1440, Settings::int('session_idle_minutes', 720) * 60));
        }
        session_name(self::SESSION_NAME);
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => $req->basePath(),
            'secure'   => $req->isHttps(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
    }

    private static function hasSessionCookie(): bool
    {
        $c = $_COOKIE[self::SESSION_NAME] ?? null;
        return is_string($c) && $c !== '';
    }

    /**
     * True only when we can tell for certain that the native "files" session handler has no
     * file for this id. Any doubt (custom handler, "N;/path" layouts, unreadable or
     * open_basedir-restricted directory) answers false, so the session is opened normally.
     */
    private static function sessionFileMissing(string $id): bool
    {
        if (!preg_match('/^[A-Za-z0-9,-]{1,256}$/', $id)) {
            return true; // PHP never issues such an id, so no session can exist for it
        }
        if (strtolower((string) ini_get('session.save_handler')) !== 'files') {
            return false;
        }
        $path = (string) ini_get('session.save_path');
        if (str_contains($path, ';')) {
            return false;
        }
        $dir = rtrim($path !== '' ? $path : sys_get_temp_dir(), '/\\');
        if ($dir === '' || !@is_dir($dir)) {
            return false;
        }
        return !@is_file($dir . '/sess_' . $id);
    }

    // ------------------------------------------------------------------ request resolution

    /** Populate $req->user / $req->authVia from a Bearer token, the session or the remember cookie. */
    public static function resolve(Request $req): void
    {
        if (self::$resolved) {
            $req->user = self::$user;
            $req->authVia = self::$user !== null ? (self::$via ?? 'session') : null;
            return;
        }
        self::$resolved = true;

        // 1) Bearer API token (no cookies, no CSRF)
        $bearer = $req->bearerToken();
        if ($bearer !== null) {
            RateLimiter::enforce('token_auth', 'ip' . RateLimiter::ipSubject($req->ip()));
            $tok = ApiTokens::resolve($bearer);
            if ($tok === null) {
                Logger::security('Invalid API token presented');
                throw new ApiException('TOKEN_INVALID', 'The API token is invalid, expired or revoked.', 401);
            }
            $row = self::loadUser((int) $tok['user_id']);
            if ($row === null) {
                throw new ApiException('TOKEN_INVALID', 'The API token is invalid, expired or revoked.', 401);
            }
            self::assertActive($row);
            if ($tok['scopes'] === 'read' && $req->method() !== 'GET') {
                throw ApiException::forbidden('This API token is read-only. Create a full-access token to make changes.');
            }
            self::setUser($row, null);
            self::$user['token_id'] = (int) $tok['token_id'];
            self::$user['token_scopes'] = $tok['scopes'];
            self::$via = 'token';
            $req->user = self::$user;
            $req->authVia = 'token';
            return;
        }

        // 2) PHP session bound to a user_sessions row. Anonymous requests without a session
        //    cookie never create a session here (no session file per anonymous hit), and neither
        //    does a cookie naming a session that does not exist (strict mode would answer it with
        //    a brand-new empty session file). Code that needs a session starts one when it must.
        if (self::hasSessionCookie()
            && (session_status() === PHP_SESSION_ACTIVE || !self::sessionFileMissing((string) $_COOKIE[self::SESSION_NAME]))) {
            self::startSession();
        }
        $uid = (int) ($_SESSION['ft_uid'] ?? 0);
        $sid = (int) ($_SESSION['ft_sid'] ?? 0);
        if ($uid > 0 && $sid > 0) {
            $row = Db::one('SELECT * FROM user_sessions WHERE id = ? AND user_id = ?', [$sid, $uid]);
            $valid = $row !== null
                && $row['revoked_at'] === null
                && (string) $row['expires_at'] > Db::now()
                && $row['sid_hash'] !== null
                && hash_equals((string) $row['sid_hash'], hash('sha256', (string) session_id()));
            if ($valid) {
                $user = self::loadUser($uid);
                if ($user !== null) {
                    self::assertActive($user, $sid);
                    $wrote = self::touch($row);
                    self::setUser($user, $sid);
                    self::$via = 'session';
                    $req->user = self::$user;
                    $req->authVia = 'session';
                    // Keep the role hint used by the real-time fast path in step with the account.
                    if (($_SESSION['ft_role'] ?? null) !== self::$user['role']) {
                        $_SESSION['ft_role'] = self::$user['role'];
                        $wrote = true;
                    }
                    // PHP locks the session file for the whole request, which would serialise a
                    // browser's parallel GETs (thumbnails, listings, polls). Safe requests release
                    // it now; anything that writes later re-opens it via startSession(). The
                    // once-a-minute touch keeps the session open so its file timestamp is renewed
                    // and the PHP garbage collector never removes an active session.
                    if (!$wrote && $req->isSafeMethod()) {
                        self::closeSession();
                    }
                    return;
                }
                self::revokeSession($sid, 'account_deleted');
            }
            self::forgetSessionKeys();
        }

        // 3) Remember-me cookie
        $cookie = $_COOKIE[self::REMEMBER_COOKIE] ?? null;
        if (is_string($cookie) && $cookie !== '') {
            if (preg_match('/^([A-Za-z0-9]{24}):([a-f0-9]{64})$/', $cookie, $m)) {
                self::resolveRemember($m[1], $m[2], $req);
            } else {
                self::clearRememberCookie();
            }
            if (self::$user !== null) {
                $req->user = self::$user;
                $req->authVia = 'session';
                return;
            }
        }

        $req->user = null;
        $req->authVia = null;
    }

    public static function user(): ?array
    {
        return self::$user;
    }

    public static function id(): ?int
    {
        return self::$user !== null ? (int) self::$user['id'] : null;
    }

    public static function sessionRowId(): ?int
    {
        return self::$sessionRowId;
    }

    /** 'session' | 'token' | null */
    public static function via(): ?string
    {
        return self::$user !== null ? self::$via : null;
    }

    /**
     * Account-security changes (two-factor set-up, creating API tokens) need an interactive
     * browser session: a leaked API token must not be able to lock the owner out by turning on
     * 2FA with someone else's authenticator, or to mint further tokens for itself.
     */
    public static function requireInteractive(Request $req): void
    {
        if ($req->user === null) {
            throw ApiException::unauthorized();
        }
        if ($req->authVia !== 'session') {
            throw ApiException::forbidden('Sign in to FastTransfer in your browser to change security settings.');
        }
    }

    /**
     * Confirm the signed-in user's current password before a sensitive change (two-factor
     * set-up, new API tokens, turning 2FA off). A hijacked session cookie alone is then not
     * enough. Reads $field ("current_password") and accepts the other spelling ("password") too.
     * Wrong passwords count towards the "password" bucket (5 per hour per account); correct ones
     * are refunded so normal use never runs into the limit. Returns the full users row.
     */
    public static function reauthenticate(Request $req, string $field = 'current_password'): array
    {
        if ($req->user === null) {
            throw ApiException::unauthorized();
        }
        $id = (int) $req->user['id'];
        $other = $field === 'password' ? 'current_password' : 'password';
        $pw = $req->input($field);
        if (!is_string($pw) || $pw === '') {
            $pw = $req->input($other);
        }
        if (!is_string($pw) || $pw === '') {
            throw new ApiException('VALIDATION_FAILED', 'Enter your current password to confirm this change.', 422, ['fields' => [$field => 'Enter your current password.']]);
        }
        $check = RateLimiter::hit('password', 'u' . $id);
        if (!$check['allowed']) {
            throw ApiException::tooManyRequests($check['retry_after']);
        }
        $row = Db::one('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL', [$id]);
        if ($row === null) {
            throw ApiException::unauthorized();
        }
        if (!Passwords::verify($pw, (string) $row['password_hash'])) {
            Audit::log('auth.reauth_failed', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'meta' => ['path' => $req->path()]]);
            throw new ApiException('INVALID_CREDENTIALS', 'Your password is incorrect.', 422, ['fields' => [$field => 'Your password is incorrect.']]);
        }
        RateLimiter::refund('password', 'u' . $id);
        return $row;
    }

    // ------------------------------------------------------------------ forced password change

    /** True while the signed-in account (session or token) must choose a new password. */
    public static function passwordChangeRequired(): bool
    {
        return self::$user !== null && self::$mustChangePassword;
    }

    /** May an account that must change its password call this route? */
    public static function allowedDuringPasswordChange(string $method, string $path): bool
    {
        $method = strtoupper($method) === 'HEAD' ? 'GET' : strtoupper($method);
        $path = $path === '' ? '/' : $path;
        return isset(self::PASSWORD_CHANGE_ALLOWED[$method . ' ' . $path]);
    }

    /**
     * Called by the Router after authentication: while must_change_password is set, everything
     * outside PASSWORD_CHANGE_ALLOWED answers 403 PASSWORD_CHANGE_REQUIRED.
     */
    public static function enforcePasswordChange(Request $req): void
    {
        if ($req->user === null || !self::passwordChangeRequired()) {
            return;
        }
        if (self::allowedDuringPasswordChange($req->method(), $req->path())) {
            return;
        }
        throw new ApiException(
            'PASSWORD_CHANGE_REQUIRED',
            'Please choose a new password before you continue. Until then you can only change your password or sign out.',
            403,
            ['change_password' => 'POST /api/v1/user/password']
        );
    }

    // ------------------------------------------------------------------ sign-in flow

    /**
     * Check credentials with brute-force protection. Returns the full users row on success.
     * Does NOT create a session (2FA may still be required) — call login() afterwards.
     */
    public static function attempt(string $username, string $password, Request $req): array
    {
        $username = trim($username);
        $ipSubject = 'ip' . RateLimiter::ipSubject($req->ip());

        // Every attempt is counted up front (atomic, race-free); a success is refunded below.
        $ipCheck = RateLimiter::hit('login', $ipSubject);
        // The collation (utf8mb4_unicode_ci) matches "Admin", "ADMİN" and "ádmin" to the same row,
        // so the per-account allowance is keyed on the row id, never on the text typed.
        $row = ($username === '' || mb_strlen($username) > 191) ? null : Db::one(
            'SELECT * FROM users WHERE (username = ? OR (email IS NOT NULL AND email = ?)) AND deleted_at IS NULL LIMIT 1',
            [$username, $username]
        );
        $userSubject = self::loginSubject($username, $row);
        $userCheck = RateLimiter::hit('login_user', $userSubject);
        if (!$ipCheck['allowed'] || !$userCheck['allowed']) {
            self::recordLogin($row !== null ? (int) $row['id'] : null, $username, false, 'rate_limited', 'password', true, 'rate_limited');
            Logger::security('Sign-in rate limit reached', ['username' => mb_substr($username, 0, 64)]);
            throw ApiException::tooManyRequests(max($ipCheck['retry_after'], $userCheck['retry_after']));
        }

        // Locked: refuse without checking the password, so a locked account is no password oracle.
        if ($row !== null && $row['locked_until'] !== null && (string) $row['locked_until'] > Db::now()) {
            Passwords::verify($password, null); // equalise timing
            self::recordLogin((int) $row['id'], $username, false, 'locked');
            $wait = max(60, (Db::toUnix((string) $row['locked_until']) ?? time()) - time());
            throw new ApiException('ACCOUNT_LOCKED', 'This account is temporarily locked after too many failed sign-in attempts. Please try again in ' . (int) ceil($wait / 60) . ' minutes.', 403, ['retry_after' => $wait]);
        }

        $ok = $row !== null ? Passwords::verify($password, (string) $row['password_hash']) : Passwords::verify($password, null);
        if (!$ok) {
            self::registerFailure($row, $username, $row !== null ? 'bad_password' : 'unknown_user');
            throw new ApiException('INVALID_CREDENTIALS', 'Incorrect username or password.', 401);
        }
        if ($row['status'] !== 'active') {
            self::recordLogin((int) $row['id'], $username, false, (string) $row['status']);
            Audit::log('auth.login_failed', [
                'user_id' => null, 'actor_label' => mb_substr($username, 0, 100), 'target_type' => 'user',
                'target_id' => (int) $row['id'], 'owner_id' => (int) $row['id'], 'meta' => ['reason' => (string) $row['status']],
            ]);
            throw self::statusException((string) $row['status']);
        }
        $uid = (int) $row['id'];
        if (Passwords::needsRehash((string) $row['password_hash'])) {
            Db::update('users', ['password_hash' => Passwords::hash($password)], ['id' => $uid]);
        }
        Passwords::setWeakFlag($uid, !Passwords::isAcceptable($password, (string) $row['username'], $row['email'] ?? null));
        RateLimiter::refund('login', $ipSubject);
        RateLimiter::clear('login_user', $userSubject);
        return Db::one('SELECT * FROM users WHERE id = ?', [$uid]) ?? $row;
    }

    /**
     * The whole sign-in step shared by the JSON API and the HTML form.
     * @return array{status:string, user?:array, challenge?:string, token?:array}
     *         status 'ok' (signed in; token when $issueToken) or 'two_factor' (challenge issued)
     */
    public static function signIn(Request $req, string $username, string $password, bool $remember = false, ?string $code = null, ?string $recovery = null, bool $issueToken = false, string $tokenName = ''): array
    {
        $row = self::attempt($username, $password, $req);
        if ($issueToken && !Policy::can(self::sanitize($row), 'api.tokens')) {
            throw ApiException::forbidden('Your account cannot create API tokens.');
        }
        if ($issueToken) {
            self::refuseTokenWhilePasswordChange($row);
        }
        $method = 'password';
        if ((int) $row['totp_enabled'] === 1) {
            if (trim((string) $code) === '' && trim((string) $recovery) === '') {
                $challenge = self::beginTwoFactor($row, $remember, ['issue_token' => $issueToken, 'token_name' => $tokenName]);
                return ['status' => 'two_factor', 'challenge' => $challenge];
            }
            self::verifySecondFactor($row, $code, $recovery, $req);
            $method = '2fa';
        }
        return self::finishSignIn($row, $req, $remember, $method, $issueToken, $tokenName);
    }

    /**
     * Second step: a pending challenge (stored in the session) plus a TOTP or recovery code.
     * @return array{status:string, user:array, token?:array}
     */
    public static function completeTwoFactor(Request $req, string $challenge, ?string $code, ?string $recovery, bool $remember = false): array
    {
        $state = self::pendingTwoFactor($challenge);
        if ($state === null) {
            throw new ApiException('TWO_FACTOR_REQUIRED', 'Your sign-in attempt has expired. Please enter your username and password again.', 401, ['restart' => true]);
        }
        $row = Db::one('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL', [(int) $state['uid']]);
        if ($row === null || (int) $row['totp_enabled'] !== 1) {
            self::clearTwoFactor();
            throw new ApiException('TWO_FACTOR_REQUIRED', 'Your sign-in attempt has expired. Please enter your username and password again.', 401, ['restart' => true]);
        }
        if ($row['status'] !== 'active') {
            self::clearTwoFactor();
            throw self::statusException((string) $row['status']);
        }
        if ($row['locked_until'] !== null && (string) $row['locked_until'] > Db::now()) {
            self::clearTwoFactor();
            throw new ApiException('ACCOUNT_LOCKED', 'This account is temporarily locked after too many failed sign-in attempts. Please try again later.', 403);
        }
        try {
            self::verifySecondFactor($row, $code, $recovery, $req);
        } catch (ApiException $e) {
            if ($e->errorCode === 'TWO_FACTOR_INVALID') {
                $left = self::failTwoFactorAttempt();
                if ($left <= 0) {
                    throw new ApiException('TWO_FACTOR_REQUIRED', 'Too many incorrect codes. Please sign in again.', 401, ['restart' => true]);
                }
            }
            throw $e;
        }
        self::clearTwoFactor();
        return self::finishSignIn($row, $req, $remember || !empty($state['remember']), '2fa', !empty($state['issue_token']), (string) ($state['token_name'] ?? ''));
    }

    /**
     * Verify a TOTP or recovery code for a user who already proved their password.
     * Rate limited (bucket two_factor, per IP and per account). Failures count towards the lock.
     * @return string 'totp' | 'recovery'
     */
    public static function verifySecondFactor(array $row, ?string $code, ?string $recovery, Request $req): string
    {
        $uid = (int) $row['id'];
        $a = RateLimiter::hit('two_factor', 'ip' . RateLimiter::ipSubject($req->ip()));
        $b = RateLimiter::hit('two_factor', 'u' . $uid);
        if (!$a['allowed'] || !$b['allowed']) {
            self::recordLogin($uid, (string) $row['username'], false, 'rate_limited', '2fa', true, 'two_factor_rate_limited');
            throw ApiException::tooManyRequests(max($a['retry_after'], $b['retry_after']));
        }
        $used = Totp::verifyAny($row, $code, $recovery);
        if ($used === null) {
            self::registerFailure($row, (string) $row['username'], '2fa_failed', '2fa');
            throw new ApiException('TWO_FACTOR_INVALID', 'That code did not work. Check your authenticator app and try again.', 401);
        }
        if ($used === 'recovery') {
            $fresh = Db::one('SELECT recovery_codes_enc FROM users WHERE id = ?', [$uid]) ?? [];
            $left = Totp::remainingRecoveryCodes($fresh);
            Audit::log('auth.recovery_code_used', ['user_id' => $uid, 'target_type' => 'user', 'target_id' => $uid, 'owner_id' => $uid, 'meta' => ['remaining' => $left]]);
            Passwords::notifySecurity($uid, 'security.recovery_code_used', 'A recovery code was used to sign in', 'You have ' . $left . ' recovery ' . ($left === 1 ? 'code' : 'codes') . ' left. Generate new ones in the Security Centre if you are running low.');
        }
        return $used;
    }

    /** @return array{status:string, user:array, token?:array} */
    private static function finishSignIn(array $row, Request $req, bool $remember, string $method, bool $issueToken, string $tokenName): array
    {
        if ($issueToken) {
            self::refuseTokenWhilePasswordChange($row);
            $name = trim($tokenName) !== '' ? $tokenName : 'API client (' . UserAgent::describe($req->userAgent()) . ')';
            $created = ApiTokens::create((int) $row['id'], mb_substr($name, 0, 100), '*', self::TOKEN_LOGIN_DAYS, 'login');
            $user = self::loginWithoutSession($row, $req, $method === '2fa' ? '2fa' : 'token');
            return ['status' => 'ok', 'user' => $user, 'token' => ['token' => $created['token']] + ApiTokens::shape($created['row'])];
        }
        return ['status' => 'ok', 'user' => self::login($row, $req, $remember, $method)];
    }

    /**
     * Create the authenticated session (after password and, if enabled, 2FA succeeded).
     * @return array sanitized user
     */
    public static function login(array $userRow, Request $req, bool $remember = false, string $method = 'password'): array
    {
        self::startSession();
        if (session_status() === PHP_SESSION_ACTIVE && !headers_sent()) {
            session_regenerate_id(true); // prevent session fixation
        }
        $uid = (int) $userRow['id'];
        $assessment = self::assess($uid, $req);
        $now = Db::now();
        $idle = max(5, Settings::int('session_idle_minutes', 720));
        $rememberDays = max(1, Settings::int('remember_days', 30));
        $sessionRow = [
            'user_id'           => $uid,
            'sid_hash'          => hash('sha256', (string) session_id()),
            'device_id'         => self::upsertDevice($uid, $req),
            'ip'                => $req->ip(),
            'user_agent'        => $req->userAgent(),
            'auth_method'       => mb_substr($method, 0, 16),
            'two_factor_passed' => $method === '2fa' ? 1 : 0,
            'created_at'        => $now,
            'last_seen_at'      => $now,
            'expires_at'        => Db::ts(time() + ($remember ? $rememberDays * 86400 : $idle * 60)),
        ];
        $validator = null;
        if ($remember) {
            $validator = bin2hex(random_bytes(32));
            $sessionRow['remember_selector'] = Secrets::token(24);
            $sessionRow['remember_hash'] = hash('sha256', $validator);
            $sessionRow['remember_expires_at'] = Db::ts(time() + $rememberDays * 86400);
        }
        $sid = Db::insert('user_sessions', $sessionRow);
        $_SESSION['ft_uid'] = $uid;
        $_SESSION['ft_sid'] = $sid;
        $_SESSION['ft_role'] = Policy::roleSlug((int) $userRow['role_id']);
        unset($_SESSION['ft_2fa']);
        if ($remember && $validator !== null) {
            self::setRememberCookie($sessionRow['remember_selector'] . ':' . $validator, $rememberDays);
        }
        Csrf::rotate();
        self::$via = 'session';
        self::afterSignIn($userRow, $req, $method, $sid, $remember, $assessment);
        return self::$user;
    }

    /** Successful authentication that does not create a cookie session (API token issuance). */
    public static function loginWithoutSession(array $userRow, Request $req, string $method = 'token'): array
    {
        $uid = (int) $userRow['id'];
        $assessment = self::assess($uid, $req);
        self::upsertDevice($uid, $req);
        self::$via = 'token';
        self::afterSignIn($userRow, $req, $method, null, false, $assessment);
        return self::$user;
    }

    public static function logout(Request $req): void
    {
        // A token client "signing out" gives up the token it used; there is no cookie session.
        if (self::$via === 'token' && self::$user !== null && isset(self::$user['token_id'])) {
            $uid = (int) self::$user['id'];
            ApiTokens::revoke($uid, (int) self::$user['token_id'], 'logout');
            Audit::log('auth.logout', ['user_id' => $uid, 'target_type' => 'user', 'target_id' => $uid, 'owner_id' => $uid, 'meta' => ['via' => 'token']]);
            self::$user = null;
            self::$sessionRowId = null;
            self::$via = null;
            self::$mustChangePassword = false;
            return;
        }
        if (self::hasSessionCookie()) {
            self::startSession();
        }
        $sid = self::$sessionRowId ?? (int) ($_SESSION['ft_sid'] ?? 0);
        $uid = self::id() ?? (int) ($_SESSION['ft_uid'] ?? 0);
        if ($sid > 0) {
            // Never trust the session blindly: only revoke a row that belongs to this user.
            $owner = Db::value('SELECT user_id FROM user_sessions WHERE id = ?', [$sid]);
            if ($owner === null || (int) $owner !== $uid) {
                $sid = 0;
            }
        }
        if ($sid > 0) {
            self::revokeSession($sid, 'logout');
        }
        if ($uid > 0) {
            Audit::log('auth.logout', ['user_id' => $uid, 'target_type' => 'user', 'target_id' => $uid, 'owner_id' => $uid, 'meta' => ['session_id' => $sid > 0 ? $sid : null]]);
        }
        self::clearRememberCookie();
        $_SESSION = [];
        if (session_status() === PHP_SESSION_ACTIVE) {
            $p = session_get_cookie_params();
            if (!headers_sent()) {
                setcookie(self::SESSION_NAME, '', ['expires' => time() - 3600, 'path' => $p['path'], 'secure' => $p['secure'], 'httponly' => true, 'samesite' => 'Lax']);
            }
            session_destroy();
        }
        self::$user = null;
        self::$sessionRowId = null;
        self::$via = null;
        self::$mustChangePassword = false;
    }

    public static function revokeSession(int $sessionRowId, string $reason = 'revoked'): void
    {
        $row = Db::one('SELECT user_id FROM user_sessions WHERE id = ? AND revoked_at IS NULL', [$sessionRowId]);
        if ($row === null) {
            return;
        }
        Db::update('user_sessions', ['revoked_at' => Db::now(), 'revoked_reason' => mb_substr($reason, 0, 64)], ['id' => $sessionRowId]);
        EventBus::publish('session.revoked', ['session_id' => $sessionRowId, 'reason' => $reason], [(int) $row['user_id']]);
    }

    /**
     * Revoke every session of a user (optionally keeping one). Returns the number revoked.
     *
     * Event contract (§10.2): session_id null means "every session" — clients sign out. When one
     * session is kept (password change, "sign out other devices") a null event would also sign out
     * the device that asked, so each revoked session gets its own event instead.
     */
    public static function revokeAllSessions(int $userId, ?int $exceptSessionId = null, string $reason = 'revoked_all'): int
    {
        $reason = mb_substr($reason, 0, 64);
        if ($exceptSessionId === null) {
            $n = Db::run(
                'UPDATE user_sessions SET revoked_at = :t, revoked_reason = :r WHERE user_id = :u AND revoked_at IS NULL',
                ['t' => Db::now(), 'r' => $reason, 'u' => $userId]
            )->rowCount();
            if ($n > 0) {
                EventBus::publish('session.revoked', ['session_id' => null, 'reason' => $reason], [$userId]);
            }
            return $n;
        }
        $ids = array_map('intval', Db::column(
            'SELECT id FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL AND id <> ? ORDER BY id',
            [$userId, $exceptSessionId]
        ));
        if ($ids === []) {
            return 0;
        }
        [$in, $params] = Db::inList($ids, 's');
        $n = Db::run(
            "UPDATE user_sessions SET revoked_at = :t, revoked_reason = :r WHERE user_id = :u AND revoked_at IS NULL AND id IN {$in}",
            $params + ['t' => Db::now(), 'r' => $reason, 'u' => $userId]
        )->rowCount();
        // Only sessions that can still be in use need telling; expired rows have no open tabs.
        $live = array_map('intval', Db::column(
            "SELECT id FROM user_sessions WHERE id IN {$in} AND expires_at > :now ORDER BY id DESC LIMIT 100",
            $params + ['now' => Db::now()]
        ));
        foreach ($live as $sid) {
            EventBus::publish('session.revoked', ['session_id' => $sid, 'reason' => $reason], [$userId]);
        }
        return $n;
    }

    /**
     * Issue a fresh PHP session id for the current signed-in session (after a password change),
     * keeping the user_sessions row bound to it.
     */
    public static function regenerateCurrentSession(): void
    {
        $sid = self::$sessionRowId;
        if ($sid === null || session_status() !== PHP_SESSION_ACTIVE || headers_sent() || (int) ($_SESSION['ft_sid'] ?? 0) !== $sid) {
            return;
        }
        session_regenerate_id(true);
        Db::update('user_sessions', ['sid_hash' => hash('sha256', (string) session_id())], ['id' => $sid]);
    }

    /**
     * Sign an account out everywhere: every session and every API token, optionally keeping the
     * session and/or token that made this request. Used by password change and reset, the
     * administrator's reset and forced sign-out, and the Security Centre's "sign out everywhere".
     * @return array{sessions_revoked:int, tokens_revoked:int}
     */
    public static function signOutEverywhere(int $userId, string $reason, ?int $exceptSessionId = null, ?int $exceptTokenId = null, bool $includeTokens = true): array
    {
        $sessions = self::revokeAllSessions($userId, $exceptSessionId, $reason);
        $tokens = $includeTokens ? ApiTokens::revokeAllFor($userId, $reason, $exceptTokenId) : 0;
        return ['sessions_revoked' => $sessions, 'tokens_revoked' => $tokens];
    }

    /** "2 other sessions were signed out and 1 API token was revoked" (empty string when nothing was). */
    public static function describeSignOut(array $counts, bool $others = false): string
    {
        $parts = [];
        $s = (int) ($counts['sessions_revoked'] ?? 0);
        $t = (int) ($counts['tokens_revoked'] ?? 0);
        if ($s > 0) {
            $parts[] = $s . ' ' . ($others ? 'other ' : '') . ($s === 1 ? 'session was signed out' : 'sessions were signed out');
        }
        if ($t > 0) {
            $parts[] = $t . ' API ' . ($t === 1 ? 'token was revoked' : 'tokens were revoked');
        }
        return implode(' and ', $parts);
    }

    /**
     * Subject for the per-account sign-in limit: "id<n>" for an existing account (all spellings
     * that reach the same row share it), otherwise a normalised form of what was typed.
     */
    public static function loginSubject(string $username, ?array $row): string
    {
        if ($row !== null && isset($row['id'])) {
            return 'id' . (int) $row['id'];
        }
        return 'user' . self::normaliseLoginName($username);
    }

    /** Lower case without accents ("ÁdMïn" → "admin"); Normalizer (intl) when present, else a transliteration table. */
    public static function normaliseLoginName(string $name): string
    {
        $name = mb_strtolower(trim($name));
        if (class_exists(\Normalizer::class)) {
            $decomposed = \Normalizer::normalize($name, \Normalizer::FORM_KD);
            if (is_string($decomposed)) {
                $name = (string) preg_replace('/\p{Mn}+/u', '', $decomposed);
            }
        }
        static $map = null;
        $map ??= [
            'à' => 'a', 'á' => 'a', 'â' => 'a', 'ã' => 'a', 'ä' => 'a', 'å' => 'a', 'ā' => 'a', 'ă' => 'a', 'ą' => 'a', 'æ' => 'ae',
            'ç' => 'c', 'ć' => 'c', 'ĉ' => 'c', 'ċ' => 'c', 'č' => 'c', 'ď' => 'd', 'đ' => 'd', 'ð' => 'd',
            'è' => 'e', 'é' => 'e', 'ê' => 'e', 'ë' => 'e', 'ē' => 'e', 'ĕ' => 'e', 'ė' => 'e', 'ę' => 'e', 'ě' => 'e',
            'ĝ' => 'g', 'ğ' => 'g', 'ġ' => 'g', 'ģ' => 'g', 'ĥ' => 'h', 'ħ' => 'h',
            'ì' => 'i', 'í' => 'i', 'î' => 'i', 'ï' => 'i', 'ĩ' => 'i', 'ī' => 'i', 'ĭ' => 'i', 'į' => 'i', 'ı' => 'i',
            'ĵ' => 'j', 'ķ' => 'k', 'ĺ' => 'l', 'ļ' => 'l', 'ľ' => 'l', 'ŀ' => 'l', 'ł' => 'l',
            'ñ' => 'n', 'ń' => 'n', 'ņ' => 'n', 'ň' => 'n', 'ŉ' => 'n',
            'ò' => 'o', 'ó' => 'o', 'ô' => 'o', 'õ' => 'o', 'ö' => 'o', 'ø' => 'o', 'ō' => 'o', 'ŏ' => 'o', 'ő' => 'o', 'œ' => 'oe',
            'ŕ' => 'r', 'ŗ' => 'r', 'ř' => 'r', 'ś' => 's', 'ŝ' => 's', 'ş' => 's', 'š' => 's', 'ș' => 's', 'ß' => 'ss',
            'ţ' => 't', 'ť' => 't', 'ŧ' => 't', 'ț' => 't', 'þ' => 'th',
            'ù' => 'u', 'ú' => 'u', 'û' => 'u', 'ü' => 'u', 'ũ' => 'u', 'ū' => 'u', 'ŭ' => 'u', 'ů' => 'u', 'ű' => 'u', 'ų' => 'u',
            'ŵ' => 'w', 'ý' => 'y', 'ÿ' => 'y', 'ŷ' => 'y', 'ź' => 'z', 'ż' => 'z', 'ž' => 'z',
        ];
        $name = strtr($name, $map);
        // Any remaining combining marks (input already in decomposed form).
        return (string) preg_replace('/\p{Mn}+/u', '', $name);
    }

    /** Reload the signed-in user's row (after changing it) so later code in this request sees it. */
    public static function refresh(): void
    {
        if (self::$user === null) {
            return;
        }
        $row = self::loadUser((int) self::$user['id']);
        if ($row !== null) {
            $extra = array_intersect_key(self::$user, ['token_id' => 1, 'token_scopes' => 1]);
            self::setUser($row, self::$sessionRowId);
            self::$user += $extra;
        }
    }

    // ------------------------------------------------------------------ 2FA challenge state

    /** Store a pending second-factor challenge in the session (5 minutes). Returns the challenge. */
    public static function beginTwoFactor(array $userRow, bool $remember, array $extra = []): string
    {
        self::startSession();
        $challenge = Secrets::token(43);
        $_SESSION['ft_2fa'] = [
            'c'           => hash('sha256', $challenge),
            'uid'         => (int) $userRow['id'],
            'remember'    => $remember,
            'exp'         => time() + self::CHALLENGE_TTL,
            'tries'       => 0,
            'issue_token' => !empty($extra['issue_token']),
            'token_name'  => mb_substr((string) ($extra['token_name'] ?? ''), 0, 100),
        ];
        return $challenge;
    }

    /** @return array<string,mixed>|null the pending challenge state when valid */
    public static function pendingTwoFactor(string $challenge): ?array
    {
        self::startSession();
        $s = $_SESSION['ft_2fa'] ?? null;
        if (!is_array($s) || $challenge === '' || !isset($s['c'], $s['uid'], $s['exp'])) {
            return null;
        }
        if ((int) $s['exp'] < time() || (int) ($s['tries'] ?? 0) >= self::CHALLENGE_MAX_ATTEMPTS) {
            unset($_SESSION['ft_2fa']);
            return null;
        }
        return hash_equals((string) $s['c'], hash('sha256', $challenge)) ? $s : null;
    }

    /** Count a wrong code against the pending challenge. Returns attempts left (0 = challenge dropped). */
    public static function failTwoFactorAttempt(): int
    {
        if (!isset($_SESSION['ft_2fa']) || !is_array($_SESSION['ft_2fa'])) {
            return 0;
        }
        $_SESSION['ft_2fa']['tries'] = (int) ($_SESSION['ft_2fa']['tries'] ?? 0) + 1;
        $left = self::CHALLENGE_MAX_ATTEMPTS - $_SESSION['ft_2fa']['tries'];
        if ($left <= 0) {
            unset($_SESSION['ft_2fa']);
        }
        return max(0, $left);
    }

    public static function clearTwoFactor(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            unset($_SESSION['ft_2fa']);
        }
    }

    // ------------------------------------------------------------------ shapes

    /** Strip secrets and add the role slug. */
    public static function sanitize(array $row, ?int $sessionRowId = null): array
    {
        unset($row['password_hash'], $row['totp_secret_enc'], $row['recovery_codes_enc'], $row['totp_last_step']);
        $row['id'] = (int) $row['id'];
        $row['role_id'] = (int) $row['role_id'];
        $row['role'] = Policy::roleSlug((int) $row['role_id']);
        $row['session_id'] = $sessionRowId;
        return $row;
    }

    /** User(me) JSON shape (docs/ARCHITECTURE.md §9.2) plus session_id. */
    public static function me(array $user): array
    {
        $prefs = json_decode((string) ($user['preferences'] ?? ''), true);
        $prefs = is_array($prefs) ? array_filter($prefs, static fn ($k) => !str_starts_with((string) $k, '_'), ARRAY_FILTER_USE_KEY) : [];
        $quota = null;
        try {
            // Optional module (A2); a missing or broken class must never break sign-in.
            if (class_exists(\FT\Storage\QuotaService::class)) {
                $quota = \FT\Storage\QuotaService::usage((int) $user['id']);
            }
        } catch (\Throwable $e) {
            Logger::warning('auth', 'Quota usage unavailable', ['error' => $e->getMessage()]);
        }
        $quota = is_array($quota) ? $quota : self::fallbackQuota($user);
        return [
            'id'                   => (int) $user['id'],
            'username'             => (string) $user['username'],
            'display_name'         => (string) (($user['display_name'] ?? '') !== '' ? $user['display_name'] : $user['username']),
            'email'                => $user['email'] ?? null,
            'role'                 => Policy::roleSlug((int) $user['role_id']),
            'status'               => (string) $user['status'],
            'quota'                => $quota,
            'two_factor_enabled'   => (bool) ($user['totp_enabled'] ?? false),
            'must_change_password' => (bool) ($user['must_change_password'] ?? false),
            'password_changed_at'  => Db::iso($user['password_changed_at'] ?? null),
            'created_at'           => Db::iso($user['created_at'] ?? null),
            'last_login_at'        => Db::iso($user['last_login_at'] ?? null),
            'preferences'          => $prefs !== [] ? $prefs : (object) [],
            'permissions'          => Policy::permissionsFor($user),
            'session_id'           => isset($user['session_id']) ? (int) $user['session_id'] : null,
        ];
    }

    /** Quota shape computed from the users row (used when A2's QuotaService is unavailable). */
    public static function fallbackQuota(array $user): array
    {
        $quota = self::effectiveQuota($user);
        $used = (int) ($user['used_bytes'] ?? 0);
        return [
            'quota_bytes'     => $quota,
            'used_bytes'      => $used,
            'reserved_bytes'  => 0,
            'available_bytes' => $quota === null ? null : max(0, $quota - $used),
            'percent'         => $quota === null || $quota === 0 ? 0 : round(min(100, $used * 100 / $quota), 1),
        ];
    }

    /** Effective quota in bytes (null = unlimited): explicit value, else the role default. */
    public static function effectiveQuota(array $user): ?int
    {
        try {
            if (class_exists(\FT\Storage\QuotaService::class) && method_exists(\FT\Storage\QuotaService::class, 'effectiveQuota')) {
                $q = \FT\Storage\QuotaService::effectiveQuota($user);
                if ($q === null || is_int($q)) {
                    return $q;
                }
            }
        } catch (\Throwable) {
            // fall through to the local rule
        }
        if (isset($user['quota_bytes']) && $user['quota_bytes'] !== null) {
            $q = is_numeric($user['quota_bytes']) ? (int) $user['quota_bytes'] : PHP_INT_MAX;
            return $q >= PHP_INT_MAX ? null : $q;
        }
        return match ((int) ($user['role_id'] ?? 2)) {
            1 => null,
            3 => max(0, Settings::int('guest_quota_bytes', 0)),
            default => max(0, Settings::int('default_quota_bytes', 1073741824)),
        };
    }

    /** UserRef shape. */
    public static function ref(?array $user): ?array
    {
        if ($user === null) {
            return null;
        }
        return [
            'id' => (int) $user['id'],
            'username' => (string) $user['username'],
            'display_name' => (string) (($user['display_name'] ?? '') !== '' ? $user['display_name'] : $user['username']),
        ];
    }

    // ------------------------------------------------------------------ internals

    private static function setUser(array $row, ?int $sessionRowId): void
    {
        self::$user = self::sanitize($row, $sessionRowId);
        self::$sessionRowId = $sessionRowId;
        self::$mustChangePassword = !empty($row['must_change_password']);
        RequestContext::setUserId((int) $row['id']);
    }

    /** Sign-in with issue_token: no new API token until the password has been changed. */
    private static function refuseTokenWhilePasswordChange(array $row): void
    {
        if (!empty($row['must_change_password'])) {
            throw new ApiException(
                'PASSWORD_CHANGE_REQUIRED',
                'Please sign in with your browser and choose a new password before creating API tokens.',
                403
            );
        }
    }

    private static function loadUser(int $id): ?array
    {
        return Db::one('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL', [$id]);
    }

    private static function statusException(string $status): ApiException
    {
        return $status === 'suspended'
            ? new ApiException('ACCOUNT_SUSPENDED', 'This account has been suspended. Please contact an administrator.', 403)
            : new ApiException('ACCOUNT_DISABLED', 'This account has been disabled. Please contact an administrator.', 403);
    }

    private static function assertActive(?array $user, ?int $sessionRowId = null): void
    {
        if ($user === null) {
            throw ApiException::unauthorized();
        }
        if ($user['status'] !== 'active') {
            if ($sessionRowId !== null) {
                Db::update('user_sessions', ['revoked_at' => Db::now(), 'revoked_reason' => 'account_' . $user['status']], ['id' => $sessionRowId]);
                self::forgetSessionKeys();
                self::clearRememberCookie();
            }
            throw self::statusException((string) $user['status']);
        }
    }

    private static function forgetSessionKeys(): void
    {
        unset($_SESSION['ft_uid'], $_SESSION['ft_sid'], $_SESSION['ft_role']);
    }

    /** Sliding idle expiry + last_seen, written at most once a minute. Returns true when it wrote. */
    private static function touch(array $sessionRow): bool
    {
        $last = Db::toUnix((string) $sessionRow['last_seen_at']) ?? 0;
        if (time() - $last < 60) {
            return false;
        }
        $set = ['last_seen_at' => Db::now()];
        if ($sessionRow['remember_selector'] === null) {
            $set['expires_at'] = Db::ts(time() + max(5, Settings::int('session_idle_minutes', 720)) * 60);
        }
        $ip = RequestContext::ip();
        if ($ip !== null && $ip !== $sessionRow['ip']) {
            $set['ip'] = $ip;
        }
        Db::update('user_sessions', $set, ['id' => (int) $sessionRow['id']]);
        Db::update('users', ['last_seen_at' => Db::now()], ['id' => (int) $sessionRow['user_id']]);
        if ($sessionRow['device_id'] !== null) {
            Db::update('user_devices', ['last_seen_at' => Db::now(), 'last_ip' => $ip], ['id' => (int) $sessionRow['device_id']]);
        }
        return true;
    }

    private static function resolveRemember(string $selector, string $validator, Request $req): void
    {
        $row = Db::one('SELECT * FROM user_sessions WHERE remember_selector = ?', [$selector]);
        $now = Db::now();
        if ($row === null || $row['revoked_at'] !== null || $row['remember_expires_at'] === null
            || (string) $row['remember_expires_at'] <= $now || (string) $row['expires_at'] <= $now) {
            self::clearRememberCookie();
            return;
        }
        $sid = (int) $row['id'];
        $uid = (int) $row['user_id'];
        $hash = hash('sha256', $validator);

        if (hash_equals((string) $row['remember_hash'], $hash)) {
            $user = self::loadUser($uid);
            if ($user === null || $user['status'] !== 'active') {
                self::revokeSession($sid, $user === null ? 'account_deleted' : 'account_' . $user['status']);
                self::clearRememberCookie();
                return;
            }
            self::resumeFromRemember($user, $row, $req, $hash);
            return;
        }

        // The immediately previous validator, shortly after a rotation: a parallel request raced
        // the rotation. Authenticate this request only (no rotation, no cookie change).
        $prev = $row['remember_prev_hash'] ?? null;
        $rotated = Db::toUnix(isset($row['remember_rotated_at']) ? (string) $row['remember_rotated_at'] : null);
        if (is_string($prev) && $prev !== '' && hash_equals($prev, $hash) && $rotated !== null && time() - $rotated <= self::REMEMBER_GRACE_SECONDS) {
            $user = self::loadUser($uid);
            if ($user !== null && $user['status'] === 'active') {
                self::setUser($user, $sid);
                self::$via = 'session';
            }
            return;
        }

        // Selector matched but the validator is stale: the cookie was copied and used elsewhere.
        self::revokeSession($sid, 'remember_theft');
        self::clearRememberCookie();
        Logger::security('Remember-me validator mismatch; session revoked', ['session_id' => $sid]);
        $username = (string) (Db::value('SELECT username FROM users WHERE id = ?', [$uid]) ?? '');
        self::recordLogin($uid, $username, false, 'cookie_reuse', 'remember', true, 'remember_cookie_reused');
        Audit::log('auth.session_revoked', ['user_id' => null, 'actor_label' => 'System', 'target_type' => 'user', 'target_id' => $uid, 'owner_id' => $uid, 'meta' => ['session_id' => $sid, 'reason' => 'remember_theft']]);
        Passwords::notifySecurity(
            $uid,
            'security.session_theft',
            'We signed out a device to protect your account',
            'A saved sign-in was used from two places, which can mean it was copied. That device has been signed out. If you did not expect this, change your password.',
            ['session_id' => $sid],
            'remember-theft:' . $sid
        );
    }

    private static function resumeFromRemember(array $user, array $row, Request $req, string $currentHash): void
    {
        $sid = (int) $row['id'];
        if (headers_sent()) {
            self::setUser($user, $sid); // cannot rotate without sending cookies
            self::$via = 'session';
            return;
        }
        self::startSession();
        if (session_status() === PHP_SESSION_ACTIVE) {
            session_regenerate_id(true);
        }
        $validator = bin2hex(random_bytes(32)); // rotate on every use
        $now = Db::now();
        $n = Db::run(
            'UPDATE user_sessions SET remember_prev_hash = remember_hash, remember_hash = :h, remember_rotated_at = :t,
                    sid_hash = :sid, last_seen_at = :t2, ip = :ip
             WHERE id = :id AND remember_hash = :old AND revoked_at IS NULL',
            ['h' => hash('sha256', $validator), 't' => $now, 'sid' => hash('sha256', (string) session_id()), 't2' => $now, 'ip' => $req->ip(), 'id' => $sid, 'old' => $currentHash]
        )->rowCount();
        if ($n !== 1) {
            // Another request rotated first: treat like the grace case.
            self::setUser($user, $sid);
            self::$via = 'session';
            return;
        }
        $days = max(1, (int) ceil(((Db::toUnix((string) $row['remember_expires_at']) ?? time()) - time()) / 86400));
        self::setRememberCookie($row['remember_selector'] . ':' . $validator, $days);
        $_SESSION['ft_uid'] = (int) $user['id'];
        $_SESSION['ft_sid'] = $sid;
        $_SESSION['ft_role'] = Policy::roleSlug((int) $user['role_id']);
        self::setUser($user, $sid);
        self::$via = 'session';
        self::recordLogin((int) $user['id'], (string) $user['username'], true, null, 'remember');
    }

    private static function setRememberCookie(string $value, int $days): void
    {
        if (headers_sent()) {
            return;
        }
        $req = Request::capture();
        setcookie(self::REMEMBER_COOKIE, $value, [
            'expires'  => time() + $days * 86400,
            'path'     => $req->basePath(),
            'secure'   => $req->isHttps(),
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        $_COOKIE[self::REMEMBER_COOKIE] = $value;
    }

    private static function clearRememberCookie(): void
    {
        if (!isset($_COOKIE[self::REMEMBER_COOKIE]) || headers_sent()) {
            return;
        }
        $req = Request::capture();
        setcookie(self::REMEMBER_COOKIE, '', ['expires' => time() - 3600, 'path' => $req->basePath(), 'secure' => $req->isHttps(), 'httponly' => true, 'samesite' => 'Lax']);
        unset($_COOKIE[self::REMEMBER_COOKIE]);
    }

    private static function upsertDevice(int $userId, Request $req): ?int
    {
        $client = $req->clientId();
        if ($client === null) {
            return null;
        }
        $hash = hash('sha256', $client);
        $now = Db::now();
        Db::run(
            'INSERT INTO user_devices (user_id, client_hash, name, user_agent, last_ip, first_seen_at, last_seen_at)
             VALUES (:u, :h, :n, :ua, :ip, :f, :l)
             ON DUPLICATE KEY UPDATE name = VALUES(name), user_agent = VALUES(user_agent), last_ip = VALUES(last_ip), last_seen_at = VALUES(last_seen_at)',
            ['u' => $userId, 'h' => $hash, 'n' => mb_substr(UserAgent::describe($req->userAgent()), 0, 120), 'ua' => $req->userAgent(), 'ip' => $req->ip(), 'f' => $now, 'l' => $now]
        );
        $id = Db::value('SELECT id FROM user_devices WHERE user_id = ? AND client_hash = ?', [$userId, $hash]);
        return $id !== null ? (int) $id : null;
    }

    /**
     * Is this sign-in unusual for the account? New device, new IP, or recent failures from the
     * same address. The very first sign-in of an account is never flagged.
     * @return array{first:bool,new_device:bool,new_ip:bool,reasons:string[]}
     */
    private static function assess(int $userId, Request $req): array
    {
        $out = ['first' => true, 'new_device' => false, 'new_ip' => false, 'reasons' => []];
        try {
            $prior = (int) Db::value('SELECT COUNT(*) FROM login_history WHERE user_id = ? AND success = 1', [$userId]);
            $out['first'] = $prior === 0;
            $client = $req->clientId();
            if ($client !== null) {
                $known = Db::value('SELECT id FROM user_devices WHERE user_id = ? AND client_hash = ?', [$userId, hash('sha256', $client)]);
            } else {
                $known = Db::value('SELECT id FROM login_history WHERE user_id = ? AND success = 1 AND user_agent = ? LIMIT 1', [$userId, $req->userAgent()]);
            }
            $out['new_device'] = $known === null;
            $out['new_ip'] = Db::value('SELECT id FROM login_history WHERE user_id = ? AND success = 1 AND ip = ? LIMIT 1', [$userId, $req->ip()]) === null;
            $f = Db::one(
                'SELECT SUM(CASE WHEN user_id = :u THEN 1 ELSE 0 END) AS mine, COUNT(*) AS total
                 FROM login_history WHERE ip = :ip AND success = 0 AND created_at > :since',
                ['u' => $userId, 'ip' => $req->ip(), 'since' => Db::ts(time() - 86400)]
            ) ?? [];
            if (!$out['first'] && $out['new_device']) {
                $out['reasons'][] = 'new_device';
            }
            if (!$out['first'] && $out['new_ip']) {
                $out['reasons'][] = 'new_ip';
            }
            if ((int) ($f['mine'] ?? 0) >= 3 || (int) ($f['total'] ?? 0) >= 10) {
                $out['reasons'][] = 'previous_failures';
            }
        } catch (\Throwable $e) {
            Logger::warning('auth', 'Sign-in assessment failed', ['error' => $e->getMessage()]);
        }
        return $out;
    }

    /** Book-keeping shared by every successful sign-in. */
    private static function afterSignIn(array $userRow, Request $req, string $method, ?int $sid, bool $remember, array $assessment): void
    {
        $uid = (int) $userRow['id'];
        $now = Db::now();
        Db::update('users', ['last_login_at' => $now, 'last_login_ip' => $req->ip(), 'last_seen_at' => $now, 'failed_login_count' => 0, 'locked_until' => null], ['id' => $uid]);
        self::setUser(self::loadUser($uid) ?? $userRow, $sid);
        RequestContext::setUserId($uid);
        $reasons = $assessment['reasons'];
        self::recordLogin($uid, (string) $userRow['username'], true, null, $method, $reasons !== [], $reasons !== [] ? implode(',', $reasons) : null);
        Audit::log('auth.login', ['user_id' => $uid, 'target_type' => 'user', 'target_id' => $uid, 'owner_id' => $uid, 'meta' => [
            'method' => $method, 'remember' => $remember, 'session_id' => $sid, 'suspicious' => $reasons,
        ]]);
        Stats::bump('logins');
        EventBus::publish('stats.updated', ['metric' => 'logins', 'delta' => 1], [], ['admin' => true, 'actor_id' => $uid]);

        if ($reasons === []) {
            return;
        }
        $device = UserAgent::describe($req->userAgent());
        $when = gmdate('d M Y, H:i') . ' UTC';
        $body = $device . ' · ' . $req->ip() . ' · ' . $when;
        $notifier = 'FT\\Notifications\\Notifier';
        try {
            if (!class_exists($notifier)) {
                return;
            }
            if (in_array('previous_failures', $reasons, true)) {
                $notifier::notify($uid, 'security', 'login.suspicious', 'Unusual sign-in to your account',
                    'Someone signed in after several failed attempts from the same address: ' . $body . '. If this was not you, change your password and sign out other sessions.',
                    ['link' => '#/security', 'session_id' => $sid, 'reasons' => $reasons], 'login-suspicious:' . $uid . ':' . ($sid ?? gmdate('YmdHi')), $uid);
            } else {
                $notifier::notify($uid, 'login', 'login.new_device', 'New sign-in to your account',
                    $body . '. If this was not you, change your password and sign out other sessions in the Security Centre.',
                    ['link' => '#/security', 'session_id' => $sid, 'reasons' => $reasons], 'login-new:' . $uid . ':' . ($sid ?? gmdate('YmdHi')), $uid);
            }
        } catch (\Throwable $e) {
            Logger::warning('auth', 'Sign-in notification failed', ['error' => $e->getMessage()]);
        }
    }

    /** A failed password or second-factor check: counters, lock, history, audit, alerts. */
    private static function registerFailure(?array $row, string $username, string $reason, string $method = 'password'): void
    {
        $uid = $row !== null ? (int) $row['id'] : null;
        $suspicious = false;
        if ($uid !== null) {
            Db::run('UPDATE users SET failed_login_count = failed_login_count + 1 WHERE id = ?', [$uid]);
            $count = (int) Db::value('SELECT failed_login_count FROM users WHERE id = ?', [$uid]);
            $suspicious = $count >= 5;
            if ($count >= self::LOCK_THRESHOLD) {
                Db::update('users', ['locked_until' => Db::ts(time() + self::LOCK_MINUTES * 60), 'failed_login_count' => 0], ['id' => $uid]);
                Audit::log('auth.account_locked', ['user_id' => $uid, 'actor_label' => 'System', 'target_type' => 'user', 'target_id' => $uid, 'owner_id' => $uid, 'meta' => ['minutes' => self::LOCK_MINUTES, 'failures' => $count]]);
                Logger::security('Account locked after repeated failures', ['user_id' => $uid]);
                Passwords::notifySecurity($uid, 'security.account_locked', 'Your account was temporarily locked',
                    'There were ' . $count . ' failed sign-in attempts in a row, so sign-in is paused for ' . self::LOCK_MINUTES . ' minutes. If this was not you, consider changing your password.',
                    [], 'locked:' . $uid . ':' . gmdate('YmdH'));
            } elseif ($count === 5 || ($count > 5 && $count % 5 === 0)) {
                Passwords::notifySecurity($uid, 'security.failed_logins', 'Several failed sign-in attempts',
                    'Someone has tried to sign in to your account ' . $count . ' times with the wrong ' . ($method === '2fa' ? 'code' : 'password') . '.',
                    [], 'failures:' . $uid . ':' . gmdate('YmdH'));
            }
        }
        self::recordLogin($uid, $username, false, $reason, $method, $suspicious, $suspicious ? 'repeated_failures' : null);
        // The actor of a failed attempt is unknown (it is whoever typed the password), so the
        // account is recorded as the owner/target only — it still shows in the user's Security Centre.
        Audit::log($method === '2fa' ? 'auth.2fa_failed' : 'auth.login_failed', [
            'user_id' => null, 'actor_label' => mb_substr($username, 0, 100), 'target_type' => 'user',
            'target_id' => $uid, 'owner_id' => $uid, 'meta' => ['reason' => $reason, 'method' => $method],
        ]);
    }

    private static function recordLogin(?int $userId, string $username, bool $success, ?string $reason, string $method = 'password', bool $suspicious = false, ?string $suspiciousReason = null): void
    {
        try {
            Db::insert('login_history', [
                'user_id'           => $userId,
                'username'          => mb_substr($username, 0, 64),
                'ip'                => RequestContext::ip(),
                'user_agent'        => RequestContext::userAgent(),
                'success'           => $success ? 1 : 0,
                'failure_reason'    => $reason !== null ? mb_substr($reason, 0, 48) : null,
                'method'            => mb_substr($method, 0, 16),
                'suspicious'        => $suspicious ? 1 : 0,
                'suspicious_reason' => $suspiciousReason !== null ? mb_substr($suspiciousReason, 0, 100) : null,
                'created_at'        => Db::now(),
            ]);
        } catch (\Throwable $e) {
            Logger::exception('auth', $e);
        }
    }

    /** For tests and CLI. */
    public static function reset(): void
    {
        self::$user = null;
        self::$sessionRowId = null;
        self::$via = null;
        self::$mustChangePassword = false;
        self::$resolved = false;
        if (Config::get('app.env') === 'testing') {
            $_SESSION = [];
        }
    }
}
