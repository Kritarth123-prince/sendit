<?php
declare(strict_types=1);

namespace FT\Controllers\Web;

use FT\Auth\Auth;
use FT\Auth\Passwords;
use FT\Core\ApiException;
use FT\Core\Config;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\Csrf;

/**
 * The sign-in page (GET/POST /login) and sign-out (GET/POST /logout).
 *
 * The page works without JavaScript: every step (credentials, two-factor code, forgotten
 * password, reset, sign-out confirmation) is a plain HTML form posted to /login or /logout and
 * protected by a per-session CSRF form token. assets/js/login.js enhances it to use the JSON API
 * (/api/v1/auth/*) so the browser's device id is registered and no full reload is needed.
 *
 * show() is static so FE-CORE's ShellController can render it for "/" when nobody is signed in
 * (AuthPageController::show($req)); the Router calls it on an instance, which PHP also allows.
 */
final class AuthPageController
{
    public const STEPS = ['login', '2fa', 'forgot', 'reset', 'logout'];

    /** GET /login — also used for "/" when signed out. */
    public static function show(Request $req): Response
    {
        $next = self::safeNext($req->query('next'));
        if (self::signedIn($req)) {
            return Response::redirect(self::target($req, $next), 302);
        }
        $vars = ['next' => $next];
        $step = 'login';
        if (Passwords::resetAvailable()) {
            $reset = $req->query('reset');
            if (is_string($reset) && $reset !== '') {
                $step = 'reset';
                $vars['reset_token'] = preg_match('/^[A-Za-z0-9]{20,100}$/', $reset) ? $reset : '';
            } elseif ($req->query('forgot') !== null) {
                $step = 'forgot';
            }
        }
        if ($req->query('signed_out') !== null) {
            $vars['notice'] = 'You have been signed out.';
        }
        return self::render($req, $step, $vars);
    }

    /** POST /login — the no-JavaScript form fallback for every step of the sign-in page. */
    public static function submit(Request $req): Response
    {
        $step = (string) $req->string('step', 'login', 16);
        $step = in_array($step, ['login', '2fa', 'forgot', 'reset'], true) ? $step : 'login';
        $next = self::safeNext($req->input('next'));
        $username = $req->string('username', '', 191);

        if (!Csrf::check($req)) {
            // An expired form (session gone) or a cross-site post: show the form again with a fresh token.
            return self::render($req, $step === '2fa' ? 'login' : $step, [
                'next' => $next, 'username' => $username,
                'error' => 'Your session expired before the form was sent. Please try again.',
                'reset_token' => $step === 'reset' ? self::tokenInput($req) : '',
            ]);
        }

        try {
            switch ($step) {
                case '2fa':
                    $challenge = $req->string('challenge', '', 100);
                    $code = self::codeInput($req->input('code'));
                    $recovery = self::codeInput($req->input('recovery_code'));
                    if ($code === null && $recovery === null) {
                        return self::render($req, '2fa', ['next' => $next, 'challenge' => $challenge, 'error' => 'Enter the 6-digit code from your authenticator app, or a recovery code.']);
                    }
                    try {
                        Auth::completeTwoFactor($req, $challenge, $code, $recovery, $req->bool('remember'));
                    } catch (ApiException $e) {
                        if ($e->errorCode === 'TWO_FACTOR_INVALID' || ($e->errorCode === 'VALIDATION_FAILED')) {
                            return self::render($req, '2fa', ['next' => $next, 'challenge' => $challenge, 'error' => $e->getMessage()]);
                        }
                        throw $e;
                    }
                    return Response::redirect(self::target($req, $next), 303);

                case 'forgot':
                    if (!Passwords::resetAvailable()) {
                        return self::render($req, 'login', ['next' => $next, 'error' => 'Password reset by e-mail is not available on this server. Please ask an administrator.']);
                    }
                    Passwords::requestReset($req->string('email', '', 191), $req);
                    return self::render($req, 'forgot', ['next' => $next, 'notice' => 'If an account uses that address, we have sent instructions to reset the password. The link expires in 1 hour.']);

                case 'reset':
                    if (!Passwords::resetAvailable()) {
                        return self::render($req, 'login', ['next' => $next, 'error' => 'Password reset by e-mail is not available on this server. Please ask an administrator.']);
                    }
                    $token = self::tokenInput($req);
                    $password = $req->input('password');
                    $confirm = $req->input('password_confirm');
                    $password = is_string($password) ? $password : '';
                    if ($token === '' || $password === '') {
                        return self::render($req, 'reset', ['next' => $next, 'reset_token' => $token, 'error' => 'Enter the reset code and choose a new password.']);
                    }
                    if (is_string($confirm) && $confirm !== $password) {
                        return self::render($req, 'reset', ['next' => $next, 'reset_token' => $token, 'error' => 'The two passwords do not match.']);
                    }
                    try {
                        Passwords::completeReset($token, $password, $req);
                    } catch (ApiException $e) {
                        if (in_array($e->errorCode, ['PASSWORD_TOO_WEAK', 'VALIDATION_FAILED'], true)) {
                            return self::render($req, 'reset', ['next' => $next, 'reset_token' => $token, 'error' => self::describe($e)]);
                        }
                        throw $e;
                    }
                    return self::render($req, 'login', ['next' => $next, 'notice' => 'Your password has been changed. You can now sign in.']);

                default:
                    $password = $req->input('password');
                    $password = is_string($password) ? $password : '';
                    if ($username === '' || $password === '' || strlen($password) > 4096) {
                        return self::render($req, 'login', ['next' => $next, 'username' => $username, 'error' => 'Enter your username and password.']);
                    }
                    $result = Auth::signIn($req, $username, $password, $req->bool('remember'));
                    if ($result['status'] === 'two_factor') {
                        return self::render($req, '2fa', ['next' => $next, 'challenge' => (string) $result['challenge']]);
                    }
                    return Response::redirect(self::target($req, $next), 303);
            }
        } catch (ApiException $e) {
            $back = in_array($e->errorCode, ['TWO_FACTOR_REQUIRED'], true) ? 'login' : ($step === '2fa' ? 'login' : $step);
            $headers = isset($e->headers['Retry-After']) ? ['Retry-After' => $e->headers['Retry-After']] : [];
            return self::render($req, $back, [
                'next' => $next, 'username' => $username, 'error' => self::describe($e),
                'reset_token' => $back === 'reset' ? self::tokenInput($req) : '',
            ], 200, $headers);
        }
    }

    /**
     * GET /logout (the legacy "?logout" link). A same-site visit signs out straight away; a link
     * followed from another site gets a confirmation form instead, so a third-party page cannot
     * sign people out behind their backs.
     */
    public static function logoutPage(Request $req): Response
    {
        if (self::isCrossSite($req)) {
            return self::render($req, 'logout');
        }
        return self::doLogout($req);
    }

    /** POST /logout (form with CSRF token). */
    public static function logout(Request $req): Response
    {
        if (!Csrf::check($req)) {
            return self::render($req, 'logout', ['error' => 'Your session expired before the form was sent. Please try again.']);
        }
        return self::doLogout($req);
    }

    // ------------------------------------------------------------------ helpers (public for reuse/tests)

    /**
     * A post-sign-in destination: only a path on this site ("/files", "/#/security") or an app
     * hash route ("#/shared"). Anything that could leave the site ("//evil", "https://…",
     * backslashes, control characters) or loop back to the sign-in pages becomes "".
     */
    public static function safeNext(mixed $next): string
    {
        if (!is_string($next)) {
            return '';
        }
        $next = trim($next);
        if ($next === '' || strlen($next) > 512 || preg_match('/[\x00-\x20\x7F\\\\]/', $next)) {
            return '';
        }
        if ($next[0] === '#') {
            return preg_match('~^#/[A-Za-z0-9\-._\~!$&\'()*+,;=:@/?%]*$~', $next) ? $next : '';
        }
        if ($next[0] !== '/' || str_starts_with($next, '//')) {
            return '';
        }
        if (!preg_match('~^/[A-Za-z0-9\-._\~!$&\'()*+,;=:@/?#%]*$~', $next)) {
            return '';
        }
        $path = strtolower((string) parse_url('http://localhost' . $next, PHP_URL_PATH));
        if (preg_match('~^/(login|logout)(/|$)|^/api(/|$)~', $path)) {
            return '';
        }
        return $next === '/' ? '' : $next;
    }

    /** Absolute-path URL for a validated next value (or the app root). */
    public static function target(Request $req, string $next): string
    {
        if ($next === '') {
            return $req->basePath();
        }
        if ($next[0] === '#') {
            return $req->basePath() . $next;
        }
        return self::url($req, ltrim($next, '/'));
    }

    /** URL of an app path that works with and without mod_rewrite ("login" → "/base/login"). */
    public static function url(Request $req, string $path): string
    {
        $base = $req->basePath();
        if ($path === '' || Config::get('app.pretty_urls', true)) {
            return $base . $path;
        }
        $q = strpos($path, '?');
        $route = $q === false ? $path : substr($path, 0, $q);
        $rest = $q === false ? '' : '&' . substr($path, $q + 1);
        return $base . 'index.php?r=/' . $route . $rest;
    }

    // ------------------------------------------------------------------ internals

    private static function doLogout(Request $req): Response
    {
        try {
            Auth::resolve($req);
        } catch (ApiException) {
            // a disabled account or a bad token: still clear whatever the browser holds
        }
        Auth::logout($req);
        return Response::redirect(self::url($req, 'login?signed_out=1'), 303);
    }

    private static function signedIn(Request $req): bool
    {
        if ($req->user !== null) {
            return true;
        }
        try {
            Auth::resolve($req);
        } catch (ApiException) {
            return false; // e.g. the account was disabled: show the sign-in page
        }
        return $req->user !== null && $req->authVia === 'session';
    }

    private static function isCrossSite(Request $req): bool
    {
        try {
            Csrf::assertSameOrigin($req);
        } catch (ApiException) {
            return true;
        }
        return false;
    }

    /** A user-facing sentence for an API error. */
    private static function describe(ApiException $e): string
    {
        if ($e->errorCode === 'RATE_LIMITED') {
            $wait = (int) ($e->details['retry_after'] ?? 60);
            $minutes = max(1, (int) ceil($wait / 60));
            return 'Too many attempts. Please wait ' . $minutes . ' ' . ($minutes === 1 ? 'minute' : 'minutes') . ' and try again.';
        }
        if ($e->errorCode === 'PASSWORD_TOO_WEAK' && !empty($e->details['problems']) && is_array($e->details['problems'])) {
            return implode(' ', array_map('strval', $e->details['problems']));
        }
        if ($e->status >= 500) {
            return 'Something went wrong on our side. Please try again.';
        }
        return $e->getMessage();
    }

    private static function tokenInput(Request $req): string
    {
        $t = $req->string('token', '', 200);
        return preg_match('/^[A-Za-z0-9]{20,100}$/', $t) ? $t : '';
    }

    private static function codeInput(mixed $v): ?string
    {
        if (!is_string($v)) {
            return null;
        }
        $v = trim($v);
        return $v === '' ? null : mb_substr($v, 0, 64);
    }

    private static function theme(): string
    {
        $t = $_COOKIE['ft_theme'] ?? 'dark';
        return is_string($t) && in_array($t, ['dark', 'light'], true) ? $t : 'dark';
    }

    /** Cache-busting query for a static asset (its modification time), never a path disclosure. */
    private static function assetVersion(string $relative): string
    {
        $file = FT_ROOT . '/' . $relative;
        $m = is_file($file) ? (int) @filemtime($file) : 0;
        return substr(hash('sha256', FT_VERSION . '|' . $m), 0, 10);
    }

    /** @return array<string,string> */
    private static function pageHeaders(string $nonce): array
    {
        $headers = [];
        try {
            if (class_exists(\FT\Support\Csp::class) && method_exists(\FT\Support\Csp::class, 'pageHeaders')) {
                $headers = \FT\Support\Csp::pageHeaders($nonce);
            }
        } catch (\Throwable $e) {
            Logger::warning('auth', 'CSP helper unavailable', ['error' => $e->getMessage()]);
            $headers = [];
        }
        if (!isset($headers['Content-Security-Policy']) || $headers['Content-Security-Policy'] === '') {
            $headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'nonce-{$nonce}' https://cdnjs.cloudflare.com; "
                . "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com data:; "
                . "img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; worker-src 'self' blob: https://cdnjs.cloudflare.com; "
                . "frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'";
        }
        // A reset link carries its token in the URL: never send it on in a Referer header.
        $headers['Referrer-Policy'] = 'no-referrer';
        $headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private';
        $headers['Vary'] = 'Cookie';
        $headers['X-Frame-Options'] = 'SAMEORIGIN';
        $headers['X-Content-Type-Options'] = 'nosniff';
        return $headers;
    }

    private static function render(Request $req, string $step, array $vars = [], int $status = 200, array $extraHeaders = []): Response
    {
        $step = in_array($step, self::STEPS, true) ? $step : 'login';
        $nonce = '';
        try {
            if (class_exists(\FT\Support\Csp::class) && method_exists(\FT\Support\Csp::class, 'nonce')) {
                $nonce = (string) \FT\Support\Csp::nonce();
            }
        } catch (\Throwable) {
            $nonce = '';
        }
        if (!preg_match('~^[A-Za-z0-9+/_=-]{16,128}$~', $nonce)) {
            $nonce = base64_encode(random_bytes(16));
        }
        $base = $req->basePath();
        $resetAvailable = Passwords::resetAvailable();
        $next = (string) ($vars['next'] ?? '');
        $siteName = trim(Settings::string('site_name', 'FastTransfer')) ?: 'FastTransfer';
        $apiBase = Config::get('app.pretty_urls', true) ? $base . 'api/v1/' : $base . 'index.php?r=/api/v1/';
        $challenge = (string) ($vars['challenge'] ?? '');

        $v = [
            'step'            => $step,
            'site_name'       => $siteName,
            'base'            => $base,
            'theme'           => self::theme(),
            'nonce'           => $nonce,
            'css_href'        => $base . 'assets/css/login.css?v=' . self::assetVersion('assets/css/login.css'),
            'js_src'          => $base . 'assets/js/login.js?v=' . self::assetVersion('assets/js/login.js'),
            'csrf'            => Csrf::token(),
            'next'            => $next,
            'error'           => (string) ($vars['error'] ?? ''),
            'notice'          => (string) ($vars['notice'] ?? ''),
            'username'        => (string) ($vars['username'] ?? ''),
            'challenge'       => $challenge,
            'reset_available' => $resetAvailable,
            'reset_token'     => (string) ($vars['reset_token'] ?? ''),
            'remember_days'   => max(1, Settings::int('remember_days', 30)),
            'login_action'    => self::url($req, 'login'),
            'logout_action'   => self::url($req, 'logout'),
            'login_url'       => self::url($req, 'login') . ($next !== '' ? (Config::get('app.pretty_urls', true) ? '?' : '&') . 'next=' . rawurlencode($next) : ''),
            'forgot_url'      => self::url($req, 'login?forgot=1'),
            'reset_url'       => self::url($req, 'login?reset=1'),
            'home_url'        => $base,
        ];
        $v['config'] = [
            'base'            => $base,
            'api_base'        => $apiBase,
            'step'            => $step,
            'redirect'        => self::target($req, $next),
            'reset_available' => $resetAvailable,
            'site_name'       => $siteName,
        ];
        $html = self::template(FT_ROOT . '/views/login.php', $v);
        return Response::html($html, $status, self::pageHeaders($nonce) + $extraHeaders);
    }

    /** Render a view with only $v in scope. */
    private static function template(string $file, array $v): string
    {
        $render = static function (string $__file, array $v): string {
            ob_start();
            try {
                include $__file;
            } catch (\Throwable $e) {
                ob_end_clean();
                throw $e;
            }
            return (string) ob_get_clean();
        };
        return $render($file, $v);
    }
}
