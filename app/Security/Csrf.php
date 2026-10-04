<?php
declare(strict_types=1);

namespace FT\Security;

use FT\Auth\Auth;
use FT\Core\ApiException;
use FT\Core\Config;
use FT\Core\Logger;
use FT\Http\Request;

/**
 * CSRF protection for cookie-authenticated, state-changing requests.
 * Token: 32 random bytes (hex) stored in the PHP session, sent by the web client in the
 * X-CSRF-Token header (or a "_csrf"/"csrf" BODY field for plain HTML forms — never the query
 * string, which would leak the token into logs and Referer headers).
 *
 * Defence in depth: a present Origin header must match the request host, and browsers that
 * send Sec-Fetch-Site must report the request as same-origin (or user-initiated). Endpoints that
 * are CSRF-exempt by design (sign-in, 2FA, password reset) call assertSameOrigin() instead, so a
 * foreign page cannot sign a victim into an attacker's account ("login CSRF").
 */
final class Csrf
{
    public static function token(): string
    {
        Auth::startSession();
        if (empty($_SESSION['ft_csrf']) || !is_string($_SESSION['ft_csrf'])) {
            $_SESSION['ft_csrf'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['ft_csrf'];
    }

    public static function rotate(): string
    {
        Auth::startSession();
        $_SESSION['ft_csrf'] = bin2hex(random_bytes(32));
        return $_SESSION['ft_csrf'];
    }

    /** Hidden form field for server-rendered forms. */
    public static function field(): string
    {
        return '<input type="hidden" name="_csrf" value="' . htmlspecialchars(self::token(), ENT_QUOTES, 'UTF-8') . '">';
    }

    public static function verify(Request $req): void
    {
        self::assertSameOrigin($req);
        Auth::startSession();
        $expected = $_SESSION['ft_csrf'] ?? '';
        $given = self::given($req);
        if (!is_string($expected) || $expected === '' || $given === '' || !hash_equals($expected, $given)) {
            Logger::security('CSRF token mismatch', ['path' => Logger::safePath($req->path())]); // share tokens never reach the logs
            throw ApiException::csrf();
        }
    }

    /** Non-throwing variant for server-rendered pages that want to show their own message. */
    public static function check(Request $req): bool
    {
        try {
            self::verify($req);
            return true;
        } catch (ApiException) {
            return false;
        }
    }

    /**
     * Reject requests that a browser marks as coming from another site. Requests without any of
     * these headers (API scripts, curl) pass: they carry no ambient browser credentials of a victim.
     */
    public static function assertSameOrigin(Request $req): void
    {
        $origin = $req->header('Origin');
        if ($origin !== null && $origin !== '') {
            if ($origin === 'null' || !self::isOwnHost((string) parse_url($origin, PHP_URL_HOST))) {
                Logger::security('Cross-origin state-changing request blocked', ['origin' => mb_substr($origin, 0, 200)]);
                throw ApiException::csrf();
            }
        } else {
            $referer = $req->header('Referer');
            if ($referer !== null && $referer !== '' && !self::isOwnHost((string) parse_url($referer, PHP_URL_HOST))) {
                Logger::security('Cross-site state-changing request blocked (Referer)', []);
                throw ApiException::csrf();
            }
        }
        $site = strtolower((string) ($req->header('Sec-Fetch-Site') ?? ''));
        if ($site === 'cross-site' || $site === 'same-site') {
            Logger::security('Cross-site state-changing request blocked (Sec-Fetch-Site)', ['site' => $site]);
            throw ApiException::csrf();
        }
    }

    private static function given(Request $req): string
    {
        $h = $req->header('X-CSRF-Token');
        if (is_string($h) && $h !== '') {
            return $h;
        }
        $json = $req->json();
        foreach (['_csrf', 'csrf'] as $k) {
            if ($json !== null && isset($json[$k]) && is_string($json[$k])) {
                return $json[$k];
            }
            if (isset($_POST[$k]) && is_string($_POST[$k])) {
                return $_POST[$k];
            }
        }
        return '';
    }

    private static function isOwnHost(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));
        if ($host === '') {
            return false;
        }
        $requestHost = strtolower(trim((string) preg_replace('/:\d+$/', '', (string) ($_SERVER['HTTP_HOST'] ?? '')), '[]'));
        if ($requestHost !== '' && hash_equals($requestHost, $host)) {
            return true;
        }
        $configured = (string) Config::get('app.url');
        if ($configured !== '') {
            $appHost = strtolower(trim((string) parse_url($configured, PHP_URL_HOST), '[]'));
            if ($appHost !== '' && hash_equals($appHost, $host)) {
                return true;
            }
        }
        return false;
    }
}
