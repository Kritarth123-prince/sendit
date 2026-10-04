<?php
declare(strict_types=1);

namespace FT\Support;

use FT\Core\Env;

/**
 * Byethost / iFastNet free-hosting compatibility.
 *
 * The host runs a JavaScript cookie check ("__test" cookie set by /aes.js) in front of PHP.
 * Browsers pass it automatically, so PHP only ever runs for requests that already passed it.
 *
 * The original index.php also forged a "__test=1" cookie and redirected the host's probe. That
 * code is preserved here but is OFF by default: it had no effect for real visitors (PHP never
 * runs before the check), and the host's terms forbid interfering with its security features.
 * Set LEGACY_HOST_COOKIE_SHIM=true only if you have a specific reason.
 *
 * Non-browser clients (curl, scripts, external cron pingers) are blocked by the host on the free
 * plan; see docs/DEPLOYMENT-BYETHOST.md.
 */
final class HostCompat
{
    public static function apply(): void
    {
        if (PHP_SAPI === 'cli' || headers_sent() || !Env::bool('LEGACY_HOST_COOKIE_SHIM', false)) {
            return;
        }
        $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
        $cookieOpts = ['expires' => 0, 'path' => '/', 'secure' => $isHttps, 'httponly' => false, 'samesite' => 'Lax'];

        $probe = isset($_GET['__host_check'])
            || (!isset($_COOKIE['__test']) && str_contains((string) ($_SERVER['HTTP_REFERER'] ?? ''), 'ifastnet.com'));
        if ($probe) {
            setcookie('__test', '1', $cookieOpts);
            $host = preg_match('/^[A-Za-z0-9.\-:]+$/', (string) ($_SERVER['HTTP_HOST'] ?? '')) ? $_SERVER['HTTP_HOST'] : 'localhost';
            header('Location: ' . ($isHttps ? 'https' : 'http') . '://' . $host . ($_SERVER['SCRIPT_NAME'] ?? '/'), true, 302);
            exit;
        }
        if (!isset($_COOKIE['__test'])) {
            setcookie('__test', '1', $cookieOpts);
        }
    }
}
