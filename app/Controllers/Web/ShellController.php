<?php
declare(strict_types=1);

namespace FT\Controllers\Web;

use FT\Core\Logger;
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\Csrf;
use FT\Security\Policy;
use FT\Support\ClientConfig;
use FT\Support\Csp;

/**
 * The single-page app shell (GET /) and its boot data (GET /api/v1/bootstrap).
 *
 * Signed-in users get views/app.php: the static skeleton (sidebar, top bar, containers) plus the
 * boot JSON, so the first paint needs no API round trip. Signed-out visitors get A1's login page
 * when it exists, otherwise a minimal built-in sign-in form (so a half-deployed install is never
 * a dead end). The page is never cached: it embeds a CSRF token and the user's profile.
 */
final class ShellController
{
    /** GET / */
    public function show(Request $req): mixed
    {
        if ($req->user === null) {
            return $this->signedOut($req);
        }
        $nonce = Csp::nonce();
        $user = $req->user;
        $boot = ClientConfig::build($user);
        $me = $boot['user'];
        $html = self::render('app.php', [
            'mode'      => 'app',
            'nonce'     => $nonce,
            'bootJson'  => ClientConfig::embed($boot),
            'base'      => $boot['config']['base'],
            'version'   => FT_VERSION,
            'appName'   => $boot['config']['app_name'],
            'theme'     => self::theme($me['preferences'] ?? null),
            'me'        => $me,
            'isAdmin'   => Policy::isAdmin($user),
            'canUpload' => in_array('files.upload', $me['permissions'] ?? [], true),
            'pretty'    => (bool) $boot['config']['pretty_urls'],
        ]);
        return Response::html($html, 200, Csp::pageHeaders($nonce));
    }

    /** GET /api/v1/bootstrap */
    public function bootstrap(Request $req): array
    {
        return ClientConfig::build($req->user);
    }

    private function signedOut(Request $req): mixed
    {
        $page = 'FT\\Controllers\\Web\\AuthPageController';
        if (class_exists($page) && method_exists($page, 'show')) {
            return (new $page())->show($req);
        }
        // Fallback sign-in page (A1's login page is not deployed yet).
        $nonce = Csp::nonce();
        $config = ClientConfig::publicConfig();
        $boot = [
            'mode'       => 'login',
            'csrf_token' => Csrf::token(),
            'next'       => self::safeNext($req->query('next')),
            'config'     => $config,
        ];
        $html = self::render('app.php', [
            'mode'     => 'login',
            'nonce'    => $nonce,
            'bootJson' => ClientConfig::embed($boot),
            'base'     => $config['base'],
            'version'  => FT_VERSION,
            'appName'  => $config['app_name'],
            'theme'    => self::theme(null),
            'me'       => null,
            'isAdmin'  => false,
            'canUpload' => false,
            'pretty'   => (bool) $config['pretty_urls'],
        ]);
        return Response::html($html, 200, Csp::pageHeaders($nonce));
    }

    /**
     * Only an app-relative path is accepted as the post-sign-in destination (no open redirect):
     * starts with one "/", no scheme, no backslashes, no control characters.
     */
    public static function safeNext(mixed $next): ?string
    {
        if (!is_string($next) || $next === '' || strlen($next) > 300) {
            return null;
        }
        if (!preg_match('#^/(?![/\\\\])[A-Za-z0-9/_\-.~%]*$#', $next) || str_contains($next, '..')) {
            return null;
        }
        return $next;
    }

    /** Initial theme for the first paint: cookie (legacy persistence), else the profile, else dark. */
    private static function theme(mixed $prefs): string
    {
        $cookie = $_COOKIE['ft_theme'] ?? null;
        if ($cookie === 'light' || $cookie === 'dark') {
            return $cookie;
        }
        if (is_array($prefs) && in_array($prefs['theme'] ?? null, ['light', 'dark'], true)) {
            return $prefs['theme'];
        }
        return 'dark';
    }

    /** Render a PHP template from views/ with the given variables. */
    private static function render(string $view, array $vars): string
    {
        $file = FT_ROOT . '/views/' . $view;
        $e = static fn (mixed $s): string => htmlspecialchars((string) $s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        extract($vars, EXTR_SKIP);
        ob_start();
        try {
            require $file;
        } catch (\Throwable $ex) {
            ob_end_clean();
            Logger::error('shell', 'Shell template failed', ['error' => $ex->getMessage()]);
            throw $ex;
        }
        return (string) ob_get_clean();
    }
}
