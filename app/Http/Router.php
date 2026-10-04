<?php
declare(strict_types=1);

namespace FT\Http;

use FT\Core\ApiException;
use FT\Core\ErrorHandler;
use FT\Core\Lifecycle;
use FT\Core\RequestContext;

/**
 * Tiny router with per-route middleware options.
 *
 * Route files live in app/routes/*.php and each returns:
 *     return static function (FT\Http\Router $r): void {
 *         $r->group('/api/v1', static function (Router $r) {
 *             $r->get('/files', [FileController::class, 'index']);
 *             $r->get('/files/{id:\d+}', [FileController::class, 'show']);
 *         });
 *     };
 *
 * Options (merged from groups, route wins):
 *   auth  => 'none' | 'optional' | 'user' | 'admin'   (default: 'user' for /api, 'none' otherwise)
 *   csrf  => bool   (default true: unsafe methods with cookie-session auth must send X-CSRF-Token)
 *   rate  => ?string rate-limit bucket name (default 'api' for /api routes; null disables)
 *   perm  => ?string permission slug checked with Policy::requirePermission()
 *   json  => bool   (default true for /api routes: errors rendered as JSON)
 *   guest => bool   (default true: users with the guest role may call the route if perm allows)
 *
 * Whenever a route resolves a user, an account flagged must_change_password may only reach the
 * routes in FT\Auth\Auth::PASSWORD_CHANGE_ALLOWED; everything else is 403 PASSWORD_CHANGE_REQUIRED.
 */
final class Router
{
    /** @var array<int,array{method:string,regex:string,pattern:string,handler:mixed,opts:array}> */
    private array $routes = [];
    private string $prefix = '';
    private array $groupOpts = [];

    public function get(string $pattern, mixed $handler, array $opts = []): void
    {
        $this->add('GET', $pattern, $handler, $opts);
    }

    public function post(string $pattern, mixed $handler, array $opts = []): void
    {
        $this->add('POST', $pattern, $handler, $opts);
    }

    public function put(string $pattern, mixed $handler, array $opts = []): void
    {
        $this->add('PUT', $pattern, $handler, $opts);
    }

    public function patch(string $pattern, mixed $handler, array $opts = []): void
    {
        $this->add('PATCH', $pattern, $handler, $opts);
    }

    public function delete(string $pattern, mixed $handler, array $opts = []): void
    {
        $this->add('DELETE', $pattern, $handler, $opts);
    }

    /** @param string[] $methods */
    public function match(array $methods, string $pattern, mixed $handler, array $opts = []): void
    {
        foreach ($methods as $m) {
            $this->add(strtoupper($m), $pattern, $handler, $opts);
        }
    }

    public function group(string $prefix, callable $fn, array $opts = []): void
    {
        $prevPrefix = $this->prefix;
        $prevOpts = $this->groupOpts;
        $this->prefix = $prevPrefix . $prefix;
        $this->groupOpts = array_merge($prevOpts, $opts);
        $fn($this);
        $this->prefix = $prevPrefix;
        $this->groupOpts = $prevOpts;
    }

    private function add(string $method, string $pattern, mixed $handler, array $opts): void
    {
        $full = $this->prefix . $pattern;
        $full = $full === '' ? '/' : $full;
        // Placeholder regexes may contain one level of braces, e.g. {id:[a-f0-9]{32}}.
        $regex = preg_replace_callback('/\{([a-z_][a-z0-9_]*)(?::((?:[^{}]|\{[^{}]*\})+))?\}/i', static function (array $m): string {
            $re = $m[2] ?? '[^/]+';
            return '(?P<' . $m[1] . '>' . $re . ')';
        }, $full);
        $this->routes[] = [
            'method'  => $method,
            'regex'   => '#^' . $regex . '$#',
            'pattern' => $full,
            'handler' => $handler,
            'opts'    => array_merge($this->groupOpts, $opts),
        ];
    }

    /** Load every route file in app/routes (sorted by name). */
    public function loadRouteFiles(string $dir): void
    {
        $files = glob(rtrim($dir, '/') . '/*.php') ?: [];
        sort($files);
        foreach ($files as $file) {
            $fn = require $file;
            if (is_callable($fn)) {
                $fn($this);
            }
        }
    }

    /** @return array<int,array{method:string,pattern:string}> for docs/tests */
    public function routes(): array
    {
        return array_map(static fn ($r) => ['method' => $r['method'], 'pattern' => $r['pattern'], 'opts' => $r['opts']], $this->routes);
    }

    /** Find route + params without dispatching. @return array{0:?array,1:array<string,string>,2:bool} [route, params, methodMismatch] */
    public function find(string $method, string $path): array
    {
        $methodMismatch = false;
        foreach ($this->routes as $route) {
            if (!preg_match($route['regex'], $path, $m)) {
                continue;
            }
            if ($route['method'] !== $method) {
                $methodMismatch = true;
                continue;
            }
            $params = [];
            foreach ($m as $k => $v) {
                if (is_string($k)) {
                    $params[$k] = $v;
                }
            }
            return [$route, $params, false];
        }
        return [null, [], $methodMismatch];
    }

    public function dispatch(Request $req): void
    {
        RequestContext::init($req->ip(), $req->userAgent(), $req->clientId());
        $path = $req->path();
        $isApi = str_starts_with($path, '/api/');
        ErrorHandler::jsonMode($isApi);

        try {
            if (\FT\Core\Config::get('app.force_https') && !$req->isHttps() && $req->realMethod() === 'GET' && PHP_SAPI !== 'cli') {
                $qs = (string) ($_SERVER['QUERY_STRING'] ?? '');
                $target = 'https://' . preg_replace('~^https?://~', '', $req->baseUrl()) . ltrim($path, '/') . ($qs !== '' ? '?' . $qs : '');
                (new Response('', 301, ['Location' => $target]))->send(); // same host, scheme upgrade only
                return;
            }
            $method = $req->method();
            if ($method === 'OPTIONS') {
                (new Response('', 204, ['Allow' => 'GET, POST, PUT, PATCH, DELETE, OPTIONS']))->send();
                return;
            }
            [$route, $params, $mismatch] = $this->find($method, $path);
            if ($route === null) {
                throw $mismatch ? ApiException::methodNotAllowed() : ApiException::notFound('page');
            }
            $req->params = $params;
            $opts = $route['opts'] + [
                'auth'  => $isApi ? 'user' : 'none',
                'csrf'  => true,
                'rate'  => $isApi ? 'api' : null,
                'perm'  => null,
                'json'  => $isApi,
                'guest' => true,
            ];
            ErrorHandler::jsonMode((bool) $opts['json']);
            self::baselineHeaders((bool) $opts['json']);

            // --- authentication ---------------------------------------------------------
            if ($opts['auth'] !== 'none') {
                \FT\Auth\Auth::resolve($req); // sets $req->user / $req->authVia, enforces account status
                if ($req->user === null && in_array($opts['auth'], ['user', 'admin'], true)) {
                    if (!$opts['json']) {
                        $next = rawurlencode($path);
                        (Response::redirect($req->basePath() . '?next=' . $next))->send();
                        return;
                    }
                    throw ApiException::unauthorized();
                }
                if ($opts['auth'] === 'admin' && ($req->user['role'] ?? '') !== 'admin') {
                    throw ApiException::forbidden('Administrator access is required.');
                }
                if (!$opts['guest'] && ($req->user['role'] ?? '') === 'guest') {
                    throw ApiException::forbidden('Guest accounts cannot do that.');
                }
                RequestContext::setUserId($req->user !== null ? (int) $req->user['id'] : null);
                // must_change_password (session or token): only the password change, sign-out and
                // what the open app needs to show the change dialog (Auth::PASSWORD_CHANGE_ALLOWED).
                \FT\Auth\Auth::enforcePasswordChange($req);
            }

            // --- CSRF (cookie-session requests only; bearer-token API calls are exempt) ---
            if ($opts['csrf'] && !$req->isSafeMethod() && $req->authVia !== 'token') {
                \FT\Security\Csrf::verify($req);
            }

            // --- rate limiting ------------------------------------------------------------
            if ($opts['rate'] !== null) {
                $who = $req->user !== null ? 'u' . $req->user['id'] : 'ip' . \FT\Security\RateLimiter::ipSubject($req->ip());
                \FT\Security\RateLimiter::enforce((string) $opts['rate'], $who);
            }

            // --- permission ---------------------------------------------------------------
            if ($opts['perm'] !== null) {
                \FT\Security\Policy::requirePermission($req->user, (string) $opts['perm']);
            }

            $result = $this->invoke($route['handler'], $req);
            if ($result instanceof Response) {
                $result->send();
            } elseif ($result !== null) {
                Response::ok($result)->send();
            }
        } catch (\Throwable $e) {
            ErrorHandler::handle($e);
        }

        Lifecycle::terminate();
    }

    private function invoke(mixed $handler, Request $req): mixed
    {
        if (is_array($handler) && count($handler) === 2 && is_string($handler[0])) {
            $obj = new $handler[0]();
            return $obj->{$handler[1]}($req);
        }
        if (is_callable($handler)) {
            return $handler($req);
        }
        throw new \LogicException('Invalid route handler');
    }

    /**
     * Security headers are sent from PHP because some shared hosts reject `Header` directives
     * in .htaccess. JSON responses carry the `X-FT-Api` marker so the web client can tell a real
     * API answer from an HTML page injected by the host's JavaScript cookie check.
     */
    private static function baselineHeaders(bool $json): void
    {
        if (headers_sent()) {
            return;
        }
        header('X-Content-Type-Options: nosniff');
        header('Referrer-Policy: strict-origin-when-cross-origin');
        header('X-Frame-Options: SAMEORIGIN');
        header('Permissions-Policy: geolocation=(), microphone=(), payment=(), usb=(), camera=(self)');
        header('Cross-Origin-Opener-Policy: same-origin');
        if (\FT\Core\Config::get('app.force_https') && Request::capture()->isHttps()) {
            header('Strict-Transport-Security: max-age=15552000');
        }
        if ($json) {
            header('Cache-Control: no-store');
            header('X-FT-Api: 1');
        }
    }
}
