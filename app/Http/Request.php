<?php
declare(strict_types=1);

namespace FT\Http;

use FT\Core\ApiException;
use FT\Core\Config;

/**
 * Immutable-ish view of the current HTTP request.
 *
 * Routing path resolution supports three URL styles so the app works with or without
 * mod_rewrite:   /api/v1/files   |   /index.php/api/v1/files   |   /index.php?r=/api/v1/files
 */
final class Request
{
    private ?array $json = null;
    private bool $jsonParsed = false;
    private ?string $path = null;
    /** @var array<string,string> route parameters set by the Router */
    public array $params = [];
    /** @var array<string,mixed>|null authenticated user row (set by Router after auth) */
    public ?array $user = null;
    /** 'session' | 'token' | null */
    public ?string $authVia = null;

    private static ?Request $current = null;

    public static function capture(): self
    {
        if (self::$current === null) {
            self::$current = new self();
        }
        return self::$current;
    }

    /** For tests. */
    public static function reset(): void
    {
        self::$current = null;
    }

    public function method(): string
    {
        $m = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        if ($m === 'POST') {
            $override = strtoupper((string) ($_SERVER['HTTP_X_HTTP_METHOD_OVERRIDE'] ?? ($_POST['_method'] ?? '')));
            if (in_array($override, ['PUT', 'PATCH', 'DELETE'], true)) {
                return $override;
            }
        }
        return $m === 'HEAD' ? 'GET' : $m;
    }

    public function realMethod(): string
    {
        return strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
    }

    public function isSafeMethod(): bool
    {
        return in_array($this->method(), ['GET', 'HEAD', 'OPTIONS'], true);
    }

    /** Routing path, always starting with "/" and without trailing slash (except root). */
    public function path(): string
    {
        if ($this->path !== null) {
            return $this->path;
        }
        $p = null;
        if (isset($_GET['r']) && is_string($_GET['r']) && $_GET['r'] !== '') {
            $p = $_GET['r'];
        } elseif (!empty($_SERVER['PATH_INFO'])) {
            $p = (string) $_SERVER['PATH_INFO'];
        } else {
            $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
            $uri = (string) parse_url($uri, PHP_URL_PATH);
            $uri = rawurldecode($uri);
            $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php');
            $base = rtrim(str_replace('\\', '/', dirname($script)), '/');
            if ($script !== '' && str_starts_with($uri, $script)) {
                $uri = substr($uri, strlen($script));
            } elseif ($base !== '' && str_starts_with($uri, $base)) {
                $uri = substr($uri, strlen($base));
            }
            $p = $uri;
        }
        $p = '/' . ltrim(str_replace('\\', '/', $p), '/');
        $p = preg_replace('~/+~', '/', $p) ?? '/';
        if ($p !== '/' && str_ends_with($p, '/')) {
            $p = rtrim($p, '/');
        }
        return $this->path = $p;
    }

    public function isApi(): bool
    {
        return str_starts_with($this->path(), '/api/');
    }

    public function query(string $key, mixed $default = null): mixed
    {
        return $_GET[$key] ?? $default;
    }

    /** @return array<string,mixed> */
    public function queryAll(): array
    {
        $q = $_GET;
        unset($q['r']);
        return $q;
    }

    /** Body input (JSON or form), falling back to the query string. */
    public function input(string $key, mixed $default = null): mixed
    {
        $json = $this->json();
        if ($json !== null && array_key_exists($key, $json)) {
            return $json[$key];
        }
        if (array_key_exists($key, $_POST)) {
            return $_POST[$key];
        }
        return $_GET[$key] ?? $default;
    }

    /** @return array<string,mixed> all body input (JSON or form) */
    public function all(): array
    {
        return $this->json() ?? $_POST;
    }

    public function has(string $key): bool
    {
        $json = $this->json();
        return ($json !== null && array_key_exists($key, $json)) || array_key_exists($key, $_POST) || array_key_exists($key, $_GET);
    }

    /** @return array<string,mixed>|null decoded JSON body (null when the body is not JSON) */
    public function json(): ?array
    {
        if ($this->jsonParsed) {
            return $this->json;
        }
        $this->jsonParsed = true;
        if (!str_contains(strtolower($this->header('Content-Type') ?? ''), 'application/json')) {
            return null;
        }
        $raw = file_get_contents('php://input');
        if ($raw === false || trim($raw) === '') {
            return $this->json = [];
        }
        if (strlen($raw) > 2 * 1024 * 1024) {
            throw ApiException::tooLarge('Request body is too large.');
        }
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            throw ApiException::badRequest('Malformed JSON body.', 'INVALID_JSON');
        }
        return $this->json = $data;
    }

    /** @return resource stream of the raw request body (used for binary upload chunks) */
    public function bodyStream()
    {
        $h = fopen('php://input', 'rb');
        if ($h === false) {
            throw ApiException::badRequest('Could not read request body.');
        }
        return $h;
    }

    public function header(string $name): ?string
    {
        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
        if (isset($_SERVER[$key])) {
            return (string) $_SERVER[$key];
        }
        $lower = strtolower($name);
        if ($lower === 'content-type') {
            return isset($_SERVER['CONTENT_TYPE']) ? (string) $_SERVER['CONTENT_TYPE'] : null;
        }
        if ($lower === 'content-length') {
            return isset($_SERVER['CONTENT_LENGTH']) ? (string) $_SERVER['CONTENT_LENGTH'] : null;
        }
        if ($lower === 'authorization') {
            // .htaccess forwards the header into REDIRECT_HTTP_AUTHORIZATION on Apache/CGI.
            // (getallheaders()/apache_request_headers() are disabled on some shared hosts.)
            foreach (['HTTP_AUTHORIZATION', 'REDIRECT_HTTP_AUTHORIZATION'] as $k) {
                if (!empty($_SERVER[$k])) {
                    return (string) $_SERVER[$k];
                }
            }
        }
        return null;
    }

    public function bearerToken(): ?string
    {
        $h = $this->header('Authorization');
        if ($h !== null && preg_match('/^Bearer\s+([A-Za-z0-9._~+\/=-]{20,200})$/', trim($h), $m)) {
            return $m[1];
        }
        return null;
    }

    /**
     * The client's IP address. REMOTE_ADDR unless TRUST_PROXY_HEADERS=true AND REMOTE_ADDR is one
     * of TRUSTED_PROXIES (IPs/CIDRs); only then are forwarding headers believed:
     *   1. X-Forwarded-For, walked right to left: each trusted proxy appends the address it saw,
     *      so the first entry that is not a trusted proxy is the client (entries further left
     *      were written by the client and can be forged);
     *   2. otherwise X-Real-IP; 3. otherwise CF-Connecting-IP (Cloudflare at the edge — list
     *      Cloudflare's ranges in TRUSTED_PROXIES when it connects directly).
     * Anyone can send these headers, so without the REMOTE_ADDR check a client could pick any
     * address and dodge per-IP limits or frame someone else.
     */
    public function ip(): string
    {
        $remote = self::cleanIp((string) ($_SERVER['REMOTE_ADDR'] ?? '')) ?? '0.0.0.0';
        if (!Config::get('app.trust_proxy')) {
            return $remote;
        }
        $trusted = Config::get('app.trusted_proxies', []);
        $trusted = is_array($trusted) ? $trusted : [];
        if ($trusted === [] || !self::ipInRanges($remote, $trusted)) {
            return $remote;
        }
        $xff = (string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? '');
        if (trim($xff) !== '') {
            $hops = array_reverse(array_map('trim', explode(',', $xff)));
            $last = null;
            foreach ($hops as $hop) {
                $ip = self::cleanIp($hop);
                if ($ip === null) {
                    break; // garbage in the chain: stop at the last address a trusted proxy vouched for
                }
                if (!self::ipInRanges($ip, $trusted)) {
                    return $ip;
                }
                $last = $ip;
            }
            return $last ?? $remote;
        }
        foreach (['HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP'] as $h) {
            $ip = self::cleanIp((string) ($_SERVER[$h] ?? ''));
            if ($ip !== null) {
                return $ip;
            }
        }
        return $remote;
    }

    /** A valid IP from a header value ("1.2.3.4", "1.2.3.4:5678", "[2001:db8::1]:443", "::ffff:1.2.3.4"), else null. */
    public static function cleanIp(string $value): ?string
    {
        $v = trim($value);
        if ($v === '' || strlen($v) > 64) {
            return null;
        }
        if (preg_match('/^\[([0-9A-Fa-f:.]+)\](?::\d{1,5})?$/', $v, $m)) {
            $v = $m[1];
        } elseif (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/', $v, $m)) {
            $v = $m[1];
        }
        if (filter_var($v, FILTER_VALIDATE_IP) === false) {
            return null;
        }
        $bin = @inet_pton($v);
        if ($bin !== false && strlen($bin) === 16 && str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
            return (string) inet_ntop(substr($bin, 12)); // IPv4-mapped IPv6 → IPv4
        }
        return $v;
    }

    /**
     * Is $ip inside any of the ranges ("10.0.0.1", "10.0.0.0/8", "2001:db8::/32", "::1")?
     * Invalid entries never match. IPv4 and IPv6 are never mixed.
     * @param string[] $ranges
     */
    public static function ipInRanges(string $ip, array $ranges): bool
    {
        $ip = self::cleanIp($ip);
        $bin = $ip !== null ? @inet_pton($ip) : false;
        if ($bin === false) {
            return false;
        }
        foreach ($ranges as $range) {
            $range = trim((string) $range);
            $bits = null;
            if (str_contains($range, '/')) {
                [$range, $len] = explode('/', $range, 2);
                if (!preg_match('/^\d{1,3}$/', $len)) {
                    continue;
                }
                $bits = (int) $len;
            }
            $net = self::cleanIp($range);
            $netBin = $net !== null ? @inet_pton($net) : false;
            if ($netBin === false || strlen($netBin) !== strlen($bin)) {
                continue;
            }
            $max = strlen($bin) * 8;
            $bits ??= $max;
            if ($bits < 0 || $bits > $max) {
                continue;
            }
            $full = intdiv($bits, 8);
            $rest = $bits % 8;
            if (strncmp($bin, $netBin, $full) !== 0) {
                continue;
            }
            if ($rest === 0) {
                return true;
            }
            $mask = (0xFF << (8 - $rest)) & 0xFF;
            if ((ord($bin[$full]) & $mask) === (ord($netBin[$full]) & $mask)) {
                return true;
            }
        }
        return false;
    }

    public function userAgent(): string
    {
        return mb_substr((string) ($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);
    }

    /** Random per-browser id from the web client (X-Client-Id), used for event origin + devices. */
    public function clientId(): ?string
    {
        $id = $this->header('X-Client-Id');
        return ($id !== null && preg_match('/^[A-Za-z0-9-]{8,64}$/', $id)) ? $id : null;
    }

    public function isHttps(): bool
    {
        if (!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off') {
            return true;
        }
        if (strtolower((string) ($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '')) === 'https') {
            return true;
        }
        if (strtolower((string) ($_SERVER['HTTP_X_FORWARDED_SSL'] ?? '')) === 'on') {
            return true;
        }
        if (str_contains((string) ($_SERVER['HTTP_CF_VISITOR'] ?? ''), 'https')) {
            return true;
        }
        return (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
    }

    /** URL path prefix where the app lives, always ending in "/" (e.g. "/" or "/sendit/"). */
    public function basePath(): string
    {
        $configured = (string) Config::get('app.url');
        if ($configured !== '') {
            $p = (string) parse_url($configured, PHP_URL_PATH);
            return rtrim($p, '/') . '/';
        }
        $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/index.php');
        $dir = rtrim(str_replace('\\', '/', dirname($script)), '/');
        return $dir . '/';
    }

    /** Absolute base URL ending in "/" (e.g. "https://example.com/"). */
    public function baseUrl(): string
    {
        $configured = (string) Config::get('app.url');
        if ($configured !== '') {
            return rtrim($configured, '/') . '/';
        }
        $host = (string) ($_SERVER['HTTP_HOST'] ?? 'localhost');
        if (!preg_match('/^[A-Za-z0-9.\-:\[\]]+$/', $host)) {
            $host = 'localhost';
        }
        return ($this->isHttps() ? 'https' : 'http') . '://' . $host . $this->basePath();
    }

    /** True when the client prefers a JSON response. */
    public function wantsJson(): bool
    {
        return $this->isApi() || str_contains((string) ($this->header('Accept') ?? ''), 'application/json');
    }

    public function param(string $name): ?string
    {
        return $this->params[$name] ?? null;
    }

    public function intParam(string $name): int
    {
        $v = $this->params[$name] ?? null;
        if ($v === null || !ctype_digit($v)) {
            throw ApiException::notFound();
        }
        return (int) $v;
    }

    /** Integer query/body input with bounds. */
    public function int(string $key, int $default = 0, ?int $min = null, ?int $max = null): int
    {
        $v = $this->input($key);
        $n = (is_int($v) || (is_string($v) && preg_match('/^-?\d+$/', $v))) ? (int) $v : $default;
        if ($min !== null) {
            $n = max($min, $n);
        }
        if ($max !== null) {
            $n = min($max, $n);
        }
        return $n;
    }

    public function string(string $key, string $default = '', int $maxLen = 1000): string
    {
        $v = $this->input($key);
        if (!is_string($v) && !is_int($v) && !is_float($v)) {
            return $default;
        }
        return mb_substr(trim((string) $v), 0, $maxLen);
    }

    public function bool(string $key, bool $default = false): bool
    {
        $v = $this->input($key);
        if ($v === null) {
            return $default;
        }
        if (is_bool($v)) {
            return $v;
        }
        return in_array(strtolower((string) $v), ['1', 'true', 'yes', 'on'], true);
    }

    /** Pagination: returns [page, perPage, offset]. */
    public function pagination(int $defaultPer = 50, int $maxPer = 200): array
    {
        $page = $this->int('page', 1, 1, 100000);
        $per = $this->int('per_page', $defaultPer, 1, $maxPer);
        return [$page, $per, ($page - 1) * $per];
    }
}
