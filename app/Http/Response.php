<?php
declare(strict_types=1);

namespace FT\Http;

/**
 * Response value object. Controllers return one of:
 *   - array|JsonSerializable  → wrapped as {"success":true,"data":…}
 *   - Response                → sent as-is
 *   - null                    → controller already streamed output itself (downloads, SSE)
 */
final class Response
{
    /** @param array<string,string> $headers */
    public function __construct(
        public string $body = '',
        public int $status = 200,
        public array $headers = [],
    ) {
    }

    /** Standard success envelope: {"success":true,"data":…,"meta":{…}} */
    public static function ok(mixed $data = null, array $meta = [], int $status = 200): self
    {
        $payload = ['success' => true, 'data' => $data];
        if ($meta !== []) {
            $payload['meta'] = $meta;
        }
        return self::json($payload, $status);
    }

    public static function created(mixed $data = null, array $meta = []): self
    {
        return self::ok($data, $meta, 201);
    }

    /** Paginated list envelope. */
    public static function paginated(array $items, int $total, int $page, int $perPage, array $extraMeta = []): self
    {
        return self::ok($items, array_merge([
            'page'        => $page,
            'per_page'    => $perPage,
            'total'       => $total,
            'total_pages' => $perPage > 0 ? (int) ceil($total / $perPage) : 0,
            'has_more'    => $page * $perPage < $total,
        ], $extraMeta));
    }

    public static function json(mixed $payload, int $status = 200, array $headers = []): self
    {
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        return new self($body === false ? '{"success":false}' : $body, $status, ['Content-Type' => 'application/json; charset=utf-8', 'Cache-Control' => 'no-store'] + $headers);
    }

    public static function html(string $html, int $status = 200, array $headers = []): self
    {
        return new self($html, $status, ['Content-Type' => 'text/html; charset=utf-8', 'Cache-Control' => 'no-store'] + $headers);
    }

    public static function redirect(string $url, int $status = 302): self
    {
        // Only allow relative or same-origin absolute redirects (no open redirects).
        if (preg_match('~^(https?:)?//~i', $url)) {
            $base = Request::capture()->baseUrl();
            if (!str_starts_with($url, $base)) {
                $url = $base;
            }
        }
        return new self('', $status, ['Location' => $url]);
    }

    public static function noContent(): self
    {
        return new self('', 204);
    }

    public function withHeader(string $name, string $value): self
    {
        $this->headers[$name] = $value;
        return $this;
    }

    public function send(): void
    {
        if (!headers_sent()) {
            http_response_code($this->status);
            foreach ($this->headers as $k => $v) {
                header($k . ': ' . str_replace(["\r", "\n"], '', $v));
            }
        }
        if ($this->body !== '' && ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'HEAD') {
            echo $this->body;
        }
    }

    /**
     * Flush the response to the client and keep running (for background work such as the job
     * queue and pseudo-cron). Works with PHP-FPM, LiteSpeed and plain Apache (best effort).
     */
    public static function finishEarly(): void
    {
        if (PHP_SAPI === 'cli') {
            return;
        }
        \FT\Support\Capabilities::ignoreUserAbort();
        if (function_exists('fastcgi_finish_request')) {
            fastcgi_finish_request();
            return;
        }
        if (function_exists('litespeed_finish_request')) {
            litespeed_finish_request();
            return;
        }
        // No way to detach (e.g. byethost): flush what we have; post-response work must stay tiny.
        while (ob_get_level() > 0) {
            @ob_end_flush();
        }
        flush();
    }

    /** Safe Content-Disposition header value (RFC 6266 / 5987) for a user-supplied filename. */
    public static function contentDisposition(string $filename, bool $inline = false): string
    {
        $filename = str_replace(["\r", "\n", "\0", '"', '\\', '/'], ['', '', '', "'", '_', '_'], $filename);
        $ascii = preg_replace('/[^\x20-\x7E]/', '_', $filename) ?: 'download';
        return ($inline ? 'inline' : 'attachment') . '; filename="' . $ascii . '"; filename*=UTF-8\'\'' . rawurlencode($filename);
    }
}
