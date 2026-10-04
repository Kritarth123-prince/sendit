<?php
declare(strict_types=1);

namespace FT\Security;

use FT\Core\ApiException;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Settings;

/**
 * Fixed-window rate limiter backed by the rate_limits table.
 * Subjects are opaque strings ("u12", "ip1.2.3.4", "ip1.2.3.4|share9"); they are hashed.
 *
 * IPv6 clients usually control a whole /64, so IP-based subjects should go through
 * ipSubject() which collapses an IPv6 address to its /64 prefix (otherwise an attacker could
 * rotate through addresses to dodge per-IP limits).
 */
final class RateLimiter
{
    /** bucket => [limit, windowSeconds] */
    private const BUCKETS = [
        'api'            => [300, 60],
        'login'          => [10, 900],      // per IP
        'login_user'     => [5, 900],       // per username (overridden by settings)
        'password'       => [5, 3600],
        'share_create'   => [30, 600],
        'download'       => [120, 60],
        'share_password' => [10, 900],
        'upload_chunk'   => [900, 60],
        'realtime'       => [240, 60],
        'realtime_hold'  => [20, 60],       // SSE / long-poll requests that are held open, per user
        'tick'           => [4, 60],
        'public_comment' => [10, 600],
        'public'         => [120, 60],
        'two_factor'     => [10, 900],
        'token_auth'     => [600, 60],
        'url_meta'       => [30, 60],       // link previews (outbound fetches) per user
        'maintenance'    => [10, 900],      // wrong maintenance-URL tokens per IP
        'ocr'            => [20, 600],      // manual OCR requests per user (external, possibly paid API)
        'notepad'        => [120, 60],      // notepad autosaves + presence heartbeats per user (kept out of 'api')
    ];

    /** @return array{0:int,1:int} [limit, window] */
    public static function config(string $bucket): array
    {
        if ($bucket === 'login_user') {
            return [max(1, Settings::int('login_max_attempts', 5)), max(60, Settings::int('login_window_minutes', 15) * 60)];
        }
        if ($bucket === 'login') {
            // Per-IP allowance is twice the per-username one (shared offices sit behind one NAT).
            return [max(2, Settings::int('login_max_attempts', 5) * 2), max(60, Settings::int('login_window_minutes', 15) * 60)];
        }
        return self::BUCKETS[$bucket] ?? [300, 60];
    }

    /** Count a hit and throw RATE_LIMITED (429) when over the limit. */
    public static function enforce(string $bucket, string $subject): void
    {
        $r = self::hit($bucket, $subject);
        if (!$r['allowed']) {
            Logger::security('Rate limit exceeded', ['bucket' => $bucket]);
            throw ApiException::tooManyRequests($r['retry_after']);
        }
    }

    /** @return array{allowed:bool,remaining:int,retry_after:int,hits:int} */
    public static function hit(string $bucket, string $subject, int $by = 1): array
    {
        [$limit, $window] = self::config($bucket);
        $now = time();
        $start = $now - ($now % $window);
        $key = self::key($bucket, $subject, $start);
        try {
            Db::run(
                'INSERT INTO rate_limits (bucket, hits, expires_at) VALUES (:b, :h, :e)
                 ON DUPLICATE KEY UPDATE hits = hits + VALUES(hits)',
                ['b' => $key, 'h' => max(1, $by), 'e' => $start + $window]
            );
            $hits = (int) Db::value('SELECT hits FROM rate_limits WHERE bucket = ?', [$key]);
        } catch (\Throwable $e) {
            Logger::warning('security', 'Rate limiter unavailable', ['error' => $e->getMessage()]);
            return ['allowed' => true, 'remaining' => $limit, 'retry_after' => 0, 'hits' => 0];
        }
        return [
            'allowed'     => $hits <= $limit,
            'remaining'   => max(0, $limit - $hits),
            'retry_after' => max(1, $start + $window - $now),
            'hits'        => $hits,
        ];
    }

    /**
     * Give back one hit (e.g. a login attempt that turned out to be successful), so only failures
     * use up the allowance while every attempt is still counted atomically up front.
     */
    public static function refund(string $bucket, string $subject, int $by = 1): void
    {
        [, $window] = self::config($bucket);
        $now = time();
        $start = $now - ($now % $window);
        try {
            Db::run(
                'UPDATE rate_limits SET hits = IF(hits > :by, hits - :by2, 0) WHERE bucket = :b',
                ['by' => max(1, $by), 'by2' => max(1, $by), 'b' => self::key($bucket, $subject, $start)]
            );
        } catch (\Throwable $e) {
            Logger::warning('security', 'Rate limiter refund failed', ['error' => $e->getMessage()]);
        }
    }

    /** True when the subject is already over the limit (does not count a hit). */
    public static function tooMany(string $bucket, string $subject): bool
    {
        [$limit, $window] = self::config($bucket);
        $now = time();
        $start = $now - ($now % $window);
        try {
            $hits = (int) (Db::value('SELECT hits FROM rate_limits WHERE bucket = ?', [self::key($bucket, $subject, $start)]) ?? 0);
        } catch (\Throwable) {
            return false;
        }
        return $hits >= $limit;
    }

    /** Seconds until the current window of a bucket ends. */
    public static function retryAfter(string $bucket): int
    {
        [, $window] = self::config($bucket);
        $now = time();
        return max(1, ($now - ($now % $window)) + $window - $now);
    }

    public static function clear(string $bucket, string $subject): void
    {
        [, $window] = self::config($bucket);
        $now = time();
        $start = $now - ($now % $window);
        try {
            Db::run('DELETE FROM rate_limits WHERE bucket = ?', [self::key($bucket, $subject, $start)]);
        } catch (\Throwable $e) {
            Logger::warning('security', 'Rate limiter clear failed', ['error' => $e->getMessage()]);
        }
    }

    public static function prune(): int
    {
        return Db::run('DELETE FROM rate_limits WHERE expires_at < ?', [time()])->rowCount();
    }

    /** Subject for an IP address: IPv4 as-is, IPv6 collapsed to its /64 network. */
    public static function ipSubject(string $ip): string
    {
        if (str_contains($ip, ':')) {
            $bin = @inet_pton($ip);
            if ($bin !== false && strlen($bin) === 16) {
                if (str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
                    return (string) inet_ntop(substr($bin, 12)); // IPv4-mapped
                }
                return bin2hex(substr($bin, 0, 8)) . '::/64';
            }
        }
        return $ip;
    }

    private static function key(string $bucket, string $subject, int $start): string
    {
        return hash('sha256', $bucket . '|' . $subject . '|' . $start);
    }
}
