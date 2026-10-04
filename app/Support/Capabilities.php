<?php
declare(strict_types=1);

namespace FT\Support;

use FT\Core\Config;

/**
 * Runtime capability probes. Shared hosts (notably byethost / iFastNet free) disable functions
 * such as sleep(), set_time_limit(), ignore_user_abort() and fastcgi_finish_request(); calling
 * a disabled function throws an Error in PHP 8 (the @ operator does NOT help). Always go
 * through these helpers instead of calling such functions directly.
 */
final class Capabilities
{
    /**
     * Should this host hold requests open (SSE / long-poll)? Feeds boot config realtime.can_hold
     * (ClientConfig), the SSE endpoint and long-poll waits.
     *
     * False when:
     *  - REALTIME_MODE=poll (the operator's explicit choice), or
     *  - the request carries the "__test" cookie of the iFastNet/byethost free-hosting JavaScript
     *    challenge. Those hosts leave usleep() enabled, but a held request ties up one of the
     *    account's very few entry processes and their proxy buffers the output, so SSE never
     *    arrives and long-polls block everything else. Cheap to detect: only that host's
     *    challenge sets the cookie (we never set or forge it — HostCompat's legacy shim is off).
     *  - no sleep primitive is available (usleep / time_nanosleep disabled).
     */
    public static function canHold(): bool
    {
        $mode = (string) Config::get('realtime.mode');
        if ($mode === 'poll') {
            return false;
        }
        if (isset($_COOKIE['__test'])) {
            return false;
        }
        return function_exists('usleep') || function_exists('time_nanosleep');
    }

    /** Sleep without busy-waiting; returns false if no sleep primitive is available. */
    public static function sleep(float $seconds): bool
    {
        if ($seconds <= 0) {
            return true;
        }
        if (function_exists('usleep')) {
            usleep((int) ($seconds * 1_000_000));
            return true;
        }
        if (function_exists('time_nanosleep')) {
            $s = (int) floor($seconds);
            @time_nanosleep($s, (int) (($seconds - $s) * 1_000_000_000));
            return true;
        }
        return false;
    }

    public static function setTimeLimit(int $seconds): void
    {
        if (function_exists('set_time_limit')) {
            @set_time_limit($seconds);
        }
    }

    public static function ignoreUserAbort(): void
    {
        if (function_exists('ignore_user_abort')) {
            @ignore_user_abort(true);
        }
    }

    /** True when the response can be completed while PHP keeps working (FPM / LiteSpeed). */
    public static function canFinishEarly(): bool
    {
        return function_exists('fastcgi_finish_request') || function_exists('litespeed_finish_request');
    }

    public static function hasGd(): bool
    {
        return extension_loaded('gd') && function_exists('imagecreatetruecolor');
    }

    public static function hasZipArchive(): bool
    {
        return class_exists(\ZipArchive::class);
    }

    public static function hasCurl(): bool
    {
        return function_exists('curl_init') && function_exists('curl_exec');
    }

    public static function hasEcCrypto(): bool
    {
        return function_exists('openssl_pkey_derive') && function_exists('openssl_get_curve_names')
            && in_array('prime256v1', openssl_get_curve_names() ?: [], true);
    }

    /** Max bytes one HTTP request body may carry (min of post_max_size / upload_max_filesize). */
    public static function maxRequestBytes(): int
    {
        $post = self::iniBytes((string) ini_get('post_max_size'));
        $upload = self::iniBytes((string) ini_get('upload_max_filesize'));
        $vals = array_filter([$post, $upload], static fn ($v) => $v > 0);
        return $vals ? min($vals) : 8 * 1024 * 1024;
    }

    public static function iniBytes(string $v): int
    {
        $v = trim($v);
        if ($v === '' || $v === '-1') {
            return 0;
        }
        $n = (float) $v;
        return (int) match (strtolower(substr($v, -1))) {
            'g' => $n * 1024 ** 3,
            'm' => $n * 1024 ** 2,
            'k' => $n * 1024,
            default => $n,
        };
    }

    /** Diagnostic snapshot for the admin System page. @return array<string,mixed> */
    public static function report(): array
    {
        $fns = ['usleep', 'sleep', 'set_time_limit', 'ignore_user_abort', 'fastcgi_finish_request', 'litespeed_finish_request',
            'mail', 'curl_exec', 'curl_multi_exec', 'openssl_pkey_derive', 'hash_hkdf', 'finfo_open', 'exif_read_data',
            'imagecreatefromwebp', 'disk_free_space', 'disk_total_space', 'gzopen'];
        $exts = ['pdo_mysql', 'openssl', 'sodium', 'gd', 'zip', 'fileinfo', 'mbstring', 'curl', 'exif', 'intl', 'zlib'];
        $ini = ['max_execution_time', 'memory_limit', 'upload_max_filesize', 'post_max_size', 'max_input_time',
            'output_buffering', 'zlib.output_compression', 'open_basedir', 'allow_url_fopen', 'session.save_path'];
        return [
            'php_version' => PHP_VERSION,
            'sapi' => PHP_SAPI,
            'functions' => array_combine($fns, array_map('function_exists', $fns)),
            'extensions' => array_combine($exts, array_map('extension_loaded', $exts)),
            'ini' => array_combine($ini, array_map(static fn ($k) => (string) ini_get($k), $ini)),
            'can_hold' => self::canHold(),
            'can_finish_early' => self::canFinishEarly(),
            'ec_crypto' => self::hasEcCrypto(),
            'max_request_bytes' => self::maxRequestBytes(),
        ];
    }
}
