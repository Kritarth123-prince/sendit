<?php
declare(strict_types=1);

namespace FT\Core;

use FT\Storage\Paths;

/**
 * Structured JSON-lines logger writing to storage/logs/{channel}-YYYY-MM-DD.log.
 * Context values whose keys look sensitive are redacted; never pass raw secrets anyway.
 *
 * Channels: app, auth, upload, download, share, delete, restore, permission, api, security,
 *           maintenance, realtime, mail, push, migration.
 */
final class Logger
{
    private const SENSITIVE = '/pass(word)?|secret|token|key|authori[sz]ation|cookie|csrf|totp|otp|code|dek|signature|webhook|p256dh|auth$/i';

    public static function debug(string $channel, string $message, array $context = []): void
    {
        if (Config::isDebug()) {
            self::write('debug', $channel, $message, $context);
        }
    }

    public static function info(string $channel, string $message, array $context = []): void
    {
        self::write('info', $channel, $message, $context);
    }

    public static function warning(string $channel, string $message, array $context = []): void
    {
        self::write('warning', $channel, $message, $context);
    }

    public static function error(string $channel, string $message, array $context = []): void
    {
        self::write('error', $channel, $message, $context);
    }

    /** Security-relevant events (failed logins, permission denials, token misuse…). */
    public static function security(string $message, array $context = []): void
    {
        self::write('warning', 'security', $message, $context);
    }

    public static function exception(string $channel, \Throwable $e, array $context = []): void
    {
        $context['exception'] = get_class($e);
        $context['file'] = basename($e->getFile()) . ':' . $e->getLine();
        $context['trace'] = array_slice(array_map(
            static fn ($f) => (isset($f['file']) ? basename($f['file']) . ':' . ($f['line'] ?? 0) : '') . ' ' . ($f['class'] ?? '') . ($f['type'] ?? '') . ($f['function'] ?? ''),
            $e->getTrace()
        ), 0, 12);
        self::write('error', $channel, $e->getMessage(), $context);
    }

    /**
     * A request path or URL that is safe to log: public share-link tokens ("/s/<token>…",
     * legacy "?share=<token>") are replaced, so a log file never grants access to shared files.
     */
    public static function safePath(string $path): string
    {
        $path = (string) preg_replace('~(^|/)s/[^/?#]+~', '$1s/[redacted]', $path);
        return (string) preg_replace('~([?&](?:share|token)=)[^&#]*~i', '$1[redacted]', $path);
    }

    /** @return array<string,mixed> */
    public static function redact(array $context): array
    {
        $out = [];
        foreach ($context as $k => $v) {
            if (is_string($k) && preg_match(self::SENSITIVE, $k) && !in_array($k, ['token_prefix', 'key_id', 'error_code'], true)) {
                $out[$k] = '[redacted]';
            } elseif (is_array($v)) {
                $out[$k] = self::redact($v);
            } elseif (is_string($v) && strlen($v) > 2000) {
                $out[$k] = substr($v, 0, 2000) . '…';
            } else {
                $out[$k] = $v;
            }
        }
        return $out;
    }

    private static function write(string $level, string $channel, string $message, array $context): void
    {
        try {
            $dir = Paths::logs();
            $channel = preg_replace('/[^a-z0-9_-]/i', '', $channel) ?: 'app';
            foreach (['path', 'uri', 'url', 'referer', 'next'] as $k) {
                if (isset($context[$k]) && is_string($context[$k])) {
                    $context[$k] = self::safePath($context[$k]); // never log share-link tokens
                }
            }
            $line = json_encode([
                'ts'      => gmdate('Y-m-d\TH:i:s\Z'),
                'level'   => $level,
                'channel' => $channel,
                'msg'     => $message,
                'ctx'     => self::redact($context),
                'req'     => RequestContext::id(),
                'user'    => RequestContext::userId(),
                'ip'      => RequestContext::ip(),
            ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PARTIAL_OUTPUT_ON_ERROR);
            // Size-based rotation: some hosts delete any file larger than 10 MB.
            $base = $dir . '/' . $channel . '-' . gmdate('Y-m-d');
            $file = $base . '.log';
            for ($part = 2; is_file($file) && @filesize($file) > 4 * 1024 * 1024 && $part < 50; $part++) {
                $file = $base . '-' . $part . '.log';
            }
            @file_put_contents($file, $line . "\n", FILE_APPEND | LOCK_EX);
        } catch (\Throwable) {
            // Logging must never break a request.
        }
    }
}
