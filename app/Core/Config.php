<?php
declare(strict_types=1);

namespace FT\Core;

/**
 * Typed, read-only view of environment configuration (secrets and deployment settings).
 * Runtime-tunable options (quotas, retention, …) live in the `settings` table — see Settings.
 */
final class Config
{
    /** @var array<string,mixed>|null */
    private static ?array $cache = null;

    /** @return array<string,mixed> */
    public static function all(): array
    {
        if (self::$cache !== null) {
            return self::$cache;
        }
        $storage = Env::get('STORAGE_PATH');
        if ($storage === null) {
            $storage = FT_ROOT . '/storage';
        } elseif (!self::isAbsolutePath($storage)) {
            $storage = FT_ROOT . '/' . $storage; // relative to app root
        }
        self::$cache = [
            'app.env'            => Env::get('APP_ENV', 'production'),
            'app.debug'          => Env::bool('APP_DEBUG', false),
            'app.url'            => rtrim((string) Env::get('APP_URL', ''), '/'),
            'app.key'            => (string) Env::get('APP_KEY', ''),
            'app.name'           => Env::get('APP_NAME', 'FastTransfer'),
            'app.force_https'    => Env::bool('FORCE_HTTPS', false),
            'app.pretty_urls'    => Env::bool('PRETTY_URLS', true),
            'app.method_override'=> Env::bool('METHOD_OVERRIDE', true),
            'app.trust_proxy'    => Env::bool('TRUST_PROXY_HEADERS', false), // only trust X-Forwarded-For behind a known proxy
            // Proxies (IPs or CIDR ranges, IPv4/IPv6) whose forwarding headers are believed when
            // TRUST_PROXY_HEADERS=true. Headers from any other REMOTE_ADDR are ignored.
            'app.trusted_proxies' => self::csv((string) Env::get('TRUSTED_PROXIES', '')),

            'db.host'     => Env::get('DATABASE_HOST', 'localhost'),
            'db.port'     => Env::int('DATABASE_PORT', 3306),
            'db.name'     => Env::get('DATABASE_NAME', ''),
            'db.user'     => Env::get('DATABASE_USER', ''),
            'db.password' => Env::get('DATABASE_PASSWORD', ''),
            'db.prefix'   => '',

            'storage.path'        => rtrim(str_replace('\\', '/', $storage), '/'),
            // Physical files never exceed this size (byethost deletes files > 10 MB): blobs are
            // stored as numbered segments of at most this many bytes.
            'storage.segment_bytes' => max(1, min(64, Env::int('STORAGE_SEGMENT_MB', 8))) * 1024 * 1024,
            // Total capacity for the admin dashboard (disk_total_space() is disabled on some hosts). 0 = unknown.
            'storage.capacity_bytes' => (int) round(((float) Env::get('STORAGE_CAPACITY_GB', '0')) * 1024 ** 3),
            // Relative values are resolved against the app root (like STORAGE_PATH), never the
            // PHP working directory; empty means the default.
            'legacy.uploads_path' => rtrim(self::appPath(Env::get('LEGACY_UPLOADS_PATH'), 'uploads'), '/'),

            'encryption.enabled'  => Env::bool('ENCRYPTION_ENABLED', Env::get('ENCRYPTION_KEY') !== null),
            'encryption.key'      => (string) Env::get('ENCRYPTION_KEY', ''),
            'encryption.key_id'   => Env::get('ENCRYPTION_KEY_ID', 'k1'),
            'encryption.old_keys' => (string) Env::get('ENCRYPTION_OLD_KEYS', ''), // "id:base64key,id2:base64key"
            'encryption.legacy_key_file' => self::appPath(Env::get('LEGACY_ENCRYPTION_KEY_FILE'), 'uploads/.enc_key'),

            'slack.webhook'  => (string) Env::get('SLACK_WEBHOOK', ''),
            'ocr.provider'   => (string) Env::get('OCR_PROVIDER', ''),
            'ocr.api_key'    => (string) Env::get('OCR_API_KEY', ''),

            'vapid.public'   => (string) Env::get('VAPID_PUBLIC_KEY', ''),
            'vapid.private'  => (string) Env::get('VAPID_PRIVATE_KEY', ''),
            'vapid.subject'  => (string) Env::get('VAPID_SUBJECT', 'mailto:admin@example.com'),

            'mail.driver'     => Env::get('MAIL_DRIVER', 'none'), // none | smtp | log
            'mail.from'       => Env::get('MAIL_FROM', ''),
            'mail.from_name'  => Env::get('MAIL_FROM_NAME', 'FastTransfer'),
            'smtp.host'       => Env::get('SMTP_HOST', ''),
            'smtp.port'       => Env::int('SMTP_PORT', 587),
            'smtp.user'       => Env::get('SMTP_USER', ''),
            'smtp.password'   => Env::get('SMTP_PASSWORD', ''),
            'smtp.encryption' => Env::get('SMTP_ENCRYPTION', 'tls'), // tls | ssl | none

            'maintenance.token' => (string) Env::get('MAINTENANCE_TOKEN', ''),
            'install.token'     => (string) Env::get('INSTALL_TOKEN', ''),

            'realtime.mode'         => Env::get('REALTIME_MODE', 'auto'), // auto | sse | longpoll | poll
            'realtime.hold_seconds' => max(5, min(55, Env::int('REALTIME_HOLD_SECONDS', 20))),
            'realtime.poll_seconds' => max(2, min(60, Env::int('REALTIME_POLL_SECONDS', 4))),

            'pseudo_cron.enabled'  => Env::bool('PSEUDO_CRON', true),
            'pseudo_cron.interval' => max(60, Env::int('PSEUDO_CRON_INTERVAL', 300)),
        ];
        return self::$cache;
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        $all = self::all();
        return array_key_exists($key, $all) ? $all[$key] : $default;
    }

    /** "C:\x", "C:/x", "/x" or "\\server\share" (UNC). */
    public static function isAbsolutePath(string $path): bool
    {
        return (bool) preg_match('~^([A-Za-z]:[\\\\/]|/|\\\\\\\\)~', $path);
    }

    /**
     * A filesystem path from the environment: empty ⇒ FT_ROOT/<default>; relative ⇒ resolved
     * against the app root (FT_ROOT), never the working directory; forward slashes throughout.
     */
    public static function appPath(?string $value, string $default): string
    {
        $value = $value !== null ? trim($value) : '';
        if ($value === '') {
            $value = $default;
        }
        if (!self::isAbsolutePath($value)) {
            $value = FT_ROOT . '/' . ltrim($value, '/\\');
        }
        return str_replace('\\', '/', $value);
    }

    /** @return string[] comma-separated list → trimmed non-empty items */
    private static function csv(string $value): array
    {
        return array_values(array_filter(array_map('trim', explode(',', $value)), static fn (string $v): bool => $v !== ''));
    }

    /** Test hook: forget cached values after Env::set(). */
    public static function reset(): void
    {
        self::$cache = null;
    }

    public static function isDebug(): bool
    {
        return (bool) self::get('app.debug');
    }
}
