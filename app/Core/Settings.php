<?php
declare(strict_types=1);

namespace FT\Core;

/**
 * Runtime settings stored in the `settings` table (admin-editable). Secrets in .env are read
 * through Config instead. Values are cached for the duration of the request.
 */
final class Settings
{
    /** Defaults used when a key is missing from the table. Keep in sync with 009_seed.sql. */
    public const DEFAULTS = [
        'site_name'                    => 'FastTransfer',
        'default_quota_bytes'          => 1073741824,
        'guest_quota_bytes'            => 0,
        'max_upload_bytes'             => 209715200,
        'blocked_extensions'           => '',
        'trash_retention_days'         => 30,      // 7 | 30 | 60 | 90 | 0 (never)
        'version_retention_count'      => 5,
        'version_retention_days'       => 0,
        'auto_expire_hours'            => 72,      // legacy auto-delete for files not marked "Keep forever"; 0 = off
        'text_auto_expire_hours'       => 72,
        'dedup_scope'                  => 'user',  // user | global
        'event_retention_days'         => 7,
        'audit_retention_days'         => 365,
        'login_history_retention_days' => 180,
        'notification_retention_days'  => 90,
        'upload_session_ttl_hours'     => 24,
        'bundle_ttl_hours'             => 24,
        'quota_warning_percent'        => 90,
        'session_idle_minutes'         => 720,
        'remember_days'                => 30,
        'login_max_attempts'           => 5,
        'login_window_minutes'         => 15,
        'registration_enabled'         => 0,
        'ocr_enabled'                  => 1,
        'slack_events'                 => 'upload,delete,share,download,comment,text,favorite,version_restore,batch_delete',
        'slack_webhook_override'       => '',      // secret; admin UI override of SLACK_WEBHOOK
        'events_pruned_before_id'      => 0,       // maintained by maintenance; drives missed-event "reset"
    ];

    /** Keys stored encrypted. */
    public const SECRET_KEYS = ['slack_webhook_override'];

    /** @var array<string,mixed>|null */
    private static ?array $cache = null;

    public static function get(string $key, mixed $default = null): mixed
    {
        $all = self::load();
        if (array_key_exists($key, $all)) {
            return $all[$key];
        }
        return $default ?? (self::DEFAULTS[$key] ?? null);
    }

    public static function int(string $key, int $default = 0): int
    {
        $v = self::get($key, self::DEFAULTS[$key] ?? $default);
        return is_numeric($v) ? (int) $v : $default;
    }

    public static function bool(string $key, bool $default = false): bool
    {
        $v = self::get($key, self::DEFAULTS[$key] ?? $default);
        return in_array(strtolower((string) $v), ['1', 'true', 'yes', 'on'], true);
    }

    public static function string(string $key, string $default = ''): string
    {
        return (string) self::get($key, self::DEFAULTS[$key] ?? $default);
    }

    public static function set(string $key, mixed $value, ?int $updatedBy = null): void
    {
        if (!preg_match('/^[a-z0-9_]{1,100}$/', $key)) {
            throw new \InvalidArgumentException('Invalid setting key');
        }
        $isSecret = in_array($key, self::SECRET_KEYS, true);
        $stored = is_bool($value) ? ($value ? '1' : '0') : (string) $value;
        if ($isSecret && $stored !== '') {
            $stored = Secrets::encrypt($stored);
        }
        Db::run(
            'INSERT INTO settings (`key`, `value`, is_secret, updated_by, updated_at) VALUES (:k, :v, :s, :u, :t)
             ON DUPLICATE KEY UPDATE `value` = VALUES(`value`), is_secret = VALUES(is_secret), updated_by = VALUES(updated_by), updated_at = VALUES(updated_at)',
            ['k' => $key, 'v' => $stored, 's' => $isSecret ? 1 : 0, 'u' => $updatedBy, 't' => Db::now()]
        );
        self::$cache = null;
    }

    /** @return array<string,mixed> all settings (secrets masked unless $includeSecrets) */
    public static function all(bool $includeSecrets = false): array
    {
        $all = self::DEFAULTS;
        foreach (self::load() as $k => $v) {
            $all[$k] = $v;
        }
        if (!$includeSecrets) {
            foreach (self::SECRET_KEYS as $k) {
                $all[$k] = ($all[$k] ?? '') !== '' ? '********' : '';
            }
        }
        return $all;
    }

    public static function forget(): void
    {
        self::$cache = null;
    }

    /** @return array<string,mixed> */
    private static function load(): array
    {
        if (self::$cache !== null) {
            return self::$cache;
        }
        $out = [];
        try {
            foreach (Db::all('SELECT `key`, `value`, is_secret FROM settings') as $row) {
                $v = $row['value'];
                if ((int) $row['is_secret'] === 1 && $v !== null && $v !== '') {
                    $v = Secrets::decrypt((string) $v) ?? '';
                }
                $out[(string) $row['key']] = $v;
            }
        } catch (\Throwable $e) {
            Logger::warning('app', 'Settings unavailable, using defaults', ['error' => $e->getMessage()]);
        }
        return self::$cache = $out;
    }
}
