<?php
declare(strict_types=1);

namespace FT\Support;

use FT\Auth\Auth;
use FT\Core\Config;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Events\EventBus;
use FT\Http\Request;
use FT\Security\Csrf;
use FT\Security\Policy;

/**
 * Boot data for the web client (docs/ARCHITECTURE.md §12.1). Embedded in the shell as
 * <script id="ft-boot" type="application/json"> and served by GET /api/v1/bootstrap.
 *
 * Everything here is visible to the signed-in user, so it must never contain secrets: no keys,
 * no password hashes, no physical paths, no VAPID private key, no webhook URLs. Optional
 * services owned by other modules are probed with class_exists so the shell keeps working while
 * those modules are absent or broken (fail soft: the shell is the one page that must load).
 */
final class ClientConfig
{
    /** Upload chunks never exceed one storage segment (byethost deletes files > 10 MB). */
    public const MAX_CHUNK = 8 * 1024 * 1024;
    /** Head-room for multipart/header overhead under post_max_size. */
    public const CHUNK_HEADROOM = 64 * 1024;

    /**
     * @param array $user the sanitised user array ($req->user)
     * @return array<string,mixed>
     */
    public static function build(array $user): array
    {
        $uid = (int) $user['id'];
        $isAdmin = Policy::isAdmin($user);
        return [
            'csrf_token'           => Csrf::token(),
            'user'                 => Auth::me($user),
            'unread_notifications' => self::unread($uid),
            'config'               => self::config($uid, $isAdmin),
        ];
    }

    /**
     * Configuration that is safe to show before sign-in (used by the fallback login page).
     * @return array<string,mixed>
     */
    public static function publicConfig(): array
    {
        $c = self::config(0, false);
        unset($c['realtime']['last_event_id']);
        $c['vapid_public_key'] = null;
        return $c;
    }

    /** JSON for embedding inside a <script type="application/json"> element (no "</script>" breakout). */
    public static function embed(array $data): string
    {
        $json = json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
        return $json === false ? '{}' : $json;
    }

    /** @return array<string,mixed> */
    private static function config(int $uid, bool $isAdmin): array
    {
        $req = Request::capture();
        $base = $req->basePath();
        $pretty = (bool) Config::get('app.pretty_urls', true);
        $vapid = (string) Config::get('vapid.public', '');
        $pushReady = $vapid !== '' && (string) Config::get('vapid.private', '') !== '';
        return [
            'app_name'        => self::appName(),
            'version'         => FT_VERSION,
            'base'            => $base,
            'api_base'        => $pretty ? $base . 'api/v1' : $base . 'index.php?r=/api/v1',
            'share_base'      => $req->baseUrl() . ($pretty ? 's/' : 'index.php?r=/s/'),
            'pretty_urls'     => $pretty,
            'method_override' => (bool) Config::get('app.method_override', true),
            'upload'          => [
                'chunk_size'         => self::chunkSize(),
                'max_upload_bytes'   => max(0, Settings::int('max_upload_bytes', 209715200)),
                'max_parallel'       => 2,
                'blocked_extensions' => self::blockedExtensions(),
            ],
            'realtime'        => [
                'mode'          => self::realtimeMode(),
                'can_hold'      => Capabilities::canHold(),
                'hold_seconds'  => (int) Config::get('realtime.hold_seconds', 20),
                'poll_seconds'  => (int) Config::get('realtime.poll_seconds', 4),
                'last_event_id' => $uid > 0 ? self::lastEventId($uid, $isAdmin) : 0,
            ],
            'features'        => [
                'ocr'        => self::ocrEnabled(),
                'push'       => $pushReady,
                'email'      => strtolower((string) Config::get('mail.driver', 'none')) !== 'none',
                'encryption' => self::encryptionEnabled(),
            ],
            'vapid_public_key'     => $pushReady ? $vapid : null,
            'auto_expire_hours'    => max(0, Settings::int('auto_expire_hours', 72)),
            'trash_retention_days' => max(0, Settings::int('trash_retention_days', 30)),
            'settings'             => [
                'quota_warning_percent' => max(1, min(100, Settings::int('quota_warning_percent', 90))),
            ],
        ];
    }

    public static function appName(): string
    {
        $name = trim(Settings::string('site_name', ''));
        if ($name === '') {
            $name = (string) Config::get('app.name', 'FastTransfer');
        }
        return mb_substr($name !== '' ? $name : 'FastTransfer', 0, 60);
    }

    /** Upload chunk size: the storage module decides when present, else the safe host bound. */
    public static function chunkSize(): int
    {
        $cls = 'FT\\Uploads\\UploadService';
        if (class_exists($cls) && method_exists($cls, 'chunkSize')) {
            try {
                $n = (int) $cls::chunkSize();
                if ($n > 0) {
                    return $n;
                }
            } catch (\Throwable $e) {
                Logger::warning('shell', 'UploadService::chunkSize failed', ['error' => $e->getMessage()]);
            }
        }
        $limit = Capabilities::maxRequestBytes() - self::CHUNK_HEADROOM;
        $segment = (int) Config::get('storage.segment_bytes', self::MAX_CHUNK);
        return max(256 * 1024, min(self::MAX_CHUNK, $segment, $limit));
    }

    /** @return string[] lower-case extensions without dots */
    public static function blockedExtensions(): array
    {
        $raw = Settings::get('blocked_extensions', '');
        $list = is_array($raw) ? $raw : preg_split('/[\s,;]+/', (string) $raw);
        $out = [];
        foreach ($list ?: [] as $ext) {
            $ext = strtolower(ltrim(trim((string) $ext), '.'));
            if ($ext !== '' && preg_match('/^[a-z0-9_+-]{1,20}$/', $ext)) {
                $out[$ext] = true;
            }
        }
        return array_keys($out);
    }

    private static function realtimeMode(): string
    {
        $mode = strtolower((string) Config::get('realtime.mode', 'auto'));
        return in_array($mode, ['auto', 'sse', 'longpoll', 'poll'], true) ? $mode : 'auto';
    }

    private static function lastEventId(int $uid, bool $isAdmin): int
    {
        try {
            return EventBus::latestIdFor($uid, $isAdmin);
        } catch (\Throwable $e) {
            Logger::warning('shell', 'Latest event id unavailable', ['error' => $e->getMessage()]);
            return 0;
        }
    }

    private static function unread(int $uid): int
    {
        $cls = 'FT\\Notifications\\NotificationService';
        if (!class_exists($cls) || !method_exists($cls, 'unreadCount')) {
            return 0;
        }
        try {
            return max(0, (int) $cls::unreadCount($uid));
        } catch (\Throwable $e) {
            Logger::warning('shell', 'Unread count unavailable', ['error' => $e->getMessage()]);
            return 0;
        }
    }

    private static function ocrEnabled(): bool
    {
        return Settings::bool('ocr_enabled', true) && class_exists('FT\\Ocr\\OcrService');
    }

    private static function encryptionEnabled(): bool
    {
        $cls = 'FT\\Storage\\Crypto';
        if (class_exists($cls) && method_exists($cls, 'enabled')) {
            try {
                return (bool) $cls::enabled();
            } catch (\Throwable) {
                return false;
            }
        }
        return (bool) Config::get('encryption.enabled', false) && (string) Config::get('encryption.key', '') !== '';
    }
}
