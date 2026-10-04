<?php
declare(strict_types=1);

namespace FT\Notifications;

use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Events\EventBus;
use FT\Http\Request;
use FT\Support\Capabilities;

/**
 * The single entry point every module uses to tell a user about something
 * (docs/ARCHITECTURE.md §11):
 *
 *     Notifier::notify($userId, 'share', 'share.received', 'Alice shared “report.pdf” with you',
 *                      '', ['file_id' => 123, 'share_id' => 9, 'link' => '#/shared'], 'share:9', $actorId);
 *
 * Channels per category come from notification_preferences (rows are created lazily — a
 * missing row means "category defaults"):
 *   - in-app ⇒ a notifications row + a notification.created event to the user;
 *   - push   ⇒ one WebPush::deliverJob per subscription (only when VAPID keys are configured);
 *   - e-mail ⇒ Mailer::sendJob (only when MAIL_DRIVER is not "none" and the user has an address).
 *
 * The notifications row doubles as the de-duplication record (UNIQUE user_id + dedupe_key), so a
 * row is stored whenever ANY channel is on. When in-app is off for the category the row is stored
 * pre-read with the HIDDEN_READ_AT sentinel and never listed — that keeps de-duplication and the
 * push payload's notification_id working without showing the item in the notification centre.
 *
 * Notifications are best effort: notify() never throws, so it can be called after the caller's
 * real work without risking it.
 */
final class Notifier
{
    /** category => [British-English label, default in_app, default push, default email] */
    public const CATEGORIES = [
        'share'         => ['File shared with you', true, true, false],
        'download'      => ['File downloaded', true, false, false],
        'comment'       => ['New comment', true, true, false],
        'version'       => ['New version', true, false, false],
        'share_expired' => ['Share expired', true, false, false],
        'login'         => ['Account login', true, false, false],
        'security'      => ['Security event', true, true, true],
        'quota'         => ['Storage quota warning', true, true, true],
        'upload'        => ['Upload completed / failed', true, false, false],
    ];

    /** Categories where the actor may be told about their own action. */
    public const SELF_NOTIFY = ['security', 'login', 'quota', 'upload'];

    /** read_at value of rows stored only for de-duplication / push (in-app turned off). */
    public const HIDDEN_READ_AT = '1970-01-01 00:00:00';

    /** Categories whose push messages are delivered with Urgency: high. */
    private const URGENT = ['security', 'login'];

    /**
     * Outbound HTTP transport override (tests). Receives ($url, $body, $headers) and returns
     * ['status' => int, 'body' => string, 'error' => ?string].
     * @var (\Closure(string,string,array<int,string>):array{status:int,body:string,error:?string})|null
     */
    public static ?\Closure $transport = null;

    /**
     * Notify a user. Returns the notification id, or null when nothing was stored: duplicate
     * dedupe key, the actor acting on their own item, every channel turned off, unknown user or
     * category, or an internal failure (logged).
     *
     * @param array<string,mixed> $data JSON-safe context (file_id, share_id, link …) — never secrets
     */
    public static function notify(
        int $userId,
        string $category,
        string $type,
        string $title,
        string $body = '',
        array $data = [],
        ?string $dedupeKey = null,
        ?int $actorId = null
    ): ?int {
        try {
            return self::dispatch($userId, $category, $type, $title, $body, $data, $dedupeKey, $actorId);
        } catch (\Throwable $e) {
            Logger::exception('app', $e, ['notification_type' => mb_substr($type, 0, 48), 'category' => $category]);
            return null;
        }
    }

    public static function isCategory(string $category): bool
    {
        return isset(self::CATEGORIES[$category]);
    }

    public static function label(string $category): string
    {
        return self::CATEGORIES[$category][0] ?? $category;
    }

    /** @return array{in_app:bool,push:bool,email:bool} */
    public static function defaults(string $category): array
    {
        $d = self::CATEGORIES[$category] ?? ['', true, false, false];
        return ['in_app' => $d[1], 'push' => $d[2], 'email' => $d[3]];
    }

    /**
     * Absolute (when the base URL is known) or relative URL for an in-app hash link such as
     * "#/shared". Anything that is not a plain in-app route becomes "#/notifications", so a
     * notification can never point the browser at another origin.
     */
    public static function linkUrl(?string $link, bool $absolute = true): string
    {
        $link = is_string($link) && preg_match('~^#/[A-Za-z0-9/_?=&.%:-]{0,200}$~', $link) ? $link : '#/notifications';
        $base = $absolute ? self::baseUrl() : null;
        return ($base ?? './') . $link;
    }

    /** The app's absolute base URL ("https://host/path/"), or null when it cannot be known (CLI). */
    public static function baseUrl(): ?string
    {
        $configured = (string) Config::get('app.url', '');
        if ($configured !== '' && preg_match('~^https?://~i', $configured)) {
            return rtrim($configured, '/') . '/';
        }
        if (PHP_SAPI === 'cli' || PHP_SAPI === 'phpdbg' || empty($_SERVER['HTTP_HOST'])) {
            return null;
        }
        return Request::capture()->baseUrl();
    }

    public static function siteName(): string
    {
        $name = '';
        try {
            $name = trim(Settings::string('site_name', ''));
        } catch (\Throwable) {
            // settings unavailable: fall back below
        }
        if ($name === '') {
            $name = (string) Config::get('app.name', 'FastTransfer');
        }
        return mb_substr($name !== '' ? $name : 'FastTransfer', 0, 60);
    }

    /**
     * POST to an external HTTPS service: one call at a time, connect timeout 5 s, total 10 s,
     * TLS verified, no redirects (a redirect could point at an internal address). Never throws.
     * In the test environment (APP_ENV=testing) nothing leaves the machine unless a test installs
     * a transport: the call is logged and answered with 201 so queue handlers can be exercised.
     *
     * @param array<int,string> $headers "Name: value" lines
     * @return array{status:int,body:string,error:?string}
     */
    public static function httpPost(string $url, string $body, array $headers, string $channel = 'app'): array
    {
        if (self::$transport !== null) {
            return (self::$transport)($url, $body, $headers);
        }
        $host = (string) parse_url($url, PHP_URL_HOST);
        if (strtolower((string) parse_url($url, PHP_URL_SCHEME)) !== 'https' || $host === '') {
            return ['status' => 0, 'body' => '', 'error' => 'Only HTTPS destinations are allowed.'];
        }
        if (Config::get('app.env') === 'testing') {
            Logger::info($channel, 'Outbound HTTP skipped in the test environment', ['host' => $host, 'bytes' => strlen($body)]);
            return ['status' => 201, 'body' => '', 'error' => null];
        }
        foreach ($headers as $h) {
            if (preg_match('/[\r\n]/', $h)) {
                return ['status' => 0, 'body' => '', 'error' => 'Invalid header.'];
            }
        }
        if (Capabilities::hasCurl()) {
            $ch = curl_init($url);
            if ($ch === false) {
                return ['status' => 0, 'body' => '', 'error' => 'cURL is unavailable.'];
            }
            $opts = [
                CURLOPT_POST           => true,
                CURLOPT_POSTFIELDS     => $body,
                CURLOPT_HTTPHEADER     => $headers,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER         => false,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => 5,
                CURLOPT_TIMEOUT        => 10,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT      => 'FastTransfer/' . (defined('FT_VERSION') ? FT_VERSION : '2'),
            ];
            if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTPS')) {
                $opts[CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS;
            }
            curl_setopt_array($ch, $opts);
            $resp = curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $error = $resp === false ? (curl_error($ch) ?: 'Request failed') : null;
            curl_close($ch);
            return ['status' => $status, 'body' => is_string($resp) ? substr($resp, 0, 65536) : '', 'error' => $error];
        }
        $ctx = stream_context_create([
            'http' => [
                'method'          => 'POST',
                'header'          => implode("\r\n", $headers),
                'content'         => $body,
                'timeout'         => 10,
                'follow_location' => 0,
                'max_redirects'   => 0,
                'ignore_errors'   => true,
            ],
            'ssl' => ['verify_peer' => true, 'verify_peer_name' => true],
        ]);
        $resp = @file_get_contents($url, false, $ctx, 0, 65536);
        $status = 0;
        foreach ($http_response_header ?? [] as $line) {
            if (preg_match('~^HTTP/\S+\s+(\d{3})~', $line, $m)) {
                $status = (int) $m[1];
            }
        }
        return ['status' => $status, 'body' => is_string($resp) ? $resp : '', 'error' => $resp === false && $status === 0 ? 'Request failed' : null];
    }

    // ------------------------------------------------------------------ internals

    /** @param array<string,mixed> $data */
    private static function dispatch(int $userId, string $category, string $type, string $title, string $body, array $data, ?string $dedupeKey, ?int $actorId): ?int
    {
        if (!self::isCategory($category)) {
            Logger::warning('app', 'Notification with an unknown category ignored', ['category' => mb_substr($category, 0, 40)]);
            return null;
        }
        if ($userId <= 0) {
            return null;
        }
        if ($actorId !== null && $actorId === $userId && !in_array($category, self::SELF_NOTIFY, true)) {
            return null; // nobody needs to be told about their own action
        }
        $user = Db::one('SELECT id, username, display_name, email, status FROM users WHERE id = ? AND deleted_at IS NULL', [$userId]);
        if ($user === null) {
            return null;
        }
        $prefs = NotificationService::preferenceFor($userId, $category);
        $active = (string) $user['status'] === 'active';
        $email = trim((string) ($user['email'] ?? ''));
        $wantPush = $active && $prefs['push'] && WebPush::enabled();
        $wantEmail = $active && $prefs['email'] && $email !== '' && Mailer::enabled() && Mailer::isValidAddress($email);
        if (!$prefs['in_app'] && !$wantPush && !$wantEmail) {
            return null;
        }

        $type = substr((string) preg_replace('/[^A-Za-z0-9_.-]/', '', $type), 0, 48) ?: $category;
        $title = self::singleLine($title, 200);
        if ($title === '') {
            $title = self::label($category);
        }
        $body = self::multiLine($body, 1000);
        if ($dedupeKey !== null) {
            $dedupeKey = trim($dedupeKey);
            if ($dedupeKey === '') {
                $dedupeKey = null;
            } elseif (strlen($dedupeKey) > 120) {
                $dedupeKey = 'h:' . hash('sha256', $dedupeKey);
            }
        }
        $data = self::cleanData($data);
        $now = Db::now();

        $stmt = Db::run(
            'INSERT IGNORE INTO notifications (user_id, category, type, title, body, data, actor_id, dedupe_key, read_at, created_at)
             VALUES (:u, :c, :t, :ti, :b, :d, :a, :k, :r, :n)',
            [
                'u' => $userId, 'c' => $category, 't' => $type, 'ti' => $title, 'b' => $body,
                'd' => $data !== [] ? json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE) : null,
                'a' => $actorId, 'k' => $dedupeKey, 'r' => $prefs['in_app'] ? null : self::HIDDEN_READ_AT, 'n' => $now,
            ]
        );
        if ($stmt->rowCount() !== 1) {
            return null; // duplicate dedupe key: already notified
        }
        $id = (int) Db::pdo()->lastInsertId();
        if ($id <= 0) {
            $id = (int) Db::value('SELECT id FROM notifications WHERE user_id = ? AND created_at = ? ORDER BY id DESC LIMIT 1', [$userId, $now]);
        }

        if ($prefs['in_app']) {
            $row = Db::one(
                'SELECT n.*, a.username AS actor_username, a.display_name AS actor_display_name
                 FROM notifications n LEFT JOIN users a ON a.id = n.actor_id WHERE n.id = ?',
                [$id]
            );
            if ($row !== null) {
                EventBus::publish('notification.created', [
                    'notification' => NotificationService::format($row),
                    'unread_count' => NotificationService::unreadCount($userId),
                ], [$userId], ['actor_id' => $actorId]);
            }
        }

        $link = isset($data['link']) && is_string($data['link']) ? $data['link'] : null;
        if ($wantPush) {
            try {
                WebPush::queueForUser($userId, [
                    'title'           => $title,
                    'body'            => $body,
                    'url'             => self::linkUrl($link),
                    'tag'             => 'ft-n' . $id,
                    'notification_id' => $id,
                ], in_array($category, self::URGENT, true) ? 'high' : 'normal');
            } catch (\Throwable $e) {
                Logger::warning('push', 'Could not queue push delivery', ['error' => $e->getMessage()]);
            }
        }
        if ($wantEmail) {
            try {
                [$text, $html] = self::emailBodies($user, $category, $title, $body, $link);
                Mailer::queue($email, $title, $text, $html);
            } catch (\Throwable $e) {
                Logger::warning('mail', 'Could not queue notification e-mail', ['error' => $e->getMessage()]);
            }
        }
        return $id;
    }

    /**
     * @param array<string,mixed> $user
     * @return array{0:string,1:string} [plain text, html]
     */
    private static function emailBodies(array $user, string $category, string $title, string $body, ?string $link): array
    {
        $site = self::siteName();
        $name = (string) (($user['display_name'] ?? '') !== '' ? $user['display_name'] : $user['username']);
        $base = self::baseUrl();
        $url = $base !== null ? self::linkUrl($link) : null;
        $label = self::label($category);

        $lines = ["Hello {$name},", '', $title];
        if ($body !== '') {
            $lines[] = '';
            $lines[] = $body;
        }
        if ($url !== null) {
            $lines[] = '';
            $lines[] = "Open {$site}: {$url}";
        }
        $lines[] = '';
        $lines[] = "You are receiving this e-mail because e-mail notifications are turned on for \"{$label}\". You can change this in Settings > Notifications.";
        $lines[] = '';
        $lines[] = "— {$site}";
        $text = implode("\n", $lines);

        $e = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $html = '<!DOCTYPE html><html lang="en-GB"><head><meta charset="utf-8"><title>' . $e($title) . '</title></head>'
            . '<body style="margin:0;padding:24px;background:#f7f5f0;font-family:Arial,Helvetica,sans-serif;color:#1d1a15">'
            . '<div style="max-width:520px;margin:0 auto;background:#ffffff;border-radius:12px;padding:24px">'
            . '<p style="margin:0 0 12px">Hello ' . $e($name) . ',</p>'
            . '<h1 style="font-size:18px;margin:0 0 12px;color:#7a571e">' . $e($title) . '</h1>'
            . ($body !== '' ? '<p style="margin:0 0 16px;line-height:1.5">' . nl2br($e($body)) . '</p>' : '')
            . ($url !== null ? '<p style="margin:0 0 16px"><a href="' . $e($url) . '" style="display:inline-block;background:#c9a063;color:#1b150b;font-weight:bold;text-decoration:none;padding:10px 16px;border-radius:8px">Open ' . $e($site) . '</a></p>' : '')
            . '<p style="margin:16px 0 0;font-size:12px;color:#6f695e">You are receiving this e-mail because e-mail notifications are turned on for “' . $e($label) . '”. You can change this in Settings &gt; Notifications.</p>'
            . '</div></body></html>';
        return [$text, $html];
    }

    private static function singleLine(string $s, int $max): string
    {
        $s = (string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $s);
        return mb_substr(trim($s), 0, $max);
    }

    private static function multiLine(string $s, int $max): string
    {
        $s = str_replace(["\r\n", "\r"], "\n", $s);
        $s = (string) preg_replace('/[\x00-\x09\x0B-\x1F\x7F]+/u', ' ', $s);
        return mb_substr(trim($s), 0, $max);
    }

    /**
     * Keep the data object small and free of anything that looks like a secret.
     * @param array<string,mixed> $data
     * @return array<string,mixed>
     */
    private static function cleanData(array $data): array
    {
        $out = [];
        foreach ($data as $k => $v) {
            if (!is_string($k) || preg_match('/pass(word)?|secret|token|private|webhook|cookie/i', $k)) {
                continue;
            }
            if (is_scalar($v) || $v === null || is_array($v)) {
                $out[$k] = $v;
            }
        }
        $json = json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false || strlen($json) > 4000) {
            $out = array_filter($out, static fn ($v) => is_scalar($v) || $v === null);
            $out = array_map(static fn ($v) => is_string($v) ? mb_substr($v, 0, 300) : $v, $out);
            $json = json_encode($out, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
            if ($json === false || strlen($json) > 4000) {
                $out = array_intersect_key($out, array_flip(['link', 'file_id', 'folder_id', 'share_id', 'comment_id', 'session_id']));
            }
        }
        return $out;
    }
}
