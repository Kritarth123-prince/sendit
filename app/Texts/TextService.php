<?php
declare(strict_types=1);

namespace FT\Texts;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Events\EventBus;
use FT\Jobs\Queue;
use FT\Sharing\ShareService;
use FT\Support\Capabilities;

/**
 * Clipboard texts — the legacy "Save Text or URL" feature, now private to each user
 * (docs/ARCHITECTURE.md §4 auto-expiry, §9.4 "Clipboard texts & URL previews", §10.2 text.*).
 *
 *  - A text is kept forever when is_permanent, otherwise it expires text_auto_expire_hours after
 *    it was saved (0 = never) and maintenance hard-deletes it (expireDue()).
 *  - A text whose trimmed content is a single http(s) URL is flagged is_url; its preview
 *    (UrlMeta) is fetched in the background and cached in texts.url_meta.
 *  - Texts are only ever visible to their owner: every id from the browser is re-loaded with
 *    owner_id = the caller, otherwise 404.
 */
final class TextService
{
    public const MAX_LENGTH = 50000;
    /** Cached previews are refreshed after this long (failed fetches retry sooner). */
    public const META_TTL = 86400;
    public const META_RETRY = 3600;

    /** @return array{0:array<int,array<string,mixed>>,1:int} [shapes, total] */
    public static function list(array $user, int $page, int $perPage): array
    {
        $params = ['u' => (int) $user['id'], 'now' => Db::now()];
        $where = 'owner_id = :u AND deleted_at IS NULL AND (is_permanent = 1 OR expires_at IS NULL OR expires_at > :now)';
        $total = (int) Db::value("SELECT COUNT(*) FROM texts WHERE {$where}", $params);
        $rows = Db::all("SELECT * FROM texts WHERE {$where} ORDER BY created_at DESC, id DESC LIMIT :lim OFFSET :off", $params + [
            'lim' => $perPage, 'off' => ($page - 1) * $perPage,
        ]);
        return [array_map([self::class, 'shape'], $rows), $total];
    }

    public static function get(array $user, int $id): array
    {
        return self::shape(self::requireOwn($user, $id));
    }

    /** POST /texts {content, is_permanent?} */
    public static function create(array $user, mixed $content, bool $permanent): array
    {
        $content = self::cleanContent($content);
        $now = Db::now();
        $isUrl = self::isUrl($content);
        if ($isUrl) {
            $content = trim($content); // URL texts are stored exactly as the URL (cache key)
        }
        $id = Db::insert('texts', [
            'owner_id'     => (int) $user['id'],
            'content'      => $content,
            'is_url'       => $isUrl ? 1 : 0,
            'url_meta'     => $isUrl ? self::cachedMetaJson((int) $user['id'], trim($content)) : null,
            'is_permanent' => $permanent ? 1 : 0,
            'expires_at'   => $permanent ? null : self::expiryFromNow(),
            'created_at'   => $now,
            'updated_at'   => $now,
        ]);
        $row = self::requireOwn($user, $id);
        Audit::log('text.create', [
            'user_id'     => (int) $user['id'],
            'target_type' => 'text',
            'target_id'   => $id,
            'owner_id'    => (int) $user['id'],
            'meta'        => ['is_url' => $isUrl, 'permanent' => $permanent, 'length' => mb_strlen($content)],
        ]);
        EventBus::publish('text.created', ['text' => self::shape($row)], [(int) $user['id']]);
        ShareService::slack('text', [
            'By'      => ShareService::displayName($user),
            'Preview' => mb_substr(trim($content), 0, 80) . (mb_strlen(trim($content)) > 80 ? '…' : ''),
        ]);
        if ($isUrl && $row['url_meta'] === null) {
            self::queueMeta($id);
        }
        return self::shape($row);
    }

    /** PATCH /texts/{id} {content?, is_permanent?} */
    public static function update(array $user, int $id, array $in): array
    {
        $row = self::requireOwn($user, $id);
        $set = [];
        $changes = [];
        if (array_key_exists('content', $in)) {
            $content = self::cleanContent($in['content']);
            $isUrl = self::isUrl($content);
            if ($isUrl) {
                $content = trim($content);
            }
            if ($content !== (string) $row['content']) {
                $set['content'] = $content;
                $set['is_url'] = $isUrl ? 1 : 0;
                $set['url_meta'] = $isUrl ? self::cachedMetaJson((int) $user['id'], trim($content)) : null;
                $changes[] = 'content';
            }
        }
        if (array_key_exists('is_permanent', $in)) {
            $v = $in['is_permanent'];
            $perm = is_bool($v) ? $v : in_array(strtolower((string) (is_scalar($v) ? $v : '')), ['1', 'true', 'yes', 'on'], true);
            if ($perm !== ((int) $row['is_permanent'] === 1)) {
                $set['is_permanent'] = $perm ? 1 : 0;
                $set['expires_at'] = $perm ? null : self::expiryFromNow();
                $changes[] = 'is_permanent';
            }
        }
        if ($set === []) {
            return self::shape($row);
        }
        $set['updated_at'] = Db::now();
        Db::update('texts', $set, ['id' => $id]);
        $row = self::requireOwn($user, $id);
        Audit::log('text.update', [
            'user_id' => (int) $user['id'], 'target_type' => 'text', 'target_id' => $id, 'owner_id' => (int) $user['id'],
            'meta' => ['changes' => $changes],
        ]);
        EventBus::publish('text.updated', ['text' => self::shape($row), 'changes' => $changes], [(int) $user['id']]);
        if ((int) $row['is_url'] === 1 && $row['url_meta'] === null) {
            self::queueMeta($id);
        }
        return self::shape($row);
    }

    /** DELETE /texts/{id} (hard delete — texts have no Trash). */
    public static function delete(array $user, int $id): void
    {
        self::requireOwn($user, $id);
        Db::delete('texts', ['id' => $id, 'owner_id' => (int) $user['id']]);
        Audit::log('text.delete', ['user_id' => (int) $user['id'], 'target_type' => 'text', 'target_id' => $id, 'owner_id' => (int) $user['id']]);
        EventBus::publish('text.deleted', ['id' => $id], [(int) $user['id']]);
    }

    /**
     * A6 maintenance (expire_texts): hard-delete texts past their expiry. Returns the count.
     */
    public static function expireDue(int $limit = 200): int
    {
        $rows = Db::all(
            'SELECT id, owner_id FROM texts WHERE is_permanent = 0 AND expires_at IS NOT NULL AND expires_at <= :now ORDER BY expires_at ASC LIMIT :lim',
            ['now' => Db::now(), 'lim' => max(1, min(2000, $limit))]
        );
        $n = 0;
        foreach ($rows as $r) {
            if (Db::run('DELETE FROM texts WHERE id = :id AND is_permanent = 0', ['id' => (int) $r['id']])->rowCount() === 1) {
                $n++;
                EventBus::publish('text.deleted', ['id' => (int) $r['id'], 'reason' => 'expired'], [(int) $r['owner_id']], ['actor_id' => null]);
            }
        }
        if ($n > 0) {
            Audit::log('system.maintenance', ['user_id' => null, 'actor_label' => 'FastTransfer', 'category' => 'system', 'detail' => 'Expired clipboard texts removed', 'meta' => ['texts' => $n]]);
        }
        return $n;
    }

    /**
     * GET /url-meta?url= — preview for a URL, served from texts.url_meta when one of the user's
     * texts has a fresh cached copy; otherwise fetched and stored on every matching text.
     */
    public static function urlMeta(array $user, string $url): array
    {
        $url = trim($url);
        if (!self::isUrl($url)) {
            throw ApiException::validation(['url' => 'Enter a full web address, for example https://example.com.']);
        }
        $cached = self::cachedMeta((int) $user['id'], $url);
        if ($cached !== null) {
            return $cached + ['cached' => true];
        }
        $meta = UrlMeta::fetch($url);
        self::storeMeta((int) $user['id'], $url, $meta);
        return $meta + ['cached' => false];
    }

    /** Queue handler: fetch and cache the preview of one URL text. */
    public static function fetchMetaJob(array $payload): void
    {
        $row = Db::one('SELECT * FROM texts WHERE id = ? AND deleted_at IS NULL', [(int) ($payload['text_id'] ?? 0)]);
        if ($row === null || (int) $row['is_url'] !== 1 || $row['url_meta'] !== null) {
            return;
        }
        $url = trim((string) $row['content']);
        try {
            $meta = UrlMeta::fetch($url);
        } catch (ApiException $e) {
            $meta = ['url' => $url, 'title' => null, 'description' => null, 'image' => null, 'favicon' => null,
                'domain' => (string) parse_url($url, PHP_URL_HOST), 'site_name' => null, 'ok' => false, 'blocked' => true,
                'fetched_at' => (string) Db::iso(Db::now())];
        }
        self::storeMeta((int) $row['owner_id'], $url, $meta);
    }

    public static function isUrl(string $content): bool
    {
        $t = trim($content);
        if ($t === '' || strlen($t) > UrlMeta::MAX_URL || preg_match('/\s/', $t)) {
            return false;
        }
        if (!preg_match('~^https?://~i', $t)) {
            return false;
        }
        return filter_var($t, FILTER_VALIDATE_URL) !== false;
    }

    public static function shape(array $row): array
    {
        $meta = $row['url_meta'] !== null ? json_decode((string) $row['url_meta'], true) : null;
        $permanent = (int) $row['is_permanent'] === 1;
        return [
            'id'           => (int) $row['id'],
            'content'      => (string) $row['content'],
            'is_url'       => (int) $row['is_url'] === 1,
            'url_meta'     => is_array($meta) ? $meta : null,
            'is_permanent' => $permanent,
            'expires_at'   => $permanent ? null : Db::iso($row['expires_at']),
            'created_at'   => Db::iso($row['created_at']),
            'updated_at'   => Db::iso($row['updated_at']),
        ];
    }

    // ------------------------------------------------------------------ internals

    private static function requireOwn(array $user, int $id): array
    {
        $row = Db::one(
            'SELECT * FROM texts WHERE id = :id AND owner_id = :u AND deleted_at IS NULL AND (is_permanent = 1 OR expires_at IS NULL OR expires_at > :now)',
            ['id' => $id, 'u' => (int) $user['id'], 'now' => Db::now()]
        );
        if ($row === null) {
            throw ApiException::notFound('text');
        }
        return $row;
    }

    private static function cleanContent(mixed $content): string
    {
        if (!is_string($content)) {
            throw ApiException::validation(['content' => 'Type or paste some text first.']);
        }
        $content = str_replace(["\r\n", "\r", "\0"], ["\n", "\n", ''], $content);
        if (!mb_check_encoding($content, 'UTF-8')) {
            throw ApiException::validation(['content' => 'The text contains invalid characters.']);
        }
        if (trim($content) === '') {
            throw ApiException::validation(['content' => 'Type or paste some text first.']);
        }
        if (mb_strlen($content) > self::MAX_LENGTH) {
            throw ApiException::validation(['content' => 'Texts can be up to ' . number_format(self::MAX_LENGTH) . ' characters long.']);
        }
        return rtrim($content);
    }

    private static function expiryFromNow(): ?string
    {
        $hours = Settings::int('text_auto_expire_hours', 72);
        return $hours > 0 ? Db::ts(time() + $hours * 3600) : null;
    }

    /** Fresh cached preview for $url among the user's texts, or null. */
    private static function cachedMeta(int $userId, string $url): ?array
    {
        $json = Db::value(
            'SELECT url_meta FROM texts WHERE owner_id = :u AND is_url = 1 AND url_meta IS NOT NULL AND deleted_at IS NULL AND content = :c
              ORDER BY updated_at DESC LIMIT 1',
            ['u' => $userId, 'c' => $url]
        );
        $meta = is_string($json) ? json_decode($json, true) : null;
        if (!is_array($meta)) {
            return null;
        }
        $age = time() - (int) (Db::toUnix(str_replace(['T', 'Z'], [' ', ''], (string) ($meta['fetched_at'] ?? ''))) ?? 0);
        $ttl = !empty($meta['ok']) ? self::META_TTL : self::META_RETRY;
        return $age >= 0 && $age < $ttl ? $meta : null;
    }

    private static function cachedMetaJson(int $userId, string $url): ?string
    {
        $m = self::isUrl($url) ? self::cachedMeta($userId, $url) : null;
        return $m !== null ? json_encode($m, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) : null;
    }

    private static function storeMeta(int $userId, string $url, array $meta): void
    {
        $json = json_encode($meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
        if ($json === false || strlen($json) > 60000) {
            return;
        }
        $ids = array_map('intval', Db::column(
            'SELECT id FROM texts WHERE owner_id = :u AND is_url = 1 AND deleted_at IS NULL AND content = :c LIMIT 50',
            ['u' => $userId, 'c' => $url]
        ));
        if ($ids === []) {
            return;
        }
        [$in, $p] = Db::inList($ids, 'tm');
        $p['m'] = $json;
        Db::run("UPDATE texts SET url_meta = :m WHERE id IN {$in}", $p);
        foreach ($ids as $id) {
            $row = Db::one('SELECT * FROM texts WHERE id = ?', [$id]);
            if ($row !== null) {
                EventBus::publish('text.updated', ['text' => self::shape($row), 'changes' => ['url_meta']], [$userId], ['actor_id' => null]);
            }
        }
    }

    /**
     * Background preview fetch. On hosts that can finish the response early it runs right after
     * it; elsewhere (byethost) it waits for the next tick so the save itself stays fast.
     */
    private static function queueMeta(int $textId): void
    {
        try {
            Queue::push(self::class . '::fetchMetaJob', ['text_id' => $textId], Capabilities::canFinishEarly() ? 0 : 5, 'default', 2);
        } catch (\Throwable $e) {
            Logger::warning('app', 'Could not queue the link preview', ['error' => $e->getMessage()]);
        }
    }
}
