<?php
declare(strict_types=1);

namespace FT\Events;

use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\RequestContext;
use FT\Core\Settings;
use FT\Files\FileAccess;

/**
 * Standardised real-time event system.
 *
 * Every state change publishes an event to an explicit list of AUTHORISED recipients
 * (fan-out on write into event_recipients). Clients receive them over SSE / long-poll and
 * recover missed ones with GET /api/v1/events?after=<event_id>.
 *
 * Wire format (what clients receive):
 *   {
 *     "event_id": 1234, "type": "file.created", "timestamp": "2026-10-03T14:00:00Z",
 *     "user_id": 10, "actor": {"id":10,"name":"Kritarth"},
 *     "file_id": 123, "folder_id": 5, "share_id": null,
 *     "origin": "<X-Client-Id of the device that caused it>",
 *     "data": { … type-specific … }
 *   }
 *
 * Rules for publishers:
 *   - Never include secrets, physical paths, password hashes or share tokens of other users.
 *   - "data" for file.* events carries a FileSummary as data.file (see docs/ARCHITECTURE.md).
 *   - For moves/permission changes publish to the UNION of the audience before and after.
 *   - Pass ['admin' => true] for events that should update the admin dashboard (channel 0).
 */
final class EventBus
{
    public const TYPES = [
        'file.created', 'file.updated', 'file.deleted', 'file.restored', 'file.moved', 'file.renamed', 'file.purged',
        'folder.created', 'folder.updated', 'folder.deleted', 'folder.restored', 'folder.purged',
        'upload.started', 'upload.progress', 'upload.completed', 'upload.failed',
        'share.created', 'share.updated', 'share.revoked', 'share.expired',
        'comment.created', 'comment.deleted',
        'version.created', 'version.restored',
        'notification.created', 'notification.read',
        'user.created', 'user.updated', 'user.deleted',
        'quota.updated', 'trash.emptied',
        'text.created', 'text.updated', 'text.deleted',
        'presence.updated', 'session.revoked', 'stats.updated', 'settings.updated',
        'notepad.created', 'notepad.updated', 'notepad.renamed', 'notepad.deleted', 'notepad.presence',
    ];

    public const ADMIN_CHANNEL = 0;

    /** @var array<int,string> */
    private static array $nameCache = [];

    /**
     * @param array<string,mixed> $data
     * @param int[] $recipients user ids allowed to see this event
     * @param array{actor_id?:?int,file_id?:?int,folder_id?:?int,share_id?:?int,origin?:?string,admin?:bool} $o
     * @return int event id (0 if nothing was published)
     */
    public static function publish(string $type, array $data, array $recipients, array $o = []): int
    {
        if (!in_array($type, self::TYPES, true)) {
            throw new \InvalidArgumentException('Unknown event type: ' . $type);
        }
        $ids = array_values(array_unique(array_filter(array_map('intval', $recipients), static fn ($i) => $i > 0)));
        if (!empty($o['admin'])) {
            $ids[] = self::ADMIN_CHANNEL;
        }
        if ($ids === []) {
            return 0;
        }
        $actorId = array_key_exists('actor_id', $o) ? $o['actor_id'] : RequestContext::userId();
        $payload = [
            'data'       => $data,
            'actor_name' => $actorId ? self::actorName((int) $actorId) : null,
        ];
        try {
            $eventId = Db::transaction(static function () use ($type, $actorId, $o, $payload, $ids): int {
                $id = Db::insert('events', [
                    'type'       => $type,
                    'actor_id'   => $actorId,
                    'file_id'    => $o['file_id'] ?? null,
                    'folder_id'  => $o['folder_id'] ?? null,
                    'share_id'   => $o['share_id'] ?? null,
                    'origin'     => array_key_exists('origin', $o) ? $o['origin'] : RequestContext::clientId(),
                    'payload'    => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE),
                    'created_at' => Db::now(),
                ]);
                $values = [];
                $params = [];
                foreach ($ids as $i => $uid) {
                    // Native prepared statements cannot reuse a named placeholder.
                    $values[] = "(:u{$i}, :e{$i})";
                    $params["u{$i}"] = $uid;
                    $params["e{$i}"] = $id;
                }
                Db::run('INSERT IGNORE INTO event_recipients (user_id, event_id) VALUES ' . implode(',', $values), $params);
                return $id;
            });
        } catch (\Throwable $e) {
            // Real-time delivery is best effort; never fail the user's action because of it.
            Logger::exception('realtime', $e, ['type' => $type]);
            return 0;
        }
        foreach ($ids as $uid) {
            RealtimeSignal::bump($uid, $eventId);
        }
        return $eventId;
    }

    /**
     * Users who may see events about a file: its owner plus recipients of active user shares
     * on the file itself, on a bundle containing it, or on any ancestor folder — only shares that
     * still grant access (creator and file owner active; re-shares honoured, see
     * FileAccess::honoured()).
     * @return int[]
     */
    public static function fileAudience(int $fileId): array
    {
        $f = Db::one(
            'SELECT f.owner_id, f.folder_id, u.status AS owner_status, u.deleted_at AS owner_deleted_at
               FROM files f LEFT JOIN users u ON u.id = f.owner_id WHERE f.id = ?',
            [$fileId]
        );
        if ($f === null) {
            return [];
        }
        $ids = [(int) $f['owner_id']];
        if ($f['owner_status'] !== 'active' || $f['owner_deleted_at'] !== null) {
            return $ids; // a disabled or deleted owner's content is not shared with anyone
        }
        $folders = $f['folder_id'] !== null ? self::ancestorFolderIds((int) $f['folder_id']) : [];
        [$in, $params] = Db::inList($folders !== [] ? $folders : [0], 'fa');
        $params['fid'] = $fileId;
        $params['fid2'] = $fileId;
        $params['now'] = Db::now();
        $rows = Db::all(
            "SELECT s.* FROM shares s JOIN users cu ON cu.id = s.owner_id
             WHERE s.kind = 'user' AND s.recipient_id IS NOT NULL AND s.revoked_at IS NULL
               AND (s.expires_at IS NULL OR s.expires_at > :now)
               AND cu.status = 'active' AND cu.deleted_at IS NULL
               AND (s.file_id = :fid OR s.folder_id IN {$in}
                    OR s.id IN (SELECT si.share_id FROM share_items si WHERE si.file_id = :fid2))",
            $params
        );
        foreach (FileAccess::honoured($rows) as $s) {
            if (isset($s['_items']) && !in_array($fileId, $s['_items'], true)) {
                continue; // a bundle re-share item its parent no longer reaches
            }
            $ids[] = (int) $s['recipient_id'];
        }
        return array_values(array_unique($ids));
    }

    /**
     * @return int[] owner + recipients of active user shares on the folder or any ancestor (same
     * rules as fileAudience())
     */
    public static function folderAudience(int $folderId): array
    {
        $d = Db::one(
            'SELECT d.owner_id, u.status AS owner_status, u.deleted_at AS owner_deleted_at
               FROM folders d LEFT JOIN users u ON u.id = d.owner_id WHERE d.id = ?',
            [$folderId]
        );
        if ($d === null) {
            return [];
        }
        $ids = [(int) $d['owner_id']];
        if ($d['owner_status'] !== 'active' || $d['owner_deleted_at'] !== null) {
            return $ids;
        }
        [$in, $params] = Db::inList(self::ancestorFolderIds($folderId), 'fa');
        $params['now'] = Db::now();
        $rows = Db::all(
            "SELECT s.* FROM shares s JOIN users cu ON cu.id = s.owner_id
              WHERE s.kind = 'user' AND s.recipient_id IS NOT NULL AND s.revoked_at IS NULL
                AND (s.expires_at IS NULL OR s.expires_at > :now) AND s.folder_id IN {$in}
                AND cu.status = 'active' AND cu.deleted_at IS NULL",
            $params
        );
        foreach (FileAccess::honoured($rows) as $s) {
            $ids[] = (int) $s['recipient_id'];
        }
        return array_values(array_unique($ids));
    }

    /** @return int[] the folder itself followed by its ancestors (max depth 64) */
    public static function ancestorFolderIds(int $folderId): array
    {
        $out = [];
        $current = $folderId;
        for ($depth = 0; $current > 0 && $depth < 64; $depth++) {
            if (in_array($current, $out, true)) {
                break; // cycle guard
            }
            $out[] = $current;
            $parent = Db::value('SELECT parent_id FROM folders WHERE id = ?', [$current]);
            $current = $parent === null ? 0 : (int) $parent;
        }
        return $out;
    }

    /**
     * Events for a user after a given id (ascending). When the requested position is older than
     * the retained history, returns reset=true so the client does a lightweight state refresh.
     * @return array{events:array<int,array<string,mixed>>,reset:bool,last_id:int,has_more:bool}
     */
    public static function since(int $userId, int $afterId, int $limit = 200, bool $includeAdminChannel = false): array
    {
        $limit = max(1, min(500, $limit));
        $prunedBefore = Settings::int('events_pruned_before_id', 0);
        $latest = (int) (Db::value('SELECT MAX(id) FROM events') ?? 0);
        if ($afterId > 0 && ($afterId < $prunedBefore || $afterId > $latest)) {
            return ['events' => [], 'reset' => true, 'last_id' => self::latestIdFor($userId, $includeAdminChannel), 'has_more' => false];
        }
        $channels = $includeAdminChannel ? [$userId, self::ADMIN_CHANNEL] : [$userId];
        [$in, $params] = Db::inList($channels, 'ch');
        $params['after'] = $afterId;
        $params['lim'] = $limit + 1;
        $rows = Db::all(
            "SELECT DISTINCT e.* FROM event_recipients r JOIN events e ON e.id = r.event_id
             WHERE r.user_id IN {$in} AND r.event_id > :after ORDER BY e.id ASC LIMIT :lim",
            $params
        );
        $hasMore = count($rows) > $limit;
        $rows = array_slice($rows, 0, $limit);
        $events = array_map([self::class, 'format'], $rows);
        $last = $events !== [] ? (int) end($events)['event_id'] : $afterId;
        return ['events' => $events, 'reset' => false, 'last_id' => $last, 'has_more' => $hasMore];
    }

    public static function latestIdFor(int $userId, bool $includeAdminChannel = false): int
    {
        $channels = $includeAdminChannel ? [$userId, self::ADMIN_CHANNEL] : [$userId];
        [$in, $params] = Db::inList($channels, 'ch');
        return (int) (Db::value("SELECT MAX(event_id) FROM event_recipients WHERE user_id IN {$in}", $params) ?? 0);
    }

    /** @param array<string,mixed> $row events table row @return array<string,mixed> wire format */
    public static function format(array $row): array
    {
        $payload = json_decode((string) $row['payload'], true) ?: [];
        $actorId = $row['actor_id'] !== null ? (int) $row['actor_id'] : null;
        return [
            'event_id'  => (int) $row['id'],
            'type'      => (string) $row['type'],
            'timestamp' => str_replace(' ', 'T', (string) $row['created_at']) . 'Z',
            'user_id'   => $actorId,
            'actor'     => $actorId !== null ? ['id' => $actorId, 'name' => $payload['actor_name'] ?? null] : null,
            'file_id'   => $row['file_id'] !== null ? (int) $row['file_id'] : null,
            'folder_id' => $row['folder_id'] !== null ? (int) $row['folder_id'] : null,
            'share_id'  => $row['share_id'] !== null ? (int) $row['share_id'] : null,
            'origin'    => $row['origin'],
            'data'      => $payload['data'] ?? (object) [],
        ];
    }

    private static function actorName(int $userId): ?string
    {
        if (!isset(self::$nameCache[$userId])) {
            $u = Db::one('SELECT username, display_name FROM users WHERE id = ?', [$userId]);
            self::$nameCache[$userId] = $u ? ((string) ($u['display_name'] ?: $u['username'])) : '';
        }
        return self::$nameCache[$userId] !== '' ? self::$nameCache[$userId] : null;
    }
}
