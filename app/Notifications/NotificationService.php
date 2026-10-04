<?php
declare(strict_types=1);

namespace FT\Notifications;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Settings;
use FT\Events\EventBus;

/**
 * Notification centre: listing, read state, deletion, per-category channel preferences and
 * retention. Every query is scoped to the user id passed in by the controller (taken from the
 * authenticated user, never from the browser), so one user can never see or change another
 * user's notifications — unknown or foreign ids are reported as NOTIFICATION_NOT_FOUND (404).
 *
 * Rows stored with Notifier::HIDDEN_READ_AT exist only for de-duplication/push (in-app turned
 * off) and are never listed.
 */
final class NotificationService
{
    /**
     * Paginated notifications (newest first) with actor UserRefs in one query.
     * @return array{items:array<int,array<string,mixed>>,total:int,unread_count:int}
     */
    public static function list(int $userId, bool $unreadOnly = false, int $page = 1, int $perPage = 50, ?string $category = null): array
    {
        $where = 'n.user_id = :u AND ' . ($unreadOnly ? 'n.read_at IS NULL' : '(n.read_at IS NULL OR n.read_at <> :hidden)');
        $params = ['u' => $userId];
        if (!$unreadOnly) {
            $params['hidden'] = Notifier::HIDDEN_READ_AT;
        }
        if ($category !== null) {
            $where .= ' AND n.category = :c';
            $params['c'] = $category;
        }
        $total = (int) Db::value("SELECT COUNT(*) FROM notifications n WHERE {$where}", $params);
        $rows = Db::all(
            "SELECT n.*, a.username AS actor_username, a.display_name AS actor_display_name
             FROM notifications n LEFT JOIN users a ON a.id = n.actor_id
             WHERE {$where} ORDER BY n.id DESC LIMIT :lim OFFSET :off",
            $params + ['lim' => max(1, $perPage), 'off' => max(0, ($page - 1) * $perPage)]
        );
        return [
            'items'        => array_map([self::class, 'format'], $rows),
            'total'        => $total,
            'unread_count' => self::unreadCount($userId),
        ];
    }

    /** @return array<string,mixed> one visible notification of this user (404 otherwise) */
    public static function find(int $userId, int $id): array
    {
        return self::format(self::load($userId, $id));
    }

    /** Mark one notification read. Publishes notification.read when it changed. @return array<string,mixed> */
    public static function markRead(int $userId, int $id): array
    {
        $row = self::load($userId, $id);
        if ($row['read_at'] === null) {
            $changed = Db::run('UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ? AND read_at IS NULL', [Db::now(), $id, $userId])->rowCount();
            if ($changed === 1) {
                EventBus::publish('notification.read', ['ids' => [$id], 'unread_count' => self::unreadCount($userId)], [$userId]);
            }
            $row = self::load($userId, $id);
        }
        return self::format($row);
    }

    /** Mark every unread notification read. Returns how many changed. */
    public static function markAllRead(int $userId): int
    {
        $n = Db::run('UPDATE notifications SET read_at = ? WHERE user_id = ? AND read_at IS NULL', [Db::now(), $userId])->rowCount();
        if ($n > 0) {
            EventBus::publish('notification.read', ['ids' => 'all', 'unread_count' => self::unreadCount($userId)], [$userId]);
        }
        return $n;
    }

    /** Delete one notification (other devices remove it via notification.read {deleted:true}). */
    public static function delete(int $userId, int $id): void
    {
        $row = self::load($userId, $id);
        Db::run('DELETE FROM notifications WHERE id = ? AND user_id = ?', [$id, $userId]);
        Audit::log('notification.delete', [
            'user_id' => $userId, 'target_type' => 'user', 'target_id' => $userId, 'owner_id' => $userId,
            'meta' => ['notification_id' => $id, 'category' => (string) $row['category'], 'type' => (string) $row['type']],
        ]);
        EventBus::publish('notification.read', ['ids' => [$id], 'deleted' => true, 'unread_count' => self::unreadCount($userId)], [$userId]);
    }

    /** Unread in-app notifications (boot data badge, list meta). */
    public static function unreadCount(int $userId): int
    {
        return (int) Db::value('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL', [$userId]);
    }

    /**
     * Channel settings for one category: the stored row, else the category defaults.
     * @return array{in_app:bool,push:bool,email:bool}
     */
    public static function preferenceFor(int $userId, string $category): array
    {
        $row = Db::one('SELECT in_app, push, email FROM notification_preferences WHERE user_id = ? AND category = ?', [$userId, $category]);
        if ($row === null) {
            return Notifier::defaults($category);
        }
        return ['in_app' => (bool) $row['in_app'], 'push' => (bool) $row['push'], 'email' => (bool) $row['email']];
    }

    /** @return array<int,array{category:string,label:string,in_app:bool,push:bool,email:bool}> every category, in catalogue order */
    public static function preferences(int $userId): array
    {
        $stored = [];
        foreach (Db::all('SELECT category, in_app, push, email FROM notification_preferences WHERE user_id = ?', [$userId]) as $r) {
            $stored[(string) $r['category']] = ['in_app' => (bool) $r['in_app'], 'push' => (bool) $r['push'], 'email' => (bool) $r['email']];
        }
        $out = [];
        foreach (array_keys(Notifier::CATEGORIES) as $cat) {
            $p = $stored[$cat] ?? Notifier::defaults($cat);
            $out[] = ['category' => $cat, 'label' => Notifier::label($cat)] + $p;
        }
        return $out;
    }

    /**
     * Update preferences. Accepts a list [{category, in_app?, push?, email?}, …] or a map
     * {category: {in_app?, push?, email?}}. Channels left out keep their current value.
     * @param mixed $input
     * @return array<int,array<string,mixed>> the full, updated preference list
     */
    public static function updatePreferences(int $userId, mixed $input): array
    {
        if (!is_array($input) || $input === []) {
            throw ApiException::validation(['preferences' => 'Send a list of notification preferences.']);
        }
        $items = [];
        if (array_is_list($input)) {
            $items = $input;
        } else {
            foreach ($input as $cat => $v) {
                $items[] = is_array($v) ? ['category' => $cat] + $v : ['category' => $cat, '_invalid' => true];
            }
        }
        if (count($items) > 50) {
            throw ApiException::validation(['preferences' => 'Too many preference entries.']);
        }
        $errors = [];
        $changes = [];
        foreach ($items as $i => $item) {
            if (!is_array($item) || isset($item['_invalid'])) {
                $errors["preferences.{$i}"] = 'Each entry must be an object with a category.';
                continue;
            }
            $cat = $item['category'] ?? null;
            if (!is_string($cat) || !Notifier::isCategory($cat)) {
                $errors["preferences.{$i}.category"] = 'Unknown notification category.';
                continue;
            }
            $set = $changes[$cat] ?? self::preferenceFor($userId, $cat);
            foreach (['in_app', 'push', 'email'] as $ch) {
                if (!array_key_exists($ch, $item)) {
                    continue;
                }
                $b = self::toBool($item[$ch]);
                if ($b === null) {
                    $errors["preferences.{$i}.{$ch}"] = 'Use true or false.';
                    continue;
                }
                $set[$ch] = $b;
            }
            $changes[$cat] = $set;
        }
        if ($errors !== []) {
            throw ApiException::validation($errors);
        }
        Db::transaction(static function () use ($userId, $changes): void {
            foreach ($changes as $cat => $p) {
                Db::run(
                    'INSERT INTO notification_preferences (user_id, category, in_app, push, email, updated_at)
                     VALUES (:u, :c, :i, :p, :e, :t)
                     ON DUPLICATE KEY UPDATE in_app = VALUES(in_app), push = VALUES(push), email = VALUES(email), updated_at = VALUES(updated_at)',
                    ['u' => $userId, 'c' => $cat, 'i' => $p['in_app'] ? 1 : 0, 'p' => $p['push'] ? 1 : 0, 'e' => $p['email'] ? 1 : 0, 't' => Db::now()]
                );
            }
        });
        Audit::log('notification.preferences', [
            'user_id' => $userId, 'target_type' => 'user', 'target_id' => $userId, 'owner_id' => $userId,
            'meta' => ['preferences' => $changes],
        ]);
        $u = Db::one('SELECT id, username, display_name, status, role_id FROM users WHERE id = ?', [$userId]);
        if ($u !== null) {
            // Lets the user's other devices refresh their Settings page.
            EventBus::publish('user.updated', [
                'user' => [
                    'id' => (int) $u['id'], 'username' => (string) $u['username'],
                    'display_name' => (string) (($u['display_name'] ?? '') !== '' ? $u['display_name'] : $u['username']),
                    'status' => (string) $u['status'],
                ],
                'changes' => ['notification_preferences'],
            ], [$userId]);
        }
        return self::preferences($userId);
    }

    /**
     * Retention (A6 maintenance): delete notifications older than $days, in small batches and
     * time-boxed so it fits a shared-host request. Returns the number deleted.
     */
    public static function prune(int $days = 0, float $budgetSeconds = 10.0): int
    {
        if ($days <= 0) {
            $days = Settings::int('notification_retention_days', 90);
        }
        if ($days <= 0) {
            return 0;
        }
        $cutoff = Db::ts(time() - $days * 86400);
        $deadline = microtime(true) + max(0.5, $budgetSeconds);
        $total = 0;
        do {
            $n = Db::run('DELETE FROM notifications WHERE created_at < ? ORDER BY id ASC LIMIT 1000', [$cutoff])->rowCount();
            $total += $n;
        } while ($n === 1000 && microtime(true) < $deadline);
        return $total;
    }

    /**
     * Notification JSON shape (docs/ARCHITECTURE.md §9.2). $row may carry actor_username /
     * actor_display_name from a join.
     * @param array<string,mixed> $row
     * @return array<string,mixed>
     */
    public static function format(array $row): array
    {
        $data = json_decode((string) ($row['data'] ?? ''), true);
        $actor = null;
        if ($row['actor_id'] !== null) {
            $username = (string) ($row['actor_username'] ?? '');
            $display = (string) ($row['actor_display_name'] ?? '');
            $actor = [
                'id' => (int) $row['actor_id'],
                'username' => $username,
                'display_name' => $display !== '' ? $display : $username,
            ];
        }
        $readAt = $row['read_at'] !== null && (string) $row['read_at'] !== Notifier::HIDDEN_READ_AT ? (string) $row['read_at'] : null;
        return [
            'id'         => (int) $row['id'],
            'category'   => (string) $row['category'],
            'type'       => (string) $row['type'],
            'title'      => (string) $row['title'],
            'body'       => (string) $row['body'],
            'data'       => is_array($data) && $data !== [] ? $data : (object) [],
            'actor'      => $actor,
            'read'       => $row['read_at'] !== null,
            'read_at'    => Db::iso($readAt),
            'created_at' => Db::iso((string) $row['created_at']),
        ];
    }

    /** @return array<string,mixed> */
    private static function load(int $userId, int $id): array
    {
        $row = Db::one(
            'SELECT n.*, a.username AS actor_username, a.display_name AS actor_display_name
             FROM notifications n LEFT JOIN users a ON a.id = n.actor_id
             WHERE n.id = :id AND n.user_id = :u AND (n.read_at IS NULL OR n.read_at <> :hidden)',
            ['id' => $id, 'u' => $userId, 'hidden' => Notifier::HIDDEN_READ_AT]
        );
        if ($row === null) {
            throw ApiException::notFound('notification', 'NOTIFICATION_NOT_FOUND');
        }
        return $row;
    }

    private static function toBool(mixed $v): ?bool
    {
        if (is_bool($v)) {
            return $v;
        }
        if ($v === 1 || $v === 0) {
            return $v === 1;
        }
        if (is_string($v)) {
            $s = strtolower(trim($v));
            if (in_array($s, ['1', 'true', 'yes', 'on'], true)) {
                return true;
            }
            if (in_array($s, ['0', 'false', 'no', 'off'], true)) {
                return false;
            }
        }
        return null;
    }
}
