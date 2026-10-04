<?php
declare(strict_types=1);

namespace FT\Storage;

use FT\Core\ApiException;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Events\EventBus;

/**
 * Per-user storage quotas (§4).
 *
 *   used      = users.used_bytes = SUM(file_versions.size) over files the user OWNS, including
 *               trashed files and every version (logical size: dedup does not reduce it).
 *   reserved  = declared size of the owner's active/assembling upload sessions — so parallel
 *               uploads cannot together overshoot the quota.
 *   effective = users.quota_bytes when set (PHP_INT_MAX or above = unlimited), otherwise the role
 *               default: admin unlimited, user default_quota_bytes, guest guest_quota_bytes.
 *
 * Files uploaded into someone else's shared folder belong to (and are charged to) the folder
 * owner, so reservations are attributed through the session's target file/folder owner.
 */
final class QuotaService
{
    /** null = unlimited */
    public static function effectiveQuota(array $userRow): ?int
    {
        $explicit = $userRow['quota_bytes'] ?? null;
        if ($explicit !== null && $explicit !== '') {
            return self::normalise($explicit);
        }
        // role_id is authoritative (Policy rule); the 'role' slug is only a fallback for arrays
        // built without it.
        if (isset($userRow['role_id']) && $userRow['role_id'] !== '') {
            $roleId = (int) $userRow['role_id'];
            $role = $roleId === 1 ? 'admin' : ($roleId === 3 ? 'guest' : 'user');
        } else {
            $role = (string) ($userRow['role'] ?? 'user');
        }
        return match ($role) {
            'admin' => null,
            'guest' => self::normalise(Settings::get('guest_quota_bytes', 0)),
            default => self::normalise(Settings::get('default_quota_bytes', 1073741824)),
        };
    }

    /** @return array{quota_bytes:?int, used_bytes:int, reserved_bytes:int, available_bytes:?int, percent:float} */
    public static function usage(int $userId): array
    {
        $user = Db::one('SELECT id, role_id, quota_bytes, used_bytes FROM users WHERE id = ?', [$userId]);
        if ($user === null) {
            return ['quota_bytes' => 0, 'used_bytes' => 0, 'reserved_bytes' => 0, 'available_bytes' => 0, 'percent' => 0.0];
        }
        $quota = self::effectiveQuota($user);
        $used = (int) $user['used_bytes'];
        $reserved = self::reserved($userId);
        return [
            'quota_bytes'     => $quota,
            'used_bytes'      => $used,
            'reserved_bytes'  => $reserved,
            'available_bytes' => $quota === null ? null : max(0, $quota - $used - $reserved),
            'percent'         => self::percent($used, $quota),
        ];
    }

    /**
     * Throw QUOTA_EXCEEDED (413) unless $bytes more fit into $ownerId's quota, counting other
     * active upload reservations (except $excludeUploadId — the upload being checked).
     */
    public static function assertCanStore(int $ownerId, int $bytes, ?string $excludeUploadId = null): void
    {
        $user = Db::one('SELECT id, role_id, quota_bytes, used_bytes FROM users WHERE id = ?', [$ownerId]);
        if ($user === null) {
            throw ApiException::quotaExceeded(max(0, $bytes), 0);
        }
        $quota = self::effectiveQuota($user);
        if ($quota === null) {
            return;
        }
        $available = $quota - (int) $user['used_bytes'] - self::reserved($ownerId, $excludeUploadId);
        if ($bytes > $available) {
            throw ApiException::quotaExceeded(max(0, $bytes), max(0, $available));
        }
    }

    /**
     * Apply a delta to users.used_bytes (never below zero), publish quota.updated to the user and
     * notify ONCE when usage crosses the quota_warning_percent threshold upwards.
     */
    public static function adjust(int $userId, int $deltaBytes): void
    {
        if ($deltaBytes === 0) {
            return;
        }
        if ($deltaBytes > 0) {
            $n = Db::run('UPDATE users SET used_bytes = used_bytes + :d WHERE id = :id', ['d' => $deltaBytes, 'id' => $userId])->rowCount();
        } else {
            // BIGINT UNSIGNED cannot go negative: clamp at zero without an out-of-range error.
            $n = Db::run(
                'UPDATE users SET used_bytes = IF(used_bytes > :a, used_bytes - :b, 0) WHERE id = :id',
                ['a' => -$deltaBytes, 'b' => -$deltaBytes, 'id' => $userId]
            )->rowCount();
        }
        if ($n === 0 && Db::value('SELECT 1 FROM users WHERE id = ?', [$userId]) === null) {
            return;
        }
        $usage = self::usage($userId);
        EventBus::publish('quota.updated', ['quota' => $usage], [$userId], ['actor_id' => null]);
        if ($deltaBytes > 0) {
            self::maybeWarn($userId, $usage, $deltaBytes);
        }
    }

    /** Authoritative recount from file_versions (maintenance reconcile_quotas). Returns used bytes. */
    public static function recalculate(int $userId): int
    {
        $sum = (int) (Db::value(
            'SELECT COALESCE(SUM(v.size), 0) FROM file_versions v JOIN files f ON f.id = v.file_id WHERE f.owner_id = ?',
            [$userId]
        ) ?? 0);
        $old = Db::value('SELECT used_bytes FROM users WHERE id = ?', [$userId]);
        if ($old === null) {
            return 0;
        }
        if ((int) $old !== $sum) {
            Db::update('users', ['used_bytes' => $sum], ['id' => $userId]);
            Logger::info('maintenance', 'Quota usage reconciled', ['user_id' => $userId, 'from' => (int) $old, 'to' => $sum]);
            EventBus::publish('quota.updated', ['quota' => self::usage($userId)], [$userId], ['actor_id' => null]);
        }
        return $sum;
    }

    /** Declared size of active/assembling (unexpired) uploads whose content $ownerId will own. */
    public static function reserved(int $ownerId, ?string $excludeUploadId = null): int
    {
        $params = ['now' => Db::now(), 'uid' => $ownerId];
        $exclude = '';
        if ($excludeUploadId !== null && $excludeUploadId !== '') {
            $exclude = ' AND s.id <> :ex';
            $params['ex'] = $excludeUploadId;
        }
        return (int) (Db::value(
            "SELECT COALESCE(SUM(s.size), 0) FROM upload_sessions s
               LEFT JOIN files fi ON fi.id = s.target_file_id
               LEFT JOIN folders fo ON fo.id = s.folder_id
              WHERE s.status IN ('active', 'assembling') AND s.expires_at > :now{$exclude}
                AND (CASE WHEN s.target_file_id IS NOT NULL THEN fi.owner_id
                          WHEN s.folder_id IS NOT NULL THEN fo.owner_id
                          ELSE s.user_id END) = :uid",
            $params
        ) ?? 0);
    }

    public static function percent(int $used, ?int $quota): float
    {
        if ($quota === null) {
            return 0.0;
        }
        if ($quota <= 0) {
            return $used > 0 ? 100.0 : 0.0;
        }
        return round(min(100.0, $used * 100 / $quota), 1);
    }

    /** "Unlimited" sentinel (PHP_INT_MAX or any larger/negative configured value) => null. */
    private static function normalise(mixed $v): ?int
    {
        if (is_string($v)) {
            $v = trim($v);
            if (!preg_match('/^-?\d+$/', $v)) {
                return 0;
            }
            // BIGINT UNSIGNED values above PHP_INT_MAX arrive as strings.
            if ($v[0] !== '-' && (strlen($v) > 19 || (strlen($v) === 19 && strcmp($v, (string) PHP_INT_MAX) >= 0))) {
                return null;
            }
            $v = (int) $v;
        }
        if (!is_int($v)) {
            $v = is_numeric($v) ? (int) $v : 0;
        }
        if ($v < 0 || $v >= PHP_INT_MAX) {
            return null;
        }
        return $v;
    }

    private static function maybeWarn(int $userId, array $usage, int $delta): void
    {
        $quota = $usage['quota_bytes'];
        $threshold = max(1, min(100, Settings::int('quota_warning_percent', 90)));
        if ($quota === null || $quota <= 0) {
            return;
        }
        $after = (int) $usage['used_bytes'];
        $before = $after - $delta;
        $limit = $quota * $threshold / 100;
        if (!($before < $limit && $after >= $limit)) {
            return;
        }
        if (!class_exists(\FT\Notifications\Notifier::class) || !method_exists(\FT\Notifications\Notifier::class, 'notify')) {
            return;
        }
        try {
            $pct = (int) floor($usage['percent']);
            \FT\Notifications\Notifier::notify(
                $userId,
                'quota',
                'quota.warning',
                "You have used {$pct}% of your storage",
                'Free up space by emptying the Trash or deleting old versions, or ask an administrator for a larger quota.',
                ['link' => '#/settings', 'percent' => $usage['percent'], 'used_bytes' => $after, 'quota_bytes' => $quota],
                // one notification per threshold crossing (a later crossing on another day notifies again)
                'quota-warning:' . $threshold . ':' . gmdate('Ymd'),
                null
            );
        } catch (\Throwable $e) {
            Logger::warning('app', 'Quota warning notification failed', ['user_id' => $userId, 'error' => $e->getMessage()]);
        }
    }
}
