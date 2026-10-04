<?php
declare(strict_types=1);

namespace FT\Users;

use FT\Auth\ApiTokens;
use FT\Auth\Auth;
use FT\Auth\Passwords;
use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Stats;
use FT\Events\EventBus;
use FT\Http\Request;
use FT\Jobs\Queue;
use FT\Security\Policy;
use FT\Security\RateLimiter;

/**
 * Users: profile changes by the user, the administrator lifecycle (create, edit, disable, suspend,
 * delete, reset password, role, quota, sign-out, 2FA), share-dialog lookup and activity.
 *
 * Invariants enforced here (never trust the client for them):
 *  - an administrator cannot delete, disable, suspend or demote their own account;
 *  - there is always at least one active administrator (checked under row locks, so two admins
 *    demoting each other at the same moment cannot both succeed);
 *  - disabling, suspending or deleting an account signs it out everywhere immediately.
 */
final class UserService
{
    public const USERNAME_PATTERN = '/^[A-Za-z0-9._-]{3,32}$/';
    public const STATUSES = ['active', 'disabled', 'suspended'];

    /** Preference keys with a fixed set of values. Other keys are free-form scalars. */
    private const PREF_ENUMS = [
        'theme'  => ['dark', 'light', 'system'],
        // Accent palette (CSS tokens on html[data-accent] in assets/css/app.css); champagne is the default.
        'accent' => ['champagne', 'platinum', 'rose', 'aurora', 'sapphire', 'violet'],
        'view'   => ['grid', 'list'],
        'sort'   => ['name', 'size', 'created_at', 'updated_at', 'kind'],
        'order'  => ['asc', 'desc'],
    ];

    // ------------------------------------------------------------------ lookups

    public static function find(int $id): ?array
    {
        return $id > 0 ? Db::one('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL', [$id]) : null;
    }

    /** Load a (non-deleted) user or throw USER_NOT_FOUND (404). */
    public static function require(int $id): array
    {
        $row = self::find($id);
        if ($row === null) {
            throw ApiException::notFound('user', 'USER_NOT_FOUND');
        }
        return $row;
    }

    /**
     * Share-dialog lookup: active users whose username or display name starts with $q
     * (or a word of the display name does). Never returns e-mail addresses.
     * @return array<int,array{id:int,username:string,display_name:string}>
     */
    public static function lookup(array $viewer, string $q, int $limit = 10): array
    {
        $q = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', '', $q));
        if (mb_strlen($q) < 2) {
            return [];
        }
        $q = mb_substr($q, 0, 64);
        $like = Db::like($q);
        $rows = Db::all(
            "SELECT id, username, display_name FROM users
             WHERE deleted_at IS NULL AND status = 'active' AND id <> :me
               AND (username LIKE :p1 OR display_name LIKE :p2 OR display_name LIKE :p3)
             ORDER BY (username = :exact) DESC, username ASC
             LIMIT :lim",
            ['me' => (int) $viewer['id'], 'p1' => $like . '%', 'p2' => $like . '%', 'p3' => '% ' . $like . '%', 'exact' => $q, 'lim' => max(1, min(10, $limit))]
        );
        return array_map(static fn (array $r): array => Auth::ref($r), $rows);
    }

    // ------------------------------------------------------------------ shapes

    /** UserRef + status/role (the payload of user.* events; safe for the admin channel). */
    public static function eventRef(array $row): array
    {
        return Auth::ref($row) + [
            'role'   => Policy::roleSlug((int) $row['role_id']),
            'status' => $row['deleted_at'] !== null ? 'deleted' : (string) $row['status'],
        ];
    }

    /** AdminUser shape. $usage defaults to the fallback computed from the row. */
    public static function adminShape(array $row, ?array $usage = null, int $activeSessions = 0): array
    {
        $raw = $row['quota_bytes'];
        $rawQuota = $raw === null ? null : ((is_numeric($raw) && (int) $raw < PHP_INT_MAX) ? (int) $raw : -1);
        $locked = $row['locked_until'] !== null && (string) $row['locked_until'] > Db::now();
        return Auth::ref($row) + [
            'email'                => $row['email'] ?? null,
            'role'                 => Policy::roleSlug((int) $row['role_id']),
            'status'               => (string) $row['status'],
            'status_reason'        => $row['status_reason'] ?? null,
            'two_factor_enabled'   => (bool) $row['totp_enabled'],
            'must_change_password' => (bool) $row['must_change_password'],
            'locked'               => $locked,
            'locked_until'         => $locked ? Db::iso((string) $row['locked_until']) : null,
            'failed_login_count'   => (int) $row['failed_login_count'],
            'quota_bytes'          => $rawQuota,
            'used_bytes'           => (int) $row['used_bytes'],
            'quota'                => $usage ?? Auth::fallbackQuota($row),
            'sessions_active'      => $activeSessions,
            'created_at'           => Db::iso($row['created_at'] ?? null),
            'updated_at'           => Db::iso($row['updated_at'] ?? null),
            'last_login_at'        => Db::iso($row['last_login_at'] ?? null),
            'last_login_ip'        => $row['last_login_ip'] ?? null,
            'last_seen_at'         => Db::iso($row['last_seen_at'] ?? null),
            'password_changed_at'  => Db::iso($row['password_changed_at'] ?? null),
        ];
    }

    /** Full quota usage for one user (A2 QuotaService when present). */
    public static function usage(array $row): array
    {
        try {
            if (class_exists(\FT\Storage\QuotaService::class)) {
                $u = \FT\Storage\QuotaService::usage((int) $row['id']);
                if (is_array($u)) {
                    return $u;
                }
            }
        } catch (\Throwable $e) {
            Logger::warning('app', 'Quota usage unavailable', ['error' => $e->getMessage()]);
        }
        $u = Auth::fallbackQuota($row);
        $u['reserved_bytes'] = self::reservedBytes([(int) $row['id']])[(int) $row['id']] ?? 0;
        if ($u['available_bytes'] !== null) {
            $u['available_bytes'] = max(0, $u['available_bytes'] - $u['reserved_bytes']);
        }
        return $u;
    }

    /** @return array{items:array<int,array>,total:int} */
    public static function adminList(array $filters, int $page, int $perPage): array
    {
        $where = ['u.deleted_at IS NULL'];
        $params = [];
        $q = trim((string) ($filters['q'] ?? ''));
        if ($q !== '') {
            $like = '%' . Db::like(mb_substr($q, 0, 100)) . '%';
            $where[] = '(u.username LIKE :q1 OR u.display_name LIKE :q2 OR u.email LIKE :q3)';
            $params += ['q1' => $like, 'q2' => $like, 'q3' => $like];
        }
        $status = (string) ($filters['status'] ?? '');
        if (in_array($status, self::STATUSES, true)) {
            $where[] = 'u.status = :st';
            $params['st'] = $status;
        } elseif ($status === 'locked') {
            $where[] = 'u.locked_until > :lk';
            $params['lk'] = Db::now();
        }
        $role = (string) ($filters['role'] ?? '');
        if (isset(Policy::ROLES[$role])) {
            $where[] = 'u.role_id = :rl';
            $params['rl'] = Policy::ROLES[$role];
        }
        $sorts = ['username' => 'u.username', 'created_at' => 'u.created_at', 'last_login_at' => 'u.last_login_at', 'used_bytes' => 'u.used_bytes', 'status' => 'u.status'];
        $sort = $sorts[(string) ($filters['sort'] ?? '')] ?? 'u.username';
        $order = strtolower((string) ($filters['order'] ?? '')) === 'desc' ? 'DESC' : 'ASC';
        $whereSql = implode(' AND ', $where);

        $total = (int) Db::value("SELECT COUNT(*) FROM users u WHERE {$whereSql}", $params);
        $rows = Db::all(
            "SELECT u.* FROM users u WHERE {$whereSql} ORDER BY {$sort} {$order}, u.id ASC LIMIT :lim OFFSET :off",
            $params + ['lim' => $perPage, 'off' => ($page - 1) * $perPage]
        );
        $ids = array_map(static fn ($r) => (int) $r['id'], $rows);
        $sessions = self::activeSessionCounts($ids);
        $reserved = self::reservedBytes($ids);
        $items = [];
        foreach ($rows as $r) {
            $usage = Auth::fallbackQuota($r);
            $usage['reserved_bytes'] = $reserved[(int) $r['id']] ?? 0;
            if ($usage['available_bytes'] !== null) {
                $usage['available_bytes'] = max(0, $usage['available_bytes'] - $usage['reserved_bytes']);
            }
            $items[] = self::adminShape($r, $usage, $sessions[(int) $r['id']] ?? 0);
        }
        return ['items' => $items, 'total' => $total];
    }

    /** @param int[] $ids @return array<int,int> */
    public static function activeSessionCounts(array $ids): array
    {
        if ($ids === []) {
            return [];
        }
        [$in, $params] = Db::inList($ids, 'u');
        $params['now'] = Db::now();
        $out = [];
        foreach (Db::all("SELECT user_id, COUNT(*) AS n FROM user_sessions WHERE user_id IN {$in} AND revoked_at IS NULL AND expires_at > :now GROUP BY user_id", $params) as $r) {
            $out[(int) $r['user_id']] = (int) $r['n'];
        }
        return $out;
    }

    /** Bytes reserved by in-progress uploads, per user (one query for a whole page). @return array<int,int> */
    private static function reservedBytes(array $ids): array
    {
        if ($ids === []) {
            return [];
        }
        try {
            [$in, $params] = Db::inList($ids, 'r');
            $out = [];
            foreach (Db::all("SELECT user_id, SUM(size) AS b FROM upload_sessions WHERE user_id IN {$in} AND status IN ('active','assembling') GROUP BY user_id", $params) as $r) {
                $out[(int) $r['user_id']] = (int) $r['b'];
            }
            return $out;
        } catch (\Throwable) {
            return [];
        }
    }

    // ------------------------------------------------------------------ validation helpers

    public static function validateUsername(mixed $value, ?int $exceptId = null): string
    {
        $u = is_string($value) ? trim($value) : '';
        if (!preg_match(self::USERNAME_PATTERN, $u)) {
            throw ApiException::validation(['username' => 'Use 3–32 characters: letters, numbers, dots, hyphens and underscores.']);
        }
        $taken = Db::value('SELECT id FROM users WHERE username = ? LIMIT 1', [$u]);
        if ($taken !== null && (int) $taken !== $exceptId) {
            throw ApiException::conflict('This username is already taken.', 'CONFLICT', ['fields' => ['username' => 'This username is already taken.']]);
        }
        return $u;
    }

    /** Returns the normalised address, or null for "no e-mail". */
    public static function validateEmail(mixed $value, ?int $exceptId = null): ?string
    {
        if ($value === null || (is_string($value) && trim($value) === '')) {
            return null;
        }
        $e = is_string($value) ? mb_strtolower(trim($value)) : '';
        if ($e === '' || mb_strlen($e) > 191 || filter_var($e, FILTER_VALIDATE_EMAIL) === false) {
            throw ApiException::validation(['email' => 'Enter a valid e-mail address.']);
        }
        $taken = Db::value('SELECT id FROM users WHERE email = ? LIMIT 1', [$e]);
        if ($taken !== null && (int) $taken !== $exceptId) {
            throw ApiException::conflict('This e-mail address is already in use.', 'CONFLICT', ['fields' => ['email' => 'This e-mail address is already in use.']]);
        }
        return $e;
    }

    public static function cleanDisplayName(mixed $value, string $fallback): string
    {
        $d = is_string($value) ? trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $value)) : '';
        if (mb_strlen($d) > 100) {
            throw ApiException::validation(['display_name' => 'Use at most 100 characters.']);
        }
        return $d !== '' ? $d : $fallback;
    }

    /**
     * Quota input: null = role default, -1 = unlimited (stored as PHP_INT_MAX), otherwise bytes ≥ 0.
     */
    public static function parseQuota(mixed $value): ?int
    {
        if ($value === null || $value === '') {
            return null;
        }
        if (is_string($value) && preg_match('/^-?\d+$/', trim($value))) {
            $value = (int) trim($value);
        }
        if (is_float($value) && floor($value) === $value && abs($value) < 9.0e18) {
            $value = (int) $value;
        }
        if (!is_int($value) || $value < -1 || $value >= PHP_INT_MAX) {
            throw ApiException::validation(['quota_bytes' => 'Quota must be a number of bytes, -1 for unlimited, or empty for the role default.']);
        }
        return $value === -1 ? PHP_INT_MAX : $value;
    }

    // ------------------------------------------------------------------ admin lifecycle

    /** @return array{user:array, temporary_password:?string} */
    public static function create(array $actor, array $in): array
    {
        $username = self::validateUsername($in['username'] ?? null);
        $email = self::validateEmail($in['email'] ?? null);
        $display = self::cleanDisplayName($in['display_name'] ?? null, $username);
        $roleId = Policy::roleId(is_string($in['role'] ?? null) ? $in['role'] : 'user');
        $quota = array_key_exists('quota_bytes', $in) ? self::parseQuota($in['quota_bytes']) : null;
        $password = is_string($in['password'] ?? null) ? $in['password'] : '';
        $temporary = null;
        if ($password !== '') {
            Passwords::assertAcceptable($password, $username, $email);
            $mustChange = filter_var($in['must_change_password'] ?? false, FILTER_VALIDATE_BOOLEAN);
        } else {
            $password = $temporary = Passwords::generateTemporary();
            $mustChange = true;
        }
        $now = Db::now();
        try {
            $id = Db::transaction(static fn (): int => Db::insert('users', [
                'username'             => $username,
                'email'                => $email,
                'display_name'         => $display,
                'password_hash'        => Passwords::hash($password),
                'role_id'              => $roleId,
                'status'               => 'active',
                'quota_bytes'          => $quota,
                'must_change_password' => $mustChange ? 1 : 0,
                'password_changed_at'  => $now,
                'created_by'           => (int) $actor['id'],
                'created_at'           => $now,
                'updated_at'           => $now,
            ]));
        } catch (\PDOException $e) {
            if ((string) $e->getCode() === '23000') {
                throw ApiException::conflict('This username or e-mail address is already in use.');
            }
            throw $e;
        }
        $row = self::require($id);
        Audit::log('admin.user_create', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'detail' => $username, 'meta' => [
            'role' => Policy::roleSlug($roleId), 'quota_bytes' => $quota, 'generated' => $temporary !== null, 'must_change' => $mustChange,
        ]]);
        Stats::bump('new_users');
        EventBus::publish('stats.updated', ['metric' => 'new_users', 'delta' => 1], [], ['admin' => true]);
        self::publish('user.created', $row, ['created']);
        return ['user' => self::adminShape($row, null, 0), 'temporary_password' => $temporary];
    }

    /** Admin edit: display_name, email, role, quota_bytes, must_change_password. */
    public static function adminUpdate(array $actor, int $id, array $in): array
    {
        $changes = [];
        $result = Db::transaction(static function () use ($actor, $id, $in, &$changes): array {
            $row = Db::one('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL FOR UPDATE', [$id]);
            if ($row === null) {
                throw ApiException::notFound('user', 'USER_NOT_FOUND');
            }
            $set = [];
            $audits = [];
            if (array_key_exists('display_name', $in)) {
                $d = self::cleanDisplayName($in['display_name'], (string) $row['username']);
                if ($d !== (string) $row['display_name']) {
                    $set['display_name'] = $d;
                    $changes[] = 'display_name';
                }
            }
            if (array_key_exists('email', $in)) {
                $e = self::validateEmail($in['email'], $id);
                if ($e !== $row['email']) {
                    $set['email'] = $e;
                    $changes[] = 'email';
                }
            }
            if (array_key_exists('must_change_password', $in)) {
                $m = filter_var($in['must_change_password'], FILTER_VALIDATE_BOOLEAN) ? 1 : 0;
                if ($m !== (int) $row['must_change_password']) {
                    $set['must_change_password'] = $m;
                    $changes[] = 'must_change_password';
                }
            }
            if (array_key_exists('role', $in) && $in['role'] !== null) {
                $newRole = Policy::roleId(is_string($in['role']) ? $in['role'] : '');
                $oldRole = (int) $row['role_id'];
                if ($newRole !== $oldRole) {
                    if ($oldRole === 1) {
                        if ($id === (int) $actor['id']) {
                            throw ApiException::conflict('You cannot remove your own administrator role.');
                        }
                        self::assertNotLastAdmin($row, 'demote');
                    }
                    $set['role_id'] = $newRole;
                    $changes[] = 'role';
                    $audits[] = ['admin.role_change', ['from' => Policy::roleSlug($oldRole), 'to' => Policy::roleSlug($newRole)]];
                }
            }
            if (array_key_exists('quota_bytes', $in)) {
                $q = self::parseQuota($in['quota_bytes']);
                $old = $row['quota_bytes'] === null ? null : (int) $row['quota_bytes'];
                if ($q !== $old) {
                    $set['quota_bytes'] = $q;
                    $changes[] = 'quota';
                    $audits[] = ['admin.quota_change', ['from' => self::quotaLabel($old), 'to' => self::quotaLabel($q)]];
                }
            }
            if ($set !== []) {
                $set['updated_at'] = Db::now();
                Db::update('users', $set, ['id' => $id]);
                $plain = array_values(array_diff($changes, ['role', 'quota']));
                if ($plain !== []) {
                    $audits[] = ['admin.user_update', ['fields' => $plain]];
                }
            }
            foreach ($audits as [$action, $meta]) {
                Audit::log($action, ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'detail' => (string) $row['username'], 'meta' => $meta]);
            }
            return self::require($id);
        });
        if ($changes !== []) {
            self::publish('user.updated', $result, $changes);
            if (in_array('quota', $changes, true)) {
                // The user's devices update their storage meter straight away.
                EventBus::publish('quota.updated', ['quota' => self::usage($result)], [$id]);
            }
        }
        return self::detail($result);
    }

    /** Enable, disable or suspend an account. Disabling/suspending signs it out everywhere. */
    public static function setStatus(array $actor, int $id, string $status, ?string $reason = null): array
    {
        if (!in_array($status, self::STATUSES, true)) {
            throw ApiException::validation(['status' => 'Status must be active, disabled or suspended.']);
        }
        $reason = $reason !== null ? mb_substr(trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $reason)), 0, 255) : null;
        $reason = $reason === '' ? null : $reason;
        $changed = Db::transaction(static function () use ($actor, $id, $status, $reason): bool {
            $row = Db::one('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL FOR UPDATE', [$id]);
            if ($row === null) {
                throw ApiException::notFound('user', 'USER_NOT_FOUND');
            }
            if ($status !== 'active') {
                if ($id === (int) $actor['id']) {
                    throw ApiException::conflict('You cannot ' . ($status === 'suspended' ? 'suspend' : 'disable') . ' your own account.');
                }
                if ((int) $row['role_id'] === 1 && $row['status'] === 'active') {
                    self::assertNotLastAdmin($row, $status === 'suspended' ? 'suspend' : 'disable');
                }
            }
            $set = ['status' => $status, 'status_reason' => $status === 'active' ? null : $reason, 'updated_at' => Db::now()];
            if ($status === 'active') {
                $set['locked_until'] = null;
                $set['failed_login_count'] = 0;
            }
            Db::update('users', $set, ['id' => $id]);
            $action = ['active' => 'admin.user_enable', 'disabled' => 'admin.user_disable', 'suspended' => 'admin.user_suspend'][$status];
            Audit::log($action, ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'detail' => (string) $row['username'], 'meta' => ['reason' => $reason, 'previous' => (string) $row['status']]]);
            return $row['status'] !== $status || $status === 'active';
        });
        if ($status !== 'active') {
            Auth::revokeAllSessions($id, null, 'account_' . $status);
        }
        $row = self::require($id);
        if ($changed) {
            self::publish('user.updated', $row, ['status']);
        }
        return self::detail($row);
    }

    /**
     * Soft delete: the account can no longer sign in, its sessions, API tokens and shares are
     * revoked at once, and a background job purges its files (A3 TrashService).
     */
    public static function delete(array $actor, int $id): void
    {
        if ($id === (int) $actor['id']) {
            throw ApiException::conflict('You cannot delete your own account.');
        }
        $revokedShares = [];
        $cascade = null; // ShareService cascade result (also revokes re-shares made from these shares)
        $useCascade = class_exists(\FT\Sharing\ShareService::class) && method_exists(\FT\Sharing\ShareService::class, 'revokeOwnedBy');
        $row = Db::transaction(static function () use ($id, &$revokedShares, &$cascade, $useCascade): array {
            $row = Db::one('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL FOR UPDATE', [$id]);
            if ($row === null) {
                throw ApiException::notFound('user', 'USER_NOT_FOUND');
            }
            if ((int) $row['role_id'] === 1 && $row['status'] === 'active') {
                self::assertNotLastAdmin($row, 'delete');
            }
            $now = Db::now();
            Db::update('users', [
                'deleted_at' => $now, 'status' => 'disabled', 'status_reason' => 'Account deleted',
                'email' => null, 'updated_at' => $now,
            ], ['id' => $id]);
            Db::run('UPDATE api_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL', [$now, $id]);
            Db::run('UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL', [$now, $id]);
            Db::run('DELETE FROM push_subscriptions WHERE user_id = ?', [$id]);
            if ($useCascade) {
                // Revokes the user's shares AND every re-share made from them (events after commit).
                $cascade = \FT\Sharing\ShareService::revokeOwnedBy($id, \FT\Core\RequestContext::userId());
            } else {
                $revokedShares = Db::all(
                    'SELECT id, kind, target_type, file_id, folder_id, recipient_id FROM shares WHERE owner_id = ? AND revoked_at IS NULL',
                    [$id]
                );
                if ($revokedShares !== []) {
                    Db::run('UPDATE shares SET revoked_at = ?, revoked_by = ?, updated_at = ? WHERE owner_id = ? AND revoked_at IS NULL', [$now, \FT\Core\RequestContext::userId(), $now, $id]);
                }
            }
            Audit::log('admin.user_delete', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'detail' => (string) $row['username'], 'meta' => ['shares_revoked' => $useCascade ? count((array) $cascade) : count($revokedShares)]]);
            return $row;
        });
        Auth::revokeAllSessions($id, null, 'account_deleted');
        if ($useCascade && is_array($cascade) && $cascade !== [] && method_exists(\FT\Sharing\ShareService::class, 'afterCascade')) {
            \FT\Sharing\ShareService::afterCascade($cascade, \FT\Core\RequestContext::userId(), null, ['reason' => 'owner_deleted']);
        }
        foreach ($revokedShares as $s) {
            $recipients = $s['recipient_id'] !== null ? [(int) $s['recipient_id']] : [];
            EventBus::publish('share.revoked', [
                'share'     => ['id' => (int) $s['id'], 'kind' => (string) $s['kind'], 'target_type' => (string) $s['target_type'], 'status' => 'revoked'],
                'file_id'   => $s['file_id'] !== null ? (int) $s['file_id'] : null,
                'folder_id' => $s['folder_id'] !== null ? (int) $s['folder_id'] : null,
            ], $recipients, ['share_id' => (int) $s['id'], 'admin' => true]);
        }
        try {
            Queue::push(self::class . '::purgeUserJob', ['user_id' => $id], 0, 'default', 5);
        } catch (\Throwable $e) {
            Logger::warning('app', 'Could not queue user purge', ['user_id' => $id, 'error' => $e->getMessage()]);
        }
        $row['deleted_at'] = Db::now();
        self::publish('user.deleted', $row, ['deleted']);
    }

    /** Queue handler: purge everything a deleted user owned (A3). Idempotent. */
    public static function purgeUserJob(array $payload): void
    {
        $id = (int) ($payload['user_id'] ?? 0);
        if ($id <= 0) {
            return;
        }
        $row = Db::one('SELECT id, deleted_at FROM users WHERE id = ?', [$id]);
        if ($row === null || $row['deleted_at'] === null) {
            return; // gone already, or restored
        }
        $trash = 'FT\\Files\\TrashService';
        if (!class_exists($trash) || !method_exists($trash, 'purgeAllForOwner')) {
            Logger::warning('app', 'User data purge skipped: TrashService unavailable', ['user_id' => $id]);
            return;
        }
        $trash::purgeAllForOwner($id);
        // Purging is time-boxed by A3 on slow hosts; if anything is left, continue in a later slice
        // (bounded, so a file that can never be purged does not requeue forever).
        $round = (int) ($payload['round'] ?? 0);
        $left = 0;
        try {
            $left = (int) Db::value('SELECT COUNT(*) FROM files WHERE owner_id = ?', [$id]);
        } catch (\Throwable) {
            $left = 0;
        }
        if ($left > 0 && $round < 200) {
            Queue::push(self::class . '::purgeUserJob', ['user_id' => $id, 'round' => $round + 1], 60, 'default', 5);
            Logger::info('app', 'User data purge continues later', ['user_id' => $id, 'files_left' => $left, 'round' => $round + 1]);
            return;
        }
        Logger::info('app', 'Purged data of deleted user', ['user_id' => $id, 'files_left' => $left]);
    }

    /**
     * Administrator reset: new (temporary) password, must change at next sign-in, and every
     * session and API token of the account is revoked (an administrator resetting their own
     * account keeps the session/token they are using).
     * @return array{temporary_password:?string, must_change_password:bool, sessions_revoked:int, tokens_revoked:int}
     */
    public static function resetPassword(array $actor, int $id, ?string $password = null): array
    {
        $row = self::require($id);
        $temporary = null;
        if ($password !== null && $password !== '') {
            Passwords::assertAcceptable($password, (string) $row['username'], $row['email'] ?? null);
        } else {
            $password = $temporary = Passwords::generateTemporary();
        }
        Db::transaction(static function () use ($id, $password): void {
            Passwords::store($id, $password, true);
        });
        [$keepSession, $keepToken] = self::actorKeeps($actor, $id);
        $counts = Auth::signOutEverywhere($id, 'password_reset', $keepSession, $keepToken);
        Audit::log('admin.password_reset', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'detail' => (string) $row['username'], 'meta' => [
            'generated' => $temporary !== null, 'sessions_revoked' => $counts['sessions_revoked'], 'api_clients_revoked' => $counts['tokens_revoked'],
        ]]);
        $signedOut = Auth::describeSignOut($counts);
        Passwords::notifySecurity($id, 'security.password_reset', 'An administrator reset your password',
            'You will be asked to choose a new password the next time you sign in.' . ($signedOut !== '' ? ' ' . ucfirst($signedOut) . '.' : ''),
            $counts);
        self::publish('user.updated', self::require($id), ['must_change_password']);
        return ['temporary_password' => $temporary, 'must_change_password' => true] + $counts;
    }

    /**
     * Administrator "sign out everywhere": every session and every API token of the account
     * (an administrator signing out their own account keeps the session/token they are using).
     * @return array{sessions_revoked:int, tokens_revoked:int}
     */
    public static function forceLogout(array $actor, int $id): array
    {
        $row = self::require($id);
        $self = $id === (int) $actor['id'];
        [$keepSession, $keepToken] = self::actorKeeps($actor, $id);
        $counts = Auth::signOutEverywhere($id, 'admin_force_logout', $keepSession, $keepToken);
        Audit::log('admin.force_logout', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'detail' => (string) $row['username'], 'meta' => [
            'sessions_revoked' => $counts['sessions_revoked'], 'api_clients_revoked' => $counts['tokens_revoked'],
        ]]);
        $signedOut = Auth::describeSignOut($counts);
        if ($signedOut !== '' && !$self) {
            Passwords::notifySecurity($id, 'security.sessions_revoked', 'You were signed out by an administrator',
                'An administrator signed your account out everywhere: ' . $signedOut . '.', $counts);
        }
        return $counts;
    }

    /**
     * When administrators act on their own account, the session or API token making the request
     * survives. @return array{0:?int,1:?int} [session row id to keep, token id to keep]
     */
    private static function actorKeeps(array $actor, int $targetId): array
    {
        if ($targetId !== (int) ($actor['id'] ?? 0)) {
            return [null, null];
        }
        $token = isset($actor['token_id']) ? (int) $actor['token_id'] : null;
        return [Auth::sessionRowId(), $token];
    }

    /** Turn off two-factor authentication (by the user after re-authenticating, or by an admin). */
    public static function disableTwoFactor(int $id, bool $byAdmin): array
    {
        $row = self::require($id);
        Db::update('users', ['totp_enabled' => 0, 'totp_secret_enc' => null, 'recovery_codes_enc' => null, 'totp_last_step' => null, 'updated_at' => Db::now()], ['id' => $id]);
        if ($byAdmin) {
            Audit::log('admin.2fa_disable', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'detail' => (string) $row['username'], 'meta' => ['was_enabled' => (bool) $row['totp_enabled']]]);
            Passwords::notifySecurity($id, 'security.2fa_disabled', 'Two-factor authentication was turned off', 'An administrator turned off two-factor authentication for your account. Turn it on again in the Security Centre.');
        } else {
            Audit::log('auth.2fa_disabled', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id]);
            Passwords::notifySecurity($id, 'security.2fa_disabled', 'Two-factor authentication was turned off', 'Two-factor authentication is now off for your account. If this was not you, change your password straight away.');
        }
        $fresh = self::require($id);
        self::publish('user.updated', $fresh, ['two_factor_enabled']);
        return $fresh;
    }

    /** AdminUser + recent activity + active sessions. */
    public static function detail(array $row): array
    {
        $id = (int) $row['id'];
        $sessions = Db::all(
            'SELECT id, ip, user_agent, auth_method, created_at, last_seen_at, expires_at, remember_selector FROM user_sessions
             WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ? ORDER BY last_seen_at DESC LIMIT 50',
            [$id, Db::now()]
        );
        $shape = self::adminShape($row, self::usage($row), count($sessions));
        $shape['sessions'] = array_map(static fn (array $s): array => [
            'id'           => (int) $s['id'],
            'ip'           => $s['ip'],
            'device'       => \FT\Support\UserAgent::describe($s['user_agent']),
            'method'       => (string) $s['auth_method'],
            'remember'     => $s['remember_selector'] !== null,
            'created_at'   => Db::iso($s['created_at']),
            'last_seen_at' => Db::iso($s['last_seen_at']),
            'expires_at'   => Db::iso($s['expires_at']),
        ], $sessions);
        $shape['api_tokens'] = (int) Db::value('SELECT COUNT(*) FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)', [$id, Db::now()]);
        $shape['recent_activity'] = self::activity($id, 1, 20)['items'];
        return $shape;
    }

    /** @return array{items:array<int,array>,total:int} audit rows by or about the user */
    public static function activity(int $id, int $page, int $perPage): array
    {
        $total = (int) Db::value('SELECT COUNT(*) FROM audit_logs WHERE user_id = :u OR owner_id = :o', ['u' => $id, 'o' => $id]);
        $rows = Db::all(
            'SELECT * FROM audit_logs WHERE user_id = :u OR owner_id = :o ORDER BY id DESC LIMIT :lim OFFSET :off',
            ['u' => $id, 'o' => $id, 'lim' => $perPage, 'off' => ($page - 1) * $perPage]
        );
        return ['items' => self::auditShapes($rows), 'total' => $total];
    }

    /** Audit rows → JSON (actors hydrated in one query). */
    public static function auditShapes(array $rows): array
    {
        $actorIds = array_values(array_unique(array_filter(array_map(static fn ($r) => $r['user_id'] !== null ? (int) $r['user_id'] : 0, $rows))));
        $actors = [];
        if ($actorIds !== []) {
            [$in, $params] = Db::inList($actorIds, 'a');
            foreach (Db::all("SELECT id, username, display_name FROM users WHERE id IN {$in}", $params) as $u) {
                $actors[(int) $u['id']] = Auth::ref($u);
            }
        }
        return array_map(static function (array $r) use ($actors): array {
            $meta = json_decode((string) ($r['meta'] ?? ''), true);
            return [
                'id'          => (int) $r['id'],
                'action'      => (string) $r['action'],
                'category'    => (string) $r['category'],
                'actor'       => $r['user_id'] !== null ? ($actors[(int) $r['user_id']] ?? null) : null,
                'actor_label' => $r['actor_label'],
                'target_type' => $r['target_type'],
                'target_id'   => $r['target_id'] !== null ? (int) $r['target_id'] : null,
                'detail'      => $r['detail'],
                'meta'        => is_array($meta) ? $meta : (object) [],
                'ip'          => $r['ip'],
                'device'      => $r['user_agent'] !== null && $r['user_agent'] !== '' ? \FT\Support\UserAgent::describe($r['user_agent']) : null,
                'created_at'  => Db::iso($r['created_at']),
            ];
        }, $rows);
    }

    // ------------------------------------------------------------------ self-service

    /** PATCH /user: display name, e-mail, preferences. Returns the fresh users row. */
    public static function updateProfile(array $user, array $in): array
    {
        $id = (int) $user['id'];
        $row = self::require($id);
        $set = [];
        $changes = [];
        if (array_key_exists('display_name', $in)) {
            $d = self::cleanDisplayName($in['display_name'], (string) $row['username']);
            if ($d !== (string) $row['display_name']) {
                $set['display_name'] = $d;
                $changes[] = 'display_name';
            }
        }
        $emailChanged = false;
        if (array_key_exists('email', $in)) {
            $e = self::validateEmail($in['email'], $id);
            if ($e !== $row['email']) {
                $set['email'] = $e;
                $changes[] = 'email';
                $emailChanged = true;
            }
        }
        if (array_key_exists('preferences', $in)) {
            if (!is_array($in['preferences'])) {
                throw ApiException::validation(['preferences' => 'Preferences must be an object.']);
            }
            $merged = self::mergePreferences((string) ($row['preferences'] ?? ''), $in['preferences']);
            if ($merged !== ($row['preferences'] ?? null)) {
                $set['preferences'] = $merged;
                $changes[] = 'preferences';
            }
        }
        if ($set === []) {
            return $row;
        }
        $set['updated_at'] = Db::now();
        Db::update('users', $set, ['id' => $id]);
        $fresh = self::require($id);
        $profileFields = array_values(array_diff($changes, ['preferences']));
        if ($profileFields !== []) {
            Audit::log('user.profile_update', ['category' => 'activity', 'target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'meta' => ['fields' => $profileFields]]);
        }
        if ($emailChanged) {
            Audit::log('auth.email_changed', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'meta' => ['had_email' => $row['email'] !== null, 'has_email' => $fresh['email'] !== null]]);
            Passwords::notifySecurity($id, 'security.email_changed', 'Your e-mail address was changed', 'The e-mail address on your account was changed. If this was not you, contact an administrator.');
        }
        // Preference-only changes go to the user's own devices; profile changes also update the admin dashboard.
        self::publish('user.updated', $fresh, $changes, $profileFields !== []);
        return $fresh;
    }

    /**
     * POST /user/password. Revokes every OTHER session and every API token except the one making
     * this request (when it is token-authenticated); the current session gets a fresh id.
     * @return array{sessions_revoked:int, tokens_revoked:int}
     */
    public static function changePassword(array $user, string $current, string $new, Request $req): array
    {
        $id = (int) $user['id'];
        RateLimiter::enforce('password', 'u' . $id);
        $row = self::require($id);
        if ($current === '' || !Passwords::verify($current, (string) $row['password_hash'])) {
            Audit::log('auth.password_change_failed', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id]);
            throw new ApiException('INVALID_CREDENTIALS', 'Your current password is incorrect.', 422, ['fields' => ['current_password' => 'Your current password is incorrect.']]);
        }
        if (hash_equals($current, $new)) {
            throw ApiException::validation(['new_password' => 'Choose a new password that is different from your current one.']);
        }
        Passwords::assertAcceptable($new, (string) $row['username'], $row['email'] ?? null, 'new_password');
        Db::transaction(static function () use ($id, $new): void {
            Passwords::store($id, $new, false);
        });
        $currentSession = $req->authVia === 'session' ? Auth::sessionRowId() : null;
        $currentToken = $req->authVia === 'token' && isset($user['token_id']) ? (int) $user['token_id'] : null;
        $counts = Auth::signOutEverywhere($id, 'password_changed', $currentSession, $currentToken);
        Auth::regenerateCurrentSession();
        Auth::refresh();
        Audit::log('auth.password_changed', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'meta' => [
            'other_sessions_revoked' => $counts['sessions_revoked'], 'api_clients_revoked' => $counts['tokens_revoked'],
        ]]);
        $signedOut = Auth::describeSignOut($counts, true);
        Passwords::notifySecurity($id, 'security.password_changed', 'Your password was changed',
            'Your password was changed' . ($signedOut !== '' ? '; ' . $signedOut : '') . '. If this was not you, contact an administrator.',
            $counts);
        self::publish('user.updated', self::require($id), ['password'], false);
        return $counts;
    }

    // ------------------------------------------------------------------ internals

    /**
     * There must always be at least one active administrator. Locks the active admin rows so a
     * concurrent demotion/disable sees the result of this one.
     */
    private static function assertNotLastAdmin(array $target, string $what): void
    {
        $admins = Db::column("SELECT id FROM users WHERE role_id = 1 AND status = 'active' AND deleted_at IS NULL FOR UPDATE");
        $others = array_filter($admins, static fn ($a) => (int) $a !== (int) $target['id']);
        if ($others === []) {
            throw ApiException::conflict('You cannot ' . $what . ' the last active administrator. Make another user an administrator first.', 'CONFLICT');
        }
    }

    private static function quotaLabel(?int $q): string|int|null
    {
        return $q === null ? 'role default' : ($q >= PHP_INT_MAX ? 'unlimited' : $q);
    }

    private static function mergePreferences(string $existingJson, array $patch): ?string
    {
        $prefs = json_decode($existingJson, true);
        $prefs = is_array($prefs) ? $prefs : [];
        foreach ($patch as $key => $value) {
            $key = (string) $key;
            if (!preg_match('/^[a-z][a-z0-9_]{0,39}$/', $key)) {
                throw ApiException::validation(['preferences' => 'Unknown preference "' . mb_substr($key, 0, 40) . '".']);
            }
            if ($value === null) {
                unset($prefs[$key]);
                continue;
            }
            if (isset(self::PREF_ENUMS[$key])) {
                if (!is_string($value) || !in_array($value, self::PREF_ENUMS[$key], true)) {
                    throw ApiException::validation(['preferences.' . $key => 'Choose one of: ' . implode(', ', self::PREF_ENUMS[$key]) . '.']);
                }
            } elseif ($key === 'trash_retention_days') {
                if (!is_int($value) || $value < 0 || $value > 3650) {
                    throw ApiException::validation(['preferences.trash_retention_days' => 'Use a number of days between 0 and 3650.']);
                }
            } elseif (is_array($value)) {
                if (count($value) > 50 || array_filter($value, static fn ($v) => !is_scalar($v) || (is_string($v) && mb_strlen($v) > 200)) !== []) {
                    throw ApiException::validation(['preferences.' . $key => 'Lists may hold up to 50 short values.']);
                }
            } elseif (!is_scalar($value) || (is_string($value) && mb_strlen($value) > 500)) {
                throw ApiException::validation(['preferences.' . $key => 'This value is not allowed.']);
            }
            $prefs[$key] = $value;
        }
        $public = array_filter($prefs, static fn ($k) => !str_starts_with((string) $k, '_'), ARRAY_FILTER_USE_KEY);
        if (count($public) > 60) {
            throw ApiException::validation(['preferences' => 'Too many preferences.']);
        }
        if ($prefs === []) {
            return null;
        }
        $json = (string) json_encode($prefs, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if (strlen($json) > 16384) {
            throw ApiException::validation(['preferences' => 'Preferences are too large.']);
        }
        return $json;
    }

    /** user.* events go to the user and (normally) the admin channel; payloads never hold secrets. */
    private static function publish(string $type, array $row, array $changes, bool $adminChannel = true): void
    {
        EventBus::publish($type, ['user' => self::eventRef($row), 'changes' => array_values($changes)], [(int) $row['id']], ['admin' => $adminChannel]);
    }
}
