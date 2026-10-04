<?php
declare(strict_types=1);

namespace FT\Security;

use FT\Core\ApiException;
use FT\Core\Db;

/**
 * Role → permission checks (roles / permissions / role_permissions tables).
 * File- and folder-level access is decided by FT\Files\FileAccess, not here.
 *
 * Only active, non-deleted users have permissions. The role is always derived from role_id
 * (the authoritative column), so a stale or forged 'role' key in an array cannot grant rights.
 */
final class Policy
{
    public const ROLES = ['admin' => 1, 'user' => 2, 'guest' => 3];

    /** @var array<int,array<int,string>> role_id => permission slugs */
    private static array $cache = [];

    public static function can(?array $user, string $permission): bool
    {
        if (!self::isActive($user)) {
            return false;
        }
        return in_array($permission, self::slugsForRole((int) ($user['role_id'] ?? 0)), true);
    }

    public static function requirePermission(?array $user, string $permission): void
    {
        if ($user === null) {
            throw ApiException::unauthorized();
        }
        if (!self::can($user, $permission)) {
            throw ApiException::forbidden();
        }
    }

    public static function isAdmin(?array $user): bool
    {
        if (!self::isActive($user)) {
            return false;
        }
        if (isset($user['role_id'])) {
            return (int) $user['role_id'] === self::ROLES['admin'];
        }
        return ($user['role'] ?? '') === 'admin';
    }

    public static function isGuest(?array $user): bool
    {
        return $user !== null && isset($user['role_id']) ? (int) $user['role_id'] === self::ROLES['guest'] : (($user['role'] ?? '') === 'guest');
    }

    public static function requireAdmin(?array $user): void
    {
        if ($user === null) {
            throw ApiException::unauthorized();
        }
        if (!self::isAdmin($user)) {
            throw ApiException::forbidden('Administrator access is required.');
        }
    }

    /** @return string[] */
    public static function permissionsFor(array $user): array
    {
        if (!self::isActive($user)) {
            return [];
        }
        return self::slugsForRole((int) ($user['role_id'] ?? 0));
    }

    public static function roleSlug(int $roleId): string
    {
        return match ($roleId) {
            1 => 'admin',
            3 => 'guest',
            default => 'user',
        };
    }

    public static function roleId(string $slug): int
    {
        return match ($slug) {
            'admin' => 1,
            'guest' => 3,
            'user' => 2,
            default => throw ApiException::validation(['role' => 'Role must be admin, user or guest.']),
        };
    }

    public static function reset(): void
    {
        self::$cache = [];
    }

    private static function isActive(?array $user): bool
    {
        return $user !== null
            && ($user['status'] ?? 'active') === 'active'
            && empty($user['deleted_at']);
    }

    /** @return string[] */
    private static function slugsForRole(int $roleId): array
    {
        if (!isset(self::$cache[$roleId])) {
            self::$cache[$roleId] = array_map('strval', Db::column(
                'SELECT p.slug FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = ? ORDER BY p.id',
                [$roleId]
            ));
        }
        return self::$cache[$roleId];
    }
}
