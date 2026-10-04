<?php
declare(strict_types=1);

namespace FT\Auth;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\RequestContext;
use FT\Core\Secrets;

/**
 * Personal API tokens: "ft_" + 40 random base62 characters (~238 bits).
 *
 * Only sha256(token) and a short display prefix are stored; the token itself is shown once.
 * Scopes: "*" (everything the user may do) or "read" (GET/HEAD only — enforced centrally in
 * Auth::resolve so no endpoint can forget it). last_used_at/ip are written at most once a
 * minute to keep token-authenticated polling cheap.
 */
final class ApiTokens
{
    public const PREFIX = 'ft_';
    public const SCOPES = ['*', 'read'];
    public const MAX_ACTIVE_PER_USER = 50;
    public const MAX_EXPIRY_DAYS = 3650;
    /** Expiry used when a Security Centre request names none (an explicit 0 there means "never"). */
    public const DEFAULT_EXPIRY_DAYS = 90;

    /** @return array{user_id:int, token_id:int, scopes:string}|null */
    public static function resolve(string $token): ?array
    {
        if (!self::looksValid($token)) {
            return null;
        }
        $row = Db::one(
            'SELECT t.id, t.user_id, t.scopes, t.expires_at, t.revoked_at, t.last_used_at FROM api_tokens t WHERE t.token_hash = ?',
            [hash('sha256', $token)]
        );
        if ($row === null || $row['revoked_at'] !== null) {
            return null;
        }
        if ($row['expires_at'] !== null && (string) $row['expires_at'] <= Db::now()) {
            return null;
        }
        $last = Db::toUnix($row['last_used_at'] !== null ? (string) $row['last_used_at'] : null) ?? 0;
        if (time() - $last >= 60) {
            try {
                Db::update('api_tokens', ['last_used_at' => Db::now(), 'last_used_ip' => RequestContext::ip()], ['id' => (int) $row['id']]);
            } catch (\Throwable $e) {
                Logger::warning('auth', 'Could not record API token use', ['error' => $e->getMessage()]);
            }
        }
        return [
            'user_id'  => (int) $row['user_id'],
            'token_id' => (int) $row['id'],
            'scopes'   => self::normaliseScopes((string) $row['scopes']),
        ];
    }

    public static function looksValid(string $token): bool
    {
        return (bool) preg_match('/^ft_[A-Za-z0-9]{40}$/', $token);
    }

    /**
     * Create a token. Returns ['token' => plain token (show once), 'row' => api_tokens row].
     * @param int|null $expiresInDays null = never expires
     */
    public static function create(int $userId, string $name, string $scopes = '*', ?int $expiresInDays = null, string $via = 'security_centre'): array
    {
        $name = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name));
        if ($name === '') {
            throw ApiException::validation(['name' => 'Give the token a name so you can recognise it later.']);
        }
        if (mb_strlen($name) > 100) {
            throw ApiException::validation(['name' => 'Use at most 100 characters.']);
        }
        if (!in_array($scopes, self::SCOPES, true)) {
            throw ApiException::validation(['scopes' => 'Scopes must be "*" (full access) or "read" (read-only).']);
        }
        if ($expiresInDays !== null && ($expiresInDays < 1 || $expiresInDays > self::MAX_EXPIRY_DAYS)) {
            throw ApiException::validation(['expires_in_days' => 'Choose between 1 and ' . self::MAX_EXPIRY_DAYS . ' days, or no expiry.']);
        }
        $active = (int) Db::value(
            'SELECT COUNT(*) FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)',
            [$userId, Db::now()]
        );
        if ($active >= self::MAX_ACTIVE_PER_USER) {
            throw ApiException::conflict('You have too many API tokens. Revoke some you no longer use first.');
        }
        $token = self::PREFIX . Secrets::token(40);
        $id = Db::insert('api_tokens', [
            'user_id'      => $userId,
            'name'         => $name,
            'token_prefix' => substr($token, 0, 10),
            'token_hash'   => hash('sha256', $token),
            'scopes'       => $scopes,
            'expires_at'   => $expiresInDays !== null ? Db::ts(time() + $expiresInDays * 86400) : null,
            'created_at'   => Db::now(),
        ]);
        $row = Db::one('SELECT * FROM api_tokens WHERE id = ?', [$id]) ?? [];
        Audit::log('auth.token_created', [
            'user_id' => $userId, // tokens are only ever created by their owner (also during sign-in)
            'target_type' => 'user', 'target_id' => $userId, 'owner_id' => $userId,
            'detail' => $name, 'meta' => ['token_prefix' => $row['token_prefix'] ?? '', 'scopes' => $scopes, 'via' => $via, 'id' => $id],
        ]);
        return ['token' => $token, 'row' => $row];
    }

    /** @return array<int,array<string,mixed>> the user's tokens (active first), as public shapes */
    public static function listFor(int $userId, bool $includeInactive = false): array
    {
        $sql = 'SELECT * FROM api_tokens WHERE user_id = ?';
        $params = [$userId];
        if (!$includeInactive) {
            $sql .= ' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)';
            $params[] = Db::now();
        }
        $sql .= ' ORDER BY created_at DESC, id DESC LIMIT 200';
        return array_map([self::class, 'shape'], Db::all($sql, $params));
    }

    /** Revoke one of the user's own tokens. Returns false when it does not exist / is not theirs. */
    public static function revoke(int $userId, int $tokenId, string $reason = 'user'): bool
    {
        $row = Db::one('SELECT id, name, token_prefix FROM api_tokens WHERE id = ? AND user_id = ? AND revoked_at IS NULL', [$tokenId, $userId]);
        if ($row === null) {
            return false;
        }
        Db::update('api_tokens', ['revoked_at' => Db::now()], ['id' => $tokenId]);
        Audit::log('auth.token_revoked', [
            'user_id' => $userId,
            'target_type' => 'user', 'target_id' => $userId, 'owner_id' => $userId,
            'detail' => (string) $row['name'], 'meta' => ['token_prefix' => (string) $row['token_prefix'], 'reason' => $reason, 'id' => $tokenId],
        ]);
        return true;
    }

    /**
     * Revoke every active (not revoked, not expired) API token of a user. Used whenever an
     * account is secured again — password change or reset, administrator reset or forced
     * sign-out, "sign out everywhere" in the Security Centre — so a leaked token cannot outlive it.
     *
     * $exceptTokenId keeps the token that authenticated the current request (e.g. a password
     * change made through the API), so the caller is not cut off half-way.
     * Returns the number of tokens revoked.
     */
    public static function revokeAllFor(int $userId, string $reason = 'revoked_all', ?int $exceptTokenId = null): int
    {
        $now = Db::now();
        $sql = 'UPDATE api_tokens SET revoked_at = :t
                WHERE user_id = :u AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > :now)';
        $params = ['t' => $now, 'u' => $userId, 'now' => $now];
        if ($exceptTokenId !== null && $exceptTokenId > 0) {
            $sql .= ' AND id <> :keep';
            $params['keep'] = $exceptTokenId;
        }
        $n = Db::run($sql, $params)->rowCount();
        if ($n > 0) {
            Audit::log('auth.token_revoked', ['target_type' => 'user', 'target_id' => $userId, 'owner_id' => $userId, 'meta' => [
                'count' => $n, 'reason' => mb_substr($reason, 0, 64), 'kept_id' => $exceptTokenId,
            ]]);
        }
        return $n;
    }

    /** Public JSON shape (never the hash). */
    public static function shape(array $row): array
    {
        $expired = $row['expires_at'] !== null && (string) $row['expires_at'] <= Db::now();
        return [
            'id'           => (int) $row['id'],
            'name'         => (string) $row['name'],
            'token_prefix' => (string) $row['token_prefix'],
            'scopes'       => self::normaliseScopes((string) $row['scopes']),
            'last_used_at' => Db::iso($row['last_used_at'] ?? null),
            'last_used_ip' => $row['last_used_ip'] ?? null,
            'expires_at'   => Db::iso($row['expires_at'] ?? null),
            'created_at'   => Db::iso($row['created_at'] ?? null),
            'revoked_at'   => Db::iso($row['revoked_at'] ?? null),
            'status'       => $row['revoked_at'] !== null ? 'revoked' : ($expired ? 'expired' : 'active'),
        ];
    }

    /** Only an explicit "*" grants full access; anything else (unknown/legacy scope lists) is read-only (fail safe). */
    public static function normaliseScopes(string $scopes): string
    {
        return trim($scopes) === '*' ? '*' : 'read';
    }
}
