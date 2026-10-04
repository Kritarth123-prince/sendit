<?php
declare(strict_types=1);

namespace FT\Collab;

use FT\Auth\Auth;
use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Events\EventBus;
use FT\Files\FileAccess;
use FT\Security\Policy;
use FT\Sharing\ShareService;
use FT\Storage\BlobStore;
use FT\Storage\QuotaService;

/**
 * In-browser text editor with presence — replaces the legacy collaborative notepad
 * (docs/ARCHITECTURE.md §9.4 "In-browser text editor & presence", §10.2 presence.updated).
 *
 * Concurrency is optimistic: the client sends the version it started from (base_version); if
 * the file moved on meanwhile the save is refused with 409 VERSION_CONFLICT {current_version}
 * (the legacy "version 0 always overwrites" loophole is gone). A save never overwrites bytes:
 * it stores a new blob and adds a version through FileWriter ("Edited in browser"), so every
 * edit can be restored from the version history.
 *
 * Presence: each open editor sends a heartbeat every ~10 s; entries older than 30 s are
 * dropped, and presence.updated is published only when the SET of people changes.
 */
final class EditorService
{
    public const MAX_BYTES = 2097152;
    public const EDITABLE_KINDS = ['text', 'code'];
    public const PRESENCE_TTL = 30;

    /** GET /files/{id}/text → {content, version, encoding, editable, …} */
    public static function read(array $user, int $fileId): array
    {
        $file = FileAccess::require($user, $fileId, 'preview');
        self::assertEditableKind($file);
        if ((int) $file['size'] > self::MAX_BYTES) {
            throw ApiException::tooLarge('Files larger than 2 MB cannot be opened in the browser editor. Download the file instead.');
        }
        $content = self::load($file);
        if (!mb_check_encoding($content, 'UTF-8')) {
            throw ApiException::validation(['content' => 'This file is not UTF-8 text, so it cannot be edited in the browser.'], 'This file is not UTF-8 text, so it cannot be edited in the browser.');
        }
        if (!in_array($file['access']['role'], ['owner', 'admin'], true)) {
            ShareService::markOpened((int) $user['id'], $file);
        }
        return [
            'file_id'    => (int) $file['id'],
            'name'       => (string) $file['name'],
            'content'    => $content,
            'version'    => (int) $file['version'],
            'size'       => (int) $file['size'],
            'sha256'     => (string) $file['sha256'],
            'encoding'   => 'utf-8',
            'editable'   => self::canEdit($user, $file),
            'updated_at' => Db::iso($file['updated_at']),
        ];
    }

    /**
     * PUT /files/{id}/text {content, base_version} → FileSummary, or 409 VERSION_CONFLICT.
     * Saving identical content is a no-op (no new version).
     */
    public static function save(array $user, int $fileId, mixed $content, mixed $baseVersion): array
    {
        $file = FileAccess::require($user, $fileId, 'edit');
        self::assertEditableKind($file);
        if ((int) $file['size'] > self::MAX_BYTES) {
            throw ApiException::tooLarge('Files larger than 2 MB cannot be edited in the browser.');
        }
        if (!self::canEdit($user, $file)) {
            throw ApiException::forbidden();
        }
        if (!is_string($content)) {
            throw ApiException::validation(['content' => 'The file content is missing.']);
        }
        if (!(is_int($baseVersion) || (is_string($baseVersion) && ctype_digit($baseVersion)))) {
            throw ApiException::validation(['base_version' => 'base_version (the version you started editing) is required.']);
        }
        $base = (int) $baseVersion;
        if (strlen($content) > self::MAX_BYTES) {
            throw ApiException::tooLarge('Files larger than 2 MB cannot be saved from the browser editor.');
        }
        if (!mb_check_encoding($content, 'UTF-8')) {
            throw ApiException::validation(['content' => 'The text contains invalid characters.']);
        }
        $writer = 'FT\\Files\\FileWriter';
        if (!class_exists($writer) || !method_exists($writer, 'addVersion')) {
            throw ApiException::unavailable('Saving from the browser editor is not available yet.');
        }

        // Fast path: refuse a stale save before storing anything.
        $cur = Db::one('SELECT * FROM files WHERE id = ?', [$fileId]);
        if ($cur === null || $cur['deleted_at'] !== null) {
            throw ApiException::fileNotFound();
        }
        if ((int) $cur['version'] !== $base) {
            throw self::conflict((int) $cur['version'], $base);
        }
        if (hash('sha256', $content) === (string) $cur['sha256']) {
            $result = ['file' => $cur, 'changed' => false];
        } else {
            $ownerId = (int) $cur['owner_id'];
            QuotaService::assertCanStore($ownerId, strlen($content));
            // The blob is stored OUTSIDE the transaction: BlobStore's dedup lock must not be held
            // open by an uncommitted row (A2 contract). FileWriter consumes the reference.
            $blob = BlobStore::putString($content, BlobStore::scopeFor($ownerId), (string) $cur['mime'], (string) $cur['name']);
            try {
                $result = Db::transaction(static function () use ($fileId, $base, $blob, $user, $writer): array {
                    // Row lock: the version check and the new version are one atomic step, so two
                    // editors saving from the same base can never both succeed.
                    $locked = Db::one('SELECT * FROM files WHERE id = ? FOR UPDATE', [$fileId]);
                    if ($locked === null || $locked['deleted_at'] !== null) {
                        throw ApiException::fileNotFound();
                    }
                    if ((int) $locked['version'] !== $base) {
                        throw self::conflict((int) $locked['version'], $base);
                    }
                    $new = $writer::addVersion($fileId, $blob, (int) $user['id'], 'Edited in browser');
                    return ['file' => is_array($new) && isset($new['owner_id']) ? $new : (Db::one('SELECT * FROM files WHERE id = ?', [$fileId]) ?? $locked), 'changed' => true];
                });
            } catch (\Throwable $e) {
                // Whatever failed, the transaction rolled back: no version references the blob
                // (any release FileWriter did inside it was rolled back too), so give it back.
                try {
                    BlobStore::release((int) $blob['id']);
                } catch (\Throwable) {
                    // maintenance reconciles ref_counts from file_versions
                }
                throw $e;
            }
        }

        $fresh = $result['file'];
        if ($result['changed']) {
            Audit::log('file.edit', [
                'user_id'     => (int) $user['id'],
                'target_type' => 'file',
                'target_id'   => $fileId,
                'owner_id'    => (int) $fresh['owner_id'],
                'detail'      => (string) $fresh['name'],
                'meta'        => ['version' => (int) $fresh['version'], 'base_version' => $base, 'size' => (int) $fresh['size']],
            ]);
        }
        $summary = ShareService::fileSummary($fresh, $user);
        $summary['changed'] = $result['changed'];
        return $summary;
    }

    /**
     * POST /files/{id}/presence — heartbeat (or {leave:true}). Returns the people currently in
     * the editor and publishes presence.updated to the file's audience when that set changed.
     */
    public static function heartbeat(array $user, int $fileId, ?string $clientId, bool $leave = false): array
    {
        FileAccess::require($user, $fileId, 'preview');
        $cid = $clientId !== null && preg_match('/^[A-Za-z0-9-]{1,64}$/', $clientId) ? $clientId : '';
        $uid = (int) $user['id'];
        $before = self::userIds($fileId, false);
        Db::run('DELETE FROM edit_presence WHERE file_id = :f AND last_seen_at < :cut', ['f' => $fileId, 'cut' => Db::ts(time() - self::PRESENCE_TTL)]);
        if ($leave) {
            Db::delete('edit_presence', ['file_id' => $fileId, 'user_id' => $uid, 'client_id' => $cid]);
        } else {
            Db::run(
                'INSERT INTO edit_presence (file_id, user_id, client_id, last_seen_at) VALUES (:f, :u, :c, :t)
                 ON DUPLICATE KEY UPDATE last_seen_at = VALUES(last_seen_at)',
                ['f' => $fileId, 'u' => $uid, 'c' => $cid, 't' => Db::now()]
            );
        }
        $after = self::userIds($fileId, true);
        $users = array_values(ShareService::userRefs($after));
        usort($users, static fn ($a, $b) => strcasecmp($a['display_name'], $b['display_name']));
        if ($before !== $after) {
            EventBus::publish('presence.updated', ['file_id' => $fileId, 'users' => $users], EventBus::fileAudience($fileId), ['file_id' => $fileId]);
        }
        return ['file_id' => $fileId, 'users' => $users, 'ttl' => self::PRESENCE_TTL];
    }

    /** People in the editor right now. @return array<int,array> UserRef */
    public static function present(int $fileId): array
    {
        return array_values(ShareService::userRefs(self::userIds($fileId, true)));
    }

    /** A6 maintenance (prune_presence): drop stale rows. */
    public static function prunePresence(int $limit = 1000): int
    {
        return Db::run('DELETE FROM edit_presence WHERE last_seen_at < :cut LIMIT ' . max(1, min(10000, $limit)), ['cut' => Db::ts(time() - self::PRESENCE_TTL)])->rowCount();
    }

    public static function canEdit(array $user, array $file): bool
    {
        $caps = $file['access'] ?? FileAccess::accessFor($user, $file);
        if ($caps === null || empty($caps['edit'])) {
            return false;
        }
        if (!in_array((string) $file['kind'], self::EDITABLE_KINDS, true) || (int) $file['size'] > self::MAX_BYTES) {
            return false;
        }
        // Owners still need the files.edit permission; share grants are already capped by policy.
        return $caps['role'] !== 'owner' || Policy::can($user, 'files.edit');
    }

    // ------------------------------------------------------------------ internals

    /** @return int[] sorted distinct user ids with a presence row ($fresh: seen in the last TTL) */
    private static function userIds(int $fileId, bool $fresh): array
    {
        $sql = 'SELECT DISTINCT user_id FROM edit_presence WHERE file_id = :f';
        $params = ['f' => $fileId];
        if ($fresh) {
            $sql .= ' AND last_seen_at >= :cut';
            $params['cut'] = Db::ts(time() - self::PRESENCE_TTL);
        }
        $ids = array_map('intval', Db::column($sql, $params));
        sort($ids);
        return $ids;
    }

    private static function conflict(int $current, int $base): ApiException
    {
        return ApiException::conflict(
            'Someone saved a newer version while you were editing. Reload to see their changes, or copy your text before reloading.',
            'VERSION_CONFLICT',
            ['current_version' => $current, 'base_version' => $base]
        );
    }

    private static function assertEditableKind(array $file): void
    {
        if (!in_array((string) $file['kind'], self::EDITABLE_KINDS, true)) {
            throw new ApiException('BAD_REQUEST', 'Only text and code files can be opened in the browser editor.', 415);
        }
    }

    private static function load(array $file): string
    {
        try {
            $blob = BlobStore::get((int) $file['blob_id']);
            return BlobStore::readAll($blob, self::MAX_BYTES);
        } catch (ApiException $e) {
            throw $e;
        } catch (\Throwable $e) {
            Logger::warning('app', 'Editor could not read file content', ['file_id' => (int) $file['id'], 'error' => $e->getMessage()]);
            throw new ApiException('FILE_UNAVAILABLE', 'The stored file is missing or damaged, so it cannot be opened.', 410);
        }
    }

    /** UserRef of the current user (for callers that need it without another query). */
    public static function ref(array $user): array
    {
        return Auth::ref($user) ?? ['id' => (int) $user['id'], 'username' => '', 'display_name' => ''];
    }
}
