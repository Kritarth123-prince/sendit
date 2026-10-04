<?php
declare(strict_types=1);

namespace FT\Files;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\RequestContext;
use FT\Core\Settings;
use FT\Core\Stats;
use FT\Events\EventBus;
use FT\Jobs\Queue;
use FT\Storage\BlobStore;
use FT\Storage\MimeDetector;
use FT\Storage\QuotaService;
use FT\Storage\Thumbnailer;

/**
 * THE write path for file content (docs/ARCHITECTURE.md §8.3). Uploads, the in-browser editor,
 * public-share uploads, version restores and the legacy importer all create files and versions
 * through this class, so the invariants live in one place:
 *
 *   - every version, including the current one, has a file_versions row; files.blob_id / version /
 *     size / sha256 / mime mirror the current version;
 *   - file_blobs.ref_count = number of file_versions rows referencing the blob;
 *   - users.used_bytes moves with every version row added or removed (QuotaService::adjust);
 *   - file.created / version.created / version.restored / file.updated events go to the file's
 *     authorised audience, audit rows and daily stats are written, background jobs (thumbnail,
 *     OCR, content index) and Slack are queued.
 *
 * BLOB REFERENCES: the row returned by BlobStore::put*() is already retained (+1) for the version
 * about to be created. FileWriter CONSUMES that reference: on success it belongs to the new
 * file_versions row; on failure FileWriter releases it. Callers must not release it themselves.
 *
 * Authorisation is the caller's job (FileAccess); FileWriter only re-checks structural facts
 * (the folder exists, is live and belongs to the owner; the file is not in the Trash).
 */
final class FileWriter
{
    public const MAX_NAME_BYTES = 255;
    public const MAX_TAGS = 30;
    public const MAX_TAG_CHARS = 64;

    /** Multi-part extensions kept together when de-duplicating names ("a (1).tar.gz"). */
    private const DOUBLE_EXT = ['tar.gz', 'tar.bz2', 'tar.xz', 'tar.zst', 'tar.lz'];

    /** Kinds queued for OCR (A6) and for plain-text content indexing (A6). */
    private const OCR_KINDS = ['image', 'pdf'];
    private const INDEX_KINDS = ['text', 'code', 'document', 'spreadsheet', 'presentation', 'pdf'];

    // ================================================================== create

    /**
     * Create a new file (version 1) from a retained blob.
     *
     * $o: created_by, tags[] (or comma list), is_permanent (bool), expires_at ('Y-m-d H:i:s' UTC),
     *     description, on_conflict ('rename'|'replace'|'error'), note, legacy_name, is_bundle,
     *     created_at (import), mime / kind overrides, silent (no events/notifications/Slack/stats;
     *     importer), auto_tags (bool, default true), queue_jobs (bool, default true).
     * @return array the files row
     */
    public static function createFile(int $ownerId, ?int $folderId, string $name, array $blob, array $o = []): array
    {
        $blobId = self::blobId($blob);
        $folderId = ($folderId !== null && $folderId > 0) ? $folderId : null;
        $onConflict = (string) ($o['on_conflict'] ?? 'rename');
        if (!in_array($onConflict, ['rename', 'replace', 'error'], true)) {
            $onConflict = 'rename';
        }
        $actorId = isset($o['created_by']) ? (int) $o['created_by'] : (RequestContext::userId() ?? $ownerId);
        $silent = !empty($o['silent']);
        $handedOver = false;
        $lock = null;

        try {
            $name = self::sanitizeName($name);
            if (Db::value('SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL', [$ownerId]) === null) {
                throw ApiException::notFound('user', 'USER_NOT_FOUND');
            }
            if ($folderId !== null) {
                $folder = Db::one('SELECT id, owner_id, deleted_at FROM folders WHERE id = ?', [$folderId]);
                if ($folder === null || $folder['deleted_at'] !== null || (int) $folder['owner_id'] !== $ownerId) {
                    throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
                }
            }

            // Serialise name selection + insert per (owner, folder) so two parallel uploads of
            // "photo.jpg" become "photo.jpg" and "photo (1).jpg" rather than two equal names.
            $lock = self::lockName($ownerId, $folderId);
            if ((int) Db::value('SELECT GET_LOCK(?, 10)', [$lock]) !== 1) {
                $lock = null; // proceed without the lock rather than fail the upload
            }

            $existing = self::findByName($ownerId, $folderId, $name);
            if ($existing !== null) {
                if ($onConflict === 'error') {
                    throw ApiException::conflict('A file called “' . $name . '” already exists here.', 'NAME_CONFLICT', ['file_id' => (int) $existing['id']]);
                }
                if ($onConflict === 'replace') {
                    self::unlock($lock);
                    $lock = null;
                    $handedOver = true; // addVersion() now owns (and on failure releases) the reference
                    return self::addVersion((int) $existing['id'], $blob, $actorId, (string) ($o['note'] ?? ''), $o);
                }
                $name = self::uniqueName($ownerId, $folderId, $name);
            }

            $ext = MimeDetector::extension($name);
            $mime = isset($o['mime']) && is_string($o['mime']) && $o['mime'] !== '' ? mb_substr($o['mime'], 0, 127) : self::mimeFor($blob, $ext);
            $kind = isset($o['kind']) && in_array($o['kind'], MimeDetector::KINDS, true) ? (string) $o['kind'] : MimeDetector::kindFor($ext, $mime);
            $createdAt = self::validDateTime($o['created_at'] ?? null) ?? Db::now();
            [$permanent, $expiresAt] = self::expiry($o, $createdAt);
            $tags = self::normaliseTags($o['tags'] ?? []);
            if (($o['auto_tags'] ?? true) !== false) {
                $tags = self::mergeTags($tags, self::autoTags($ext));
            }
            $description = isset($o['description']) && is_string($o['description']) && trim($o['description']) !== ''
                ? mb_substr(trim($o['description']), 0, 1000) : null;

            $fileId = Db::transaction(static function () use ($ownerId, $folderId, $name, $ext, $mime, $kind, $blob, $blobId, $actorId, $createdAt, $permanent, $expiresAt, $description, $o, $tags): int {
                $size = (int) $blob['size'];
                $id = Db::insert('files', [
                    'owner_id'       => $ownerId,
                    'folder_id'      => $folderId,
                    'name'           => $name,
                    'ext'            => mb_substr($ext, 0, 32),
                    'mime'           => $mime,
                    'kind'           => $kind,
                    'size'           => $size,
                    'blob_id'        => $blobId,
                    'sha256'         => (string) $blob['sha256'],
                    'version'        => 1,
                    'description'    => $description,
                    'is_permanent'   => $permanent ? 1 : 0,
                    'expires_at'     => $expiresAt,
                    'download_count' => 0,
                    'thumb_version'  => null,
                    'is_bundle'      => !empty($o['is_bundle']) ? 1 : 0,
                    'created_by'     => $actorId,
                    'updated_by'     => $actorId,
                    'created_at'     => $createdAt,
                    'updated_at'     => $createdAt,
                    'legacy_name'    => isset($o['legacy_name']) && is_string($o['legacy_name']) ? mb_substr($o['legacy_name'], 0, 255) : null,
                ]);
                Db::insert('file_versions', [
                    'file_id'    => $id,
                    'version'    => 1,
                    'blob_id'    => $blobId,
                    'size'       => $size,
                    'sha256'     => (string) $blob['sha256'],
                    'name'       => $name,
                    'mime'       => $mime,
                    'created_by' => $actorId,
                    'created_at' => $createdAt,
                    'note'       => isset($o['note']) && is_string($o['note']) && $o['note'] !== '' ? mb_substr($o['note'], 0, 255) : null,
                ]);
                self::writeTags($id, $ownerId, $tags);
                return $id;
            });
            $handedOver = true;
        } catch (\Throwable $e) {
            if (!$handedOver) {
                self::safeRelease($blobId);
            }
            throw $e;
        } finally {
            self::unlock($lock);
        }

        $file = self::load($fileId);
        $size = (int) $file['size'];
        QuotaService::adjust($ownerId, $size);

        Audit::log('file.upload', [
            'user_id'     => $actorId,
            'target_type' => 'file',
            'target_id'   => $fileId,
            'owner_id'    => $ownerId,
            'detail'      => $file['name'],
            'meta'        => ['name' => $file['name'], 'size' => $size, 'version' => 1, 'folder_id' => $folderId, 'mime' => $file['mime']],
        ]);

        if (!$silent) {
            Stats::bump('uploads');
            Stats::bump('upload_bytes', $size);
            EventBus::publish('file.created', ['file' => self::summary($file, null, true)], EventBus::fileAudience($fileId), [
                'actor_id' => $actorId, 'file_id' => $fileId, 'folder_id' => $folderId, 'admin' => true,
            ]);
            self::slack('upload', [
                'Name'   => $file['name'],
                'By'     => self::displayName($actorId),
                'Time'   => self::timeLabel(),
                'Size'   => self::humanBytes($size),
                'Folder' => $folderId !== null ? (string) Db::value('SELECT name FROM folders WHERE id = ?', [$folderId]) : null,
            ]);
        }
        if (($o['queue_jobs'] ?? true) !== false) {
            self::queueJobs($file);
        }
        return $file;
    }

    // ================================================================== versions

    /**
     * Make $blob the new current version of $fileId (version = highest + 1).
     * $o (optional): silent, queue_jobs, notify (bool, default true).
     * @return array the updated files row
     */
    public static function addVersion(int $fileId, array $blob, int $userId, string $note = '', array $o = []): array
    {
        $blobId = self::blobId($blob);
        try {
            [$file, $version] = Db::transaction(static function () use ($fileId, $blob, $blobId, $userId, $note): array {
                $file = Db::one('SELECT * FROM files WHERE id = ? FOR UPDATE', [$fileId]);
                if ($file === null || $file['deleted_at'] !== null) {
                    throw ApiException::fileNotFound();
                }
                $next = self::nextVersion($file);
                $ext = (string) $file['ext'];
                $mime = self::mimeFor($blob, $ext);
                $now = Db::now();
                Db::insert('file_versions', [
                    'file_id'    => $fileId,
                    'version'    => $next,
                    'blob_id'    => $blobId,
                    'size'       => (int) $blob['size'],
                    'sha256'     => (string) $blob['sha256'],
                    'name'       => (string) $file['name'],
                    'mime'       => $mime,
                    'created_by' => $userId > 0 ? $userId : null,
                    'created_at' => $now,
                    'note'       => $note !== '' ? mb_substr($note, 0, 255) : null,
                ]);
                Db::update('files', [
                    'blob_id'       => $blobId,
                    'sha256'        => (string) $blob['sha256'],
                    'size'          => (int) $blob['size'],
                    'version'       => $next,
                    'mime'          => $mime,
                    'kind'          => MimeDetector::kindFor($ext, $mime),
                    'thumb_version' => null, // the old thumbnail shows old content
                    'updated_by'    => $userId > 0 ? $userId : null,
                    'updated_at'    => $now,
                ], ['id' => $fileId]);
                return [Db::one('SELECT * FROM files WHERE id = ?', [$fileId]), $next];
            });
        } catch (\Throwable $e) {
            self::safeRelease($blobId);
            throw $e;
        }

        $ownerId = (int) $file['owner_id'];
        QuotaService::adjust($ownerId, (int) $file['size']);
        self::pruneVersions($fileId, false);
        $file = self::load($fileId);

        Audit::log('file.version_upload', [
            'user_id'     => $userId > 0 ? $userId : null,
            'target_type' => 'file',
            'target_id'   => $fileId,
            'owner_id'    => $ownerId,
            'detail'      => $file['name'],
            'meta'        => ['version' => $version, 'size' => (int) $file['size'], 'note' => $note !== '' ? mb_substr($note, 0, 255) : null],
        ]);
        if (empty($o['silent'])) {
            Stats::bump('uploads');
            Stats::bump('upload_bytes', (int) $file['size']);
            self::publishVersion('version.created', $file, $version, $userId, null);
            if (($o['notify'] ?? true) !== false) {
                self::notifyVersion($file, $version, $userId, null);
            }
            self::slack('upload', [
                'Name'    => $file['name'],
                'By'      => self::displayName($userId),
                'Time'    => self::timeLabel(),
                'Size'    => self::humanBytes((int) $file['size']),
                'Version' => (string) $version,
            ]);
        }
        if (($o['queue_jobs'] ?? true) !== false) {
            self::queueJobs($file);
        }
        return $file;
    }

    /**
     * Restore version N non-destructively: creates version M+1 pointing to N's blob.
     * @return array the updated files row
     */
    public static function restoreVersion(int $fileId, int $version, int $userId): array
    {
        [$file, $newVersion] = Db::transaction(static function () use ($fileId, $version, $userId): array {
            $file = Db::one('SELECT * FROM files WHERE id = ? FOR UPDATE', [$fileId]);
            if ($file === null || $file['deleted_at'] !== null) {
                throw ApiException::fileNotFound();
            }
            $old = Db::one('SELECT * FROM file_versions WHERE file_id = ? AND version = ?', [$fileId, $version]);
            if ($old === null) {
                throw ApiException::notFound('version', 'NOT_FOUND');
            }
            if ((int) $file['version'] === $version) {
                throw ApiException::conflict('Version ' . $version . ' is already the current version.');
            }
            BlobStore::retain((int) $old['blob_id']);
            $next = self::nextVersion($file);
            $ext = (string) $file['ext'];
            $mime = MimeDetector::resolve((string) $old['mime'], $ext);
            $now = Db::now();
            Db::insert('file_versions', [
                'file_id'    => $fileId,
                'version'    => $next,
                'blob_id'    => (int) $old['blob_id'],
                'size'       => (int) $old['size'],
                'sha256'     => (string) $old['sha256'],
                'name'       => (string) $file['name'],
                'mime'       => $mime,
                'created_by' => $userId > 0 ? $userId : null,
                'created_at' => $now,
                'note'       => 'Restored from version ' . $version,
            ]);
            Db::update('files', [
                'blob_id'       => (int) $old['blob_id'],
                'sha256'        => (string) $old['sha256'],
                'size'          => (int) $old['size'],
                'version'       => $next,
                'mime'          => $mime,
                'kind'          => MimeDetector::kindFor($ext, $mime),
                'thumb_version' => null,
                'updated_by'    => $userId > 0 ? $userId : null,
                'updated_at'    => $now,
            ], ['id' => $fileId]);
            return [Db::one('SELECT * FROM files WHERE id = ?', [$fileId]), $next];
        });

        $ownerId = (int) $file['owner_id'];
        QuotaService::adjust($ownerId, (int) $file['size']);
        self::pruneVersions($fileId, false);
        $file = self::load($fileId);

        Audit::log('file.version_restore', [
            'user_id'     => $userId > 0 ? $userId : null,
            'target_type' => 'file',
            'target_id'   => $fileId,
            'owner_id'    => $ownerId,
            'detail'      => $file['name'],
            'meta'        => ['version' => $version, 'new_version' => $newVersion],
        ]);
        self::publishVersion('version.restored', $file, $newVersion, $userId, $version);
        self::notifyVersion($file, $newVersion, $userId, $version);
        self::slack('version_restore', [
            'Name'    => $file['name'],
            'By'      => self::displayName($userId),
            'Time'    => self::timeLabel(),
            'Version' => (string) $version,
        ]);
        self::queueJobs($file);
        return $file;
    }

    /**
     * Enforce version_retention_count (versions kept in total, current included; 0 = no limit)
     * and version_retention_days (0 = no age limit). The current version is never removed.
     * Released blobs are deleted later by BlobStore::sweep(). Returns the number pruned.
     */
    public static function pruneVersions(int $fileId, bool $publish = true): int
    {
        $count = Settings::int('version_retention_count', 5);
        $days = Settings::int('version_retention_days', 0);
        if ($count <= 0 && $days <= 0) {
            return 0;
        }
        $result = Db::transaction(static function () use ($fileId, $count, $days): ?array {
            $file = Db::one('SELECT id, owner_id, version FROM files WHERE id = ? FOR UPDATE', [$fileId]);
            if ($file === null) {
                return null;
            }
            $current = (int) $file['version'];
            $rows = Db::all('SELECT id, version, blob_id, size, created_at FROM file_versions WHERE file_id = ? ORDER BY version DESC', [$fileId]);
            $cutoff = $days > 0 ? Db::ts(time() - $days * 86400) : null;
            $kept = 1; // the current version
            $prune = [];
            foreach ($rows as $row) {
                if ((int) $row['version'] === $current) {
                    continue;
                }
                $tooMany = $count > 0 && $kept >= $count;
                $tooOld = $cutoff !== null && (string) $row['created_at'] < $cutoff;
                if ($tooMany || $tooOld) {
                    $prune[] = $row;
                } else {
                    $kept++;
                }
            }
            $bytes = 0;
            foreach ($prune as $row) {
                Db::delete('file_versions', ['id' => (int) $row['id']]);
                BlobStore::release((int) $row['blob_id']);
                $bytes += (int) $row['size'];
            }
            return ['owner_id' => (int) $file['owner_id'], 'pruned' => count($prune), 'bytes' => $bytes];
        });
        if ($result === null || $result['pruned'] === 0) {
            return 0;
        }
        QuotaService::adjust($result['owner_id'], -$result['bytes']);
        if ($publish) {
            $file = Db::one('SELECT * FROM files WHERE id = ?', [$fileId]);
            if ($file !== null) {
                EventBus::publish('file.updated', ['file' => self::summary($file, null, true), 'changes' => ['versions']], EventBus::fileAudience($fileId), [
                    'actor_id' => null, 'file_id' => $fileId, 'folder_id' => $file['folder_id'] !== null ? (int) $file['folder_id'] : null,
                ]);
            }
        }
        return $result['pruned'];
    }

    // ================================================================== names

    /** A name not used by another live file in (owner, folder): "name.ext", "name (1).ext", … */
    public static function uniqueName(int $ownerId, ?int $folderId, string $name, ?int $exceptFileId = null): string
    {
        $name = self::sanitizeName($name);
        $folderId = ($folderId !== null && $folderId > 0) ? $folderId : null;
        [$base, $ext] = self::splitName($name);
        $rows = Db::column(
            'SELECT name FROM files WHERE owner_id = :o AND folder_id <=> :f AND deleted_at IS NULL AND id <> :x
               AND (name = :n OR name LIKE :p)',
            [
                'o' => $ownerId,
                'f' => $folderId,
                'x' => $exceptFileId ?? 0,
                'n' => $name,
                'p' => Db::like(self::fitName($base, '', '')) . '%',
            ]
        );
        $taken = [];
        foreach ($rows as $r) {
            $taken[mb_strtolower((string) $r)] = true;
        }
        if (!isset($taken[mb_strtolower($name)])) {
            return $name;
        }
        for ($i = 1; $i <= 10000; $i++) {
            $candidate = self::fitName($base, ' (' . $i . ')', $ext);
            if (!isset($taken[mb_strtolower($candidate)])) {
                return $candidate;
            }
        }
        return self::fitName($base, ' (' . bin2hex(random_bytes(3)) . ')', $ext);
    }

    /**
     * Safe display/storage name: strips control and bidirectional-override characters and
     * / \ : * ? " < > |, trims surrounding spaces and trailing dots, caps at 255 bytes (keeping
     * the extension) and never returns an empty string. Names are never used as disk paths.
     */
    public static function sanitizeName(string $name): string
    {
        if (!mb_check_encoding($name, 'UTF-8')) {
            $name = (string) mb_convert_encoding($name, 'UTF-8', 'UTF-8');
        }
        $name = (string) preg_replace('/[\x00-\x1F\x7F]/u', '', $name);
        // Bidi controls let "photo<RLO>gpj.exe" display as "photoexe.jpg".
        $name = (string) preg_replace('/[\x{200E}\x{200F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{FEFF}]/u', '', $name);
        $name = str_replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], '', $name);
        $name = (string) preg_replace('/\s+/u', ' ', $name);
        // Leading runs of dots ("../" residue) go; a single leading dot (".env") is a real name.
        $name = (string) preg_replace('/^[\s.]*\.{2,}/u', '', $name);
        $name = rtrim(trim($name), '. ');
        if ($name === '' || trim($name, '.') === '') {
            return 'file';
        }
        if (strlen($name) > self::MAX_NAME_BYTES) {
            [$base, $ext] = self::splitName($name);
            $name = self::fitName($base, '', $ext);
        }
        return $name;
    }

    // ================================================================== summaries

    /**
     * FileSummary (§9.2). Uses A3's FileRepository::summary() when available; otherwise builds
     * the same keys itself. $forEvent strips the per-viewer keys (access, favorite).
     */
    public static function summary(array $file, ?array $viewer = null, bool $forEvent = false): array
    {
        $repo = 'FT\\Files\\FileRepository';
        if (class_exists($repo) && method_exists($repo, 'summary')) {
            try {
                $s = $forEvent ? $repo::summary($file, null, ['event' => true]) : $repo::summary($file, $viewer);
                if (is_array($s)) {
                    if ($forEvent) {
                        unset($s['access'], $s['favorite']);
                    }
                    return $s;
                }
            } catch (\Throwable $e) {
                Logger::warning('app', 'FileRepository::summary failed; using the minimal summary', ['error' => $e->getMessage()]);
            }
        }
        $id = (int) $file['id'];
        $owner = Db::one('SELECT id, username, display_name FROM users WHERE id = ?', [(int) $file['owner_id']]);
        $tags = array_map('strval', Db::column(
            'SELECT t.name FROM file_tags ft JOIN tags t ON t.id = ft.tag_id WHERE ft.file_id = ? ORDER BY t.name',
            [$id]
        ));
        $encoding = Db::value('SELECT encryption FROM file_blobs WHERE id = ?', [(int) $file['blob_id']]);
        $s = [
            'id'             => $id,
            'type'           => 'file',
            'name'           => (string) $file['name'],
            'ext'            => (string) $file['ext'],
            'mime'           => (string) $file['mime'],
            'kind'           => (string) $file['kind'],
            'size'           => (int) $file['size'],
            'folder_id'      => $file['folder_id'] !== null ? (int) $file['folder_id'] : null,
            'owner'          => $owner !== null ? [
                'id' => (int) $owner['id'],
                'username' => (string) $owner['username'],
                'display_name' => (string) (($owner['display_name'] ?? '') !== '' ? $owner['display_name'] : $owner['username']),
            ] : null,
            'created_at'     => Db::iso((string) $file['created_at']),
            'updated_at'     => Db::iso((string) $file['updated_at']),
            'version'        => (int) $file['version'],
            'favorite'       => false,
            'tags'           => $tags,
            'is_permanent'   => (int) $file['is_permanent'] === 1,
            'expires_at'     => Db::iso($file['expires_at'] ?? null),
            'download_count' => (int) $file['download_count'],
            'comment_count'  => (int) Db::value('SELECT COUNT(*) FROM comments WHERE file_id = ? AND deleted_at IS NULL', [$id]),
            'is_shared'      => Db::value(
                'SELECT 1 FROM shares WHERE revoked_at IS NULL AND (expires_at IS NULL OR expires_at > :now)
                   AND (file_id = :f OR id IN (SELECT share_id FROM share_items WHERE file_id = :f2)) LIMIT 1',
                ['now' => Db::now(), 'f' => $id, 'f2' => $id]
            ) !== null,
            'has_thumbnail'  => $file['thumb_version'] !== null,
            'encrypted'      => $encoding !== null && $encoding !== 'none',
            'is_bundle'      => (int) $file['is_bundle'] === 1,
            'description'    => $file['description'] ?? null,
            'access'         => null,
            'trash'          => null,
        ];
        if ($viewer !== null) {
            $s['favorite'] = Db::value('SELECT 1 FROM favorites WHERE user_id = ? AND file_id = ?', [(int) $viewer['id'], $id]) !== null;
            $s['access'] = FileAccess::accessFor($viewer, $file);
        }
        if ($forEvent) {
            unset($s['access'], $s['favorite']);
        }
        return $s;
    }

    // ================================================================== tags

    /** Lower-case, [letters digits - _] only, ≤ 64 chars, unique, ≤ 30 tags. @return string[] */
    public static function normaliseTags(mixed $tags): array
    {
        if (is_string($tags)) {
            $tags = explode(',', $tags);
        }
        if (!is_array($tags)) {
            return [];
        }
        $out = [];
        foreach ($tags as $t) {
            if (!is_string($t) && !is_int($t)) {
                continue;
            }
            $t = mb_strtolower(trim((string) $t));
            $t = (string) preg_replace('/\s+/u', '-', $t);
            $t = (string) preg_replace('/[^\p{L}\p{N}_-]/u', '', $t);
            $t = mb_substr($t, 0, self::MAX_TAG_CHARS);
            if ($t !== '' && !in_array($t, $out, true)) {
                $out[] = $t;
            }
            if (count($out) >= self::MAX_TAGS) {
                break;
            }
        }
        return $out;
    }

    // ================================================================== internals

    private static function blobId(array $blob): int
    {
        $id = (int) ($blob['id'] ?? 0);
        if ($id <= 0 || !isset($blob['sha256'], $blob['size'])) {
            throw new \InvalidArgumentException('A stored blob row is required');
        }
        return $id;
    }

    private static function safeRelease(int $blobId): void
    {
        try {
            BlobStore::release($blobId);
        } catch (\Throwable $e) {
            Logger::warning('upload', 'Could not release a blob reference after a failed write', ['blob_id' => $blobId, 'error' => $e->getMessage()]);
        }
    }

    private static function load(int $fileId): array
    {
        $row = Db::one('SELECT * FROM files WHERE id = ?', [$fileId]);
        if ($row === null) {
            throw ApiException::fileNotFound();
        }
        return $row;
    }

    private static function nextVersion(array $file): int
    {
        $max = (int) (Db::value('SELECT COALESCE(MAX(version), 0) FROM file_versions WHERE file_id = ?', [(int) $file['id']]) ?? 0);
        return max($max, (int) $file['version']) + 1;
    }

    /** files.mime for a blob under a given name: content first, refined by the extension. */
    private static function mimeFor(array $blob, string $ext): string
    {
        return mb_substr(MimeDetector::resolve((string) ($blob['mime'] ?? ''), $ext), 0, 127);
    }

    /** @return array{0:bool,1:?string} [is_permanent, expires_at] */
    private static function expiry(array $o, string $base): array
    {
        if (array_key_exists('is_permanent', $o) && filter_var($o['is_permanent'], FILTER_VALIDATE_BOOLEAN)) {
            return [true, null];
        }
        $explicit = self::validDateTime($o['expires_at'] ?? null);
        if ($explicit !== null) {
            return [false, $explicit];
        }
        $hours = Settings::int('auto_expire_hours', 72);
        $baseTs = Db::toUnix($base) ?? time();
        return [false, $hours > 0 ? Db::ts($baseTs + $hours * 3600) : null];
    }

    private static function validDateTime(mixed $v): ?string
    {
        if (!is_string($v) || !preg_match('/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}/', $v)) {
            return null;
        }
        $ts = strtotime(str_replace('T', ' ', substr($v, 0, 19)) . ' UTC');
        return $ts === false ? null : Db::ts($ts);
    }

    private static function findByName(int $ownerId, ?int $folderId, string $name): ?array
    {
        return Db::one(
            'SELECT id, name FROM files WHERE owner_id = :o AND folder_id <=> :f AND deleted_at IS NULL AND name = :n LIMIT 1',
            ['o' => $ownerId, 'f' => $folderId, 'n' => $name]
        );
    }

    private static function lockName(int $ownerId, ?int $folderId): string
    {
        return 'ftn_' . $ownerId . '_' . ($folderId ?? 0);
    }

    private static function unlock(?string $lock): void
    {
        if ($lock !== null) {
            try {
                Db::value('SELECT RELEASE_LOCK(?)', [$lock]);
            } catch (\Throwable) {
                // the lock dies with the connection anyway
            }
        }
    }

    /** @return array{0:string,1:string} [base, extension including the dot or ''] */
    private static function splitName(string $name): array
    {
        $lower = mb_strtolower($name);
        foreach (self::DOUBLE_EXT as $de) {
            if (str_ends_with($lower, '.' . $de) && strlen($name) > strlen($de) + 1) {
                return [substr($name, 0, -(strlen($de) + 1)), substr($name, -(strlen($de) + 1))];
            }
        }
        $ext = MimeDetector::extension($name);
        if ($ext === '' || strlen($name) <= strlen($ext) + 1) {
            return [$name, ''];
        }
        return [substr($name, 0, -(strlen($ext) + 1)), substr($name, -(strlen($ext) + 1))];
    }

    /** base + suffix + ext within MAX_NAME_BYTES (UTF-8 safe: trims whole characters of base). */
    private static function fitName(string $base, string $suffix, string $ext): string
    {
        if (strlen($ext) > 40) {
            $ext = '';
        }
        $room = self::MAX_NAME_BYTES - strlen($suffix) - strlen($ext);
        if (strlen($base) > $room) {
            $base = mb_strcut($base, 0, max(1, $room), 'UTF-8');
            $base = rtrim($base, '. ');
            if ($base === '') {
                $base = 'file';
            }
        }
        return $base . $suffix . $ext;
    }

    /** Auto tags (legacy extension rules, plus A3's TagService rules when it exists). @return string[] */
    private static function autoTags(string $ext): array
    {
        $tags = MimeDetector::legacyTags($ext);
        $svc = 'FT\\Files\\TagService';
        if (class_exists($svc) && method_exists($svc, 'autoTagsFor')) {
            try {
                $more = $svc::autoTagsFor($ext);
                if (is_array($more)) {
                    $tags = self::mergeTags($tags, self::normaliseTags($more));
                }
            } catch (\Throwable) {
                // signature mismatch or failure: the legacy rules still apply
            }
        }
        return $tags;
    }

    /** @return string[] */
    private static function mergeTags(array $a, array $b): array
    {
        return array_slice(array_values(array_unique(array_merge($a, $b))), 0, self::MAX_TAGS);
    }

    /** Attach tags to a new file (inside the creating transaction). */
    private static function writeTags(int $fileId, int $ownerId, array $tags): void
    {
        if ($tags === []) {
            return;
        }
        $svc = 'FT\\Files\\TagService';
        if (class_exists($svc) && method_exists($svc, 'setTags')) {
            try {
                $svc::setTags($fileId, $ownerId, $tags); // A3: setTags(int $fileId, int $ownerId, array $names)
                return;
            } catch (\Throwable $e) {
                // Different signature or a failure: the rows below are idempotent (INSERT IGNORE).
                Logger::debug('upload', 'TagService::setTags unavailable, writing tags directly', ['error' => $e->getMessage()]);
            }
        }
        $now = Db::now();
        foreach ($tags as $t) {
            Db::run('INSERT IGNORE INTO tags (owner_id, name, created_at) VALUES (?, ?, ?)', [$ownerId, $t, $now]);
            $tagId = Db::value('SELECT id FROM tags WHERE owner_id = ? AND name = ?', [$ownerId, $t]);
            if ($tagId !== null) {
                Db::run('INSERT IGNORE INTO file_tags (file_id, tag_id, created_at) VALUES (?, ?, ?)', [$fileId, (int) $tagId, $now]);
            }
        }
    }

    private static function publishVersion(string $type, array $file, int $version, int $actorId, ?int $restoredFrom): void
    {
        $fileId = (int) $file['id'];
        $summary = self::summary($file, null, true);
        $v = Db::one('SELECT * FROM file_versions WHERE file_id = ? AND version = ?', [$fileId, $version]);
        $info = $v === null ? null : [
            'version'    => (int) $v['version'],
            'size'       => (int) $v['size'],
            'sha256'     => (string) $v['sha256'],
            'name'       => (string) $v['name'],
            'created_by' => $v['created_by'] !== null ? self::userRef((int) $v['created_by']) : null,
            'created_at' => Db::iso((string) $v['created_at']),
            'note'       => $v['note'],
            'current'    => true,
        ];
        $audience = EventBus::fileAudience($fileId);
        $opts = ['actor_id' => $actorId > 0 ? $actorId : null, 'file_id' => $fileId, 'folder_id' => $file['folder_id'] !== null ? (int) $file['folder_id'] : null];
        $data = ['file' => $summary, 'version' => $version, 'version_info' => $info];
        if ($restoredFrom !== null) {
            $data['restored_from'] = $restoredFrom;
        }
        EventBus::publish($type, $data, $audience, $opts);
        EventBus::publish('file.updated', ['file' => $summary, 'changes' => ['version', 'size', 'content']], $audience, $opts);
    }

    /**
     * "New version" notification (§11 category version) for everyone with access except the
     * actor. The dedupe key is per file+version, so A3 can use the same key without doubling up.
     */
    private static function notifyVersion(array $file, int $version, int $actorId, ?int $restoredFrom): void
    {
        // §11 assigns "version" notifications to A3: use its implementation when present (same
        // dedupe key, so its own call after restoreVersion() cannot double up).
        $versions = 'FT\\Files\\VersionService';
        if (class_exists($versions) && method_exists($versions, 'notifyRecipients')) {
            try {
                $versions::notifyRecipients($file, $version, $actorId > 0 ? $actorId : null, $restoredFrom !== null ? 'restored' : 'uploaded');
            } catch (\Throwable $e) {
                Logger::warning('app', 'Version notification failed', ['file_id' => (int) $file['id'], 'error' => $e->getMessage()]);
            }
            return;
        }
        $notifier = 'FT\\Notifications\\Notifier';
        if (!class_exists($notifier) || !method_exists($notifier, 'notify')) {
            return;
        }
        $fileId = (int) $file['id'];
        $actor = self::displayName($actorId);
        $title = $restoredFrom !== null
            ? $actor . ' restored version ' . $restoredFrom . ' of “' . $file['name'] . '”'
            : $actor . ' uploaded version ' . $version . ' of “' . $file['name'] . '”';
        foreach (EventBus::fileAudience($fileId) as $uid) {
            if ($uid === $actorId) {
                continue;
            }
            try {
                $isOwner = $uid === (int) $file['owner_id'];
                $notifier::notify($uid, 'version', $restoredFrom !== null ? 'version.restored' : 'version.created', mb_substr($title, 0, 200), '', [
                    'file_id' => $fileId,
                    'version' => $version,
                    'link'    => $isOwner ? '#/files' . ($file['folder_id'] !== null ? '/' . (int) $file['folder_id'] : '') : '#/shared',
                ], 'version:' . $fileId . ':' . $version, $actorId > 0 ? $actorId : null);
            } catch (\Throwable $e) {
                Logger::warning('app', 'Version notification failed', ['file_id' => $fileId, 'error' => $e->getMessage()]);
            }
        }
    }

    /** Thumbnail (GD images), OCR (images/PDF) and content indexing jobs. Never fails the write. */
    private static function queueJobs(array $file): void
    {
        $payload = ['file_id' => (int) $file['id'], 'version' => (int) $file['version']];
        try {
            if (Thumbnailer::supports($file)) {
                Queue::push(Thumbnailer::class . '::generateJob', $payload);
            }
            $ocr = 'FT\\Ocr\\OcrService';
            if (class_exists($ocr)) {
                if (method_exists($ocr, 'ocrJob') && in_array($file['kind'], self::OCR_KINDS, true) && Settings::bool('ocr_enabled', true)) {
                    Queue::push($ocr . '::ocrJob', $payload);
                }
                if (method_exists($ocr, 'indexContentJob') && in_array($file['kind'], self::INDEX_KINDS, true)) {
                    Queue::push($ocr . '::indexContentJob', $payload);
                }
            }
        } catch (\Throwable $e) {
            Logger::warning('upload', 'Could not queue post-upload jobs', ['file_id' => (int) $file['id'], 'error' => $e->getMessage()]);
        }
    }

    private static function slack(string $event, array $fields): void
    {
        $slack = 'FT\\Notifications\\Slack';
        if (!class_exists($slack) || !method_exists($slack, 'notify')) {
            return;
        }
        try {
            $slack::notify($event, array_filter($fields, static fn ($v) => $v !== null && $v !== ''));
        } catch (\Throwable $e) {
            Logger::warning('app', 'Slack notification failed', ['event' => $event, 'error' => $e->getMessage()]);
        }
    }

    private static function userRef(int $userId): ?array
    {
        $u = Db::one('SELECT id, username, display_name FROM users WHERE id = ?', [$userId]);
        if ($u === null) {
            return null;
        }
        return ['id' => (int) $u['id'], 'username' => (string) $u['username'],
            'display_name' => (string) (($u['display_name'] ?? '') !== '' ? $u['display_name'] : $u['username'])];
    }

    private static function displayName(int $userId): string
    {
        $ref = $userId > 0 ? self::userRef($userId) : null;
        return $ref !== null ? $ref['display_name'] : 'Someone';
    }

    /** 24-hour UTC timestamp for integration messages, e.g. "04 Oct 2026, 14:31 UTC". */
    private static function timeLabel(): string
    {
        return gmdate('d M Y, H:i') . ' UTC';
    }

    private static function humanBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB', 'TB'];
        $v = (float) $bytes;
        $i = 0;
        while ($v >= 1024 && $i < count($units) - 1) {
            $v /= 1024;
            $i++;
        }
        return ($i === 0 ? (string) $bytes : number_format($v, 1)) . ' ' . $units[$i];
    }
}
