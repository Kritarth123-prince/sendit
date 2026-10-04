<?php
declare(strict_types=1);

namespace FT\Files;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Events\EventBus;
use FT\Http\Request;
use FT\Storage\BlobStore;

/**
 * Versions API: list, download an older version, restore one (non-destructive: A2's
 * FileWriter::restoreVersion creates a NEW current version pointing at the old blob).
 * Requires the "versions" capability (owner, admin, editor).
 */
final class VersionService
{
    /** @return array<int,array<string,mixed>> newest first */
    public static function list(array $viewer, int $fileId): array
    {
        $file = FileAccess::require($viewer, $fileId, 'versions');
        $rows = Db::all('SELECT * FROM file_versions WHERE file_id = ? ORDER BY version DESC LIMIT 500', [$fileId]);
        $users = FileRepository::userRefs(array_map(static fn ($r) => (int) ($r['created_by'] ?? 0), $rows));
        $current = (int) $file['version'];
        return array_map(static fn (array $r): array => [
            'version'    => (int) $r['version'],
            'size'       => (int) $r['size'],
            'sha256'     => (string) $r['sha256'],
            'name'       => (string) $r['name'],
            'mime'       => (string) $r['mime'],
            'created_by' => $r['created_by'] !== null ? ($users[(int) $r['created_by']] ?? null) : null,
            'created_at' => Db::iso($r['created_at']),
            'note'       => $r['note'] !== null && $r['note'] !== '' ? (string) $r['note'] : null,
            'current'    => (int) $r['version'] === $current,
        ], $rows);
    }

    /** Stream an older (or the current) version as an attachment. */
    public static function download(Request $req, array $viewer, int $fileId, int $version): void
    {
        $file = FileAccess::require($viewer, $fileId, 'versions');
        if (empty($file['access']['download'])) {
            throw ApiException::forbidden();
        }
        $v = Db::one('SELECT * FROM file_versions WHERE file_id = ? AND version = ?', [$fileId, $version]);
        if ($v === null) {
            throw ApiException::notFound('version', 'NOT_FOUND');
        }
        $blob = BlobStore::get((int) $v['blob_id']);
        if (!BlobStore::isIntact($blob)) {
            throw FileService::unavailable();
        }
        $row = $file;
        unset($row['access']);
        $row['name'] = (string) $v['name'];
        $row['mime'] = (string) $v['mime'];
        $row['size'] = (int) $v['size'];
        $row['sha256'] = (string) $v['sha256'];
        $row['version'] = (int) $v['version'];
        $row['blob_id'] = (int) $v['blob_id'];
        if (FileService::countsAsDownload($req)) {
            Audit::log('file.download', [
                'user_id' => (int) $viewer['id'], 'target_type' => 'file', 'target_id' => $fileId, 'owner_id' => (int) $file['owner_id'],
                'detail' => (string) $v['name'], 'meta' => ['version' => (int) $v['version']],
            ]);
        }
        FileService::stream($row, $blob, $req, false, (string) $v['name']);
    }

    /** Restore version N as the new current version. Returns the fresh files row. */
    public static function restore(array $viewer, int $fileId, int $version): array
    {
        $file = FileAccess::require($viewer, $fileId, 'versions');
        if (empty($file['access']['edit'])) {
            throw ApiException::forbidden();
        }
        $v = Db::one('SELECT version FROM file_versions WHERE file_id = ? AND version = ?', [$fileId, $version]);
        if ($v === null) {
            throw ApiException::notFound('version', 'NOT_FOUND');
        }
        if ((int) $file['version'] === $version) {
            throw ApiException::conflict('This is already the current version.', 'VERSION_CONFLICT', ['current_version' => (int) $file['version']]);
        }
        $writer = FileWriter::class;
        if (!class_exists($writer) || !method_exists($writer, 'restoreVersion')) {
            throw ApiException::unavailable('Restoring versions is not available right now.');
        }
        // FileWriter writes the version row, audit (file.version_restore), version.restored event,
        // version notifications and Slack — nothing to repeat here.
        $writer::restoreVersion($fileId, $version, (int) $viewer['id']);
        return FileRepository::find($fileId) ?? throw ApiException::fileNotFound();
    }

    /**
     * Notify everyone with access (except the actor) that a file has a new current version
     * (category "version", §11). Helper for writers that do not notify themselves (A2's FileWriter
     * already does for uploads and restores).
     * @return int notifications attempted
     */
    public static function notifyRecipients(array $file, int $version, ?int $actorId, string $how = 'uploaded'): int
    {
        $notifier = '\\FT\\Notifications\\Notifier';
        if (!class_exists($notifier) || !method_exists($notifier, 'notify')) {
            return 0;
        }
        $fileId = (int) $file['id'];
        $actor = $actorId !== null ? Db::one('SELECT id, username, display_name FROM users WHERE id = ?', [$actorId]) : null;
        $who = FileRepository::displayName($actor);
        $name = (string) $file['name'];
        $title = $how === 'restored'
            ? "{$who} restored an earlier version of “{$name}”"
            : "{$who} uploaded a new version of “{$name}”";
        $n = 0;
        foreach (EventBus::fileAudience($fileId) as $uid) {
            if ($actorId !== null && $uid === $actorId) {
                continue;
            }
            try {
                $notifier::notify($uid, 'version', 'file.version', mb_substr($title, 0, 200), '', [
                    'file_id' => $fileId, 'version' => $version, 'link' => '#/files' . ($file['folder_id'] !== null && (int) $file['owner_id'] === $uid ? '/' . (int) $file['folder_id'] : ''),
                ], 'version:' . $fileId . ':' . $version, $actorId);
                $n++;
            } catch (\Throwable $e) {
                Logger::warning('app', 'Version notification failed', ['file_id' => $fileId, 'error' => $e->getMessage()]);
            }
        }
        return $n;
    }
}
