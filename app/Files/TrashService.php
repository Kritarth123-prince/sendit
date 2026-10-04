<?php
declare(strict_types=1);

namespace FT\Files;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Core\Stats;
use FT\Events\EventBus;
use FT\Jobs\Queue;
use FT\Security\Policy;
use FT\Sharing\ShareService;
use FT\Storage\BlobStore;
use FT\Storage\Paths;
use FT\Storage\QuotaService;

/**
 * Trash lifecycle (docs/ARCHITECTURE.md §4 "Trash"): soft delete, restore, permanent delete,
 * empty trash, retention purge and the purge of a deleted user's data.
 *
 * Model:
 *  - Trashing sets deleted_at/deleted_by/trash_batch/trash_reason and remembers the original
 *    location (trash_original_folder_id / trash_original_parent_id). folder_id/parent_id are kept,
 *    so a trashed folder's subtree keeps its shape and restores in one go.
 *  - Trashing a folder trashes every live descendant (folders + files) with ONE batch id; the
 *    descendants get reason "folder" and are not listed separately in the Trash — the folder
 *    stands for them. Restoring (or purging) a folder acts on its whole batch.
 *  - Permanent deletion only ever applies to items already in the Trash. It releases one blob
 *    reference per version (BlobStore::release — physical deletion is deferred to the blob sweep,
 *    so a concurrent upload deduplicating into the blob is never broken), revokes shares, and
 *    gives the bytes back to the owner's quota.
 *  - Long operations (empty trash, retention purge, user purge) are time-boxed and resumable:
 *    files are purged before their folders, so an interrupted run never leaves orphans.
 */
final class TrashService
{
    public const REASONS = ['user', 'folder', 'expired', 'admin', 'owner_deleted'];

    /** Files purged per transaction. */
    private const CHUNK = 100;

    // ================================================================== retention

    /** Effective retention in days for an owner (0 = keep forever). */
    public static function retentionDays(int $ownerId): int
    {
        return self::retentionMap([$ownerId])[$ownerId] ?? max(0, Settings::int('trash_retention_days', 30));
    }

    /**
     * Global setting, overridden by the owner's preference trash_retention_days when that is
     * shorter (0/unset = no override; a global 0 means "never", so any positive preference wins).
     * @return array<int,int>
     */
    public static function retentionMap(array $ownerIds): array
    {
        $global = max(0, Settings::int('trash_retention_days', 30));
        $ownerIds = array_values(array_unique(array_filter(array_map('intval', $ownerIds), static fn ($i) => $i > 0)));
        $out = [];
        foreach ($ownerIds as $id) {
            $out[$id] = $global;
        }
        if ($ownerIds === []) {
            return $out;
        }
        [$in, $p] = Db::inList($ownerIds, 'rm');
        foreach (Db::all("SELECT id, preferences FROM users WHERE id IN {$in}", $p) as $u) {
            $pref = self::preferenceDays($u['preferences']);
            if ($pref > 0 && ($global === 0 || $pref < $global)) {
                $out[(int) $u['id']] = $pref;
            }
        }
        return $out;
    }

    private static function preferenceDays(?string $json): int
    {
        if ($json === null || $json === '') {
            return 0;
        }
        $prefs = json_decode($json, true);
        $v = is_array($prefs) ? ($prefs['trash_retention_days'] ?? null) : null;
        return (is_int($v) || (is_string($v) && ctype_digit($v))) ? max(0, min(3650, (int) $v)) : 0;
    }

    /**
     * trash{} objects (§9.2) for trashed rows of one type.
     * @return array<int,array<string,mixed>> id => trash info
     */
    public static function infoMany(array $rows, string $type, ?array $viewer = null): array
    {
        $isFile = $type === 'file';
        $origKey = $isFile ? 'trash_original_folder_id' : 'trash_original_parent_id';
        $curKey = $isFile ? 'folder_id' : 'parent_id';
        $folderIds = [];
        $userIds = [];
        $owners = [];
        $batches = [];
        foreach ($rows as $r) {
            $orig = $r[$origKey] ?? $r[$curKey];
            if ($orig !== null) {
                $folderIds[] = (int) $orig;
            }
            if ($r['deleted_by'] !== null) {
                $userIds[] = (int) $r['deleted_by'];
            }
            $owners[] = (int) $r['owner_id'];
            if (!$isFile && $r['trash_batch'] !== null) {
                $batches[] = (string) $r['trash_batch'];
            }
        }
        $map = $folderIds !== [] ? FileAccess::folderMap($folderIds) : [];
        $users = FileRepository::userRefs($userIds);
        $retention = self::retentionMap($owners);

        $contents = [];
        if ($batches !== []) {
            [$inB, $pB] = self::inStrings(array_values(array_unique($batches)), 'tb');
            foreach (Db::all("SELECT trash_batch, COUNT(*) AS n, COALESCE(SUM(size), 0) AS bytes FROM files WHERE deleted_at IS NOT NULL AND trash_batch IN {$inB} GROUP BY trash_batch", $pB) as $c) {
                $contents[(string) $c['trash_batch']]['files'] = (int) $c['n'];
                $contents[(string) $c['trash_batch']]['bytes'] = (int) $c['bytes'];
            }
            foreach (Db::all("SELECT trash_batch, COUNT(*) AS n FROM folders WHERE deleted_at IS NOT NULL AND trash_batch IN {$inB} GROUP BY trash_batch", $pB) as $c) {
                $contents[(string) $c['trash_batch']]['folders'] = max(0, (int) $c['n'] - 1);
            }
        }

        $now = time();
        $out = [];
        foreach ($rows as $r) {
            $orig = $r[$origKey] ?? $r[$curKey];
            $orig = $orig !== null ? (int) $orig : null;
            $crumbs = [];
            if ($orig !== null) {
                foreach (array_reverse(FileAccess::chain($map, $orig)) as $fid) {
                    $crumbs[] = ['id' => $fid, 'name' => (string) $map[$fid]['name']];
                }
            }
            $days = $retention[(int) $r['owner_id']] ?? 0;
            $deletedTs = Db::toUnix($r['deleted_at']) ?? $now;
            $purgeTs = $days > 0 ? $deletedTs + $days * 86400 : null;
            $info = [
                'deleted_at'         => Db::iso($r['deleted_at']),
                'deleted_by'         => $r['deleted_by'] !== null ? ($users[(int) $r['deleted_by']] ?? null) : null,
                'original_folder_id' => ($orig !== null && ($map[$orig] ?? null) !== null) ? $orig : null,
                'original_path'      => FileRepository::pathOf($crumbs),
                'reason'             => (string) ($r['trash_reason'] ?? 'user'),
                'purge_at'           => $purgeTs !== null ? Db::iso(Db::ts($purgeTs)) : null,
                'days_left'          => $purgeTs !== null ? max(0, (int) ceil(($purgeTs - $now) / 86400)) : null,
            ];
            if (!$isFile) {
                $c = $contents[(string) $r['trash_batch']] ?? [];
                $info['contents'] = ['files' => $c['files'] ?? 0, 'folders' => $c['folders'] ?? 0, 'bytes' => $c['bytes'] ?? 0];
            }
            $out[(int) $r['id']] = $info;
        }
        return $out;
    }

    // ================================================================== listing

    /**
     * Trash listing: only top-level items (a trashed folder stands for its contents).
     * $ownerId null = all users (admin view).
     * @return array{items:array,total:int,meta:array}
     */
    public static function listing(?array $viewer, ?int $ownerId, array $f, int $page, int $per): array
    {
        $kind = in_array($f['kind'] ?? '', ['file', 'folder'], true) ? $f['kind'] : null;
        $q = trim((string) ($f['q'] ?? ''));
        $parts = [];
        $countParts = [];
        $params = [];
        foreach (['file' => 'files', 'folder' => 'folders'] as $type => $table) {
            if ($kind !== null && $kind !== $type) {
                continue;
            }
            $w = ["{$table}.deleted_at IS NOT NULL", "({$table}.trash_reason IS NULL OR {$table}.trash_reason <> 'folder')"];
            if ($ownerId !== null) {
                $w[] = "{$table}.owner_id = :o_{$type}";
                $params["o_{$type}"] = $ownerId;
            }
            if ($q !== '') {
                $w[] = "{$table}.name LIKE :q_{$type}";
                $params["q_{$type}"] = '%' . Db::like(mb_substr($q, 0, 200)) . '%';
            }
            $where = implode(' AND ', $w);
            $parts[] = "SELECT '{$type}' AS item_type, {$table}.id AS id, {$table}.deleted_at AS deleted_at FROM {$table} WHERE {$where}";
            $countParts[$type] = [$where, $table];
        }
        $total = 0;
        foreach ($countParts as $type => [$where, $table]) {
            $cp = array_filter($params, static fn ($k) => str_ends_with((string) $k, '_' . $type), ARRAY_FILTER_USE_KEY);
            $total += (int) Db::value("SELECT COUNT(*) FROM {$table} WHERE {$where}", $cp);
        }
        $params['lim'] = $per;
        $params['off'] = ($page - 1) * $per;
        $refs = Db::all('SELECT * FROM (' . implode(' UNION ALL ', $parts) . ') t ORDER BY deleted_at DESC, id DESC LIMIT :lim OFFSET :off', $params);

        $fileIds = [];
        $folderIds = [];
        foreach ($refs as $r) {
            if ($r['item_type'] === 'file') {
                $fileIds[] = (int) $r['id'];
            } else {
                $folderIds[] = (int) $r['id'];
            }
        }
        $files = FileRepository::findMany($fileIds);
        $folders = [];
        if ($folderIds !== []) {
            [$in, $p] = Db::inList($folderIds, 'tf');
            foreach (Db::all("SELECT * FROM folders WHERE id IN {$in}", $p) as $row) {
                $folders[(int) $row['id']] = $row;
            }
        }
        $fs = [];
        foreach (FileRepository::summaries(array_values($files), $viewer, ['trash' => true]) as $s) {
            $fs[$s['id']] = $s;
        }
        $ds = [];
        foreach (FileRepository::folderSummaries(array_values($folders), $viewer, ['trash' => true]) as $s) {
            $ds[$s['id']] = $s;
        }
        $items = [];
        foreach ($refs as $r) {
            $item = $r['item_type'] === 'file' ? ($fs[(int) $r['id']] ?? null) : ($ds[(int) $r['id']] ?? null);
            if ($item !== null) {
                $items[] = $item;
            }
        }

        $bytesParams = [];
        $bytesWhere = 'f.deleted_at IS NOT NULL';
        if ($ownerId !== null) {
            $bytesWhere .= ' AND f.owner_id = :o';
            $bytesParams['o'] = $ownerId;
        }
        $totalBytes = (int) (Db::value("SELECT COALESCE(SUM(v.size), 0) FROM file_versions v JOIN files f ON f.id = v.file_id WHERE {$bytesWhere}", $bytesParams) ?? 0);
        $meta = [
            'retention_days' => $ownerId !== null ? self::retentionDays($ownerId) : max(0, Settings::int('trash_retention_days', 30)),
            'total_bytes'    => $totalBytes,
        ];
        return ['items' => $items, 'total' => $total, 'meta' => $meta];
    }

    // ================================================================== trash

    public static function newBatch(): string
    {
        return bin2hex(random_bytes(8));
    }

    /**
     * Move one file to the Trash. $actor null = system (auto-expiry). Returns the updated row.
     * Options: batch (string), slack (bool, default true), audience (precomputed int[]).
     */
    public static function trashFile(array $file, ?array $actor, string $reason = 'user', array $o = []): array
    {
        if ($file['deleted_at'] !== null) {
            throw ApiException::conflict('This item is already in the Trash.', 'ALREADY_IN_TRASH');
        }
        $id = (int) $file['id'];
        $owner = (int) $file['owner_id'];
        if ($reason === 'user' && $actor !== null && (int) $actor['id'] !== $owner && Policy::isAdmin($actor)) {
            $reason = 'admin';
        }
        $audience = $o['audience'] ?? EventBus::fileAudience($id);
        $n = Db::run(
            'UPDATE files SET deleted_at = :now, deleted_by = :by, trash_batch = :b, trash_original_folder_id = folder_id, trash_reason = :r
              WHERE id = :id AND deleted_at IS NULL',
            ['now' => Db::now(), 'by' => $actor !== null ? (int) $actor['id'] : null, 'b' => $o['batch'] ?? self::newBatch(), 'r' => $reason, 'id' => $id]
        )->rowCount();
        if ($n === 0) {
            throw ApiException::conflict('This item is already in the Trash.', 'ALREADY_IN_TRASH');
        }
        $row = FileRepository::find($id, true) ?? $file;
        $summary = FileRepository::eventSummary($row, true);
        EventBus::publish('file.deleted', [
            'file_id' => $id, 'folder_id' => $row['folder_id'] !== null ? (int) $row['folder_id'] : null, 'file' => $summary,
        ], $audience, ['file_id' => $id, 'folder_id' => $row['folder_id'] !== null ? (int) $row['folder_id'] : null, 'admin' => true, 'actor_id' => $actor !== null ? (int) $actor['id'] : null]);
        Audit::log('file.trash', [
            'user_id' => $actor !== null ? (int) $actor['id'] : null,
            'actor_label' => $actor === null ? 'FastTransfer' : null,
            'target_type' => 'file', 'target_id' => $id, 'owner_id' => $owner,
            'detail' => (string) $row['name'], 'meta' => ['reason' => $reason, 'folder_id' => $row['folder_id'] !== null ? (int) $row['folder_id'] : null],
        ]);
        Stats::bump('deletes');
        if (($o['slack'] ?? true) && $actor !== null) {
            FileService::slack('delete', ['Name' => (string) $row['name'], 'By' => FileRepository::displayName($actor), 'Time' => FileService::slackTime()]);
        }
        return $row;
    }

    /**
     * Move a folder and its whole live subtree to the Trash under one batch id.
     * @return array{folder:array,files:int,folders:int}
     */
    public static function trashFolder(array $folder, ?array $actor, string $reason = 'user'): array
    {
        if ($folder['deleted_at'] !== null) {
            throw ApiException::conflict('This item is already in the Trash.', 'ALREADY_IN_TRASH');
        }
        $id = (int) $folder['id'];
        $owner = (int) $folder['owner_id'];
        if ($reason === 'user' && $actor !== null && (int) $actor['id'] !== $owner && Policy::isAdmin($actor)) {
            $reason = 'admin';
        }
        $audience = EventBus::folderAudience($id);
        $subtree = FolderService::subtreeIds($owner, $id);
        $batch = self::newBatch();
        $now = Db::now();
        $by = $actor !== null ? (int) $actor['id'] : null;
        $fileIds = [];
        Db::transaction(static function () use ($subtree, $id, $owner, $batch, $now, $by, $reason, &$fileIds): void {
            $n = Db::run(
                'UPDATE folders SET deleted_at = :now, deleted_by = :by, trash_batch = :b, trash_original_parent_id = parent_id, trash_reason = :r
                  WHERE id = :id AND deleted_at IS NULL',
                ['now' => $now, 'by' => $by, 'b' => $batch, 'r' => $reason, 'id' => $id]
            )->rowCount();
            if ($n === 0) {
                throw ApiException::conflict('This item is already in the Trash.', 'ALREADY_IN_TRASH');
            }
            foreach (array_chunk($subtree, 500) as $chunk) {
                [$in, $p] = Db::inList($chunk, 'st');
                $descendants = array_values(array_filter($chunk, static fn ($fid) => $fid !== $id));
                if ($descendants !== []) {
                    [$inD, $pD] = Db::inList($descendants, 'sd');
                    Db::run(
                        "UPDATE folders SET deleted_at = :now, deleted_by = :by, trash_batch = :b, trash_original_parent_id = parent_id, trash_reason = 'folder'
                          WHERE id IN {$inD} AND deleted_at IS NULL",
                        $pD + ['now' => $now, 'by' => $by, 'b' => $batch]
                    );
                }
                $p['o'] = $owner;
                foreach (Db::column("SELECT id FROM files WHERE owner_id = :o AND folder_id IN {$in} AND deleted_at IS NULL", $p) as $fid) {
                    $fileIds[] = (int) $fid;
                }
                Db::run(
                    "UPDATE files SET deleted_at = :now, deleted_by = :by, trash_batch = :b, trash_original_folder_id = folder_id, trash_reason = 'folder'
                      WHERE owner_id = :o AND folder_id IN {$in} AND deleted_at IS NULL",
                    $p + ['now' => $now, 'by' => $by, 'b' => $batch]
                );
            }
        });
        $row = Db::one('SELECT * FROM folders WHERE id = ?', [$id]) ?? $folder;
        $parent = $row['parent_id'] !== null ? (int) $row['parent_id'] : null;
        EventBus::publish('folder.deleted', [
            'folder_id' => $id, 'parent_id' => $parent, 'folder' => FileRepository::folderEventSummary($row, true),
            'file_ids' => array_slice($fileIds, 0, 500), 'files' => count($fileIds), 'folders' => count($subtree) - 1,
        ], $audience, ['folder_id' => $id, 'admin' => true, 'actor_id' => $by]);
        Audit::log('folder.trash', [
            'user_id' => $by, 'target_type' => 'folder', 'target_id' => $id, 'owner_id' => $owner, 'detail' => (string) $row['name'],
            'meta' => ['reason' => $reason, 'files' => count($fileIds), 'folders' => count($subtree) - 1],
        ]);
        Stats::bump('deletes', max(1, count($fileIds)));
        if ($actor !== null) {
            FileService::slack('delete', ['Name' => $row['name'] . ' (folder, ' . count($fileIds) . ' ' . (count($fileIds) === 1 ? 'file' : 'files') . ')', 'By' => FileRepository::displayName($actor), 'Time' => FileService::slackTime()]);
        }
        return ['folder' => $row, 'files' => count($fileIds), 'folders' => count($subtree) - 1];
    }

    // ================================================================== restore

    /** Restore one trashed file into its original folder (or the root), renaming on conflict. */
    public static function restoreFile(array $file, array $actor): array
    {
        if ($file['deleted_at'] === null) {
            throw ApiException::conflict('This item is not in the Trash.', 'NOT_IN_TRASH');
        }
        $id = (int) $file['id'];
        $owner = (int) $file['owner_id'];
        $orig = $file['trash_original_folder_id'] ?? $file['folder_id'];
        $target = null;
        if ($orig !== null) {
            $ok = Db::value('SELECT 1 FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NULL', [(int) $orig, $owner]);
            $target = $ok !== null ? (int) $orig : null;
        }
        $name = FileRepository::uniqueName($owner, $target, (string) $file['name'], $id);
        $set = ['folder_id' => $target, 'name' => $name];
        // An auto-expired file would be trashed again by the next maintenance run: give it a new lease.
        if ((int) $file['is_permanent'] === 0 && $file['expires_at'] !== null && (string) $file['expires_at'] <= Db::now()) {
            $hours = Settings::int('auto_expire_hours', 72);
            $set['expires_at'] = $hours > 0 ? Db::ts(time() + $hours * 3600) : null;
        }
        $params = $set + ['id' => $id];
        $n = Db::run(
            'UPDATE files SET deleted_at = NULL, deleted_by = NULL, trash_batch = NULL, trash_original_folder_id = NULL, trash_reason = NULL,
                    folder_id = :folder_id, name = :name' . (array_key_exists('expires_at', $set) ? ', expires_at = :expires_at' : '') . '
              WHERE id = :id AND deleted_at IS NOT NULL',
            $params
        )->rowCount();
        if ($n === 0) {
            throw ApiException::conflict('This item is not in the Trash.', 'NOT_IN_TRASH');
        }
        $row = FileRepository::find($id) ?? $file;
        EventBus::publish('file.restored', ['file' => FileRepository::eventSummary($row)], EventBus::fileAudience($id), ['file_id' => $id, 'folder_id' => $target]);
        Audit::log('file.restore', [
            'user_id' => (int) $actor['id'], 'target_type' => 'file', 'target_id' => $id, 'owner_id' => $owner, 'detail' => $name,
            'meta' => ['folder_id' => $target, 'renamed' => $name !== (string) $file['name'] ? ['from' => (string) $file['name'], 'to' => $name] : null],
        ]);
        return $row;
    }

    /**
     * Restore a trashed folder with everything that was trashed together with it. A folder
     * that was trashed as part of a parent's batch restores that whole batch.
     * @return array{folder:array,files:int,folders:int}
     */
    public static function restoreFolder(array $folder, array $actor): array
    {
        if ($folder['deleted_at'] === null) {
            throw ApiException::conflict('This item is not in the Trash.', 'NOT_IN_TRASH');
        }
        $owner = (int) $folder['owner_id'];
        $batch = $folder['trash_batch'];
        $root = $folder;
        $batchFolderIds = [(int) $folder['id']];
        if ($batch !== null) {
            $batchFolders = Db::all('SELECT * FROM folders WHERE owner_id = ? AND trash_batch = ? AND deleted_at IS NOT NULL', [$owner, $batch]);
            $batchFolderIds = array_map(static fn ($r) => (int) $r['id'], $batchFolders);
            foreach ($batchFolders as $bf) {
                $parent = $bf['parent_id'] !== null ? (int) $bf['parent_id'] : null;
                if ($parent === null || !in_array($parent, $batchFolderIds, true)) {
                    $root = $bf; // the folder the user originally deleted
                    break;
                }
            }
        }
        $rootId = (int) $root['id'];
        $orig = $root['trash_original_parent_id'] ?? $root['parent_id'];
        $target = null;
        if ($orig !== null && !in_array((int) $orig, $batchFolderIds, true)) {
            $ok = Db::value('SELECT 1 FROM folders WHERE id = ? AND owner_id = ? AND deleted_at IS NULL', [(int) $orig, $owner]);
            $target = $ok !== null ? (int) $orig : null;
        }
        $name = FileRepository::uniqueFolderName($owner, $target, (string) $root['name'], $rootId);
        $files = 0;
        Db::transaction(static function () use ($owner, $batch, $rootId, $target, $name, &$files): void {
            $clear = 'deleted_at = NULL, deleted_by = NULL, trash_batch = NULL, trash_reason = NULL';
            Db::run("UPDATE folders SET {$clear}, trash_original_parent_id = NULL, parent_id = :pa, name = :n WHERE id = :id", ['pa' => $target, 'n' => $name, 'id' => $rootId]);
            if ($batch !== null) {
                Db::run("UPDATE folders SET {$clear}, trash_original_parent_id = NULL WHERE owner_id = :o AND trash_batch = :b AND deleted_at IS NOT NULL", ['o' => $owner, 'b' => $batch]);
                $files = Db::run("UPDATE files SET {$clear}, trash_original_folder_id = NULL WHERE owner_id = :o AND trash_batch = :b AND deleted_at IS NOT NULL", ['o' => $owner, 'b' => $batch])->rowCount();
            }
        });
        $row = Db::one('SELECT * FROM folders WHERE id = ?', [$rootId]) ?? $root;
        EventBus::publish('folder.restored', [
            'folder' => FileRepository::folderEventSummary($row), 'files' => $files, 'folders' => count($batchFolderIds) - 1,
        ], EventBus::folderAudience($rootId), ['folder_id' => $rootId]);
        Audit::log('folder.restore', [
            'user_id' => (int) $actor['id'], 'target_type' => 'folder', 'target_id' => $rootId, 'owner_id' => $owner, 'detail' => $name,
            'meta' => ['parent_id' => $target, 'files' => $files, 'folders' => count($batchFolderIds) - 1],
        ]);
        return ['folder' => $row, 'files' => $files, 'folders' => count($batchFolderIds) - 1];
    }

    // ================================================================== permanent deletion

    /** Permanently delete one trashed file. @return int freed bytes */
    public static function purgeFile(array $file, ?array $actor): int
    {
        if ($file['deleted_at'] === null) {
            throw ApiException::conflict('Only items in the Trash can be deleted permanently.', 'NOT_IN_TRASH');
        }
        $r = self::purgeFiles([(int) $file['id']], (int) $file['owner_id'], $actor, true, true);
        if ($r['files'] === 0) {
            throw ApiException::conflict('Only items in the Trash can be deleted permanently.', 'NOT_IN_TRASH');
        }
        return $r['bytes'];
    }

    /**
     * Permanently delete a trashed folder and its batch (files first, then folders).
     * @return array{files:int,folders:int,bytes:int,complete:bool}
     */
    public static function purgeFolder(array $folder, ?array $actor, float $budgetSeconds = 15.0): array
    {
        if ($folder['deleted_at'] === null) {
            throw ApiException::conflict('Only items in the Trash can be deleted permanently.', 'NOT_IN_TRASH');
        }
        $owner = (int) $folder['owner_id'];
        $deadline = microtime(true) + $budgetSeconds;
        $batch = $folder['trash_batch'];
        $folderIds = [(int) $folder['id']];
        if ($batch !== null) {
            $folderIds = array_map('intval', Db::column('SELECT id FROM folders WHERE owner_id = ? AND trash_batch = ? AND deleted_at IS NOT NULL', [$owner, $batch]));
            if (!in_array((int) $folder['id'], $folderIds, true)) {
                $folderIds[] = (int) $folder['id'];
            }
        }
        $files = 0;
        $bytes = 0;
        $complete = true;
        while (true) {
            $ids = $batch !== null
                ? array_map('intval', Db::column('SELECT id FROM files WHERE owner_id = ? AND trash_batch = ? AND deleted_at IS NOT NULL LIMIT ' . self::CHUNK, [$owner, $batch]))
                : [];
            if ($ids === []) {
                break;
            }
            $r = self::purgeFiles($ids, $owner, $actor, true, false);
            $files += $r['files'];
            $bytes += $r['bytes'];
            if ($r['files'] === 0 || microtime(true) > $deadline) {
                $complete = Db::value('SELECT 1 FROM files WHERE owner_id = ? AND trash_batch = ? AND deleted_at IS NOT NULL LIMIT 1', [$owner, $batch]) === null;
                break;
            }
        }
        $folders = 0;
        if ($complete) {
            $folders = self::deleteFolderRows($folderIds, $actor);
            if ($bytes > 0) {
                self::adjustQuota($owner, -$bytes);
            }
            EventBus::publish('folder.purged', ['folder_id' => (int) $folder['id'], 'files' => $files, 'folders' => $folders], [$owner], ['folder_id' => (int) $folder['id'], 'admin' => true, 'actor_id' => $actor !== null ? (int) $actor['id'] : null]);
            Audit::log('folder.purge', [
                'user_id' => $actor !== null ? (int) $actor['id'] : null, 'actor_label' => $actor === null ? 'FastTransfer' : null,
                'target_type' => 'folder', 'target_id' => (int) $folder['id'], 'owner_id' => $owner, 'detail' => (string) $folder['name'],
                'meta' => ['files' => $files, 'folders' => $folders, 'bytes' => $bytes],
            ]);
        } elseif ($bytes > 0) {
            self::adjustQuota($owner, -$bytes);
        }
        return ['files' => $files, 'folders' => $folders, 'bytes' => $bytes, 'complete' => $complete];
    }

    /**
     * Empty an owner's Trash (time-boxed; call again while complete=false).
     * @return array{purged_files:int,purged_folders:int,freed_bytes:int,complete:bool}
     */
    public static function emptyTrash(int $ownerId, ?array $actor, float $budgetSeconds = 15.0): array
    {
        $deadline = microtime(true) + $budgetSeconds;
        $files = 0;
        $bytes = 0;
        $complete = true;
        while (true) {
            $ids = array_map('intval', Db::column('SELECT id FROM files WHERE owner_id = ? AND deleted_at IS NOT NULL ORDER BY id LIMIT ' . self::CHUNK, [$ownerId]));
            if ($ids === []) {
                break;
            }
            $r = self::purgeFiles($ids, $ownerId, $actor, true, false);
            $files += $r['files'];
            $bytes += $r['bytes'];
            if ($r['files'] === 0 || microtime(true) > $deadline) {
                $complete = Db::value('SELECT 1 FROM files WHERE owner_id = ? AND deleted_at IS NOT NULL LIMIT 1', [$ownerId]) === null;
                break;
            }
        }
        $folders = 0;
        if ($complete) {
            $folderIds = array_map('intval', Db::column('SELECT id FROM folders WHERE owner_id = ? AND deleted_at IS NOT NULL', [$ownerId]));
            $folders = self::deleteFolderRows($folderIds, $actor);
        }
        if ($bytes > 0) {
            self::adjustQuota($ownerId, -$bytes);
        }
        $result = ['purged_files' => $files, 'purged_folders' => $folders, 'freed_bytes' => $bytes, 'complete' => $complete];
        EventBus::publish('trash.emptied', $result, [$ownerId], ['admin' => true, 'actor_id' => $actor !== null ? (int) $actor['id'] : null]);
        Audit::log('file.purge', [
            'user_id' => $actor !== null ? (int) $actor['id'] : null, 'actor_label' => $actor === null ? 'FastTransfer' : null,
            'target_type' => 'user', 'target_id' => $ownerId, 'owner_id' => $ownerId, 'detail' => 'Emptied the Trash',
            'meta' => ['files' => $files, 'folders' => $folders, 'bytes' => $bytes, 'empty_trash' => true, 'complete' => $complete],
        ]);
        return $result;
    }

    /**
     * Maintenance (A6 purge_trash): permanently delete trashed items past their retention.
     * Returns the number of items (files + folders) purged. Time-boxed to ~10 s.
     */
    public static function purgeExpired(int $limit = 200): int
    {
        $limit = max(1, $limit);
        $deadline = microtime(true) + 10.0; // maintenance slices share a ~20 s request budget
        $global = max(0, Settings::int('trash_retention_days', 30));
        $rules = [];
        if ($global > 0) {
            $rules[] = [null, Db::ts(time() - $global * 86400)];
        }
        // owners whose preference is shorter than the global retention
        foreach (Db::all("SELECT id, preferences FROM users WHERE preferences LIKE :p LIMIT 1000", ['p' => '%trash_retention_days%']) as $u) {
            $pref = self::preferenceDays($u['preferences']);
            if ($pref > 0 && ($global === 0 || $pref < $global)) {
                $rules[] = [(int) $u['id'], Db::ts(time() - $pref * 86400)];
            }
        }
        $done = 0;
        $freed = [];
        foreach ($rules as [$owner, $cutoff]) {
            $ownerSql = $owner !== null ? ' AND owner_id = :o' : '';
            $p = ['c' => $cutoff] + ($owner !== null ? ['o' => $owner] : []);
            while ($done < $limit && microtime(true) < $deadline) {
                $p['lim'] = min(self::CHUNK, $limit - $done);
                $rows = Db::all("SELECT id, owner_id FROM files WHERE deleted_at IS NOT NULL AND deleted_at <= :c{$ownerSql} ORDER BY deleted_at LIMIT :lim", $p);
                if ($rows === []) {
                    break;
                }
                $byOwner = [];
                foreach ($rows as $r) {
                    $byOwner[(int) $r['owner_id']][] = (int) $r['id'];
                }
                $progress = 0;
                foreach ($byOwner as $oid => $ids) {
                    $r = self::purgeFiles($ids, $oid, null, true, false);
                    $done += $r['files'];
                    $progress += $r['files'];
                    $freed[$oid] = ($freed[$oid] ?? 0) + $r['bytes'];
                }
                if ($progress === 0) {
                    break;
                }
            }
            // folders past retention whose batch holds no more trashed files
            if ($done < $limit && microtime(true) < $deadline) {
                $fp = ['c' => $cutoff, 'lim' => max(1, $limit - $done)] + ($owner !== null ? ['o' => $owner] : []);
                $folderRows = Db::all(
                    "SELECT fo.id FROM folders fo WHERE fo.deleted_at IS NOT NULL AND fo.deleted_at <= :c" . ($owner !== null ? ' AND fo.owner_id = :o' : '') . "
                       AND NOT EXISTS (SELECT 1 FROM files fi WHERE fi.trash_batch = fo.trash_batch AND fi.owner_id = fo.owner_id AND fi.deleted_at IS NOT NULL)
                     ORDER BY fo.deleted_at LIMIT :lim",
                    $fp
                );
                if ($folderRows !== []) {
                    $done += self::deleteFolderRows(array_map(static fn ($r) => (int) $r['id'], $folderRows), null);
                }
            }
            if ($done >= $limit || microtime(true) >= $deadline) {
                break;
            }
        }
        foreach ($freed as $oid => $bytes) {
            if ($bytes > 0) {
                self::adjustQuota($oid, -$bytes);
            }
        }
        if ($done > 0) {
            Logger::info('maintenance', 'Trash retention purge', ['items' => $done]);
        }
        return $done;
    }

    /**
     * Purge EVERYTHING an owner has (live and trashed) — used when an account is deleted
     * (A1 UserService::purgeUserJob). Time-boxed; re-queues itself when unfinished.
     * Returns the number of items purged in this run.
     */
    public static function purgeAllForOwner(int $ownerId): int
    {
        $deadline = microtime(true) + 8.0; // runs inside queue slices (tick requests): stay short, re-queue the rest
        $files = 0;
        $bytes = 0;
        $complete = true;
        while (true) {
            $ids = array_map('intval', Db::column('SELECT id FROM files WHERE owner_id = ? ORDER BY id LIMIT ' . self::CHUNK, [$ownerId]));
            if ($ids === []) {
                break;
            }
            $r = self::purgeFiles($ids, $ownerId, null, false, false);
            $files += $r['files'];
            $bytes += $r['bytes'];
            if ($r['files'] === 0 || microtime(true) > $deadline) {
                $complete = Db::value('SELECT 1 FROM files WHERE owner_id = ? LIMIT 1', [$ownerId]) === null;
                break;
            }
        }
        $folders = 0;
        if ($complete) {
            $folders = self::deleteFolderRows(array_map('intval', Db::column('SELECT id FROM folders WHERE owner_id = ?', [$ownerId])), null);
            Db::run('DELETE ft FROM file_tags ft JOIN tags t ON t.id = ft.tag_id WHERE t.owner_id = ?', [$ownerId]);
            Db::run('DELETE FROM tags WHERE owner_id = ?', [$ownerId]);
            Db::run('DELETE FROM favorites WHERE user_id = ?', [$ownerId]);
        }
        if ($bytes > 0) {
            self::adjustQuota($ownerId, -$bytes);
        }
        Audit::log('file.purge', [
            'user_id' => null, 'actor_label' => 'FastTransfer', 'category' => 'system', 'target_type' => 'user', 'target_id' => $ownerId,
            'owner_id' => $ownerId, 'detail' => 'Deleted account data purged',
            'meta' => ['files' => $files, 'folders' => $folders, 'bytes' => $bytes, 'complete' => $complete, 'reason' => 'owner_deleted'],
        ]);
        if (!$complete) {
            try {
                Queue::push('FT\\Users\\UserService::purgeUserJob', ['user_id' => $ownerId], 5, 'default', 5);
            } catch (\Throwable $e) {
                Logger::warning('app', 'Could not re-queue the user data purge', ['user_id' => $ownerId, 'error' => $e->getMessage()]);
            }
        }
        return $files + $folders;
    }

    // ================================================================== internals

    /**
     * Permanently delete files (all owned by $ownerId) in one transaction: versions → blob
     * references released, shares revoked, rows deleted (comments/tags/favourites/share items
     * cascade). $onlyTrashed guards against purging live files.
     * Quota is adjusted here only when $adjustQuota (callers that loop sum it themselves).
     * @return array{files:int,bytes:int}
     */
    private static function purgeFiles(array $ids, int $ownerId, ?array $actor, bool $onlyTrashed, bool $adjustQuota): array
    {
        $ids = array_values(array_unique(array_map('intval', $ids)));
        if ($ids === []) {
            return ['files' => 0, 'bytes' => 0];
        }
        $actorId = $actor !== null ? (int) $actor['id'] : null;
        $result = Db::transaction(static function () use ($ids, $ownerId, $onlyTrashed, $actorId): array {
            [$in, $p] = Db::inList($ids, 'pf');
            $p['o'] = $ownerId;
            $rows = Db::all(
                "SELECT id, name, folder_id FROM files WHERE id IN {$in} AND owner_id = :o" . ($onlyTrashed ? ' AND deleted_at IS NOT NULL' : '') . ' FOR UPDATE',
                $p
            );
            if ($rows === []) {
                return ['rows' => [], 'bytes' => 0, 'blobs' => [], 'shares' => []];
            }
            $locked = array_map(static fn ($r) => (int) $r['id'], $rows);
            [$inL, $pL] = Db::inList($locked, 'pl');
            $versions = Db::all("SELECT blob_id, size FROM file_versions WHERE file_id IN {$inL}", $pL);
            $bytes = 0;
            foreach ($versions as $v) {
                $bytes += (int) $v['size'];
            }
            // Shares on the files die with them, together with every re-share made from them
            // (bundles merely lose the item: share_items rows cascade).
            $shares = self::revokeShares(Db::all("SELECT id, owner_id, recipient_id, kind, target_type, file_id, folder_id FROM shares WHERE file_id IN {$inL} AND revoked_at IS NULL", $pL), $actorId);
            Db::run("DELETE FROM edit_presence WHERE file_id IN {$inL}", $pL);
            Db::run("DELETE FROM file_versions WHERE file_id IN {$inL}", $pL);
            Db::run("DELETE FROM files WHERE id IN {$inL}", $pL);
            foreach ($versions as $v) {
                BlobStore::release((int) $v['blob_id']);
            }
            return ['rows' => $rows, 'bytes' => $bytes, 'shares' => $shares];
        });
        if ($result['rows'] === []) {
            return ['files' => 0, 'bytes' => 0];
        }
        foreach ($result['rows'] as $r) {
            self::deleteThumbnails($ownerId, (int) $r['id']);
            EventBus::publish('file.purged', ['file_id' => (int) $r['id']], [$ownerId], ['file_id' => (int) $r['id'], 'admin' => true, 'actor_id' => $actorId]);
        }
        self::publishRevocations($result['shares'], $actorId);
        if (count($result['rows']) === 1) {
            $r = $result['rows'][0];
            Audit::log('file.purge', [
                'user_id' => $actorId, 'actor_label' => $actorId === null ? 'FastTransfer' : null,
                'target_type' => 'file', 'target_id' => (int) $r['id'], 'owner_id' => $ownerId, 'detail' => (string) $r['name'],
                'meta' => ['bytes' => $result['bytes']],
            ]);
        }
        if ($adjustQuota && $result['bytes'] > 0) {
            self::adjustQuota($ownerId, -$result['bytes']);
        }
        return ['files' => count($result['rows']), 'bytes' => $result['bytes']];
    }

    /**
     * Delete folder rows (their files must already be gone), revoke folder shares and detach
     * anything that still points at them (it falls back to the root). @return int folders deleted
     */
    private static function deleteFolderRows(array $folderIds, ?array $actor): int
    {
        $folderIds = array_values(array_unique(array_map('intval', $folderIds)));
        $deleted = 0;
        $actorId = $actor !== null ? (int) $actor['id'] : null;
        foreach (array_chunk($folderIds, 500) as $chunk) {
            $shares = Db::transaction(static function () use ($chunk, $actorId, &$deleted): array {
                [$in, $p] = Db::inList($chunk, 'df');
                $shares = self::revokeShares(Db::all("SELECT id, owner_id, recipient_id, kind, target_type, file_id, folder_id FROM shares WHERE folder_id IN {$in} AND revoked_at IS NULL", $p), $actorId);
                Db::run("UPDATE files SET folder_id = NULL WHERE folder_id IN {$in}", $p);
                Db::run("UPDATE files SET trash_original_folder_id = NULL WHERE trash_original_folder_id IN {$in}", $p);
                Db::run("UPDATE folders SET parent_id = NULL WHERE parent_id IN {$in}", $p);
                Db::run("UPDATE folders SET trash_original_parent_id = NULL WHERE trash_original_parent_id IN {$in}", $p);
                $deleted += Db::run("DELETE FROM folders WHERE id IN {$in}", $p)->rowCount();
                return $shares;
            });
            self::publishRevocations($shares, $actorId);
        }
        return $deleted;
    }

    /**
     * Revoke shares that die with their content INSIDE the caller's transaction — through A4's
     * ShareService::revokeTree() so every re-share made from them goes too. Returns the rows to
     * report after the commit (publishRevocations()). Guarded: without A4, a plain UPDATE.
     * @param array<int,array<string,mixed>> $shares rows (id, owner_id, recipient_id, kind, target_type, file_id, folder_id)
     * @return array<int,array<string,mixed>> rows, or ['cascade' => int[]] entries when A4 did the work
     */
    private static function revokeShares(array $shares, ?int $actorId): array
    {
        if ($shares === []) {
            return [];
        }
        $ids = array_map(static fn ($s) => (int) $s['id'], $shares);
        if (method_exists(ShareService::class, 'revokeTree') && method_exists(ShareService::class, 'afterCascade')) {
            $revoked = [];
            foreach ($ids as $id) {
                if (!in_array($id, $revoked, true)) {
                    $revoked = array_merge($revoked, ShareService::revokeTree($id, $actorId));
                }
            }
            return [['cascade' => array_values(array_unique($revoked))]];
        }
        [$inS, $pS] = Db::inList($ids, 'rs');
        Db::run("UPDATE shares SET revoked_at = :now, revoked_by = :by, updated_at = :now2 WHERE id IN {$inS} AND revoked_at IS NULL", $pS + ['now' => Db::now(), 'now2' => Db::now(), 'by' => $actorId]);
        return $shares;
    }

    /** share.revoked for shares that died with their content (minimal payload, no tokens). */
    private static function publishRevocations(array $shares, ?int $actorId): void
    {
        FileAccess::reset();
        foreach ($shares as $s) {
            if (isset($s['cascade'])) {
                // A4 revoked them: its audit rows and share.revoked events (to the share owner, the
                // recipient and the admin channel), never failing the purge.
                ShareService::afterCascade(['updated' => [], 'revoked' => $s['cascade']], $actorId, null, ['reason' => 'deleted']);
                continue;
            }
            $recipients = [(int) $s['owner_id']];
            if ($s['recipient_id'] !== null) {
                $recipients[] = (int) $s['recipient_id'];
            }
            EventBus::publish('share.revoked', [
                'share' => ['id' => (int) $s['id'], 'kind' => (string) $s['kind'], 'target_type' => (string) $s['target_type'], 'status' => 'revoked'],
                'file_id' => $s['file_id'] !== null ? (int) $s['file_id'] : null,
                'folder_id' => $s['folder_id'] !== null ? (int) $s['folder_id'] : null,
                'reason' => 'deleted',
            ], $recipients, ['share_id' => (int) $s['id'], 'admin' => true, 'actor_id' => $actorId]);
        }
    }

    /** Remove the stored (encrypted) thumbnail of a purged file — through A2's Thumbnailer when present. */
    private static function deleteThumbnails(int $ownerId, int $fileId): void
    {
        $thumb = '\\FT\\Storage\\Thumbnailer';
        if (class_exists($thumb) && method_exists($thumb, 'delete')) {
            try {
                $thumb::delete($ownerId, $fileId);
                return;
            } catch (\Throwable $e) {
                Logger::warning('app', 'Thumbnail cleanup failed', ['file_id' => $fileId, 'error' => $e->getMessage()]);
            }
        }
        try {
            $dir = Paths::root() . '/users/' . $ownerId . '/thumbs';
            if (!is_dir($dir)) {
                return;
            }
            foreach (glob($dir . '/' . $fileId . '.*') ?: [] as $f) {
                @unlink($f);
            }
        } catch (\Throwable $e) {
            Logger::warning('app', 'Thumbnail cleanup failed', ['file_id' => $fileId, 'error' => $e->getMessage()]);
        }
    }

    /** Give bytes back to the owner (A2 QuotaService; falls back to an authoritative recount). */
    private static function adjustQuota(int $ownerId, int $delta): void
    {
        try {
            if (class_exists(QuotaService::class) && method_exists(QuotaService::class, 'adjust')) {
                QuotaService::adjust($ownerId, $delta);
                return;
            }
            Db::run(
                'UPDATE users SET used_bytes = (SELECT COALESCE(SUM(v.size), 0) FROM file_versions v JOIN files f ON f.id = v.file_id WHERE f.owner_id = :o) WHERE id = :id',
                ['o' => $ownerId, 'id' => $ownerId]
            );
        } catch (\Throwable $e) {
            Logger::warning('app', 'Quota update after purge failed', ['user_id' => $ownerId, 'error' => $e->getMessage()]);
        }
    }

    /** @return array{0:string,1:array<string,string>} IN list of strings */
    private static function inStrings(array $values, string $prefix): array
    {
        $ph = [];
        $params = [];
        foreach (array_values($values) as $i => $v) {
            $ph[] = ':' . $prefix . $i;
            $params[$prefix . $i] = (string) $v;
        }
        return ['(' . ($ph !== [] ? implode(',', $ph) : 'NULL') . ')', $params];
    }
}
