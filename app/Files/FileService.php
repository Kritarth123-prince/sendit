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
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\Policy;
use FT\Storage\BlobStore;
use FT\Storage\MimeDetector;

/**
 * Files domain service: listings, details, metadata changes (rename, move, description, keep
 * forever, tags, favourites), trash entry points, downloads/previews, batch actions, ZIP
 * downloads and auto-expiry.
 *
 * Every mutation follows the same recipe: authorise through FileAccess (re-loading the row by
 * id), change the database inside one transaction (audit rows included, so they roll back with
 * the change), and publish real-time events only after the commit.
 */
final class FileService
{
    public const BATCH_ACTIONS = ['trash', 'move', 'tag', 'untag', 'favorite', 'unfavorite', 'permanent', 'restore', 'purge'];
    public const MAX_BATCH = 500;
    public const VIEWS = ['all', 'recent', 'favorites'];

    /** Favourites are filtered for access in PHP; cap the candidate set. */
    private const MAX_FAVORITES = 2000;

    // ================================================================== listing

    /**
     * GET /files.
     * @param array{folder_id?:?int,root?:bool,view?:string,kind?:?string,tag?:?string,q?:string,sort?:string,order?:string,page?:int,per_page?:int} $o
     * @return array{items:array,total:int,page:int,per_page:int,meta:array}
     */
    public static function listing(array $viewer, array $o): array
    {
        $uid = (int) $viewer['id'];
        $view = in_array($o['view'] ?? 'all', self::VIEWS, true) ? (string) ($o['view'] ?? 'all') : 'all';
        $page = max(1, (int) ($o['page'] ?? 1));
        $per = max(1, min(200, (int) ($o['per_page'] ?? 50)));
        [$sort, $order] = self::sortFor($viewer, $o['sort'] ?? null, $o['order'] ?? null, $view);
        $folderId = $o['folder_id'] ?? null;
        if (!empty($o['root'])) {
            $folderId = null;
        }

        $w = ['f.deleted_at IS NULL'];
        $p = [];
        $kind = $o['kind'] ?? null;
        if ($kind !== null && $kind !== '') {
            if (!in_array($kind, MimeDetector::KINDS, true)) {
                throw ApiException::validation(['kind' => 'Unknown file kind.']);
            }
            $w[] = 'f.kind = :kind';
            $p['kind'] = $kind;
        }
        $tag = $o['tag'] ?? null;
        if ($tag !== null && $tag !== '') {
            $t = TagService::normalise($tag);
            if ($t === null) {
                throw ApiException::validation(['tag' => 'Unknown tag.']);
            }
            $w[] = 'EXISTS (SELECT 1 FROM file_tags ft JOIN tags t ON t.id = ft.tag_id WHERE ft.file_id = f.id AND t.owner_id = f.owner_id AND t.name = :tag)';
            $p['tag'] = $t;
        }
        $q = trim((string) ($o['q'] ?? ''));
        if ($q !== '') {
            $w[] = 'f.name LIKE :q';
            $p['q'] = '%' . Db::like(mb_substr($q, 0, 200)) . '%';
        }

        $meta = ['view' => $view, 'sort' => $sort, 'order' => $order, 'folder' => null, 'breadcrumbs' => []];
        $folder = null;

        if ($view === 'favorites') {
            $rows = Db::all(
                'SELECT f.*, b.encryption AS blob_encryption FROM favorites fav
                   JOIN files f ON f.id = fav.file_id
                   LEFT JOIN file_blobs b ON b.id = f.blob_id
                  WHERE fav.user_id = :me AND ' . implode(' AND ', $w) . '
                  ORDER BY f.' . FileRepository::SORTS[$sort] . ' ' . $order . ', f.id ' . $order . ' LIMIT ' . self::MAX_FAVORITES,
                $p + ['me' => $uid]
            );
            $caps = FileAccess::accessForMany($viewer, $rows);
            $rows = array_values(array_filter($rows, static fn ($r) => ($caps[(int) $r['id']] ?? null) !== null));
            $total = count($rows);
            $pageRows = array_slice($rows, ($page - 1) * $per, $per);
            $items = FileRepository::summaries($pageRows, $viewer, ['access' => $caps]);
            $meta['folders'] = [];
            return ['items' => $items, 'total' => $total, 'page' => $page, 'per_page' => $per, 'meta' => $meta];
        }

        if ($view === 'recent') {
            $w[] = 'f.owner_id = :me';
            $p['me'] = $uid;
        } elseif ($folderId !== null) {
            $folder = FileAccess::requireFolder($viewer, (int) $folderId, 'view');
            $w[] = 'f.owner_id = :owner';
            $w[] = 'f.folder_id = :fid';
            $p['owner'] = (int) $folder['owner_id'];
            $p['fid'] = (int) $folder['id'];
            $meta['folder'] = FileRepository::folderSummary($folder, $viewer, ['access' => [(int) $folder['id'] => $folder['access']]]);
            $meta['breadcrumbs'] = FileRepository::breadcrumbs($viewer, (int) $folder['id']);
            if ($page === 1) {
                self::markFolderOpened($viewer, $folder);
            }
        } else {
            $w[] = 'f.owner_id = :me';
            $w[] = 'f.folder_id IS NULL';
            $p['me'] = $uid;
        }
        $where = implode(' AND ', $w);
        $total = (int) Db::value("SELECT COUNT(*) FROM files f WHERE {$where}", $p);
        $col = FileRepository::SORTS[$sort];
        $rows = Db::all(
            "SELECT f.*, b.encryption AS blob_encryption FROM files f LEFT JOIN file_blobs b ON b.id = f.blob_id
              WHERE {$where} ORDER BY f.{$col} {$order}, f.id {$order} LIMIT :lim OFFSET :off",
            $p + ['lim' => $per, 'off' => ($page - 1) * $per]
        );
        $items = FileRepository::summaries($rows, $viewer);
        if ($page === 1 && $view === 'all') {
            // the parent was authorised above; subfolders share its owner
            [$folderRows] = FolderService::childRows($folder !== null ? (int) $folder['owner_id'] : $uid, $folder !== null ? (int) $folder['id'] : null, $q, 500);
            $meta['folders'] = FileRepository::folderSummaries($folderRows, $viewer);
        } elseif ($page === 1) {
            $meta['folders'] = [];
        }
        return ['items' => $items, 'total' => $total, 'page' => $page, 'per_page' => $per, 'meta' => $meta];
    }

    /** @return array{0:string,1:string} whitelisted [sort, ORDER] */
    private static function sortFor(array $viewer, mixed $sort, mixed $order, string $view): array
    {
        $prefs = json_decode((string) ($viewer['preferences'] ?? ''), true);
        $prefs = is_array($prefs) ? $prefs : [];
        $defaultSort = $view === 'recent' ? 'updated_at' : (is_string($prefs['sort'] ?? null) && isset(FileRepository::SORTS[$prefs['sort']]) ? $prefs['sort'] : 'created_at');
        $defaultOrder = $view === 'recent' ? 'desc' : (in_array($prefs['order'] ?? null, ['asc', 'desc'], true) ? $prefs['order'] : ($defaultSort === 'name' ? 'asc' : 'desc'));
        $s = is_string($sort) && isset(FileRepository::SORTS[$sort]) ? $sort : $defaultSort;
        $ord = is_string($order) && in_array(strtolower($order), ['asc', 'desc'], true) ? strtolower($order) : $defaultOrder;
        return [$s, strtoupper($ord)];
    }

    /** GET /files/{id}: FileSummary + versions_count, path, breadcrumbs, shares (owner/admin only). */
    public static function show(array $viewer, int $id): array
    {
        $file = FileAccess::require($viewer, $id, 'view', true);
        $caps = $file['access'];
        unset($file['access']);
        $summary = FileRepository::summary($file, $viewer, ['access' => [$id => $caps], 'trash' => true]);
        $summary['versions_count'] = (int) Db::value('SELECT COUNT(*) FROM file_versions WHERE file_id = ?', [$id]);
        $crumbs = $file['deleted_at'] === null ? FileRepository::breadcrumbs($viewer, $file['folder_id'] !== null ? (int) $file['folder_id'] : null) : [];
        $summary['breadcrumbs'] = $crumbs;
        $summary['path'] = FileRepository::pathOf($crumbs);
        if (in_array($caps['role'], ['owner', 'admin'], true)) {
            $summary['shares'] = self::sharesOf($id);
        }
        return $summary;
    }

    /** Minimal share list for the owner's details panel (never contains tokens or passwords). */
    private static function sharesOf(int $fileId): array
    {
        $now = Db::now();
        $rows = Db::all(
            'SELECT * FROM shares WHERE (file_id = :f OR id IN (SELECT share_id FROM share_items WHERE file_id = :f2))
               AND revoked_at IS NULL ORDER BY created_at DESC LIMIT 100',
            ['f' => $fileId, 'f2' => $fileId]
        );
        $users = FileRepository::userRefs(array_merge(
            array_map(static fn ($s) => (int) ($s['recipient_id'] ?? 0), $rows),
            array_map(static fn ($s) => (int) $s['owner_id'], $rows)
        ));
        return array_map(static function (array $s) use ($users, $now): array {
            $status = 'active';
            if ($s['expires_at'] !== null && (string) $s['expires_at'] <= $now) {
                $status = 'expired';
            } elseif ($s['max_downloads'] !== null && (int) $s['download_count'] >= (int) $s['max_downloads']) {
                $status = 'exhausted';
            }
            return [
                'id'             => (int) $s['id'],
                'kind'           => (string) $s['kind'],
                'target_type'    => (string) $s['target_type'],
                'recipient'      => $s['recipient_id'] !== null ? ($users[(int) $s['recipient_id']] ?? null) : null,
                'owner'          => $users[(int) $s['owner_id']] ?? null,
                'permission'     => (string) $s['permission'],
                'has_password'   => $s['password_hash'] !== null && $s['password_hash'] !== '',
                'expires_at'     => Db::iso($s['expires_at']),
                'max_downloads'  => $s['max_downloads'] !== null ? (int) $s['max_downloads'] : null,
                'download_count' => (int) $s['download_count'],
                'status'         => $status,
                'created_at'     => Db::iso($s['created_at']),
            ];
        }, $rows);
    }

    // ================================================================== metadata changes

    /**
     * PATCH /files/{id}: {name?, folder_id?, description?, is_permanent?, tags?, favorite?, on_conflict?}
     * Returns the FileSummary for the viewer.
     */
    public static function update(array $viewer, int $id, array $in): array
    {
        $file = FileAccess::require($viewer, $id, 'view');
        $caps = $file['access'];
        if (array_key_exists('favourite', $in) && !array_key_exists('favorite', $in)) {
            $in['favorite'] = $in['favourite'];
        }
        $fields = array_intersect(array_keys($in), ['name', 'folder_id', 'description', 'is_permanent', 'tags', 'favorite']);
        if ($fields === []) {
            throw ApiException::validation(['name' => 'Nothing to change.'], 'Nothing to change.');
        }

        // ---- validate everything first (no partial updates on bad input)
        $errors = [];
        $name = null;
        if (array_key_exists('name', $in)) {
            if (!is_string($in['name']) || trim($in['name']) === '') {
                $errors['name'] = 'Enter a file name.';
            } else {
                $name = FileRepository::sanitizeName(trim($in['name']));
            }
        }
        $target = null;
        if (array_key_exists('folder_id', $in)) {
            try {
                $target = FolderService::parseFolderId($in['folder_id']);
            } catch (ApiException) {
                $errors['folder_id'] = 'Choose a valid folder.';
            }
        }
        $description = null;
        if (array_key_exists('description', $in)) {
            if ($in['description'] !== null && !is_string($in['description'])) {
                $errors['description'] = 'The description must be text.';
            } else {
                $description = self::cleanDescription($in['description']);
                if ($description !== null && mb_strlen($description) > 1000) {
                    $errors['description'] = 'The description can be at most 1,000 characters.';
                }
            }
        }
        $permanent = null;
        if (array_key_exists('is_permanent', $in)) {
            $permanent = self::parseBool($in['is_permanent']);
            if ($permanent === null) {
                $errors['is_permanent'] = 'Choose yes or no.';
            }
        }
        $tags = null;
        if (array_key_exists('tags', $in)) {
            try {
                $tags = TagService::normaliseList($in['tags'] ?? []);
            } catch (ApiException $e) {
                $errors['tags'] = (string) ($e->details['fields']['tags'] ?? 'Invalid tags.');
            }
        }
        $favorite = null;
        if (array_key_exists('favorite', $in)) {
            $favorite = self::parseBool($in['favorite']);
            if ($favorite === null) {
                $errors['favorite'] = 'Choose yes or no.';
            }
        }
        $onConflict = ($in['on_conflict'] ?? 'error') === 'rename' ? 'rename' : 'error';
        if ($errors !== []) {
            throw ApiException::validation($errors);
        }

        // ---- capabilities
        $needsEdit = $name !== null || array_key_exists('description', $in) || $permanent !== null || $tags !== null;
        if ($needsEdit && empty($caps['edit'])) {
            throw ApiException::forbidden();
        }
        if (array_key_exists('folder_id', $in) && empty($caps['move'])) {
            // Forms often resend the unchanged folder with a rename: that is not a move. For a
            // recipient the visible folder may be hidden (null) — echoing it back is not one either.
            $current = $file['folder_id'] !== null ? (int) $file['folder_id'] : null;
            $shown = $target === null && $current !== null
                ? FileRepository::summary(array_diff_key($file, ['access' => 1]), $viewer, ['access' => [$id => $caps]])['folder_id']
                : $current;
            if ($target !== $current && !($target === null && $shown === null)) {
                throw ApiException::forbidden();
            }
            unset($in['folder_id']);
            if (count(array_intersect(array_keys($in), ['name', 'description', 'is_permanent', 'tags', 'favorite'])) === 0) {
                return FileRepository::summary(array_diff_key($file, ['access' => 1]), $viewer, ['access' => [$id => $caps]]);
            }
        }

        $after = [];
        Db::transaction(static function () use ($viewer, $id, $name, $target, $in, $description, $permanent, $tags, $favorite, $onConflict, &$after): void {
            $row = Db::one('SELECT * FROM files WHERE id = ? AND deleted_at IS NULL FOR UPDATE', [$id]) ?? throw ApiException::fileNotFound();
            if (array_key_exists('folder_id', $in)) {
                $after[] = self::applyMove($viewer, $row, $target, $onConflict);
                $row = Db::one('SELECT * FROM files WHERE id = ?', [$id]);
            }
            if ($name !== null) {
                $after[] = self::applyRename($viewer, $row, $name);
                $row = Db::one('SELECT * FROM files WHERE id = ?', [$id]);
            }
            $changes = [];
            $set = [];
            if (array_key_exists('description', $in) && $description !== ($row['description'] !== '' ? $row['description'] : null)) {
                $set['description'] = $description;
                $changes[] = 'description';
            }
            if ($permanent !== null && $permanent !== ((int) $row['is_permanent'] === 1)) {
                $set += self::permanenceSet($permanent);
                $changes[] = 'is_permanent';
            }
            if ($set !== []) {
                Db::update('files', $set + ['updated_at' => Db::now(), 'updated_by' => (int) $viewer['id']], ['id' => $id]);
            }
            if ($tags !== null) {
                $before = TagService::tagsFor($id);
                $now = TagService::setTags($id, (int) $row['owner_id'], $tags);
                if ($before !== $now) {
                    Db::update('files', ['updated_at' => Db::now(), 'updated_by' => (int) $viewer['id']], ['id' => $id]);
                    $changes[] = 'tags';
                }
            }
            if ($changes !== []) {
                foreach ($changes as $c) {
                    Audit::log('file.edit', [
                        'user_id' => (int) $viewer['id'], 'target_type' => 'file', 'target_id' => $id, 'owner_id' => (int) $row['owner_id'], 'detail' => (string) $row['name'],
                        'meta' => ['changes' => [$c]] + ($c === 'is_permanent' ? ['is_permanent' => $permanent] : []),
                    ]);
                }
                $eventChanges = in_array('is_permanent', $changes, true) ? array_merge($changes, ['expires_at']) : $changes;
                $after[] = static function () use ($id, $eventChanges): void {
                    $fresh = FileRepository::find($id);
                    if ($fresh !== null) {
                        EventBus::publish('file.updated', ['file' => FileRepository::eventSummary($fresh), 'changes' => $eventChanges], EventBus::fileAudience($id), ['file_id' => $id, 'folder_id' => $fresh['folder_id'] !== null ? (int) $fresh['folder_id'] : null]);
                    }
                };
            }
            if ($favorite !== null) {
                $after[] = self::applyFavorite($viewer, $row, $favorite);
            }
        });
        foreach ($after as $fn) {
            if (is_callable($fn)) {
                $fn();
            }
        }
        $fresh = FileRepository::find($id) ?? throw ApiException::fileNotFound();
        FileAccess::reset();
        return FileRepository::summary($fresh, $viewer);
    }

    /** Rename inside the caller's transaction; returns the post-commit event closure. */
    private static function applyRename(array $viewer, array $row, string $name): ?callable
    {
        $id = (int) $row['id'];
        $old = (string) $row['name'];
        if ($name === $old) {
            return null;
        }
        $owner = (int) $row['owner_id'];
        $folderId = $row['folder_id'] !== null ? (int) $row['folder_id'] : null;
        if (FileRepository::fileNameTaken($owner, $folderId, $name, $id)) {
            throw ApiException::conflict('A file with this name already exists in this folder.', 'NAME_CONFLICT', ['name' => $name]);
        }
        $ext = MimeDetector::extension($name);
        Db::update('files', [
            'name' => $name, 'ext' => $ext, 'kind' => MimeDetector::kindFor($ext, (string) $row['mime']),
            'updated_at' => Db::now(), 'updated_by' => (int) $viewer['id'],
        ], ['id' => $id]);
        Audit::log('file.rename', [
            'user_id' => (int) $viewer['id'], 'target_type' => 'file', 'target_id' => $id, 'owner_id' => $owner, 'detail' => $old . ' → ' . $name,
            'meta' => ['from' => $old, 'to' => $name],
        ]);
        return static function () use ($id, $old): void {
            $fresh = FileRepository::find($id);
            if ($fresh !== null) {
                EventBus::publish('file.renamed', ['file' => FileRepository::eventSummary($fresh), 'old_name' => $old], EventBus::fileAudience($id), ['file_id' => $id, 'folder_id' => $fresh['folder_id'] !== null ? (int) $fresh['folder_id'] : null]);
            }
        };
    }

    /**
     * Move inside the caller's transaction (owner/admin only — checked by the caller). The target
     * must be a live folder of the SAME owner (or null = the owner's root).
     */
    private static function applyMove(array $viewer, array $row, ?int $target, string $onConflict): ?callable
    {
        $id = (int) $row['id'];
        $owner = (int) $row['owner_id'];
        $from = $row['folder_id'] !== null ? (int) $row['folder_id'] : null;
        if ($target === $from) {
            return null;
        }
        $folderName = null;
        if ($target !== null) {
            $f = Db::one('SELECT id, owner_id, name, deleted_at FROM folders WHERE id = ?', [$target]);
            if ($f === null || $f['deleted_at'] !== null || (int) $f['owner_id'] !== $owner) {
                throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
            }
            $folderName = (string) $f['name'];
        }
        $before = EventBus::fileAudience($id);
        $name = (string) $row['name'];
        if (FileRepository::fileNameTaken($owner, $target, $name, $id)) {
            if ($onConflict !== 'rename') {
                throw ApiException::conflict('A file with this name already exists in the destination folder.', 'NAME_CONFLICT', ['name' => $name]);
            }
            $name = FileRepository::uniqueName($owner, $target, $name, $id);
        }
        Db::update('files', ['folder_id' => $target, 'name' => $name, 'updated_at' => Db::now(), 'updated_by' => (int) $viewer['id']], ['id' => $id]);
        Audit::log('file.move', [
            'user_id' => (int) $viewer['id'], 'target_type' => 'file', 'target_id' => $id, 'owner_id' => $owner, 'detail' => $folderName ?? 'My Files',
            'meta' => ['from_folder_id' => $from, 'to_folder_id' => $target, 'folder' => $folderName ?? 'My Files'],
        ]);
        return static function () use ($id, $from, $target, $before): void {
            $fresh = FileRepository::find($id);
            if ($fresh === null) {
                return;
            }
            $audience = array_values(array_unique(array_merge($before, EventBus::fileAudience($id))));
            EventBus::publish('file.moved', ['file' => FileRepository::eventSummary($fresh), 'from_folder_id' => $from, 'to_folder_id' => $target], $audience, ['file_id' => $id, 'folder_id' => $target]);
        };
    }

    /** Per-user favourite flag. Returns the post-commit event closure. */
    private static function applyFavorite(array $viewer, array $row, bool $on): ?callable
    {
        $id = (int) $row['id'];
        $uid = (int) $viewer['id'];
        $changed = $on
            ? Db::run('INSERT IGNORE INTO favorites (user_id, file_id, created_at) VALUES (?, ?, ?)', [$uid, $id, Db::now()])->rowCount() > 0
            : Db::run('DELETE FROM favorites WHERE user_id = ? AND file_id = ?', [$uid, $id])->rowCount() > 0;
        if (!$changed) {
            return null;
        }
        Audit::log('file.favorite', [
            'user_id' => (int) $viewer['id'], 'target_type' => 'file', 'target_id' => $id, 'owner_id' => (int) $row['owner_id'], 'detail' => $on ? 'added' : 'removed',
            'meta' => ['favorite' => $on],
        ]);
        $name = (string) $row['name'];
        return static function () use ($id, $uid, $on, $viewer, $name): void {
            $fresh = FileRepository::find($id);
            if ($fresh !== null) {
                // favourites are per user: only the user's own devices hear about it
                EventBus::publish('file.updated', ['file' => FileRepository::eventSummary($fresh), 'changes' => ['favorite'], 'favorite' => $on], [$uid], ['file_id' => $id]);
            }
            self::slack('favorite', [
                'Action' => $on ? 'Added to favourites' : 'Removed from favourites',
                'Name' => $name, 'By' => FileRepository::displayName($viewer), 'Time' => self::slackTime(),
            ]);
        };
    }

    /** Columns for "Keep forever" on/off (legacy auto-expiry). */
    private static function permanenceSet(bool $permanent): array
    {
        if ($permanent) {
            return ['is_permanent' => 1, 'expires_at' => null];
        }
        $hours = Settings::int('auto_expire_hours', 72);
        return ['is_permanent' => 0, 'expires_at' => $hours > 0 ? Db::ts(time() + $hours * 3600) : null];
    }

    // ================================================================== trash entry points

    /** DELETE /files/{id}: to Trash; ?permanent=1 deletes an item already in the Trash. */
    public static function destroy(array $viewer, int $id, bool $permanent): void
    {
        if (!Policy::isAdmin($viewer)) {
            Policy::requirePermission($viewer, 'files.delete');
        }
        if ($permanent) {
            $file = FileAccess::require($viewer, $id, 'delete', true);
            if ($file['deleted_at'] === null) {
                throw ApiException::conflict('Move the file to the Trash before deleting it permanently.', 'NOT_IN_TRASH');
            }
            TrashService::purgeFile($file, $viewer);
            return;
        }
        $file = FileAccess::require($viewer, $id, 'delete');
        TrashService::trashFile($file, $viewer);
    }

    /** POST /files/{id}/restore and /trash/{id}/restore. Returns the FileSummary. */
    public static function restore(array $viewer, int $id): array
    {
        $file = FileAccess::require($viewer, $id, 'delete', true);
        $row = TrashService::restoreFile($file, $viewer);
        return FileRepository::summary($row, $viewer);
    }

    /**
     * Maintenance (A6 auto_expire_files): files not marked "Keep forever" whose expires_at has
     * passed move to the Trash with reason "expired". Returns how many were moved.
     */
    public static function expireDue(int $limit = 200): int
    {
        $deadline = microtime(true) + 10.0; // maintenance slices share a ~20 s request budget
        $rows = Db::all(
            'SELECT * FROM files WHERE is_permanent = 0 AND expires_at IS NOT NULL AND expires_at <= :now AND deleted_at IS NULL
              ORDER BY expires_at ASC LIMIT :lim',
            ['now' => Db::now(), 'lim' => max(1, min(5000, $limit))]
        );
        $n = 0;
        foreach ($rows as $row) {
            if (microtime(true) > $deadline) {
                break;
            }
            try {
                TrashService::trashFile($row, null, 'expired', ['slack' => false]);
                $n++;
            } catch (ApiException) {
                // already trashed concurrently
            } catch (\Throwable $e) {
                Logger::warning('maintenance', 'Auto-expiry failed for a file', ['file_id' => (int) $row['id'], 'error' => $e->getMessage()]);
            }
        }
        return $n;
    }

    // ================================================================== content

    /** GET /files/{id}/download */
    public static function download(Request $req, array $viewer, int $id): void
    {
        $file = FileAccess::require($viewer, $id, 'download');
        $blob = self::blobFor($file);
        if (self::countsAsDownload($req)) {
            self::recordDownload($viewer, $file);
        } else {
            Db::run('UPDATE files SET last_accessed_at = ? WHERE id = ?', [Db::now(), $id]);
        }
        self::markOpened($req, $viewer, $file);
        unset($file['access']);
        self::stream($file, $blob, $req, false, (string) $file['name']);
    }

    /** GET /files/{id}/content — inline, safe preview. */
    public static function content(Request $req, array $viewer, int $id): void
    {
        $file = FileAccess::require($viewer, $id, 'preview');
        if (MimeDetector::inlineType((string) $file['mime'], (string) $file['ext']) === null) {
            throw new ApiException('BAD_REQUEST', 'This type of file cannot be previewed. Download it instead.', 415);
        }
        $blob = self::blobFor($file);
        $uid = (int) $viewer['id'];
        $recent = Db::value(
            "SELECT 1 FROM audit_logs WHERE target_type = 'file' AND target_id = :f AND action = 'file.preview' AND user_id = :u AND created_at > :since LIMIT 1",
            ['f' => $id, 'u' => $uid, 'since' => Db::ts(time() - 600)]
        );
        if ($recent === null) {
            Audit::log('file.preview', ['user_id' => (int) $viewer['id'], 'target_type' => 'file', 'target_id' => $id, 'owner_id' => (int) $file['owner_id'], 'detail' => (string) $file['name']]);
        }
        Db::run('UPDATE files SET last_accessed_at = ? WHERE id = ?', [Db::now(), $id]);
        self::markOpened($req, $viewer, $file);
        unset($file['access']);
        self::stream($file, $blob, $req, true, (string) $file['name']);
    }

    /**
     * Shared With Me "last accessed" (A4): a recipient opened or downloaded a file shared with
     * them. Skipped for owners and for follow-up Range requests (media seeking), and throttled
     * by ShareService itself; never fails the request.
     */
    private static function markOpened(Request $req, array $viewer, array $file): void
    {
        if ((int) $file['owner_id'] === (int) $viewer['id'] || !method_exists(\FT\Sharing\ShareService::class, 'markOpened')) {
            return;
        }
        $range = trim((string) ($req->header('Range') ?? ''));
        if ($range !== '' && !preg_match('/^bytes=0-/i', $range)) {
            return;
        }
        $row = $file;
        unset($row['access']);
        \FT\Sharing\ShareService::markOpened((int) $viewer['id'], $row);
    }

    /** Same for a shared folder a recipient opened (folder listings). */
    public static function markFolderOpened(array $viewer, array $folder): void
    {
        if ((int) $folder['owner_id'] === (int) $viewer['id'] || !method_exists(\FT\Sharing\ShareService::class, 'markFolderOpened')) {
            return;
        }
        \FT\Sharing\ShareService::markFolderOpened((int) $viewer['id'], (int) $folder['id']);
    }

    /** GET /files/{id}/thumbnail */
    public static function thumbnail(Request $req, array $viewer, int $id): void
    {
        $file = FileAccess::require($viewer, $id, 'preview');
        $thumb = '\\FT\\Storage\\Thumbnailer';
        if ($file['thumb_version'] === null || !class_exists($thumb) || !method_exists($thumb, 'send')) {
            throw ApiException::notFound('thumbnail');
        }
        unset($file['access']);
        if (class_exists(\FT\Auth\Auth::class) && method_exists(\FT\Auth\Auth::class, 'closeSession')) {
            \FT\Auth\Auth::closeSession();
        }
        $thumb::send($file, $req);
    }

    /**
     * Count a download, audit it, notify the owner (non-owner downloads, once per downloader and
     * file per hour), update the owner's views and the admin dashboard.
     */
    public static function recordDownload(array $viewer, array $file): void
    {
        $id = (int) $file['id'];
        $owner = (int) $file['owner_id'];
        $uid = (int) $viewer['id'];
        Db::run('UPDATE files SET download_count = download_count + 1, last_accessed_at = ? WHERE id = ?', [Db::now(), $id]);
        Audit::log('file.download', ['user_id' => (int) $viewer['id'], 'target_type' => 'file', 'target_id' => $id, 'owner_id' => $owner, 'detail' => (string) $file['name']]);
        Stats::bump('downloads');
        $fresh = FileRepository::find($id);
        if ($fresh !== null) {
            EventBus::publish('file.updated', ['file' => FileRepository::eventSummary($fresh), 'changes' => ['download_count']], [$owner], ['file_id' => $id]);
        }
        EventBus::publish('stats.updated', ['metric' => 'downloads', 'delta' => 1], [], ['admin' => true]);
        $who = FileRepository::displayName($viewer);
        if ($uid !== $owner) {
            self::notify($owner, 'download', 'file.downloaded', "{$who} downloaded “{$file['name']}”", '', [
                'file_id' => $id, 'link' => '#/files' . ($file['folder_id'] !== null ? '/' . (int) $file['folder_id'] : ''),
            ], 'download:' . $id . ':' . $uid . ':' . gmdate('YmdH'), $uid);
        }
        self::slack('download', ['Name' => (string) $file['name'], 'By' => $who, 'Time' => self::slackTime()]);
    }

    /** Full downloads count; Range requests for later parts (media seeking, resumes) and cache revalidations do not. */
    public static function countsAsDownload(Request $req): bool
    {
        if ($req->header('If-None-Match') !== null) {
            return false; // a revalidation (304) is not a new download
        }
        $range = $req->header('Range');
        if ($range === null || trim($range) === '') {
            return true;
        }
        return (bool) preg_match('/^bytes=0-/i', trim($range));
    }

    /**
     * Stream content through A2's FileStreamer (Range, ETag, safe headers). A minimal built-in
     * streamer is used only when FileStreamer is not installed.
     */
    public static function stream(array $file, array $blob, Request $req, bool $inline, ?string $name = null): void
    {
        $streamer = '\\FT\\Storage\\FileStreamer';
        if (class_exists($streamer) && method_exists($streamer, 'send')) {
            try {
                $streamer::send($file, $blob, $req, $inline, $name);
            } catch (ApiException $e) {
                throw $e;
            } catch (\RuntimeException $e) {
                if (!headers_sent()) {
                    Logger::warning('app', 'Stored file unavailable', ['file_id' => (int) $file['id'], 'error' => $e->getMessage()]);
                    throw self::unavailable();
                }
                Logger::warning('app', 'Stream interrupted', ['file_id' => (int) $file['id'], 'error' => $e->getMessage()]);
            }
            return;
        }
        self::fallbackStream($file, $blob, $req, $inline, $name ?? (string) $file['name']);
    }

    public static function unavailable(): ApiException
    {
        return new ApiException('FILE_UNAVAILABLE', 'This file is unavailable: its stored data is missing or damaged.', 410);
    }

    private static function blobFor(array $file): array
    {
        try {
            $blob = BlobStore::get((int) $file['blob_id']);
        } catch (\Throwable) {
            throw self::unavailable();
        }
        if (!BlobStore::isIntact($blob)) {
            Logger::warning('app', 'Stored file missing or damaged', ['file_id' => (int) $file['id'], 'blob_id' => (int) $file['blob_id']]);
            throw self::unavailable();
        }
        return $blob;
    }

    /** Minimal single-range streamer (used only until A2's FileStreamer is present). */
    private static function fallbackStream(array $file, array $blob, Request $req, bool $inline, string $name): void
    {
        try {
            $reader = BlobStore::open($blob);
        } catch (\Throwable) {
            throw self::unavailable();
        }
        $size = $reader->size();
        $start = 0;
        $end = $size - 1;
        $status = 200;
        $range = $req->header('Range');
        if ($range !== null && preg_match('/^bytes=(\d*)-(\d*)$/', trim($range), $m) && ($m[1] !== '' || $m[2] !== '')) {
            if ($m[1] === '') {
                $start = max(0, $size - (int) $m[2]);
            } else {
                $start = (int) $m[1];
                if ($m[2] !== '') {
                    $end = min((int) $m[2], $size - 1);
                }
            }
            if ($start > $end || $start >= $size) {
                http_response_code(416);
                header('Content-Range: bytes */' . $size);
                return;
            }
            $status = 206;
        }
        $type = 'application/octet-stream';
        if ($inline) {
            $type = MimeDetector::inlineType((string) $file['mime'], (string) $file['ext']) ?? 'application/octet-stream';
        }
        if (class_exists(\FT\Auth\Auth::class) && method_exists(\FT\Auth\Auth::class, 'closeSession')) {
            \FT\Auth\Auth::closeSession();
        }
        Db::disconnect();
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        http_response_code($status);
        header('Content-Type: ' . $type);
        header('Content-Disposition: ' . Response::contentDisposition($name, $inline && $type !== 'application/octet-stream'));
        header('Content-Length: ' . ($size === 0 ? 0 : $end - $start + 1));
        header('Accept-Ranges: bytes');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: private, no-store');
        header("Content-Security-Policy: default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox");
        if ($status === 206) {
            header("Content-Range: bytes {$start}-{$end}/{$size}");
        }
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'HEAD' || $size === 0) {
            return;
        }
        $reader->seek($start);
        $left = $end - $start + 1;
        while ($left > 0) {
            $chunk = $reader->read(min(1048576, $left));
            if ($chunk === '') {
                break;
            }
            echo $chunk;
            $left -= strlen($chunk);
            flush();
            if (PHP_SAPI !== 'cli' && connection_aborted()) {
                break;
            }
        }
        $reader->close();
    }

    // ================================================================== batch + zip

    /**
     * POST /files/batch {action, ids, folder_id?, tag?, value?} → {done, failed}
     * Each item is authorised and applied on its own; failures are reported per item.
     */
    public static function batch(array $viewer, array $in): array
    {
        $action = is_string($in['action'] ?? null) ? $in['action'] : '';
        if (!in_array($action, self::BATCH_ACTIONS, true)) {
            throw ApiException::validation(['action' => 'Unknown batch action.']);
        }
        $ids = self::parseIds($in['ids'] ?? null, 'ids', self::MAX_BATCH);
        $opts = [];
        if ($action === 'move') {
            if (!array_key_exists('folder_id', $in)) {
                throw ApiException::validation(['folder_id' => 'Choose a destination folder.']);
            }
            $opts['folder_id'] = FolderService::parseFolderId($in['folder_id']);
        }
        if ($action === 'tag' || $action === 'untag') {
            $tag = TagService::normalise($in['tag'] ?? null);
            if ($tag === null) {
                throw ApiException::validation(['tag' => 'Enter a tag (letters, digits, - and _).']);
            }
            $opts['tag'] = $tag;
        }
        if ($action === 'permanent') {
            $v = self::parseBool($in['value'] ?? true);
            if ($v === null) {
                throw ApiException::validation(['value' => 'Choose yes or no.']);
            }
            $opts['value'] = $v;
        }
        $done = [];
        $failed = [];
        $trashedNames = [];
        $deadline = microtime(true) + 20.0;
        foreach ($ids as $id) {
            if (microtime(true) > $deadline) {
                $failed[] = ['id' => $id, 'code' => 'RATE_LIMITED', 'message' => 'Not processed: the request took too long. Please try again.'];
                continue;
            }
            try {
                FileAccess::reset();
                switch ($action) {
                    case 'trash':
                        if (!Policy::isAdmin($viewer)) {
                            Policy::requirePermission($viewer, 'files.delete');
                        }
                        $row = TrashService::trashFile(FileAccess::require($viewer, $id, 'delete'), $viewer, 'user', ['slack' => false]);
                        $trashedNames[] = (string) $row['name'];
                        break;
                    case 'restore':
                        TrashService::restoreFile(FileAccess::require($viewer, $id, 'delete', true), $viewer);
                        break;
                    case 'purge':
                        if (!Policy::isAdmin($viewer)) {
                            Policy::requirePermission($viewer, 'files.delete');
                        }
                        TrashService::purgeFile(FileAccess::require($viewer, $id, 'delete', true), $viewer);
                        break;
                    case 'move':
                        self::update($viewer, $id, ['folder_id' => $opts['folder_id']]);
                        break;
                    case 'favorite':
                    case 'unfavorite':
                        self::update($viewer, $id, ['favorite' => $action === 'favorite']);
                        break;
                    case 'permanent':
                        self::update($viewer, $id, ['is_permanent' => $opts['value']]);
                        break;
                    case 'tag':
                    case 'untag':
                        $file = FileAccess::require($viewer, $id, 'edit');
                        $before = TagService::tagsFor($id);
                        $now = $action === 'tag'
                            ? TagService::addTags($id, (int) $file['owner_id'], [$opts['tag']])
                            : TagService::removeTags($id, (int) $file['owner_id'], [$opts['tag']]);
                        if ($before !== $now) {
                            Db::update('files', ['updated_at' => Db::now(), 'updated_by' => (int) $viewer['id']], ['id' => $id]);
                            Audit::log('file.edit', ['user_id' => (int) $viewer['id'], 'target_type' => 'file', 'target_id' => $id, 'owner_id' => (int) $file['owner_id'], 'detail' => (string) $file['name'], 'meta' => ['changes' => ['tags']]]);
                            $fresh = FileRepository::find($id);
                            if ($fresh !== null) {
                                EventBus::publish('file.updated', ['file' => FileRepository::eventSummary($fresh), 'changes' => ['tags']], EventBus::fileAudience($id), ['file_id' => $id]);
                            }
                        }
                        break;
                }
                $done[] = $id;
            } catch (ApiException $e) {
                $failed[] = ['id' => $id, 'code' => $e->errorCode, 'message' => $e->getMessage()];
            }
        }
        if ($trashedNames !== []) {
            self::slack('batch_delete', ['Files Deleted' => (string) count($trashedNames), 'By' => FileRepository::displayName($viewer), 'Time' => self::slackTime()]);
        }
        return ['done' => $done, 'failed' => $failed];
    }

    /**
     * POST /files/zip and GET /folders/{id}/zip: stream a ZIP of everything in the request the
     * viewer may download. Items they cannot see or download are left out (count in the
     * X-FT-Skipped header); nothing at all → 404.
     */
    public static function zip(array $viewer, array $fileIds, array $folderIds, string $name = ''): void
    {
        $fileIds = array_slice(array_values(array_unique($fileIds)), 0, ZipService::MAX_ENTRIES + 1);
        $folderIds = array_slice(array_values(array_unique($folderIds)), 0, 100);
        if ($fileIds === [] && $folderIds === []) {
            throw ApiException::validation(['file_ids' => 'Choose at least one file or folder.']);
        }
        $entries = [];
        $skipped = 0;
        $owners = [];
        if ($fileIds !== []) {
            $rows = array_filter(FileRepository::findMany($fileIds), static fn ($r) => $r['deleted_at'] === null);
            $caps = FileAccess::accessForMany($viewer, array_values($rows));
            foreach ($fileIds as $fid) {
                $row = $rows[$fid] ?? null;
                if ($row === null || empty($caps[$fid]['download'])) {
                    $skipped++;
                    continue;
                }
                $entries[] = ['file' => $row, 'path' => (string) $row['name']];
                $owners[(int) $row['owner_id']] = true;
            }
        }
        $singleFolder = null;
        foreach ($folderIds as $fid) {
            try {
                $folder = FileAccess::requireFolder($viewer, (int) $fid, 'view');
            } catch (ApiException) {
                $skipped++;
                continue;
            }
            $singleFolder = count($folderIds) === 1 && $fileIds === [] ? $folder : null;
            $folderEntries = ZipService::folderEntries($folder, null, null, ZipService::MAX_ENTRIES + 1);
            $fileRows = [];
            foreach ($folderEntries as $e) {
                if (isset($e['file'])) {
                    $fileRows[] = $e['file'];
                }
            }
            $caps = FileAccess::accessForMany($viewer, $fileRows);
            foreach ($folderEntries as $e) {
                if (isset($e['file']) && empty($caps[(int) $e['file']['id']]['download'])) {
                    $skipped++;
                    continue;
                }
                $entries[] = $e;
            }
            $owners[(int) $folder['owner_id']] = true;
        }
        $m = ZipService::measure($entries);
        // an empty folder may be downloaded as an (empty) archive; files you may not download may not
        if ($m['files'] === 0 && ($skipped > 0 || $singleFolder === null || $m['entries'] === 0)) {
            throw new ApiException('FILE_NOT_FOUND', 'There is nothing you can download here.', 404);
        }
        if ($m['entries'] > ZipService::MAX_ENTRIES) {
            throw ApiException::tooLarge('Too many items for one ZIP download (at most ' . number_format(ZipService::MAX_ENTRIES) . '). Choose fewer files.');
        }
        $maxBytes = max(1, Settings::int('max_upload_bytes', 209715200)) * 10;
        if ($m['bytes'] > $maxBytes) {
            throw ApiException::tooLarge('These files are too large to download as one ZIP. Choose fewer files.');
        }
        $zipName = $name !== '' ? $name : ($singleFolder !== null ? (string) $singleFolder['name'] : 'FastTransfer ' . gmdate('Y-m-d H-i'));
        $ownerIds = array_keys($owners);
        $uid = (int) $viewer['id'];
        Audit::log('file.download', [
            'user_id' => (int) $viewer['id'], 'target_type' => $singleFolder !== null ? 'folder' : null,
            'target_id' => $singleFolder !== null ? (int) $singleFolder['id'] : null,
            'owner_id' => count($ownerIds) === 1 ? $ownerIds[0] : null,
            'detail' => 'ZIP: ' . ZipService::zipFileName($zipName) . ' (' . $m['files'] . ' ' . ($m['files'] === 1 ? 'file' : 'files') . ')',
            'meta' => ['zip' => true, 'files' => $m['files'], 'bytes' => $m['bytes'], 'skipped' => $skipped],
        ]);
        if (Policy::isAdmin($viewer) && array_diff($ownerIds, [$uid]) !== []) {
            Audit::log('admin.file_access', ['user_id' => $uid, 'category' => 'admin', 'target_type' => $singleFolder !== null ? 'folder' : null, 'target_id' => $singleFolder !== null ? (int) $singleFolder['id'] : null, 'detail' => 'zip', 'meta' => ['files' => $m['files']]]);
        }
        Stats::bump('downloads');
        EventBus::publish('stats.updated', ['metric' => 'downloads', 'delta' => 1], [], ['admin' => true]);
        if ($skipped > 0 && !headers_sent()) {
            header('X-FT-Skipped: ' . $skipped);
        }
        ZipService::stream($entries, $zipName);
    }

    // ================================================================== helpers

    /**
     * Parse a list of positive ids from JSON arrays, form arrays or "1,2,3" strings.
     * @return int[]
     */
    public static function parseIds(mixed $v, string $field, int $max, bool $required = true): array
    {
        if ($v === null || $v === '') {
            if ($required) {
                throw ApiException::validation([$field => 'Choose at least one item.']);
            }
            return [];
        }
        if (is_string($v)) {
            $decoded = json_decode($v, true);
            $v = is_array($decoded) ? $decoded : explode(',', $v);
        }
        if (is_int($v)) {
            $v = [$v];
        }
        if (!is_array($v)) {
            throw ApiException::validation([$field => 'Send a list of ids.']);
        }
        $ids = [];
        foreach ($v as $item) {
            if (is_int($item) && $item > 0) {
                $ids[] = $item;
            } elseif (is_string($item) && ctype_digit(trim($item)) && (int) trim($item) > 0 && strlen(trim($item)) <= 19) {
                $ids[] = (int) trim($item);
            } else {
                throw ApiException::validation([$field => 'Send a list of ids.']);
            }
        }
        $ids = array_values(array_unique($ids));
        if ($required && $ids === []) {
            throw ApiException::validation([$field => 'Choose at least one item.']);
        }
        if (count($ids) > $max) {
            throw ApiException::validation([$field => 'Choose at most ' . number_format($max) . ' items at a time.']);
        }
        return $ids;
    }

    /** true/false from JSON booleans, 1/0 and "true"/"false"; null when not a boolean. */
    public static function parseBool(mixed $v): ?bool
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

    private static function cleanDescription(?string $v): ?string
    {
        if ($v === null) {
            return null;
        }
        if (!mb_check_encoding($v, 'UTF-8')) {
            $v = mb_convert_encoding($v, 'UTF-8', 'UTF-8');
        }
        $v = trim((string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $v));
        return $v === '' ? null : $v;
    }

    /** Notifier (A5) — guarded: notifications are best effort. */
    public static function notify(int $userId, string $category, string $type, string $title, string $body = '', array $data = [], ?string $dedupe = null, ?int $actorId = null): void
    {
        $cls = '\\FT\\Notifications\\Notifier';
        if (!class_exists($cls) || !method_exists($cls, 'notify')) {
            return;
        }
        try {
            $cls::notify($userId, $category, $type, mb_substr($title, 0, 200), $body, $data, $dedupe, $actorId);
        } catch (\Throwable $e) {
            Logger::warning('app', 'Notification failed', ['type' => $type, 'error' => $e->getMessage()]);
        }
    }

    /** Slack (A5) — guarded and best effort; Slack::notify queues the outbound call. */
    public static function slack(string $event, array $fields): void
    {
        $cls = '\\FT\\Notifications\\Slack';
        if (!class_exists($cls) || !method_exists($cls, 'notify')) {
            return;
        }
        try {
            $cls::notify($event, $fields);
        } catch (\Throwable $e) {
            Logger::warning('app', 'Slack notification failed', ['event' => $event, 'error' => $e->getMessage()]);
        }
    }

    /** 24-hour time for Slack messages. */
    public static function slackTime(): string
    {
        return gmdate('d M Y, H:i') . ' UTC';
    }
}
