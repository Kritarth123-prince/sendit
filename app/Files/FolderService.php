<?php
declare(strict_types=1);

namespace FT\Files;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Events\EventBus;
use FT\Security\Policy;

/**
 * Folders: create, rename, move (with cycle prevention), tree, contents, breadcrumbs.
 *
 * Ownership: a folder created inside someone else's shared folder (editor access) belongs to
 * that folder's owner — the same rule as uploads — so a subtree always has a single owner and
 * trash/quota/share semantics stay simple.
 */
final class FolderService
{
    /** Deepest allowed nesting (EventBus/FileAccess walk at most 64 levels). */
    public const MAX_DEPTH = 60;

    /** Create a folder in $parentId (null = the user's own root). Returns the folders row. */
    public static function create(array $user, string $name, ?int $parentId): array
    {
        $raw = trim($name);
        if ($raw === '') {
            throw ApiException::validation(['name' => 'Enter a folder name.']);
        }
        $parentId = FileAccess::requireFolderWrite($user, $parentId);
        $owner = FileAccess::contentOwnerFor($user, $parentId);
        if ($parentId !== null && count(EventBus::ancestorFolderIds($parentId)) >= self::MAX_DEPTH) {
            throw ApiException::validation(['parent_id' => 'Folders cannot be nested this deeply.']);
        }
        $name = FileRepository::sanitizeName($raw);
        $id = Db::transaction(static function () use ($owner, $parentId, $name, $user): int {
            if (FileRepository::folderNameTaken($owner, $parentId, $name)) {
                throw ApiException::conflict('A folder with this name already exists here.', 'NAME_CONFLICT', ['name' => $name]);
            }
            $now = Db::now();
            return Db::insert('folders', [
                'owner_id'   => $owner,
                'parent_id'  => $parentId,
                'name'       => $name,
                'created_by' => (int) $user['id'],
                'created_at' => $now,
                'updated_at' => $now,
            ]);
        });
        $row = self::row($id);
        EventBus::publish('folder.created', ['folder' => FileRepository::folderEventSummary($row)], EventBus::folderAudience($id), ['folder_id' => $id]);
        Audit::log('folder.create', [
            'user_id' => (int) $user['id'], 'target_type' => 'folder', 'target_id' => $id, 'owner_id' => $owner, 'detail' => $name,
            'meta' => ['parent_id' => $parentId],
        ]);
        return $row;
    }

    /**
     * PATCH /folders/{id}: {name?, parent_id?}. Returns the updated folders row.
     */
    public static function update(array $user, int $folderId, array $in): array
    {
        $folder = FileAccess::requireFolder($user, $folderId, 'view');
        $hasName = array_key_exists('name', $in);
        $hasParent = array_key_exists('parent_id', $in);
        if (!$hasName && !$hasParent) {
            throw ApiException::validation(['name' => 'Nothing to change.']);
        }
        if ($hasName) {
            if (!is_string($in['name']) || trim($in['name']) === '') {
                throw ApiException::validation(['name' => 'Enter a folder name.']);
            }
            if (empty($folder['access']['edit'])) {
                throw ApiException::forbidden();
            }
        }
        $newParent = null;
        $current = $folder['parent_id'] !== null ? (int) $folder['parent_id'] : null;
        if ($hasParent) {
            $newParent = self::parseFolderId($in['parent_id'], 'parent_id');
            if (empty($folder['access']['move'])) {
                // Resending the unchanged parent with a rename is not a move. A recipient sees a
                // parent above the shared root as null, so echoing that back is not one either.
                $shown = $newParent === null && $current !== null
                    ? FileRepository::folderSummary(array_diff_key($folder, ['access' => 1]), $user, ['access' => [(int) $folder['id'] => $folder['access']]])['parent_id']
                    : $current;
                if ($newParent !== $current && !($newParent === null && $shown === null)) {
                    throw ApiException::forbidden();
                }
                $hasParent = false;
                if (!$hasName) {
                    return $folder;
                }
            }
        }
        if ($hasParent && $newParent !== $current) {
            $folder = self::move($user, $folder, $newParent);
        }
        if ($hasName) {
            $folder = self::rename($user, $folder, (string) $in['name']);
        }
        return $folder;
    }

    public static function rename(array $user, array $folder, string $name): array
    {
        $id = (int) $folder['id'];
        $owner = (int) $folder['owner_id'];
        $new = FileRepository::sanitizeName(trim($name));
        $old = (string) $folder['name'];
        if ($new === $old) {
            return $folder;
        }
        $parent = $folder['parent_id'] !== null ? (int) $folder['parent_id'] : null;
        Db::transaction(static function () use ($owner, $parent, $new, $id): void {
            if (FileRepository::folderNameTaken($owner, $parent, $new, $id)) {
                throw ApiException::conflict('A folder with this name already exists here.', 'NAME_CONFLICT', ['name' => $new]);
            }
            Db::update('folders', ['name' => $new, 'updated_at' => Db::now()], ['id' => $id]);
        });
        $row = self::row($id);
        EventBus::publish('folder.updated', ['folder' => FileRepository::folderEventSummary($row), 'changes' => ['name'], 'old_name' => $old], EventBus::folderAudience($id), ['folder_id' => $id]);
        Audit::log('folder.rename', [
            'user_id' => (int) $user['id'], 'target_type' => 'folder', 'target_id' => $id, 'owner_id' => $owner, 'detail' => $old . ' → ' . $new,
            'meta' => ['from' => $old, 'to' => $new],
        ]);
        return $row;
    }

    /** Move a folder under $parentId (null = root of the owner's drive). FOLDER_CYCLE protected. */
    public static function move(array $user, array $folder, ?int $parentId, string $onConflict = 'error'): array
    {
        $id = (int) $folder['id'];
        $owner = (int) $folder['owner_id'];
        $from = $folder['parent_id'] !== null ? (int) $folder['parent_id'] : null;
        if ($parentId === $from) {
            return $folder;
        }
        $targetName = null;
        if ($parentId !== null) {
            if ($parentId === $id) {
                throw ApiException::conflict('A folder cannot be moved into itself.', 'FOLDER_CYCLE');
            }
            $target = Db::one('SELECT * FROM folders WHERE id = ?', [$parentId]);
            if ($target === null || $target['deleted_at'] !== null || (int) $target['owner_id'] !== $owner) {
                // the target must be a live folder of the same owner (never reveal others' folders)
                throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
            }
            if ((int) $target['owner_id'] !== (int) $user['id'] && !Policy::isAdmin($user)) {
                throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
            }
            $chain = EventBus::ancestorFolderIds($parentId);
            if (in_array($id, $chain, true)) {
                throw ApiException::conflict('A folder cannot be moved into one of its own subfolders.', 'FOLDER_CYCLE');
            }
            if (count($chain) + self::depthBelow($owner, $id) >= self::MAX_DEPTH) {
                throw ApiException::validation(['parent_id' => 'Folders cannot be nested this deeply.']);
            }
            $targetName = (string) $target['name'];
        }
        $before = EventBus::folderAudience($id);
        $name = (string) $folder['name'];
        Db::transaction(static function () use ($owner, $parentId, $id, &$name, $onConflict): void {
            if (FileRepository::folderNameTaken($owner, $parentId, $name, $id)) {
                if ($onConflict !== 'rename') {
                    throw ApiException::conflict('A folder with this name already exists in the destination.', 'NAME_CONFLICT', ['name' => $name]);
                }
                $name = FileRepository::uniqueFolderName($owner, $parentId, $name, $id);
            }
            Db::update('folders', ['parent_id' => $parentId, 'name' => $name, 'updated_at' => Db::now()], ['id' => $id]);
        });
        $row = self::row($id);
        $after = EventBus::folderAudience($id);
        EventBus::publish('folder.updated', [
            'folder' => FileRepository::folderEventSummary($row), 'changes' => ['parent_id'],
            'from_parent_id' => $from, 'to_parent_id' => $parentId,
        ], array_values(array_unique(array_merge($before, $after))), ['folder_id' => $id]);
        Audit::log('folder.move', [
            'user_id' => (int) $user['id'], 'target_type' => 'folder', 'target_id' => $id, 'owner_id' => $owner, 'detail' => $targetName ?? 'My Files',
            'meta' => ['from_parent_id' => $from, 'to_parent_id' => $parentId, 'folder' => $targetName],
        ]);
        return $row;
    }

    /** DELETE /folders/{id}: move to Trash with all contents. */
    public static function trash(array $user, int $folderId): array
    {
        $folder = FileAccess::requireFolder($user, $folderId, 'delete');
        if (!Policy::isAdmin($user)) {
            Policy::requirePermission($user, 'files.delete');
        }
        return TrashService::trashFolder($folder, $user);
    }

    // ------------------------------------------------------------------ reads

    /**
     * Child folders of $parentId (null = the viewer's own root).
     * @return array{items:array,total:int,meta:array}
     */
    public static function children(array $viewer, ?int $parentId, int $page = 1, int $per = 200, string $q = ''): array
    {
        $meta = ['folder' => null, 'breadcrumbs' => []];
        $ownerId = (int) $viewer['id'];
        if ($parentId !== null) {
            $parent = FileAccess::requireFolder($viewer, $parentId, 'view');
            $ownerId = (int) $parent['owner_id'];
            $meta['folder'] = FileRepository::folderSummary($parent, $viewer, ['access' => [(int) $parent['id'] => $parent['access']]]);
            $meta['breadcrumbs'] = FileRepository::breadcrumbs($viewer, $parentId);
            if ($page === 1) {
                FileService::markFolderOpened($viewer, $parent); // Shared With Me "last accessed"
            }
        }
        [$rows, $total] = self::childRows($ownerId, $parentId, $q, $per, ($page - 1) * $per);
        return ['items' => FileRepository::folderSummaries($rows, $viewer), 'total' => $total, 'meta' => $meta];
    }

    /**
     * Live child folders of $parentId owned by $ownerId — no access check (callers have already
     * authorised the parent). @return array{0:array<int,array>,1:int} [rows, total]
     */
    public static function childRows(int $ownerId, ?int $parentId, string $q = '', int $limit = 500, int $offset = 0): array
    {
        $p = ['o' => $ownerId];
        $where = 'owner_id = :o AND deleted_at IS NULL AND ' . ($parentId === null ? 'parent_id IS NULL' : 'parent_id = :pa');
        if ($parentId !== null) {
            $p['pa'] = $parentId;
        }
        if ($q !== '') {
            $where .= ' AND name LIKE :q';
            $p['q'] = '%' . Db::like(mb_substr($q, 0, 200)) . '%';
        }
        $total = (int) Db::value("SELECT COUNT(*) FROM folders WHERE {$where}", $p);
        $rows = Db::all("SELECT * FROM folders WHERE {$where} ORDER BY name ASC, id ASC LIMIT :lim OFFSET :off", $p + ['lim' => max(1, $limit), 'off' => max(0, $offset)]);
        return [$rows, $total];
    }

    /**
     * GET /folders/tree: all own live folders, plus folders shared with the viewer (flagged
     * shared:true, their parent hidden above the shared root) and the live folders below them.
     * @return array<int,array<string,mixed>>
     */
    public static function tree(array $viewer, int $limit = 5000): array
    {
        $uid = (int) $viewer['id'];
        $out = [];
        foreach (Db::all('SELECT id, name, parent_id FROM folders WHERE owner_id = ? AND deleted_at IS NULL ORDER BY name ASC, id ASC LIMIT ' . $limit, [$uid]) as $r) {
            $out[] = ['id' => (int) $r['id'], 'name' => (string) $r['name'], 'parent_id' => $r['parent_id'] !== null ? (int) $r['parent_id'] : null, 'shared' => false];
        }
        $sharedRoots = [];
        foreach (FileAccess::viewerShares($uid) as $s) {
            if ($s['folder_id'] !== null) {
                $sharedRoots[(int) $s['folder_id']] = true;
            }
        }
        if ($sharedRoots === []) {
            return $out;
        }
        // drop shares nested inside another shared folder (the outer root covers them)
        $map = FileAccess::folderMap(array_keys($sharedRoots));
        $roots = [];
        foreach (array_keys($sharedRoots) as $fid) {
            $row = $map[$fid] ?? null;
            if ($row === null || (int) $row['owner_id'] === $uid) {
                continue;
            }
            $chain = FileAccess::liveChain($map, $fid);
            if ($chain === [] || $chain[0] !== $fid) {
                continue; // trashed
            }
            $nested = false;
            foreach (array_slice($chain, 1) as $anc) {
                if (isset($sharedRoots[$anc])) {
                    $nested = true;
                    break;
                }
            }
            if (!$nested) {
                $roots[] = $row;
            }
        }
        $owners = FileRepository::userRefs(array_map(static fn ($r) => (int) $r['owner_id'], $roots));
        $count = count($out);
        foreach ($roots as $root) {
            $rid = (int) $root['id'];
            $out[] = ['id' => $rid, 'name' => (string) $root['name'], 'parent_id' => null, 'shared' => true, 'shared_root' => true, 'owner' => $owners[(int) $root['owner_id']] ?? null];
            $count++;
            $frontier = [$rid];
            while ($frontier !== [] && $count < $limit) {
                [$in, $p] = Db::inList($frontier, 'tr');
                $p['o'] = (int) $root['owner_id'];
                $children = Db::all("SELECT id, name, parent_id FROM folders WHERE owner_id = :o AND parent_id IN {$in} AND deleted_at IS NULL ORDER BY name ASC, id ASC", $p);
                $frontier = [];
                foreach ($children as $c) {
                    if ($count >= $limit) {
                        break;
                    }
                    $out[] = ['id' => (int) $c['id'], 'name' => (string) $c['name'], 'parent_id' => (int) $c['parent_id'], 'shared' => true];
                    $frontier[] = (int) $c['id'];
                    $count++;
                }
            }
        }
        return $out;
    }

    /** GET /folders/{id}: FolderSummary + breadcrumbs + path. */
    public static function show(array $viewer, int $folderId): array
    {
        $folder = FileAccess::requireFolder($viewer, $folderId, 'view');
        $summary = FileRepository::folderSummary($folder, $viewer, ['access' => [(int) $folder['id'] => $folder['access']]]);
        $crumbs = FileRepository::breadcrumbs($viewer, $folderId);
        $summary['breadcrumbs'] = $crumbs;
        $summary['path'] = FileRepository::pathOf($crumbs);
        return $summary;
    }

    // ------------------------------------------------------------------ helpers

    /**
     * The folder and all its LIVE descendants (same owner), breadth first. @return int[]
     */
    public static function subtreeIds(int $ownerId, int $folderId, int $limit = 100000): array
    {
        $seen = [$folderId => true];
        $frontier = [$folderId];
        while ($frontier !== [] && count($seen) < $limit) {
            $next = [];
            foreach (array_chunk($frontier, 500) as $chunk) {
                [$in, $p] = Db::inList($chunk, 'sub');
                $p['o'] = $ownerId;
                foreach (Db::column("SELECT id FROM folders WHERE owner_id = :o AND parent_id IN {$in} AND deleted_at IS NULL", $p) as $id) {
                    $id = (int) $id;
                    if (!isset($seen[$id])) {
                        $seen[$id] = true;
                        $next[] = $id;
                    }
                }
            }
            $frontier = $next;
        }
        return array_keys($seen);
    }

    /** Height of the subtree below a folder (0 = no subfolders). */
    private static function depthBelow(int $ownerId, int $folderId): int
    {
        $depth = 0;
        $frontier = [$folderId];
        while ($frontier !== [] && $depth <= self::MAX_DEPTH) {
            [$in, $p] = Db::inList($frontier, 'db');
            $p['o'] = $ownerId;
            $frontier = array_map('intval', Db::column("SELECT id FROM folders WHERE owner_id = :o AND parent_id IN {$in} AND deleted_at IS NULL", $p));
            if ($frontier !== []) {
                $depth++;
            }
        }
        return $depth;
    }

    /** Parse a folder id from input: null/0/"" = root, positive int = folder. */
    public static function parseFolderId(mixed $v, string $field = 'folder_id'): ?int
    {
        if ($v === null || $v === '' || $v === 0 || $v === '0' || $v === false) {
            return null;
        }
        if (is_int($v) && $v > 0) {
            return $v;
        }
        if (is_string($v) && ctype_digit($v) && strlen($v) <= 10) {
            return (int) $v;
        }
        throw ApiException::validation([$field => 'Choose a valid folder.']);
    }

    private static function row(int $id): array
    {
        $row = Db::one('SELECT * FROM folders WHERE id = ?', [$id]);
        if ($row === null) {
            throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
        }
        return $row;
    }
}
