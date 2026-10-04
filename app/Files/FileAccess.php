<?php
declare(strict_types=1);

namespace FT\Files;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Events\EventBus;
use FT\Security\Policy;

/**
 * THE authorisation decision for files and folders (docs/ARCHITECTURE.md §6).
 * Never check ownership ad hoc elsewhere — call this class.
 *
 * Levels: viewer(1) < downloader(2) < commenter(3) < editor(4). A share's allow_* flags can only
 * remove grants of its level; allow_reshare is an explicit extra right.
 *
 * Further rules on top of the share level, all "deny wins":
 *  - role permissions cap what a share can grant (a guest — who has no files.edit/files.share/
 *    files.upload permission — never becomes an editor or re-sharer, whatever the share says);
 *  - a folder share only reaches content through LIVE folders: if any folder between the item
 *    and the shared folder is in the Trash, the share grants nothing below it;
 *  - a share only counts while the person who created it AND the owner of the item are active
 *    (status 'active', not deleted) — disabling or deleting an account stops every share it made
 *    or that exposes its content, exactly like link shares (ShareService::linkProblem);
 *  - a RE-share (parent_share_id) is honoured only while every share above it is still active
 *    (not revoked, not expired, creator active, still allowing re-sharing) and still reaches the
 *    re-shared item — see honoured(). Its grants are capped at the weakest share in its chain.
 *
 * The *Many() variants resolve a whole page of rows with a constant number of queries (one for
 * the viewer's shares, one for bundle items, one per folder depth level), so listings never do
 * per-row access queries.
 */
final class FileAccess
{
    public const LEVELS = ['viewer' => 1, 'downloader' => 2, 'commenter' => 3, 'editor' => 4];

    private const NONE = [
        'role' => null, 'preview' => false, 'download' => false, 'comment' => false, 'edit' => false,
        'share' => false, 'delete' => false, 'move' => false, 'versions' => false, 'activity' => false, 'manage' => false,
    ];

    /** @var array<string,array|null> per-request cache userId:fileId:state => caps */
    private static array $cache = [];

    /** @var array<int,array<int,array<string,mixed>>> per-request cache: recipient id => active user shares */
    private static array $viewerShares = [];

    // ---------------------------------------------------------------- files

    /** Capabilities of $user on a files row, or null when the user has no access at all. */
    public static function accessFor(?array $user, array $file): ?array
    {
        if ($user === null) {
            return null;
        }
        $key = $user['id'] . ':' . $file['id'] . ':' . ($file['deleted_at'] === null ? 'a' : 't');
        if (array_key_exists($key, self::$cache)) {
            return self::$cache[$key];
        }
        return self::accessForMany($user, [$file])[(int) $file['id']] ?? null;
    }

    /**
     * Batch variant of accessFor(): capabilities for many files rows at once.
     * @param array<int,array<string,mixed>> $files
     * @return array<int,array<string,mixed>|null> file id => caps|null
     */
    public static function accessForMany(?array $user, array $files): array
    {
        $out = [];
        if ($user === null) {
            foreach ($files as $f) {
                $out[(int) $f['id']] = null;
            }
            return $out;
        }
        $uid = (int) $user['id'];
        $isAdmin = Policy::isAdmin($user);
        $pending = [];
        foreach ($files as $f) {
            $id = (int) $f['id'];
            $isOwner = (int) $f['owner_id'] === $uid;
            if ($f['deleted_at'] !== null) {
                $out[$id] = ($isOwner || $isAdmin) ? self::full($isOwner ? 'owner' : 'admin') : null;
            } elseif ($isOwner) {
                $out[$id] = self::full('owner');
            } elseif ($isAdmin) {
                $out[$id] = self::full('admin');
            } else {
                $pending[$id] = $f;
            }
        }
        if ($pending !== []) {
            // Content of a disabled or deleted owner is not shared with anyone any more.
            $active = self::activeUsers(array_map(static fn (array $f): int => (int) $f['owner_id'], $pending));
            foreach ($pending as $id => $f) {
                if (empty($active[(int) $f['owner_id']])) {
                    $out[$id] = null;
                    unset($pending[$id]);
                }
            }
        }
        if ($pending !== []) {
            $shares = self::viewerShares($uid);
            if ($shares === []) {
                foreach ($pending as $id => $_) {
                    $out[$id] = null;
                }
            } else {
                $byFile = [];
                $byFolder = [];
                $byId = [];
                foreach ($shares as $s) {
                    $byId[(int) $s['id']] = $s;
                    if ($s['file_id'] !== null) {
                        $byFile[(int) $s['file_id']][] = $s;
                    }
                    if ($s['folder_id'] !== null) {
                        $byFolder[(int) $s['folder_id']][] = $s;
                    }
                }
                // bundle membership (share_items) for these files
                [$inS, $pS] = Db::inList(array_keys($byId), 'vs');
                [$inF, $pF] = Db::inList(array_keys($pending), 'vf');
                foreach (Db::all("SELECT share_id, file_id FROM share_items WHERE share_id IN {$inS} AND file_id IN {$inF}", $pS + $pF) as $it) {
                    $s = $byId[(int) $it['share_id']];
                    if (isset($s['_items']) && !in_array((int) $it['file_id'], $s['_items'], true)) {
                        continue; // a bundle re-share item its parent no longer reaches
                    }
                    $byFile[(int) $it['file_id']][] = $s;
                }
                $map = [];
                if ($byFolder !== []) {
                    $folderIds = [];
                    foreach ($pending as $f) {
                        if ($f['folder_id'] !== null) {
                            $folderIds[] = (int) $f['folder_id'];
                        }
                    }
                    $map = self::folderMap($folderIds);
                }
                foreach ($pending as $id => $f) {
                    $applicable = $byFile[$id] ?? [];
                    if ($byFolder !== [] && $f['folder_id'] !== null) {
                        foreach (self::liveChain($map, (int) $f['folder_id']) as $fid) {
                            foreach ($byFolder[$fid] ?? [] as $s) {
                                $applicable[] = $s;
                            }
                        }
                    }
                    $caps = self::combine($applicable);
                    $out[$id] = $caps === null ? null : self::applyPolicy($user, $caps);
                }
            }
        }
        foreach ($files as $f) {
            self::$cache[$uid . ':' . $f['id'] . ':' . ($f['deleted_at'] === null ? 'a' : 't')] = $out[(int) $f['id']] ?? null;
        }
        return $out;
    }

    /**
     * Load a file and require a capability. 404 when the user cannot see it at all (existence is
     * not revealed), 403 when they can see it but lack the capability.
     * @return array files row + ['access' => caps]
     */
    public static function require(?array $user, int $fileId, string $capability, bool $includeTrashed = false): array
    {
        if ($user === null) {
            throw ApiException::unauthorized();
        }
        $file = Db::one('SELECT * FROM files WHERE id = ?', [$fileId]);
        if ($file === null || (!$includeTrashed && $file['deleted_at'] !== null)) {
            throw ApiException::fileNotFound();
        }
        $caps = self::accessFor($user, $file);
        if ($caps === null) {
            throw ApiException::fileNotFound();
        }
        if ($capability !== 'view' && empty($caps[$capability])) {
            throw ApiException::forbidden();
        }
        if ($caps['role'] === 'admin' && in_array($capability, ['preview', 'download', 'edit', 'versions'], true)) {
            Audit::log('admin.file_access', ['user_id' => (int) $user['id'], 'category' => 'admin', 'target_type' => 'file', 'target_id' => $fileId, 'owner_id' => (int) $file['owner_id'], 'detail' => $capability]);
        }
        $file['access'] = $caps;
        return $file;
    }

    /**
     * Honoured user shares through which $userId can reach the file: direct, via a bundle
     * (share_items) or via a live ancestor folder — the same rules as accessForMany().
     * @return array<int,array<string,mixed>>
     */
    public static function sharesFor(int $userId, array $file): array
    {
        $shares = self::viewerShares($userId);
        if ($shares === [] || empty(self::activeUsers([(int) $file['owner_id']])[(int) $file['owner_id']])) {
            return [];
        }
        $fileId = (int) $file['id'];
        $chain = $file['folder_id'] !== null ? self::liveChain(self::folderMap([(int) $file['folder_id']]), (int) $file['folder_id']) : [];
        $bundleIds = [];
        foreach ($shares as $s) {
            if ($s['target_type'] === 'bundle') {
                $bundleIds[] = (int) $s['id'];
            }
        }
        $inBundle = [];
        if ($bundleIds !== []) {
            [$in, $p] = Db::inList($bundleIds, 'sb');
            $p['fid'] = $fileId;
            foreach (Db::column("SELECT share_id FROM share_items WHERE share_id IN {$in} AND file_id = :fid", $p) as $sid) {
                $inBundle[(int) $sid] = true;
            }
        }
        $out = [];
        foreach ($shares as $s) {
            $reaches = match ((string) $s['target_type']) {
                'file'   => (int) $s['file_id'] === $fileId,
                'folder' => $s['folder_id'] !== null && in_array((int) $s['folder_id'], $chain, true),
                'bundle' => isset($inBundle[(int) $s['id']]) && (!isset($s['_items']) || in_array($fileId, $s['_items'], true)),
                default  => false,
            };
            if ($reaches) {
                $out[] = $s;
            }
        }
        return $out;
    }

    /**
     * Capabilities for a file reached through a LINK share (public page context). A link made
     * from a re-share grants at most what its chain still grants (see honoured()).
     */
    public static function forLinkShare(array $share, int $fileId): array
    {
        $file = Db::one('SELECT * FROM files WHERE id = ? AND deleted_at IS NULL', [$fileId]);
        if ($file === null || !self::inLinkScope($share, $file)) {
            throw ApiException::fileNotFound();
        }
        $effective = $share['parent_share_id'] !== null && !isset($share['_honoured']) ? (self::honoured([$share])[0] ?? null) : $share;
        if ($effective === null) {
            throw ApiException::fileNotFound();
        }
        $caps = self::combine([$effective]) ?? self::NONE;
        $caps['share'] = false;
        $file['access'] = $caps;
        return $file;
    }

    public static function inLinkScope(array $share, array $file): bool
    {
        if ($share['revoked_at'] !== null || $file['deleted_at'] !== null) {
            return false;
        }
        if ($share['parent_share_id'] !== null) {
            // A link made from a re-share: the whole chain must still reach this very file.
            $effective = isset($share['_honoured']) ? $share : (self::honoured([$share])[0] ?? null);
            if ($effective === null || (isset($effective['_items']) && !in_array((int) $file['id'], $effective['_items'], true))) {
                return false;
            }
        }
        switch ($share['target_type']) {
            case 'file':
                return (int) $share['file_id'] === (int) $file['id'];
            case 'bundle':
                return Db::value('SELECT 1 FROM share_items WHERE share_id = ? AND file_id = ?', [(int) $share['id'], (int) $file['id']]) !== null;
            case 'folder':
                if ($file['folder_id'] === null || $share['folder_id'] === null) {
                    return false;
                }
                $chain = EventBus::ancestorFolderIds((int) $file['folder_id']);
                if (!in_array((int) $share['folder_id'], $chain, true)) {
                    return false;
                }
                // every folder on the way must be live (not trashed)
                [$in, $p] = Db::inList($chain, 'cf');
                return (int) Db::value("SELECT COUNT(*) FROM folders WHERE id IN {$in} AND deleted_at IS NOT NULL", $p) === 0;
        }
        return false;
    }

    // ---------------------------------------------------------------- folders

    /** Folder capabilities: view, upload, edit, share, delete, move, manage, download, comment, role. */
    public static function folderAccessFor(?array $user, array $folder): ?array
    {
        if ($user === null) {
            return null;
        }
        return self::folderAccessForMany($user, [$folder])[(int) $folder['id']] ?? null;
    }

    /**
     * Batch variant of folderAccessFor().
     * @param array<int,array<string,mixed>> $folders folders rows
     * @return array<int,array<string,mixed>|null> folder id => caps|null
     */
    public static function folderAccessForMany(?array $user, array $folders): array
    {
        $out = [];
        if ($user === null) {
            foreach ($folders as $f) {
                $out[(int) $f['id']] = null;
            }
            return $out;
        }
        $uid = (int) $user['id'];
        $isAdmin = Policy::isAdmin($user);
        $pending = [];
        foreach ($folders as $f) {
            $id = (int) $f['id'];
            $isOwner = (int) $f['owner_id'] === $uid;
            if ($isOwner || $isAdmin) {
                // trashed folders stay visible to their owner and admins (Trash view, restore, purge)
                $out[$id] = self::fullFolder($isOwner ? 'owner' : 'admin');
            } elseif ($f['deleted_at'] !== null) {
                $out[$id] = null;
            } else {
                $pending[$id] = $f;
            }
        }
        if ($pending !== []) {
            $active = self::activeUsers(array_map(static fn (array $f): int => (int) $f['owner_id'], $pending));
            foreach ($pending as $id => $f) {
                if (empty($active[(int) $f['owner_id']])) {
                    $out[$id] = null;
                    unset($pending[$id]);
                }
            }
        }
        if ($pending !== []) {
            $byFolder = [];
            foreach (self::viewerShares($uid) as $s) {
                if ($s['folder_id'] !== null) {
                    $byFolder[(int) $s['folder_id']][] = $s;
                }
            }
            $map = $byFolder !== [] ? self::folderMap(array_keys($pending)) : [];
            foreach ($pending as $id => $f) {
                $applicable = [];
                if ($byFolder !== []) {
                    foreach (self::liveChain($map, $id) as $fid) {
                        foreach ($byFolder[$fid] ?? [] as $s) {
                            $applicable[] = $s;
                        }
                    }
                }
                $caps = self::combine($applicable);
                if ($caps === null) {
                    $out[$id] = null;
                    continue;
                }
                $caps = self::applyPolicy($user, $caps);
                $out[$id] = [
                    'role' => $caps['role'], 'view' => true,
                    'upload' => $caps['edit'] && Policy::can($user, 'files.upload'),
                    'edit' => $caps['edit'], 'share' => $caps['share'],
                    'delete' => false, 'move' => false, 'manage' => false,
                    'download' => $caps['download'], 'comment' => $caps['comment'],
                ];
            }
        }
        return $out;
    }

    /** @return array folders row + ['access' => caps] */
    public static function requireFolder(?array $user, int $folderId, string $capability, bool $includeTrashed = false): array
    {
        if ($user === null) {
            throw ApiException::unauthorized();
        }
        $folder = Db::one('SELECT * FROM folders WHERE id = ?', [$folderId]);
        if ($folder === null || (!$includeTrashed && $folder['deleted_at'] !== null)) {
            throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
        }
        $caps = self::folderAccessFor($user, $folder);
        if ($caps === null) {
            throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
        }
        if (empty($caps[$capability])) {
            throw ApiException::forbidden();
        }
        $folder['access'] = $caps;
        return $folder;
    }

    /**
     * Validate an upload/create target. null = the user's own root (requires files.upload).
     * Returns the folder id (or null) — the owner of new content is the folder's owner.
     */
    public static function requireFolderWrite(?array $user, ?int $folderId): ?int
    {
        if ($user === null) {
            throw ApiException::unauthorized();
        }
        if ($folderId === null || $folderId === 0) {
            Policy::requirePermission($user, 'files.upload');
            return null;
        }
        $folder = self::requireFolder($user, $folderId, 'upload');
        if ($folder['access']['role'] === 'owner') {
            Policy::requirePermission($user, 'files.upload');
        }
        return (int) $folder['id'];
    }

    /** Owner id that new content in $folderId belongs to (the folder owner, or $user for root). */
    public static function contentOwnerFor(array $user, ?int $folderId): int
    {
        if ($folderId === null) {
            return (int) $user['id'];
        }
        return (int) Db::value('SELECT owner_id FROM folders WHERE id = ?', [$folderId]);
    }

    /**
     * For a share recipient: the topmost folder of $folderId's live ancestor chain that is shared
     * with them (breadcrumbs and paths must never reveal folders above it). Owners and admins get
     * null (= everything is visible). Returns 0 when the folder is not reachable at all.
     */
    public static function sharedRootFor(array $user, int $folderId, ?array $map = null): ?int
    {
        $map ??= self::folderMap([$folderId]);
        $row = $map[$folderId] ?? null;
        if ($row === null) {
            return 0;
        }
        if ((int) $row['owner_id'] === (int) $user['id'] || Policy::isAdmin($user)) {
            return null;
        }
        $shared = [];
        foreach (self::viewerShares((int) $user['id']) as $s) {
            if ($s['folder_id'] !== null) {
                $shared[(int) $s['folder_id']] = true;
            }
        }
        $top = 0;
        foreach (self::liveChain($map, $folderId) as $fid) {
            if (isset($shared[$fid])) {
                $top = $fid;
            }
        }
        return $top;
    }

    // ---------------------------------------------------------------- folder chains

    /**
     * Folder rows for the given ids AND all their ancestors, loaded level by level (one query per
     * depth level — no recursive CTEs on MySQL 5.7/MariaDB 10.3). Missing ids map to null.
     * @return array<int,array<string,mixed>|null>
     */
    public static function folderMap(array $folderIds): array
    {
        $map = [];
        $want = array_values(array_unique(array_filter(array_map('intval', $folderIds), static fn ($i) => $i > 0)));
        for ($depth = 0; $want !== [] && $depth < 66; $depth++) {
            [$in, $p] = Db::inList($want, 'fm');
            $next = [];
            foreach (Db::all("SELECT id, owner_id, parent_id, name, color, created_by, created_at, updated_at, deleted_at, deleted_by, trash_batch, trash_original_parent_id, trash_reason FROM folders WHERE id IN {$in}", $p) as $r) {
                $map[(int) $r['id']] = $r;
                if ($r['parent_id'] !== null) {
                    $next[] = (int) $r['parent_id'];
                }
            }
            foreach ($want as $w) {
                if (!array_key_exists($w, $map)) {
                    $map[$w] = null;
                }
            }
            $want = array_values(array_unique(array_filter($next, static fn ($i) => !array_key_exists($i, $map))));
        }
        return $map;
    }

    /** Folder ids from $folderId upwards (the folder first), max depth 64, cycle-safe. @return int[] */
    public static function chain(array $map, int $folderId): array
    {
        $out = [];
        $cur = $folderId;
        while ($cur > 0 && count($out) < 64 && !in_array($cur, $out, true) && ($map[$cur] ?? null) !== null) {
            $out[] = $cur;
            $cur = $map[$cur]['parent_id'] !== null ? (int) $map[$cur]['parent_id'] : 0;
        }
        return $out;
    }

    /** Like chain() but stops at the first trashed folder (shares above it do not reach down). */
    public static function liveChain(array $map, int $folderId): array
    {
        $out = [];
        foreach (self::chain($map, $folderId) as $fid) {
            if ($map[$fid]['deleted_at'] !== null) {
                break;
            }
            $out[] = $fid;
        }
        return $out;
    }

    // ---------------------------------------------------------------- helpers

    /**
     * User shares whose recipient is $userId and that still count: not revoked, not expired,
     * created by an active account, and — for re-shares — honoured (see honoured(); bundle
     * re-shares may carry '_items'). Whether the shared ITEM's owner is active is checked per item
     * by the callers (accessForMany & co.). Cached per request.
     */
    public static function viewerShares(int $userId): array
    {
        if (!isset(self::$viewerShares[$userId])) {
            self::$viewerShares[$userId] = self::honoured(Db::all(
                "SELECT s.* FROM shares s JOIN users cu ON cu.id = s.owner_id
                  WHERE s.kind = 'user' AND s.recipient_id = :uid AND s.revoked_at IS NULL
                    AND (s.expires_at IS NULL OR s.expires_at > :now)
                    AND cu.status = 'active' AND cu.deleted_at IS NULL",
                ['uid' => $userId, 'now' => Db::now()]
            ));
        }
        return self::$viewerShares[$userId];
    }

    /**
     * The re-share rule, evaluated at ACCESS time so it holds whatever happened to the rows (a
     * file moved out of the shared folder, a folder moved elsewhere, a parent revoked or downgraded
     * by a raw UPDATE, a re-sharer disabled):
     *
     * a share with parent_share_id is honoured only while every share above it
     *   - is a user share that is not revoked, not expired, made by an active account, still allows
     *     re-sharing and was given to the person who made the share below it, and
     *   - still reaches the re-shared item: the same file, a bundle containing it, or a folder in
     *     the item's LIVE ancestor chain (for a folder: in the folder's own live chain).
     * A bundle re-share keeps only the items every ancestor reaches ('_items' => int[]); one with no
     * such item is dropped. Honoured re-shares are capped at the weakest share in their chain
     * (level and allow_* flags), so a downgrade upstream can never be bypassed downstream.
     *
     * Shares without a parent pass through untouched; callers filter those themselves (active,
     * creator active). Returned rows carry '_honoured' => true. A constant number of queries (one
     * per chain depth level, plus share_items / files / folder levels for re-shares only).
     * @param array<int,array<string,mixed>> $shares
     * @return array<int,array<string,mixed>>
     */
    public static function honoured(array $shares): array
    {
        $shares = array_values($shares);
        $children = [];
        foreach ($shares as $i => $s) {
            if ($s['parent_share_id'] !== null && empty($s['_honoured'])) {
                $children[$i] = $s;
            }
        }
        if ($children === []) {
            return $shares;
        }

        // 1. every ancestor row (with its creator's status), level by level
        $rows = [];
        $want = array_values(array_unique(array_map(static fn (array $s): int => (int) $s['parent_share_id'], $children)));
        for ($depth = 0; $want !== [] && $depth < 32; $depth++) {
            [$in, $p] = Db::inList($want, 'hp');
            foreach (Db::all(
                "SELECT s.*, cu.status AS creator_status, cu.deleted_at AS creator_deleted_at
                   FROM shares s LEFT JOIN users cu ON cu.id = s.owner_id WHERE s.id IN {$in}",
                $p
            ) as $r) {
                $rows[(int) $r['id']] = $r;
            }
            $next = [];
            foreach ($want as $w) {
                $r = $rows[$w] ?? null;
                if ($r !== null && $r['parent_share_id'] !== null && !array_key_exists((int) $r['parent_share_id'], $rows)) {
                    $next[] = (int) $r['parent_share_id'];
                }
            }
            $want = array_values(array_unique($next));
        }

        // 2. each child's chain must be intact and live
        $now = Db::now();
        $chains = [];
        foreach ($children as $i => $s) {
            $chain = [];
            $below = (int) $s['owner_id'];
            $cur = (int) $s['parent_share_id'];
            $ok = true;
            while ($cur > 0) {
                $p = $rows[$cur] ?? null;
                if ($p === null || count($chain) >= 32 || isset($chain[$cur]) || $cur === (int) $s['id']
                    || $p['kind'] !== 'user' || $p['revoked_at'] !== null
                    || ($p['expires_at'] !== null && (string) $p['expires_at'] <= $now)
                    || $p['creator_status'] !== 'active' || $p['creator_deleted_at'] !== null
                    || (int) $p['allow_reshare'] !== 1 || (int) $p['recipient_id'] !== $below) {
                    $ok = false;
                    break;
                }
                $chain[$cur] = $p;
                $below = (int) $p['owner_id'];
                $cur = $p['parent_share_id'] !== null ? (int) $p['parent_share_id'] : 0;
            }
            if ($ok) {
                $chains[$i] = array_values($chain);
            } else {
                unset($shares[$i]);
            }
        }

        // 3. what the re-shares point at: files (direct + bundle items) and folders
        $items = [];
        $bundleChildren = [];
        $fileIds = [];
        $folderIds = [];
        foreach ($chains as $i => $_) {
            $s = $children[$i];
            if ($s['target_type'] === 'bundle') {
                $bundleChildren[] = (int) $s['id'];
            } elseif ($s['target_type'] === 'file' && $s['file_id'] !== null) {
                $fileIds[] = (int) $s['file_id'];
            } elseif ($s['target_type'] === 'folder' && $s['folder_id'] !== null) {
                $folderIds[] = (int) $s['folder_id'];
            }
        }
        if ($bundleChildren !== []) {
            [$in, $p] = Db::inList($bundleChildren, 'hb');
            foreach (Db::all("SELECT share_id, file_id FROM share_items WHERE share_id IN {$in}", $p) as $it) {
                $items[(int) $it['share_id']][] = (int) $it['file_id'];
                $fileIds[] = (int) $it['file_id'];
            }
        }
        $fileIds = array_values(array_unique($fileIds));
        $fileFolder = [];
        if ($fileIds !== []) {
            [$in, $p] = Db::inList($fileIds, 'hf');
            foreach (Db::all("SELECT id, folder_id FROM files WHERE id IN {$in}", $p) as $f) {
                $fileFolder[(int) $f['id']] = $f['folder_id'] !== null ? (int) $f['folder_id'] : null;
                if ($f['folder_id'] !== null) {
                    $folderIds[] = (int) $f['folder_id'];
                }
            }
        }
        $map = $folderIds !== [] ? self::folderMap($folderIds) : [];
        $ancestorBundles = [];
        foreach ($chains as $chain) {
            foreach ($chain as $p) {
                if ($p['target_type'] === 'bundle') {
                    $ancestorBundles[(int) $p['id']] = true;
                }
            }
        }
        $ancestorItems = [];
        if ($ancestorBundles !== [] && $fileIds !== []) {
            [$inS, $pS] = Db::inList(array_keys($ancestorBundles), 'ha');
            [$inF, $pF] = Db::inList($fileIds, 'hi');
            foreach (Db::all("SELECT share_id, file_id FROM share_items WHERE share_id IN {$inS} AND file_id IN {$inF}", $pS + $pF) as $it) {
                $ancestorItems[(int) $it['share_id']][(int) $it['file_id']] = true;
            }
        }

        // 4. every ancestor must still reach the target; cap the grant at the weakest link
        foreach ($chains as $i => $chain) {
            $s = $shares[$i];
            $reachesAll = static function (?int $fileId, array $liveChain) use ($chain, $ancestorItems): bool {
                foreach ($chain as $p) {
                    if (!self::reaches($p, $fileId, $liveChain, $ancestorItems)) {
                        return false;
                    }
                }
                return true;
            };
            $fileChain = static function (int $fileId) use ($fileFolder, $map): ?array {
                if (!array_key_exists($fileId, $fileFolder)) {
                    return null; // the file row is gone
                }
                return $fileFolder[$fileId] !== null ? self::liveChain($map, $fileFolder[$fileId]) : [];
            };
            $keep = false;
            switch ($s['target_type']) {
                case 'file':
                    $fc = $s['file_id'] !== null ? $fileChain((int) $s['file_id']) : null;
                    $keep = $fc !== null && $reachesAll((int) $s['file_id'], $fc);
                    break;
                case 'folder':
                    $keep = $s['folder_id'] !== null && $reachesAll(null, self::liveChain($map, (int) $s['folder_id']));
                    break;
                case 'bundle':
                    $kept = [];
                    foreach ($items[(int) $s['id']] ?? [] as $fid) {
                        $fc = $fileChain($fid);
                        if ($fc !== null && $reachesAll($fid, $fc)) {
                            $kept[] = $fid;
                        }
                    }
                    if ($kept !== []) {
                        $s['_items'] = $kept;
                        $keep = true;
                    }
                    break;
            }
            if (!$keep) {
                unset($shares[$i]);
                continue;
            }
            foreach ($chain as $p) {
                if ((self::LEVELS[(string) $s['permission']] ?? 1) > (self::LEVELS[(string) $p['permission']] ?? 1)) {
                    $s['permission'] = (string) $p['permission'];
                }
                $pCaps = self::combine([$p]) ?? self::NONE;
                foreach (['allow_preview' => 'preview', 'allow_download' => 'download', 'allow_comments' => 'comment', 'allow_edit' => 'edit'] as $flag => $cap) {
                    if (empty($pCaps[$cap])) {
                        $s[$flag] = 0;
                    }
                }
            }
            $s['_honoured'] = true;
            $shares[$i] = $s;
        }
        return array_values($shares);
    }

    /**
     * Does $share reach the file $fileId (null = a folder) whose LIVE ancestor chain is
     * $liveChain? $bundleItems: share id => file id => true.
     */
    private static function reaches(array $share, ?int $fileId, array $liveChain, array $bundleItems): bool
    {
        return match ((string) $share['target_type']) {
            'file'   => $fileId !== null && (int) $share['file_id'] === $fileId,
            'bundle' => $fileId !== null && isset($bundleItems[(int) $share['id']][$fileId]),
            'folder' => $share['folder_id'] !== null && in_array((int) $share['folder_id'], $liveChain, true),
            default  => false,
        };
    }

    /**
     * Which of these accounts are active (status 'active' and not deleted). One query.
     * @param int[] $userIds
     * @return array<int,bool>
     */
    public static function activeUsers(array $userIds): array
    {
        $userIds = array_values(array_unique(array_filter(array_map('intval', $userIds), static fn ($i) => $i > 0)));
        $out = array_fill_keys($userIds, false);
        if ($userIds === []) {
            return $out;
        }
        [$in, $p] = Db::inList($userIds, 'au');
        foreach (Db::column("SELECT id FROM users WHERE id IN {$in} AND status = 'active' AND deleted_at IS NULL", $p) as $id) {
            $out[(int) $id] = true;
        }
        return $out;
    }

    /** Combine one or more shares into capabilities (highest level, flags OR-ed). */
    public static function combine(array $shares): ?array
    {
        if ($shares === []) {
            return null;
        }
        $caps = self::NONE;
        $best = 0;
        foreach ($shares as $s) {
            $lvl = self::LEVELS[$s['permission']] ?? 1;
            if ($lvl > $best) {
                $best = $lvl;
                $caps['role'] = (string) $s['permission'];
            }
            $caps['preview'] = $caps['preview'] || ($lvl >= 1 && (int) $s['allow_preview'] === 1);
            $caps['download'] = $caps['download'] || ($lvl >= 2 && (int) $s['allow_download'] === 1);
            $caps['comment'] = $caps['comment'] || ($lvl >= 3 && (int) $s['allow_comments'] === 1);
            $caps['edit'] = $caps['edit'] || ($lvl >= 4 && (int) $s['allow_edit'] === 1);
            $caps['share'] = $caps['share'] || (int) $s['allow_reshare'] === 1;
        }
        $caps['versions'] = $caps['edit'];
        $caps['activity'] = $caps['edit'];
        return $caps;
    }

    /** Default allow_* flags for a permission level (what the level grants). */
    public static function defaultFlags(string $permission): array
    {
        $lvl = self::LEVELS[$permission] ?? 2;
        return [
            'allow_preview'  => 1,
            'allow_download' => $lvl >= 2 ? 1 : 0,
            'allow_comments' => $lvl >= 3 ? 1 : 0,
            'allow_edit'     => $lvl >= 4 ? 1 : 0,
        ];
    }

    /** Role permissions cap share grants (deny wins). */
    private static function applyPolicy(array $user, array $caps): array
    {
        if ($caps['edit'] && !Policy::can($user, 'files.edit')) {
            $caps['edit'] = false;
        }
        if ($caps['comment'] && !Policy::can($user, 'files.comment')) {
            $caps['comment'] = false;
        }
        if ($caps['share'] && !Policy::can($user, 'files.share')) {
            $caps['share'] = false;
        }
        $caps['versions'] = $caps['edit'];
        $caps['activity'] = $caps['edit'];
        return $caps;
    }

    private static function full(string $role): array
    {
        return ['role' => $role, 'preview' => true, 'download' => true, 'comment' => true, 'edit' => true,
            'share' => true, 'delete' => true, 'move' => true, 'versions' => true, 'activity' => true, 'manage' => true];
    }

    private static function fullFolder(string $role): array
    {
        return ['role' => $role, 'view' => true, 'upload' => true, 'edit' => true, 'share' => true, 'delete' => true,
            'move' => true, 'manage' => true, 'download' => true, 'comment' => true];
    }

    public static function reset(): void
    {
        self::$cache = [];
        self::$viewerShares = [];
    }
}
