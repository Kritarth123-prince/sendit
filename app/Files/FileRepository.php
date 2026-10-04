<?php
declare(strict_types=1);

namespace FT\Files;

use FT\Core\Db;
use FT\Security\Policy;
use FT\Storage\MimeDetector;

/**
 * Read model of the files domain: FileSummary / FolderSummary shapes (docs/ARCHITECTURE.md §9.2),
 * batch hydration, breadcrumbs and name helpers.
 *
 * Hydration of a page of rows always costs a constant number of queries (tags, favourites,
 * comment counts, share flags, blob encryption, owners, access) — never one query per row —
 * so lists of 200 items stay cheap on a 4-connection shared database.
 *
 * Privacy rule for share recipients: a folder above the shared root is never revealed — neither
 * in breadcrumbs/paths nor as a file's folder_id or a folder's parent_id.
 */
final class FileRepository
{
    /** Whitelisted sort keys => column. */
    public const SORTS = ['name' => 'name', 'size' => 'size', 'created_at' => 'created_at', 'updated_at' => 'updated_at', 'kind' => 'kind'];

    public const MAX_NAME_BYTES = 255;

    /** files row (+ blob_encryption) or null. */
    public static function find(int $id, bool $includeTrashed = false): ?array
    {
        $row = Db::one(
            'SELECT f.*, b.encryption AS blob_encryption FROM files f LEFT JOIN file_blobs b ON b.id = f.blob_id WHERE f.id = ?',
            [$id]
        );
        if ($row === null || (!$includeTrashed && $row['deleted_at'] !== null)) {
            return null;
        }
        return $row;
    }

    /** @return array<int,array<string,mixed>> files rows (+ blob_encryption) keyed by id */
    public static function findMany(array $ids): array
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids), static fn ($i) => $i > 0)));
        $out = [];
        foreach (array_chunk($ids, 500) as $chunk) {
            [$in, $p] = Db::inList($chunk, 'fi');
            foreach (Db::all("SELECT f.*, b.encryption AS blob_encryption FROM files f LEFT JOIN file_blobs b ON b.id = f.blob_id WHERE f.id IN {$in}", $p) as $r) {
                $out[(int) $r['id']] = $r;
            }
        }
        return $out;
    }

    // ================================================================= FileSummary

    /** FileSummary of one row for $viewer (per-viewer fields: favorite, access). */
    public static function summary(array $row, ?array $viewer, array $o = []): array
    {
        return self::summaries([$row], $viewer, $o)[0];
    }

    /**
     * FileSummary for many rows in a constant number of queries.
     * Options: 'trash' => true adds trash{} for trashed rows; 'event' => true omits per-viewer
     * fields (favorite, access); 'access' => precomputed caps map (id => caps).
     * @param array<int,array<string,mixed>> $rows
     * @return array<int,array<string,mixed>>
     */
    public static function summaries(array $rows, ?array $viewer, array $o = []): array
    {
        $rows = array_values($rows);
        if ($rows === []) {
            return [];
        }
        $event = !empty($o['event']);
        $ids = array_map(static fn ($r) => (int) $r['id'], $rows);
        [$in, $p] = Db::inList($ids, 'sf');
        $now = Db::now();

        $tags = [];
        foreach (Db::all("SELECT ft.file_id, t.name FROM file_tags ft JOIN tags t ON t.id = ft.tag_id WHERE ft.file_id IN {$in} ORDER BY t.name", $p) as $t) {
            $tags[(int) $t['file_id']][] = (string) $t['name'];
        }
        $comments = [];
        foreach (Db::all("SELECT file_id, COUNT(*) AS n FROM comments WHERE deleted_at IS NULL AND file_id IN {$in} GROUP BY file_id", $p) as $c) {
            $comments[(int) $c['file_id']] = (int) $c['n'];
        }
        [$in2, $p2] = Db::inList($ids, 'sg');
        $shared = array_flip(array_map('intval', Db::column(
            "SELECT file_id FROM shares WHERE file_id IN {$in} AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > :n1)
             UNION
             SELECT si.file_id FROM share_items si JOIN shares s ON s.id = si.share_id
              WHERE si.file_id IN {$in2} AND s.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > :n2)",
            $p + $p2 + ['n1' => $now, 'n2' => $now]
        )));

        // blob encryption (listings join it already; single rows may not have it)
        $enc = [];
        $missing = [];
        foreach ($rows as $r) {
            if (array_key_exists('blob_encryption', $r)) {
                $enc[(int) $r['id']] = (string) ($r['blob_encryption'] ?? 'none');
            } else {
                $missing[(int) $r['blob_id']][] = (int) $r['id'];
            }
        }
        if ($missing !== []) {
            [$inB, $pB] = Db::inList(array_keys($missing), 'sb');
            foreach (Db::all("SELECT id, encryption FROM file_blobs WHERE id IN {$inB}", $pB) as $b) {
                foreach ($missing[(int) $b['id']] ?? [] as $fid) {
                    $enc[$fid] = (string) $b['encryption'];
                }
            }
        }

        $favs = [];
        $caps = [];
        if (!$event && $viewer !== null) {
            $p['fu'] = (int) $viewer['id'];
            $favs = array_flip(array_map('intval', Db::column("SELECT file_id FROM favorites WHERE user_id = :fu AND file_id IN {$in}", $p)));
            $caps = $o['access'] ?? FileAccess::accessForMany($viewer, $rows);
        }

        $trash = [];
        $userIds = [];
        foreach ($rows as $r) {
            $userIds[] = (int) $r['owner_id'];
        }
        if (!empty($o['trash'])) {
            $trashed = array_values(array_filter($rows, static fn ($r) => $r['deleted_at'] !== null));
            if ($trashed !== []) {
                $trash = TrashService::infoMany($trashed, 'file', $viewer);
            }
        }
        $users = self::userRefs($userIds);

        $hidden = $viewer !== null && !$event ? self::hiddenFolders($viewer, $rows, 'folder_id') : [];

        $out = [];
        foreach ($rows as $r) {
            $id = (int) $r['id'];
            $folderId = $r['folder_id'] !== null ? (int) $r['folder_id'] : null;
            if ($folderId !== null && isset($hidden[$folderId])) {
                $folderId = null;
            }
            $s = [
                'id'             => $id,
                'type'           => 'file',
                'name'           => (string) $r['name'],
                'ext'            => (string) $r['ext'],
                'mime'           => (string) $r['mime'],
                'kind'           => (string) $r['kind'],
                'size'           => (int) $r['size'],
                'folder_id'      => $folderId,
                'owner'          => $users[(int) $r['owner_id']] ?? self::unknownUser((int) $r['owner_id']),
                'created_at'     => Db::iso($r['created_at']),
                'updated_at'     => Db::iso($r['updated_at']),
                'version'        => (int) $r['version'],
                'favorite'       => isset($favs[$id]),
                'tags'           => $tags[$id] ?? [],
                'is_permanent'   => (int) $r['is_permanent'] === 1,
                'expires_at'     => (int) $r['is_permanent'] === 1 ? null : Db::iso($r['expires_at']),
                'download_count' => (int) $r['download_count'],
                'comment_count'  => $comments[$id] ?? 0,
                'is_shared'      => isset($shared[$id]),
                'has_thumbnail'  => $r['thumb_version'] !== null,
                'encrypted'      => ($enc[$id] ?? 'none') !== 'none',
                'is_bundle'      => (int) $r['is_bundle'] === 1,
                'description'    => $r['description'] !== null && $r['description'] !== '' ? (string) $r['description'] : null,
                'access'         => $caps[$id] ?? null,
                'trash'          => $trash[$id] ?? null,
            ];
            if ($event) {
                unset($s['favorite'], $s['access']);
            }
            $out[] = $s;
        }
        return $out;
    }

    /** FileSummary for real-time events: no per-viewer fields (favorite, access). */
    public static function eventSummary(array $row, bool $withTrash = false): array
    {
        return self::summaries([$row], null, ['event' => true, 'trash' => $withTrash])[0];
    }

    // ================================================================= FolderSummary

    public static function folderSummary(array $row, ?array $viewer, array $o = []): array
    {
        return self::folderSummaries([$row], $viewer, $o)[0];
    }

    /**
     * FolderSummary for many rows in a constant number of queries.
     * Options as summaries() ('trash', 'event', 'access').
     */
    public static function folderSummaries(array $rows, ?array $viewer, array $o = []): array
    {
        $rows = array_values($rows);
        if ($rows === []) {
            return [];
        }
        $event = !empty($o['event']);
        $ids = array_map(static fn ($r) => (int) $r['id'], $rows);
        [$in, $p] = Db::inList($ids, 'fs');
        $p['now'] = Db::now();
        $shared = array_flip(array_map('intval', Db::column(
            "SELECT DISTINCT folder_id FROM shares WHERE folder_id IN {$in} AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > :now)",
            $p
        )));
        $caps = [];
        if (!$event && $viewer !== null) {
            $caps = $o['access'] ?? FileAccess::folderAccessForMany($viewer, $rows);
        }
        $trash = [];
        if (!empty($o['trash'])) {
            $trashed = array_values(array_filter($rows, static fn ($r) => $r['deleted_at'] !== null));
            if ($trashed !== []) {
                $trash = TrashService::infoMany($trashed, 'folder', $viewer);
            }
        }
        $users = self::userRefs(array_map(static fn ($r) => (int) $r['owner_id'], $rows));
        $hidden = $viewer !== null && !$event ? self::hiddenFolders($viewer, $rows, 'parent_id') : [];

        $out = [];
        foreach ($rows as $r) {
            $id = (int) $r['id'];
            $parent = $r['parent_id'] !== null ? (int) $r['parent_id'] : null;
            if ($parent !== null && isset($hidden[$parent])) {
                $parent = null;
            }
            $s = [
                'id'         => $id,
                'type'       => 'folder',
                'name'       => (string) $r['name'],
                'parent_id'  => $parent,
                'owner'      => $users[(int) $r['owner_id']] ?? self::unknownUser((int) $r['owner_id']),
                'color'      => $r['color'] ?? null,
                'created_at' => Db::iso($r['created_at']),
                'updated_at' => Db::iso($r['updated_at']),
                'is_shared'  => isset($shared[$id]),
                'access'     => $caps[$id] ?? null,
                'trash'      => $trash[$id] ?? null,
            ];
            if ($event) {
                unset($s['access']);
            }
            $out[] = $s;
        }
        return $out;
    }

    public static function folderEventSummary(array $row, bool $withTrash = false): array
    {
        return self::folderSummaries([$row], null, ['event' => true, 'trash' => $withTrash])[0];
    }

    // ================================================================= users, paths

    /** @return array<int,array{id:int,username:string,display_name:string}> */
    public static function userRefs(array $ids): array
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids), static fn ($i) => $i > 0)));
        if ($ids === []) {
            return [];
        }
        [$in, $p] = Db::inList($ids, 'ur');
        $out = [];
        foreach (Db::all("SELECT id, username, display_name FROM users WHERE id IN {$in}", $p) as $u) {
            $out[(int) $u['id']] = self::ref($u);
        }
        return $out;
    }

    /** UserRef from a users row. */
    public static function ref(array $u): array
    {
        return [
            'id'           => (int) $u['id'],
            'username'     => (string) $u['username'],
            'display_name' => (string) (($u['display_name'] ?? '') !== '' ? $u['display_name'] : $u['username']),
        ];
    }

    /** Display name of a user row/ref ("Kritarth"). */
    public static function displayName(?array $u): string
    {
        if ($u === null) {
            return 'Someone';
        }
        $n = (string) (($u['display_name'] ?? '') !== '' ? $u['display_name'] : ($u['username'] ?? ''));
        return $n !== '' ? $n : 'Someone';
    }

    /**
     * Breadcrumbs [{id,name}] from the visible root down to $folderId. Owners/admins see the
     * whole chain; share recipients only from the topmost folder shared with them.
     * @return array<int,array{id:int,name:string}>
     */
    public static function breadcrumbs(?array $viewer, ?int $folderId, ?array $map = null): array
    {
        if ($folderId === null || $folderId <= 0) {
            return [];
        }
        $map ??= FileAccess::folderMap([$folderId]);
        $chain = FileAccess::chain($map, $folderId);
        if ($chain === []) {
            return [];
        }
        if ($viewer !== null) {
            $root = FileAccess::sharedRootFor($viewer, $folderId, $map);
            if ($root === 0) {
                return [];
            }
            if ($root !== null) {
                $pos = array_search($root, $chain, true);
                $chain = $pos === false ? [] : array_slice($chain, 0, $pos + 1);
            }
        }
        $out = [];
        foreach (array_reverse($chain) as $fid) {
            $out[] = ['id' => $fid, 'name' => (string) $map[$fid]['name']];
        }
        return $out;
    }

    /** "/Work/Reports" (or "/" for the root) from breadcrumbs. */
    public static function pathOf(array $crumbs): string
    {
        return '/' . implode('/', array_map(static fn ($c) => (string) $c['name'], $crumbs));
    }

    /**
     * For a non-owner, non-admin viewer: the set of folder ids (taken from $key of $rows) that
     * must not be revealed because they are not inside a folder shared with the viewer.
     * @return array<int,true>
     */
    private static function hiddenFolders(array $viewer, array $rows, string $key): array
    {
        if (Policy::isAdmin($viewer)) {
            return [];
        }
        $uid = (int) $viewer['id'];
        $candidates = [];
        foreach ($rows as $r) {
            if ((int) $r['owner_id'] !== $uid && $r[$key] !== null) {
                $candidates[(int) $r[$key]] = true;
            }
        }
        if ($candidates === []) {
            return [];
        }
        $sharedFolders = [];
        foreach (FileAccess::viewerShares($uid) as $s) {
            if ($s['folder_id'] !== null) {
                $sharedFolders[(int) $s['folder_id']] = true;
            }
        }
        if ($sharedFolders === []) {
            return $candidates;
        }
        $map = FileAccess::folderMap(array_keys($candidates));
        $hidden = [];
        foreach (array_keys($candidates) as $fid) {
            $reachable = false;
            foreach (FileAccess::liveChain($map, $fid) as $c) {
                if (isset($sharedFolders[$c])) {
                    $reachable = true;
                    break;
                }
            }
            if (!$reachable) {
                $hidden[$fid] = true;
            }
        }
        return $hidden;
    }

    private static function unknownUser(int $id): array
    {
        return ['id' => $id, 'username' => '', 'display_name' => 'Unknown user'];
    }

    // ================================================================= names

    /**
     * Safe display/file name: no control characters, no / \ : * ? " < > |, no leading/trailing
     * dots or spaces, at most 255 bytes (extension kept), never empty. Delegates to A2's
     * FileWriter when present so uploads and renames follow exactly the same rules.
     */
    public static function sanitizeName(string $name): string
    {
        if (class_exists(FileWriter::class) && method_exists(FileWriter::class, 'sanitizeName')) {
            return FileWriter::sanitizeName($name);
        }
        if (!mb_check_encoding($name, 'UTF-8')) {
            $name = mb_convert_encoding($name, 'UTF-8', 'UTF-8');
        }
        $name = (string) preg_replace('/[\x00-\x1F\x7F\x{2028}\x{2029}]/u', '', $name);
        $name = str_replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], '', $name);
        $name = trim($name, " .\t");
        if (strlen($name) > self::MAX_NAME_BYTES) {
            $ext = MimeDetector::extension($name);
            $suffix = $ext !== '' ? '.' . $ext : '';
            $base = $ext !== '' ? substr($name, 0, -strlen($suffix)) : $name;
            $name = rtrim(mb_strcut($base, 0, self::MAX_NAME_BYTES - strlen($suffix), 'UTF-8'), ' .') . $suffix;
        }
        return $name === '' ? 'untitled' : $name;
    }

    public static function fileNameTaken(int $ownerId, ?int $folderId, string $name, ?int $exceptId = null): bool
    {
        $p = ['o' => $ownerId, 'n' => $name, 'x' => $exceptId ?? 0];
        $folderSql = 'folder_id IS NULL';
        if ($folderId !== null) {
            $folderSql = 'folder_id = :f';
            $p['f'] = $folderId;
        }
        return Db::value("SELECT 1 FROM files WHERE owner_id = :o AND {$folderSql} AND deleted_at IS NULL AND name = :n AND id <> :x LIMIT 1", $p) !== null;
    }

    public static function folderNameTaken(int $ownerId, ?int $parentId, string $name, ?int $exceptId = null): bool
    {
        $p = ['o' => $ownerId, 'n' => $name, 'x' => $exceptId ?? 0];
        $parentSql = 'parent_id IS NULL';
        if ($parentId !== null) {
            $parentSql = 'parent_id = :pa';
            $p['pa'] = $parentId;
        }
        return Db::value("SELECT 1 FROM folders WHERE owner_id = :o AND {$parentSql} AND deleted_at IS NULL AND name = :n AND id <> :x LIMIT 1", $p) !== null;
    }

    /** "report (1).pdf" style unique file name within a folder (live files only). */
    public static function uniqueName(int $ownerId, ?int $folderId, string $name, ?int $exceptFileId = null): string
    {
        if (class_exists(FileWriter::class) && method_exists(FileWriter::class, 'uniqueName')) {
            return FileWriter::uniqueName($ownerId, $folderId, $name, $exceptFileId);
        }
        return self::uniqueWith($name, static fn (string $n): bool => self::fileNameTaken($ownerId, $folderId, $n, $exceptFileId), true);
    }

    /** "Work (1)" style unique folder name within a parent (live folders only). */
    public static function uniqueFolderName(int $ownerId, ?int $parentId, string $name, ?int $exceptId = null): string
    {
        return self::uniqueWith($name, static fn (string $n): bool => self::folderNameTaken($ownerId, $parentId, $n, $exceptId), false);
    }

    private static function uniqueWith(string $name, callable $taken, bool $splitExt): string
    {
        if (!$taken($name)) {
            return $name;
        }
        $ext = $splitExt ? MimeDetector::extension($name) : '';
        $suffix = $ext !== '' ? '.' . $ext : '';
        $base = $ext !== '' ? substr($name, 0, -strlen($suffix)) : $name;
        for ($i = 1; $i <= 500; $i++) {
            $tag = " ({$i})";
            $b = mb_strcut($base, 0, self::MAX_NAME_BYTES - strlen($suffix) - strlen($tag), 'UTF-8');
            $candidate = $b . $tag . $suffix;
            if (!$taken($candidate)) {
                return $candidate;
            }
        }
        $tag = ' (' . bin2hex(random_bytes(4)) . ')';
        return mb_strcut($base, 0, self::MAX_NAME_BYTES - strlen($suffix) - strlen($tag), 'UTF-8') . $tag . $suffix;
    }
}
