<?php
declare(strict_types=1);

namespace FT\Sharing;

use FT\Auth\Auth;
use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Secrets;
use FT\Core\Stats;
use FT\Events\EventBus;
use FT\Files\FileAccess;
use FT\Http\Request;
use FT\Security\Policy;
use FT\Security\RateLimiter;

/**
 * Shares: public links and user shares of a file, a bundle of files or a folder
 * (docs/ARCHITECTURE.md §4 "Shares", §6, §9.2 ShareSummary, §9.4 "Shares", §10.2, §11).
 *
 * Rules enforced here (FileAccess decides what a share GRANTS; this class decides who may
 * CREATE / CHANGE one and keeps the rows consistent):
 *  - owners need the files.share permission; anyone else needs the "share" capability, i.e. a
 *    user share with allow_reshare. A re-share records parent_share_id, may grant at most the
 *    re-sharer's own level and flags, never outlives its parent, and is revoked with it.
 *  - a permission level sets the default allow_* flags (FileAccess::defaultFlags); explicit
 *    flags may only take grants away; allow_reshare is explicit (user shares only).
 *  - guests can receive shares but never create them.
 *  - link URLs are only ever returned to the share owner, the owner of the shared item and
 *    admins — never to recipients, never on the admin event channel, never in logs or Slack.
 *
 * Status is computed, never stored: revoked (revoked_at) > expired (expires_at <= now) >
 * exhausted (download limit reached: still viewable, no longer downloadable) > active.
 *
 * The notify()/slack()/fileSummary() helpers are shared by the other A4 services (comments,
 * texts, editor) so the "guard optional modules" logic lives in one place.
 */
final class ShareService
{
    public const KINDS = ['link', 'user'];
    public const PERMISSIONS = ['viewer', 'downloader', 'commenter', 'editor'];
    public const FLAGS = ['allow_preview', 'allow_download', 'allow_comments', 'allow_edit'];
    public const STATUSES = ['active', 'expired', 'revoked', 'exhausted'];
    public const MAX_ITEMS = 200;
    public const MAX_RECIPIENTS = 50;
    public const MAX_EXPIRY_SECONDS = 315360000; // 10 years
    public const MAX_DOWNLOADS = 1000000;
    /** For NEW or changed link passwords only; stored (legacy/imported) hashes keep working. */
    public const PASSWORD_MIN = 8;
    public const PASSWORD_MAX = 200;
    /** Wrong link passwords allowed per link per hour from all addresses together. */
    public const PASSWORD_SHARE_LIMIT = 30;
    public const PASSWORD_SHARE_WINDOW = 3600;
    /** Consecutive wrong passwords after which the link's owner is told (once per hour). */
    public const PASSWORD_ALERT_AFTER = 10;
    public const ANON_LABEL = 'Someone with the link';
    public const TOKEN_LENGTH = 22;

    /** allow_* flag => capability it maps to in FileAccess caps. */
    private const FLAG_CAPS = ['allow_preview' => 'preview', 'allow_download' => 'download', 'allow_comments' => 'comment', 'allow_edit' => 'edit'];
    private const LEVEL_LABELS = ['viewer' => 'Viewer', 'downloader' => 'Downloader', 'commenter' => 'Commenter', 'editor' => 'Editor'];

    // ================================================================== create

    /**
     * POST /shares. Returns the created rows (one per recipient for user shares; an existing
     * active share from the same person to the same recipient for the same item is updated
     * instead of duplicated).
     * @param array<string,mixed> $in
     * @return array<int,array<string,mixed>> shares rows
     */
    public static function create(array $actor, array $in): array
    {
        if (Policy::isGuest($actor)) {
            throw ApiException::forbidden('Guest accounts can open what is shared with them but cannot share items.');
        }
        $kind = is_string($in['kind'] ?? null) && $in['kind'] !== '' ? strtolower(trim($in['kind'])) : 'link';
        if (!in_array($kind, self::KINDS, true)) {
            throw ApiException::validation(['kind' => 'Choose a share link ("link") or specific people ("user").']);
        }
        $target = self::resolveTarget($actor, $in);
        $parent = $target['parent'];
        $permission = self::parsePermission($in['permission'] ?? null) ?? 'downloader';
        if ($parent !== null && FileAccess::LEVELS[$permission] > FileAccess::LEVELS[(string) $parent['permission']]) {
            throw ApiException::validation(['permission' => 'You can only share with the same or a lower permission than you were given (' . self::levelLabel((string) $parent['permission']) . ').']);
        }
        $flags = self::flagsFor($permission, $in, null, $parent, $kind);
        $expiresAt = self::clampToParent(self::parseExpiry($in)['value'], $parent);
        $title = self::cleanText($in['title'] ?? null, 255, 'title', false);
        $message = self::cleanText($in['message'] ?? null, 1000, 'message', true);

        $passwordHash = null;
        $maxDownloads = null;
        $recipients = [];
        if ($kind === 'link') {
            $pw = $in['password'] ?? null;
            if ($pw !== null && $pw !== '') {
                $passwordHash = password_hash(self::validatePassword($pw), PASSWORD_DEFAULT);
            }
            $maxDownloads = self::parseMaxDownloads($in['max_downloads'] ?? null);
        } else {
            $recipients = self::resolveRecipients($actor, $in['recipients'] ?? null, $target['owners']);
        }

        $now = Db::now();
        $base = [
            'owner_id'        => (int) $actor['id'],
            'kind'            => $kind,
            'target_type'     => $target['type'],
            'file_id'         => $target['type'] === 'file' ? (int) $target['files'][0]['id'] : null,
            'folder_id'       => $target['type'] === 'folder' ? (int) $target['folder']['id'] : null,
            'permission'      => $permission,
            'password_hash'   => $passwordHash,
            'expires_at'      => $expiresAt,
            'max_downloads'   => $maxDownloads,
            'title'           => $title,
            'message'         => $message,
            'parent_share_id' => $parent !== null ? (int) $parent['id'] : null,
            'created_at'      => $now,
            'updated_at'      => $now,
        ] + $flags;
        $fileIds = array_map(static fn (array $f): int => (int) $f['id'], $target['files']);

        $actorId = (int) $actor['id'];
        $cascade = ['updated' => [], 'revoked' => []];
        $result = Db::transaction(static function () use ($kind, $base, $recipients, $target, $fileIds, $now, $actorId, &$cascade): array {
            $out = [];
            if ($kind === 'link') {
                $id = Db::insert('shares', $base + ['token' => self::newToken()]);
                $out[] = ['id' => $id, 'new' => true, 'changes' => []];
            } else {
                foreach ($recipients as $r) {
                    $existing = null;
                    if ($target['type'] !== 'bundle') {
                        $existing = Db::one(
                            "SELECT * FROM shares WHERE kind = 'user' AND owner_id = :o AND recipient_id = :r AND target_type = :t
                               AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > :now)
                               AND " . ($target['type'] === 'file' ? 'file_id = :x' : 'folder_id = :x') . ' ORDER BY id DESC LIMIT 1',
                            ['o' => $base['owner_id'], 'r' => (int) $r['id'], 't' => $target['type'], 'now' => $now,
                             'x' => $target['type'] === 'file' ? $base['file_id'] : $base['folder_id']]
                        );
                    }
                    if ($existing !== null) {
                        $set = array_intersect_key($base, array_flip(['permission', 'allow_preview', 'allow_download', 'allow_comments', 'allow_edit', 'allow_reshare', 'expires_at', 'parent_share_id']));
                        if ($base['message'] !== null) {
                            $set['message'] = $base['message'];
                        }
                        if ($base['title'] !== null) {
                            $set['title'] = $base['title'];
                        }
                        $changes = self::diff($existing, $set);
                        if ($changes !== []) {
                            // The share dialog changes a person's access this way: the same
                            // cascade as PATCH /shares/{id} (re-shares clamped or revoked).
                            $cascade = self::mergeCascade($cascade, self::applyChange((int) $existing['id'], array_intersect_key($set, $changes) + ['updated_at' => $now], $actorId));
                        }
                        $out[] = ['id' => (int) $existing['id'], 'new' => false, 'changes' => $changes];
                        continue;
                    }
                    $id = Db::insert('shares', $base + ['recipient_id' => (int) $r['id']]);
                    $out[] = ['id' => $id, 'new' => true, 'changes' => []];
                }
            }
            if ($target['type'] === 'bundle') {
                foreach ($out as $o) {
                    if (!$o['new']) {
                        continue;
                    }
                    $values = [];
                    $params = [];
                    foreach ($fileIds as $i => $fid) {
                        $values[] = "(:s{$i}, :f{$i})";
                        $params["s{$i}"] = $o['id'];
                        $params["f{$i}"] = $fid;
                    }
                    Db::run('INSERT IGNORE INTO share_items (share_id, file_id) VALUES ' . implode(',', $values), $params);
                }
            }
            return $out;
        });
        FileAccess::reset();

        $rows = self::loadMany(array_column($result, 'id'));
        $byId = [];
        foreach ($rows as $row) {
            $byId[(int) $row['id']] = $row;
        }
        $actorName = self::displayName($actor);
        $created = 0;
        foreach ($result as $r) {
            $share = $byId[$r['id']] ?? null;
            if ($share === null) {
                continue;
            }
            if ($r['new']) {
                $created++;
                self::auditShare('share.create', $share, (int) $actor['id'], ['permission' => $share['permission'], 'reshare' => $share['parent_share_id'] !== null]);
                self::publish('share.created', $share, true);
                if ($share['kind'] === 'user') {
                    self::notifyRecipient($share, $actor, $target);
                }
            } elseif ($r['changes'] !== []) {
                self::auditShare('share.update', $share, (int) $actor['id'], ['changes' => $r['changes']]);
                self::publish('share.updated', $share, false);
            }
        }
        self::afterCascade($cascade, $actorId);
        if ($created > 0) {
            Stats::bump('shares_created', $created);
            EventBus::publish('stats.updated', ['metric' => 'shares_created', 'delta' => $created], [], ['admin' => true]);
            self::slack('share', array_filter([
                'Item'    => self::targetTitle($target, $title),
                'By'      => $actorName,
                'Type'    => $kind === 'link' ? 'Share link' . ($passwordHash !== null ? ' (password protected)' : '') : 'Shared with ' . implode(', ', array_map(static fn ($u) => self::displayName($u), $recipients)),
                'Access'  => self::levelLabel($permission),
                'Expires' => $expiresAt !== null ? gmdate('d M Y, H:i', (int) Db::toUnix($expiresAt)) . ' UTC' : 'Never',
            ], static fn ($v) => $v !== null && $v !== ''));
        }
        return array_values(array_filter(array_map(static fn ($r) => $byId[$r['id']] ?? null, $result)));
    }

    // ================================================================== read

    public static function find(int $id): ?array
    {
        return $id > 0 ? Db::one('SELECT * FROM shares WHERE id = ?', [$id]) : null;
    }

    /** @return array<int,array<string,mixed>> rows in the given id order */
    public static function loadMany(array $ids): array
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids), static fn ($i) => $i > 0)));
        if ($ids === []) {
            return [];
        }
        [$in, $p] = Db::inList($ids, 'sh');
        $rows = [];
        foreach (Db::all("SELECT * FROM shares WHERE id IN {$in}", $p) as $r) {
            $rows[(int) $r['id']] = $r;
        }
        $out = [];
        foreach ($ids as $id) {
            if (isset($rows[$id])) {
                $out[] = $rows[$id];
            }
        }
        return $out;
    }

    /**
     * Load a share the actor may see. Visible to: the share owner, the owner(s) of the shared
     * item, admins with admin.shares, and (read-only) the recipient. Anyone else gets a 404 so
     * share ids cannot be probed. With $manage the recipient gets a 403 instead.
     */
    public static function requireVisible(array $actor, int $id, bool $manage = false): array
    {
        $share = self::find($id);
        if ($share === null) {
            throw ApiException::notFound('share', 'SHARE_NOT_FOUND');
        }
        if (self::canManage($actor, $share)) {
            return $share;
        }
        if ($share['kind'] === 'user' && (int) $share['recipient_id'] === (int) $actor['id'] && $share['revoked_at'] === null) {
            if ($manage) {
                throw ApiException::forbidden('Only the person who shared this, the owner or an administrator can change it.');
            }
            return $share;
        }
        throw ApiException::notFound('share', 'SHARE_NOT_FOUND');
    }

    public static function canManage(array $actor, array $share): bool
    {
        $uid = (int) $actor['id'];
        if ((int) $share['owner_id'] === $uid) {
            return true;
        }
        if (Policy::isAdmin($actor) && Policy::can($actor, 'admin.shares')) {
            return true;
        }
        return in_array($uid, self::targetOwnerIds($share), true);
    }

    /** Owners of the shared item(s). @return int[] */
    public static function targetOwnerIds(array $share): array
    {
        switch ($share['target_type']) {
            case 'file':
                $o = Db::value('SELECT owner_id FROM files WHERE id = ?', [(int) $share['file_id']]);
                return $o !== null ? [(int) $o] : [];
            case 'folder':
                $o = Db::value('SELECT owner_id FROM folders WHERE id = ?', [(int) $share['folder_id']]);
                return $o !== null ? [(int) $o] : [];
            case 'bundle':
                return array_map('intval', Db::column(
                    'SELECT DISTINCT f.owner_id FROM share_items si JOIN files f ON f.id = si.file_id WHERE si.share_id = ?',
                    [(int) $share['id']]
                ));
        }
        return [];
    }

    public static function status(array $share, ?string $now = null): string
    {
        if ($share['revoked_at'] !== null) {
            return 'revoked';
        }
        $now ??= Db::now();
        if ($share['expires_at'] !== null && (string) $share['expires_at'] <= $now) {
            return 'expired';
        }
        if ($share['max_downloads'] !== null && (int) $share['download_count'] >= (int) $share['max_downloads']) {
            return 'exhausted';
        }
        return 'active';
    }

    /** Public URL of a link share token (pretty /s/<token> or index.php?r=/s/<token>). */
    public static function url(string $token): string
    {
        $base = Request::capture()->baseUrl();
        return Config::get('app.pretty_urls') ? $base . 's/' . $token : $base . 'index.php?r=/s/' . $token;
    }

    public static function summary(array $share, ?array $viewer, ?bool $withUrl = null): array
    {
        return self::summaries([$share], $viewer, $withUrl)[0];
    }

    /**
     * ShareSummary (§9.2) for many rows with a constant number of queries.
     * $withUrl: null = decide per viewer (share owner / item owner / admin), true/false = force
     * (event payloads for managers vs. recipients and the admin channel).
     * @param array<int,array<string,mixed>> $rows
     * @return array<int,array<string,mixed>>
     */
    public static function summaries(array $rows, ?array $viewer, ?bool $withUrl = null): array
    {
        $rows = array_values($rows);
        if ($rows === []) {
            return [];
        }
        $userIds = [];
        $fileIds = [];
        $folderIds = [];
        $bundleIds = [];
        foreach ($rows as $r) {
            $userIds[] = (int) $r['owner_id'];
            if ($r['recipient_id'] !== null) {
                $userIds[] = (int) $r['recipient_id'];
            }
            if ($r['target_type'] === 'file' && $r['file_id'] !== null) {
                $fileIds[] = (int) $r['file_id'];
            } elseif ($r['target_type'] === 'folder' && $r['folder_id'] !== null) {
                $folderIds[] = (int) $r['folder_id'];
            } elseif ($r['target_type'] === 'bundle') {
                $bundleIds[] = (int) $r['id'];
            }
        }
        $users = self::userRefs($userIds);
        $files = [];
        if ($fileIds !== []) {
            [$in, $p] = Db::inList($fileIds, 'sf');
            foreach (Db::all("SELECT id, name, owner_id FROM files WHERE id IN {$in}", $p) as $f) {
                $files[(int) $f['id']] = $f;
            }
        }
        $folders = [];
        if ($folderIds !== []) {
            [$in, $p] = Db::inList($folderIds, 'sd');
            foreach (Db::all("SELECT id, name, owner_id FROM folders WHERE id IN {$in}", $p) as $f) {
                $folders[(int) $f['id']] = $f;
            }
        }
        $items = [];
        $bundleOwners = [];
        $bundleFirst = [];
        if ($bundleIds !== []) {
            [$in, $p] = Db::inList($bundleIds, 'sb');
            foreach (Db::all("SELECT si.share_id, si.file_id, f.name, f.owner_id FROM share_items si JOIN files f ON f.id = si.file_id
                              WHERE si.share_id IN {$in} ORDER BY si.share_id, f.name", $p) as $it) {
                $sid = (int) $it['share_id'];
                $items[$sid][] = (int) $it['file_id'];
                $bundleOwners[$sid][(int) $it['owner_id']] = true;
                $bundleFirst[$sid] ??= (string) $it['name'];
            }
        }
        $viewerId = $viewer !== null ? (int) $viewer['id'] : 0;
        $viewerIsAdmin = $viewer !== null && Policy::isAdmin($viewer);
        $now = Db::now();
        $out = [];
        foreach ($rows as $r) {
            $id = (int) $r['id'];
            $targetOwners = [];
            $title = $r['title'] !== null && $r['title'] !== '' ? (string) $r['title'] : null;
            $fileIdsOut = [];
            switch ($r['target_type']) {
                case 'file':
                    $f = $files[(int) $r['file_id']] ?? null;
                    $title ??= $f !== null ? (string) $f['name'] : 'File';
                    $targetOwners = $f !== null ? [(int) $f['owner_id']] : [];
                    $fileIdsOut = [(int) $r['file_id']];
                    break;
                case 'folder':
                    $f = $folders[(int) $r['folder_id']] ?? null;
                    $title ??= $f !== null ? (string) $f['name'] : 'Folder';
                    $targetOwners = $f !== null ? [(int) $f['owner_id']] : [];
                    break;
                case 'bundle':
                    $fileIdsOut = $items[$id] ?? [];
                    $n = count($fileIdsOut);
                    $title ??= $n === 1 ? ($bundleFirst[$id] ?? '1 file') : $n . ' files';
                    $targetOwners = array_keys($bundleOwners[$id] ?? []);
                    break;
            }
            $showUrl = $withUrl ?? ($viewer !== null && ($viewerId === (int) $r['owner_id'] || in_array($viewerId, $targetOwners, true) || $viewerIsAdmin));
            $out[] = [
                'id'               => $id,
                'kind'             => (string) $r['kind'],
                'target_type'      => (string) $r['target_type'],
                'file_id'          => $r['target_type'] === 'file' ? (int) $r['file_id'] : null,
                'folder_id'        => $r['target_type'] === 'folder' ? (int) $r['folder_id'] : null,
                'file_ids'         => $fileIdsOut,
                'title'            => $title,
                'url'              => ($showUrl && $r['kind'] === 'link' && $r['token'] !== null) ? self::url((string) $r['token']) : null,
                'recipient'        => $r['recipient_id'] !== null ? ($users[(int) $r['recipient_id']] ?? self::unknownUser((int) $r['recipient_id'])) : null,
                'owner'            => $users[(int) $r['owner_id']] ?? self::unknownUser((int) $r['owner_id']),
                'permission'       => (string) $r['permission'],
                'allow_preview'    => (int) $r['allow_preview'] === 1,
                'allow_download'   => (int) $r['allow_download'] === 1,
                'allow_comments'   => (int) $r['allow_comments'] === 1,
                'allow_edit'       => (int) $r['allow_edit'] === 1,
                'allow_reshare'    => (int) $r['allow_reshare'] === 1,
                'has_password'     => $r['password_hash'] !== null && $r['password_hash'] !== '',
                'expires_at'       => Db::iso($r['expires_at']),
                'max_downloads'    => $r['max_downloads'] !== null ? (int) $r['max_downloads'] : null,
                'download_count'   => (int) $r['download_count'],
                'access_count'     => (int) $r['access_count'],
                'status'           => self::status($r, $now),
                'created_at'       => Db::iso($r['created_at']),
                'updated_at'       => Db::iso($r['updated_at']),
                'last_accessed_at' => Db::iso($r['last_accessed_at']),
                'message'          => $r['message'] !== null && $r['message'] !== '' ? (string) $r['message'] : null,
                'parent_share_id'  => $r['parent_share_id'] !== null ? (int) $r['parent_share_id'] : null,
            ];
        }
        return $out;
    }

    /**
     * Shares created by $actor. Filters: status (active|expired|revoked|exhausted|all), kind,
     * file_id, folder_id. @return array{0:array<int,array>,1:int} [rows, total]
     */
    public static function listMine(array $actor, array $filters, int $page, int $perPage): array
    {
        $where = ['s.owner_id = :me'];
        $params = ['me' => (int) $actor['id']];
        self::applyFilters($filters, $where, $params);
        return self::paged($where, $params, $page, $perPage);
    }

    /** All shares (admin.shares). Filters as listMine plus owner_id, recipient_id. */
    public static function adminList(array $filters, int $page, int $perPage): array
    {
        $where = ['1 = 1'];
        $params = [];
        if (!empty($filters['owner_id'])) {
            $where[] = 's.owner_id = :own';
            $params['own'] = (int) $filters['owner_id'];
        }
        if (!empty($filters['recipient_id'])) {
            $where[] = 's.recipient_id = :rcp';
            $params['rcp'] = (int) $filters['recipient_id'];
        }
        self::applyFilters($filters, $where, $params);
        return self::paged($where, $params, $page, $perPage);
    }

    /** Shares on one file (direct and bundles containing it), for its owner or an admin. */
    public static function forFile(array $actor, int $fileId, ?string $status = null): array
    {
        FileAccess::require($actor, $fileId, 'manage');
        $where = ['(s.file_id = :f OR s.id IN (SELECT si.share_id FROM share_items si WHERE si.file_id = :f2))'];
        $params = ['f' => $fileId, 'f2' => $fileId];
        if ($status !== null && $status !== '' && $status !== 'all') {
            $where[] = self::statusSql($status, $params);
        }
        return Db::all('SELECT s.* FROM shares s WHERE ' . implode(' AND ', $where) . ' ORDER BY s.created_at DESC, s.id DESC LIMIT 500', $params);
    }

    /**
     * Shared With Me (§9.2): one entry per item (file or folder) reachable through an active
     * user share whose target is not in the Trash. A bundle contributes one entry per file; an
     * item shared several times appears once (latest share).
     * @return array{0:array<int,array<string,mixed>>,1:int}
     */
    public static function sharedWithMe(array $actor, int $page, int $perPage, ?string $type = null): array
    {
        $uid = (int) $actor['id'];
        // Only shares that still grant something: FileAccess::viewerShares() has dropped revoked,
        // expired, inactive-creator and broken re-share rows (and trimmed bundle re-shares to the
        // items their chain reaches); the item's owner must be active as well.
        $fileShares = [];
        $folderShares = [];
        $bundleShares = [];
        $trimmed = [];
        foreach (FileAccess::viewerShares($uid) as $s) {
            $sid = (int) $s['id'];
            if ($s['target_type'] === 'file') {
                $fileShares[] = $sid;
            } elseif ($s['target_type'] === 'folder') {
                $folderShares[] = $sid;
            } elseif ($s['target_type'] === 'bundle') {
                if (isset($s['_items'])) {
                    $trimmed[$sid] = $s['_items'];
                } else {
                    $bundleShares[] = $sid;
                }
            }
        }
        $params = [];
        $parts = [];
        $ownerActive = static fn (string $alias): string => "EXISTS (SELECT 1 FROM users ou WHERE ou.id = {$alias}.owner_id AND ou.status = 'active' AND ou.deleted_at IS NULL)";
        if ($type !== 'folder') {
            if ($fileShares !== []) {
                [$in, $p] = Db::inList($fileShares, 'wsf');
                $parts[] = "SELECT s.id AS share_id, 'file' AS item_type, s.file_id AS item_id, s.created_at AS shared_at
                              FROM shares s JOIN files f ON f.id = s.file_id
                             WHERE s.id IN {$in} AND f.deleted_at IS NULL AND " . $ownerActive('f');
                $params += $p;
            }
            if ($bundleShares !== [] || $trimmed !== []) {
                $or = [];
                if ($bundleShares !== []) {
                    [$in, $p] = Db::inList($bundleShares, 'wsb');
                    $or[] = "si.share_id IN {$in}";
                    $params += $p;
                }
                $n = 0;
                foreach ($trimmed as $sid => $items) {
                    [$inI, $pI] = Db::inList($items, 'wti' . $n . '_');
                    $or[] = "(si.share_id = :wts{$n} AND si.file_id IN {$inI})";
                    $params += $pI + ["wts{$n}" => $sid];
                    $n++;
                }
                $parts[] = "SELECT s.id AS share_id, 'file' AS item_type, si.file_id AS item_id, s.created_at AS shared_at
                              FROM shares s JOIN share_items si ON si.share_id = s.id JOIN files f ON f.id = si.file_id
                             WHERE (" . implode(' OR ', $or) . ') AND f.deleted_at IS NULL AND ' . $ownerActive('f');
            }
        }
        if ($type !== 'file' && $folderShares !== []) {
            // Every branch names its columns: with ?type=folder this is the only branch.
            [$in, $p] = Db::inList($folderShares, 'wsd');
            $parts[] = "SELECT s.id AS share_id, 'folder' AS item_type, s.folder_id AS item_id, s.created_at AS shared_at
                          FROM shares s JOIN folders d ON d.id = s.folder_id
                         WHERE s.id IN {$in} AND d.deleted_at IS NULL AND " . $ownerActive('d');
            $params += $p;
        }
        if ($parts === []) {
            return [[], 0];
        }
        $grouped = 'SELECT x.item_type, x.item_id, MAX(x.share_id) AS share_id, MAX(x.shared_at) AS shared_at FROM ('
            . implode(' UNION ALL ', $parts) . ') x GROUP BY x.item_type, x.item_id';
        $total = (int) Db::value("SELECT COUNT(*) FROM ({$grouped}) g", $params);
        $rows = Db::all("{$grouped} ORDER BY shared_at DESC, share_id DESC LIMIT :lim OFFSET :off", $params + ['lim' => $perPage, 'off' => ($page - 1) * $perPage]);
        if ($rows === []) {
            return [[], $total];
        }
        $shares = [];
        foreach (self::loadMany(array_column($rows, 'share_id')) as $s) {
            $shares[(int) $s['id']] = $s;
        }
        $summaries = [];
        foreach (self::summaries(array_values($shares), $actor, false) as $sum) {
            $summaries[$sum['id']] = $sum;
        }
        $fileRows = [];
        $folderRows = [];
        $fileIds = [];
        $folderIds = [];
        foreach ($rows as $r) {
            if ($r['item_type'] === 'file') {
                $fileIds[] = (int) $r['item_id'];
            } else {
                $folderIds[] = (int) $r['item_id'];
            }
        }
        if ($fileIds !== []) {
            [$in, $p] = Db::inList($fileIds, 'wf');
            foreach (Db::all("SELECT * FROM files WHERE id IN {$in}", $p) as $f) {
                $fileRows[(int) $f['id']] = $f;
            }
        }
        if ($folderIds !== []) {
            [$in, $p] = Db::inList($folderIds, 'wd');
            foreach (Db::all("SELECT * FROM folders WHERE id IN {$in}", $p) as $f) {
                $folderRows[(int) $f['id']] = $f;
            }
        }
        $fileSums = self::fileSummaries(array_values($fileRows), $actor);
        $folderSums = self::folderSummaries(array_values($folderRows), $actor);
        $out = [];
        foreach ($rows as $r) {
            $itemId = (int) $r['item_id'];
            $item = $r['item_type'] === 'file' ? ($fileSums[$itemId] ?? null) : ($folderSums[$itemId] ?? null);
            $sum = $summaries[(int) $r['share_id']] ?? null;
            if ($item === null || $sum === null) {
                continue;
            }
            $sum['url'] = null; // recipients never see link URLs
            $out[] = [
                'share'            => $sum,
                'item'             => $item,
                'shared_at'        => Db::iso((string) $r['shared_at']),
                'last_accessed_at' => $sum['last_accessed_at'],
                'owner'            => $sum['owner'],
                'permission'       => is_array($item['access'] ?? null) && ($item['access']['role'] ?? null) !== null ? $item['access']['role'] : $sum['permission'],
                'expires_at'       => $sum['expires_at'],
            ];
        }
        return [$out, $total];
    }

    /**
     * Record that a recipient opened an item shared with them (Shared With Me "last accessed").
     * Throttled to one write per share per minute. A3 can call this from file previews/downloads.
     */
    public static function markOpened(int $userId, array $fileRow): void
    {
        try {
            if ((int) $fileRow['owner_id'] === $userId) {
                return;
            }
            $ids = array_map(static fn ($s) => (int) $s['id'], FileAccess::sharesFor($userId, $fileRow));
            self::touchShares($ids);
        } catch (\Throwable $e) {
            Logger::warning('share', 'Could not record share access', ['error' => $e->getMessage()]);
        }
    }

    /** Same as markOpened() for a folder the recipient opened. */
    public static function markFolderOpened(int $userId, int $folderId): void
    {
        try {
            $chain = FileAccess::liveChain(FileAccess::folderMap([$folderId]), $folderId);
            $ids = [];
            foreach (FileAccess::viewerShares($userId) as $s) {
                if ($s['folder_id'] !== null && in_array((int) $s['folder_id'], $chain, true)) {
                    $ids[] = (int) $s['id'];
                }
            }
            self::touchShares($ids);
        } catch (\Throwable $e) {
            Logger::warning('share', 'Could not record share access', ['error' => $e->getMessage()]);
        }
    }

    // ================================================================== update / revoke

    /**
     * PATCH /shares/{id} {permission?, password?(""=remove), expires_at?|expires_in?, max_downloads?,
     * allow_*?, title?, message?}. Lowering a share also clamps its re-shares.
     */
    public static function update(array $actor, int $id, array $in): array
    {
        $share = self::requireVisible($actor, $id, true);
        if ($share['revoked_at'] !== null) {
            throw ApiException::conflict('This share has been turned off and can no longer be changed.');
        }
        $parent = $share['parent_share_id'] !== null ? self::find((int) $share['parent_share_id']) : null;
        $permission = (string) $share['permission'];
        if (array_key_exists('permission', $in)) {
            $permission = self::parsePermission($in['permission']) ?? $permission;
        }
        if ($parent !== null && FileAccess::LEVELS[$permission] > FileAccess::LEVELS[(string) $parent['permission']]) {
            throw ApiException::validation(['permission' => 'A re-share cannot grant more than ' . self::levelLabel((string) $parent['permission']) . ' access.']);
        }
        $set = ['permission' => $permission] + self::flagsFor($permission, $in, $share, $parent, (string) $share['kind']);

        $exp = self::parseExpiry($in);
        if ($exp['given']) {
            $set['expires_at'] = self::clampToParent($exp['value'], $parent);
        }
        if (array_key_exists('password', $in)) {
            $pw = $in['password'];
            $empty = $pw === null || $pw === '';
            if ($share['kind'] !== 'link') {
                if (!$empty) {
                    throw ApiException::validation(['password' => 'Only share links can have a password.']);
                }
            } else {
                $set['password_hash'] = $empty ? null : password_hash(self::validatePassword($pw), PASSWORD_DEFAULT);
            }
        }
        if (array_key_exists('max_downloads', $in)) {
            $limit = self::parseMaxDownloads($in['max_downloads']);
            if ($share['kind'] !== 'link') {
                if ($limit !== null) {
                    throw ApiException::validation(['max_downloads' => 'Only share links can have a download limit.']);
                }
            } else {
                $set['max_downloads'] = $limit;
            }
        }
        if (array_key_exists('title', $in)) {
            $set['title'] = self::cleanText($in['title'], 255, 'title', false);
        }
        if (array_key_exists('message', $in)) {
            $set['message'] = self::cleanText($in['message'], 1000, 'message', true);
        }
        $changes = self::diff($share, $set);
        if ($changes === []) {
            return $share;
        }
        $applied = array_intersect_key($set, $changes);
        $applied['updated_at'] = Db::now();
        $children = Db::transaction(static fn (): array => self::applyChange((int) $share['id'], $applied, (int) $actor['id']));
        FileAccess::reset();
        $fresh = self::find((int) $share['id']) ?? $share;
        self::auditShare('share.update', $fresh, (int) $actor['id'], ['changes' => $changes]);
        self::publish('share.updated', $fresh, false);
        self::afterCascade($children, (int) $actor['id']);
        return $fresh;
    }

    /** DELETE /shares/{id}: revoke immediately, together with every re-share made from it. */
    public static function revoke(array $actor, int $id): array
    {
        $share = self::requireVisible($actor, $id, true);
        if ($share['revoked_at'] !== null) {
            return $share;
        }
        $ids = Db::transaction(static fn (): array => self::revokeTree((int) $share['id'], (int) $actor['id']));
        FileAccess::reset();
        self::afterCascade(['updated' => [], 'revoked' => $ids], (int) $actor['id'], (int) $share['id']);
        return self::find((int) $share['id']) ?? $share;
    }

    /**
     * A6 maintenance (expire_shares): shares past expires_at that were not reported yet notify
     * their owner once (category share_expired), publish share.expired and get expired_notified_at.
     */
    public static function expireDue(int $limit = 200): int
    {
        $limit = max(1, min(1000, $limit));
        $rows = Db::all(
            'SELECT * FROM shares WHERE revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= :now
               AND expired_notified_at IS NULL ORDER BY expires_at ASC LIMIT :lim',
            ['now' => Db::now(), 'lim' => $limit]
        );
        $done = 0;
        foreach ($rows as $share) {
            // Claim the row first so two overlapping maintenance runs never notify twice.
            $claimed = Db::run('UPDATE shares SET expired_notified_at = :now WHERE id = :id AND expired_notified_at IS NULL', ['now' => Db::now(), 'id' => (int) $share['id']])->rowCount();
            if ($claimed !== 1) {
                continue;
            }
            $done++;
            try {
                $title = self::summary($share, null, false)['title'];
                $recipient = $share['recipient_id'] !== null ? Db::one('SELECT id, username, display_name FROM users WHERE id = ?', [(int) $share['recipient_id']]) : null;
                $text = $share['kind'] === 'link'
                    ? 'Your share link for “' . $title . '” has expired'
                    : 'Your share of “' . $title . '” with ' . self::displayName($recipient) . ' has expired';
                self::notify((int) $share['owner_id'], 'share_expired', 'share.expired', $text, '', array_filter([
                    'share_id'  => (int) $share['id'],
                    'file_id'   => $share['file_id'] !== null ? (int) $share['file_id'] : null,
                    'folder_id' => $share['folder_id'] !== null ? (int) $share['folder_id'] : null,
                    'link'      => '#/shared',
                ], static fn ($v) => $v !== null), 'share-expired:' . (int) $share['id'], null);
                self::auditShare('share.expired', $share, null, []);
                self::publish('share.expired', $share, false, null);
            } catch (\Throwable $e) {
                Logger::exception('share', $e, ['share_id' => (int) $share['id']]);
            }
        }
        return $done;
    }

    // ================================================================== public link support

    /** Link share by token (new 22-char base62 or legacy 32-hex), or null. */
    public static function findByToken(string $token): ?array
    {
        if (!preg_match('/^[A-Za-z0-9]{16,64}$/', $token)) {
            return null;
        }
        return Db::one("SELECT * FROM shares WHERE token = ? AND kind = 'link'", [$token]);
    }

    /**
     * Why a link cannot be used: null (usable), 'missing', 'revoked', 'expired' or
     * 'unavailable' (owner disabled/deleted, or the shared item is gone / in the Trash).
     */
    public static function linkProblem(?array $share): ?string
    {
        if ($share === null) {
            return 'missing';
        }
        if ($share['revoked_at'] !== null) {
            return 'revoked';
        }
        if ($share['expires_at'] !== null && (string) $share['expires_at'] <= Db::now()) {
            return 'expired';
        }
        if (!self::userActive((int) $share['owner_id'])) {
            return 'unavailable';
        }
        if ($share['parent_share_id'] !== null) {
            // A link made from a re-share lives only as long as its chain still reaches the item.
            $share = FileAccess::honoured([$share])[0] ?? null;
            if ($share === null) {
                return 'unavailable';
            }
        }
        switch ($share['target_type']) {
            case 'file':
                $f = Db::one('SELECT owner_id, deleted_at FROM files WHERE id = ?', [(int) $share['file_id']]);
                return ($f === null || $f['deleted_at'] !== null || !self::userActive((int) $f['owner_id'])) ? 'unavailable' : null;
            case 'bundle':
                $p = ['s' => (int) $share['id']];
                $only = '';
                if (isset($share['_items'])) {
                    [$inI, $pI] = Db::inList($share['_items'], 'li');
                    $only = " AND si.file_id IN {$inI}";
                    $p += $pI;
                }
                $n = (int) Db::value(
                    "SELECT COUNT(*) FROM share_items si JOIN files f ON f.id = si.file_id JOIN users u ON u.id = f.owner_id
                      WHERE si.share_id = :s AND f.deleted_at IS NULL AND u.deleted_at IS NULL AND u.status = 'active'{$only}",
                    $p
                );
                return $n > 0 ? null : 'unavailable';
            case 'folder':
                $d = Db::one('SELECT id, owner_id, deleted_at FROM folders WHERE id = ?', [(int) $share['folder_id']]);
                if ($d === null || $d['deleted_at'] !== null || !self::userActive((int) $d['owner_id'])) {
                    return 'unavailable';
                }
                $map = FileAccess::folderMap([(int) $d['id']]);
                return count(FileAccess::liveChain($map, (int) $d['id'])) === count(FileAccess::chain($map, (int) $d['id'])) ? null : 'unavailable';
        }
        return 'unavailable';
    }

    /**
     * Count one download atomically. Returns false when the limit has been reached (or the share
     * was revoked meanwhile) — the check and the increment are the same UPDATE, so concurrent
     * downloads can never exceed max_downloads.
     */
    public static function consumeDownload(array $share): bool
    {
        $n = Db::run(
            'UPDATE shares SET download_count = download_count + 1, last_accessed_at = :now
              WHERE id = :id AND revoked_at IS NULL AND (max_downloads IS NULL OR download_count < max_downloads)',
            ['now' => Db::now(), 'id' => (int) $share['id']]
        )->rowCount();
        return $n === 1;
    }

    // ------------------------------------------------------------------ link password guessing
    //
    // Per-IP limits alone do not stop a botnet (or one IPv6 site rotating addresses) from guessing
    // a link password. On top of the per-IP bucket (RateLimiter 'share_password', IPv6 per /48)
    // every link has a bucket of its own, independent of the address, and the owner is told once
    // an hour while wrong passwords keep coming in a row. Counters live in the rate_limits table
    // (hashed keys, pruned by RateLimiter::prune()).

    /**
     * Count one password attempt on a link (all addresses together) BEFORE checking it.
     * @return array{allowed:bool,retry_after:int,hits:int}
     */
    public static function passwordAttempt(int $shareId): array
    {
        $now = time();
        $start = $now - ($now % self::PASSWORD_SHARE_WINDOW);
        $key = self::counterKey('share_password_share', $shareId, $start);
        try {
            Db::run(
                'INSERT INTO rate_limits (bucket, hits, expires_at) VALUES (:b, 1, :e) ON DUPLICATE KEY UPDATE hits = hits + 1',
                ['b' => $key, 'e' => $start + self::PASSWORD_SHARE_WINDOW]
            );
            $hits = (int) Db::value('SELECT hits FROM rate_limits WHERE bucket = ?', [$key]);
        } catch (\Throwable $e) {
            Logger::warning('security', 'Share password limiter unavailable', ['error' => $e->getMessage()]);
            return ['allowed' => true, 'retry_after' => 0, 'hits' => 0];
        }
        return ['allowed' => $hits <= self::PASSWORD_SHARE_LIMIT, 'retry_after' => max(1, $start + self::PASSWORD_SHARE_WINDOW - $now), 'hits' => $hits];
    }

    /** The password was right: give the attempt back, so only failures use up the link's allowance. */
    public static function passwordAttemptRefund(int $shareId): void
    {
        $now = time();
        try {
            Db::run(
                'UPDATE rate_limits SET hits = IF(hits > 0, hits - 1, 0) WHERE bucket = :b',
                ['b' => self::counterKey('share_password_share', $shareId, $now - ($now % self::PASSWORD_SHARE_WINDOW))]
            );
        } catch (\Throwable $e) {
            Logger::warning('security', 'Share password limiter refund failed', ['error' => $e->getMessage()]);
        }
    }

    /**
     * A wrong link password. Counts the run of consecutive failures (reset by a right password or
     * after a quiet day) and, from PASSWORD_ALERT_AFTER on, notifies the link's owner (category
     * security, at most once per link per hour). @return int consecutive failures so far
     */
    public static function passwordFailed(array $share): int
    {
        $id = (int) $share['id'];
        $now = time();
        $key = self::counterKey('share_password_fails', $id, 0);
        try {
            Db::run(
                'INSERT INTO rate_limits (bucket, hits, expires_at) VALUES (:b, 1, :e)
                 ON DUPLICATE KEY UPDATE hits = IF(expires_at < :now, 1, hits + 1), expires_at = :e2',
                ['b' => $key, 'e' => $now + 86400, 'now' => $now, 'e2' => $now + 86400]
            );
            $n = (int) Db::value('SELECT hits FROM rate_limits WHERE bucket = ?', [$key]);
        } catch (\Throwable $e) {
            Logger::warning('security', 'Share password failure counter unavailable', ['error' => $e->getMessage()]);
            return 0;
        }
        if ($n >= self::PASSWORD_ALERT_AFTER) {
            try {
                $title = self::summary($share, null, false)['title'];
                Logger::security('Repeated wrong share link passwords', ['share_id' => $id, 'failures' => $n]);
                self::notify(
                    (int) $share['owner_id'],
                    'security',
                    'share.password_attempts',
                    'Someone is trying to guess the password of your share link',
                    $n . ' wrong passwords in a row were entered for your link to “' . $title . '”. If this was not you or someone you sent it to, change the password or turn the link off.',
                    ['share_id' => $id, 'failures' => $n, 'link' => '#/shared'],
                    'share-pw:' . $id . ':' . gmdate('YmdH'),
                    null
                );
            } catch (\Throwable $e) {
                Logger::warning('share', 'Password alert failed', ['share_id' => $id, 'error' => $e->getMessage()]);
            }
        }
        return $n;
    }

    /** A right link password ends the run of failures. */
    public static function passwordSucceeded(int $shareId): void
    {
        try {
            Db::run('DELETE FROM rate_limits WHERE bucket = ?', [self::counterKey('share_password_fails', $shareId, 0)]);
        } catch (\Throwable $e) {
            Logger::warning('security', 'Share password failure counter reset failed', ['error' => $e->getMessage()]);
        }
    }

    /**
     * Rate-limit subject of an address for link passwords: IPv4 as is, IPv6 collapsed to its /48
     * — a single site usually holds a whole /48, so a /64 bucket (RateLimiter::ipSubject) would
     * still give one attacker 65,536 fresh buckets.
     */
    public static function passwordIpSubject(string $ip): string
    {
        if (str_contains($ip, ':')) {
            $bin = @inet_pton($ip);
            if ($bin !== false && strlen($bin) === 16 && !str_starts_with($bin, str_repeat("\0", 10) . "\xff\xff")) {
                return bin2hex(substr($bin, 0, 6)) . '::/48';
            }
        }
        return RateLimiter::ipSubject($ip);
    }

    private static function counterKey(string $bucket, int $shareId, int $start): string
    {
        return hash('sha256', $bucket . '|share' . $shareId . '|' . $start);
    }

    /** access_count + 1 and last_accessed_at = now (link page opened). */
    public static function recordAccess(array $share): void
    {
        Db::run('UPDATE shares SET access_count = access_count + 1, last_accessed_at = :now WHERE id = :id', ['now' => Db::now(), 'id' => (int) $share['id']]);
    }

    /**
     * Live files of a bundle share (sorted by name). For a bundle made from a re-share, only the
     * items its chain still reaches (FileAccess::honoured()).
     */
    public static function bundleFiles(array $share, int $limit = self::MAX_ITEMS): array
    {
        if ($share['parent_share_id'] !== null && empty($share['_honoured'])) {
            $share = FileAccess::honoured([$share])[0] ?? null;
            if ($share === null) {
                return [];
            }
        }
        $p = ['s' => (int) $share['id'], 'lim' => max(1, $limit)];
        $only = '';
        if (isset($share['_items'])) {
            [$inI, $pI] = Db::inList($share['_items'], 'bi');
            $only = " AND f.id IN {$inI}";
            $p += $pI;
        }
        return Db::all(
            "SELECT f.* FROM share_items si JOIN files f ON f.id = si.file_id
              WHERE si.share_id = :s AND f.deleted_at IS NULL{$only} ORDER BY f.name ASC, f.id ASC LIMIT :lim",
            $p
        );
    }

    /**
     * Contents of a folder inside a folder link share: only the shared root and its live
     * descendants are reachable. Throws FOLDER_NOT_FOUND otherwise.
     * @return array{folder:array,breadcrumbs:array,folders:array,files:array,truncated:bool}
     */
    public static function linkFolder(array $share, int $folderId, int $maxFiles = 500, int $maxFolders = 200): array
    {
        if ($share['target_type'] !== 'folder' || $share['folder_id'] === null) {
            throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
        }
        $root = (int) $share['folder_id'];
        $map = FileAccess::folderMap([$folderId]);
        $chain = FileAccess::chain($map, $folderId);
        $pos = array_search($root, $chain, true);
        if ($pos === false) {
            throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
        }
        $visible = array_slice($chain, 0, $pos + 1); // current … root
        foreach ($visible as $fid) {
            if ($map[$fid]['deleted_at'] !== null) {
                throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
            }
        }
        $crumbs = [];
        foreach (array_reverse($visible) as $fid) {
            $crumbs[] = ['id' => $fid, 'name' => (string) $map[$fid]['name']];
        }
        $folders = Db::all(
            'SELECT id, name, updated_at FROM folders WHERE parent_id = :p AND deleted_at IS NULL ORDER BY name ASC LIMIT :lim',
            ['p' => $folderId, 'lim' => $maxFolders + 1]
        );
        $files = Db::all(
            'SELECT * FROM files WHERE folder_id = :p AND deleted_at IS NULL ORDER BY name ASC, id ASC LIMIT :lim',
            ['p' => $folderId, 'lim' => $maxFiles + 1]
        );
        $truncated = count($folders) > $maxFolders || count($files) > $maxFiles;
        return [
            'folder'      => ['id' => $folderId, 'name' => (string) $map[$folderId]['name'], 'is_root' => $folderId === $root],
            'breadcrumbs' => $crumbs,
            'folders'     => array_slice($folders, 0, $maxFolders),
            'files'       => array_slice($files, 0, $maxFiles),
            'truncated'   => $truncated,
        ];
    }

    // ================================================================== shared helpers (A4)

    /**
     * Notification through A5's Notifier; until A5 is installed, an in-app notification row +
     * notification.created event (no push / e-mail). Never notifies a disabled/deleted user.
     */
    public static function notify(int $userId, string $category, string $type, string $title, string $body = '', array $data = [], ?string $dedupeKey = null, ?int $actorId = null): ?int
    {
        if ($userId <= 0 || ($actorId !== null && $userId === $actorId && !in_array($category, ['security', 'login', 'quota', 'upload'], true))) {
            return null;
        }
        $title = mb_substr($title, 0, 200);
        $body = mb_substr($body, 0, 1000);
        try {
            $notifier = 'FT\\Notifications\\Notifier';
            if (class_exists($notifier) && method_exists($notifier, 'notify')) {
                return $notifier::notify($userId, $category, $type, $title, $body, $data, $dedupeKey, $actorId);
            }
            if (!self::userActive($userId)) {
                return null;
            }
            $pref = Db::value('SELECT in_app FROM notification_preferences WHERE user_id = ? AND category = ?', [$userId, $category]);
            if ($pref !== null && (int) $pref === 0) {
                return null;
            }
            $now = Db::now();
            $n = Db::run(
                'INSERT IGNORE INTO notifications (user_id, category, type, title, body, data, actor_id, dedupe_key, created_at)
                 VALUES (:u, :c, :t, :ti, :b, :d, :a, :k, :now)',
                ['u' => $userId, 'c' => $category, 't' => mb_substr($type, 0, 48), 'ti' => $title, 'b' => $body,
                 'd' => json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), 'a' => $actorId,
                 'k' => $dedupeKey !== null ? mb_substr($dedupeKey, 0, 120) : null, 'now' => $now]
            );
            if ($n->rowCount() !== 1) {
                return null; // duplicate (dedupe key)
            }
            $id = (int) Db::pdo()->lastInsertId();
            $actor = $actorId !== null ? Db::one('SELECT id, username, display_name FROM users WHERE id = ?', [$actorId]) : null;
            EventBus::publish('notification.created', [
                'notification' => [
                    'id' => $id, 'category' => $category, 'type' => $type, 'title' => $title, 'body' => $body,
                    'data' => $data === [] ? (object) [] : $data, 'actor' => $actor !== null ? Auth::ref($actor) : null,
                    'read' => false, 'created_at' => Db::iso($now),
                ],
                'unread_count' => (int) Db::value('SELECT COUNT(*) FROM notifications WHERE user_id = ? AND read_at IS NULL', [$userId]),
            ], [$userId], ['actor_id' => $actorId]);
            return $id;
        } catch (\Throwable $e) {
            Logger::warning('share', 'Notification failed', ['type' => $type, 'error' => $e->getMessage()]);
            return null;
        }
    }

    /** Slack message through A5 (guarded; never fails the caller). */
    public static function slack(string $event, array $fields): void
    {
        $slack = 'FT\\Notifications\\Slack';
        if (!class_exists($slack) || !method_exists($slack, 'notify')) {
            return;
        }
        try {
            $slack::notify($event, $fields);
        } catch (\Throwable $e) {
            Logger::warning('share', 'Slack notification failed', ['event' => $event, 'error' => $e->getMessage()]);
        }
    }

    /**
     * FileSummary for rows (A3 FileRepository when present, else A2 FileWriter::summary, else a
     * minimal local shape). $viewer null = event payload (no per-viewer fields).
     * @return array<int,array<string,mixed>> keyed by file id
     */
    public static function fileSummaries(array $rows, ?array $viewer): array
    {
        $rows = array_values($rows);
        if ($rows === []) {
            return [];
        }
        $out = [];
        $repo = 'FT\\Files\\FileRepository';
        if (class_exists($repo) && method_exists($repo, 'summaries')) {
            try {
                foreach ($repo::summaries($rows, $viewer, $viewer === null ? ['event' => true] : []) as $s) {
                    $out[(int) $s['id']] = $s;
                }
                return $out;
            } catch (\Throwable $e) {
                Logger::warning('share', 'FileRepository::summaries failed; using a minimal summary', ['error' => $e->getMessage()]);
            }
        }
        foreach ($rows as $r) {
            $out[(int) $r['id']] = self::basicFileSummary($r, $viewer);
        }
        return $out;
    }

    public static function fileSummary(array $row, ?array $viewer): array
    {
        unset($row['access']);
        return self::fileSummaries([$row], $viewer)[(int) $row['id']];
    }

    /** @return array<int,array<string,mixed>> FolderSummary keyed by folder id */
    public static function folderSummaries(array $rows, ?array $viewer): array
    {
        $rows = array_values($rows);
        if ($rows === []) {
            return [];
        }
        $out = [];
        $repo = 'FT\\Files\\FileRepository';
        if (class_exists($repo) && method_exists($repo, 'folderSummaries')) {
            try {
                foreach ($repo::folderSummaries($rows, $viewer, $viewer === null ? ['event' => true] : []) as $s) {
                    $out[(int) $s['id']] = $s;
                }
                return $out;
            } catch (\Throwable $e) {
                Logger::warning('share', 'FileRepository::folderSummaries failed; using a minimal summary', ['error' => $e->getMessage()]);
            }
        }
        $users = self::userRefs(array_map(static fn ($r) => (int) $r['owner_id'], $rows));
        foreach ($rows as $r) {
            $out[(int) $r['id']] = [
                'id' => (int) $r['id'], 'type' => 'folder', 'name' => (string) $r['name'],
                'parent_id' => null, 'owner' => $users[(int) $r['owner_id']] ?? self::unknownUser((int) $r['owner_id']),
                'created_at' => Db::iso($r['created_at']), 'updated_at' => Db::iso($r['updated_at']),
                'is_shared' => true, 'access' => $viewer !== null ? FileAccess::folderAccessFor($viewer, $r) : null, 'trash' => null,
            ];
        }
        return $out;
    }

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
            $out[(int) $u['id']] = Auth::ref($u);
        }
        return $out;
    }

    public static function displayName(?array $u): string
    {
        if ($u === null) {
            return 'Someone';
        }
        $n = (string) (($u['display_name'] ?? '') !== '' ? $u['display_name'] : ($u['username'] ?? ''));
        return $n !== '' ? $n : 'Someone';
    }

    public static function levelLabel(string $permission): string
    {
        return self::LEVEL_LABELS[$permission] ?? ucfirst($permission);
    }

    public static function userActive(int $userId): bool
    {
        $u = Db::one('SELECT status, deleted_at FROM users WHERE id = ?', [$userId]);
        return $u !== null && $u['deleted_at'] === null && $u['status'] === 'active';
    }

    // ================================================================== internals: targets

    /**
     * Resolve and authorise what is being shared.
     * @return array{type:string,files:array<int,array>,folder:?array,parent:?array,owners:int[]}
     */
    private static function resolveTarget(array $actor, array $in): array
    {
        $raw = $in['file_ids'] ?? (isset($in['file_id']) ? [$in['file_id']] : null);
        if ($raw !== null && !is_array($raw)) {
            $raw = [$raw];
        }
        $fileIds = [];
        foreach ($raw ?? [] as $v) {
            $n = self::positiveInt($v);
            if ($n === null) {
                throw ApiException::validation(['file_ids' => 'File ids must be positive numbers.']);
            }
            $fileIds[$n] = $n;
        }
        $fileIds = array_values($fileIds);
        $folderRaw = $in['folder_id'] ?? null;
        $folderId = ($folderRaw === null || $folderRaw === '' || $folderRaw === 0 || $folderRaw === '0') ? null : self::positiveInt($folderRaw);
        if ($folderRaw !== null && $folderRaw !== '' && $folderRaw !== 0 && $folderRaw !== '0' && $folderId === null) {
            throw ApiException::validation(['folder_id' => 'The folder id must be a positive number.']);
        }
        if ($fileIds === [] && $folderId === null) {
            throw ApiException::validation(['file_ids' => 'Choose at least one file or a folder to share.']);
        }
        if ($fileIds !== [] && $folderId !== null) {
            throw ApiException::validation(['folder_id' => 'Share either files or a folder, not both at once.']);
        }
        if (count($fileIds) > self::MAX_ITEMS) {
            throw ApiException::validation(['file_ids' => 'You can share up to ' . self::MAX_ITEMS . ' files at once.']);
        }
        $uid = (int) $actor['id'];

        if ($folderId !== null) {
            $folder = FileAccess::requireFolder($actor, $folderId, 'share');
            $role = (string) $folder['access']['role'];
            $parent = null;
            if ($role === 'owner') {
                Policy::requirePermission($actor, 'files.share');
            } elseif ($role !== 'admin') {
                $parent = self::bestParent(self::folderReshareCandidates($uid, $folderId));
                if ($parent === null) {
                    throw ApiException::forbidden('You are not allowed to share this folder.');
                }
            }
            return ['type' => 'folder', 'files' => [], 'folder' => $folder, 'parent' => $parent, 'owners' => [(int) $folder['owner_id']]];
        }

        $files = [];
        $direct = 0;
        foreach ($fileIds as $id) {
            $f = FileAccess::require($actor, $id, 'share');
            if (in_array($f['access']['role'], ['owner', 'admin'], true)) {
                $direct++;
            }
            $files[] = $f;
        }
        $parent = null;
        if ($direct > 0 && $direct < count($files)) {
            throw ApiException::validation(['file_ids' => 'Share your own files and files that were shared with you separately.']);
        }
        if ($direct === 0) {
            $common = null;
            foreach ($files as $f) {
                $cands = [];
                foreach (FileAccess::sharesFor($uid, $f) as $s) {
                    if ((int) $s['allow_reshare'] === 1) {
                        $cands[(int) $s['id']] = $s;
                    }
                }
                $common = $common === null ? $cands : array_intersect_key($common, $cands);
            }
            $parent = self::bestParent(array_values($common ?? []));
            if ($parent === null) {
                throw ApiException::validation(['file_ids' => 'Files shared with you by different people must be shared separately.']);
            }
        } else {
            foreach ($files as $f) {
                if ($f['access']['role'] === 'owner') {
                    Policy::requirePermission($actor, 'files.share');
                    break;
                }
            }
        }
        $owners = array_values(array_unique(array_map(static fn ($f) => (int) $f['owner_id'], $files)));
        return ['type' => count($files) === 1 ? 'file' : 'bundle', 'files' => $files, 'folder' => null, 'parent' => $parent, 'owners' => $owners];
    }

    /**
     * Honoured user shares with allow_reshare reaching $folderId (the folder or a live ancestor) —
     * FileAccess::viewerShares(), so a broken re-share chain can never become a new parent.
     */
    private static function folderReshareCandidates(int $userId, int $folderId): array
    {
        $chain = FileAccess::liveChain(FileAccess::folderMap([$folderId]), $folderId);
        if ($chain === []) {
            return [];
        }
        $out = [];
        foreach (FileAccess::viewerShares($userId) as $s) {
            if ((int) $s['allow_reshare'] === 1 && $s['folder_id'] !== null && in_array((int) $s['folder_id'], $chain, true)) {
                $out[] = $s;
            }
        }
        return $out;
    }

    /** Highest level wins; ties go to the oldest share (most stable parent). */
    private static function bestParent(array $candidates): ?array
    {
        $best = null;
        foreach ($candidates as $c) {
            if ($best === null) {
                $best = $c;
                continue;
            }
            $lc = FileAccess::LEVELS[(string) $c['permission']] ?? 1;
            $lb = FileAccess::LEVELS[(string) $best['permission']] ?? 1;
            if ($lc > $lb || ($lc === $lb && (int) $c['id'] < (int) $best['id'])) {
                $best = $c;
            }
        }
        return $best;
    }

    /**
     * Recipients by id or username: active, not deleted, not the actor, not an owner of the
     * shared item. @return array<int,array> users rows
     */
    private static function resolveRecipients(array $actor, mixed $raw, array $ownerIds): array
    {
        if ($raw === null || $raw === '' || $raw === []) {
            throw ApiException::validation(['recipients' => 'Choose at least one person to share with.']);
        }
        if (!is_array($raw)) {
            $raw = is_string($raw) ? preg_split('/\s*,\s*/', trim($raw)) : [$raw];
        }
        if (count($raw) > self::MAX_RECIPIENTS) {
            throw ApiException::validation(['recipients' => 'You can share with up to ' . self::MAX_RECIPIENTS . ' people at once.']);
        }
        $out = [];
        foreach ($raw as $r) {
            if (is_array($r)) {
                $r = $r['id'] ?? ($r['username'] ?? null);
            }
            $row = null;
            $label = is_scalar($r) ? mb_substr(trim((string) $r), 0, 64) : '';
            if (is_int($r) || (is_string($r) && ctype_digit($r) && $r !== '')) {
                $row = Db::one('SELECT * FROM users WHERE id = ? AND deleted_at IS NULL', [(int) $r]);
            } elseif (is_string($r) && trim($r) !== '') {
                $name = ltrim(trim($r), '@');
                if (mb_strlen($name) <= 64) {
                    $row = Db::one('SELECT * FROM users WHERE username = ? AND deleted_at IS NULL', [$name]);
                }
            }
            if ($row === null || $row['status'] !== 'active') {
                throw ApiException::validation(['recipients' => $label !== '' ? 'We could not find an active account called “' . $label . '”.' : 'One of the people you chose could not be found.']);
            }
            $id = (int) $row['id'];
            if ($id === (int) $actor['id']) {
                throw ApiException::validation(['recipients' => 'You cannot share with yourself.']);
            }
            if (in_array($id, $ownerIds, true)) {
                throw ApiException::validation(['recipients' => self::displayName($row) . ' already owns this item.']);
            }
            $out[$id] = $row;
        }
        return array_values($out);
    }

    // ================================================================== internals: values

    private static function parsePermission(mixed $v): ?string
    {
        if ($v === null || $v === '') {
            return null;
        }
        $p = is_string($v) ? strtolower(trim($v)) : '';
        if (!in_array($p, self::PERMISSIONS, true)) {
            throw ApiException::validation(['permission' => 'Choose Viewer, Downloader, Commenter or Editor.']);
        }
        return $p;
    }

    /**
     * allow_* flags for a level: the level's defaults, minus any flag explicitly turned off,
     * minus anything the parent share (re-shares) does not grant. On update, a flag that is not
     * mentioned keeps its value unless the level changed (then it resets to the new default).
     */
    private static function flagsFor(string $permission, array $in, ?array $existing, ?array $parent, string $kind): array
    {
        $defaults = FileAccess::defaultFlags($permission);
        $levelChanged = $existing !== null && (string) $existing['permission'] !== $permission;
        $parentCaps = $parent !== null ? (FileAccess::combine([$parent]) ?? []) : null;
        $out = [];
        foreach (self::FLAGS as $k) {
            if (array_key_exists($k, $in)) {
                $want = self::boolish($in[$k], $k);
            } elseif ($existing !== null && !$levelChanged) {
                $want = (int) $existing[$k] === 1;
            } else {
                $want = true;
            }
            $v = (int) $defaults[$k] === 1 && $want;
            if ($parentCaps !== null) {
                $v = $v && !empty($parentCaps[self::FLAG_CAPS[$k]]);
            }
            $out[$k] = $v ? 1 : 0;
        }
        if (array_key_exists('allow_reshare', $in)) {
            $reshare = self::boolish($in['allow_reshare'], 'allow_reshare');
        } else {
            $reshare = $existing !== null && (int) $existing['allow_reshare'] === 1;
        }
        if ($reshare && $kind !== 'user') {
            if (array_key_exists('allow_reshare', $in)) {
                throw ApiException::validation(['allow_reshare' => 'Only people you share with directly can be allowed to re-share.']);
            }
            $reshare = false;
        }
        $out['allow_reshare'] = $reshare ? 1 : 0;
        return $out;
    }

    /** @return array{given:bool,value:?string} expiry from expires_at (ISO / unix) or expires_in (seconds). */
    private static function parseExpiry(array $in): array
    {
        if (array_key_exists('expires_at', $in)) {
            $v = $in['expires_at'];
            if ($v === null || $v === '' || $v === 0 || $v === '0') {
                return ['given' => true, 'value' => null];
            }
            $ts = is_int($v) ? $v : (is_string($v) && ctype_digit($v) ? (int) $v : (is_string($v) ? strtotime($v) : false));
            if ($ts === false || $ts <= 0) {
                throw ApiException::validation(['expires_at' => 'Enter a valid expiry date.']);
            }
            return ['given' => true, 'value' => self::checkExpiry((int) $ts, 'expires_at')];
        }
        if (array_key_exists('expires_in', $in)) {
            $v = $in['expires_in'];
            if ($v === null || $v === '' || $v === 0 || $v === '0') {
                return ['given' => true, 'value' => null];
            }
            if (!(is_int($v) || (is_string($v) && ctype_digit($v)))) {
                throw ApiException::validation(['expires_in' => 'The expiry must be a number of seconds.']);
            }
            $sec = (int) $v;
            if ($sec < 60) {
                throw ApiException::validation(['expires_in' => 'Choose an expiry of at least one minute.']);
            }
            return ['given' => true, 'value' => self::checkExpiry(time() + min($sec, self::MAX_EXPIRY_SECONDS + 60), 'expires_in')];
        }
        return ['given' => false, 'value' => null];
    }

    private static function checkExpiry(int $ts, string $field): string
    {
        if ($ts <= time()) {
            throw ApiException::validation([$field => 'The expiry must be in the future.']);
        }
        if ($ts > time() + self::MAX_EXPIRY_SECONDS + 3600) {
            throw ApiException::validation([$field => 'Choose an expiry within the next 10 years, or no expiry.']);
        }
        return Db::ts($ts);
    }

    /** A re-share never outlives its parent. */
    private static function clampToParent(?string $expiresAt, ?array $parent): ?string
    {
        if ($parent === null || $parent['expires_at'] === null) {
            return $expiresAt;
        }
        if ($expiresAt === null || $expiresAt > (string) $parent['expires_at']) {
            return (string) $parent['expires_at'];
        }
        return $expiresAt;
    }

    private static function parseMaxDownloads(mixed $v): ?int
    {
        if ($v === null || $v === '' || $v === 0 || $v === '0') {
            return null;
        }
        if (!(is_int($v) || (is_string($v) && ctype_digit($v)))) {
            throw ApiException::validation(['max_downloads' => 'The download limit must be a whole number.']);
        }
        $n = (int) $v;
        if ($n < 1 || $n > self::MAX_DOWNLOADS) {
            throw ApiException::validation(['max_downloads' => 'Choose a download limit between 1 and ' . number_format(self::MAX_DOWNLOADS) . '.']);
        }
        return $n;
    }

    private static function validatePassword(mixed $pw): string
    {
        if (!is_string($pw)) {
            throw ApiException::validation(['password' => 'The password must be text.']);
        }
        $len = mb_strlen($pw);
        if ($len < self::PASSWORD_MIN) {
            throw ApiException::validation(['password' => 'Use at least ' . self::PASSWORD_MIN . ' characters for the link password.']);
        }
        if ($len > self::PASSWORD_MAX || strlen($pw) > 4 * self::PASSWORD_MAX) {
            throw ApiException::validation(['password' => 'The link password is too long.']);
        }
        return $pw;
    }

    private static function cleanText(mixed $v, int $max, string $field, bool $multiline): ?string
    {
        if ($v === null) {
            return null;
        }
        if (!is_string($v)) {
            throw ApiException::validation([$field => 'This must be text.']);
        }
        $v = (string) preg_replace($multiline ? '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u' : '/[\x00-\x1F\x7F]/u', '', $v);
        $v = trim($v);
        if ($v === '') {
            return null;
        }
        if (mb_strlen($v) > $max) {
            throw ApiException::validation([$field => 'Keep this under ' . number_format($max) . ' characters.']);
        }
        return $v;
    }

    private static function boolish(mixed $v, string $field): bool
    {
        if (is_bool($v)) {
            return $v;
        }
        if (is_int($v) && ($v === 0 || $v === 1)) {
            return $v === 1;
        }
        if (is_string($v)) {
            $l = strtolower(trim($v));
            if (in_array($l, ['1', 'true', 'yes', 'on'], true)) {
                return true;
            }
            if (in_array($l, ['0', 'false', 'no', 'off', ''], true)) {
                return false;
            }
        }
        throw ApiException::validation([$field => 'Use true or false.']);
    }

    private static function positiveInt(mixed $v): ?int
    {
        if (is_int($v)) {
            return $v > 0 ? $v : null;
        }
        if (is_string($v) && $v !== '' && ctype_digit($v) && strlen($v) < 19) {
            $n = (int) $v;
            return $n > 0 ? $n : null;
        }
        return null;
    }

    private static function newToken(): string
    {
        for ($i = 0; $i < 6; $i++) {
            $t = Secrets::token(self::TOKEN_LENGTH);
            if (Db::value('SELECT 1 FROM shares WHERE token = ?', [$t]) === null) {
                return $t;
            }
        }
        throw new \RuntimeException('Could not generate a unique share token');
    }

    /**
     * Changed columns: column => [old, new]. These end up in audit meta that the file timeline
     * shows to editors, so password material is never included and a share's title or private
     * note is only recorded as "changed".
     */
    private static function diff(array $old, array $set): array
    {
        $out = [];
        foreach ($set as $k => $v) {
            $o = $old[$k] ?? null;
            $same = ($o === null || $v === null) ? $o === $v : (string) $o === (string) $v;
            if (!$same) {
                $out[$k] = match ($k) {
                    'password_hash'    => ['changed' => $v === null ? 'removed' : 'set'],
                    'title', 'message' => ['changed' => true],
                    default            => [$o, $v],
                };
            }
        }
        return $out;
    }

    private static function applyFilters(array $filters, array &$where, array &$params): void
    {
        $status = is_string($filters['status'] ?? null) ? strtolower($filters['status']) : 'all';
        if ($status !== '' && $status !== 'all') {
            if (!in_array($status, self::STATUSES, true)) {
                throw ApiException::validation(['status' => 'Status must be active, expired, revoked, exhausted or all.']);
            }
            $where[] = self::statusSql($status, $params);
        }
        $kind = is_string($filters['kind'] ?? null) ? strtolower($filters['kind']) : '';
        if ($kind !== '' && $kind !== 'all') {
            if (!in_array($kind, self::KINDS, true)) {
                throw ApiException::validation(['kind' => 'Kind must be link or user.']);
            }
            $where[] = 's.kind = :kind';
            $params['kind'] = $kind;
        }
        if (!empty($filters['file_id'])) {
            $where[] = '(s.file_id = :ff OR s.id IN (SELECT si.share_id FROM share_items si WHERE si.file_id = :ff2))';
            $params['ff'] = (int) $filters['file_id'];
            $params['ff2'] = (int) $filters['file_id'];
        }
        if (!empty($filters['folder_id'])) {
            $where[] = 's.folder_id = :fd';
            $params['fd'] = (int) $filters['folder_id'];
        }
    }

    private static function statusSql(string $status, array &$params): string
    {
        switch ($status) {
            case 'revoked':
                return 's.revoked_at IS NOT NULL';
            case 'expired':
                $params['st_now'] = Db::now();
                return 's.revoked_at IS NULL AND s.expires_at IS NOT NULL AND s.expires_at <= :st_now';
            case 'exhausted':
                $params['st_now'] = Db::now();
                return 's.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > :st_now)
                        AND s.max_downloads IS NOT NULL AND s.download_count >= s.max_downloads';
            case 'active':
                $params['st_now'] = Db::now();
                return 's.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > :st_now)
                        AND (s.max_downloads IS NULL OR s.download_count < s.max_downloads)';
        }
        return '1 = 1';
    }

    /** @return array{0:array<int,array>,1:int} */
    private static function paged(array $where, array $params, int $page, int $perPage): array
    {
        $sql = ' FROM shares s WHERE ' . implode(' AND ', $where);
        $total = (int) Db::value('SELECT COUNT(*)' . $sql, $params);
        $rows = Db::all('SELECT s.*' . $sql . ' ORDER BY s.created_at DESC, s.id DESC LIMIT :lim OFFSET :off', $params + ['lim' => $perPage, 'off' => ($page - 1) * $perPage]);
        return [$rows, $total];
    }

    private static function touchShares(array $ids): void
    {
        $ids = array_values(array_unique(array_filter($ids, static fn ($i) => $i > 0)));
        if ($ids === []) {
            return;
        }
        [$in, $p] = Db::inList($ids, 'ts');
        $p['now'] = Db::now();
        $p['cut'] = Db::ts(time() - 60);
        Db::run("UPDATE shares SET last_accessed_at = :now, access_count = access_count + 1
                  WHERE id IN {$in} AND (last_accessed_at IS NULL OR last_accessed_at < :cut)", $p);
    }

    // ================================================================== cascade (also used by A1/A3)

    /**
     * Revoke every share created by $userId together with all re-shares made from them — for
     * account deletion (A1 UserService::delete). Call INSIDE the caller's transaction, then pass
     * the result to afterCascade() once it has committed (audit + share.revoked events).
     * @return array{updated:int[],revoked:int[]}
     */
    public static function revokeOwnedBy(int $userId, ?int $actorId): array
    {
        $revoked = [];
        foreach (array_map('intval', Db::column('SELECT id FROM shares WHERE owner_id = ? AND revoked_at IS NULL ORDER BY id', [$userId])) as $id) {
            if (!in_array($id, $revoked, true)) {
                $revoked = array_merge($revoked, self::revokeTree($id, $actorId));
            }
        }
        FileAccess::reset();
        return ['updated' => [], 'revoked' => array_values(array_unique($revoked))];
    }

    /**
     * Revoke a share and all of its (transitive) re-shares. Run it inside a transaction and call
     * afterCascade(['updated' => [], 'revoked' => $ids], …) after the commit.
     * @return int[] ids revoked now
     */
    public static function revokeTree(int $rootId, ?int $actorId): array
    {
        $ids = [$rootId];
        $frontier = [$rootId];
        for ($depth = 0; $frontier !== [] && $depth < 32 && count($ids) < 5000; $depth++) {
            [$in, $p] = Db::inList($frontier, 'rv');
            $frontier = array_map('intval', Db::column("SELECT id FROM shares WHERE parent_share_id IN {$in} AND revoked_at IS NULL", $p));
            $frontier = array_values(array_diff($frontier, $ids));
            $ids = array_merge($ids, $frontier);
        }
        [$inSel, $pSel] = Db::inList($ids, 'ry');
        $todo = array_map('intval', Db::column("SELECT id FROM shares WHERE id IN {$inSel} AND revoked_at IS NULL", $pSel));
        if ($todo === []) {
            return [];
        }
        [$in, $p] = Db::inList($todo, 'rx');
        $now = Db::now();
        $p['now'] = $now;
        $p['now2'] = $now;
        $p['by'] = $actorId;
        Db::run("UPDATE shares SET revoked_at = :now, revoked_by = :by, updated_at = :now2 WHERE id IN {$in} AND revoked_at IS NULL", $p);
        return $todo;
    }

    /**
     * After a share changed: re-shares made from it may not exceed it any more. Children whose
     * parent lost allow_reshare are revoked; others get their level, flags and expiry clamped.
     * @return array{updated:int[],revoked:int[]}
     */
    private static function propagateToChildren(array $parent, ?int $actorId, int $depth): array
    {
        $result = ['updated' => [], 'revoked' => []];
        if ($depth > 30) {
            return $result;
        }
        $children = Db::all('SELECT * FROM shares WHERE parent_share_id = ? AND revoked_at IS NULL', [(int) $parent['id']]);
        if ($children === []) {
            return $result;
        }
        if ((int) $parent['allow_reshare'] !== 1) {
            foreach ($children as $c) {
                $result['revoked'] = array_merge($result['revoked'], self::revokeTree((int) $c['id'], $actorId));
            }
            return $result;
        }
        $parentLevel = FileAccess::LEVELS[(string) $parent['permission']] ?? 1;
        $parentCaps = FileAccess::combine([$parent]) ?? [];
        foreach ($children as $c) {
            $set = [];
            if ((FileAccess::LEVELS[(string) $c['permission']] ?? 1) > $parentLevel) {
                $set['permission'] = (string) $parent['permission'];
            }
            foreach (self::FLAGS as $k) {
                if ((int) $c[$k] === 1 && empty($parentCaps[self::FLAG_CAPS[$k]])) {
                    $set[$k] = 0;
                }
            }
            $clamped = self::clampToParent($c['expires_at'], $parent);
            if ($clamped !== $c['expires_at']) {
                $set['expires_at'] = $clamped;
            }
            if ($set === []) {
                continue;
            }
            Db::update('shares', $set + ['updated_at' => Db::now()], ['id' => (int) $c['id']]);
            $result['updated'][] = (int) $c['id'];
            $fresh = self::find((int) $c['id']);
            if ($fresh !== null) {
                $sub = self::propagateToChildren($fresh, $actorId, $depth + 1);
                $result['updated'] = array_merge($result['updated'], $sub['updated']);
                $result['revoked'] = array_merge($result['revoked'], $sub['revoked']);
            }
        }
        return $result;
    }

    /**
     * Audit + events for shares changed by a cascade (after the transaction committed). $meta is
     * added to the audit rows (e.g. ['reason' => 'deleted'] when the content was purged).
     * Never fails the caller.
     */
    public static function afterCascade(array $changed, ?int $actorId, ?int $rootId = null, array $meta = []): void
    {
        FileAccess::reset();
        try {
            foreach (self::loadMany($changed['revoked'] ?? []) as $s) {
                self::auditShare('share.revoke', $s, $actorId, ['cascade' => (int) $s['id'] !== $rootId] + $meta);
                self::publish('share.revoked', $s, true, $actorId);
            }
            foreach (self::loadMany(array_diff($changed['updated'] ?? [], $changed['revoked'] ?? [])) as $s) {
                self::auditShare('share.update', $s, $actorId, ['cascade' => true] + $meta);
                self::publish('share.updated', $s, false, $actorId);
            }
        } catch (\Throwable $e) {
            Logger::exception('share', $e, ['cascade' => count($changed['revoked'] ?? []) + count($changed['updated'] ?? [])]);
        }
    }

    /** Write changed columns of a share and clamp/revoke its re-shares (inside a transaction). */
    private static function applyChange(int $shareId, array $set, ?int $actorId): array
    {
        Db::update('shares', $set, ['id' => $shareId]);
        $fresh = self::find($shareId);
        return $fresh !== null ? self::propagateToChildren($fresh, $actorId, 0) : ['updated' => [], 'revoked' => []];
    }

    /** @return array{updated:int[],revoked:int[]} */
    private static function mergeCascade(array $a, array $b): array
    {
        return [
            'updated' => array_values(array_unique(array_merge($a['updated'] ?? [], $b['updated'] ?? []))),
            'revoked' => array_values(array_unique(array_merge($a['revoked'] ?? [], $b['revoked'] ?? []))),
        ];
    }

    // ================================================================== internals: side effects

    /**
     * share.* event: managers (share owner + item owners) get the summary with the link URL;
     * the recipient and (for created/revoked) the admin channel get it without.
     */
    public static function publish(string $type, array $share, bool $adminChannel, ?int $actorId = -1): void
    {
        try {
            $managers = array_values(array_unique(array_merge([(int) $share['owner_id']], self::targetOwnerIds($share))));
            $others = ($share['kind'] === 'user' && $share['recipient_id'] !== null) ? array_values(array_diff([(int) $share['recipient_id']], $managers)) : [];
            $base = [
                'file_id'   => $share['target_type'] === 'file' ? (int) $share['file_id'] : null,
                'folder_id' => $share['target_type'] === 'folder' ? (int) $share['folder_id'] : null,
            ];
            $opts = ['file_id' => $base['file_id'], 'folder_id' => $base['folder_id'], 'share_id' => (int) $share['id']];
            if ($actorId !== -1) {
                $opts['actor_id'] = $actorId;
            }
            if ($others !== [] || $adminChannel) {
                EventBus::publish($type, ['share' => self::summary($share, null, false)] + $base, $others, $opts + ['admin' => $adminChannel]);
            }
            EventBus::publish($type, ['share' => self::summary($share, null, true)] + $base, $managers, $opts);
        } catch (\Throwable $e) {
            Logger::warning('share', 'Share event failed', ['type' => $type, 'error' => $e->getMessage()]);
        }
    }

    /**
     * Audit rows land on the shared FILE (or folder) so the item's activity timeline shows them;
     * a bundle writes one row per file.
     */
    private static function auditShare(string $action, array $share, ?int $actorId, array $meta): void
    {
        $recipient = $share['recipient_id'] !== null ? Db::one('SELECT id, username, display_name FROM users WHERE id = ?', [(int) $share['recipient_id']]) : null;
        // permission = the level AFTER the change (rows are audited after the update), recipient =
        // UserRef: A3's timeline renders "Alice changed Rahul's permission to Editor" from these.
        $meta = [
            'share_id'     => (int) $share['id'],
            'kind'         => (string) $share['kind'],
            'permission'   => (string) $share['permission'],
            'recipient'    => $recipient !== null ? Auth::ref($recipient) : null,
            'recipient_id' => $recipient !== null ? (int) $recipient['id'] : null,
        ] + $meta;
        $base = ['category' => 'activity', 'meta' => $meta];
        if ($actorId !== null) {
            $base['user_id'] = $actorId;
        } else {
            $base['user_id'] = null;
            $base['actor_label'] = 'FastTransfer';
        }
        switch ($share['target_type']) {
            case 'file':
                $owner = Db::value('SELECT owner_id FROM files WHERE id = ?', [(int) $share['file_id']]);
                Audit::log($action, $base + ['target_type' => 'file', 'target_id' => (int) $share['file_id'], 'owner_id' => $owner !== null ? (int) $owner : null]);
                break;
            case 'folder':
                $owner = Db::value('SELECT owner_id FROM folders WHERE id = ?', [(int) $share['folder_id']]);
                Audit::log($action, $base + ['target_type' => 'folder', 'target_id' => (int) $share['folder_id'], 'owner_id' => $owner !== null ? (int) $owner : null]);
                break;
            case 'bundle':
                $items = Db::all('SELECT f.id, f.owner_id FROM share_items si JOIN files f ON f.id = si.file_id WHERE si.share_id = ? LIMIT 200', [(int) $share['id']]);
                foreach ($items as $it) {
                    Audit::log($action, $base + ['target_type' => 'file', 'target_id' => (int) $it['id'], 'owner_id' => (int) $it['owner_id']]);
                }
                if ($items === []) {
                    Audit::log($action, $base + ['target_type' => 'share', 'target_id' => (int) $share['id'], 'owner_id' => (int) $share['owner_id']]);
                }
                break;
        }
    }

    private static function notifyRecipient(array $share, array $actor, array $target): void
    {
        $who = self::displayName($actor);
        $title = self::summary($share, null, false)['title'];
        $text = match ($share['target_type']) {
            'folder' => $who . ' shared the folder “' . $title . '” with you',
            'bundle' => $share['title'] !== null && $share['title'] !== '' ? $who . ' shared “' . $title . '” with you' : $who . ' shared ' . $title . ' with you',
            default  => $who . ' shared “' . $title . '” with you',
        };
        self::notify((int) $share['recipient_id'], 'share', 'share.received', $text, (string) ($share['message'] ?? ''), array_filter([
            'share_id'  => (int) $share['id'],
            'file_id'   => $share['target_type'] === 'file' ? (int) $share['file_id'] : null,
            'folder_id' => $share['target_type'] === 'folder' ? (int) $share['folder_id'] : null,
            'permission' => (string) $share['permission'],
            'link'      => '#/shared',
        ], static fn ($v) => $v !== null), 'share:' . (int) $share['id'], (int) $actor['id']);
    }

    private static function targetTitle(array $target, ?string $title): string
    {
        if ($title !== null) {
            return $title;
        }
        if ($target['type'] === 'folder') {
            return (string) $target['folder']['name'];
        }
        $n = count($target['files']);
        return $n === 1 ? (string) $target['files'][0]['name'] : $n . ' files';
    }

    private static function basicFileSummary(array $r, ?array $viewer): array
    {
        $writer = 'FT\\Files\\FileWriter';
        if (class_exists($writer) && method_exists($writer, 'summary')) {
            try {
                return $writer::summary($r, $viewer, $viewer === null);
            } catch (\Throwable $e) {
                Logger::warning('share', 'FileWriter::summary failed', ['error' => $e->getMessage()]);
            }
        }
        $owner = self::userRefs([(int) $r['owner_id']])[(int) $r['owner_id']] ?? self::unknownUser((int) $r['owner_id']);
        $s = [
            'id' => (int) $r['id'], 'type' => 'file', 'name' => (string) $r['name'], 'ext' => (string) $r['ext'],
            'mime' => (string) $r['mime'], 'kind' => (string) $r['kind'], 'size' => (int) $r['size'],
            'folder_id' => null, 'owner' => $owner, 'created_at' => Db::iso($r['created_at']), 'updated_at' => Db::iso($r['updated_at']),
            'version' => (int) $r['version'], 'favorite' => false, 'tags' => [], 'is_permanent' => (int) $r['is_permanent'] === 1,
            'expires_at' => Db::iso($r['expires_at']), 'download_count' => (int) $r['download_count'], 'comment_count' => 0,
            'is_shared' => true, 'has_thumbnail' => $r['thumb_version'] !== null, 'encrypted' => false,
            'is_bundle' => (int) $r['is_bundle'] === 1, 'description' => $r['description'] ?? null,
            'access' => $viewer !== null ? FileAccess::accessFor($viewer, $r) : null, 'trash' => null,
        ];
        if ($viewer === null) {
            unset($s['access'], $s['favorite']);
        }
        return $s;
    }

    private static function unknownUser(int $id): array
    {
        return ['id' => $id, 'username' => 'deleted', 'display_name' => 'Deleted user'];
    }
}
