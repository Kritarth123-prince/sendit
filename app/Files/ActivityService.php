<?php
declare(strict_types=1);

namespace FT\Files;

use FT\Core\Db;

/**
 * Per-file activity timeline (docs/ARCHITECTURE.md §7): audit_logs rows about the file — and
 * about shares of the file — rendered as short British-English sentences with actor refs.
 *
 * Only a whitelisted subset of each row's meta is returned; IP addresses and user agents are
 * never exposed here (the timeline is visible to editors, not only the owner).
 */
final class ActivityService
{
    public const PER_PAGE = 50;

    private const META_KEYS = ['version', 'from', 'to', 'folder', 'folder_id', 'from_folder_id', 'to_folder_id', 'permission',
        'kind', 'changes', 'reason', 'count', 'favorite', 'recipient_id', 'is_permanent', 'new_version'];

    /**
     * @return array{items:array<int,array<string,mixed>>,total:int,page:int,per_page:int}
     */
    public static function timeline(int $fileId, array $viewer, int $page = 1, int $perPage = self::PER_PAGE): array
    {
        FileAccess::require($viewer, $fileId, 'activity', true);
        $page = max(1, $page);
        $perPage = max(1, min(200, $perPage));

        $shareRows = Db::all(
            'SELECT id, kind, recipient_id, permission FROM shares
              WHERE file_id = :f OR id IN (SELECT share_id FROM share_items WHERE file_id = :f2) LIMIT 1000',
            ['f' => $fileId, 'f2' => $fileId]
        );
        $shares = [];
        foreach ($shareRows as $s) {
            $shares[(int) $s['id']] = $s;
        }
        $where = "(target_type = 'file' AND target_id = :fid)";
        $params = ['fid' => $fileId];
        if ($shares !== []) {
            [$in, $p] = Db::inList(array_keys($shares), 'sh');
            $where .= " OR (target_type = 'share' AND target_id IN {$in})";
            $params += $p;
        }
        $total = (int) Db::value("SELECT COUNT(*) FROM audit_logs WHERE {$where}", $params);
        $rows = Db::all(
            "SELECT id, user_id, actor_label, action, target_type, target_id, detail, meta, created_at FROM audit_logs
              WHERE {$where} ORDER BY id DESC LIMIT :lim OFFSET :off",
            $params + ['lim' => $perPage, 'off' => ($page - 1) * $perPage]
        );

        // actors + share recipients + folders mentioned, in three queries
        $userIds = [];
        $folderIds = [];
        $metas = [];
        foreach ($rows as $r) {
            $meta = json_decode((string) ($r['meta'] ?? ''), true);
            $meta = is_array($meta) ? $meta : [];
            $metas[(int) $r['id']] = $meta;
            if ($r['user_id'] !== null) {
                $userIds[] = (int) $r['user_id'];
            }
            if (isset($meta['recipient_id']) && is_numeric($meta['recipient_id'])) {
                $userIds[] = (int) $meta['recipient_id'];
            }
            if ($r['target_type'] === 'share' && isset($shares[(int) $r['target_id']]['recipient_id'])) {
                $userIds[] = (int) $shares[(int) $r['target_id']]['recipient_id'];
            }
            if ($r['action'] === 'file.move' && isset($meta['to_folder_id']) && is_numeric($meta['to_folder_id']) && !isset($meta['folder'])) {
                $folderIds[] = (int) $meta['to_folder_id'];
            }
        }
        $users = FileRepository::userRefs($userIds);
        $folders = [];
        if ($folderIds !== []) {
            [$in, $p] = Db::inList($folderIds, 'af');
            foreach (Db::all("SELECT id, name FROM folders WHERE id IN {$in}", $p) as $f) {
                $folders[(int) $f['id']] = (string) $f['name'];
            }
        }

        $items = [];
        foreach ($rows as $r) {
            $meta = $metas[(int) $r['id']];
            $actor = $r['user_id'] !== null ? ($users[(int) $r['user_id']] ?? null) : null;
            $share = $r['target_type'] === 'share' ? ($shares[(int) $r['target_id']] ?? null) : null;
            $items[] = [
                'id'          => (int) $r['id'],
                'action'      => (string) $r['action'],
                'text'        => self::sentence($r, $meta, $actor, $share, $users, $folders),
                'actor'       => $actor,
                'actor_label' => $r['actor_label'] ?? null,
                'created_at'  => Db::iso($r['created_at']),
                'meta'        => (object) array_intersect_key($meta, array_flip(self::META_KEYS)),
            ];
        }
        return ['items' => $items, 'total' => $total, 'page' => $page, 'per_page' => $perPage];
    }

    /** Human sentence for one audit row (British English). */
    public static function sentence(array $row, array $meta, ?array $actor, ?array $share, array $users = [], array $folders = []): string
    {
        $action = (string) $row['action'];
        $who = self::actorName($row, $actor);
        $detail = (string) ($row['detail'] ?? '');
        $recipient = null;
        $rid = $share['recipient_id'] ?? ($meta['recipient_id'] ?? null);
        if ($rid !== null && isset($users[(int) $rid])) {
            $recipient = FileRepository::displayName($users[(int) $rid]);
        }
        $isLink = ($share['kind'] ?? ($meta['kind'] ?? null)) === 'link';

        switch ($action) {
            case 'file.upload':
                return "{$who} uploaded the file";
            case 'file.download':
                return isset($meta['version']) ? "{$who} downloaded version " . (int) $meta['version'] : "{$who} downloaded the file";
            case 'file.preview':
                return "{$who} viewed the file";
            case 'file.rename':
                $from = (string) ($meta['from'] ?? '');
                $to = (string) ($meta['to'] ?? '');
                return ($from !== '' && $to !== '') ? "{$who} renamed the file from “{$from}” to “{$to}”" : "{$who} renamed the file";
            case 'file.move':
                $folder = $meta['folder'] ?? (isset($meta['to_folder_id']) && is_numeric($meta['to_folder_id']) ? ($folders[(int) $meta['to_folder_id']] ?? null) : null);
                if (array_key_exists('to_folder_id', $meta) && $meta['to_folder_id'] === null) {
                    $folder = 'My Files';
                }
                return $folder !== null && $folder !== '' ? "{$who} moved the file to {$folder}" : "{$who} moved the file";
            case 'file.trash':
                return ($meta['reason'] ?? '') === 'expired'
                    ? 'The file expired and was moved to the Trash'
                    : "{$who} moved the file to the Trash";
            case 'file.restore':
                return "{$who} restored the file from the Trash";
            case 'file.purge':
                return "{$who} deleted the file permanently";
            case 'file.version_upload':
                return isset($meta['version']) ? "{$who} uploaded version " . (int) $meta['version'] : "{$who} uploaded a new version";
            case 'file.version_restore':
                $v = $meta['restored_version'] ?? ($meta['from_version'] ?? ($meta['version'] ?? null));
                return $v !== null ? "{$who} restored version " . (int) $v : "{$who} restored an earlier version";
            case 'file.comment':
                return "{$who} added a comment";
            case 'file.comment_delete':
                return "{$who} deleted a comment";
            case 'file.edit':
                if (array_key_exists('base_version', $meta)) {
                    // A4 in-browser text editor saves (a new version written by the editor)
                    return "{$who} edited the file in the browser";
                }
                $changes = is_array($meta['changes'] ?? null) ? $meta['changes'] : [];
                if ($changes === ['description']) {
                    return "{$who} updated the description";
                }
                if ($changes === ['tags']) {
                    return "{$who} updated the tags";
                }
                if ($changes === ['is_permanent']) {
                    return !empty($meta['is_permanent']) ? "{$who} set the file to be kept forever" : "{$who} set the file to expire automatically";
                }
                return $changes !== [] ? "{$who} updated the file details" : "{$who} edited the file";
            case 'file.favorite':
                return !empty($meta['favorite']) ? "{$who} added the file to favourites" : "{$who} removed the file from favourites";
            case 'share.create':
                if ($isLink) {
                    return "{$who} created a share link";
                }
                return $recipient !== null ? "{$who} shared the file with {$recipient}" : "{$who} shared the file";
            case 'share.update':
                if (!$isLink && $recipient !== null && isset($meta['permission']) && is_string($meta['permission'])) {
                    return "{$who} changed {$recipient}’s permission to " . ucfirst($meta['permission']);
                }
                return $isLink ? "{$who} changed the share link settings" : "{$who} changed the sharing settings";
            case 'share.revoke':
                if ($isLink) {
                    return "{$who} disabled the share link";
                }
                return $recipient !== null ? "{$who} stopped sharing with {$recipient}" : "{$who} stopped sharing the file";
            case 'share.access':
                return "{$who} opened the share link";
            case 'share.download':
                return "{$who} downloaded the file through a share link";
            case 'share.upload':
                return isset($meta['version']) && is_numeric($meta['version'])
                    ? "{$who} uploaded a new version (version " . (int) $meta['version'] . ')'
                    : "{$who} uploaded a new version";
            case 'share.password_failed':
                return 'Someone entered a wrong password for the share link';
            case 'upload.failed':
                return $detail !== '' && mb_strlen($detail) <= 120 ? "{$who}’s upload of “{$detail}” failed" : "{$who}’s upload failed";
            case 'file.ocr_request':
                return "{$who} asked for the text in the file to be recognised";
            case 'share.expired':
                return $isLink ? 'The share link expired' : ($recipient !== null ? "Sharing with {$recipient} expired" : 'A share expired');
            case 'admin.file_access':
                return "{$who} (administrator) accessed the file";
            case 'file.ocr':
                return 'Text in the file was recognised';
        }
        $verb = str_replace(['.', '_'], ' ', $action);
        return trim("{$who} {$verb}" . ($detail !== '' && mb_strlen($detail) <= 80 ? ": {$detail}" : ''));
    }

    private static function actorName(array $row, ?array $actor): string
    {
        if ($actor !== null) {
            return FileRepository::displayName($actor);
        }
        $label = trim((string) ($row['actor_label'] ?? ''));
        if ($label !== '') {
            return $label;
        }
        return str_starts_with((string) $row['action'], 'share.') ? 'Someone with the link' : 'FastTransfer';
    }
}
