<?php
declare(strict_types=1);

namespace FT\Comments;

use FT\Auth\Auth;
use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Events\EventBus;
use FT\Files\FileAccess;
use FT\Security\Policy;
use FT\Sharing\ShareService;

/**
 * File comments (docs/ARCHITECTURE.md §9.4 "Comments", §10.2 comment.*, §11 "comment").
 *
 *  - Anyone who can see a file can read its comments; adding one needs the "comment"
 *    capability (owner/admin, or a commenter/editor share with comments allowed).
 *  - The author, the file owner or an admin may delete a comment (soft delete).
 *  - A new comment notifies the file owner and everyone who commented before and still has
 *    access — never the person who wrote it.
 *  - Anonymous comments arrive through link shares with allow_comments (author_name + share_id,
 *    user_id NULL); their author is shown by the name they typed, the audit actor is
 *    "Someone with the link".
 */
final class CommentService
{
    public const MAX_LENGTH = 2000;
    public const MAX_NAME = 60;
    public const LIST_LIMIT = 500;
    private const NOTIFY_LIMIT = 50;

    /** GET /files/{id}/comments @return array<int,array<string,mixed>> oldest first */
    public static function list(array $user, int $fileId): array
    {
        $file = FileAccess::require($user, $fileId, 'view');
        $rows = self::rows($fileId);
        return self::shapes($rows, $user, $file);
    }

    /** POST /files/{id}/comments {body} */
    public static function create(array $user, int $fileId, mixed $body): array
    {
        $file = FileAccess::require($user, $fileId, 'comment');
        Policy::requirePermission($user, 'files.comment');
        $body = self::cleanBody($body);
        $now = Db::now();
        $id = Db::insert('comments', [
            'file_id'     => $fileId,
            'user_id'     => (int) $user['id'],
            'author_name' => mb_substr(ShareService::displayName($user), 0, 100),
            'share_id'    => null,
            'body'        => $body,
            'created_at'  => $now,
        ]);
        $row = Db::one('SELECT * FROM comments WHERE id = ?', [$id]);
        $actorName = ShareService::displayName($user);
        self::afterCreate($row, $file, (int) $user['id'], $actorName, null);
        return self::shapes([$row], $user, $file)[0];
    }

    /**
     * Anonymous comment through a link share (the caller has checked the share is usable and
     * allows comments, and that $file is inside its scope).
     */
    public static function createAnonymous(array $share, array $file, mixed $name, mixed $body): array
    {
        if ((int) $share['allow_comments'] !== 1 || empty($file['access']['comment'])) {
            throw ApiException::forbidden('Comments are turned off for this link.');
        }
        $name = is_string($name) ? trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $name)) : '';
        if ($name === '') {
            throw ApiException::validation(['name' => 'Enter your name so the owner knows who commented.']);
        }
        if (mb_strlen($name) > self::MAX_NAME) {
            throw ApiException::validation(['name' => 'Keep your name under ' . self::MAX_NAME . ' characters.']);
        }
        $body = self::cleanBody($body);
        $id = Db::insert('comments', [
            'file_id'     => (int) $file['id'],
            'user_id'     => null,
            'author_name' => $name,
            'share_id'    => (int) $share['id'],
            'body'        => $body,
            'created_at'  => Db::now(),
        ]);
        $row = Db::one('SELECT * FROM comments WHERE id = ?', [$id]);
        self::afterCreate($row, $file, null, $name, $share);
        return self::publicShape($row);
    }

    /** Comments visible on a public link page (no user ids, no delete rights). */
    public static function listForLink(array $file): array
    {
        return array_map([self::class, 'publicShape'], self::rows((int) $file['id']));
    }

    /** DELETE /comments/{id} — author, file owner or admin. */
    public static function delete(array $user, int $commentId): void
    {
        $c = Db::one('SELECT * FROM comments WHERE id = ? AND deleted_at IS NULL', [$commentId]);
        $file = $c !== null ? Db::one('SELECT * FROM files WHERE id = ?', [(int) $c['file_id']]) : null;
        $caps = $file !== null ? FileAccess::accessFor($user, $file) : null;
        if ($c === null || $caps === null) {
            throw ApiException::notFound('comment', 'COMMENT_NOT_FOUND');
        }
        if (!self::canDelete($user, $c, $file)) {
            throw ApiException::forbidden('Only the author, the file owner or an administrator can delete this comment.');
        }
        $n = Db::run('UPDATE comments SET deleted_at = :now, deleted_by = :by WHERE id = :id AND deleted_at IS NULL', [
            'now' => Db::now(), 'by' => (int) $user['id'], 'id' => $commentId,
        ])->rowCount();
        if ($n !== 1) {
            return; // deleted concurrently
        }
        Audit::log('file.comment_delete', [
            'user_id'     => (int) $user['id'],
            'target_type' => 'file',
            'target_id'   => (int) $file['id'],
            'owner_id'    => (int) $file['owner_id'],
            'meta'        => ['comment_id' => $commentId, 'author_id' => $c['user_id'] !== null ? (int) $c['user_id'] : null],
        ]);
        EventBus::publish('comment.deleted', ['comment_id' => $commentId, 'file_id' => (int) $file['id']], EventBus::fileAudience((int) $file['id']), [
            'file_id' => (int) $file['id'],
        ]);
    }

    public static function canDelete(array $user, array $comment, array $file): bool
    {
        $uid = (int) $user['id'];
        return ($comment['user_id'] !== null && (int) $comment['user_id'] === $uid)
            || (int) $file['owner_id'] === $uid
            || Policy::isAdmin($user);
    }

    /**
     * Comment shapes with authors hydrated in one query.
     * @param array<int,array<string,mixed>> $rows
     */
    public static function shapes(array $rows, ?array $viewer, ?array $file): array
    {
        $ids = [];
        foreach ($rows as $r) {
            if ($r['user_id'] !== null) {
                $ids[] = (int) $r['user_id'];
            }
        }
        $users = ShareService::userRefs($ids);
        $out = [];
        foreach ($rows as $r) {
            $author = $r['user_id'] !== null ? ($users[(int) $r['user_id']] ?? null) : null;
            $out[] = [
                'id'          => (int) $r['id'],
                'file_id'     => (int) $r['file_id'],
                'body'        => (string) $r['body'],
                'author'      => $author,
                'author_name' => $author !== null ? $author['display_name'] : (string) ($r['author_name'] ?? 'Someone'),
                'via_link'    => $r['share_id'] !== null && $r['user_id'] === null,
                'created_at'  => Db::iso($r['created_at']),
                'edited_at'   => Db::iso($r['edited_at']),
                'can_delete'  => $viewer !== null && $file !== null && self::canDelete($viewer, $r, $file),
            ];
        }
        return $out;
    }

    public static function publicShape(array $r): array
    {
        $name = (string) ($r['author_name'] ?? '');
        return [
            'id'          => (int) $r['id'],
            'body'        => (string) $r['body'],
            'author_name' => $name !== '' ? $name : 'Someone',
            'created_at'  => Db::iso($r['created_at']),
        ];
    }

    // ------------------------------------------------------------------ internals

    /** @return array<int,array<string,mixed>> the most recent LIST_LIMIT comments, oldest first */
    private static function rows(int $fileId): array
    {
        $rows = Db::all(
            'SELECT * FROM comments WHERE file_id = :f AND deleted_at IS NULL ORDER BY id DESC LIMIT :lim',
            ['f' => $fileId, 'lim' => self::LIST_LIMIT]
        );
        return array_reverse($rows);
    }

    private static function cleanBody(mixed $body): string
    {
        if (!is_string($body)) {
            throw ApiException::validation(['body' => 'Write a comment first.']);
        }
        $body = trim((string) preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', str_replace("\r\n", "\n", $body)));
        if ($body === '') {
            throw ApiException::validation(['body' => 'Write a comment first.']);
        }
        if (!mb_check_encoding($body, 'UTF-8')) {
            throw ApiException::validation(['body' => 'The comment contains invalid characters.']);
        }
        if (mb_strlen($body) > self::MAX_LENGTH) {
            throw ApiException::validation(['body' => 'Comments can be up to ' . number_format(self::MAX_LENGTH) . ' characters long.']);
        }
        return $body;
    }

    /** Audit, event, notifications and Slack for a new comment. */
    private static function afterCreate(array $row, array $file, ?int $actorId, string $actorName, ?array $share): void
    {
        $fileId = (int) $file['id'];
        $ownerId = (int) $file['owner_id'];
        $audit = [
            'target_type' => 'file',
            'target_id'   => $fileId,
            'owner_id'    => $ownerId,
            'meta'        => ['comment_id' => (int) $row['id']] + ($share !== null ? ['share_id' => (int) $share['id'], 'author_name' => $actorName] : []),
        ];
        if ($actorId === null) {
            $audit['user_id'] = null;
            $audit['actor_label'] = ShareService::ANON_LABEL;
        } else {
            $audit['user_id'] = $actorId;
        }
        Audit::log('file.comment', $audit);

        $shape = self::shapes([$row], null, null)[0];
        unset($shape['can_delete']);
        EventBus::publish('comment.created', ['comment' => $shape, 'file_id' => $fileId], EventBus::fileAudience($fileId), [
            'file_id'  => $fileId,
            'actor_id' => $actorId,
            'share_id' => $share !== null ? (int) $share['id'] : null,
        ]);

        // Who hears about it: the owner + earlier commenters who can still see the file.
        $candidates = [$ownerId];
        foreach (Db::column(
            'SELECT DISTINCT user_id FROM comments WHERE file_id = :f AND deleted_at IS NULL AND user_id IS NOT NULL AND id <> :id ORDER BY user_id LIMIT :lim',
            ['f' => $fileId, 'id' => (int) $row['id'], 'lim' => self::NOTIFY_LIMIT]
        ) as $uid) {
            $candidates[] = (int) $uid;
        }
        if ($share !== null && (int) $share['owner_id'] !== $ownerId) {
            $candidates[] = (int) $share['owner_id'];
        }
        $candidates = array_values(array_unique(array_filter($candidates, static fn ($u) => $u > 0 && $u !== $actorId)));
        if ($candidates !== []) {
            [$in, $p] = Db::inList($candidates, 'cu');
            $users = Db::all("SELECT * FROM users WHERE id IN {$in} AND deleted_at IS NULL AND status = 'active'", $p);
            $preview = mb_substr((string) $row['body'], 0, 140) . (mb_strlen((string) $row['body']) > 140 ? '…' : '');
            $title = $share !== null
                ? '“' . mb_substr($actorName, 0, 60) . '” commented on “' . $file['name'] . '” via your share link'
                : $actorName . ' commented on “' . $file['name'] . '”';
            foreach ($users as $u) {
                $u = Auth::sanitize($u);
                $isOwner = (int) $u['id'] === $ownerId;
                if (!$isOwner && !($share !== null && (int) $u['id'] === (int) $share['owner_id']) && FileAccess::accessFor($u, $file) === null) {
                    continue;
                }
                ShareService::notify((int) $u['id'], 'comment', 'comment.created', $title, $preview, [
                    'file_id'    => $fileId,
                    'comment_id' => (int) $row['id'],
                    'link'       => $isOwner ? '#/files' . ($file['folder_id'] !== null ? '/' . (int) $file['folder_id'] : '') : '#/shared',
                ], null, $actorId);
            }
        }

        ShareService::slack('comment', [
            'File'    => (string) $file['name'],
            'By'      => $actorId === null ? $actorName . ' (via share link)' : $actorName,
            'Comment' => mb_substr((string) $row['body'], 0, 80) . (mb_strlen((string) $row['body']) > 80 ? '…' : ''),
        ]);
    }
}
