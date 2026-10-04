<?php
declare(strict_types=1);

namespace FT\Notepads;

use FT\Auth\Auth;
use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Events\EventBus;
use FT\Security\Policy;
use FT\Storage\Crypto;

/**
 * Notepads — the legacy "Collaborative Notepad" as a first-class feature
 * (docs/API.md §5.12a, docs/EVENTS.md "Notepads").
 *
 *  - Team notepads: every active non-guest account may open and edit them; only the creator or an
 *    administrator may rename, re-scope or delete one. When no team notepad exists, the first list
 *    request creates "Team notepad" (no owner), so there is always one to open — like the old app.
 *  - Private notepads: their owner only (administrators included: 404 for everyone else).
 *  - Guests: no access at all (403).
 *
 * Concurrency is optimistic: a save names the version it was based on; if the notepad moved on,
 * the save is refused with 409 VERSION_CONFLICT whose details carry the current version AND the
 * current text, so the client can do a three-way merge without another request. Saving the text
 * that is already stored is a no-op (it also makes a retried save after a lost response harmless).
 *
 * Text is stored encoded: deflated when that helps, then encrypted with AES-256-GCM
 * (Crypto::encryptString, purpose "notepad:<id>") when ENCRYPTION_ENABLED with a valid key;
 * content_codec says which steps were applied, so rows stay readable after the setting changes.
 *
 * History: every save updates the newest revision while it is by the same person and started
 * less than 10 minutes ago; otherwise (or for a restore) a new revision is recorded. The newest 50
 * revisions per notepad are kept.
 *
 * Real-time: notepad.updated goes to the people who have the notepad open (presence within the
 * TTL) for team notepads, and to the owner's devices for private ones. Created/renamed/deleted and
 * presence changes go to everyone who can see the notepad.
 */
final class NotepadService
{
    public const MAX_BYTES = 1048576;
    public const MAX_TITLE = 120;
    public const PRESENCE_TTL = 30;
    public const REVISION_KEEP = 50;
    public const COALESCE_SECONDS = 600;
    /** Notepads one account may own (team notepads they created + private ones). */
    public const MAX_OWNED = 100;
    public const DEFAULT_TITLE = 'Team notepad';
    public const VISIBILITIES = ['team', 'private'];

    /** Everything but the (possibly 1 MiB) content. */
    private const META_COLS = 'id, title, visibility, owner_id, content_size, version, updated_by, legacy_key, created_at, updated_at';

    // ------------------------------------------------------------------ reading

    /** GET /notepads → team notepads + the caller's private ones (team first, newest first). */
    public static function list(array $user): array
    {
        self::assertMember($user);
        self::ensureTeamNotepad();
        $rows = Db::all(
            'SELECT ' . self::META_COLS . " FROM notepads WHERE visibility = 'team' OR owner_id = :u
             ORDER BY (visibility = 'team') DESC, updated_at DESC, id DESC",
            ['u' => (int) $user['id']]
        );
        if ($rows === []) {
            return [];
        }
        $ids = array_map(static fn ($r) => (int) $r['id'], $rows);
        [$in, $params] = Db::inList($ids, 'np');
        $params['cut'] = Db::ts(time() - self::PRESENCE_TTL);
        $present = [];
        foreach (Db::all("SELECT notepad_id, COUNT(DISTINCT user_id) AS n FROM notepad_presence
                           WHERE notepad_id IN {$in} AND seen_at >= :cut GROUP BY notepad_id", $params) as $p) {
            $present[(int) $p['notepad_id']] = (int) $p['n'];
        }
        $names = self::names(self::peopleIn($rows));
        return array_map(static fn ($r) => self::shape($r, $user, $names, $present[(int) $r['id']] ?? 0), $rows);
    }

    /** GET /notepads/{id} → summary + content + the people who have it open. */
    public static function get(array $user, int $id): array
    {
        $row = self::requireVisible($user, $id, true);
        return self::detail($row, $user, self::decode($row));
    }

    /** GET /notepads/{id}/revisions → newest first, without content. */
    public static function revisions(array $user, int $id): array
    {
        $row = self::requireVisible($user, $id);
        $rows = Db::all(
            'SELECT id, version, content_size, user_id, restored_from_version, created_at, updated_at
               FROM notepad_revisions WHERE notepad_id = ? ORDER BY id DESC LIMIT ' . self::REVISION_KEEP,
            [$id]
        );
        $names = self::names(array_map(static fn ($r) => $r['user_id'], $rows));
        return array_map(static fn ($r) => self::revisionShape($r, $row, $names), $rows);
    }

    /** GET /notepads/{id}/revisions/{rid} → revision + content. */
    public static function revision(array $user, int $id, int $rid): array
    {
        $row = self::requireVisible($user, $id);
        $rev = self::requireRevision($id, $rid);
        $out = self::revisionShape($rev, $row, self::names([$rev['user_id']]));
        $out['content'] = self::decodeBlob((string) $rev['content'], (string) $rev['content_codec'], $id);
        return $out;
    }

    // ------------------------------------------------------------------ writing

    /** POST /notepads {title, visibility} */
    public static function create(array $user, mixed $title, mixed $visibility): array
    {
        self::assertMember($user);
        $title = ($title === null || (is_string($title) && trim($title) === '')) ? 'Untitled notepad' : self::cleanTitle($title);
        $visibility = $visibility === null || $visibility === '' ? 'team' : self::cleanVisibility($visibility);
        $uid = (int) $user['id'];
        if ((int) Db::value('SELECT COUNT(*) FROM notepads WHERE owner_id = ?', [$uid]) >= self::MAX_OWNED) {
            throw ApiException::conflict('You have reached the limit of ' . self::MAX_OWNED . ' notepads. Delete one you no longer need first.');
        }
        $id = self::insertNotepad($title, $visibility, $uid, '', $uid, Db::now());
        $row = self::requireVisible($user, $id, true);
        Audit::log('notepad.create', [
            'user_id' => $uid, 'target_type' => 'notepad', 'target_id' => $id, 'owner_id' => $uid,
            'detail' => $title, 'meta' => ['visibility' => $visibility],
        ]);
        EventBus::publish('notepad.created', ['notepad' => self::eventShape($row)], self::audience($row), ['actor_id' => $uid]);
        return self::detail($row, $user, '');
    }

    /**
     * PUT /notepads/{id}/content {content, base_version, client_id?} → {id, version, updated_at, size, changed}.
     * 409 VERSION_CONFLICT {current_version, base_version, content, updated_at, updated_by} when stale.
     */
    public static function saveContent(array $user, int $id, mixed $content, mixed $baseVersion, ?string $clientId = null): array
    {
        self::assertMember($user);
        if (!is_string($content)) {
            throw ApiException::validation(['content' => 'The notepad text is missing.']);
        }
        if (!(is_int($baseVersion) || (is_string($baseVersion) && ctype_digit($baseVersion)))) {
            throw ApiException::validation(['base_version' => 'base_version (the version you started editing) is required.']);
        }
        self::assertSize(strlen($content));
        if (!mb_check_encoding($content, 'UTF-8')) {
            throw ApiException::validation(['content' => 'The text contains invalid characters.']);
        }
        $base = (int) $baseVersion;
        $uid = (int) $user['id'];
        $cid = self::cleanClientId($clientId);
        self::requireVisible($user, $id); // 404 before taking any lock
        $now = Db::now();
        $result = Db::transaction(static function () use ($user, $id, $content, $base, $uid, $now): array {
            // Row lock: the version check and the new version are one atomic step.
            $row = self::requireVisible($user, $id, true, true);
            $current = self::decode($row);
            if ($content === $current) {
                return ['row' => $row, 'changed' => false];
            }
            if ((int) $row['version'] !== $base) {
                throw self::conflict($row, $current, $base);
            }
            $version = (int) $row['version'] + 1;
            [$blob, $codec] = self::encode($content, $id);
            Db::update('notepads', [
                'content' => $blob, 'content_codec' => $codec, 'content_size' => strlen($content),
                'version' => $version, 'updated_by' => $uid, 'updated_at' => $now,
            ], ['id' => $id]);
            self::recordRevision($id, $version, $blob, $codec, strlen($content), $uid, $now);
            $row = array_merge($row, ['version' => $version, 'content_size' => strlen($content), 'updated_by' => $uid, 'updated_at' => $now]);
            return ['row' => $row, 'changed' => true];
        });
        $row = $result['row'];
        if ($result['changed']) {
            self::publishUpdated($row, $user, $cid);
        }
        return [
            'id'         => $id,
            'version'    => (int) $row['version'],
            'size'       => (int) $row['content_size'],
            'updated_at' => Db::iso((string) $row['updated_at']),
            'updated_by' => self::names([$row['updated_by']])[(int) $row['updated_by']] ?? null,
            'changed'    => $result['changed'],
        ];
    }

    /** PATCH /notepads/{id} {title?, visibility?} — creator or administrator. */
    public static function update(array $user, int $id, array $in): array
    {
        $row = self::requireVisible($user, $id);
        self::assertManage($user, $row);
        $uid = (int) $user['id'];
        $set = [];
        $changes = [];
        if (array_key_exists('title', $in)) {
            $title = self::cleanTitle($in['title']);
            if ($title !== (string) $row['title']) {
                $set['title'] = $title;
                $changes[] = 'title';
            }
        }
        if (array_key_exists('visibility', $in)) {
            $vis = self::cleanVisibility($in['visibility']);
            if ($vis !== (string) $row['visibility']) {
                $set['visibility'] = $vis;
                $changes[] = 'visibility';
                if ($vis === 'private' && $row['owner_id'] === null) {
                    $set['owner_id'] = $uid; // the automatic team notepad has no owner: whoever hides it keeps it
                }
            }
        }
        if ($set === []) {
            return self::shape($row, $user, self::names(self::peopleIn([$row])), self::presentCount($id));
        }
        $before = self::audience($row);
        Db::update('notepads', $set, ['id' => $id]);
        $fresh = self::requireRow($id);
        if (in_array('title', $changes, true)) {
            Audit::log('notepad.rename', [
                'user_id' => $uid, 'target_type' => 'notepad', 'target_id' => $id, 'owner_id' => self::ownerOf($fresh),
                'detail' => (string) $fresh['title'], 'meta' => ['from' => (string) $row['title'], 'to' => (string) $fresh['title']],
            ]);
        }
        if (in_array('visibility', $changes, true)) {
            Audit::log('notepad.visibility', [
                'user_id' => $uid, 'target_type' => 'notepad', 'target_id' => $id, 'owner_id' => self::ownerOf($fresh),
                'detail' => (string) $fresh['title'], 'meta' => ['from' => (string) $row['visibility'], 'to' => (string) $fresh['visibility']],
            ]);
        }
        // Announce to the union of the audiences, each in terms of what they can see now.
        $after = self::audience($fresh);
        $shape = self::eventShape($fresh);
        $lost = array_values(array_diff($before, $after));
        $gained = array_values(array_diff($after, $before));
        $kept = array_values(array_intersect($after, $before));
        EventBus::publish('notepad.renamed', ['notepad' => $shape, 'changes' => $changes, 'old_title' => (string) $row['title']], $kept, ['actor_id' => $uid]);
        EventBus::publish('notepad.created', ['notepad' => $shape], $gained, ['actor_id' => $uid]);
        EventBus::publish('notepad.deleted', ['notepad_id' => $id, 'reason' => 'private'], $lost, ['actor_id' => $uid]);
        if ($lost !== []) {
            [$in, $params] = Db::inList($lost, 'lu');
            $params['n'] = $id;
            Db::run("DELETE FROM notepad_presence WHERE notepad_id = :n AND user_id IN {$in}", $params);
        }
        return self::shape($fresh, $user, self::names(self::peopleIn([$fresh])), self::presentCount($id));
    }

    /** DELETE /notepads/{id} — creator or administrator; removes its history too. */
    public static function delete(array $user, int $id): void
    {
        $row = self::requireVisible($user, $id);
        self::assertManage($user, $row);
        $audience = self::audience($row);
        Db::delete('notepads', ['id' => $id]); // revisions and presence cascade
        Audit::log('notepad.delete', [
            'user_id' => (int) $user['id'], 'target_type' => 'notepad', 'target_id' => $id, 'owner_id' => self::ownerOf($row),
            'detail' => (string) $row['title'], 'meta' => ['visibility' => (string) $row['visibility'], 'version' => (int) $row['version']],
        ]);
        EventBus::publish('notepad.deleted', ['notepad_id' => $id, 'title' => (string) $row['title']], $audience, ['actor_id' => (int) $user['id']]);
    }

    /** POST /notepads/{id}/revisions/{rid}/restore — a new version with the revision's text. */
    public static function restore(array $user, int $id, int $rid, ?string $clientId = null): array
    {
        self::requireVisible($user, $id);
        $uid = (int) $user['id'];
        $cid = self::cleanClientId($clientId);
        $now = Db::now();
        $result = Db::transaction(static function () use ($user, $id, $rid, $uid, $now): array {
            $row = self::requireVisible($user, $id, true, true);
            $rev = self::requireRevision($id, $rid);
            $text = self::decodeBlob((string) $rev['content'], (string) $rev['content_codec'], $id);
            if ($text === self::decode($row)) {
                return ['row' => $row, 'text' => $text, 'changed' => false, 'from' => (int) $rev['version']];
            }
            $version = (int) $row['version'] + 1;
            [$blob, $codec] = self::encode($text, $id);
            Db::update('notepads', [
                'content' => $blob, 'content_codec' => $codec, 'content_size' => strlen($text),
                'version' => $version, 'updated_by' => $uid, 'updated_at' => $now,
            ], ['id' => $id]);
            self::recordRevision($id, $version, $blob, $codec, strlen($text), $uid, $now, (int) $rev['version']);
            $row = array_merge($row, ['version' => $version, 'content_size' => strlen($text), 'updated_by' => $uid, 'updated_at' => $now]);
            return ['row' => $row, 'text' => $text, 'changed' => true, 'from' => (int) $rev['version']];
        });
        $row = $result['row'];
        if ($result['changed']) {
            Audit::log('notepad.restore', [
                'user_id' => $uid, 'target_type' => 'notepad', 'target_id' => $id, 'owner_id' => self::ownerOf($row),
                'detail' => (string) $row['title'], 'meta' => ['restored_version' => $result['from'], 'version' => (int) $row['version']],
            ]);
            self::publishUpdated($row, $user, $cid, $result['from']);
        }
        return self::detail($row, $user, $result['text']) + ['changed' => $result['changed']];
    }

    /**
     * POST /notepads/{id}/presence (heartbeat) or DELETE (leave). Returns the people who have the
     * notepad open plus its current version (a cheap "did I miss a save?" check for the client);
     * publishes notepad.presence when that set of people changed.
     */
    public static function heartbeat(array $user, int $id, ?string $clientId, bool $leave = false): array
    {
        $row = self::requireVisible($user, $id);
        $cid = self::cleanClientId($clientId) ?? '';
        $uid = (int) $user['id'];
        $before = self::presentUserIds($id, false);
        Db::run('DELETE FROM notepad_presence WHERE notepad_id = :n AND seen_at < :cut', ['n' => $id, 'cut' => Db::ts(time() - self::PRESENCE_TTL)]);
        if ($leave) {
            Db::delete('notepad_presence', ['notepad_id' => $id, 'user_id' => $uid, 'client_id' => $cid]);
        } else {
            Db::run(
                'INSERT INTO notepad_presence (notepad_id, user_id, client_id, seen_at) VALUES (:n, :u, :c, :t)
                 ON DUPLICATE KEY UPDATE seen_at = VALUES(seen_at)',
                ['n' => $id, 'u' => $uid, 'c' => $cid, 't' => Db::now()]
            );
            if (random_int(1, 50) === 1) {
                self::prunePresence(); // rows of notepads nobody opens again
            }
        }
        $after = self::presentUserIds($id, true);
        $users = self::presentUsers($after);
        if ($before !== $after) {
            EventBus::publish('notepad.presence', ['notepad_id' => $id, 'users' => $users], self::audience($row), ['actor_id' => $uid]);
        }
        return [
            'notepad_id' => $id,
            'users'      => $users,
            'version'    => (int) $row['version'],
            'updated_at' => Db::iso((string) $row['updated_at']),
            'ttl'        => self::PRESENCE_TTL,
        ];
    }

    /** Drop stale presence rows everywhere (also usable from maintenance). */
    public static function prunePresence(int $limit = 1000): int
    {
        return Db::run('DELETE FROM notepad_presence WHERE seen_at < :cut LIMIT ' . max(1, min(10000, $limit)), ['cut' => Db::ts(time() - self::PRESENCE_TTL)])->rowCount();
    }

    /**
     * Legacy importer (collab.json): one document → a team notepad, idempotent by legacy_key.
     * "shared" (the old app's only notepad) fills the automatic "Team notepad" when it is still
     * empty, becomes "Team notepad" when there is no team notepad yet, and otherwise is added as
     * "Team notepad (imported)". Other documents become team notepads titled from their id.
     * No events are published (like the rest of the import). Returns the notepad id.
     */
    public static function importLegacy(string $doc, string $content, ?int $userId, string $time, ?int $actorId = null): int
    {
        $existing = Db::value('SELECT id FROM notepads WHERE legacy_key = ?', [$doc]);
        if ($existing !== null) {
            return (int) $existing;
        }
        if (strlen($content) > self::MAX_BYTES) {
            $content = mb_strcut($content, 0, self::MAX_BYTES, 'UTF-8');
        }
        $size = strlen($content);
        if ($doc === 'shared') {
            $team = Db::one(
                "SELECT id, version FROM notepads WHERE visibility = 'team' AND title = ? AND legacy_key IS NULL AND content_size = 0
                 ORDER BY id ASC LIMIT 1 FOR UPDATE",
                [self::DEFAULT_TITLE]
            );
            if ($team !== null) {
                $id = (int) $team['id'];
                $version = (int) $team['version'] + 1;
                [$blob, $codec] = self::encode($content, $id);
                Db::update('notepads', [
                    'content' => $blob, 'content_codec' => $codec, 'content_size' => $size, 'version' => $version,
                    'updated_by' => $userId, 'updated_at' => $time, 'legacy_key' => $doc,
                ], ['id' => $id]);
                self::recordRevision($id, $version, $blob, $codec, $size, $userId, $time, null, false);
                self::logImport($id, self::DEFAULT_TITLE, $doc, $actorId);
                return $id;
            }
            $anyTeam = Db::value("SELECT 1 FROM notepads WHERE visibility = 'team' LIMIT 1") !== null;
            $title = $anyTeam ? self::DEFAULT_TITLE . ' (imported)' : self::DEFAULT_TITLE;
        } else {
            $title = self::titleFromDoc($doc);
        }
        $id = self::insertNotepad($title, 'team', null, $content, $userId, $time, $doc);
        self::logImport($id, $title, $doc, $actorId);
        return $id;
    }

    // ------------------------------------------------------------------ rules

    public static function canManage(array $user, array $row): bool
    {
        if ($row['visibility'] === 'private') {
            return (int) ($row['owner_id'] ?? 0) === (int) $user['id'];
        }
        return Policy::isAdmin($user) || ($row['owner_id'] !== null && (int) $row['owner_id'] === (int) $user['id']);
    }

    /**
     * Who may see the notepad: the owner of a private one; every active, non-guest account for a
     * team one. Events about the notepad's existence go to these people.
     * @return int[]
     */
    public static function audience(array $row): array
    {
        if ($row['visibility'] === 'private') {
            return $row['owner_id'] !== null ? [(int) $row['owner_id']] : [];
        }
        return array_map('intval', Db::column(
            "SELECT u.id FROM users u JOIN roles r ON r.id = u.role_id
              WHERE u.deleted_at IS NULL AND u.status = 'active' AND r.slug <> 'guest'"
        ));
    }

    /**
     * Who gets live content updates: the owner (all devices) of a private notepad; the people who
     * have a team notepad open right now. Everyone else sees the new text when they open it.
     * @return int[]
     */
    public static function liveAudience(array $row): array
    {
        if ($row['visibility'] === 'private') {
            return $row['owner_id'] !== null ? [(int) $row['owner_id']] : [];
        }
        return self::presentUserIds((int) $row['id'], true);
    }

    // ------------------------------------------------------------------ internals

    private static function assertMember(array $user): void
    {
        if (($user['role'] ?? '') === 'guest') {
            throw ApiException::forbidden('Notepads are not available to guest accounts.');
        }
    }

    private static function assertManage(array $user, array $row): void
    {
        if (!self::canManage($user, $row)) {
            throw ApiException::forbidden('Only the person who created this notepad or an administrator can rename or delete it.');
        }
    }

    /** 422 with a clear message when a text of $n bytes is over the 1 MiB limit. */
    public static function assertSize(int $n): void
    {
        if ($n > self::MAX_BYTES) {
            $mb = number_format($n / 1048576, 1);
            throw new ApiException('VALIDATION_FAILED', "A notepad can hold up to 1 MB of text and this text is {$mb} MB. Remove some text or move it into a file.", 422, [
                'fields'    => ['content' => 'A notepad can hold up to 1 MB of text.'],
                'max_bytes' => self::MAX_BYTES,
                'size'      => $n,
            ]);
        }
    }

    /** The row if $user may open it (team, or their own private one); 404 otherwise. */
    private static function requireVisible(array $user, int $id, bool $withContent = false, bool $lock = false): array
    {
        self::assertMember($user);
        $row = Db::one('SELECT ' . ($withContent ? '*' : self::META_COLS) . ' FROM notepads WHERE id = ?' . ($lock ? ' FOR UPDATE' : ''), [$id]);
        if ($row === null || ($row['visibility'] === 'private' && (int) ($row['owner_id'] ?? 0) !== (int) $user['id'])) {
            throw new ApiException('NOTEPAD_NOT_FOUND', 'The requested notepad could not be found.', 404);
        }
        return $row;
    }

    private static function requireRow(int $id): array
    {
        $row = Db::one('SELECT ' . self::META_COLS . ' FROM notepads WHERE id = ?', [$id]);
        if ($row === null) {
            throw new ApiException('NOTEPAD_NOT_FOUND', 'The requested notepad could not be found.', 404);
        }
        return $row;
    }

    private static function requireRevision(int $id, int $rid): array
    {
        $rev = Db::one('SELECT * FROM notepad_revisions WHERE id = ? AND notepad_id = ?', [$rid, $id]);
        if ($rev === null) {
            throw ApiException::notFound('revision');
        }
        return $rev;
    }

    private static function conflict(array $row, string $current, int $base): ApiException
    {
        return ApiException::conflict(
            'Someone saved this notepad while you were editing. Your changes are being merged with theirs.',
            'VERSION_CONFLICT',
            [
                'current_version' => (int) $row['version'],
                'base_version'    => $base,
                'content'         => $current,
                'updated_at'      => Db::iso((string) $row['updated_at']),
                'updated_by'      => self::names([$row['updated_by']])[(int) $row['updated_by']] ?? null,
            ]
        );
    }

    private static function publishUpdated(array $row, array $user, ?string $clientId, ?int $restoredFrom = null): void
    {
        $data = [
            'notepad_id' => (int) $row['id'],
            'version'    => (int) $row['version'],
            'size'       => (int) $row['content_size'],
            'updated_at' => Db::iso((string) $row['updated_at']),
            'by'         => ['id' => (int) $user['id'], 'name' => self::displayName($user)],
            'client_id'  => $clientId,
        ];
        if ($restoredFrom !== null) {
            $data['restored_from_version'] = $restoredFrom;
        }
        EventBus::publish('notepad.updated', $data, self::liveAudience($row), ['actor_id' => (int) $user['id']]);
    }

    /**
     * Snapshot for the history. Coalesces into the newest revision while it is by the same person,
     * started less than COALESCE_SECONDS ago and is not a restore; keeps the newest REVISION_KEEP.
     */
    private static function recordRevision(int $notepadId, int $version, string $blob, string $codec, int $size, ?int $userId, string $now, ?int $restoredFrom = null, bool $coalesce = true): void
    {
        $last = $coalesce && $restoredFrom === null && $userId !== null
            ? Db::one('SELECT id, user_id, restored_from_version, created_at FROM notepad_revisions WHERE notepad_id = ? ORDER BY id DESC LIMIT 1', [$notepadId])
            : null;
        if ($last !== null && $last['restored_from_version'] === null && $last['user_id'] !== null && (int) $last['user_id'] === $userId
            && (int) Db::toUnix((string) $last['created_at']) > (int) Db::toUnix($now) - self::COALESCE_SECONDS) {
            Db::update('notepad_revisions', [
                'version' => $version, 'content' => $blob, 'content_codec' => $codec, 'content_size' => $size, 'updated_at' => $now,
            ], ['id' => (int) $last['id']]);
            return;
        }
        Db::insert('notepad_revisions', [
            'notepad_id' => $notepadId, 'version' => $version, 'content' => $blob, 'content_codec' => $codec, 'content_size' => $size,
            'user_id' => $userId, 'restored_from_version' => $restoredFrom, 'created_at' => $now, 'updated_at' => $now,
        ]);
        $cut = Db::value('SELECT id FROM notepad_revisions WHERE notepad_id = ? ORDER BY id DESC LIMIT 1 OFFSET ' . (self::REVISION_KEEP - 1), [$notepadId]);
        if ($cut !== null) {
            Db::run('DELETE FROM notepad_revisions WHERE notepad_id = ? AND id < ?', [$notepadId, (int) $cut]);
        }
    }

    /** Insert a notepad (+ its first revision when it starts with text). Returns the id. */
    private static function insertNotepad(string $title, string $visibility, ?int $ownerId, string $content, ?int $updatedBy, string $time, ?string $legacyKey = null): int
    {
        $id = Db::insert('notepads', [
            'title' => $title, 'visibility' => $visibility, 'owner_id' => $ownerId,
            'content' => '', 'content_codec' => 'plain', 'content_size' => 0, 'version' => 1,
            'updated_by' => $updatedBy, 'legacy_key' => $legacyKey, 'created_at' => $time, 'updated_at' => $time,
        ]);
        if ($content !== '') {
            // Encrypted text is bound to the notepad id, so it can only be written once the id exists.
            [$blob, $codec] = self::encode($content, $id);
            Db::update('notepads', ['content' => $blob, 'content_codec' => $codec, 'content_size' => strlen($content)], ['id' => $id]);
            self::recordRevision($id, 1, $blob, $codec, strlen($content), $updatedBy, $time, null, false);
        }
        return $id;
    }

    /** The first list request creates the team notepad when there is none (one at a time). */
    private static function ensureTeamNotepad(): void
    {
        if (Db::value("SELECT 1 FROM notepads WHERE visibility = 'team' LIMIT 1") !== null) {
            return;
        }
        $lock = 'ft_notepad_seed:' . substr(sha1((string) Db::value('SELECT DATABASE()')), 0, 40);
        if ((int) Db::value('SELECT GET_LOCK(?, 5)', [$lock]) !== 1) {
            return; // another request is creating it right now
        }
        try {
            if (Db::value("SELECT 1 FROM notepads WHERE visibility = 'team' LIMIT 1") === null) {
                self::insertNotepad(self::DEFAULT_TITLE, 'team', null, '', null, Db::now());
            }
        } finally {
            Db::value('SELECT RELEASE_LOCK(?)', [$lock]);
        }
    }

    /** @return array{0:string,1:string} [stored bytes, codec] */
    private static function encode(string $text, int $id): array
    {
        $data = $text;
        $steps = [];
        if (strlen($text) >= 256) {
            $z = gzdeflate($text, 6);
            if ($z !== false && strlen($z) < (int) (strlen($text) * 0.9)) {
                $data = $z;
                $steps[] = 'deflate';
            }
        }
        if (Crypto::enabled()) {
            $data = Crypto::encryptString($data, 'notepad:' . $id);
            array_unshift($steps, 'aes');
        }
        return [$data, $steps === [] ? 'plain' : implode('+', $steps)];
    }

    private static function decode(array $row): string
    {
        return self::decodeBlob((string) $row['content'], (string) $row['content_codec'], (int) $row['id']);
    }

    private static function decodeBlob(string $data, string $codec, int $id): string
    {
        $steps = $codec === 'plain' || $codec === '' ? [] : explode('+', $codec);
        try {
            if (in_array('aes', $steps, true)) {
                $data = Crypto::decryptString($data, 'notepad:' . $id);
            }
            if (in_array('deflate', $steps, true)) {
                $out = @gzinflate($data, self::MAX_BYTES + 1);
                if ($out === false) {
                    throw new \RuntimeException('Notepad text could not be decompressed');
                }
                $data = $out;
            }
        } catch (\Throwable $e) {
            Logger::warning('app', 'Notepad text could not be read', ['notepad_id' => $id, 'codec' => $codec, 'error' => $e->getMessage()]);
            throw new ApiException('FILE_UNAVAILABLE', 'This notepad could not be read on this server (its encryption key may be missing).', 410);
        }
        return $data;
    }

    private static function detail(array $row, array $user, string $content): array
    {
        $present = self::presentUserIds((int) $row['id'], true);
        $out = self::shape($row, $user, self::names(self::peopleIn([$row])), count($present));
        $out['content'] = $content;
        $out['present_users'] = self::presentUsers($present);
        return $out;
    }

    /** Per-viewer summary (can_manage, present) or, with $viewer null, the event payload shape. */
    private static function shape(array $row, ?array $viewer, array $names, int $present = 0): array
    {
        $out = [
            'id'         => (int) $row['id'],
            'title'      => (string) $row['title'],
            'visibility' => (string) $row['visibility'],
            'version'    => (int) $row['version'],
            'size'       => (int) $row['content_size'],
            'owner'      => $row['owner_id'] !== null ? ($names[(int) $row['owner_id']] ?? null) : null,
            'updated_by' => $row['updated_by'] !== null ? ($names[(int) $row['updated_by']] ?? null) : null,
            'created_at' => Db::iso((string) $row['created_at']),
            'updated_at' => Db::iso((string) $row['updated_at']),
            'imported'   => $row['legacy_key'] !== null,
        ];
        if ($viewer !== null) {
            $out['can_manage'] = self::canManage($viewer, $row);
            $out['present'] = $present;
        }
        return $out;
    }

    private static function eventShape(array $row): array
    {
        return self::shape($row, null, self::names(self::peopleIn([$row])));
    }

    private static function revisionShape(array $rev, array $notepad, array $names): array
    {
        return [
            'id'                    => (int) $rev['id'],
            'version'               => (int) $rev['version'],
            'size'                  => (int) $rev['content_size'],
            'user'                  => $rev['user_id'] !== null ? ($names[(int) $rev['user_id']] ?? null) : null,
            'created_at'            => Db::iso((string) $rev['created_at']),
            'saved_at'              => Db::iso((string) $rev['updated_at']),
            'restored_from_version' => $rev['restored_from_version'] !== null ? (int) $rev['restored_from_version'] : null,
            'current'               => (int) $rev['version'] === (int) $notepad['version'],
        ];
    }

    /** @return int[] sorted distinct user ids with a presence row ($fresh: seen within the TTL) */
    private static function presentUserIds(int $id, bool $fresh): array
    {
        $sql = 'SELECT DISTINCT user_id FROM notepad_presence WHERE notepad_id = :n';
        $params = ['n' => $id];
        if ($fresh) {
            $sql .= ' AND seen_at >= :cut';
            $params['cut'] = Db::ts(time() - self::PRESENCE_TTL);
        }
        $ids = array_map('intval', Db::column($sql, $params));
        sort($ids);
        return $ids;
    }

    private static function presentCount(int $id): int
    {
        return count(self::presentUserIds($id, true));
    }

    /** @param int[] $ids @return array<int,array> UserRefs sorted by name */
    private static function presentUsers(array $ids): array
    {
        if ($ids === []) {
            return [];
        }
        [$in, $p] = Db::inList($ids, 'pu');
        $users = array_map([Auth::class, 'ref'], Db::all("SELECT id, username, display_name FROM users WHERE id IN {$in}", $p));
        usort($users, static fn ($a, $b) => strcasecmp((string) $a['display_name'], (string) $b['display_name']));
        return array_values($users);
    }

    /** @param array<int,mixed> $ids @return array<int,array{id:int,name:string}> */
    private static function names(array $ids): array
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids), static fn ($i) => $i > 0)));
        if ($ids === []) {
            return [];
        }
        [$in, $p] = Db::inList($ids, 'nm');
        $out = [];
        foreach (Db::all("SELECT id, username, display_name FROM users WHERE id IN {$in}", $p) as $u) {
            $out[(int) $u['id']] = ['id' => (int) $u['id'], 'name' => self::displayName($u)];
        }
        return $out;
    }

    /** @return array<int,mixed> owner and last-editor ids of the rows */
    private static function peopleIn(array $rows): array
    {
        $ids = [];
        foreach ($rows as $r) {
            $ids[] = $r['owner_id'];
            $ids[] = $r['updated_by'];
        }
        return $ids;
    }

    private static function displayName(array $u): string
    {
        $n = (string) (($u['display_name'] ?? '') !== '' ? $u['display_name'] : ($u['username'] ?? ''));
        return $n !== '' ? $n : 'Someone';
    }

    private static function ownerOf(array $row): ?int
    {
        return $row['owner_id'] !== null ? (int) $row['owner_id'] : null;
    }

    private static function cleanTitle(mixed $title): string
    {
        if (!is_string($title) || !mb_check_encoding($title, 'UTF-8')) {
            throw ApiException::validation(['title' => 'Give the notepad a title.']);
        }
        $t = trim((string) preg_replace('/\s+/u', ' ', (string) preg_replace('/[\x00-\x1F\x7F]/u', ' ', $title)));
        if ($t === '') {
            throw ApiException::validation(['title' => 'Give the notepad a title.']);
        }
        if (mb_strlen($t) > self::MAX_TITLE) {
            throw ApiException::validation(['title' => 'Titles can be up to ' . self::MAX_TITLE . ' characters long.']);
        }
        return $t;
    }

    private static function cleanVisibility(mixed $v): string
    {
        if (!is_string($v) || !in_array($v, self::VISIBILITIES, true)) {
            throw ApiException::validation(['visibility' => 'Choose "team" (everyone can edit) or "private" (only you).']);
        }
        return $v;
    }

    private static function cleanClientId(?string $clientId): ?string
    {
        return $clientId !== null && preg_match('/^[A-Za-z0-9-]{1,64}$/', $clientId) ? $clientId : null;
    }

    private static function titleFromDoc(string $doc): string
    {
        $t = trim((string) preg_replace('/[\s_.\-]+/u', ' ', mb_scrub($doc, 'UTF-8')));
        $t = $t !== '' ? mb_strtoupper(mb_substr($t, 0, 1)) . mb_substr($t, 1) : 'Imported notepad';
        return mb_substr($t, 0, self::MAX_TITLE);
    }

    private static function logImport(int $id, string $title, string $doc, ?int $actorId): void
    {
        Audit::log('notepad.create', [
            'user_id' => $actorId, 'target_type' => 'notepad', 'target_id' => $id, 'detail' => $title,
            'meta' => ['visibility' => 'team', 'imported' => true, 'document' => mb_substr($doc, 0, 100)],
        ]);
    }
}
