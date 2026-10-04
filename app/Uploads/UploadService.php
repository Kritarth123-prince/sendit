<?php
declare(strict_types=1);

namespace FT\Uploads;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Core\Stats;
use FT\Events\EventBus;
use FT\Files\FileAccess;
use FT\Files\FileWriter;
use FT\Security\Policy;
use FT\Storage\BlobStore;
use FT\Storage\MimeDetector;
use FT\Storage\Paths;
use FT\Storage\QuotaService;
use FT\Support\Capabilities;

/**
 * Resumable chunked uploads (docs/ARCHITECTURE.md §8.4).
 *
 * Why chunks: shared hosts cap request bodies, kill requests after ~25 s and delete any physical
 * file over 10 MB. A file is therefore sent as raw-body chunks of chunkSize() (≤ 8 MiB) that are
 * staged as separate part files and never concatenated on disk: completion streams the parts in
 * order through hashing/encryption straight into the segmented blob store.
 *
 * Sessions live in upload_sessions (one per file), visible from every device of the user, so an
 * upload interrupted on one device can be inspected (and resumed by re-sending missing chunks).
 * The declared size is reserved against the content owner's quota while a session is active.
 *
 * Content owner: the uploader for their own drive, the folder owner for uploads into a folder
 * shared with them as editor, the file owner for a new version (quota is charged to that owner).
 */
final class UploadService
{
    public const MIN_CHUNK = 262144;
    public const MAX_CHUNK = 8388608;
    /** Single-request uploads (POST /files) stay below the host's physical file-size cap. */
    public const MAX_SIMPLE_BYTES = BlobStore::SEGMENT_BYTES;

    private const PROGRESS_INTERVAL = 2.0;
    private const NOTIFY_AFTER_SECONDS = 30;
    private const READ_PIECE = 65536;
    private const MAX_NAME_INPUT = 1000;

    /** Chunk size offered to clients: ≤ 8 MiB, ≤ segment size, ≤ request body limit − 64 KiB. */
    public static function chunkSize(): int
    {
        $cap = min(self::MAX_CHUNK, (int) Config::get('storage.segment_bytes', self::MAX_CHUNK), Capabilities::maxRequestBytes() - 65536);
        return max(self::MIN_CHUNK, $cap);
    }

    // ================================================================== start

    /**
     * POST /uploads. $in: name, size, folder_id?, file_id?, mime?, tags?, is_permanent?,
     * on_conflict?, last_modified?. Returns the session shape (201).
     */
    public static function start(array $user, array $in): array
    {
        $errors = [];
        $rawName = $in['name'] ?? null;
        if (!is_string($rawName) || trim($rawName) === '') {
            $errors['name'] = 'Enter the file name.';
        } elseif (mb_strlen($rawName) > self::MAX_NAME_INPUT) {
            $errors['name'] = 'The file name is too long.';
        }
        $size = self::intOrNull($in['size'] ?? null);
        if ($size === null || $size < 0) {
            $errors['size'] = 'The file size is missing or invalid.';
        }
        $onConflict = $in['on_conflict'] ?? 'rename';
        if (!is_string($onConflict) || !in_array($onConflict, ['rename', 'replace', 'error'], true)) {
            $errors['on_conflict'] = 'Choose rename, replace or error.';
        }
        $fileId = self::intOrNull($in['file_id'] ?? null);
        $folderId = self::intOrNull($in['folder_id'] ?? null);
        if (($in['file_id'] ?? null) !== null && ($fileId === null || $fileId <= 0)) {
            $errors['file_id'] = 'The file id is invalid.';
        }
        if (($in['folder_id'] ?? null) !== null && $in['folder_id'] !== '' && ($folderId === null || $folderId < 0)) {
            $errors['folder_id'] = 'The folder id is invalid.';
        }
        if ($errors !== []) {
            throw ApiException::validation($errors);
        }
        $name = FileWriter::sanitizeName((string) $rawName);
        self::assertAllowedName($name);
        self::assertSize((int) $size);

        [$folderId, $ownerId, $targetId] = self::resolveTarget($user, $fileId, $folderId ?: null);
        if ($targetId === null && $onConflict === 'error'
            && Db::value('SELECT 1 FROM files WHERE owner_id = :o AND folder_id <=> :f AND deleted_at IS NULL AND name = :n LIMIT 1',
                ['o' => $ownerId, 'f' => $folderId, 'n' => $name]) !== null) {
            throw ApiException::conflict('A file called “' . $name . '” already exists here.', 'NAME_CONFLICT');
        }

        $chunk = self::chunkSize();
        $total = (int) ceil($size / $chunk);
        $id = bin2hex(random_bytes(16));
        $now = Db::now();
        $ttl = max(1, Settings::int('upload_session_ttl_hours', 24));
        $isPermanent = array_key_exists('is_permanent', $in) && $in['is_permanent'] !== null
            ? filter_var($in['is_permanent'], FILTER_VALIDATE_BOOLEAN) : null;
        $options = [
            'owner_id'      => $ownerId,
            'tags'          => FileWriter::normaliseTags($in['tags'] ?? []),
            'is_permanent'  => $isPermanent,
            'on_conflict'   => $onConflict,
            'last_modified' => self::intOrNull($in['last_modified'] ?? null),
            'description'   => isset($in['description']) && is_string($in['description']) ? mb_substr(trim($in['description']), 0, 1000) : null,
        ];
        $mimeClient = isset($in['mime']) && is_string($in['mime']) && preg_match('~^[\w.+-]+/[\w.+-]+$~', $in['mime']) ? mb_substr($in['mime'], 0, 127) : null;

        // Check + reserve atomically per owner, so parallel starts cannot overshoot the quota.
        self::withOwnerLock($ownerId, static function () use ($ownerId, $size, $id, $user, $folderId, $targetId, $name, $mimeClient, $chunk, $total, $options, $now, $ttl): void {
            QuotaService::assertCanStore($ownerId, (int) $size);
            Db::insert('upload_sessions', [
                'id'              => $id,
                'user_id'         => (int) $user['id'],
                'folder_id'       => $folderId,
                'target_file_id'  => $targetId,
                'name'            => $name,
                'size'            => (int) $size,
                'mime_client'     => $mimeClient,
                'chunk_size'      => $chunk,
                'total_chunks'    => $total,
                'received_chunks' => 0,
                'received_bytes'  => 0,
                'options'         => json_encode($options, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                'status'          => 'active',
                'client_id'       => \FT\Core\RequestContext::clientId(),
                'created_at'      => $now,
                'updated_at'      => $now,
                'expires_at'      => Db::ts(time() + $ttl * 3600),
            ]);
        });

        $session = self::get($id);
        self::publish('upload.started', $session, []);
        return self::shape($session);
    }

    // ================================================================== chunks

    /**
     * PUT /uploads/{id}/chunks/{index}: store one raw-body chunk (idempotent; a re-sent chunk
     * replaces the earlier copy). $body is a readable stream (php://input).
     * @param resource $body
     */
    public static function putChunk(array $user, string $id, int $index, $body, ?int $declaredLength = null, ?string $sha256 = null): array
    {
        $s = self::load($user, $id);
        $s = self::assertActive($s);
        $total = (int) $s['total_chunks'];
        if ($index < 0 || $index >= $total) {
            throw self::chunkInvalid('Chunk ' . $index . ' is out of range (this upload has ' . $total . ' chunk' . ($total === 1 ? '' : 's') . ').');
        }
        $expected = self::expectedLength($s, $index);
        if ($declaredLength !== null && $declaredLength !== $expected) {
            throw self::chunkInvalid('Chunk ' . $index . ' must be exactly ' . $expected . ' bytes.', ['expected_bytes' => $expected]);
        }
        if ($sha256 !== null && !preg_match('/^[a-f0-9]{64}$/i', $sha256)) {
            throw self::chunkInvalid('The chunk checksum header is malformed.');
        }
        $owner = self::ownerOf($s);
        QuotaService::assertCanStore($owner, (int) $s['size'], $id); // the quota may have changed

        $dir = self::tempDir($owner, $id);
        $final = $dir . '/' . $index . '.part';
        $tmp = $final . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $out = @fopen($tmp, 'wb');
        if ($out === false) {
            throw ApiException::server('The upload could not be stored. Please try again.');
        }
        $hash = hash_init('sha256');
        $got = 0;
        try {
            $stalls = 0;
            while ($got <= $expected) {
                $d = fread($body, min(self::READ_PIECE, $expected + 1 - $got));
                if ($d === false) {
                    break;
                }
                if ($d === '') {
                    if (feof($body) || ++$stalls > 1000) {
                        break;
                    }
                    continue;
                }
                $got += strlen($d);
                if ($got > $expected) {
                    break;
                }
                hash_update($hash, $d);
                if (fwrite($out, $d) !== strlen($d)) {
                    throw ApiException::server('The upload could not be stored (storage full?). Please try again.');
                }
            }
            fclose($out);
            $out = null;
            if ($got !== $expected) {
                throw self::chunkInvalid('Chunk ' . $index . ' must be exactly ' . $expected . ' bytes (received ' . ($got > $expected ? 'more' : $got) . ').', ['expected_bytes' => $expected]);
            }
            $digest = hash_final($hash);
            if ($sha256 !== null && !hash_equals(strtolower($sha256), $digest)) {
                throw self::chunkInvalid('Chunk ' . $index . ' was damaged in transit (checksum mismatch). Please resend it.');
            }
            if (!@rename($tmp, $final)) {
                throw ApiException::server('The upload could not be stored. Please try again.');
            }
        } finally {
            if (is_resource($out)) {
                fclose($out);
            }
            if (is_file($tmp)) {
                @unlink($tmp);
            }
        }

        $now = Db::now();
        Db::run(
            'INSERT INTO upload_chunks (upload_id, chunk_index, size, sha256, created_at) VALUES (:u, :i, :s, :h, :t)
             ON DUPLICATE KEY UPDATE size = VALUES(size), sha256 = VALUES(sha256), created_at = VALUES(created_at)',
            ['u' => $id, 'i' => $index, 's' => $expected, 'h' => $digest, 't' => $now]
        );
        Db::run(
            'UPDATE upload_sessions SET
                received_chunks = (SELECT COUNT(*) FROM upload_chunks WHERE upload_id = :a),
                received_bytes = (SELECT COALESCE(SUM(size), 0) FROM upload_chunks WHERE upload_id = :b),
                updated_at = :t
             WHERE id = :c',
            ['a' => $id, 'b' => $id, 't' => $now, 'c' => $id]
        );
        $s = self::get($id);
        self::maybeProgress($s);
        return [
            'index'           => $index,
            'received_chunks' => (int) $s['received_chunks'],
            'received_bytes'  => (int) $s['received_bytes'],
            'total_chunks'    => (int) $s['total_chunks'],
        ];
    }

    // ================================================================== status / list

    public static function status(array $user, string $id): array
    {
        $s = self::load($user, $id);
        if (in_array($s['status'], ['active', 'assembling'], true) && (string) $s['expires_at'] <= Db::now()) {
            $s = self::expire($s);
        }
        return self::shape($s, true);
    }

    /** GET /uploads?status=active|completed|failed|aborted|expired|all — this user's sessions. */
    public static function listFor(array $user, string $status = 'active'): array
    {
        $params = ['u' => (int) $user['id']];
        $where = 'user_id = :u';
        if ($status === 'active') {
            $where .= " AND status IN ('active', 'assembling') AND expires_at > :now";
            $params['now'] = Db::now();
        } elseif (in_array($status, ['completed', 'failed', 'aborted', 'expired', 'assembling'], true)) {
            $where .= ' AND status = :st';
            $params['st'] = $status;
        } elseif ($status !== 'all') {
            throw ApiException::validation(['status' => 'Unknown upload status filter.']);
        }
        $rows = Db::all("SELECT * FROM upload_sessions WHERE {$where} ORDER BY created_at DESC LIMIT 100", $params);
        return array_map(static fn (array $r) => self::shape($r, true), $rows);
    }

    // ================================================================== complete

    /**
     * POST /uploads/{id}/complete: assemble, store, create the file (or new version).
     * Idempotent: a completed session returns its file again.
     * @return array FileSummary for the uploader
     */
    public static function complete(array $user, string $id): array
    {
        $s = self::load($user, $id);
        if ($s['status'] === 'completed') {
            return self::completedSummary($user, $s);
        }
        $s = self::assertActive($s, true);
        $missing = self::missingChunks($s);
        if ($missing !== []) {
            throw new ApiException('UPLOAD_INCOMPLETE', 'Some parts of this file have not arrived yet. Resume the upload to send them.', 409, [
                'missing' => array_slice($missing, 0, 100),
                'missing_count' => count($missing),
            ]);
        }

        // Atomic active → assembling transition: exactly one request assembles. A crashed
        // assembly (stale 'assembling') may be taken over after staleAfter() seconds.
        $n = Db::run(
            "UPDATE upload_sessions SET status = 'assembling', updated_at = :now
              WHERE id = :id AND user_id = :uid
                AND (status = 'active' OR (status = 'assembling' AND updated_at < :stale))",
            ['now' => Db::now(), 'id' => $id, 'uid' => (int) $user['id'], 'stale' => Db::ts(time() - self::staleAfter())]
        )->rowCount();
        if ($n !== 1) {
            $again = self::get($id);
            if ($again['status'] === 'completed') {
                return self::completedSummary($user, $again);
            }
            throw ApiException::conflict('This upload is already being completed. Please wait a moment.');
        }

        Capabilities::ignoreUserAbort(); // a closed tab must not leave a half-written file
        $started = Db::toUnix((string) $s['created_at']) ?? time();
        $blob = null;
        try {
            $opts = self::options($s);
            $targetId = $s['target_file_id'] !== null ? (int) $s['target_file_id'] : null;
            // Re-authorise: sharing may have changed since the upload started.
            [$folderId, $ownerId] = self::resolveTarget($user, $targetId, $s['folder_id'] !== null ? (int) $s['folder_id'] : null);
            QuotaService::assertCanStore($ownerId, (int) $s['size'], $id);

            $dir = self::tempDir(self::ownerOf($s), $id);
            $paths = [];
            for ($i = 0; $i < (int) $s['total_chunks']; $i++) {
                $paths[] = $dir . '/' . $i . '.part';
            }
            $blob = BlobStore::putParts($paths, BlobStore::scopeFor($ownerId), null, (string) $s['name']);
            if ((int) $blob['size'] !== (int) $s['size']) {
                throw new \RuntimeException('Assembled size does not match the declared size');
            }

            $handOver = $blob;
            $blob = null; // FileWriter now owns the reference (and releases it on failure)
            if ($targetId !== null) {
                $file = FileWriter::addVersion($targetId, $handOver, (int) $user['id'], '');
            } else {
                $file = self::createOrReplace($user, $ownerId, $folderId, (string) $s['name'], $handOver, $opts);
            }

            Db::run(
                "UPDATE upload_sessions SET status = 'completed', result_file_id = :f, received_bytes = size, error = NULL, updated_at = :t WHERE id = :id",
                ['f' => (int) $file['id'], 't' => Db::now(), 'id' => $id]
            );
            Db::delete('upload_chunks', ['upload_id' => $id]);
            self::rmTree($dir);
        } catch (\Throwable $e) {
            if ($blob !== null) {
                try {
                    BlobStore::release((int) $blob['id']);
                } catch (\Throwable) {
                    // reconcile repairs ref_count drift
                }
            }
            throw self::fail(self::get($id), $e);
        }

        $done = self::get($id);
        self::publish('upload.completed', $done, ['file_id' => (int) $file['id']]);
        if (time() - $started > self::NOTIFY_AFTER_SECONDS) {
            // Long uploads: the user has probably switched to another tab or device.
            self::notify((int) $user['id'], 'upload.completed', 'Upload complete: “' . $file['name'] . '”', '', [
                'file_id' => (int) $file['id'],
                'upload_id' => $id,
                'link' => '#/files' . ($file['folder_id'] !== null && (int) $file['owner_id'] === (int) $user['id'] ? '/' . (int) $file['folder_id'] : ''),
            ], 'upload:' . $id);
        }
        return FileWriter::summary($file, $user);
    }

    // ================================================================== abort

    /** DELETE /uploads/{id}: abandon an upload, free its temp data and reservation. */
    public static function abort(array $user, string $id): void
    {
        $s = self::load($user, $id);
        if ($s['status'] === 'completed') {
            throw ApiException::conflict('This upload has already finished.');
        }
        if ($s['status'] === 'assembling' && (string) $s['updated_at'] >= Db::ts(time() - self::staleAfter())) {
            throw ApiException::conflict('This upload is being completed and can no longer be cancelled.');
        }
        $wasLive = in_array($s['status'], ['active', 'assembling'], true);
        Db::update('upload_sessions', ['status' => 'aborted', 'error' => 'Cancelled', 'updated_at' => Db::now()], ['id' => $id]);
        self::cleanup($s);
        if ($wasLive) {
            self::publish('upload.failed', self::get($id), ['reason' => 'aborted']);
        }
    }

    // ================================================================== single request

    /**
     * POST /files (multipart, field "file"): one-request upload for small files and API clients.
     * Same validations as the chunked protocol; limited to MAX_SIMPLE_BYTES so no oversized
     * physical file is ever kept.
     * @param array<string,mixed>|null $upload the $_FILES['file'] entry
     */
    public static function simpleUpload(array $user, ?array $upload, array $in): array
    {
        if ($upload === null || !isset($upload['error']) || is_array($upload['error'])) {
            throw ApiException::validation(['file' => 'Attach exactly one file in the "file" field.']);
        }
        $err = (int) $upload['error'];
        if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE) {
            throw ApiException::tooLarge('The file is too large for a single-request upload. Use the resumable upload API (POST /api/v1/uploads).');
        }
        if ($err === UPLOAD_ERR_NO_FILE) {
            throw ApiException::validation(['file' => 'Attach a file in the "file" field.']);
        }
        if ($err !== UPLOAD_ERR_OK) {
            throw ApiException::badRequest('The upload did not arrive completely. Please try again.');
        }
        $size = (int) ($upload['size'] ?? 0);
        $rawName = isset($in['name']) && is_string($in['name']) && trim($in['name']) !== '' ? $in['name'] : (string) ($upload['name'] ?? '');
        $name = FileWriter::sanitizeName(mb_substr($rawName, 0, self::MAX_NAME_INPUT));
        self::assertAllowedName($name);
        self::assertSize($size);
        if ($size > self::MAX_SIMPLE_BYTES) {
            throw ApiException::tooLarge('Files larger than 8 MB must use the resumable upload API (POST /api/v1/uploads).');
        }
        $onConflict = $in['on_conflict'] ?? 'rename';
        if (!is_string($onConflict) || !in_array($onConflict, ['rename', 'replace', 'error'], true)) {
            throw ApiException::validation(['on_conflict' => 'Choose rename, replace or error.']);
        }
        $fileId = self::intOrNull($in['file_id'] ?? null);
        $folderId = self::intOrNull($in['folder_id'] ?? null);
        [$folderId, $ownerId, $targetId] = self::resolveTarget($user, $fileId !== null && $fileId > 0 ? $fileId : null, $folderId ?: null);
        QuotaService::assertCanStore($ownerId, $size);

        // move_uploaded_file() is the only operation allowed on tmp_name (open_basedir hosts).
        $tmpDir = Paths::userDir($ownerId, 'temp') . '/single-' . bin2hex(random_bytes(8));
        Paths::ensureDir($tmpDir);
        $dest = $tmpDir . '/upload.bin';
        try {
            $tmpName = (string) ($upload['tmp_name'] ?? '');
            if ($tmpName === '' || !is_uploaded_file($tmpName) || !move_uploaded_file($tmpName, $dest)) {
                throw ApiException::badRequest('The uploaded file could not be processed.');
            }
            clearstatcache(true, $dest);
            if ((int) @filesize($dest) !== $size) {
                throw ApiException::badRequest('The upload did not arrive completely. Please try again.');
            }
            $blob = BlobStore::putFile($dest, BlobStore::scopeFor($ownerId), null, $name);
            $isPermanent = array_key_exists('is_permanent', $in) && $in['is_permanent'] !== null && $in['is_permanent'] !== ''
                ? filter_var($in['is_permanent'], FILTER_VALIDATE_BOOLEAN) : null;
            $opts = [
                'tags' => FileWriter::normaliseTags($in['tags'] ?? []),
                'is_permanent' => $isPermanent,
                'on_conflict' => $onConflict,
                'description' => isset($in['description']) && is_string($in['description']) ? mb_substr(trim($in['description']), 0, 1000) : null,
            ];
            $file = $targetId !== null
                ? FileWriter::addVersion($targetId, $blob, (int) $user['id'], '')
                : self::createOrReplace($user, $ownerId, $folderId, $name, $blob, $opts);
        } finally {
            self::rmTree($tmpDir);
        }
        return FileWriter::summary($file, $user);
    }

    // ================================================================== maintenance (A6)

    /**
     * cleanup_uploads maintenance task: expire stale sessions (freeing their reservation and
     * temp data), drop finished sessions after a week, and delete orphaned temp directories.
     * Time-boxed; returns the number of items cleaned.
     */
    public static function cleanupExpired(float $budgetSeconds = 5.0, int $limit = 200): int
    {
        $deadline = microtime(true) + max(0.5, $budgetSeconds);
        $done = 0;
        $rows = Db::all(
            "SELECT * FROM upload_sessions WHERE status IN ('active', 'assembling') AND expires_at <= ? ORDER BY expires_at LIMIT ?",
            [Db::now(), max(1, $limit)]
        );
        foreach ($rows as $s) {
            if (microtime(true) > $deadline) {
                return $done;
            }
            self::expire($s);
            $done++;
        }
        $old = Db::all(
            "SELECT * FROM upload_sessions WHERE status IN ('completed', 'failed', 'aborted', 'expired') AND updated_at < ? LIMIT ?",
            [Db::ts(time() - 7 * 86400), max(1, $limit)]
        );
        foreach ($old as $s) {
            if (microtime(true) > $deadline) {
                return $done;
            }
            self::cleanup($s);
            Db::delete('upload_sessions', ['id' => (string) $s['id']]);
            $done++;
        }
        // Orphaned temp directories: sessions deleted without cleanup, crashed blob writers.
        $ttl = max(1, Settings::int('upload_session_ttl_hours', 24)) * 3600;
        foreach (glob(Paths::root() . '/users/*/temp/*', GLOB_ONLYDIR) ?: [] as $dir) {
            if (microtime(true) > $deadline) {
                break;
            }
            $base = basename($dir);
            $age = time() - (int) @filemtime($dir);
            if (preg_match('/^[a-f0-9]{32}$/', $base)) {
                if ($age > $ttl && Db::value("SELECT 1 FROM upload_sessions WHERE id = ? AND status IN ('active', 'assembling')", [$base]) === null) {
                    self::rmTree($dir);
                    $done++;
                }
            } elseif (preg_match('/^(blob|single)-[a-f0-9]{16}$/', $base) && $age > 6 * 3600) {
                self::rmTree($dir);
                $done++;
            }
        }
        return $done;
    }

    // ================================================================== shapes

    public static function shape(array $s, bool $full = false): array
    {
        $out = [
            'id'             => (string) $s['id'],
            'name'           => (string) $s['name'],
            'size'           => (int) $s['size'],
            'status'         => (string) $s['status'],
            'chunk_size'     => (int) $s['chunk_size'],
            'total_chunks'   => (int) $s['total_chunks'],
            'received'       => in_array($s['status'], ['active', 'assembling'], true)
                ? array_map('intval', Db::column('SELECT chunk_index FROM upload_chunks WHERE upload_id = ? ORDER BY chunk_index', [(string) $s['id']]))
                : ($s['status'] === 'completed' && (int) $s['total_chunks'] > 0 ? range(0, (int) $s['total_chunks'] - 1) : []),
            'received_bytes' => (int) $s['received_bytes'],
            'percent'        => self::percent($s),
            'folder_id'      => $s['folder_id'] !== null ? (int) $s['folder_id'] : null,
            'file_id'        => $s['target_file_id'] !== null ? (int) $s['target_file_id'] : null,
            'result_file_id' => $s['result_file_id'] !== null ? (int) $s['result_file_id'] : null,
            'expires_at'     => Db::iso((string) $s['expires_at']),
        ];
        if ($full) {
            $out['error'] = $s['error'];
            $out['created_at'] = Db::iso((string) $s['created_at']);
            $out['updated_at'] = Db::iso((string) $s['updated_at']);
        }
        return $out;
    }

    // ================================================================== internals

    private static function get(string $id): array
    {
        $row = Db::one('SELECT * FROM upload_sessions WHERE id = ?', [$id]);
        if ($row === null) {
            throw ApiException::notFound('upload', 'UPLOAD_NOT_FOUND');
        }
        return $row;
    }

    /** A session of THIS user (anyone else's id is indistinguishable from a missing one). */
    private static function load(array $user, string $id): array
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
            throw ApiException::notFound('upload', 'UPLOAD_NOT_FOUND');
        }
        $row = Db::one('SELECT * FROM upload_sessions WHERE id = ? AND user_id = ?', [$id, (int) $user['id']]);
        if ($row === null) {
            throw ApiException::notFound('upload', 'UPLOAD_NOT_FOUND');
        }
        return $row;
    }

    /** Throws unless the session accepts chunks / completion. Handles expiry. */
    private static function assertActive(array $s, bool $allowStaleAssembling = false): array
    {
        if (in_array($s['status'], ['active', 'assembling'], true) && (string) $s['expires_at'] <= Db::now()) {
            self::expire($s);
            throw new ApiException('UPLOAD_EXPIRED', 'This upload has expired. Please start it again.', 409);
        }
        if ($s['status'] === 'active') {
            return $s;
        }
        if ($s['status'] === 'assembling' && $allowStaleAssembling && (string) $s['updated_at'] < Db::ts(time() - self::staleAfter())) {
            return $s;
        }
        $msg = match ((string) $s['status']) {
            'assembling' => 'This upload is already being completed.',
            'completed'  => 'This upload has already finished.',
            'aborted'    => 'This upload was cancelled. Please start it again.',
            'expired'    => 'This upload has expired. Please start it again.',
            default      => 'This upload failed. Please start it again.',
        };
        throw new ApiException($s['status'] === 'expired' ? 'UPLOAD_EXPIRED' : 'CONFLICT', $msg, 409);
    }

    /**
     * Authorise the destination and work out who owns the new content.
     * @return array{0:?int,1:int,2:?int} [folder id, content owner id, target file id]
     */
    private static function resolveTarget(array $user, ?int $fileId, ?int $folderId): array
    {
        if ($fileId !== null) {
            $file = FileAccess::require($user, $fileId, 'edit');
            if (($file['access']['role'] ?? '') === 'owner') {
                Policy::requirePermission($user, 'files.upload');
            }
            return [$file['folder_id'] !== null ? (int) $file['folder_id'] : null, (int) $file['owner_id'], (int) $file['id']];
        }
        $folderId = FileAccess::requireFolderWrite($user, $folderId);
        $owner = FileAccess::contentOwnerFor($user, $folderId);
        if ($owner <= 0) {
            throw ApiException::notFound('folder', 'FOLDER_NOT_FOUND');
        }
        return [$folderId, $owner, null];
    }

    /** New file, or (on_conflict=replace) a new version of the same-named file the user may edit. */
    private static function createOrReplace(array $user, int $ownerId, ?int $folderId, string $name, array $blob, array $opts): array
    {
        $onConflict = (string) ($opts['on_conflict'] ?? 'rename');
        $o = [
            'created_by'  => (int) $user['id'],
            'tags'        => $opts['tags'] ?? [],
            'on_conflict' => $onConflict === 'replace' ? 'rename' : $onConflict,
            'description' => $opts['description'] ?? null,
        ];
        if (($opts['is_permanent'] ?? null) !== null) {
            $o['is_permanent'] = (bool) $opts['is_permanent'];
        }
        if ($onConflict === 'replace') {
            $existing = Db::value(
                'SELECT id FROM files WHERE owner_id = :o AND folder_id <=> :f AND deleted_at IS NULL AND name = :n LIMIT 1',
                ['o' => $ownerId, 'f' => $folderId, 'n' => FileWriter::sanitizeName($name)]
            );
            if ($existing !== null) {
                try {
                    FileAccess::require($user, (int) $existing, 'edit');
                } catch (\Throwable $e) {
                    BlobStore::release((int) $blob['id']);
                    throw $e;
                }
                return FileWriter::addVersion((int) $existing, $blob, (int) $user['id'], '');
            }
        }
        return FileWriter::createFile($ownerId, $folderId, $name, $blob, $o);
    }

    /** Mark a session failed after an exception and return the exception to throw. */
    private static function fail(array $s, \Throwable $e): ApiException
    {
        $api = $e instanceof ApiException ? $e : null;
        if ($api === null) {
            Logger::exception('upload', $e, ['upload_id' => (string) $s['id']]);
        }
        $message = $api !== null ? $api->getMessage() : 'The file could not be saved. Please try again.';
        try {
            Db::update('upload_sessions', ['status' => 'failed', 'error' => mb_substr($message, 0, 255), 'updated_at' => Db::now()], ['id' => (string) $s['id']]);
            self::cleanup($s);
            Stats::bump('failed_uploads');
            $failed = self::get((string) $s['id']);
            self::publish('upload.failed', $failed, ['reason' => $api !== null ? strtolower($api->errorCode) : 'error'], true);
            self::notify((int) $s['user_id'], 'upload.failed', 'Upload failed: “' . $s['name'] . '”', $message, [
                'upload_id' => (string) $s['id'],
                'link' => '#/uploads',
            ], 'upload:' . $s['id']);
            $opts = json_decode((string) ($s['options'] ?? ''), true);
            $isVersion = ($s['target_file_id'] ?? null) !== null;
            Audit::log('upload.failed', [
                'user_id' => (int) $s['user_id'],
                // a failed new version shows on that file's activity timeline
                'target_type' => $isVersion ? 'file' : 'upload',
                'target_id' => $isVersion ? (int) $s['target_file_id'] : null,
                'owner_id' => is_array($opts) && isset($opts['owner_id']) ? (int) $opts['owner_id'] : (int) $s['user_id'],
                'detail' => mb_substr((string) $s['name'], 0, 200),
                'meta' => ['size' => (int) $s['size'], 'reason' => $api !== null ? $api->errorCode : 'SERVER_ERROR'],
            ]);
        } catch (\Throwable $inner) {
            Logger::exception('upload', $inner, ['upload_id' => (string) $s['id'], 'phase' => 'fail']);
        }
        return $api ?? ApiException::server('The file could not be saved. Please try again.');
    }

    private static function expire(array $s): array
    {
        $n = Db::run(
            "UPDATE upload_sessions SET status = 'expired', updated_at = :t WHERE id = :id AND status IN ('active', 'assembling')",
            ['t' => Db::now(), 'id' => (string) $s['id']]
        )->rowCount();
        self::cleanup($s);
        $row = self::get((string) $s['id']);
        if ($n === 1) {
            self::publish('upload.failed', $row, ['reason' => 'expired']);
        }
        return $row;
    }

    /** Remove staged parts and chunk rows (the session row stays as history). */
    private static function cleanup(array $s): void
    {
        try {
            Db::delete('upload_chunks', ['upload_id' => (string) $s['id']]);
            self::rmTree(self::tempDir(self::ownerOf($s), (string) $s['id'], false));
        } catch (\Throwable $e) {
            Logger::warning('upload', 'Upload temp cleanup failed', ['upload_id' => (string) $s['id'], 'error' => $e->getMessage()]);
        }
    }

    /** @return int[] chunk indexes whose part file is missing or has the wrong length */
    private static function missingChunks(array $s): array
    {
        $dir = self::tempDir(self::ownerOf($s), (string) $s['id'], false);
        $have = array_flip(array_map('intval', Db::column('SELECT chunk_index FROM upload_chunks WHERE upload_id = ?', [(string) $s['id']])));
        $missing = [];
        for ($i = 0; $i < (int) $s['total_chunks']; $i++) {
            $p = $dir . '/' . $i . '.part';
            clearstatcache(true, $p);
            if (!isset($have[$i]) || !is_file($p) || (int) @filesize($p) !== self::expectedLength($s, $i)) {
                $missing[] = $i;
            }
        }
        return $missing;
    }

    private static function completedSummary(array $user, array $s): array
    {
        if ($s['result_file_id'] === null) {
            throw ApiException::fileNotFound();
        }
        $file = FileAccess::require($user, (int) $s['result_file_id'], 'view');
        unset($file['access']);
        return FileWriter::summary($file, $user);
    }

    /**
     * Seconds after which an 'assembling' session is considered abandoned (its request died):
     * comfortably longer than any request may run, so a live assembly is never taken over.
     */
    private static function staleAfter(): int
    {
        $limit = (int) ini_get('max_execution_time');
        return $limit > 0 ? max(120, $limit * 2 + 60) : 600;
    }

    private static function expectedLength(array $s, int $index): int
    {
        $chunk = (int) $s['chunk_size'];
        return (int) max(0, min($chunk, (int) $s['size'] - $index * $chunk));
    }

    private static function options(array $s): array
    {
        $o = json_decode((string) ($s['options'] ?? ''), true);
        return is_array($o) ? $o : [];
    }

    /** Whose temp area / quota this session uses (fixed when the session started). */
    private static function ownerOf(array $s): int
    {
        $o = self::options($s);
        $owner = (int) ($o['owner_id'] ?? 0);
        return $owner > 0 ? $owner : (int) $s['user_id'];
    }

    private static function tempDir(int $ownerId, string $id, bool $create = true): string
    {
        if (!preg_match('/^[a-f0-9]{32}$/', $id)) {
            throw new \InvalidArgumentException('Invalid upload id');
        }
        $dir = Paths::userDir($ownerId, 'temp') . '/' . $id;
        if ($create) {
            Paths::ensureDir($dir);
        }
        return $dir;
    }

    private static function percent(array $s): float
    {
        $size = (int) $s['size'];
        if ($s['status'] === 'completed') {
            return 100.0;
        }
        return $size > 0 ? round(min(100, (int) $s['received_bytes'] * 100 / $size), 1) : 0.0;
    }

    private static function maybeProgress(array $s): void
    {
        $opts = self::options($s);
        $now = microtime(true);
        $last = (float) ($opts['progress_at'] ?? 0);
        $complete = (int) $s['received_chunks'] >= (int) $s['total_chunks'];
        if (!$complete && $now - $last < self::PROGRESS_INTERVAL) {
            return;
        }
        $opts['progress_at'] = $now;
        Db::update('upload_sessions', ['options' => json_encode($opts, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)], ['id' => (string) $s['id']]);
        self::publish('upload.progress', $s, []);
    }

    /** upload.* events go to the uploader and, when different, the owner of the content. */
    private static function publish(string $type, array $s, array $extra, bool $admin = false): void
    {
        $owner = self::ownerOf($s);
        $data = [
            'upload_id'      => (string) $s['id'],
            'name'           => (string) $s['name'],
            'size'           => (int) $s['size'],
            'folder_id'      => $s['folder_id'] !== null ? (int) $s['folder_id'] : null,
            'received_bytes' => (int) $s['received_bytes'],
            'percent'        => self::percent($s),
        ] + $extra;
        if ($s['target_file_id'] !== null) {
            $data['target_file_id'] = (int) $s['target_file_id'];
        }
        EventBus::publish($type, $data, array_values(array_unique([(int) $s['user_id'], $owner])), [
            'actor_id'  => (int) $s['user_id'],
            'file_id'   => isset($extra['file_id']) ? (int) $extra['file_id'] : null,
            'folder_id' => $s['folder_id'] !== null ? (int) $s['folder_id'] : null,
            'admin'     => $admin,
        ]);
    }

    private static function notify(int $userId, string $type, string $title, string $body, array $data, string $dedupe): void
    {
        $notifier = 'FT\\Notifications\\Notifier';
        if (!class_exists($notifier) || !method_exists($notifier, 'notify')) {
            return;
        }
        try {
            $notifier::notify($userId, 'upload', $type, mb_substr($title, 0, 200), mb_substr($body, 0, 1000), $data, $dedupe . ':' . $type, null);
        } catch (\Throwable $e) {
            Logger::warning('upload', 'Upload notification failed', ['error' => $e->getMessage()]);
        }
    }

    private static function assertAllowedName(string $name): void
    {
        $ext = MimeDetector::extension($name);
        if (MimeDetector::isBlockedExtension($ext)) {
            throw new ApiException('BLOCKED_FILE_TYPE', 'Files of type .' . $ext . ' cannot be uploaded to this server.', 415, ['extension' => $ext]);
        }
    }

    private static function assertSize(int $size): void
    {
        $max = Settings::int('max_upload_bytes', 209715200);
        if ($max > 0 && $size > $max) {
            throw new ApiException('PAYLOAD_TOO_LARGE', 'This file is larger than the maximum upload size of ' . self::humanBytes($max) . '.', 413, ['max_upload_bytes' => $max]);
        }
    }

    private static function chunkInvalid(string $message, array $details = []): ApiException
    {
        return new ApiException('CHUNK_INVALID', $message, 400, $details);
    }

    private static function withOwnerLock(int $ownerId, callable $fn): void
    {
        $lock = 'ftq_' . $ownerId;
        $got = (int) Db::value('SELECT GET_LOCK(?, 10)', [$lock]) === 1;
        try {
            $fn();
        } finally {
            if ($got) {
                Db::value('SELECT RELEASE_LOCK(?)', [$lock]);
            }
        }
    }

    private static function intOrNull(mixed $v): ?int
    {
        if (is_int($v)) {
            return $v;
        }
        if (is_float($v) && floor($v) === $v && abs($v) < 9.0e15) {
            return (int) $v;
        }
        if (is_string($v) && preg_match('/^-?\d{1,18}$/', trim($v))) {
            return (int) trim($v);
        }
        return null;
    }

    private static function humanBytes(int $bytes): string
    {
        $units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
        $v = (float) $bytes;
        $i = 0;
        while ($v >= 1024 && $i < count($units) - 1) {
            $v /= 1024;
            $i++;
        }
        return ($i === 0 ? (string) $bytes : rtrim(rtrim(number_format($v, 1), '0'), '.')) . ' ' . $units[$i];
    }

    private static function rmTree(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        foreach (scandir($dir) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = $dir . '/' . $f;
            is_dir($p) ? self::rmTree($p) : @unlink($p);
        }
        @rmdir($dir);
    }
}
