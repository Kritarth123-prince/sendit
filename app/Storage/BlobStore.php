<?php
declare(strict_types=1);

namespace FT\Storage;

use FT\Core\ApiException;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Settings;

/**
 * Content-addressed blob storage with deduplication and reference counting (§4, §8.1a, §8.3).
 *
 *  - A blob is identified by (scope, sha256 of the plaintext). Scope is "u<ownerId>" (per-user
 *    dedup, the default) or "global" (setting dedup_scope = global).
 *  - The stored byte stream (gcm1 when Crypto::enabled(), otherwise plain) is split into segment
 *    files of exactly SEGMENT_BYTES (the last may be shorter): <dir>/<sha256>.0, .1, … — hosts
 *    such as byethost delete any file over 10 MB, so no physical file ever exceeds 8 MiB.
 *  - Writers stream the input ONCE (hashing, MIME sniffing and encrypting as they go) into a
 *    temp dir in the owner's temp area, and only move the segments into place after the dedup
 *    check, under a per-(scope, hash) MySQL named lock so two concurrent uploads of the same
 *    content can never overwrite each other's segments.
 *  - ref_count = number of file_versions rows that reference the blob. put*() returns the row
 *    already retained (+1) for the version the caller is about to create. release() only
 *    decrements; sweep() (maintenance) deletes unreferenced blobs after a grace period — the
 *    delay avoids races with a concurrent upload deduplicating into a blob being deleted.
 */
final class BlobStore
{
    /** Fixed on-disk segment size. NEVER change it: every blob ever written must stay readable. */
    public const SEGMENT_BYTES = 8388608;

    private const READ_PIECE = 1048576;
    private const LOCK_WAIT_SECONDS = 15;

    public static function scopeFor(int $ownerId): string
    {
        return strtolower(Settings::string('dedup_scope', 'user')) === 'global' ? 'global' : 'u' . $ownerId;
    }

    // ================================================================== writing

    /**
     * Store a plaintext stream. $size may be given when known (enables single-pass encryption);
     * for regular files it is detected. @return array file_blobs row (retained +1)
     * @param resource $plainStream
     */
    public static function putStream($plainStream, string $scope, ?string $mime = null, ?string $filename = null, ?int $size = null): array
    {
        if (!is_resource($plainStream)) {
            throw new \InvalidArgumentException('putStream() expects a readable stream');
        }
        if ($size === null) {
            $meta = stream_get_meta_data($plainStream);
            if (($meta['wrapper_type'] ?? '') === 'plainfile' && !empty($meta['seekable'])) {
                $stat = fstat($plainStream);
                $pos = ftell($plainStream);
                if ($stat !== false && $pos !== false) {
                    $size = max(0, (int) $stat['size'] - (int) $pos);
                }
            }
        }
        return self::ingest(self::streamSource($plainStream), $size, $scope, $mime, $filename);
    }

    /**
     * Store the concatenation of several plaintext files (upload assembly reads the chunk files
     * in order through this, without ever joining them into one large file).
     * @param string[] $paths
     */
    public static function putParts(array $paths, string $scope, ?string $mime = null, ?string $filename = null): array
    {
        $size = 0;
        foreach ($paths as $p) {
            clearstatcache(true, $p);
            $s = is_file($p) ? @filesize($p) : false;
            if ($s === false) {
                throw new \RuntimeException('An upload part is missing');
            }
            $size += $s;
        }
        $paths = array_values($paths);
        $i = 0;
        $h = null;
        $next = static function () use (&$i, &$h, $paths): string {
            while (true) {
                if ($h === null) {
                    if ($i >= count($paths)) {
                        return '';
                    }
                    $h = @fopen($paths[$i], 'rb');
                    if ($h === false) {
                        $h = null;
                        throw new \RuntimeException('An upload part could not be read');
                    }
                }
                $d = fread($h, self::READ_PIECE);
                if ($d === false) {
                    throw new \RuntimeException('An upload part could not be read');
                }
                if ($d !== '') {
                    return $d;
                }
                if (feof($h)) {
                    fclose($h);
                    $h = null;
                    $i++;
                }
            }
        };
        try {
            return self::ingest($next, $size, $scope, $mime, $filename);
        } finally {
            if (is_resource($h)) {
                fclose($h);
            }
        }
    }

    /** Store a plaintext temp file (the caller still owns and deletes it). */
    public static function putFile(string $tmpPlainPath, string $scope, ?string $mime = null, ?string $filename = null): array
    {
        $h = @fopen($tmpPlainPath, 'rb');
        if ($h === false) {
            throw new \RuntimeException('The file to store could not be opened');
        }
        try {
            return self::ingest(self::streamSource($h), (int) fstat($h)['size'], $scope, $mime, $filename);
        } finally {
            fclose($h);
        }
    }

    public static function putString(string $data, string $scope, ?string $mime = null, ?string $filename = null): array
    {
        $off = 0;
        $len = strlen($data);
        $next = static function () use (&$off, $len, $data): string {
            if ($off >= $len) {
                return '';
            }
            $piece = substr($data, $off, self::READ_PIECE);
            $off += strlen($piece);
            return $piece;
        };
        return self::ingest($next, $len, $scope, $mime, $filename);
    }

    // ================================================================== references

    public static function retain(int $blobId): void
    {
        $n = Db::run('UPDATE file_blobs SET ref_count = ref_count + 1, last_ref_change_at = ? WHERE id = ?', [Db::now(), $blobId])->rowCount();
        if ($n !== 1) {
            throw new \RuntimeException('Blob not found');
        }
    }

    /** Decrement only; physical deletion is deferred to sweep(). */
    public static function release(int $blobId): void
    {
        Db::run('UPDATE file_blobs SET ref_count = ref_count - 1, last_ref_change_at = ? WHERE id = ? AND ref_count > 0', [Db::now(), $blobId]);
    }

    // ================================================================== reading

    public static function get(int $blobId): array
    {
        $row = Db::one('SELECT * FROM file_blobs WHERE id = ?', [$blobId]);
        if ($row === null) {
            throw new \RuntimeException('Blob not found');
        }
        return $row;
    }

    public static function open(array $blobRow): BlobReader
    {
        return BlobReader::open($blobRow);
    }

    /** Whole plaintext as a string; throws PAYLOAD_TOO_LARGE when larger than $maxBytes. */
    public static function readAll(array $blobRow, int $maxBytes): string
    {
        if ((int) $blobRow['size'] > $maxBytes) {
            throw ApiException::tooLarge('The file is too large for this operation.');
        }
        $r = self::open($blobRow);
        try {
            $out = '';
            while (($d = $r->read(self::READ_PIECE)) !== '') {
                $out .= $d;
            }
            return $out;
        } finally {
            $r->close();
        }
    }

    /**
     * Decrypted temporary copy (≤ SEGMENT_BYTES, so it respects the host's file-size cap) for
     * tools that need a real file (OCR upload, image decoding). The CALLER unlinks it.
     */
    public static function toTempFile(array $blobRow, string $suffix = '.tmp'): string
    {
        if ((int) $blobRow['size'] > self::SEGMENT_BYTES) {
            throw new \RuntimeException('File is too large for a temporary copy');
        }
        $suffix = preg_match('/^\.[A-Za-z0-9]{1,10}$/', $suffix) ? $suffix : '.tmp';
        $path = Paths::runtime('tmp') . '/' . bin2hex(random_bytes(12)) . $suffix;
        $r = self::open($blobRow);
        $out = @fopen($path, 'wb');
        if ($out === false) {
            $r->close();
            throw new \RuntimeException('Cannot create a temporary file');
        }
        try {
            while (($d = $r->read(self::READ_PIECE)) !== '') {
                if (fwrite($out, $d) !== strlen($d)) {
                    throw new \RuntimeException('Temporary file write failed');
                }
            }
        } catch (\Throwable $e) {
            fclose($out);
            @unlink($path);
            throw $e;
        } finally {
            $r->close();
        }
        fclose($out);
        return $path;
    }

    /** Every segment exists with exactly the expected size (cheap stat-only check). */
    public static function isIntact(array $blobRow): bool
    {
        try {
            $base = Paths::absolute((string) $blobRow['storage_path']);
        } catch (\Throwable) {
            return false;
        }
        $stored = (int) $blobRow['stored_size'];
        $n = self::segmentCount($stored);
        for ($i = 0; $i < $n; $i++) {
            $expected = $i < $n - 1 ? self::SEGMENT_BYTES : $stored - ($n - 1) * self::SEGMENT_BYTES;
            $p = $base . '.' . $i;
            clearstatcache(true, $p);
            if (!is_file($p) || @filesize($p) !== $expected) {
                return false;
            }
        }
        return true;
    }

    /** Full verification: decrypt everything and compare size + SHA-256 (maintenance). */
    public static function verify(array $blobRow): bool
    {
        try {
            $r = self::open($blobRow);
            $h = hash_init('sha256');
            $n = 0;
            while (($d = $r->read(self::READ_PIECE)) !== '') {
                hash_update($h, $d);
                $n += strlen($d);
            }
            $r->close();
            return $n === (int) $blobRow['size'] && hash_equals((string) $blobRow['sha256'], hash_final($h));
        } catch (\Throwable) {
            return false;
        }
    }

    public static function segmentCount(int $storedSize): int
    {
        return max(1, intdiv($storedSize + self::SEGMENT_BYTES - 1, self::SEGMENT_BYTES));
    }

    // ================================================================== legacy import / migration

    /**
     * A6 importer: copy a legacy AES-256-CBC file byte-for-byte into segments (encryption
     * 'legacy_cbc'), dedup on (scope, plainSha256), retain, return the row. The legacy file is
     * never modified. The copy is verified by decrypting it and comparing size + SHA-256, so a
     * wrong checksum can never make dedup serve someone else's content.
     */
    public static function importLegacyCbc(string $legacyPath, string $scope, string $plainSha256, int $plainSize, ?string $mime): array
    {
        $plainSha256 = strtolower($plainSha256);
        if (!preg_match('/^[a-f0-9]{64}$/', $plainSha256) || $plainSize < 0) {
            throw new \InvalidArgumentException('Invalid checksum or size');
        }
        self::finalDir($scope, $plainSha256); // validates the scope
        $existing = Db::one('SELECT * FROM file_blobs WHERE scope = ? AND sha256 = ?', [$scope, $plainSha256]);
        if ($existing !== null && self::isIntact($existing)) {
            try {
                // Already stored: just retain it (the closure only runs if it vanished meanwhile).
                return self::commit($scope, $plainSha256, $plainSize, $mime ?? (string) $existing['mime'], static fn () => throw new \LogicException('needs data'));
            } catch (\LogicException) {
                // swept or damaged in the meantime: import the copy below
            }
        }
        $in = @fopen($legacyPath, 'rb');
        if ($in === false) {
            throw new \RuntimeException('Legacy file could not be opened');
        }
        $tmp = self::makeTempDir($scope);
        try {
            $w = self::segmentWriter($tmp . '/s');
            while (!feof($in)) {
                $d = fread($in, self::READ_PIECE);
                if ($d === false) {
                    throw new \RuntimeException('Legacy file could not be read');
                }
                self::segmentWrite($w, $d);
            }
            self::segmentClose($w);
            $reader = BlobReader::fromFiles(self::listSegments($tmp . '/s', $w['count']), 'legacy_cbc', null, null, $plainSize);
            $h = hash_init('sha256');
            $head = '';
            while (($d = $reader->read(self::READ_PIECE)) !== '') {
                hash_update($h, $d);
                if (strlen($head) < MimeDetector::SNIFF_BYTES) {
                    $head .= substr($d, 0, MimeDetector::SNIFF_BYTES - strlen($head));
                }
            }
            $reader->close();
            if (!hash_equals($plainSha256, hash_final($h))) {
                throw new \RuntimeException('Legacy file does not match its recorded checksum');
            }
            $meta = ['encryption' => 'legacy_cbc', 'enc_key_id' => null, 'enc_dek' => null, 'stored_size' => $w['total']];
            $count = $w['count'];
            return self::commit($scope, $plainSha256, $plainSize, $mime ?? self::contentMime($head, ''), static fn () => [$tmp . '/s', $count, $meta]);
        } finally {
            fclose($in);
            self::rmTree($tmp);
        }
    }

    /**
     * A6 encryption migration: legacy_cbc|none → gcm1 (when Crypto::enabled()), and gcm1 wrapped
     * with an old key → re-wrapped with the current key. Streams and verifies the plaintext
     * SHA-256 against the row BEFORE swapping; the row update is atomic and the old segments are
     * deleted only afterwards. On any mismatch it throws and leaves the blob untouched.
     */
    public static function reencode(array $blobRow): array
    {
        if (!Crypto::enabled()) {
            throw new \RuntimeException('Encryption is not enabled');
        }
        $id = (int) $blobRow['id'];
        $row = self::get($id);
        $current = (string) Crypto::currentKeyId();

        if ($row['encryption'] === 'gcm1') {
            if ((string) $row['enc_key_id'] === $current) {
                return $row;
            }
            $dek = Crypto::unwrapDek((string) $row['enc_key_id'], (string) $row['enc_dek']);
            $wrap = Crypto::wrapDek($dek);
            $n = Db::run(
                'UPDATE file_blobs SET enc_key_id = :k, enc_dek = :d WHERE id = :id AND enc_key_id = :ok AND enc_dek = :od',
                ['k' => $wrap['enc_key_id'], 'd' => $wrap['enc_dek'], 'id' => $id, 'ok' => (string) $row['enc_key_id'], 'od' => (string) $row['enc_dek']]
            )->rowCount();
            if ($n !== 1) {
                throw new \RuntimeException('Blob changed during re-encryption');
            }
            return self::get($id);
        }
        if (!in_array($row['encryption'], ['none', 'legacy_cbc'], true)) {
            throw new \RuntimeException('Unknown storage encoding');
        }

        $tmp = self::makeTempDir((string) $row['scope']);
        try {
            $reader = self::open($row);
            $w = self::segmentWriter($tmp . '/e');
            $enc = Crypto::beginEncrypt($reader->size(), static function (string $b) use (&$w): void {
                self::segmentWrite($w, $b);
            });
            $h = hash_init('sha256');
            while (($d = $reader->read(self::READ_PIECE)) !== '') {
                hash_update($h, $d);
                Crypto::feedEncrypt($enc, $d);
            }
            $size = $reader->size();
            $reader->close();
            $meta = Crypto::finishEncrypt($enc);
            self::segmentClose($w);
            if ($size !== (int) $row['size'] || !hash_equals((string) $row['sha256'], hash_final($h))) {
                throw new \RuntimeException('Content verification failed; the blob was left unchanged');
            }
            $newBase = self::finalDir((string) $row['scope'], (string) $row['sha256']) . '/' . $row['sha256'] . '-' . bin2hex(random_bytes(4));
            $oldBase = Paths::absolute((string) $row['storage_path']);
            $oldCount = self::segmentCount((int) $row['stored_size']);
            $count = $w['count'];
            self::withLock(self::lockName((string) $row['scope'], (string) $row['sha256']), static function () use ($tmp, $count, $newBase, $id, $row, $meta): void {
                self::moveSegments($tmp . '/e', $count, $newBase);
                try {
                    Db::transaction(static function () use ($id, $row, $meta, $newBase): void {
                        $cur = Db::one('SELECT * FROM file_blobs WHERE id = ? FOR UPDATE', [$id]);
                        if ($cur === null || $cur['storage_path'] !== $row['storage_path'] || $cur['encryption'] !== $row['encryption']) {
                            throw new \RuntimeException('Blob changed during re-encryption');
                        }
                        Db::update('file_blobs', [
                            'storage_path' => Paths::relative($newBase),
                            'stored_size'  => $meta['stored_size'],
                            'encryption'   => 'gcm1',
                            'enc_key_id'   => $meta['enc_key_id'],
                            'enc_dek'      => $meta['enc_dek'],
                        ], ['id' => $id]);
                    });
                } catch (\Throwable $e) {
                    self::deleteSegments($newBase, $count);
                    throw $e;
                }
            });
            self::deleteSegments($oldBase, $oldCount);
            return self::get($id);
        } finally {
            self::rmTree($tmp);
        }
    }

    /**
     * Maintenance: delete physical segments + rows of blobs with ref_count = 0 untouched for
     * $minAgeSeconds. Each candidate is re-checked inside a transaction with SELECT … FOR UPDATE
     * (row + referencing versions/files) while holding the blob's named lock, so a blob that
     * any file_versions row references is never deleted — a drifted ref_count is repaired instead.
     */
    public static function sweep(int $minAgeSeconds = 3600, int $limit = 200): int
    {
        $cutoff = Db::ts(time() - max(0, $minAgeSeconds));
        $deadline = microtime(true) + 10.0;
        $ids = Db::column(
            'SELECT id FROM file_blobs WHERE ref_count = 0 AND last_ref_change_at < ? ORDER BY id LIMIT ?',
            [$cutoff, max(1, min(1000, $limit))]
        );
        $deleted = 0;
        foreach ($ids as $id) {
            if (microtime(true) > $deadline) {
                break;
            }
            $id = (int) $id;
            $key = Db::one('SELECT scope, sha256 FROM file_blobs WHERE id = ?', [$id]);
            if ($key === null) {
                continue;
            }
            $lock = self::lockName((string) $key['scope'], (string) $key['sha256']);
            if ((int) Db::value('SELECT GET_LOCK(?, 0)', [$lock]) !== 1) {
                continue; // a writer is deduplicating into this blob right now
            }
            try {
                $done = Db::transaction(static function () use ($id, $cutoff): bool {
                    $row = Db::one('SELECT * FROM file_blobs WHERE id = ? FOR UPDATE', [$id]);
                    if ($row === null || (int) $row['ref_count'] !== 0 || (string) $row['last_ref_change_at'] >= $cutoff) {
                        return false;
                    }
                    $versions = (int) Db::value('SELECT COUNT(*) FROM file_versions WHERE blob_id = ? FOR UPDATE', [$id]);
                    $files = (int) Db::value('SELECT COUNT(*) FROM files WHERE blob_id = ? FOR UPDATE', [$id]);
                    if ($versions > 0 || $files > 0) {
                        Db::update('file_blobs', ['ref_count' => $versions, 'last_ref_change_at' => Db::now()], ['id' => $id]);
                        Logger::warning('maintenance', 'Blob ref_count drifted; repaired instead of deleting', ['blob_id' => $id, 'versions' => $versions]);
                        return false;
                    }
                    self::deleteSegments(Paths::absolute((string) $row['storage_path']), self::segmentCount((int) $row['stored_size']));
                    Db::delete('file_blobs', ['id' => $id]);
                    return true;
                });
            } catch (\Throwable $e) {
                Logger::exception('maintenance', $e, ['blob_id' => $id]);
                $done = false;
            } finally {
                Db::value('SELECT RELEASE_LOCK(?)', [$lock]);
            }
            if ($done) {
                $deleted++;
            }
        }
        return $deleted;
    }

    // ================================================================== segment files

    /** @return array<string,mixed> writer state for segmentWrite()/segmentClose() */
    public static function segmentWriter(string $basePath): array
    {
        return ['base' => $basePath, 'index' => 0, 'fh' => null, 'in' => 0, 'total' => 0, 'count' => 0];
    }

    /** Append bytes, rolling over to the next segment file every SEGMENT_BYTES. */
    public static function segmentWrite(array &$w, string $bytes): void
    {
        $len = strlen($bytes);
        $off = 0;
        while ($off < $len) {
            if ($w['fh'] === null) {
                $fh = @fopen($w['base'] . '.' . $w['index'], 'wb');
                if ($fh === false) {
                    throw new \RuntimeException('Storage is not writable');
                }
                $w['fh'] = $fh;
                $w['in'] = 0;
                $w['count'] = $w['index'] + 1;
            }
            $n = min(self::SEGMENT_BYTES - $w['in'], $len - $off);
            $piece = ($off === 0 && $n === $len) ? $bytes : substr($bytes, $off, $n);
            if (fwrite($w['fh'], $piece) !== $n) {
                throw new \RuntimeException('Storage write failed (disk full?)');
            }
            $off += $n;
            $w['in'] += $n;
            $w['total'] += $n;
            if ($w['in'] >= self::SEGMENT_BYTES) {
                fclose($w['fh']);
                $w['fh'] = null;
                $w['index']++;
            }
        }
    }

    /** Finish writing; always leaves at least one (possibly empty) segment. @return int total bytes */
    public static function segmentClose(array &$w): int
    {
        if ($w['fh'] !== null) {
            if (!fflush($w['fh'])) {
                fclose($w['fh']);
                $w['fh'] = null;
                throw new \RuntimeException('Storage write failed');
            }
            fclose($w['fh']);
            $w['fh'] = null;
        }
        if ($w['count'] === 0) {
            if (@file_put_contents($w['base'] . '.0', '') === false) {
                throw new \RuntimeException('Storage is not writable');
            }
            $w['count'] = 1;
        }
        return $w['total'];
    }

    public static function segmentAbort(array &$w): void
    {
        if ($w['fh'] !== null) {
            fclose($w['fh']);
            $w['fh'] = null;
        }
        self::deleteSegments($w['base'], max(1, $w['count']));
    }

    // ================================================================== internals

    /** @param resource $h */
    private static function streamSource($h): callable
    {
        return static function () use ($h): string {
            for ($spins = 0; $spins < 1000; $spins++) {
                if (feof($h)) {
                    return '';
                }
                $d = fread($h, self::READ_PIECE);
                if ($d === false) {
                    throw new \RuntimeException('Read error while storing a file');
                }
                if ($d !== '') {
                    return $d;
                }
            }
            throw new \RuntimeException('The input stream stalled');
        };
    }

    /**
     * Single pass over the source: SHA-256, MIME sniff of the first bytes, byte count and
     * (when possible) gcm1 encryption straight into temp segments. When the size is unknown and
     * encryption is on, the plaintext is spooled first (gcm1 needs the size in its header).
     */
    private static function ingest(callable $next, ?int $size, string $scope, ?string $mime, ?string $filename): array
    {
        if ($size !== null && $size < 0) {
            throw new \InvalidArgumentException('Invalid size');
        }
        self::assertScope($scope);
        $tmp = self::makeTempDir($scope);
        try {
            $encrypt = Crypto::enabled();
            $spool = $encrypt && $size === null;
            $w = self::segmentWriter($tmp . '/s');
            $enc = null;
            if ($encrypt && !$spool) {
                $enc = Crypto::beginEncrypt((int) $size, static function (string $b) use (&$w): void {
                    self::segmentWrite($w, $b);
                });
            }
            $hash = hash_init('sha256');
            $head = '';
            $count = 0;
            while (($piece = $next()) !== '') {
                $count += strlen($piece);
                if ($size !== null && $count > $size) {
                    throw new \RuntimeException('The data is longer than declared');
                }
                hash_update($hash, $piece);
                if (strlen($head) < MimeDetector::SNIFF_BYTES) {
                    $head .= substr($piece, 0, MimeDetector::SNIFF_BYTES - strlen($head));
                }
                if ($enc !== null) {
                    Crypto::feedEncrypt($enc, $piece);
                } else {
                    self::segmentWrite($w, $piece);
                }
            }
            if ($size !== null && $count !== $size) {
                throw new \RuntimeException('The data is shorter than declared');
            }
            $meta = $enc !== null ? Crypto::finishEncrypt($enc) : null;
            self::segmentClose($w);
            $meta ??= ['encryption' => 'none', 'enc_key_id' => null, 'enc_dek' => null, 'stored_size' => $w['total']];
            $sha = hash_final($hash);
            $mime ??= self::contentMime($head, (string) $filename);
            $segCount = $w['count'];

            $materialise = static function () use ($spool, $tmp, $segCount, $meta, $count): array {
                if (!$spool) {
                    return [$tmp . '/s', $segCount, $meta];
                }
                // Encrypt the spooled plaintext now that its size is known.
                $reader = BlobReader::fromFiles(self::listSegments($tmp . '/s', $segCount), 'none', null, null, $count);
                $w2 = self::segmentWriter($tmp . '/e');
                $enc2 = Crypto::beginEncrypt($count, static function (string $b) use (&$w2): void {
                    self::segmentWrite($w2, $b);
                });
                while (($d = $reader->read(self::READ_PIECE)) !== '') {
                    Crypto::feedEncrypt($enc2, $d);
                }
                $reader->close();
                $m = Crypto::finishEncrypt($enc2);
                self::segmentClose($w2);
                return [$tmp . '/e', $w2['count'], $m];
            };
            return self::commit($scope, $sha, $count, $mime, $materialise);
        } finally {
            self::rmTree($tmp);
        }
    }

    /**
     * Dedup + placement. If (scope, sha) exists and is intact: retain it and discard ours. If it
     * exists but its segments are gone/damaged (e.g. deleted by the host): heal it with our copy.
     * Otherwise move our segments into place and insert the row with ref_count = 1.
     * @param callable():array{0:string,1:int,2:array} $materialise temp base, segment count, encoding meta
     */
    private static function commit(string $scope, string $sha, int $size, string $mime, callable $materialise): array
    {
        $existing = Db::one('SELECT * FROM file_blobs WHERE scope = ? AND sha256 = ?', [$scope, $sha]);
        $prepared = ($existing === null || !self::isIntact($existing)) ? $materialise() : null;
        $mime = mb_substr($mime !== '' ? $mime : 'application/octet-stream', 0, 127);

        return self::withLock(self::lockName($scope, $sha), static function () use ($scope, $sha, $size, $mime, $materialise, &$prepared): array {
            $row = Db::one('SELECT * FROM file_blobs WHERE scope = ? AND sha256 = ?', [$scope, $sha]);
            if ($row !== null && self::isIntact($row)) {
                self::retain((int) $row['id']);
                return self::get((int) $row['id']);
            }
            $prepared ??= $materialise();
            [$tmpBase, $count, $meta] = $prepared;
            $dir = self::finalDir($scope, $sha);

            if ($row !== null) {
                // Heal: same plaintext (same hash), so replacing the stored copy is safe for
                // every file that references it.
                $newBase = $dir . '/' . $sha . '-' . bin2hex(random_bytes(4));
                self::moveSegments($tmpBase, $count, $newBase);
                Db::update('file_blobs', [
                    'storage_path' => Paths::relative($newBase),
                    'stored_size'  => $meta['stored_size'],
                    'encryption'   => $meta['encryption'],
                    'enc_key_id'   => $meta['enc_key_id'],
                    'enc_dek'      => $meta['enc_dek'],
                ], ['id' => (int) $row['id']]);
                self::retain((int) $row['id']);
                try {
                    self::deleteSegments(Paths::absolute((string) $row['storage_path']), self::segmentCount((int) $row['stored_size']));
                } catch (\Throwable) {
                    // best effort: the old copy was damaged anyway
                }
                Logger::warning('upload', 'Damaged blob replaced by an identical re-upload', ['blob_id' => (int) $row['id']]);
                return self::get((int) $row['id']);
            }

            $base = $dir . '/' . $sha;
            self::moveSegments($tmpBase, $count, $base);
            try {
                $now = Db::now();
                $id = Db::insert('file_blobs', [
                    'scope'              => $scope,
                    'sha256'             => $sha,
                    'size'               => $size,
                    'stored_size'        => $meta['stored_size'],
                    'storage_path'       => Paths::relative($base),
                    'mime'               => $mime,
                    'encryption'         => $meta['encryption'],
                    'enc_key_id'         => $meta['enc_key_id'],
                    'enc_dek'            => $meta['enc_dek'],
                    'ref_count'          => 1,
                    'created_at'         => $now,
                    'last_ref_change_at' => $now,
                ]);
            } catch (\Throwable $e) {
                self::deleteSegments($base, $count);
                throw $e;
            }
            return self::get($id);
        });
    }

    /** Content-truth MIME: finfo on the first bytes; the extension only when content is ambiguous. */
    private static function contentMime(string $head, string $filename): string
    {
        $sniffed = MimeDetector::sniff($head);
        if (in_array($sniffed, ['', 'application/octet-stream', 'application/x-empty', 'inode/x-empty'], true)) {
            return MimeDetector::resolve($sniffed, MimeDetector::extension($filename));
        }
        return $sniffed;
    }

    private static function withLock(string $name, callable $fn): mixed
    {
        if ((int) Db::value('SELECT GET_LOCK(?, ?)', [$name, self::LOCK_WAIT_SECONDS]) !== 1) {
            throw new \RuntimeException('Storage is busy, please try again');
        }
        try {
            return $fn();
        } finally {
            Db::value('SELECT RELEASE_LOCK(?)', [$name]);
        }
    }

    private static function lockName(string $scope, string $sha): string
    {
        return 'ftb_' . substr(hash('sha256', $scope . '|' . $sha), 0, 40);
    }

    private static function assertScope(string $scope): void
    {
        if (!preg_match('/^(u[1-9][0-9]{0,9}|global)$/', $scope)) {
            throw new \InvalidArgumentException('Invalid blob scope');
        }
    }

    /** Final directory: users/<id>/files/<aa> (scope u<id>) or shared/blobs/<aa> (global). */
    private static function finalDir(string $scope, string $sha): string
    {
        self::assertScope($scope);
        $aa = substr($sha, 0, 2);
        $dir = ($scope === 'global' ? Paths::sharedBlobs() : Paths::userDir((int) substr($scope, 1), 'files')) . '/' . $aa;
        Paths::ensureDir($dir);
        return $dir;
    }

    private static function makeTempDir(string $scope): string
    {
        self::assertScope($scope);
        $parent = $scope === 'global' ? Paths::runtime('tmp') : Paths::userDir((int) substr($scope, 1), 'temp');
        $dir = $parent . '/blob-' . bin2hex(random_bytes(8));
        Paths::ensureDir($dir);
        return $dir;
    }

    /** @return string[] */
    private static function listSegments(string $base, int $count): array
    {
        $out = [];
        for ($i = 0; $i < $count; $i++) {
            $out[] = $base . '.' . $i;
        }
        return $out;
    }

    private static function moveSegments(string $srcBase, int $count, string $dstBase): void
    {
        for ($i = 0; $i < $count; $i++) {
            if (!@rename($srcBase . '.' . $i, $dstBase . '.' . $i)) {
                self::deleteSegments($dstBase, $i);
                throw new \RuntimeException('Could not move stored data into place');
            }
        }
        // Remove stale higher-numbered segments left by an older orphan with the same name.
        for ($i = $count; $i < $count + 64 && is_file($dstBase . '.' . $i); $i++) {
            @unlink($dstBase . '.' . $i);
        }
    }

    private static function deleteSegments(string $base, int $count): void
    {
        for ($i = 0; $i < $count; $i++) {
            if (is_file($base . '.' . $i)) {
                @unlink($base . '.' . $i);
            }
        }
        for ($i = $count; $i < $count + 64 && is_file($base . '.' . $i); $i++) {
            @unlink($base . '.' . $i);
        }
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
