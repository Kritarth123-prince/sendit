<?php
declare(strict_types=1);

namespace FT\Files;

use FT\Core\Db;
use FT\Core\Logger;
use FT\Http\Response;
use FT\Storage\BlobStore;
use FT\Support\Capabilities;

/**
 * Streaming ZIP writer — the archive is produced on the fly and NEVER written to a temp file
 * (hosts such as byethost delete any file over 10 MB).
 *
 * Format: STORE (no compression — files are usually already compressed and this keeps CPU low),
 * general-purpose bit 3 (CRC and sizes follow the data in a data descriptor, so nothing has to
 * be known or buffered in advance) and bit 11 (UTF-8 names). CRC-32 is computed incrementally
 * with hash_init('crc32b') while the decrypted bytes stream through. ZIP64 records are written
 * per entry when a size or offset reaches 4 GiB, and for the end record when there are more
 * than 65,535 entries.
 *
 * Entries: [['file' => filesRow, 'path' => 'dir/name.ext'], ['dir' => true, 'path' => 'dir/'], …].
 * A4 uses stream() for link-share bundles and folders; folderEntries() builds the list for a
 * folder subtree.
 *
 * Failure handling: each blob is opened (and its segments verified) before its local header is
 * written, so a missing blob is simply skipped. If a blob turns out damaged mid-stream, the entry
 * is closed with the bytes actually written (the archive stays structurally valid) and the file
 * is listed in a "files that could not be added" note at the end of the archive.
 */
final class ZipService
{
    public const MAX_ENTRIES = 2000;

    private const READ_BYTES = 1048576;
    private const U32 = 0xFFFFFFFF;
    private const NOTE_NAME = 'FastTransfer - files that could not be added.txt';
    /** Exception code used to unwind when the client disconnects mid-stream. */
    private const ABORTED = 499;

    /**
     * Send a ZIP download of $entries to the client. Prefetches the blob rows, then releases
     * the session lock and the database connection before streaming.
     */
    public static function stream(array $entries, string $zipName): void
    {
        $entries = self::prefetchBlobs($entries);
        if (class_exists(\FT\Auth\Auth::class) && method_exists(\FT\Auth\Auth::class, 'closeSession')) {
            \FT\Auth\Auth::closeSession();
        }
        Db::disconnect();
        Capabilities::setTimeLimit(0);
        if (PHP_SAPI !== 'cli') {
            @ini_set('zlib.output_compression', '0');
            while (ob_get_level() > 0) {
                @ob_end_clean();
            }
        }
        $name = self::zipFileName($zipName);
        if (!headers_sent()) {
            http_response_code(200);
            header('Content-Type: application/zip');
            header('Content-Disposition: ' . Response::contentDisposition($name, false));
            header('X-Content-Type-Options: nosniff');
            header('Cache-Control: no-store, no-transform');
            header('X-Accel-Buffering: no');
            header('Content-Security-Policy: default-src \'none\'; sandbox');
        }
        if (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'HEAD') {
            return;
        }
        $pending = 0;
        try {
            self::write($entries, static function (string $bytes) use (&$pending): void {
                echo $bytes;
                $pending += strlen($bytes);
                if ($pending >= 262144) {
                    $pending = 0;
                    flush();
                    if (PHP_SAPI !== 'cli' && connection_aborted()) {
                        throw new \RuntimeException('client disconnected', self::ABORTED);
                    }
                }
            });
            flush();
        } catch (\RuntimeException $e) {
            if ($e->getCode() !== self::ABORTED) {
                throw $e;
            }
            // the client went away: nothing more to do
        }
    }

    /**
     * Write the archive through $sink (callable(string): void). Returns statistics.
     * $maxEntries bounds the archive (the HTTP endpoints enforce MAX_ENTRIES before streaming).
     * @return array{entries:int,files:int,bytes:int,skipped:string[]}
     */
    public static function write(array $entries, callable $sink, int $maxEntries = self::MAX_ENTRIES): array
    {
        $offset = 0;
        $central = [];
        $used = [];
        $skipped = [];
        $files = 0;
        $out = static function (string $b) use ($sink, &$offset): void {
            if ($b !== '') {
                $sink($b);
                $offset += strlen($b);
            }
        };

        foreach (array_slice(array_values($entries), 0, max(1, $maxEntries)) as $e) {
            $isDir = !empty($e['dir']);
            $path = self::cleanPath((string) ($e['path'] ?? ''), $isDir);
            if ($path === '') {
                continue;
            }
            $path = self::uniquePath($path, $used, $isDir);
            $mtime = isset($e['file']['updated_at']) ? (Db::toUnix((string) $e['file']['updated_at']) ?? time()) : time();
            [$dosTime, $dosDate] = self::dosTime($mtime);
            $localOffset = $offset;

            if ($isDir) {
                $hdr = pack('VvvvvvVVVvv', 0x04034b50, 20, 0x0800, 0, $dosTime, $dosDate, 0, 0, 0, strlen($path), 0) . $path;
                $out($hdr);
                $central[] = ['path' => $path, 'crc' => 0, 'size' => 0, 'offset' => $localOffset, 'time' => $dosTime, 'date' => $dosDate, 'flags' => 0x0800, 'dir' => true, 'zip64' => false];
                continue;
            }

            $file = $e['file'] ?? null;
            if (!is_array($file)) {
                continue;
            }
            try {
                $blob = $e['blob'] ?? BlobStore::get((int) $file['blob_id']);
                $reader = BlobStore::open($blob);
            } catch (\Throwable $ex) {
                $skipped[] = $path;
                Logger::warning('app', 'ZIP entry skipped: stored file unavailable', ['file_id' => (int) ($file['id'] ?? 0), 'error' => $ex->getMessage()]);
                continue;
            }
            $size = $reader->size();
            $zip64 = $size >= self::U32 || $localOffset >= self::U32;
            $flags = 0x0808;
            if ($zip64) {
                $extra = pack('vv', 0x0001, 16) . pack('P', 0) . pack('P', 0);
                $hdr = pack('VvvvvvVVVvv', 0x04034b50, 45, $flags, 0, $dosTime, $dosDate, 0, self::U32, self::U32, strlen($path), strlen($extra)) . $path . $extra;
            } else {
                $hdr = pack('VvvvvvVVVvv', 0x04034b50, 20, $flags, 0, $dosTime, $dosDate, 0, 0, 0, strlen($path), 0) . $path;
            }
            $out($hdr);

            $ctx = hash_init('crc32b');
            $written = 0;
            $damaged = false;
            try {
                while (!$reader->eof()) {
                    $chunk = $reader->read(self::READ_BYTES);
                    if ($chunk === '') {
                        break;
                    }
                    hash_update($ctx, $chunk);
                    $written += strlen($chunk);
                    $out($chunk);
                }
            } catch (\Throwable $ex) {
                if ($ex->getCode() === self::ABORTED) {
                    $reader->close();
                    throw $ex;
                }
                $damaged = true;
                Logger::warning('app', 'ZIP entry truncated: stored file damaged', ['file_id' => (int) ($file['id'] ?? 0), 'error' => $ex->getMessage()]);
            }
            $reader->close();
            if ($damaged || $written !== $size) {
                $skipped[] = $path;
            }
            $crc = (int) unpack('N', hash_final($ctx, true))[1];
            $desc = $zip64
                ? pack('VV', 0x08074b50, $crc) . pack('P', $written) . pack('P', $written)
                : pack('VVVV', 0x08074b50, $crc, $written, $written);
            $out($desc);
            $files++;
            $central[] = ['path' => $path, 'crc' => $crc, 'size' => $written, 'offset' => $localOffset, 'time' => $dosTime, 'date' => $dosDate, 'flags' => $flags, 'dir' => false, 'zip64' => $zip64];
        }

        if ($skipped !== []) {
            $note = "These files could not be added to the archive because their stored data is missing or damaged:\r\n\r\n"
                . implode("\r\n", $skipped) . "\r\n";
            $path = self::uniquePath(self::NOTE_NAME, $used, false);
            [$dosTime, $dosDate] = self::dosTime(time());
            $crc = (int) unpack('N', hash('crc32b', $note, true))[1];
            $len = strlen($note);
            $localOffset = $offset;
            $out(pack('VvvvvvVVVvv', 0x04034b50, 20, 0x0800, 0, $dosTime, $dosDate, $crc, $len, $len, strlen($path), 0) . $path . $note);
            $central[] = ['path' => $path, 'crc' => $crc, 'size' => $len, 'offset' => $localOffset, 'time' => $dosTime, 'date' => $dosDate, 'flags' => 0x0800, 'dir' => false, 'zip64' => false];
        }

        // central directory
        $cdOffset = $offset;
        foreach ($central as $c) {
            $big = $c['zip64'];
            $bigOffset = $c['offset'] >= self::U32;
            $extraData = '';
            if ($big) {
                $extraData .= pack('P', $c['size']) . pack('P', $c['size']);
            }
            if ($bigOffset) {
                $extraData .= pack('P', $c['offset']);
            }
            $extra = $extraData !== '' ? pack('vv', 0x0001, strlen($extraData)) . $extraData : '';
            $needed = ($big || $bigOffset) ? 45 : 20;
            $out(pack(
                'VvvvvvvVVVvvvvvVV',
                0x02014b50,
                45,                                   // version made by: MS-DOS host, spec 4.5
                $needed,
                $c['flags'],
                0,                                    // STORE
                $c['time'],
                $c['date'],
                $c['crc'],
                $big ? self::U32 : $c['size'],
                $big ? self::U32 : $c['size'],
                strlen($c['path']),
                strlen($extra),
                0,                                    // comment length
                0,                                    // disk number start
                0,                                    // internal attributes
                $c['dir'] ? 0x10 : 0x20,              // external: directory / archive
                $bigOffset ? self::U32 : $c['offset']
            ) . $c['path'] . $extra);
        }
        $cdSize = $offset - $cdOffset;
        $count = count($central);
        if ($count > 0xFFFF || $cdOffset >= self::U32 || $cdSize >= self::U32) {
            $z64Offset = $offset;
            $out(pack('VPvvVV', 0x06064b50, 44, 45, 45, 0, 0) . pack('PPPP', $count, $count, $cdSize, $cdOffset));
            $out(pack('VVPV', 0x07064b50, 0, $z64Offset, 1));
            $out(pack('VvvvvVVv', 0x06054b50, 0, 0, min($count, 0xFFFF), min($count, 0xFFFF), min($cdSize, self::U32), min($cdOffset, self::U32), 0));
        } else {
            $out(pack('VvvvvVVv', 0x06054b50, 0, 0, $count, $count, $cdSize, $cdOffset, 0));
        }
        return ['entries' => $count, 'files' => $files, 'bytes' => $offset, 'skipped' => $skipped];
    }

    /**
     * Entries for a folder subtree: every live subfolder (as a directory entry, so empty
     * folders survive) and every live file, with paths relative to $prefix (default: the folder
     * name). $filter (callable(array $fileRow): bool) can exclude files (e.g. no download right).
     * @return array<int,array<string,mixed>>
     */
    public static function folderEntries(array $folder, ?callable $filter = null, ?string $prefix = null, int $max = self::MAX_ENTRIES): array
    {
        $owner = (int) $folder['owner_id'];
        $rootId = (int) $folder['id'];
        $prefix = self::cleanPath($prefix ?? (string) $folder['name'], true);
        $paths = [$rootId => $prefix];
        $entries = [['dir' => true, 'path' => $prefix]];
        $frontier = [$rootId];
        $fileRows = [];
        while ($frontier !== [] && count($entries) < $max) {
            $next = [];
            foreach (array_chunk($frontier, 500) as $chunk) {
                [$in, $p] = Db::inList($chunk, 'zf');
                $p['o'] = $owner;
                foreach (Db::all("SELECT f.*, b.encryption AS blob_encryption FROM files f LEFT JOIN file_blobs b ON b.id = f.blob_id WHERE f.owner_id = :o AND f.folder_id IN {$in} AND f.deleted_at IS NULL ORDER BY f.name", $p) as $f) {
                    $fileRows[] = $f;
                }
                foreach (Db::all("SELECT id, parent_id, name FROM folders WHERE owner_id = :o AND parent_id IN {$in} AND deleted_at IS NULL ORDER BY name", $p) as $sub) {
                    $sid = (int) $sub['id'];
                    if (isset($paths[$sid])) {
                        continue;
                    }
                    $paths[$sid] = $paths[(int) $sub['parent_id']] . self::cleanSegment((string) $sub['name']) . '/';
                    $entries[] = ['dir' => true, 'path' => $paths[$sid]];
                    $next[] = $sid;
                }
            }
            $frontier = $next;
        }
        if ($filter !== null) {
            $fileRows = array_values(array_filter($fileRows, $filter));
        }
        foreach ($fileRows as $f) {
            $entries[] = ['file' => $f, 'path' => ($paths[(int) $f['folder_id']] ?? $prefix) . self::cleanSegment((string) $f['name'])];
        }
        return $entries;
    }

    /** Number of file entries and their total size. @return array{files:int,bytes:int,entries:int} */
    public static function measure(array $entries): array
    {
        $files = 0;
        $bytes = 0;
        foreach ($entries as $e) {
            if (empty($e['dir']) && isset($e['file'])) {
                $files++;
                $bytes += (int) $e['file']['size'];
            }
        }
        return ['files' => $files, 'bytes' => $bytes, 'entries' => count($entries)];
    }

    /** "name.zip" from a user-supplied archive name. */
    public static function zipFileName(string $name): string
    {
        $name = FileRepository::sanitizeName($name !== '' ? $name : 'FastTransfer');
        if (!str_ends_with(strtolower($name), '.zip')) {
            $name .= '.zip';
        }
        return $name;
    }

    // ------------------------------------------------------------------ internals

    /** Load all blob rows in one query so the stream needs no database connection. */
    private static function prefetchBlobs(array $entries): array
    {
        $ids = [];
        foreach ($entries as $e) {
            if (isset($e['file']['blob_id']) && !isset($e['blob'])) {
                $ids[] = (int) $e['file']['blob_id'];
            }
        }
        $blobs = [];
        foreach (array_chunk(array_values(array_unique($ids)), 500) as $chunk) {
            [$in, $p] = Db::inList($chunk, 'zb');
            foreach (Db::all("SELECT * FROM file_blobs WHERE id IN {$in}", $p) as $b) {
                $blobs[(int) $b['id']] = $b;
            }
        }
        foreach ($entries as $i => $e) {
            if (isset($e['file']['blob_id']) && !isset($e['blob']) && isset($blobs[(int) $e['file']['blob_id']])) {
                $entries[$i]['blob'] = $blobs[(int) $e['file']['blob_id']];
            }
        }
        return $entries;
    }

    /** Relative, traversal-free path with clean segments ("a/b/c.txt", or "a/b/" for dirs). */
    private static function cleanPath(string $path, bool $isDir): string
    {
        $segments = [];
        foreach (preg_split('~[/\\\\]+~', $path) ?: [] as $raw) {
            $raw = trim($raw);
            if ($raw === '' || $raw === '.' || $raw === '..') {
                continue; // an entry may never climb out of the extraction directory
            }
            $seg = self::cleanSegment($raw);
            if ($seg !== '') {
                $segments[] = $seg;
            }
        }
        if ($segments === []) {
            return '';
        }
        return implode('/', $segments) . ($isDir ? '/' : '');
    }

    private static function cleanSegment(string $seg): string
    {
        if (!mb_check_encoding($seg, 'UTF-8')) {
            $seg = mb_convert_encoding($seg, 'UTF-8', 'UTF-8');
        }
        $seg = (string) preg_replace('/[\x00-\x1F\x7F]/u', '', $seg);
        $seg = str_replace(['/', '\\', ':', '*', '?', '"', '<', '>', '|'], '_', $seg);
        $seg = trim($seg, " \t");
        if ($seg === '.' || $seg === '..') {
            return '_';
        }
        return mb_strcut($seg, 0, 255, 'UTF-8');
    }

    /** Make an entry path unique within the archive ("a (1).txt"). */
    private static function uniquePath(string $path, array &$used, bool $isDir): string
    {
        $key = mb_strtolower($path);
        if (!isset($used[$key])) {
            $used[$key] = true;
            return $path;
        }
        $trim = $isDir ? rtrim($path, '/') : $path;
        $slash = strrpos($trim, '/');
        $dir = $slash === false ? '' : substr($trim, 0, $slash + 1);
        $base = $slash === false ? $trim : substr($trim, $slash + 1);
        $ext = '';
        if (!$isDir && ($dot = strrpos($base, '.')) !== false && $dot > 0) {
            $ext = substr($base, $dot);
            $base = substr($base, 0, $dot);
        }
        for ($i = 1; $i < 100000; $i++) {
            $candidate = $dir . $base . " ({$i})" . $ext . ($isDir ? '/' : '');
            $k = mb_strtolower($candidate);
            if (!isset($used[$k])) {
                $used[$k] = true;
                return $candidate;
            }
        }
        return $path;
    }

    /** @return array{0:int,1:int} [DOS time, DOS date] (UTC) */
    private static function dosTime(int $ts): array
    {
        $d = getdate($ts);
        if ($d['year'] < 1980) {
            return [0, (0 << 9) | (1 << 5) | 1];
        }
        $time = ($d['hours'] << 11) | ($d['minutes'] << 5) | intdiv($d['seconds'], 2);
        $date = (($d['year'] - 1980) << 9) | ($d['mon'] << 5) | $d['mday'];
        return [$time, $date];
    }
}
