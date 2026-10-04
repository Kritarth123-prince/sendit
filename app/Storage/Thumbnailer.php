<?php
declare(strict_types=1);

namespace FT\Storage;

use FT\Core\ApiException;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Events\EventBus;
use FT\Files\FileWriter;
use FT\Http\Request;
use FT\Support\Capabilities;

/**
 * Image thumbnails (§8.3): generated in the background by the job queue, never during the
 * upload request, so a slow GD decode cannot push an upload past the host's time budget.
 *
 *  - Sources: JPEG, PNG, GIF (first frame), WebP and BMP, decoded with GD when available.
 *  - Memory guard: a decoded bitmap needs roughly width × height × 5 bytes; images that would not
 *    fit in the remaining memory are skipped instead of crashing the worker (shared hosts run
 *    64–128 MB limits).
 *  - Output: fits a 400 px box (never upscaled), EXIF orientation applied when the exif extension
 *    is present, WebP (alpha kept) when GD can write it, otherwise JPEG quality 78 on white.
 *  - Storage: Paths::userDir(owner, 'thumbs')/<fileId>.thumb, encrypted with a key derived for
 *    "thumb:<fileId>" when encryption is enabled — thumbnails reveal content too.
 *  - files.thumb_version records the version the thumbnail shows; FileWriter clears it whenever
 *    the content changes and queues a new job.
 */
final class Thumbnailer
{
    public const MAX_BOX = 400;
    public const QUALITY = 78;
    /** Largest source image read into memory for decoding. */
    public const MAX_SOURCE_BYTES = 33554432;

    private const EXTENSIONS = ['jpg', 'jpeg', 'jpe', 'jfif', 'png', 'gif', 'webp', 'bmp'];
    private const MIMES = ['image/jpeg', 'image/pjpeg', 'image/png', 'image/gif', 'image/webp', 'image/bmp', 'image/x-ms-bmp', 'image/x-bmp'];

    /** Whether a thumbnail can be produced for this files row on this server. */
    public static function supports(array $file): bool
    {
        if (!Capabilities::hasGd()) {
            return false;
        }
        $mime = strtolower((string) ($file['mime'] ?? ''));
        $ext = strtolower((string) ($file['ext'] ?? ''));
        return in_array($mime, self::MIMES, true) || (($file['kind'] ?? '') === 'image' && in_array($ext, self::EXTENSIONS, true));
    }

    /** Queue handler: ['file_id' => int]. Idempotent; permanent problems are logged, not retried. */
    public static function generateJob(array $payload): void
    {
        $fileId = (int) ($payload['file_id'] ?? 0);
        if ($fileId > 0) {
            self::generate($fileId);
        }
    }

    /** Generate (or regenerate) the thumbnail of the file's current version. True when stored. */
    public static function generate(int $fileId): bool
    {
        $file = Db::one('SELECT * FROM files WHERE id = ?', [$fileId]);
        if ($file === null || $file['deleted_at'] !== null || !self::supports($file)) {
            return false;
        }
        $version = (int) $file['version'];
        if ($file['thumb_version'] !== null && (int) $file['thumb_version'] === $version && is_file(self::path((int) $file['owner_id'], $fileId))) {
            return true; // already done (job ran twice)
        }
        $blob = Db::one('SELECT * FROM file_blobs WHERE id = ?', [(int) $file['blob_id']]);
        if ($blob === null) {
            return false;
        }
        $headroom = self::memoryHeadroom();
        $size = (int) $blob['size'];
        if ($size <= 0 || $size > min(self::MAX_SOURCE_BYTES, intdiv($headroom, 3))) {
            Logger::info('upload', 'Thumbnail skipped: source too large for available memory', ['file_id' => $fileId, 'size' => $size]);
            return false;
        }
        try {
            $data = BlobStore::readAll($blob, $size);
        } catch (\Throwable $e) {
            Logger::warning('upload', 'Thumbnail skipped: stored file unreadable', ['file_id' => $fileId, 'error' => $e->getMessage()]);
            return false;
        }
        $bytes = self::render($data, $headroom);
        unset($data);
        if ($bytes === null) {
            return false;
        }

        $path = self::path((int) $file['owner_id'], $fileId);
        $stored = Crypto::enabled() ? Crypto::encryptString($bytes, 'thumb:' . $fileId) : $bytes;
        // The content may have changed while we were decoding: only publish a thumbnail that
        // still matches the current version.
        if ((int) Db::value('SELECT version FROM files WHERE id = ?', [$fileId]) !== $version) {
            return false;
        }
        $tmp = $path . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, $stored) !== strlen($stored) || !@rename($tmp, $path)) {
            @unlink($tmp);
            throw new \RuntimeException('Thumbnail could not be written');
        }
        $n = Db::run(
            'UPDATE files SET thumb_version = :v WHERE id = :id AND version = :v2 AND deleted_at IS NULL',
            ['v' => $version, 'id' => $fileId, 'v2' => $version]
        )->rowCount();
        if ($n === 1) {
            $row = Db::one('SELECT * FROM files WHERE id = ?', [$fileId]);
            if ($row !== null) {
                EventBus::publish('file.updated', ['file' => FileWriter::summary($row, null, true), 'changes' => ['has_thumbnail']], EventBus::fileAudience($fileId), [
                    'actor_id' => null, 'file_id' => $fileId, 'folder_id' => $row['folder_id'] !== null ? (int) $row['folder_id'] : null, 'origin' => null,
                ]);
            }
        }
        return true;
    }

    /**
     * Decode, orient, scale and encode. Returns WebP/JPEG bytes, or null when the image cannot
     * (or should not, for memory reasons) be decoded.
     */
    public static function render(string $data, ?int $headroom = null): ?string
    {
        if (!Capabilities::hasGd() || $data === '') {
            return null;
        }
        $headroom ??= self::memoryHeadroom();
        $info = @getimagesizefromstring($data);
        if (!is_array($info) || empty($info[0]) || empty($info[1])) {
            return null;
        }
        [$w, $h, $type] = [(int) $info[0], (int) $info[1], (int) $info[2]];
        $allowed = [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_GIF, IMAGETYPE_BMP];
        if (defined('IMAGETYPE_WEBP')) {
            $allowed[] = IMAGETYPE_WEBP;
        }
        if (!in_array($type, $allowed, true) || $w > 40000 || $h > 40000) {
            return null;
        }
        if ($w * $h * 5 > $headroom - strlen($data)) {
            Logger::info('upload', 'Thumbnail skipped: decoded image would exceed the memory limit', ['width' => $w, 'height' => $h]);
            return null;
        }
        $orientation = $type === IMAGETYPE_JPEG ? self::exifOrientation($data) : 1;
        try {
            $src = @imagecreatefromstring($data);
        } catch (\Throwable) {
            $src = false;
        }
        if ($src === false) {
            return null;
        }
        $scale = min(1.0, self::MAX_BOX / max($w, $h));
        $tw = max(1, (int) round($w * $scale));
        $th = max(1, (int) round($h * $scale));
        $dst = imagecreatetruecolor($tw, $th);
        $webp = function_exists('imagewebp');
        if ($webp) {
            imagealphablending($dst, false);
            imagesavealpha($dst, true);
            imagefill($dst, 0, 0, (int) imagecolorallocatealpha($dst, 0, 0, 0, 127));
            imagealphablending($dst, true);
        } else {
            imagefill($dst, 0, 0, (int) imagecolorallocate($dst, 255, 255, 255));
        }
        imagecopyresampled($dst, $src, 0, 0, 0, 0, $tw, $th, $w, $h);
        imagedestroy($src);
        $dst = self::orient($dst, $orientation);
        if ($webp) {
            imagesavealpha($dst, true);
        }

        ob_start();
        try {
            $ok = $webp ? imagewebp($dst, null, self::QUALITY) : imagejpeg($dst, null, self::QUALITY);
        } finally {
            $bytes = (string) ob_get_clean();
            imagedestroy($dst);
        }
        return ($ok && $bytes !== '') ? $bytes : null;
    }

    /** Stream the stored thumbnail (or 404 THUMBNAIL not found). */
    public static function send(array $fileRow, Request $req): void
    {
        $thumb = self::read($fileRow);
        if ($thumb === null) {
            throw ApiException::notFound('thumbnail');
        }
        if (class_exists(\FT\Auth\Auth::class)) {
            \FT\Auth\Auth::closeSession();
        }
        $etag = '"t' . (int) $fileRow['id'] . '-' . (int) $fileRow['thumb_version'] . '-' . substr(hash('sha256', $thumb['bytes']), 0, 16) . '"';
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        // "?v=<thumb_version>" makes the URL immutable, so the browser may keep it for a week
        // (saves requests against the host's daily hit budget); otherwise revalidate via ETag.
        $v = $req->query('v');
        $immutable = is_string($v) && $v === (string) (int) $fileRow['thumb_version'];
        $headers = [
            'Content-Type'            => $thumb['type'],
            'ETag'                    => $etag,
            'Cache-Control'           => $immutable ? 'private, max-age=604800, immutable' : 'private, no-cache',
            'X-Content-Type-Options'  => 'nosniff',
            'Content-Security-Policy' => FileStreamer::CSP,
            'Cross-Origin-Resource-Policy' => 'same-origin',
        ];
        $inm = $req->header('If-None-Match');
        if ($inm !== null && FileStreamer::etagMatches($inm, $etag)) {
            FileStreamer::emitHeaders(304, ['ETag' => $etag, 'Cache-Control' => $headers['Cache-Control']]);
            return;
        }
        $headers['Content-Length'] = (string) strlen($thumb['bytes']);
        FileStreamer::emitHeaders(200, $headers);
        if ($req->realMethod() !== 'HEAD') {
            echo $thumb['bytes'];
        }
    }

    /** @return array{bytes:string,type:string}|null the decrypted thumbnail of a files row */
    public static function read(array $fileRow): ?array
    {
        if (($fileRow['thumb_version'] ?? null) === null || ($fileRow['deleted_at'] ?? null) !== null) {
            return null;
        }
        $path = self::path((int) $fileRow['owner_id'], (int) $fileRow['id']);
        if (!is_file($path)) {
            return null;
        }
        $data = @file_get_contents($path, false, null, 0, 4 * 1048576);
        if ($data === false || $data === '') {
            return null;
        }
        if (Crypto::isEncryptedString($data)) {
            try {
                $data = Crypto::decryptString($data, 'thumb:' . (int) $fileRow['id']);
            } catch (\Throwable $e) {
                Logger::warning('download', 'Thumbnail could not be decrypted', ['file_id' => (int) $fileRow['id'], 'error' => $e->getMessage()]);
                return null;
            }
        }
        if (strlen($data) > 12 && substr($data, 0, 4) === 'RIFF' && substr($data, 8, 4) === 'WEBP') {
            return ['bytes' => $data, 'type' => 'image/webp'];
        }
        if (strncmp($data, "\xFF\xD8\xFF", 3) === 0) {
            return ['bytes' => $data, 'type' => 'image/jpeg'];
        }
        return null;
    }

    public static function path(int $ownerId, int $fileId): string
    {
        return Paths::userDir($ownerId, 'thumbs') . '/' . $fileId . '.thumb';
    }

    /** Remove a stored thumbnail (A3 calls this when a file is purged). */
    public static function delete(int $ownerId, int $fileId): void
    {
        try {
            $p = self::path($ownerId, $fileId);
            if (is_file($p)) {
                @unlink($p);
            }
        } catch (\Throwable) {
            // nothing to delete
        }
    }

    // ------------------------------------------------------------------ internals

    private static function memoryHeadroom(): int
    {
        $limit = Capabilities::iniBytes((string) ini_get('memory_limit'));
        if ($limit <= 0) {
            $limit = 512 * 1048576;
        }
        return max(0, $limit - memory_get_usage(true) - 8 * 1048576);
    }

    private static function exifOrientation(string $data): int
    {
        if (!function_exists('exif_read_data')) {
            return 1;
        }
        $h = fopen('php://memory', 'w+b');
        if ($h === false) {
            return 1;
        }
        try {
            fwrite($h, $data);
            rewind($h);
            $exif = @exif_read_data($h);
            $o = is_array($exif) ? (int) ($exif['Orientation'] ?? 1) : 1;
            return $o >= 1 && $o <= 8 ? $o : 1;
        } catch (\Throwable) {
            return 1;
        } finally {
            fclose($h);
        }
    }

    /** Apply an EXIF orientation (1–8) to an already scaled image. */
    private static function orient(\GdImage $img, int $o): \GdImage
    {
        $rotate = static function (\GdImage $i, int $deg): \GdImage {
            $r = imagerotate($i, $deg, 0);
            if ($r === false) {
                return $i;
            }
            imagedestroy($i);
            return $r;
        };
        switch ($o) {
            case 2:
                imageflip($img, IMG_FLIP_HORIZONTAL);
                return $img;
            case 3:
                return $rotate($img, 180);
            case 4:
                imageflip($img, IMG_FLIP_VERTICAL);
                return $img;
            case 5:
                imageflip($img, IMG_FLIP_VERTICAL);
                return $rotate($img, -90);
            case 6:
                return $rotate($img, -90);
            case 7:
                imageflip($img, IMG_FLIP_HORIZONTAL);
                return $rotate($img, -90);
            case 8:
                return $rotate($img, 90);
            default:
                return $img;
        }
    }
}
