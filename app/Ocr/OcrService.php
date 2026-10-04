<?php
declare(strict_types=1);

namespace FT\Ocr;

use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Env;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Jobs\Queue;
use FT\Storage\BlobStore;
use FT\Support\Capabilities;

/**
 * Searchable text for files (file_texts): OCR of images/PDFs through an external provider and
 * plain-text indexing of text/code files. Both run as queue jobs (FileWriter queues them after
 * every upload/version; POST /files/{id}/ocr queues OCR on demand) and are idempotent: a file
 * whose stored text already belongs to its current version is skipped unless "force" is set.
 *
 * Providers (ported from the old app; key in .env, never in code):
 *   OCR_PROVIDER=ocrspace      https://api.ocr.space/parse/image (free plan: ≤ 1 MB per file;
 *                              override with OCR_MAX_BYTES on paid plans)
 *   OCR_PROVIDER=googlevision  https://vision.googleapis.com/v1/images:annotate (images only)
 * One outbound call at a time with 5 s connect / 10 s total timeouts; failures never break an
 * upload. Transient failures (network, HTTP 5xx/429) throw so the queue retries with back-off;
 * permanent ones (unsupported, too large, rejected) store nothing and are not retried.
 */
final class OcrService
{
    /** At most this many bytes of text are stored per file and source. */
    public const MAX_TEXT_BYTES = 102400;

    public const OCR_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'tiff', 'tif', 'pdf'];
    public const INDEX_KINDS = ['text', 'code'];

    private const OCRSPACE_DEFAULT_MAX = 1048576;
    private const VISION_MAX = 7 * 1024 * 1024;   // base64 must stay below Google's 10 MB JSON limit
    private const CONNECT_TIMEOUT = 5;
    private const TOTAL_TIMEOUT = 10;

    private const MIME = [
        'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'png' => 'image/png', 'gif' => 'image/gif', 'webp' => 'image/webp',
        'bmp' => 'image/bmp', 'tiff' => 'image/tiff', 'tif' => 'image/tiff', 'pdf' => 'application/pdf',
    ];

    // ================================================================== configuration

    /** 'ocrspace' | 'googlevision' | null */
    public static function provider(): ?string
    {
        $p = strtolower(trim((string) Config::get('ocr.provider')));
        return match ($p) {
            'ocrspace', 'ocr.space', 'ocr_space' => 'ocrspace',
            'googlevision', 'google', 'vision', 'google_vision' => 'googlevision',
            default => null,
        };
    }

    public static function configured(): bool
    {
        return self::provider() !== null && (string) Config::get('ocr.api_key') !== '' && Capabilities::hasCurl();
    }

    /** Configured in .env and switched on in the admin settings. */
    public static function enabled(): bool
    {
        return self::configured() && Settings::bool('ocr_enabled', true);
    }

    /** Images and PDFs with an extension the providers accept (Google Vision: images only). */
    public static function supports(array $file): bool
    {
        $ext = strtolower((string) ($file['ext'] ?? ''));
        if (!in_array((string) ($file['kind'] ?? ''), ['image', 'pdf'], true) || !in_array($ext, self::OCR_EXTENSIONS, true)) {
            return false;
        }
        return !($ext === 'pdf' && self::provider() === 'googlevision');
    }

    public static function maxBytes(): int
    {
        if (self::provider() === 'googlevision') {
            return self::VISION_MAX;
        }
        return max(1024, min(BlobStore::SEGMENT_BYTES, Env::int('OCR_MAX_BYTES', self::OCRSPACE_DEFAULT_MAX)));
    }

    /**
     * Queue OCR for a file unless the same job is already waiting. Returns true when queued
     * (or already pending).
     */
    public static function queue(int $fileId, bool $force = false): bool
    {
        $pending = Db::value(
            'SELECT id FROM jobs WHERE type = :t AND failed_at IS NULL AND reserved_at IS NULL AND payload LIKE :p LIMIT 1',
            ['t' => self::class . '::ocrJob', 'p' => '%' . Db::like('"file_id":' . $fileId . ',') . '%']
        );
        if ($pending !== null) {
            return true;
        }
        $version = (int) (Db::value('SELECT version FROM files WHERE id = ?', [$fileId]) ?? 1);
        Queue::push(self::class . '::ocrJob', ['file_id' => $fileId, 'version' => $version, 'force' => $force]);
        return true;
    }

    // ================================================================== jobs

    /** Queue handler: OCR the file's current version into file_texts (source "ocr"). */
    public static function ocrJob(array $payload): void
    {
        $fileId = (int) ($payload['file_id'] ?? 0);
        if ($fileId <= 0 || !self::enabled()) {
            return;
        }
        $file = Db::one('SELECT id, blob_id, version, ext, kind, size, deleted_at FROM files WHERE id = ?', [$fileId]);
        if ($file === null || $file['deleted_at'] !== null || !self::supports($file)) {
            return;
        }
        $version = (int) $file['version'];
        $done = Db::value("SELECT version FROM file_texts WHERE file_id = ? AND source = 'ocr'", [$fileId]);
        if ($done !== null && (int) $done === $version && empty($payload['force'])) {
            return; // already recognised for this version
        }
        if ((int) $file['size'] > self::maxBytes()) {
            Logger::info('app', 'OCR skipped: file is larger than the provider limit', ['file_id' => $fileId, 'size' => (int) $file['size']]);
            return;
        }
        $blob = BlobStore::get((int) $file['blob_id']);
        $ext = strtolower((string) $file['ext']);
        $tmp = BlobStore::toTempFile($blob, '.' . $ext);
        try {
            $text = self::extract($tmp, $ext);
        } finally {
            @unlink($tmp);
        }
        // Only store when the file still is at the version we recognised.
        if ((int) (Db::value('SELECT version FROM files WHERE id = ?', [$fileId]) ?? 0) !== $version) {
            return;
        }
        self::store($fileId, 'ocr', $version, $text);
    }

    /** Queue handler: index the first 100 KB of a text/code file (source "content"). */
    public static function indexContentJob(array $payload): void
    {
        $fileId = (int) ($payload['file_id'] ?? 0);
        if ($fileId <= 0) {
            return;
        }
        $file = Db::one('SELECT id, blob_id, version, kind, deleted_at FROM files WHERE id = ?', [$fileId]);
        if ($file === null || $file['deleted_at'] !== null || !in_array((string) $file['kind'], self::INDEX_KINDS, true)) {
            return;
        }
        $version = (int) $file['version'];
        $done = Db::value("SELECT version FROM file_texts WHERE file_id = ? AND source = 'content'", [$fileId]);
        if ($done !== null && (int) $done === $version && empty($payload['force'])) {
            return;
        }
        $reader = BlobStore::open(BlobStore::get((int) $file['blob_id']));
        $data = '';
        try {
            while (strlen($data) < self::MAX_TEXT_BYTES + 4 && ($d = $reader->read(65536)) !== '') {
                $data .= $d;
            }
        } finally {
            $reader->close();
        }
        if (str_contains(substr($data, 0, 8192), "\0")) {
            return; // binary content despite the extension
        }
        self::store($fileId, 'content', $version, self::cleanText($data));
    }

    // ================================================================== helpers

    /** Valid UTF-8, BOM stripped, at most MAX_TEXT_BYTES, never split inside a character. */
    public static function cleanText(string $data): string
    {
        if (str_starts_with($data, "\xEF\xBB\xBF")) {
            $data = substr($data, 3);
        }
        $cut = mb_strcut($data, 0, self::MAX_TEXT_BYTES, 'UTF-8');
        if (!mb_check_encoding($cut, 'UTF-8')) {
            // Not UTF-8: most likely a Windows-1252 / Latin-1 text file.
            $cut = mb_strcut((string) mb_convert_encoding(substr($data, 0, self::MAX_TEXT_BYTES), 'UTF-8', 'Windows-1252'), 0, self::MAX_TEXT_BYTES, 'UTF-8');
        }
        return (string) mb_scrub($cut, 'UTF-8');
    }

    private static function store(int $fileId, string $source, int $version, string $text): void
    {
        $text = self::cleanText(trim($text));
        Db::run(
            'INSERT INTO file_texts (file_id, source, version, `text`, updated_at) VALUES (:f, :s, :v, :t, :u)
             ON DUPLICATE KEY UPDATE version = VALUES(version), `text` = VALUES(`text`), updated_at = VALUES(updated_at)',
            ['f' => $fileId, 's' => $source, 'v' => max(1, $version), 't' => $text, 'u' => Db::now()]
        );
    }

    /** Provider dispatch. Returns '' for permanent failures; throws for transient ones. */
    public static function extract(string $path, string $ext): string
    {
        return match (self::provider()) {
            'ocrspace'     => self::viaOcrSpace($path, $ext),
            'googlevision' => self::viaGoogleVision($path, $ext),
            default        => '',
        };
    }

    private static function viaOcrSpace(string $path, string $ext): string
    {
        $key = (string) Config::get('ocr.api_key');
        $ch = curl_init('https://api.ocr.space/parse/image');
        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => [
                'language'          => 'eng',
                'isOverlayRequired' => 'false',
                'filetype'          => strtoupper($ext),
                'file'              => new \CURLFile($path, self::MIME[$ext] ?? 'application/octet-stream', 'upload.' . $ext),
            ],
            CURLOPT_HTTPHEADER     => ['apikey: ' . $key],
        ] + self::curlDefaults());
        [$status, $body] = self::exec($ch);
        $json = json_decode($body, true);
        if (!is_array($json) || !empty($json['IsErroredOnProcessing'])) {
            Logger::warning('app', 'OCR.space could not process a file', ['status' => $status]);
            return '';
        }
        $text = '';
        foreach ((array) ($json['ParsedResults'] ?? []) as $r) {
            if (is_array($r) && is_string($r['ParsedText'] ?? null)) {
                $text .= $r['ParsedText'] . "\n";
            }
        }
        return trim($text);
    }

    private static function viaGoogleVision(string $path, string $ext): string
    {
        if ($ext === 'pdf') {
            return '';
        }
        $data = @file_get_contents($path);
        if ($data === false) {
            throw new \RuntimeException('Temporary OCR copy could not be read');
        }
        $payload = json_encode(['requests' => [[
            'image'    => ['content' => base64_encode($data)],
            'features' => [['type' => 'TEXT_DETECTION', 'maxResults' => 1]],
        ]]]);
        unset($data);
        $ch = curl_init('https://vision.googleapis.com/v1/images:annotate?key=' . rawurlencode((string) Config::get('ocr.api_key')));
        curl_setopt_array($ch, [
            CURLOPT_POST       => true,
            CURLOPT_POSTFIELDS => (string) $payload,
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        ] + self::curlDefaults());
        [$status, $body] = self::exec($ch);
        $json = json_decode($body, true);
        if (!is_array($json)) {
            return '';
        }
        $text = $json['responses'][0]['fullTextAnnotation']['text'] ?? '';
        return is_string($text) ? trim($text) : '';
    }

    /** @return array<int,mixed> */
    private static function curlDefaults(): array
    {
        return [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
            CURLOPT_TIMEOUT        => self::TOTAL_TIMEOUT,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
            CURLOPT_USERAGENT      => 'FastTransfer/' . FT_VERSION,
        ];
    }

    /**
     * @param \CurlHandle $ch
     * @return array{0:int,1:string} status, body (≤ 2 MB); throws on transient failures
     */
    private static function exec($ch): array
    {
        $body = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $errno = curl_errno($ch);
        curl_close($ch);
        if ($errno !== 0 || $body === false) {
            // Network trouble (timeout, DNS, host blocked): let the queue retry later.
            throw new \RuntimeException('The OCR service could not be reached (curl error ' . $errno . ')');
        }
        if ($status === 429 || $status >= 500) {
            throw new \RuntimeException('The OCR service is busy (HTTP ' . $status . ')');
        }
        if ($status >= 400) {
            Logger::warning('app', 'The OCR service rejected a request', ['status' => $status]);
            return [$status, ''];
        }
        return [$status, substr((string) $body, 0, 2 * 1024 * 1024)];
    }
}
