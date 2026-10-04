<?php
declare(strict_types=1);

namespace FT\Storage;

use FT\Core\ApiException;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Http\Request;
use FT\Http\Response;
use FT\Support\Capabilities;

/**
 * Sends file content to the browser (§8.3): downloads, inline previews and media streaming.
 *
 *  - Single-range HTTP Range support across segments and gcm1 chunks (206 / 416), so video and
 *    audio seek and resumable download managers work. Multi-range requests get the whole file.
 *  - ETag = "<sha256>-<version>"; If-None-Match ⇒ 304; If-Range honoured; HEAD sends headers only.
 *  - Inline content is only ever served with MimeDetector::inlineType(): text and code as
 *    text/plain; HTML, SVG, XML and scripts never as active content. Everything is sandboxed with
 *    a strict Content-Security-Policy and X-Content-Type-Options: nosniff.
 *
 * PDF CSP decision: the `sandbox` directive makes Chrome/Edge refuse to render a PDF ("This page
 * has been blocked") and breaks Safari's viewer, so inline PDFs get CSP_PDF instead: no sandbox,
 * but `default-src 'none'` (the document itself may load nothing), `object-src 'self'` (lets the
 * browser's own viewer embed the response) and `frame-ancestors 'self'` (only our app may frame
 * it). The built-in PDF viewers run in their own isolated context and PDF scripting cannot reach
 * our origin's DOM or cookies, and PDFs are never served as text/html. Every other response keeps
 * the sandboxed CSP from the contract. Attachments of active types are sent as octet-stream.
 *
 * Streaming: closes the PHP session first (other tabs stay responsive), releases the MySQL
 * connection (hosts allow very few), sends ≤ 256 KiB pieces with flush() and stops as soon as
 * the client disconnects. A damaged blob is detected before any header is sent (FILE_UNAVAILABLE);
 * a failure mid-stream aborts the connection, so the client sees a short body against the
 * declared Content-Length rather than silently truncated "success".
 */
final class FileStreamer
{
    public const CSP = "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox";
    public const CSP_PDF = "default-src 'none'; object-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; frame-ancestors 'self'";
    public const PIECE = 262144;

    /** Content types that must never be delivered as themselves, even as attachments. */
    private const ACTIVE = ['text/html', 'application/xhtml+xml', 'image/svg+xml', 'text/xml', 'application/xml', 'text/javascript',
        'application/javascript', 'application/x-javascript', 'application/ecmascript', 'text/ecmascript', 'text/x-php',
        'application/x-httpd-php', 'application/x-shockwave-flash', 'text/xsl', 'application/xslt+xml'];

    public static function send(array $fileRow, array $blobRow, Request $req, bool $inline, ?string $name = null): void
    {
        $plan = self::plan($fileRow, $blobRow, $req, $inline, $name);
        $head = $req->realMethod() === 'HEAD';
        $reader = null;
        if (!$head && in_array($plan['status'], [200, 206], true) && $plan['length'] > 0) {
            // Open (and verify every segment) BEFORE any header goes out, so a file the host
            // deleted produces a proper JSON error instead of a broken download.
            try {
                $reader = BlobStore::open($blobRow);
            } catch (\Throwable $e) {
                Logger::error('download', 'Stored file is missing or damaged', ['file_id' => (int) ($fileRow['id'] ?? 0), 'blob_id' => (int) ($blobRow['id'] ?? 0), 'error' => $e->getMessage()]);
                throw self::unavailable();
            }
        }

        if (class_exists(\FT\Auth\Auth::class)) {
            \FT\Auth\Auth::closeSession();
        }
        Db::disconnect();
        @ini_set('zlib.output_compression', '0');
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        self::emitHeaders($plan['status'], $plan['headers']);
        if ($reader === null) {
            return;
        }

        Capabilities::setTimeLimit(0);
        try {
            self::emit($reader, $plan['start'], $plan['end'], static function (string $piece): bool {
                echo $piece;
                flush();
                return connection_aborted() === 0;
            });
        } catch (\Throwable $e) {
            // Headers are gone; abandon the response so the client notices the short body.
            Logger::error('download', 'Streaming aborted: stored data failed verification', ['file_id' => (int) ($fileRow['id'] ?? 0), 'error' => $e->getMessage()]);
        } finally {
            $reader->close();
        }
    }

    /**
     * Work out status, headers and byte range without sending anything (unit-testable).
     * @return array{status:int, headers:array<string,string>, start:int, end:int, length:int, inline:bool}
     */
    public static function plan(array $fileRow, array $blobRow, Request $req, bool $inline, ?string $name = null): array
    {
        $size = (int) $blobRow['size'];
        $name = $name ?? (string) ($fileRow['name'] ?? 'download');
        $ext = (string) ($fileRow['ext'] ?? MimeDetector::extension($name));
        $mime = (string) (($fileRow['mime'] ?? '') !== '' ? $fileRow['mime'] : ($blobRow['mime'] ?? 'application/octet-stream'));
        $etag = '"' . $blobRow['sha256'] . '-' . (int) ($fileRow['version'] ?? 1) . '"';

        $type = $inline ? MimeDetector::inlineType($mime, $ext) : null;
        if ($type === null) {
            $inline = false;
            $type = self::attachmentType($mime);
        }
        // Content of (file, version) never changes: a URL carrying "?v=<version>" may be cached.
        $v = $req->query('v');
        $immutable = is_string($v) && $v === (string) (int) ($fileRow['version'] ?? 1);
        $headers = [
            'Content-Type'                 => $type,
            'Accept-Ranges'                => 'bytes',
            'ETag'                         => $etag,
            'Cache-Control'                => $immutable ? 'private, max-age=86400' : 'private, no-cache',
            'Content-Disposition'          => Response::contentDisposition($name, $inline),
            'X-Content-Type-Options'       => 'nosniff',
            'Content-Security-Policy'      => str_starts_with($type, 'application/pdf') ? self::CSP_PDF : self::CSP,
            'Cross-Origin-Resource-Policy' => 'same-origin',
        ];
        $modified = Db::toUnix($fileRow['updated_at'] ?? null);
        if ($modified !== null) {
            $headers['Last-Modified'] = gmdate('D, d M Y H:i:s', $modified) . ' GMT';
        }

        $inm = $req->header('If-None-Match');
        if ($inm !== null && self::etagMatches($inm, $etag)) {
            return ['status' => 304, 'headers' => ['ETag' => $etag, 'Cache-Control' => $headers['Cache-Control']], 'start' => 0, 'end' => -1, 'length' => 0, 'inline' => $inline];
        }

        $range = $req->header('Range');
        $ifRange = $req->header('If-Range');
        if ($range !== null && $ifRange !== null && trim($ifRange) !== $etag && trim($ifRange) !== ($headers['Last-Modified'] ?? '')) {
            $range = null; // the client's partial copy is stale: send the whole new content
        }
        if ($range !== null) {
            $r = self::parseRange($range, $size);
            if ($r === false) {
                $headers['Content-Range'] = 'bytes */' . $size;
                $headers['Content-Length'] = '0';
                unset($headers['Content-Disposition']);
                return ['status' => 416, 'headers' => $headers, 'start' => 0, 'end' => -1, 'length' => 0, 'inline' => $inline];
            }
            if ($r !== null) {
                [$start, $end] = $r;
                $headers['Content-Range'] = 'bytes ' . $start . '-' . $end . '/' . $size;
                $headers['Content-Length'] = (string) ($end - $start + 1);
                return ['status' => 206, 'headers' => $headers, 'start' => $start, 'end' => $end, 'length' => $end - $start + 1, 'inline' => $inline];
            }
        }
        $headers['Content-Length'] = (string) $size;
        return ['status' => 200, 'headers' => $headers, 'start' => 0, 'end' => $size - 1, 'length' => $size, 'inline' => $inline];
    }

    /**
     * Single-range parser. Returns [start, end] (inclusive), null to ignore the header (malformed
     * or multi-range ⇒ full response), or false when unsatisfiable (⇒ 416).
     * @return array{0:int,1:int}|null|false
     */
    public static function parseRange(string $header, int $size): array|null|false
    {
        $header = trim($header);
        if (!preg_match('/^bytes\s*=\s*(\d*)\s*-\s*(\d*)$/i', $header, $m)) {
            return null;
        }
        [$a, $b] = [$m[1], $m[2]];
        if ($a === '' && $b === '') {
            return null;
        }
        if ($a === '') {
            $n = self::toInt($b);
            if ($n === 0 || $size === 0) {
                return false;
            }
            return [max(0, $size - $n), $size - 1];
        }
        $start = self::toInt($a);
        if ($b !== '' && self::toInt($b) < $start) {
            return null; // syntactically invalid range: ignore it
        }
        if ($start >= $size) {
            return false;
        }
        $end = $b === '' ? $size - 1 : min(self::toInt($b), $size - 1);
        return [$start, $end];
    }

    /**
     * Copy plaintext bytes [$start, $end] from the reader to $write in ≤ PIECE pieces.
     * $write returns false when the client has gone away. Returns the bytes written.
     */
    public static function emit(BlobReader $reader, int $start, int $end, callable $write): int
    {
        if ($end < $start) {
            return 0;
        }
        $reader->seek($start);
        $left = $end - $start + 1;
        $sent = 0;
        while ($left > 0) {
            $piece = $reader->read(min(self::PIECE, $left));
            if ($piece === '') {
                throw new \RuntimeException('Stored file ended unexpectedly');
            }
            $left -= strlen($piece);
            $sent += strlen($piece);
            if ($write($piece) === false) {
                break;
            }
        }
        return $sent;
    }

    /** RFC 7232 If-None-Match comparison (weak comparison, list and "*" supported). */
    public static function etagMatches(string $header, string $etag): bool
    {
        $header = trim($header);
        if ($header === '*') {
            return true;
        }
        $strip = static fn (string $t): string => preg_replace('/^W\//', '', trim($t)) ?? '';
        foreach (explode(',', $header) as $candidate) {
            if ($strip($candidate) === $strip($etag)) {
                return true;
            }
        }
        return false;
    }

    /** @param array<string,string> $headers */
    public static function emitHeaders(int $status, array $headers): void
    {
        if (headers_sent()) {
            return;
        }
        http_response_code($status);
        foreach ($headers as $k => $v) {
            header($k . ': ' . str_replace(["\r", "\n"], '', $v));
        }
    }

    public static function unavailable(): ApiException
    {
        // 410 like A3's FileService: the stored copy is gone (e.g. removed by the host).
        return new ApiException('FILE_UNAVAILABLE', 'This file is unavailable: its stored data is missing or damaged.', 410);
    }

    private static function attachmentType(string $mime): string
    {
        $m = strtolower(trim(explode(';', $mime)[0]));
        if ($m === '' || in_array($m, self::ACTIVE, true) || !preg_match('~^[a-z0-9.+-]+/[a-z0-9.+-]+$~', $m)) {
            return 'application/octet-stream';
        }
        return $m;
    }

    private static function toInt(string $digits): int
    {
        $digits = ltrim($digits, '0');
        if ($digits === '') {
            return 0;
        }
        return strlen($digits) > 18 ? PHP_INT_MAX : (int) $digits;
    }
}
