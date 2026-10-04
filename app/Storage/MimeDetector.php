<?php
declare(strict_types=1);

namespace FT\Storage;

use FT\Core\Settings;

/**
 * Server-side content type detection and classification.
 *
 * The browser-supplied MIME type is never trusted: the type is sniffed from the content
 * (finfo on the first bytes) and refined with the extension only where the content is
 * ambiguous (plain text, ZIP/OLE containers such as .docx/.xls, empty files). The result
 * decides the "kind" used by the UI and — crucially — what may ever be served inline
 * (inlineType): HTML, SVG, XML and scripts are never served as active content.
 */
final class MimeDetector
{
    public const KINDS = ['image', 'video', 'audio', 'pdf', 'document', 'spreadsheet', 'presentation', 'code', 'text', 'archive', 'other'];

    /** Bytes of content passed to finfo. */
    public const SNIFF_BYTES = 65536;

    /** Legacy auto-tag rules (single-file app $autoTagRules), kept for tag compatibility. */
    public const LEGACY_TAGS = [
        'image'    => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'],
        'video'    => ['mp4', 'webm', 'mov', 'avi', 'mkv'],
        'audio'    => ['mp3', 'wav', 'aac', 'flac', 'm4a', 'opus'],
        'document' => ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'],
        'code'     => ['php', 'js', 'ts', 'py', 'sh', 'css', 'html', 'json', 'xml', 'yaml', 'yml'],
        'archive'  => ['zip', 'rar', '7z', 'tar', 'gz'],
        'text'     => ['txt', 'md', 'csv', 'log'],
    ];

    /** Extension => kind (legacy lists plus common office / code / media types). */
    private const KIND_BY_EXT = [
        // images
        'jpg' => 'image', 'jpeg' => 'image', 'jpe' => 'image', 'png' => 'image', 'gif' => 'image', 'webp' => 'image', 'bmp' => 'image',
        'svg' => 'image', 'ico' => 'image', 'tif' => 'image', 'tiff' => 'image', 'heic' => 'image', 'heif' => 'image', 'avif' => 'image',
        // video
        'mp4' => 'video', 'm4v' => 'video', 'webm' => 'video', 'mov' => 'video', 'avi' => 'video', 'mkv' => 'video', 'ogv' => 'video',
        '3gp' => 'video', 'wmv' => 'video', 'flv' => 'video', 'mpg' => 'video', 'mpeg' => 'video',
        // audio
        'mp3' => 'audio', 'wav' => 'audio', 'aac' => 'audio', 'flac' => 'audio', 'm4a' => 'audio', 'opus' => 'audio', 'ogg' => 'audio',
        'oga' => 'audio', 'weba' => 'audio', 'wma' => 'audio', 'mid' => 'audio', 'midi' => 'audio', 'amr' => 'audio', 'aiff' => 'audio',
        // pdf / office
        'pdf' => 'pdf',
        'doc' => 'document', 'docx' => 'document', 'odt' => 'document', 'rtf' => 'document', 'pages' => 'document', 'epub' => 'document',
        'xls' => 'spreadsheet', 'xlsx' => 'spreadsheet', 'xlsm' => 'spreadsheet', 'ods' => 'spreadsheet', 'numbers' => 'spreadsheet',
        'ppt' => 'presentation', 'pptx' => 'presentation', 'odp' => 'presentation', 'key' => 'presentation',
        // code
        'php' => 'code', 'js' => 'code', 'ts' => 'code', 'mjs' => 'code', 'cjs' => 'code', 'jsx' => 'code', 'tsx' => 'code', 'py' => 'code',
        'sh' => 'code', 'bash' => 'code', 'zsh' => 'code', 'css' => 'code', 'scss' => 'code', 'sass' => 'code', 'less' => 'code',
        'html' => 'code', 'htm' => 'code', 'xhtml' => 'code', 'json' => 'code', 'xml' => 'code', 'yaml' => 'code', 'yml' => 'code',
        'java' => 'code', 'c' => 'code', 'h' => 'code', 'cpp' => 'code', 'hpp' => 'code', 'cc' => 'code', 'cs' => 'code',
        'go' => 'code', 'rs' => 'code', 'rb' => 'code', 'pl' => 'code', 'swift' => 'code', 'kt' => 'code', 'kts' => 'code',
        'sql' => 'code', 'ini' => 'code', 'toml' => 'code', 'vue' => 'code', 'svelte' => 'code', 'dart' => 'code', 'lua' => 'code',
        'r' => 'code', 'bat' => 'code', 'cmd' => 'code', 'ps1' => 'code', 'scala' => 'code', 'groovy' => 'code', 'gradle' => 'code',
        'conf' => 'code', 'cfg' => 'code', 'env' => 'code', 'dockerfile' => 'code', 'makefile' => 'code', 'diff' => 'code', 'patch' => 'code',
        // text
        'txt' => 'text', 'md' => 'text', 'markdown' => 'text', 'csv' => 'text', 'tsv' => 'text', 'log' => 'text', 'rst' => 'text',
        'text' => 'text', 'nfo' => 'text', 'srt' => 'text', 'vtt' => 'text',
        // archives
        'zip' => 'archive', 'rar' => 'archive', '7z' => 'archive', 'tar' => 'archive', 'gz' => 'archive', 'tgz' => 'archive',
        'bz2' => 'archive', 'xz' => 'archive', 'zst' => 'archive', 'lz' => 'archive', 'lzma' => 'archive', 'cab' => 'archive', 'iso' => 'archive',
    ];

    /** Extension => canonical MIME, used when the content alone is ambiguous. */
    private const MIME_BY_EXT = [
        'jpg' => 'image/jpeg', 'jpeg' => 'image/jpeg', 'jpe' => 'image/jpeg', 'png' => 'image/png', 'gif' => 'image/gif',
        'webp' => 'image/webp', 'bmp' => 'image/bmp', 'svg' => 'image/svg+xml', 'ico' => 'image/x-icon', 'tif' => 'image/tiff',
        'tiff' => 'image/tiff', 'heic' => 'image/heic', 'heif' => 'image/heif', 'avif' => 'image/avif',
        'mp4' => 'video/mp4', 'm4v' => 'video/x-m4v', 'webm' => 'video/webm', 'mov' => 'video/quicktime', 'avi' => 'video/x-msvideo',
        'mkv' => 'video/x-matroska', 'ogv' => 'video/ogg', '3gp' => 'video/3gpp', 'wmv' => 'video/x-ms-wmv', 'flv' => 'video/x-flv',
        'mpg' => 'video/mpeg', 'mpeg' => 'video/mpeg',
        'mp3' => 'audio/mpeg', 'wav' => 'audio/wav', 'aac' => 'audio/aac', 'flac' => 'audio/flac', 'm4a' => 'audio/mp4',
        'opus' => 'audio/ogg', 'ogg' => 'audio/ogg', 'oga' => 'audio/ogg', 'weba' => 'audio/webm', 'wma' => 'audio/x-ms-wma',
        'mid' => 'audio/midi', 'midi' => 'audio/midi', 'amr' => 'audio/amr', 'aiff' => 'audio/aiff',
        'pdf' => 'application/pdf',
        'doc' => 'application/msword', 'docx' => 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'odt' => 'application/vnd.oasis.opendocument.text', 'rtf' => 'application/rtf', 'epub' => 'application/epub+zip',
        'pages' => 'application/vnd.apple.pages',
        'xls' => 'application/vnd.ms-excel', 'xlsx' => 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'xlsm' => 'application/vnd.ms-excel.sheet.macroenabled.12', 'ods' => 'application/vnd.oasis.opendocument.spreadsheet',
        'numbers' => 'application/vnd.apple.numbers',
        'ppt' => 'application/vnd.ms-powerpoint', 'pptx' => 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'odp' => 'application/vnd.oasis.opendocument.presentation', 'key' => 'application/vnd.apple.keynote',
        'js' => 'text/javascript', 'mjs' => 'text/javascript', 'cjs' => 'text/javascript', 'json' => 'application/json',
        'xml' => 'application/xml', 'html' => 'text/html', 'htm' => 'text/html', 'xhtml' => 'application/xhtml+xml',
        'css' => 'text/css', 'php' => 'text/x-php', 'py' => 'text/x-python', 'sh' => 'text/x-shellscript', 'yaml' => 'text/yaml',
        'yml' => 'text/yaml', 'ts' => 'text/plain', 'sql' => 'text/x-sql',
        'txt' => 'text/plain', 'md' => 'text/markdown', 'markdown' => 'text/markdown', 'csv' => 'text/csv', 'tsv' => 'text/tab-separated-values',
        'log' => 'text/plain', 'srt' => 'text/plain', 'vtt' => 'text/vtt',
        'zip' => 'application/zip', 'rar' => 'application/vnd.rar', '7z' => 'application/x-7z-compressed', 'tar' => 'application/x-tar',
        'gz' => 'application/gzip', 'tgz' => 'application/gzip', 'bz2' => 'application/x-bzip2', 'xz' => 'application/x-xz',
        'zst' => 'application/zstd', 'iso' => 'application/x-iso9660-image',
    ];

    /** Sniff results that say "can't tell" — the extension decides. */
    private const GENERIC = ['', 'application/octet-stream', 'application/x-empty', 'inode/x-empty', 'application/x-unknown', 'unknown/unknown'];
    private const CONTAINERS_ZIP = ['application/zip', 'application/x-zip-compressed', 'application/x-zip'];
    private const CONTAINERS_OLE = ['application/cdfv2', 'application/x-ole-storage', 'application/vnd.ms-office', 'application/cdfv2-unknown'];

    /** Never served inline as their own type (active content). */
    private const ACTIVE_MIME = ['text/html', 'application/xhtml+xml', 'image/svg+xml', 'text/xml', 'application/xml', 'text/javascript',
        'application/javascript', 'application/x-javascript', 'application/ecmascript', 'text/ecmascript', 'text/x-php', 'application/x-httpd-php',
        'application/x-shockwave-flash', 'text/xsl', 'application/xslt+xml', 'application/rss+xml', 'application/atom+xml', 'application/mathml+xml'];

    /** Text-like application types that are shown as plain text. */
    private const TEXTUAL_APP = ['application/json', 'application/xml', 'application/javascript', 'application/x-javascript',
        'application/ecmascript', 'application/x-yaml', 'application/yaml', 'application/toml', 'application/x-sh', 'application/x-php',
        'application/x-httpd-php', 'application/sql', 'application/x-sql', 'application/xhtml+xml', 'image/svg+xml', 'application/rtf',
        'application/x-empty', 'application/ld+json', 'application/graphql'];

    /** @return array{mime:string, ext:string, kind:string} */
    public static function detect(string $path, string $filename): array
    {
        $head = '';
        $h = @fopen($path, 'rb');
        if ($h !== false) {
            $head = (string) fread($h, self::SNIFF_BYTES);
            fclose($h);
        }
        return self::detectBuffer($head, $filename);
    }

    /** @return array{mime:string, ext:string, kind:string} */
    public static function detectBuffer(string $head, string $filename): array
    {
        $ext = self::extension($filename);
        $mime = self::resolve(self::sniff($head), $ext);
        return ['mime' => $mime, 'ext' => $ext, 'kind' => self::kindFor($ext, $mime)];
    }

    /** Content-only MIME type of the first bytes ('' when finfo is unavailable). */
    public static function sniff(string $head): string
    {
        if ($head === '') {
            return 'application/x-empty';
        }
        if (!class_exists(\finfo::class)) {
            return '';
        }
        try {
            $f = new \finfo(FILEINFO_MIME_TYPE);
            $m = $f->buffer($head);
            return is_string($m) ? strtolower(trim($m)) : '';
        } catch (\Throwable) {
            return '';
        }
    }

    /** Combine a sniffed content type with the file extension. */
    public static function resolve(string $sniffed, string $ext): string
    {
        $sniffed = strtolower(trim(explode(';', $sniffed)[0]));
        $ext = strtolower($ext);
        $byExt = self::MIME_BY_EXT[$ext] ?? null;
        $extKind = self::KIND_BY_EXT[$ext] ?? null;

        if (in_array($sniffed, self::GENERIC, true)) {
            return $byExt ?? 'application/octet-stream';
        }
        // Plain text whose extension says what kind of text it is (.js, .csv, .md, .svg…).
        if (str_starts_with($sniffed, 'text/') && $byExt !== null && (in_array($extKind, ['code', 'text'], true) || $ext === 'svg')) {
            return $byExt;
        }
        // Office Open XML / ODF / EPUB are ZIP containers; old Office files are OLE containers.
        if ((in_array($sniffed, self::CONTAINERS_ZIP, true) || in_array($sniffed, self::CONTAINERS_OLE, true))
            && $byExt !== null && in_array($extKind, ['document', 'spreadsheet', 'presentation'], true)) {
            return $byExt;
        }
        return $sniffed !== '' ? $sniffed : ($byExt ?? 'application/octet-stream');
    }

    /** image|video|audio|pdf|document|spreadsheet|presentation|code|text|archive|other */
    public static function kindFor(string $ext, string $mime): string
    {
        $ext = strtolower($ext);
        $mime = strtolower(trim(explode(';', $mime)[0]));
        $extKind = self::KIND_BY_EXT[$ext] ?? null;
        $mimeKind = self::kindFromMime($mime);
        $media = ['image', 'video', 'audio', 'pdf'];
        if ($extKind !== null && $mimeKind !== null && $extKind !== $mimeKind && in_array($extKind, $media, true) && in_array($mimeKind, $media, true)) {
            // Containers like MP4/Ogg/WebM hold audio or video: trust the extension there,
            // otherwise the content wins (a ".jpg" that is really a PDF is a PDF).
            $av = ['audio', 'video'];
            return (in_array($extKind, $av, true) && in_array($mimeKind, $av, true)) ? $extKind : $mimeKind;
        }
        if ($extKind !== null) {
            return $extKind;
        }
        return $mimeKind ?? 'other';
    }

    /**
     * Content-Type that is safe for INLINE display, or null when the file may only be offered
     * as an attachment. Text and code are always text/plain; html/svg/xml/js never active.
     */
    public static function inlineType(string $mime, string $ext): ?string
    {
        $m = strtolower(trim(explode(';', $mime)[0]));
        $ext = strtolower($ext);
        $plain = 'text/plain; charset=utf-8';
        $kind = self::kindFor($ext, $m);

        if (in_array($m, self::ACTIVE_MIME, true) || in_array($ext, ['svg', 'svgz', 'html', 'htm', 'xhtml', 'xml', 'xsl', 'xslt', 'js', 'mjs'], true)) {
            return $plain;
        }
        if (preg_match('~^(image|video|audio)/[a-z0-9.+-]+$~', $m)) {
            return $m;
        }
        if ($m === 'application/pdf') {
            return 'application/pdf';
        }
        if (str_starts_with($m, 'text/') || in_array($m, self::TEXTUAL_APP, true) || in_array($kind, ['code', 'text'], true)) {
            return $plain;
        }
        return null;
    }

    /** Extension blocked by the admin setting blocked_extensions (comma list, case-insensitive). */
    public static function isBlockedExtension(string $ext): bool
    {
        $ext = strtolower(ltrim(trim($ext), '.'));
        if ($ext === '') {
            return false;
        }
        foreach (explode(',', Settings::string('blocked_extensions', '')) as $b) {
            if (strtolower(ltrim(trim($b), '.')) === $ext) {
                return true;
            }
        }
        return false;
    }

    /** Lower-case extension of a file name ('' when none or not a plain alphanumeric token). */
    public static function extension(string $filename): string
    {
        $base = basename(str_replace('\\', '/', $filename));
        $dot = strrpos($base, '.');
        if ($dot === false || $dot === 0) {
            $lower = strtolower($base);
            return in_array($lower, ['dockerfile', 'makefile'], true) ? $lower : '';
        }
        $ext = strtolower(substr($base, $dot + 1));
        return preg_match('/^[a-z0-9]{1,32}$/', $ext) ? $ext : '';
    }

    /** Legacy automatic tags for an extension (image, video, audio, document, code, archive, text). */
    public static function legacyTags(string $ext): array
    {
        $ext = strtolower($ext);
        $tags = [];
        foreach (self::LEGACY_TAGS as $tag => $exts) {
            if (in_array($ext, $exts, true)) {
                $tags[] = $tag;
            }
        }
        return $tags;
    }

    private static function kindFromMime(string $mime): ?string
    {
        if ($mime === '' || in_array($mime, self::GENERIC, true)) {
            return null;
        }
        if ($mime === 'application/pdf') {
            return 'pdf';
        }
        foreach (['image', 'video', 'audio'] as $p) {
            if (str_starts_with($mime, $p . '/')) {
                return $p;
            }
        }
        if (str_contains($mime, 'wordprocessingml') || str_contains($mime, 'opendocument.text') || $mime === 'application/msword' || $mime === 'application/rtf') {
            return 'document';
        }
        if (str_contains($mime, 'spreadsheetml') || str_contains($mime, 'opendocument.spreadsheet') || str_contains($mime, 'ms-excel')) {
            return 'spreadsheet';
        }
        if (str_contains($mime, 'presentationml') || str_contains($mime, 'opendocument.presentation') || str_contains($mime, 'ms-powerpoint')) {
            return 'presentation';
        }
        if (in_array($mime, ['application/zip', 'application/x-zip-compressed', 'application/gzip', 'application/x-gzip', 'application/x-tar',
            'application/x-7z-compressed', 'application/vnd.rar', 'application/x-rar', 'application/x-rar-compressed', 'application/x-bzip2',
            'application/x-xz', 'application/zstd'], true)) {
            return 'archive';
        }
        if (in_array($mime, ['text/html', 'text/css', 'text/javascript', 'application/javascript', 'application/json', 'application/xml',
            'text/xml', 'text/x-php', 'application/x-php', 'text/x-python', 'text/x-shellscript', 'application/x-sh'], true)) {
            return 'code';
        }
        if (str_starts_with($mime, 'text/')) {
            return 'text';
        }
        return null;
    }
}
