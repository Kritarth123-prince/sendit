<?php
declare(strict_types=1);

namespace FT\Storage;

use FT\Core\Config;

/**
 * Physical storage layout (never exposed to the browser):
 *
 *   {STORAGE_PATH}/
 *     users/{userId}/files/aa/bb/<sha256>.blob   per-user content-addressed blobs (dedup scope "user")
 *     users/{userId}/temp/<uploadId>/<n>.part    chunk staging for resumable uploads
 *     users/{userId}/bundles/<shareId>.zip       cached ZIP bundles for multi-file shares
 *     users/{userId}/thumbs/<fileId>.thumb       generated thumbnails (encrypted like blobs)
 *     shared/blobs/aa/bb/<sha256>.blob           only used when dedup scope is "global"
 *     runtime/rt/u<userId>.seq                   realtime signal files (latest event id)
 *     runtime/locks/*.lock                       flock() mutexes (maintenance, migrations)
 *     logs/<channel>-YYYY-MM-DD.log              structured JSON logs
 *     backups/                                   pre-migration database/JSON backups
 *
 * "trash" and "versions" are logical states in the database (files.deleted_at,
 * file_versions) over the same blobs, so restore and version rollback never copy data.
 */
final class Paths
{
    private static array $ensured = [];

    public static function root(): string
    {
        $root = (string) Config::get('storage.path');
        if (!isset(self::$ensured[$root])) {
            self::ensureDir($root);
            self::protect($root);
            self::$ensured[$root] = true;
        }
        return $root;
    }

    public static function userDir(int $userId, string $sub = ''): string
    {
        if ($userId <= 0) {
            throw new \InvalidArgumentException('Invalid user id');
        }
        $allowed = ['', 'files', 'temp', 'bundles', 'thumbs'];
        if (!in_array($sub, $allowed, true)) {
            throw new \InvalidArgumentException('Invalid storage area');
        }
        $dir = self::root() . '/users/' . $userId . ($sub !== '' ? '/' . $sub : '');
        self::ensureDir($dir);
        return $dir;
    }

    public static function sharedBlobs(): string
    {
        $dir = self::root() . '/shared/blobs';
        self::ensureDir($dir);
        return $dir;
    }

    public static function runtime(string $sub = ''): string
    {
        if ($sub !== '' && !preg_match('/^[a-z0-9_-]+$/', $sub)) {
            throw new \InvalidArgumentException('Invalid runtime area');
        }
        $dir = self::root() . '/runtime' . ($sub !== '' ? '/' . $sub : '');
        self::ensureDir($dir);
        return $dir;
    }

    public static function logs(): string
    {
        $dir = self::root() . '/logs';
        self::ensureDir($dir);
        return $dir;
    }

    public static function backups(): string
    {
        $dir = self::root() . '/backups';
        self::ensureDir($dir);
        return $dir;
    }

    /** Resolve a storage-relative path (as stored in the DB) to an absolute path, refusing traversal. */
    public static function absolute(string $relative): string
    {
        $relative = str_replace('\\', '/', $relative);
        if ($relative === '' || str_contains($relative, '..') || str_starts_with($relative, '/') || preg_match('~^[A-Za-z]:~', $relative) || str_contains($relative, "\0")) {
            throw new \RuntimeException('Invalid storage path');
        }
        return self::root() . '/' . $relative;
    }

    /** Convert an absolute path inside the storage root back to its relative form. */
    public static function relative(string $absolute): string
    {
        $root = self::root() . '/';
        $absolute = str_replace('\\', '/', $absolute);
        if (!str_starts_with($absolute, $root)) {
            throw new \RuntimeException('Path is outside storage');
        }
        return substr($absolute, strlen($root));
    }

    public static function ensureDir(string $dir): void
    {
        if (!is_dir($dir) && !@mkdir($dir, 0775, true) && !is_dir($dir)) {
            throw new \RuntimeException('Storage directory is not writable');
        }
    }

    /**
     * Defence in depth for storage inside the web root (on byethost it must be inside htdocs):
     * deny all HTTP access, stub index files, and a canary file the admin System page fetches
     * from the browser to prove the directory is not publicly readable.
     */
    private static function protect(string $root): void
    {
        $ht = $root . '/.htaccess';
        if (!is_file($ht)) {
            @file_put_contents($ht, "Options -Indexes\nRequire all denied\n");
        }
        if (!is_file($root . '/index.php')) {
            @file_put_contents($root . '/index.php', "<?php http_response_code(404);\n");
        }
        if (!is_file($root . '/index.html')) {
            @file_put_contents($root . '/index.html', '');
        }
        if (!is_file($root . '/canary.json')) {
            @file_put_contents($root . '/canary.json', '{"ft_canary":true}');
        }
    }
}
