<?php
declare(strict_types=1);

namespace FT\Support;

use FT\Core\Config;
use FT\Core\Secrets;
use FT\Storage\Paths;

/**
 * Cheap "is the app installed and up to date?" check that runs on every request without
 * touching the database: compares storage/runtime/installed.json with the newest migration
 * file. The web installer (/install) writes the marker after migrating and creating the admin.
 */
final class Install
{
    public static function isReady(): bool
    {
        if ((string) Config::get('db.name') === '' || !Secrets::isConfigured()) {
            return false;
        }
        $marker = self::marker();
        // The marker must belong to THIS database: a storage/ folder copied from another machine
        // (e.g. uploaded from a local test install) must not make a fresh server look installed.
        return $marker !== null
            && ($marker['schema'] ?? '') === self::latestMigration()
            && hash_equals(self::databaseFingerprint(), (string) ($marker['db'] ?? ''));
    }

    /** Identifies the configured database without revealing credentials. */
    public static function databaseFingerprint(): string
    {
        return hash('sha256', 'ft-install|' . strtolower((string) Config::get('db.host')) . '|' . (int) Config::get('db.port') . '|' . (string) Config::get('db.name'));
    }

    /** @return array<string,mixed>|null */
    public static function marker(): ?array
    {
        try {
            $file = Paths::runtime() . '/installed.json';
        } catch (\Throwable) {
            return null;
        }
        if (!is_file($file)) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($file), true);
        return is_array($data) ? $data : null;
    }

    public static function markInstalled(array $extra = []): void
    {
        $data = array_merge(self::marker() ?? [], $extra, [
            'db'         => self::databaseFingerprint(),
            'schema'     => self::latestMigration(),
            'version'    => FT_VERSION,
            'updated_at' => gmdate('c'),
        ]);
        file_put_contents(Paths::runtime() . '/installed.json', json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), LOCK_EX);
    }

    public static function latestMigration(): string
    {
        $files = array_merge(glob(FT_ROOT . '/database/migrations/*.sql') ?: [], glob(FT_ROOT . '/database/migrations/*.php') ?: []);
        $names = array_map(static fn ($f) => pathinfo($f, PATHINFO_FILENAME), $files);
        sort($names, SORT_STRING);
        return (string) end($names);
    }
}
