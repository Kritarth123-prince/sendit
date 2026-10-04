<?php
declare(strict_types=1);

namespace FT\Database;

use FT\Core\Db;
use FT\Core\Logger;
use FT\Storage\Paths;

/**
 * Applies database/migrations/NNN_name.sql (and NNN_name.php returning a callable) in order,
 * exactly once each, recording them in schema_migrations. Safe to run repeatedly.
 * Never edit an applied migration — add a new one.
 */
final class Migrator
{
    public static function dir(): string
    {
        return FT_ROOT . '/database/migrations';
    }

    /** @return array<int,array{version:string,file:string,applied:bool,applied_at:?string}> */
    public static function status(): array
    {
        self::ensureTable();
        $applied = [];
        foreach (Db::all('SELECT version, applied_at FROM schema_migrations') as $row) {
            $applied[$row['version']] = $row['applied_at'];
        }
        $out = [];
        foreach (self::files() as $version => $file) {
            $out[] = [
                'version' => $version,
                'file' => basename($file),
                'applied' => isset($applied[$version]),
                'applied_at' => $applied[$version] ?? null,
            ];
        }
        return $out;
    }

    /** @return string[] pending versions */
    public static function pending(): array
    {
        return array_values(array_map(static fn ($s) => $s['version'], array_filter(self::status(), static fn ($s) => !$s['applied'])));
    }

    /**
     * Apply all pending migrations. Takes a DB-level lock so two requests cannot migrate at once.
     * @return string[] applied versions
     */
    public static function migrate(bool $backupFirst = true): array
    {
        self::ensureTable();
        $pending = self::pending();
        if ($pending === []) {
            return [];
        }
        // MySQL user-level locks are global to the whole server (all accounts and databases), so the
        // name is scoped to this database: unrelated installations on a shared MySQL server must not
        // block each other's migrations. Hashed to stay within the 64-character lock name limit.
        $lock = 'ft_migrate:' . substr(sha1((string) Db::value('SELECT DATABASE()')), 0, 40);
        $got = (int) Db::value('SELECT GET_LOCK(?, 30)', [$lock]);
        if ($got !== 1) {
            throw new \RuntimeException('Another migration is already running.');
        }
        $done = [];
        try {
            if ($backupFirst && self::hasUserData()) {
                self::backup('pre-migrate');
            }
            $files = self::files();
            foreach (self::pending() as $version) {
                $file = $files[$version];
                $started = microtime(true);
                if (str_ends_with($file, '.php')) {
                    $fn = require $file;
                    if (is_callable($fn)) {
                        $fn();
                    }
                } else {
                    foreach (self::splitSql((string) file_get_contents($file)) as $stmt) {
                        Db::pdo()->exec($stmt);
                    }
                }
                Db::insert('schema_migrations', [
                    'version' => $version,
                    'checksum' => hash_file('sha256', $file),
                    'applied_at' => Db::now(),
                ]);
                Logger::info('migration', 'Applied migration', ['version' => $version, 'ms' => (int) ((microtime(true) - $started) * 1000)]);
                $done[] = $version;
            }
        } finally {
            Db::value('SELECT RELEASE_LOCK(?)', [$lock]);
        }
        return $done;
    }

    /** True when the core schema exists (used to decide whether to show the installer). */
    public static function isInstalled(): bool
    {
        try {
            $t = Db::value("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name IN ('users','schema_migrations')");
            return (int) $t === 2 && self::pending() === [];
        } catch (\Throwable) {
            return false;
        }
    }

    /**
     * Logical SQL backup of all app tables to storage/backups/<label>-<timestamp>.sql.gz.
     * Shared hosts have no mysqldump, so this is done in PHP, in batches.
     */
    public static function backup(string $label = 'manual'): ?string
    {
        $tables = Db::column("SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name");
        if ($tables === []) {
            return null;
        }
        // Written as numbered parts (≤ 8 MB uncompressed each) because some hosts delete files > 10 MB.
        $prefix = Paths::backups() . '/' . preg_replace('/[^a-z0-9_-]/i', '', $label) . '-' . gmdate('Ymd-His');
        $part = 1;
        $written = 0;
        $path = $prefix . '.part1.sql.gz';
        $gz = gzopen($path, 'wb6');
        if ($gz === false) {
            throw new \RuntimeException('Cannot write backup file');
        }
        $write = static function (string $s) use (&$gz, &$written, &$part, $prefix): void {
            if ($written + strlen($s) > 8 * 1024 * 1024 && $written > 0) {
                gzclose($gz);
                $part++;
                $gz = gzopen($prefix . '.part' . $part . '.sql.gz', 'wb6');
                $written = 0;
                gzwrite($gz, "SET FOREIGN_KEY_CHECKS=0;\n");
            }
            gzwrite($gz, $s);
            $written += strlen($s);
        };
        $pdo = Db::pdo();
        $write("-- FastTransfer backup " . gmdate('c') . "\nSET FOREIGN_KEY_CHECKS=0;\n");
        foreach ($tables as $table) {
            if (!preg_match('/^[A-Za-z0-9_]+$/', (string) $table) || in_array($table, ['rate_limits', 'event_recipients', 'events'], true)) {
                continue;
            }
            $create = Db::one('SHOW CREATE TABLE `' . $table . '`');
            $write("\nDROP TABLE IF EXISTS `{$table}`;\n" . array_values($create ?? [])[1] . ";\n");
            $offset = 0;
            while (true) {
                $rows = Db::all('SELECT * FROM `' . $table . '` LIMIT 500 OFFSET ' . $offset);
                if ($rows === []) {
                    break;
                }
                foreach ($rows as $row) {
                    $vals = array_map(static fn ($v) => $v === null ? 'NULL' : $pdo->quote((string) $v), array_values($row));
                    $write('INSERT INTO `' . $table . '` VALUES (' . implode(',', $vals) . ");\n");
                }
                $offset += 500;
            }
        }
        $write("SET FOREIGN_KEY_CHECKS=1;\n");
        gzclose($gz);
        Logger::info('migration', 'Database backup written', ['file' => basename($path)]);
        return $path;
    }

    /** @return string[] SQL statements, splitting on ; outside quotes/comments */
    public static function splitSql(string $sql): array
    {
        $out = [];
        $buf = '';
        $len = strlen($sql);
        $quote = null;
        for ($i = 0; $i < $len; $i++) {
            $c = $sql[$i];
            $next = $i + 1 < $len ? $sql[$i + 1] : '';
            if ($quote === null) {
                if ($c === '-' && $next === '-') { // line comment
                    $nl = strpos($sql, "\n", $i);
                    $i = $nl === false ? $len : $nl;
                    $buf .= "\n";
                    continue;
                }
                if ($c === '/' && $next === '*') {
                    $end = strpos($sql, '*/', $i + 2);
                    $i = $end === false ? $len : $end + 1;
                    continue;
                }
                if ($c === "'" || $c === '"' || $c === '`') {
                    $quote = $c;
                } elseif ($c === ';') {
                    if (trim($buf) !== '') {
                        $out[] = trim($buf);
                    }
                    $buf = '';
                    continue;
                }
            } elseif ($c === $quote) {
                if ($next === $quote) { // escaped by doubling
                    $buf .= $c . $next;
                    $i++;
                    continue;
                }
                $quote = null;
            } elseif ($c === '\\' && $quote !== '`') {
                $buf .= $c . $next;
                $i++;
                continue;
            }
            $buf .= $c;
        }
        if (trim($buf) !== '') {
            $out[] = trim($buf);
        }
        return $out;
    }

    /** @return array<string,string> version => absolute file path, sorted */
    private static function files(): array
    {
        $files = array_merge(glob(self::dir() . '/*.sql') ?: [], glob(self::dir() . '/*.php') ?: []);
        $out = [];
        foreach ($files as $f) {
            $version = pathinfo($f, PATHINFO_FILENAME);
            if (preg_match('/^\d{3}_[a-z0-9_]+$/', $version)) {
                $out[$version] = $f;
            }
        }
        ksort($out, SORT_STRING);
        return $out;
    }

    private static function ensureTable(): void
    {
        Db::pdo()->exec('CREATE TABLE IF NOT EXISTS schema_migrations (
            version VARCHAR(100) NOT NULL PRIMARY KEY,
            checksum CHAR(64) NOT NULL,
            applied_at DATETIME NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci');
    }

    private static function hasUserData(): bool
    {
        try {
            return (int) Db::value("SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = 'users'") === 1
                && (int) Db::value('SELECT COUNT(*) FROM users') > 0;
        } catch (\Throwable) {
            return false;
        }
    }
}
