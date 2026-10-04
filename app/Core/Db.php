<?php
declare(strict_types=1);

namespace FT\Core;

use PDO;
use PDOStatement;

/**
 * Thin PDO wrapper. ALL SQL must go through prepared statements with bound parameters.
 * Identifiers passed to insert()/update()/delete() are validated against a strict pattern —
 * never pass user input as a table or column name.
 *
 * Dates are stored as UTC DATETIME strings ('Y-m-d H:i:s'); use Db::now() / Db::ts().
 */
final class Db
{
    private static ?PDO $pdo = null;
    private static int $txDepth = 0;

    public static function pdo(): PDO
    {
        if (self::$pdo === null) {
            $host = (string) Config::get('db.host');
            $port = (int) Config::get('db.port');
            $name = (string) Config::get('db.name');
            if ($name === '') {
                throw new \RuntimeException('Database is not configured (DATABASE_NAME is empty).');
            }
            $dsn = "mysql:host={$host};port={$port};dbname={$name};charset=utf8mb4";
            self::$pdo = new PDO($dsn, (string) Config::get('db.user'), (string) Config::get('db.password'), [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,
                PDO::ATTR_STRINGIFY_FETCHES  => false,
                PDO::ATTR_TIMEOUT            => 10,
            ]);
            self::$pdo->exec("SET time_zone = '+00:00'");
            self::$pdo->exec("SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci");
        }
        return self::$pdo;
    }

    /** True if a connection can be established (used by installer / health checks). */
    public static function canConnect(?string &$error = null): bool
    {
        try {
            self::pdo()->query('SELECT 1');
            return true;
        } catch (\Throwable $e) {
            $error = $e->getMessage();
            return false;
        }
    }

    /**
     * Release the connection. Long-running requests (SSE / long-poll) MUST call this before
     * sleeping so they do not hold one of the host's limited MySQL connections.
     */
    public static function disconnect(): void
    {
        if (self::$txDepth === 0) {
            self::$pdo = null;
        }
    }

    /** @param array<int|string,mixed> $params */
    public static function run(string $sql, array $params = []): PDOStatement
    {
        $stmt = self::pdo()->prepare($sql);
        foreach ($params as $k => $v) {
            $key = is_int($k) ? $k + 1 : (str_starts_with((string) $k, ':') ? (string) $k : ':' . $k);
            $type = match (true) {
                is_int($v)  => PDO::PARAM_INT,
                is_bool($v) => PDO::PARAM_INT,
                $v === null => PDO::PARAM_NULL,
                default     => PDO::PARAM_STR,
            };
            $stmt->bindValue($key, is_bool($v) ? (int) $v : $v, $type);
        }
        $stmt->execute();
        return $stmt;
    }

    /** @return array<string,mixed>|null */
    public static function one(string $sql, array $params = []): ?array
    {
        $row = self::run($sql, $params)->fetch();
        return $row === false ? null : $row;
    }

    /** @return array<int,array<string,mixed>> */
    public static function all(string $sql, array $params = []): array
    {
        return self::run($sql, $params)->fetchAll();
    }

    public static function value(string $sql, array $params = []): mixed
    {
        $v = self::run($sql, $params)->fetchColumn();
        return $v === false ? null : $v;
    }

    /** @return array<int,mixed> first column of every row */
    public static function column(string $sql, array $params = []): array
    {
        return self::run($sql, $params)->fetchAll(PDO::FETCH_COLUMN);
    }

    /** @param array<string,mixed> $row */
    public static function insert(string $table, array $row): int
    {
        self::assertIdent($table);
        $cols = array_keys($row);
        array_walk($cols, [self::class, 'assertIdent']);
        $sql = 'INSERT INTO `' . $table . '` (`' . implode('`,`', $cols) . '`) VALUES (' .
            implode(',', array_map(static fn ($c) => ':' . $c, $cols)) . ')';
        self::run($sql, $row);
        return (int) self::pdo()->lastInsertId();
    }

    /**
     * @param array<string,mixed> $set
     * @param array<string,mixed> $where equality conditions joined with AND (NULL => IS NULL)
     */
    public static function update(string $table, array $set, array $where): int
    {
        self::assertIdent($table);
        if ($set === [] || $where === []) {
            throw new \InvalidArgumentException('update() needs both SET and WHERE');
        }
        $params = [];
        $sets = [];
        foreach ($set as $c => $v) {
            self::assertIdent($c);
            $sets[] = "`{$c}` = :s_{$c}";
            $params["s_{$c}"] = $v;
        }
        [$whereSql, $whereParams] = self::buildWhere($where);
        return self::run('UPDATE `' . $table . '` SET ' . implode(', ', $sets) . ' WHERE ' . $whereSql, $params + $whereParams)->rowCount();
    }

    /** @param array<string,mixed> $where */
    public static function delete(string $table, array $where): int
    {
        self::assertIdent($table);
        if ($where === []) {
            throw new \InvalidArgumentException('delete() needs a WHERE');
        }
        [$whereSql, $params] = self::buildWhere($where);
        return self::run('DELETE FROM `' . $table . '` WHERE ' . $whereSql, $params)->rowCount();
    }

    /**
     * Run $fn inside a transaction (nested calls join the outer transaction).
     * @template T
     * @param callable():T $fn
     * @return T
     */
    public static function transaction(callable $fn): mixed
    {
        $pdo = self::pdo();
        if (self::$txDepth === 0) {
            $pdo->beginTransaction();
        }
        self::$txDepth++;
        try {
            $result = $fn();
            self::$txDepth--;
            if (self::$txDepth === 0) {
                $pdo->commit();
            }
            return $result;
        } catch (\Throwable $e) {
            self::$txDepth--;
            if (self::$txDepth === 0 && $pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }

    public static function inTransaction(): bool
    {
        return self::$txDepth > 0;
    }

    /** Escape a value for use inside LIKE (caller adds the % wildcards). */
    public static function like(string $value): string
    {
        return strtr($value, ['\\' => '\\\\', '%' => '\\%', '_' => '\\_']);
    }

    /** Build "IN (:p0,:p1,…)" for a list of ints. @return array{0:string,1:array<string,int>} */
    public static function inList(array $ids, string $prefix = 'in'): array
    {
        $ids = array_values(array_unique(array_map('intval', $ids)));
        if ($ids === []) {
            return ['(NULL)', []];
        }
        $ph = [];
        $params = [];
        foreach ($ids as $i => $id) {
            $ph[] = ":{$prefix}{$i}";
            $params["{$prefix}{$i}"] = $id;
        }
        return ['(' . implode(',', $ph) . ')', $params];
    }

    public static function now(): string
    {
        return gmdate('Y-m-d H:i:s');
    }

    public static function ts(int $unix): string
    {
        return gmdate('Y-m-d H:i:s', $unix);
    }

    /** Convert a stored DATETIME to ISO-8601 (UTC, 'Z'), or null. */
    public static function iso(?string $datetime): ?string
    {
        if ($datetime === null || $datetime === '') {
            return null;
        }
        return str_replace(' ', 'T', $datetime) . 'Z';
    }

    public static function toUnix(?string $datetime): ?int
    {
        if ($datetime === null || $datetime === '') {
            return null;
        }
        $t = strtotime($datetime . ' UTC');
        return $t === false ? null : $t;
    }

    private static function assertIdent(string $ident): void
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $ident)) {
            throw new \InvalidArgumentException('Invalid SQL identifier');
        }
    }

    /** @return array{0:string,1:array<string,mixed>} */
    private static function buildWhere(array $where): array
    {
        $parts = [];
        $params = [];
        foreach ($where as $c => $v) {
            self::assertIdent($c);
            if ($v === null) {
                $parts[] = "`{$c}` IS NULL";
            } else {
                $parts[] = "`{$c}` = :w_{$c}";
                $params["w_{$c}"] = $v;
            }
        }
        return [implode(' AND ', $parts), $params];
    }
}
