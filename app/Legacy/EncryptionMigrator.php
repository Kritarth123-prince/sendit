<?php
declare(strict_types=1);

namespace FT\Legacy;

use FT\Core\Db;
use FT\Core\Logger;
use FT\Storage\BlobStore;
use FT\Storage\Crypto;
use FT\Storage\LegacyCbc;
use FT\Storage\Paths;

/**
 * Converts stored blobs to the current encryption format (docs/ARCHITECTURE.md §8.2, §13.1):
 *   legacy_cbc → gcm1   (always, as soon as encryption is enabled: CBC is unauthenticated and its
 *                        key file is a liability)
 *   none       → gcm1   (when Crypto::enabled())
 *   gcm1 (old key id) → re-wrapped with the current key (key rotation)
 *
 * All the heavy lifting is BlobStore::reencode() (A2), which streams, verifies the plaintext
 * SHA-256 against the row BEFORE swapping and leaves the blob untouched on any mismatch — so a
 * failure here can never corrupt data. Per-blob failures are remembered in a small runtime file
 * and skipped for a day (no endless retries of a damaged file); the admin sees them in status().
 *
 * Time-boxed: blobs are picked smallest first and a blob is only started when its estimated
 * duration fits the remaining budget (the first blob of a batch always runs, so huge files make
 * progress when an administrator or the CLI runs a batch with a large budget).
 */
final class EncryptionMigrator
{
    /** Bytes per second assumed for planning (decrypt + encrypt + write). */
    private const THROUGHPUT = 15 * 1024 * 1024;
    private const RETRY_FAILED_AFTER = 86400;

    /** @return array<string,mixed> counts by encoding, pending work and recent failures */
    public static function status(): array
    {
        $by = [];
        foreach (Db::all('SELECT encryption, COUNT(*) AS n, COALESCE(SUM(size), 0) AS bytes, COALESCE(SUM(stored_size), 0) AS stored_bytes FROM file_blobs GROUP BY encryption') as $r) {
            $by[(string) $r['encryption']] = ['count' => (int) $r['n'], 'bytes' => (int) $r['bytes'], 'stored_bytes' => (int) $r['stored_bytes']];
        }
        foreach (['none', 'gcm1', 'legacy_cbc'] as $k) {
            $by[$k] ??= ['count' => 0, 'bytes' => 0, 'stored_bytes' => 0];
        }
        $enabled = Crypto::enabled();
        $current = $enabled ? (string) Crypto::currentKeyId() : null;
        $oldKey = $enabled ? (int) Db::value("SELECT COUNT(*) FROM file_blobs WHERE encryption = 'gcm1' AND (enc_key_id IS NULL OR enc_key_id <> ?)", [$current]) : 0;
        $pending = $enabled ? $by['legacy_cbc']['count'] + $by['none']['count'] + $oldKey : 0;
        $failures = self::failures();
        return [
            'enabled'          => $enabled,
            'key_id'           => $current,
            'by_encryption'    => $by,
            'old_key_blobs'    => $oldKey,
            'pending'          => $pending,
            'legacy_key_available' => LegacyCbc::available(),
            'failed'           => count($failures),
            'failures'         => array_slice(array_map(static fn ($id, $f) => ['blob_id' => (int) $id, 'error' => (string) $f['error'], 'at' => gmdate('Y-m-d\TH:i:s\Z', (int) $f['at'])], array_keys($failures), $failures), 0, 20),
            'done'             => !$enabled || $pending === 0,
        ];
    }

    /**
     * Convert as many blobs as fit into $budgetSeconds.
     * @return array{migrated:int,converted:int,failed:int,skipped:int,remaining:int,done:bool,errors:array,message:?string}
     */
    public static function migrateBatch(float $budgetSeconds = 15.0): array
    {
        $deadline = microtime(true) + max(0.5, $budgetSeconds);
        $result = ['migrated' => 0, 'failed' => 0, 'skipped' => 0, 'remaining' => 0, 'done' => false, 'errors' => [], 'message' => null];
        if (!Crypto::enabled()) {
            $result['done'] = true;
            $result['converted'] = 0;
            $result['message'] = 'Encryption is not enabled (set ENCRYPTION_KEY in .env), so there is nothing to convert.';
            return $result;
        }
        $failures = self::failures();
        $skipIds = array_keys(array_filter($failures, static fn ($f) => time() - (int) $f['at'] < self::RETRY_FAILED_AFTER));
        $legacyOk = LegacyCbc::available();
        if (!$legacyOk && (int) Db::value("SELECT COUNT(*) FROM file_blobs WHERE encryption = 'legacy_cbc'") > 0) {
            $result['message'] = 'Old encrypted files are waiting, but the old key file (uploads/.enc_key) is missing.';
        }
        $current = (string) Crypto::currentKeyId();
        $started = 0;
        $changed = false;
        while (microtime(true) < $deadline) {
            [$notIn, $p] = Db::inList($skipIds !== [] ? $skipIds : [0], 'sk');
            $p['cur'] = $current;
            $encodings = $legacyOk ? "'legacy_cbc', 'none'" : "'none'";
            $rows = Db::all(
                "SELECT * FROM file_blobs
                  WHERE id NOT IN {$notIn}
                    AND (encryption IN ({$encodings}) OR (encryption = 'gcm1' AND (enc_key_id IS NULL OR enc_key_id <> :cur)))
                  ORDER BY (encryption = 'legacy_cbc') DESC, size ASC, id ASC LIMIT 20",
                $p
            );
            if ($rows === []) {
                break;
            }
            $progress = false;
            foreach ($rows as $row) {
                $left = $deadline - microtime(true);
                $estimate = 0.05 + (int) $row['size'] / self::THROUGHPUT;
                if ($left <= 0 || ($started > 0 && $estimate > $left)) {
                    break 2;
                }
                $started++;
                $id = (int) $row['id'];
                try {
                    BlobStore::reencode($row);
                    $result['migrated']++;
                    $progress = true;
                    $changed = true;
                    unset($failures[$id]);
                } catch (\Throwable $e) {
                    $msg = self::safe($e->getMessage());
                    $failures[$id] = ['error' => $msg, 'at' => time(), 'attempts' => (int) ($failures[$id]['attempts'] ?? 0) + 1];
                    $skipIds[] = $id;
                    $result['failed']++;
                    $result['errors'][] = ['blob_id' => $id, 'error' => $msg];
                    $changed = true;
                    Logger::warning('maintenance', 'Blob re-encryption failed; blob left unchanged', ['blob_id' => $id, 'error' => $msg]);
                }
            }
            if (!$progress && $result['failed'] === 0) {
                break;
            }
        }
        if ($changed) {
            self::saveFailures($failures);
        }
        [$notIn, $p] = Db::inList($skipIds !== [] ? $skipIds : [0], 'sr');
        $p['cur'] = $current;
        $encodings = $legacyOk ? "'legacy_cbc', 'none'" : "'none'";
        $result['remaining'] = (int) Db::value(
            "SELECT COUNT(*) FROM file_blobs WHERE id NOT IN {$notIn}
               AND (encryption IN ({$encodings}) OR (encryption = 'gcm1' AND (enc_key_id IS NULL OR enc_key_id <> :cur)))",
            $p
        );
        $result['done'] = $result['remaining'] === 0;
        $result['converted'] = $result['migrated'];
        return $result;
    }

    /** Forget recorded failures so the next batch retries them (admin action). */
    public static function clearFailures(): void
    {
        self::saveFailures([]);
    }

    /** @return array<int,array{error:string,at:int,attempts:int}> */
    private static function failures(): array
    {
        $file = self::failureFile();
        if (!is_file($file)) {
            return [];
        }
        $d = json_decode((string) @file_get_contents($file), true);
        if (!is_array($d)) {
            return [];
        }
        $out = [];
        foreach ($d as $id => $f) {
            if (is_array($f) && (int) $id > 0) {
                $out[(int) $id] = ['error' => (string) ($f['error'] ?? ''), 'at' => (int) ($f['at'] ?? 0), 'attempts' => (int) ($f['attempts'] ?? 1)];
            }
        }
        return $out;
    }

    private static function saveFailures(array $failures): void
    {
        // Keep the file small: at most 500 most recent failures.
        uasort($failures, static fn ($a, $b) => $b['at'] <=> $a['at']);
        $failures = array_slice($failures, 0, 500, true);
        $tmp = self::failureFile() . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, (string) json_encode($failures)) !== false) {
            @rename($tmp, self::failureFile());
        }
    }

    private static function failureFile(): string
    {
        return Paths::runtime() . '/encryption_failures.json';
    }

    private static function safe(string $m): string
    {
        $m = str_replace('\\', '/', $m);
        $m = str_replace([str_replace('\\', '/', FT_ROOT), str_replace('\\', '/', Paths::root())], '…', $m);
        return mb_substr($m, 0, 300);
    }
}
