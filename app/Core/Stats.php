<?php
declare(strict_types=1);

namespace FT\Core;

/**
 * Daily counters for the admin dashboard charts (uploads, downloads, new users, …).
 * Metrics: uploads, upload_bytes, downloads, new_users, shares_created, failed_uploads,
 *          storage_bytes (snapshot, set by maintenance), logins, deletes.
 */
final class Stats
{
    public static function bump(string $metric, int $by = 1): void
    {
        try {
            Db::run(
                'INSERT INTO daily_stats (day, metric, value) VALUES (UTC_DATE(), :m, :v)
                 ON DUPLICATE KEY UPDATE value = value + VALUES(value)',
                ['m' => mb_substr($metric, 0, 32), 'v' => $by]
            );
        } catch (\Throwable $e) {
            Logger::warning('app', 'Stats bump failed', ['metric' => $metric, 'error' => $e->getMessage()]);
        }
    }

    public static function setToday(string $metric, int $value): void
    {
        Db::run(
            'INSERT INTO daily_stats (day, metric, value) VALUES (UTC_DATE(), :m, :v)
             ON DUPLICATE KEY UPDATE value = VALUES(value)',
            ['m' => mb_substr($metric, 0, 32), 'v' => $value]
        );
    }

    /** @return array<string,array<string,int>> metric => [Y-m-d => value] for the last $days days */
    public static function series(array $metrics, int $days = 30): array
    {
        $out = [];
        foreach ($metrics as $m) {
            $out[$m] = [];
            for ($i = $days - 1; $i >= 0; $i--) {
                $out[$m][gmdate('Y-m-d', time() - $i * 86400)] = 0;
            }
        }
        [$in, $params] = self::inStrings($metrics);
        $params['since'] = gmdate('Y-m-d', time() - ($days - 1) * 86400);
        foreach (Db::all("SELECT day, metric, value FROM daily_stats WHERE metric IN {$in} AND day >= :since", $params) as $row) {
            if (isset($out[$row['metric']][$row['day']])) {
                $out[$row['metric']][$row['day']] = (int) $row['value'];
            }
        }
        return $out;
    }

    /** @return array{0:string,1:array<string,string>} */
    private static function inStrings(array $values): array
    {
        $ph = [];
        $params = [];
        foreach (array_values($values) as $i => $v) {
            $ph[] = ':m' . $i;
            $params['m' . $i] = (string) $v;
        }
        return ['(' . ($ph ? implode(',', $ph) : 'NULL') . ')', $params];
    }
}
