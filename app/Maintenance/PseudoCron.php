<?php
declare(strict_types=1);

namespace FT\Maintenance;

use FT\Core\Config;
use FT\Core\Lifecycle;
use FT\Core\Logger;
use FT\Storage\Paths;
use FT\Support\Install;

/**
 * "Poor man's cron" for hosts without cron (docs/ARCHITECTURE.md §0.2, §13.1).
 *
 * index.php registers maybeRun() as a post-response callback. At most once per
 * PSEUDO_CRON_INTERVAL seconds a request runs a maintenance slice with Lifecycle::budget()
 * seconds (1.5 s on hosts that cannot finish the response early, so visitors never wait long);
 * the runner's cursor makes consecutive slices cover every task. The leader browser tab's
 * POST /api/v1/tick drives the same slice with a larger budget.
 *
 * The decision is made from a tiny JSON state file (runtime/pseudo_cron.json) without touching
 * the database; a non-blocking flock makes sure only one request claims each interval.
 */
final class PseudoCron
{
    /** Post-response hook. Never throws, never blocks. */
    public static function maybeRun(): void
    {
        try {
            if (!Config::get('pseudo_cron.enabled') || !Install::isReady() || !self::due()) {
                return;
            }
            self::runSlice('pseudo', min(8.0, Lifecycle::budget()));
        } catch (\Throwable $e) {
            Logger::exception('maintenance', $e, ['pseudo_cron' => true]);
        }
    }

    public static function interval(): int
    {
        return max(60, (int) Config::get('pseudo_cron.interval', 300));
    }

    /** True when the last claimed slice is older than the interval. */
    public static function due(): bool
    {
        $last = (int) (self::state()['last_attempt'] ?? 0);
        return time() - $last >= self::interval();
    }

    /**
     * Claim the current interval and run a maintenance slice. Returns the runner result, or null
     * when another request claimed the interval first (or it is not due).
     */
    public static function runSlice(string $trigger, float $budgetSeconds): ?array
    {
        $lock = @fopen(Paths::runtime('locks') . '/pseudo_cron.lock', 'c');
        if ($lock === false) {
            return null;
        }
        try {
            if (!flock($lock, LOCK_EX | LOCK_NB)) {
                return null;
            }
            $state = self::state();
            if (time() - (int) ($state['last_attempt'] ?? 0) < self::interval()) {
                return null; // someone else ran it a moment ago
            }
            $state['last_attempt'] = time();
            self::save($state);
            flock($lock, LOCK_UN);

            $result = MaintenanceRunner::run($trigger, null, $budgetSeconds);

            $state = self::state();
            $state['last_run'] = [
                'at'          => gmdate('Y-m-d\TH:i:s\Z'),
                'trigger'     => $trigger,
                'run_id'      => $result['run_id'],
                'skipped'     => (bool) $result['skipped'],
                'complete'    => (bool) $result['complete'],
                'tasks'       => count($result['tasks']),
                'errors'      => count(array_filter($result['tasks'], static fn ($t) => ($t['status'] ?? '') === 'error')),
                'duration_ms' => (int) $result['duration_ms'],
            ];
            self::save($state);
            return $result;
        } finally {
            @flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /** @return array<string,mixed> {last_attempt:int, last_run:{…}} */
    public static function state(): array
    {
        $file = self::file();
        clearstatcache(true, $file);
        if (!is_file($file)) {
            return [];
        }
        $d = json_decode((string) @file_get_contents($file), true);
        return is_array($d) ? $d : [];
    }

    /** Summary for the admin System page. */
    public static function status(): array
    {
        $s = self::state();
        $last = (int) ($s['last_attempt'] ?? 0);
        return [
            'enabled'         => (bool) Config::get('pseudo_cron.enabled'),
            'interval'        => self::interval(),
            'budget_seconds'  => min(8.0, Lifecycle::budget()),
            'last_attempt_at' => $last > 0 ? gmdate('Y-m-d\TH:i:s\Z', $last) : null,
            'next_due_at'     => gmdate('Y-m-d\TH:i:s\Z', max(time(), $last + self::interval())),
            'last_run'        => $s['last_run'] ?? null,
        ];
    }

    /** Test hook: forget when the last slice ran. */
    public static function reset(): void
    {
        @unlink(self::file());
    }

    private static function save(array $state): void
    {
        $file = self::file();
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, (string) json_encode($state, JSON_UNESCAPED_SLASHES)) === false) {
            return;
        }
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
            @file_put_contents($file, (string) json_encode($state, JSON_UNESCAPED_SLASHES), LOCK_EX);
        }
    }

    private static function file(): string
    {
        return Paths::runtime() . '/pseudo_cron.json';
    }
}
