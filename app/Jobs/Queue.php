<?php
declare(strict_types=1);

namespace FT\Jobs;

use FT\Core\Db;
use FT\Core\Lifecycle;
use FT\Core\Logger;

/**
 * Database-backed job queue for slow work (Web Push, e-mail, Slack, OCR, thumbnails, ZIPs).
 * There is no daemon on shared hosting, so jobs are processed:
 *   1. right after the response of the request that queued them (Lifecycle::terminate),
 *   2. by the pseudo-cron / maintenance runs.
 *
 * A job "type" is a static handler reference "FT\Some\Class::somethingJob" taking the payload
 * array. Handlers must be idempotent (a job can run twice if a worker dies mid-way).
 *
 *     Queue::push(\FT\Notifications\WebPush::class . '::deliverJob', ['subscription_id' => 5, …]);
 */
final class Queue
{
    public static function push(string $type, array $payload = [], int $delaySeconds = 0, string $queue = 'default', int $maxAttempts = 3): int
    {
        self::assertHandler($type);
        $id = Db::insert('jobs', [
            'queue'        => $queue,
            'type'         => $type,
            'payload'      => json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
            'attempts'     => 0,
            'max_attempts' => max(1, min(10, $maxAttempts)),
            'available_at' => Db::ts(time() + max(0, $delaySeconds)),
            'created_at'   => Db::now(),
        ]);
        if ($delaySeconds === 0) {
            Lifecycle::onTerminate('queue', static fn () => self::work(Lifecycle::budget(), 5));
        }
        return $id;
    }

    /** Process jobs for up to $maxSeconds. Returns the number of jobs processed. */
    public static function work(float $maxSeconds = 5.0, int $maxJobs = 25, ?string $queue = null): int
    {
        $deadline = microtime(true) + $maxSeconds;
        $done = 0;
        // Release jobs whose worker died (reserved > 10 min ago).
        Db::run('UPDATE jobs SET reserved_at = NULL, reserved_by = NULL WHERE failed_at IS NULL AND reserved_at IS NOT NULL AND reserved_at < ?', [Db::ts(time() - 600)]);
        while ($done < $maxJobs && microtime(true) < $deadline) {
            $job = self::reserve($queue);
            if ($job === null) {
                break;
            }
            $done++;
            try {
                self::assertHandler((string) $job['type']);
                [$class, $method] = explode('::', (string) $job['type'], 2);
                $payload = json_decode((string) $job['payload'], true) ?: [];
                $class::$method($payload);
                Db::delete('jobs', ['id' => (int) $job['id']]);
            } catch (\Throwable $e) {
                $attempts = (int) $job['attempts'];
                $failed = $attempts >= (int) $job['max_attempts'];
                Db::update('jobs', [
                    'reserved_at'  => null,
                    'reserved_by'  => null,
                    'last_error'   => mb_substr(get_class($e) . ': ' . $e->getMessage(), 0, 1000),
                    'failed_at'    => $failed ? Db::now() : null,
                    'available_at' => Db::ts(time() + min(3600, 30 * (2 ** $attempts))), // backoff
                ], ['id' => (int) $job['id']]);
                Logger::warning('app', 'Job failed', ['type' => $job['type'], 'attempt' => $attempts, 'final' => $failed, 'error' => $e->getMessage()]);
            }
        }
        return $done;
    }

    /** @return array<string,mixed>|null */
    private static function reserve(?string $queue): ?array
    {
        $token = bin2hex(random_bytes(8));
        $params = ['now' => Db::now(), 'tok' => $token, 'now2' => Db::now()];
        $qsql = '';
        if ($queue !== null) {
            $qsql = ' AND queue = :q';
            $params['q'] = $queue;
        }
        // Atomic claim without SELECT … FOR UPDATE SKIP LOCKED (not available on MySQL 5.7).
        $n = Db::run(
            "UPDATE jobs SET reserved_at = :now2, reserved_by = :tok, attempts = attempts + 1
             WHERE failed_at IS NULL AND reserved_at IS NULL AND available_at <= :now{$qsql}
             ORDER BY id ASC LIMIT 1",
            $params
        )->rowCount();
        if ($n === 0) {
            return null;
        }
        return Db::one('SELECT * FROM jobs WHERE reserved_by = ? LIMIT 1', [$token]);
    }

    private static function assertHandler(string $type): void
    {
        if (!preg_match('/^FT\\\\[A-Za-z0-9\\\\]+::[a-z][A-Za-z0-9]*Job$/', $type)) {
            throw new \InvalidArgumentException('Invalid job type: ' . $type);
        }
        [$class, $method] = explode('::', $type, 2);
        if (!class_exists($class) || !method_exists($class, $method)) {
            throw new \InvalidArgumentException('Unknown job handler: ' . $type);
        }
    }

    /** @return array{pending:int,failed:int,reserved:int} */
    public static function counts(): array
    {
        $row = Db::one('SELECT
            SUM(failed_at IS NULL AND reserved_at IS NULL) AS pending,
            SUM(failed_at IS NOT NULL) AS failed,
            SUM(failed_at IS NULL AND reserved_at IS NOT NULL) AS reserved FROM jobs') ?? [];
        return ['pending' => (int) ($row['pending'] ?? 0), 'failed' => (int) ($row['failed'] ?? 0), 'reserved' => (int) ($row['reserved'] ?? 0)];
    }
}
