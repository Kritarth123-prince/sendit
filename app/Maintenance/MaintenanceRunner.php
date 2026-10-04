<?php
declare(strict_types=1);

namespace FT\Maintenance;

use FT\Admin\StatsService;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\RequestContext;
use FT\Core\Settings;
use FT\Core\Stats;
use FT\Events\EventBus;
use FT\Jobs\Queue;
use FT\Legacy\EncryptionMigrator;
use FT\Security\RateLimiter;
use FT\Storage\Crypto;
use FT\Storage\Paths;
use FT\Support\Install;

/**
 * Housekeeping (docs/ARCHITECTURE.md §13.1). There is no cron or daemon on shared hosting, so the
 * same runner is driven by the CLI (maintenance.php), a token-protected URL, the admin "Run now"
 * button, the leader tab's /tick and the post-response pseudo-cron.
 *
 * Every task is idempotent (running twice changes nothing the second time), time-boxed against
 * the run's deadline and logged to maintenance_logs. Runs are exclusive (non-blocking flock on
 * runtime/locks/maintenance.lock — a second runner simply skips). When the budget runs out the
 * remaining tasks are left for the next run: a cursor in runtime/maintenance.json rotates the
 * start position, so even 1.5 s pseudo-cron slices eventually cover every task.
 *
 * Tasks owned by other modules are called only when their method exists (otherwise the task is
 * logged as "skipped"); the rest is plain SQL / file housekeeping implemented here.
 */
final class MaintenanceRunner
{
    /** Scheduled tasks, in priority order. */
    public const TASKS = [
        'expire_shares', 'expire_sessions', 'auto_expire_files', 'expire_texts', 'cleanup_uploads', 'purge_trash',
        'prune_versions', 'cleanup_bundles', 'prune_events', 'prune_audit', 'prune_login_history', 'prune_notifications',
        'prune_rate_limits', 'prune_presence', 'orphan_records', 'unreferenced_blobs', 'reconcile_quotas', 'process_jobs',
        'snapshot_stats', 'encryption_migration', 'prune_logs',
    ];

    /** Tasks that only run when asked for by name (outbound network calls). */
    public const ON_DEMAND = ['egress_check'];

    public const TRIGGERS = ['cli', 'web', 'pseudo', 'admin', 'tick'];

    /** Upload temp data younger than this is never touched (an assembly may be running). */
    private const TEMP_GRACE_SECONDS = 3600;
    /** BlobStore temp dirs ("blob-…") older than this are left-overs of crashed writes. */
    private const BLOB_TEMP_MAX_AGE = 6 * 3600;
    private const LOG_RETENTION_DAYS = 30;
    private const SESSION_ROW_RETENTION_DAYS = 90;
    private const UPLOAD_ROW_RETENTION_DAYS = 7;

    /**
     * Run maintenance. $tasks = null runs the scheduled list (resuming at the cursor);
     * otherwise exactly the named tasks (scheduled or on-demand) in the given order.
     * @return array{run_id:string,trigger:string,skipped:bool,reason?:string,complete:bool,started_at:string,duration_ms:int,tasks:array<string,array>}
     */
    public static function run(string $trigger, ?array $tasks = null, float $budgetSeconds = 20.0): array
    {
        $trigger = in_array($trigger, self::TRIGGERS, true) ? $trigger : 'admin';
        $runId = bin2hex(random_bytes(8));
        $started = microtime(true);
        $deadline = $started + max(0.2, min(900.0, $budgetSeconds));
        $base = ['run_id' => $runId, 'trigger' => $trigger, 'skipped' => false, 'complete' => false, 'started_at' => gmdate('Y-m-d\TH:i:s\Z'), 'duration_ms' => 0, 'tasks' => []];

        if ($tasks !== null) {
            $tasks = array_values(array_unique(array_map('strval', $tasks)));
            foreach ($tasks as $t) {
                if (!self::isTask($t)) {
                    throw new \InvalidArgumentException('Unknown maintenance task: ' . $t);
                }
            }
        }

        $lock = self::acquireLock();
        if ($lock === null) {
            return ['skipped' => true, 'reason' => 'Another maintenance run is in progress.'] + $base;
        }

        // Maintenance acts as the system, never as whoever's request happened to trigger it.
        $prevUser = RequestContext::userId();
        RequestContext::setUserId(null);
        try {
            $state = self::state();
            $n = count(self::TASKS);
            if ($tasks === null) {
                $cursor = ((int) ($state['cursor'] ?? 0)) % $n;
                $list = array_merge(array_slice(self::TASKS, $cursor), array_slice(self::TASKS, 0, $cursor));
            } else {
                $cursor = 0;
                $list = $tasks;
            }
            $ran = 0;
            foreach ($list as $i => $task) {
                if ($ran > 0 && microtime(true) >= $deadline - 0.02) {
                    break;
                }
                $base['tasks'][$task] = self::runTask($task, $runId, $trigger, $deadline, $state);
                $ran++;
                if ($tasks === null) {
                    $state['cursor'] = ($cursor + $i + 1) % $n;
                }
            }
            $base['complete'] = $ran === count($list);
            $base['duration_ms'] = (int) ((microtime(true) - $started) * 1000);
            $errors = count(array_filter($base['tasks'], static fn ($r) => $r['status'] === 'error'));
            $state['last_run'] = [
                'run_id'      => $runId,
                'trigger'     => $trigger,
                'at'          => gmdate('Y-m-d\TH:i:s\Z'),
                'complete'    => $base['complete'],
                'tasks'       => count($base['tasks']),
                'errors'      => $errors,
                'duration_ms' => $base['duration_ms'],
            ];
            self::saveState($state);
            return $base;
        } finally {
            RequestContext::setUserId($prevUser);
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    public static function isTask(string $task): bool
    {
        return in_array($task, self::TASKS, true) || in_array($task, self::ON_DEMAND, true);
    }

    /** @return array<string,mixed> runtime/maintenance.json (cursor, last run, batch cursors) */
    public static function state(): array
    {
        $file = self::stateFile();
        if (!is_file($file)) {
            return [];
        }
        $d = json_decode((string) @file_get_contents($file), true);
        return is_array($d) ? $d : [];
    }

    /**
     * Shared by maintenance.php (web mode) and GET /maintenance: token check (constant-time;
     * refused when MAINTENANCE_TOKEN is unset or shorter than 16 characters), failed attempts
     * rate-limited per IP, then a 20 s run. @return array{0:int,1:array} HTTP status + JSON body
     */
    public static function httpRun(?string $token, ?string $taskParam, string $ip, string $trigger = 'web'): array
    {
        $expected = (string) Config::get('maintenance.token');
        if (strlen($expected) < 16) {
            return [403, self::error('FEATURE_UNAVAILABLE', 'Maintenance over HTTP is disabled. Set MAINTENANCE_TOKEN (at least 16 characters) in .env to enable it.')];
        }
        if (!Install::isReady()) {
            return [503, self::error('NOT_INSTALLED', 'FastTransfer is not installed or needs an upgrade.')];
        }
        $subject = 'ip' . RateLimiter::ipSubject($ip);
        if (RateLimiter::tooMany('maintenance', $subject)) {
            return [429, self::error('RATE_LIMITED', 'Too many requests. Please wait a moment and try again.')];
        }
        if ($token === null || $token === '' || !hash_equals($expected, $token)) {
            RateLimiter::hit('maintenance', $subject);
            Logger::security('Maintenance URL called with a wrong token', ['ip' => $ip]);
            return [403, self::error('FORBIDDEN', 'The maintenance token is missing or wrong.')];
        }
        $tasks = null;
        if ($taskParam !== null && trim($taskParam) !== '') {
            $tasks = array_values(array_filter(array_map('trim', explode(',', $taskParam)), static fn ($t) => $t !== ''));
            foreach ($tasks as $t) {
                if (!self::isTask($t)) {
                    return [422, self::error('VALIDATION_FAILED', 'Unknown maintenance task.', ['fields' => ['task' => 'Unknown task: ' . mb_substr($t, 0, 40)]])];
                }
            }
        }
        $r = self::run($trigger, $tasks, 20.0);
        return [200, ['success' => true, 'data' => $r]];
    }

    // ================================================================== plumbing

    private static function runTask(string $task, string $runId, string $trigger, float $deadline, array &$state): array
    {
        $t0 = microtime(true);
        $startedAt = Db::now();
        $method = 'task' . str_replace('_', '', ucwords($task, '_'));
        try {
            $r = self::$method($deadline, $state);
            $status = (string) ($r['status'] ?? 'ok');
            $items = max(0, (int) ($r['items'] ?? 0));
            $message = isset($r['message']) ? (string) $r['message'] : null;
        } catch (\Throwable $e) {
            Logger::exception('maintenance', $e, ['task' => $task]);
            $status = 'error';
            $items = 0;
            $message = self::safeMessage($e);
        }
        $ms = (int) ((microtime(true) - $t0) * 1000);
        try {
            Db::insert('maintenance_logs', [
                'run_id'         => $runId,
                'task'           => $task,
                'trigger_source' => $trigger,
                'status'         => $status,
                'items'          => $items,
                'message'        => $message !== null ? mb_substr($message, 0, 1000) : null,
                'started_at'     => $startedAt,
                'finished_at'    => Db::now(),
                'duration_ms'    => $ms,
            ]);
        } catch (\Throwable $e) {
            Logger::warning('maintenance', 'Could not write the maintenance log', ['task' => $task, 'error' => $e->getMessage()]);
        }
        return ['status' => $status, 'items' => $items, 'message' => $message, 'duration_ms' => $ms];
    }

    /** @return resource|null */
    private static function acquireLock()
    {
        $fh = @fopen(Paths::runtime('locks') . '/maintenance.lock', 'c');
        if ($fh === false) {
            return null;
        }
        if (!flock($fh, LOCK_EX | LOCK_NB)) {
            fclose($fh);
            return null;
        }
        return $fh;
    }

    private static function saveState(array $state): void
    {
        $file = self::stateFile();
        $tmp = $file . '.' . bin2hex(random_bytes(4)) . '.tmp';
        if (@file_put_contents($tmp, (string) json_encode($state, JSON_UNESCAPED_SLASHES)) !== false && !@rename($tmp, $file)) {
            @unlink($tmp);
        }
    }

    private static function stateFile(): string
    {
        return Paths::runtime() . '/maintenance.json';
    }

    private static function left(float $deadline): float
    {
        return $deadline - microtime(true);
    }

    /** Batch size that fits the remaining budget (small for 1.5 s pseudo-cron slices). */
    private static function limit(float $deadline, int $max = 500): int
    {
        return max(10, min($max, (int) (self::left($deadline) * 60)));
    }

    private static function has(string $class, string $method): bool
    {
        return class_exists($class) && method_exists($class, $method);
    }

    private static function skipped(string $what): array
    {
        return ['status' => 'skipped', 'items' => 0, 'message' => $what . ' is not available in this build.'];
    }

    private static function counted(int $n, int $limit): array
    {
        return ['status' => $n >= $limit ? 'partial' : 'ok', 'items' => $n];
    }

    /** DELETE … LIMIT 1000 repeatedly until done or out of time. */
    private static function deleteInBatches(string $sql, array $params, float $deadline): array
    {
        $total = 0;
        do {
            $n = Db::run($sql . ' LIMIT 1000', $params)->rowCount();
            $total += $n;
        } while ($n === 1000 && self::left($deadline) > 0);
        return ['status' => $n === 1000 ? 'partial' : 'ok', 'items' => $total];
    }

    private static function error(string $code, string $message, array $details = []): array
    {
        $e = ['code' => $code, 'message' => $message];
        if ($details !== []) {
            $e['details'] = $details;
        }
        return ['success' => false, 'error' => $e];
    }

    private static function safeMessage(\Throwable $e): string
    {
        $m = str_replace('\\', '/', $e->getMessage());
        $m = str_replace([str_replace('\\', '/', FT_ROOT), str_replace('\\', '/', (string) Config::get('storage.path'))], '…', $m);
        return mb_substr(get_class($e) === \PDOException::class ? 'Database error' : $m, 0, 500);
    }

    /** Recursively remove a directory that must live inside the storage root. */
    private static function rmTree(string $dir): bool
    {
        $root = str_replace('\\', '/', Paths::root()) . '/';
        $dir = str_replace('\\', '/', $dir);
        if (!str_starts_with($dir, $root) || str_contains(substr($dir, strlen($root)), '..') || !is_dir($dir) || is_link($dir)) {
            return false;
        }
        foreach (scandir($dir) ?: [] as $f) {
            if ($f === '.' || $f === '..') {
                continue;
            }
            $p = $dir . '/' . $f;
            if (is_dir($p) && !is_link($p)) {
                self::rmTree($p);
            } else {
                @unlink($p);
            }
        }
        return @rmdir($dir);
    }

    /** @return int[] user ids that have a storage directory (without creating any). */
    private static function userDirs(): array
    {
        $base = Paths::root() . '/users';
        if (!is_dir($base)) {
            return [];
        }
        $out = [];
        foreach (scandir($base) ?: [] as $f) {
            if (ctype_digit($f) && (int) $f > 0 && is_dir($base . '/' . $f)) {
                $out[] = (int) $f;
            }
        }
        sort($out);
        return $out;
    }

    // ================================================================== tasks

    private static function taskExpireShares(float $deadline, array &$state): array
    {
        $svc = 'FT\\Sharing\\ShareService';
        if (!self::has($svc, 'expireDue')) {
            return self::skipped('ShareService::expireDue');
        }
        $limit = self::limit($deadline, 200);
        return self::counted((int) $svc::expireDue($limit), $limit);
    }

    /** Mark sessions past their expiry as revoked ("expired"); delete long-dead session rows. */
    private static function taskExpireSessions(float $deadline, array &$state): array
    {
        $now = Db::now();
        $n = Db::run(
            "UPDATE user_sessions SET revoked_at = :now, revoked_reason = 'expired'
              WHERE revoked_at IS NULL AND expires_at <= :now2 LIMIT 1000",
            ['now' => $now, 'now2' => $now]
        )->rowCount();
        $d = self::deleteInBatches(
            'DELETE FROM user_sessions WHERE revoked_at IS NOT NULL AND revoked_at < :cut ORDER BY id',
            ['cut' => Db::ts(time() - self::SESSION_ROW_RETENTION_DAYS * 86400)],
            $deadline
        );
        return ['status' => $n === 1000 ? 'partial' : $d['status'], 'items' => $n + $d['items']];
    }

    private static function taskAutoExpireFiles(float $deadline, array &$state): array
    {
        $svc = 'FT\\Files\\FileService';
        if (!self::has($svc, 'expireDue')) {
            return self::skipped('FileService::expireDue');
        }
        $limit = self::limit($deadline, 200);
        return self::counted((int) $svc::expireDue($limit), $limit);
    }

    private static function taskExpireTexts(float $deadline, array &$state): array
    {
        $svc = 'FT\\Texts\\TextService';
        if (!self::has($svc, 'expireDue')) {
            return self::skipped('TextService::expireDue');
        }
        $limit = self::limit($deadline, 500);
        return self::counted((int) $svc::expireDue($limit), $limit);
    }

    /**
     * Expired upload sessions → status "expired" + temp data removed (+ upload.failed so other
     * devices drop the item); old finished session rows removed; orphan temp directories and
     * stale temporary files cleaned. Recent temp data (< 1 h) is never touched.
     */
    private static function taskCleanupUploads(float $deadline, array &$state): array
    {
        $limit = self::limit($deadline, 200);
        $svc = 'FT\Uploads\UploadService';
        if (self::has($svc, 'cleanupExpired')) {
            // A2 owns the upload protocol (reservations, staging layout, events): use its rules.
            $items = (int) $svc::cleanupExpired(max(0.5, min(8.0, self::left($deadline))), $limit);
            $items += self::cleanTempCopies();
            return ['status' => $items >= $limit ? 'partial' : 'ok', 'items' => $items];
        }
        $items = 0;
        $now = Db::now();
        $rows = Db::all(
            "SELECT id, user_id, name, size, folder_id, received_bytes FROM upload_sessions
              WHERE status IN ('active', 'assembling') AND expires_at <= :now AND updated_at <= :quiet
              ORDER BY expires_at LIMIT :lim",
            ['now' => $now, 'quiet' => Db::ts(time() - 600), 'lim' => $limit]
        );
        foreach ($rows as $r) {
            if (self::left($deadline) <= 0) {
                return ['status' => 'partial', 'items' => $items];
            }
            $claimed = Db::run(
                "UPDATE upload_sessions SET status = 'expired', error = 'expired', updated_at = :now
                  WHERE id = :id AND status IN ('active', 'assembling')",
                ['now' => Db::now(), 'id' => (string) $r['id']]
            )->rowCount();
            if ($claimed !== 1) {
                continue;
            }
            $items++;
            self::removeUploadTemp((int) $r['user_id'], (string) $r['id']);
            $recipients = [(int) $r['user_id']];
            if ($r['folder_id'] !== null) {
                $owner = Db::value('SELECT owner_id FROM folders WHERE id = ?', [(int) $r['folder_id']]);
                if ($owner !== null) {
                    $recipients[] = (int) $owner;
                }
            }
            EventBus::publish('upload.failed', [
                'upload_id'      => (string) $r['id'],
                'name'           => (string) $r['name'],
                'size'           => (int) $r['size'],
                'folder_id'      => $r['folder_id'] !== null ? (int) $r['folder_id'] : null,
                'received_bytes' => (int) $r['received_bytes'],
                'percent'        => (int) $r['size'] > 0 ? round(100 * (int) $r['received_bytes'] / (int) $r['size'], 1) : 0,
                'reason'         => 'expired',
            ], $recipients, ['actor_id' => null]);
        }

        // Finished sessions older than a week: rows (chunks cascade) and any temp left-overs.
        $old = Db::all(
            "SELECT id, user_id FROM upload_sessions WHERE status IN ('completed', 'failed', 'aborted', 'expired') AND updated_at < :cut ORDER BY updated_at LIMIT :lim",
            ['cut' => Db::ts(time() - self::UPLOAD_ROW_RETENTION_DAYS * 86400), 'lim' => $limit]
        );
        foreach ($old as $r) {
            self::removeUploadTemp((int) $r['user_id'], (string) $r['id']);
            $items += Db::delete('upload_sessions', ['id' => (string) $r['id']]);
        }

        // Orphan temp directories (no live session) and crashed BlobStore temp dirs.
        $live = array_flip(array_map('strval', Db::column("SELECT id FROM upload_sessions WHERE status IN ('active', 'assembling')")));
        foreach (self::userDirs() as $uid) {
            if (self::left($deadline) <= 0) {
                return ['status' => 'partial', 'items' => $items];
            }
            $temp = Paths::root() . '/users/' . $uid . '/temp';
            if (!is_dir($temp)) {
                continue;
            }
            foreach (scandir($temp) ?: [] as $f) {
                if ($f === '.' || $f === '..') {
                    continue;
                }
                $p = $temp . '/' . $f;
                $age = time() - (int) @filemtime($p);
                $orphanUpload = preg_match('/^[A-Za-z0-9]{8,64}$/', $f) && !isset($live[$f]) && $age > self::TEMP_GRACE_SECONDS;
                $staleBlob = str_starts_with($f, 'blob-') && $age > self::BLOB_TEMP_MAX_AGE;
                if (($orphanUpload || $staleBlob) && is_dir($p) && self::rmTree($p)) {
                    $items++;
                }
            }
        }
        $items += self::cleanTempCopies();
        return ['status' => count($rows) >= $limit ? 'partial' : 'ok', 'items' => $items];
    }

    /** Decrypted temporary copies (OCR, thumbnails) that a crashed worker left in runtime/tmp. */
    private static function cleanTempCopies(): int
    {
        $n = 0;
        $tmp = Paths::root() . '/runtime/tmp';
        if (is_dir($tmp)) {
            foreach (scandir($tmp) ?: [] as $f) {
                $p = $tmp . '/' . $f;
                if ($f !== '.' && $f !== '..' && is_file($p) && time() - (int) @filemtime($p) > self::TEMP_GRACE_SECONDS && @unlink($p)) {
                    $n++;
                }
            }
        }
        return $n;
    }

    private static function removeUploadTemp(int $userId, string $uploadId): void
    {
        if ($userId <= 0 || !preg_match('/^[A-Za-z0-9]{8,64}$/', $uploadId)) {
            return;
        }
        $dir = Paths::root() . '/users/' . $userId . '/temp/' . $uploadId;
        if (is_dir($dir)) {
            self::rmTree($dir);
        }
    }

    private static function taskPurgeTrash(float $deadline, array &$state): array
    {
        $svc = 'FT\\Files\\TrashService';
        if (!self::has($svc, 'purgeExpired')) {
            return self::skipped('TrashService::purgeExpired');
        }
        $limit = self::limit($deadline, 200);
        return self::counted((int) $svc::purgeExpired($limit), $limit);
    }

    /** Enforce version_retention_count / version_retention_days on files that exceed them. */
    private static function taskPruneVersions(float $deadline, array &$state): array
    {
        $svc = 'FT\\Files\\FileWriter';
        if (!self::has($svc, 'pruneVersions')) {
            return self::skipped('FileWriter::pruneVersions');
        }
        $count = Settings::int('version_retention_count', 5);
        $days = Settings::int('version_retention_days', 0);
        if ($count <= 0 && $days <= 0) {
            return ['status' => 'ok', 'items' => 0, 'message' => 'Version retention is unlimited.'];
        }
        $limit = self::limit($deadline, 200);
        $ids = [];
        if ($count > 0) {
            $ids = array_merge($ids, Db::column(
                'SELECT file_id FROM file_versions GROUP BY file_id HAVING COUNT(*) > :c ORDER BY file_id LIMIT :lim',
                ['c' => $count, 'lim' => $limit]
            ));
        }
        if ($days > 0) {
            $ids = array_merge($ids, Db::column(
                'SELECT DISTINCT v.file_id FROM file_versions v JOIN files f ON f.id = v.file_id
                  WHERE v.version <> f.version AND v.created_at < :cut ORDER BY v.file_id LIMIT :lim',
                ['cut' => Db::ts(time() - $days * 86400), 'lim' => $limit]
            ));
        }
        $pruned = 0;
        foreach (array_unique(array_map('intval', $ids)) as $id) {
            if (self::left($deadline) <= 0) {
                return ['status' => 'partial', 'items' => $pruned];
            }
            $pruned += (int) $svc::pruneVersions($id);
        }
        return ['status' => count($ids) >= $limit ? 'partial' : 'ok', 'items' => $pruned];
    }

    /** Cached bundle ZIPs (users/<id>/bundles/*.zip) older than bundle_ttl_hours. */
    private static function taskCleanupBundles(float $deadline, array &$state): array
    {
        $ttl = max(1, Settings::int('bundle_ttl_hours', 24)) * 3600;
        $n = 0;
        foreach (self::userDirs() as $uid) {
            if (self::left($deadline) <= 0) {
                return ['status' => 'partial', 'items' => $n];
            }
            $dir = Paths::root() . '/users/' . $uid . '/bundles';
            if (!is_dir($dir)) {
                continue;
            }
            foreach (scandir($dir) ?: [] as $f) {
                $p = $dir . '/' . $f;
                if ($f !== '.' && $f !== '..' && is_file($p) && time() - (int) @filemtime($p) > $ttl && @unlink($p)) {
                    $n++;
                }
            }
        }
        return ['status' => 'ok', 'items' => $n];
    }

    /**
     * Delete real-time events older than event_retention_days (recipients cascade) and publish
     * the first retained id in setting events_pruned_before_id, so clients asking for older ids
     * get reset=true (lightweight refresh) instead of a silent gap.
     */
    private static function taskPruneEvents(float $deadline, array &$state): array
    {
        $days = max(1, Settings::int('event_retention_days', 7));
        $cut = Db::ts(time() - $days * 86400);
        $firstKept = Db::value('SELECT MIN(id) FROM events WHERE created_at >= ?', [$cut]);
        $firstKept = $firstKept !== null ? (int) $firstKept : (int) (Db::value('SELECT COALESCE(MAX(id), 0) FROM events') ?? 0) + 1;
        if ((int) (Db::value('SELECT COUNT(*) FROM events WHERE id < ?', [$firstKept]) ?? 0) === 0) {
            return ['status' => 'ok', 'items' => 0];
        }
        $r = self::deleteInBatches('DELETE FROM events WHERE id < :k ORDER BY id', ['k' => $firstKept], $deadline);
        $minLeft = Db::value('SELECT MIN(id) FROM events');
        $boundary = $minLeft !== null ? min($firstKept, (int) $minLeft) : $firstKept;
        if ($boundary > Settings::int('events_pruned_before_id', 0)) {
            Settings::set('events_pruned_before_id', (string) $boundary, null);
        }
        return $r;
    }

    /** Audit log retention (audit_retention_days; 0 = keep forever). */
    private static function taskPruneAudit(float $deadline, array &$state): array
    {
        $days = Settings::int('audit_retention_days', 365);
        if ($days <= 0) {
            return ['status' => 'ok', 'items' => 0];
        }
        return self::deleteInBatches('DELETE FROM audit_logs WHERE created_at < :cut ORDER BY id', ['cut' => Db::ts(time() - $days * 86400)], $deadline);
    }

    private static function taskPruneLoginHistory(float $deadline, array &$state): array
    {
        $days = Settings::int('login_history_retention_days', 180);
        if ($days <= 0) {
            return ['status' => 'ok', 'items' => 0];
        }
        return self::deleteInBatches('DELETE FROM login_history WHERE created_at < :cut ORDER BY id', ['cut' => Db::ts(time() - $days * 86400)], $deadline);
    }

    private static function taskPruneNotifications(float $deadline, array &$state): array
    {
        $days = Settings::int('notification_retention_days', 90);
        if ($days <= 0) {
            return ['status' => 'ok', 'items' => 0];
        }
        $svc = 'FT\\Notifications\\NotificationService';
        if (self::has($svc, 'prune')) {
            return ['status' => 'ok', 'items' => (int) $svc::prune($days, max(0.5, self::left($deadline)))];
        }
        return self::deleteInBatches('DELETE FROM notifications WHERE created_at < :cut ORDER BY id', ['cut' => Db::ts(time() - $days * 86400)], $deadline);
    }

    private static function taskPruneRateLimits(float $deadline, array &$state): array
    {
        if (self::has(RateLimiter::class, 'prune')) {
            return ['status' => 'ok', 'items' => (int) RateLimiter::prune()];
        }
        return self::deleteInBatches('DELETE FROM rate_limits WHERE expires_at < :t', ['t' => time()], $deadline);
    }

    /** Editor and notepad presence entries expire after 30 s; anything older than 2 minutes is stale. */
    private static function taskPrunePresence(float $deadline, array &$state): array
    {
        $items = 0;
        $partial = false;
        foreach (['FT\\Collab\\EditorService', 'FT\\Notepads\\NotepadService'] as $svc) {
            if (!self::has($svc, 'prunePresence')) {
                continue;
            }
            // The services own their presence rules (30 s TTL): let them decide what is stale.
            do {
                $n = (int) $svc::prunePresence(1000);
                $items += $n;
            } while ($n >= 1000 && self::left($deadline) > 0);
            $partial = $partial || $n >= 1000;
        }
        if (!self::has('FT\\Collab\\EditorService', 'prunePresence')) {
            return self::deleteInBatches('DELETE FROM edit_presence WHERE last_seen_at < :cut', ['cut' => Db::ts(time() - 120)], $deadline);
        }
        return ['status' => $partial ? 'partial' : 'ok', 'items' => $items];
    }

    /**
     * Rows that point at purged files/folders/users. Most links cascade through foreign keys;
     * shares (file_id/folder_id have no FK) and edit_presence do not, so they are cleaned here.
     */
    private static function taskOrphanRecords(float $deadline, array &$state): array
    {
        $items = 0;
        $queries = [
            'DELETE FROM favorites WHERE NOT EXISTS (SELECT 1 FROM files f WHERE f.id = favorites.file_id)',
            'DELETE FROM file_tags WHERE NOT EXISTS (SELECT 1 FROM files f WHERE f.id = file_tags.file_id)',
            'DELETE FROM share_items WHERE NOT EXISTS (SELECT 1 FROM files f WHERE f.id = share_items.file_id)',
            "DELETE FROM shares WHERE target_type = 'file' AND file_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM files f WHERE f.id = shares.file_id)",
            "DELETE FROM shares WHERE target_type = 'folder' AND folder_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM folders d WHERE d.id = shares.folder_id)",
            "DELETE FROM shares WHERE target_type = 'bundle' AND created_at < :cut AND NOT EXISTS (SELECT 1 FROM share_items si WHERE si.share_id = shares.id)",
            'DELETE FROM edit_presence WHERE NOT EXISTS (SELECT 1 FROM files f WHERE f.id = edit_presence.file_id)
                OR NOT EXISTS (SELECT 1 FROM users u WHERE u.id = edit_presence.user_id)',
            'DELETE FROM file_texts WHERE NOT EXISTS (SELECT 1 FROM files f WHERE f.id = file_texts.file_id)',
        ];
        $partial = false;
        foreach ($queries as $sql) {
            if (self::left($deadline) <= 0) {
                $partial = true;
                break;
            }
            $params = str_contains($sql, ':cut') ? ['cut' => Db::ts(time() - 3600)] : [];
            $r = self::deleteInBatches($sql, $params, $deadline);
            $items += $r['items'];
            $partial = $partial || $r['status'] === 'partial';
        }
        return ['status' => $partial ? 'partial' : 'ok', 'items' => $items];
    }

    /**
     * Reconcile file_blobs.ref_count with the number of file_versions rows (batched, cursor in
     * the state file), then let BlobStore::sweep() delete blobs nobody references for an hour.
     * Blobs touched in the last 10 minutes are skipped (an upload may be between "stored" and
     * "version row written"). A physical file that any row references is never deleted.
     */
    private static function taskUnreferencedBlobs(float $deadline, array &$state): array
    {
        $fixed = 0;
        $cursor = (int) ($state['blob_cursor'] ?? 0);
        $quiet = Db::ts(time() - 600);
        while (self::left($deadline) > 0.2) {
            $rows = Db::all('SELECT id, ref_count, last_ref_change_at FROM file_blobs WHERE id > ? ORDER BY id LIMIT 500', [$cursor]);
            if ($rows === []) {
                $cursor = 0;
                break;
            }
            $ids = array_map(static fn ($r) => (int) $r['id'], $rows);
            [$in, $p] = Db::inList($ids, 'rb');
            $actual = [];
            foreach (Db::all("SELECT blob_id, COUNT(*) AS n FROM file_versions WHERE blob_id IN {$in} GROUP BY blob_id", $p) as $c) {
                $actual[(int) $c['blob_id']] = (int) $c['n'];
            }
            foreach ($rows as $r) {
                $id = (int) $r['id'];
                $want = $actual[$id] ?? 0;
                if ($want === (int) $r['ref_count'] || (string) $r['last_ref_change_at'] > $quiet) {
                    continue;
                }
                $n = Db::run(
                    'UPDATE file_blobs SET ref_count = :want, last_ref_change_at = :now WHERE id = :id AND ref_count = :old AND last_ref_change_at = :lc',
                    ['want' => $want, 'now' => Db::now(), 'id' => $id, 'old' => (int) $r['ref_count'], 'lc' => (string) $r['last_ref_change_at']]
                )->rowCount();
                if ($n === 1) {
                    $fixed++;
                    Logger::warning('maintenance', 'Blob ref_count reconciled', ['blob_id' => $id, 'from' => (int) $r['ref_count'], 'to' => $want]);
                }
            }
            $cursor = end($ids);
            if (count($rows) < 500) {
                $cursor = 0;
                break;
            }
        }
        $state['blob_cursor'] = $cursor;
        $deleted = 0;
        $svc = 'FT\\Storage\\BlobStore';
        if (self::has($svc, 'sweep') && self::left($deadline) > 0) {
            $deleted = (int) $svc::sweep(3600, self::limit($deadline, 200));
        }
        return ['status' => $cursor === 0 ? 'ok' : 'partial', 'items' => $fixed + $deleted, 'message' => $fixed > 0 || $deleted > 0 ? "reconciled {$fixed}, deleted {$deleted}" : null];
    }

    /** users.used_bytes = SUM(file_versions.size) of owned files (batched, cursor). */
    private static function taskReconcileQuotas(float $deadline, array &$state): array
    {
        $svc = 'FT\\Storage\\QuotaService';
        if (!self::has($svc, 'recalculate')) {
            return self::skipped('QuotaService::recalculate');
        }
        $cursor = (int) ($state['quota_cursor'] ?? 0);
        $changed = 0;
        $complete = false;
        while (self::left($deadline) > 0) {
            $users = Db::all('SELECT id, used_bytes FROM users WHERE id > ? ORDER BY id LIMIT 100', [$cursor]);
            if ($users === []) {
                $complete = true;
                $cursor = 0;
                break;
            }
            foreach ($users as $u) {
                if (self::left($deadline) <= 0) {
                    break 2;
                }
                if ((int) $svc::recalculate((int) $u['id']) !== (int) $u['used_bytes']) {
                    $changed++;
                }
                $cursor = (int) $u['id'];
            }
            if (count($users) < 100) {
                $complete = true;
                $cursor = 0;
                break;
            }
        }
        $state['quota_cursor'] = $cursor;
        return ['status' => $complete ? 'ok' : 'partial', 'items' => $changed];
    }

    private static function taskProcessJobs(float $deadline, array &$state): array
    {
        $seconds = max(0.2, min(5.0, self::left($deadline)));
        $n = Queue::work($seconds, 50);
        return ['status' => 'ok', 'items' => $n];
    }

    /** Daily snapshot for the "storage over time" chart. */
    private static function taskSnapshotStats(float $deadline, array &$state): array
    {
        $logical = (int) (Db::value('SELECT COALESCE(SUM(used_bytes), 0) FROM users WHERE deleted_at IS NULL') ?? 0);
        $physical = (int) (Db::value('SELECT COALESCE(SUM(stored_size), 0) FROM file_blobs') ?? 0);
        Stats::setToday('storage_bytes', $logical);
        Stats::setToday('physical_bytes', $physical);
        return ['status' => 'ok', 'items' => 2];
    }

    private static function taskEncryptionMigration(float $deadline, array &$state): array
    {
        if (!Crypto::enabled()) {
            return ['status' => 'ok', 'items' => 0, 'message' => 'Encryption is not enabled.'];
        }
        $current = (string) Crypto::currentKeyId();
        $pending = (int) Db::value(
            "SELECT COUNT(*) FROM file_blobs WHERE encryption IN ('legacy_cbc', 'none') OR (encryption = 'gcm1' AND (enc_key_id IS NULL OR enc_key_id <> ?))",
            [$current]
        );
        if ($pending === 0) {
            return ['status' => 'ok', 'items' => 0];
        }
        $r = EncryptionMigrator::migrateBatch(max(0.3, min(8.0, self::left($deadline))));
        return [
            'status'  => $r['failed'] > 0 ? 'error' : ($r['done'] ? 'ok' : 'partial'),
            'items'   => $r['migrated'],
            'message' => $r['failed'] > 0 ? $r['failed'] . ' file(s) could not be converted and were left unchanged.' : $r['message'],
        ];
    }

    /** Old maintenance log rows and rotated log files (≥ 30 days). */
    private static function taskPruneLogs(float $deadline, array &$state): array
    {
        $r = self::deleteInBatches('DELETE FROM maintenance_logs WHERE started_at < :cut ORDER BY id', ['cut' => Db::ts(time() - self::LOG_RETENTION_DAYS * 86400)], $deadline);
        $dir = Paths::logs();
        $cut = time() - self::LOG_RETENTION_DAYS * 86400;
        foreach (scandir($dir) ?: [] as $f) {
            if (!str_ends_with($f, '.log')) {
                continue;
            }
            $p = $dir . '/' . $f;
            if (is_file($p) && (int) @filemtime($p) < $cut && @unlink($p)) {
                $r['items']++;
            }
        }
        return $r;
    }

    /** On demand: can this server reach Slack, the OCR provider and the push services? */
    private static function taskEgressCheck(float $deadline, array &$state): array
    {
        $r = StatsService::egressCheck(max(1.0, self::left($deadline)));
        $failed = count(array_filter($r['hosts'], static fn ($h) => $h['ok'] === false));
        return ['status' => $failed > 0 ? 'partial' : 'ok', 'items' => count($r['hosts']), 'message' => $failed > 0 ? $failed . ' host(s) unreachable.' : null];
    }
}
