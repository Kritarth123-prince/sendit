<?php
declare(strict_types=1);

namespace FT\Admin;

use FT\Core\ApiException;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Settings;
use FT\Core\Stats;
use FT\Database\Migrator;
use FT\Jobs\Queue;
use FT\Legacy\EncryptionMigrator;
use FT\Legacy\LegacyImporter;
use FT\Maintenance\MaintenanceRunner;
use FT\Maintenance\PseudoCron;
use FT\Storage\BlobStore;
use FT\Storage\Crypto;
use FT\Storage\Paths;
use FT\Storage\QuotaService;
use FT\Support\Capabilities;
use FT\Support\Install;

/**
 * Read models and validation for the admin area (docs/ARCHITECTURE.md §9.4 "Admin", §13.2).
 *
 * Every figure is computed with a constant number of aggregate queries (no per-row loops), so
 * the dashboard stays cheap on a 4-connection shared database. Responses never contain physical
 * paths, secrets or share URLs — only counts, sizes, names and user references.
 *
 * Terms: "logical" bytes = what users are charged (every version, trash included, before
 * deduplication); "physical" bytes = what is on disk (file_blobs.stored_size, after dedup and
 * including encryption overhead); "dedup saved" = referenced logical bytes − unique plaintext.
 */
final class StatsService
{
    public const CHART_METRICS = ['storage_bytes', 'physical_bytes', 'uploads', 'upload_bytes', 'downloads', 'new_users', 'shares_created', 'failed_uploads', 'logins', 'deletes'];

    /** Gauges are snapshots (forward-filled in charts); the other metrics are daily counters. */
    private const GAUGES = ['storage_bytes', 'physical_bytes'];

    public const SLACK_EVENTS = ['upload', 'delete', 'share', 'download', 'comment', 'text', 'favorite', 'version_restore', 'batch_delete'];

    /** Keys that only maintenance may change. */
    private const READ_ONLY_SETTINGS = ['events_pruned_before_id'];

    // ================================================================== dashboard

    /** §13.2 counters. @return array<string,int|null|string> */
    public static function counters(): array
    {
        $now = Db::now();
        $u = Db::one(
            "SELECT COUNT(*) AS total, COALESCE(SUM(status = 'active'), 0) AS active, COALESCE(SUM(status = 'disabled'), 0) AS disabled,
                    COALESCE(SUM(status = 'suspended'), 0) AS suspended FROM users WHERE deleted_at IS NULL"
        ) ?? [];
        $f = Db::one(
            'SELECT COALESCE(SUM(deleted_at IS NULL), 0) AS live, COALESCE(SUM(deleted_at IS NOT NULL), 0) AS trashed FROM files'
        ) ?? [];
        $bytes = self::byteTotals();
        $today = self::today(['uploads', 'downloads', 'shares_created', 'failed_uploads']);
        $s = Db::one(
            'SELECT COUNT(*) AS total,
                    COALESCE(SUM(revoked_at IS NULL AND (expires_at IS NULL OR expires_at > :n1) AND (max_downloads IS NULL OR download_count < max_downloads)), 0) AS active,
                    COALESCE(SUM(revoked_at IS NULL AND expires_at IS NOT NULL AND expires_at <= :n2), 0) AS expired,
                    COALESCE(SUM(revoked_at IS NOT NULL), 0) AS revoked
               FROM shares',
            ['n1' => $now, 'n2' => $now]
        ) ?? [];
        $jobs = Queue::counts();
        $cap = self::capacity($bytes['physical']);
        return [
            'users_total'             => (int) ($u['total'] ?? 0),
            'users_active'            => (int) ($u['active'] ?? 0),
            'users_disabled'          => (int) ($u['disabled'] ?? 0),
            'users_suspended'         => (int) ($u['suspended'] ?? 0),
            'files_total'             => (int) ($f['live'] ?? 0),
            'storage_used_bytes'      => $bytes['logical'],
            'storage_physical_bytes'  => $bytes['physical'],
            'storage_capacity_bytes'  => $cap['capacity_bytes'],
            'storage_available_bytes' => $cap['available_bytes'],
            'uploads_today'           => $today['uploads'],
            'downloads_today'         => $today['downloads'],
            'shares_created_today'    => $today['shares_created'],
            'shares_total'            => (int) ($s['total'] ?? 0),
            'shares_active'           => (int) ($s['active'] ?? 0),
            'shares_expired'          => (int) ($s['expired'] ?? 0),
            'shares_revoked'          => (int) ($s['revoked'] ?? 0),
            'trash_bytes'             => $bytes['trash'],
            'trash_files'             => (int) ($f['trashed'] ?? 0),
            'version_bytes'           => $bytes['versions'],
            'failed_uploads_today'    => $today['failed_uploads'],
            'dedup_saved_bytes'       => $bytes['dedup_saved'],
            'jobs_pending'            => $jobs['pending'],
            'jobs_failed'             => $jobs['failed'],
            'generated_at'            => Db::iso($now),
        ];
    }

    /**
     * Chart data: daily series from daily_stats (gauges forward-filled, today's storage live),
     * file kinds by count and bytes, and the ten most downloaded files.
     * @return array<string,mixed>
     */
    public static function charts(int $days): array
    {
        $days = max(1, min(365, $days));
        $raw = Stats::series(self::CHART_METRICS, $days);
        $labels = array_keys($raw[self::CHART_METRICS[0]] ?? []);
        $series = [];
        $bytes = null;
        foreach (self::CHART_METRICS as $m) {
            $values = array_values($raw[$m] ?? []);
            if (in_array($m, self::GAUGES, true)) {
                $bytes ??= self::byteTotals();
                $values[count($values) - 1] = $m === 'storage_bytes' ? $bytes['logical'] : $bytes['physical'];
                $last = 0;
                foreach ($values as $i => $v) {
                    if ($v === 0 && $i < count($values) - 1) {
                        $values[$i] = $last;
                    }
                    $last = $values[$i];
                }
            }
            // {"2026-10-04": 12, …} — what the admin dashboard charts consume.
            $series[$m] = $labels !== [] ? array_combine($labels, $values) : [];
        }
        $kinds = array_map(static fn ($r) => ['kind' => (string) $r['kind'], 'count' => (int) $r['n'], 'bytes' => (int) $r['bytes']], Db::all(
            'SELECT kind, COUNT(*) AS n, COALESCE(SUM(size), 0) AS bytes FROM files WHERE deleted_at IS NULL GROUP BY kind ORDER BY bytes DESC, kind ASC'
        ));
        $top = Db::all(
            'SELECT id, name, ext, kind, size, download_count, owner_id, created_at FROM files
              WHERE deleted_at IS NULL AND download_count > 0 ORDER BY download_count DESC, id ASC LIMIT 10'
        );
        $refs = self::userRefs(array_map(static fn ($r) => (int) $r['owner_id'], $top));
        return [
            'days'          => $days,
            'labels'        => $labels,
            'series'        => $series,
            'kinds'         => $kinds,
            'top_downloads' => array_map(static fn ($r) => [
                'id'             => (int) $r['id'],
                'name'           => (string) $r['name'],
                'ext'            => (string) $r['ext'],
                'kind'           => (string) $r['kind'],
                'size'           => (int) $r['size'],
                'download_count' => (int) $r['download_count'],
                'owner'          => $refs[(int) $r['owner_id']] ?? null,
                'created_at'     => Db::iso((string) $r['created_at']),
            ], $top),
        ];
    }

    /**
     * Per-user storage (paginated) + totals + capacity.
     * @return array{users:array,total:int,totals:array,capacity:array}
     */
    public static function storage(int $page, int $perPage, string $sort = 'used_bytes', string $order = 'desc', string $q = ''): array
    {
        $sorts = ['used_bytes' => 'u.used_bytes', 'username' => 'u.username', 'created_at' => 'u.created_at', 'quota_bytes' => 'u.quota_bytes'];
        $col = $sorts[$sort] ?? 'u.used_bytes';
        $dir = strtolower($order) === 'asc' ? 'ASC' : 'DESC';
        $where = 'u.deleted_at IS NULL';
        $params = [];
        if ($q !== '') {
            $where .= ' AND (u.username LIKE :q1 OR u.display_name LIKE :q2)';
            $params['q1'] = '%' . Db::like($q) . '%';
            $params['q2'] = '%' . Db::like($q) . '%';
        }
        $total = (int) Db::value("SELECT COUNT(*) FROM users u WHERE {$where}", $params);
        $params['lim'] = $perPage;
        $params['off'] = ($page - 1) * $perPage;
        $rows = Db::all(
            "SELECT u.id, u.username, u.display_name, u.role_id, u.status, u.quota_bytes, u.used_bytes, u.created_at
               FROM users u WHERE {$where} ORDER BY {$col} {$dir}, u.id ASC LIMIT :lim OFFSET :off",
            $params
        );
        $ids = array_map(static fn ($r) => (int) $r['id'], $rows);
        $files = $trash = $versions = [];
        if ($ids !== []) {
            [$in, $p] = Db::inList($ids, 'su');
            foreach (Db::all("SELECT owner_id, COUNT(*) AS n, COALESCE(SUM(size), 0) AS b FROM files WHERE deleted_at IS NULL AND owner_id IN {$in} GROUP BY owner_id", $p) as $r) {
                $files[(int) $r['owner_id']] = $r;
            }
            foreach (Db::all(
                "SELECT f.owner_id, COUNT(DISTINCT f.id) AS n, COALESCE(SUM(v.size), 0) AS b FROM files f JOIN file_versions v ON v.file_id = f.id
                  WHERE f.deleted_at IS NOT NULL AND f.owner_id IN {$in} GROUP BY f.owner_id",
                $p
            ) as $r) {
                $trash[(int) $r['owner_id']] = $r;
            }
            foreach (Db::all(
                "SELECT f.owner_id, COUNT(*) AS n, COALESCE(SUM(v.size), 0) AS b FROM file_versions v JOIN files f ON f.id = v.file_id
                  WHERE f.deleted_at IS NULL AND v.version <> f.version AND f.owner_id IN {$in} GROUP BY f.owner_id",
                $p
            ) as $r) {
                $versions[(int) $r['owner_id']] = $r;
            }
        }
        $items = [];
        foreach ($rows as $r) {
            $id = (int) $r['id'];
            $quota = QuotaService::effectiveQuota($r);
            $used = (int) $r['used_bytes'];
            $reserved = QuotaService::reserved($id);
            $display = (string) (($r['display_name'] ?? '') !== '' ? $r['display_name'] : $r['username']);
            $items[] = [
                'id'              => $id,
                'username'        => (string) $r['username'],
                'display_name'    => $display,
                'user'            => [
                    'id'           => $id,
                    'username'     => (string) $r['username'],
                    'display_name' => $display,
                    'role'         => (int) $r['role_id'] === 1 ? 'admin' : ((int) $r['role_id'] === 3 ? 'guest' : 'user'),
                    'status'       => (string) $r['status'],
                ],
                'quota_bytes'     => $quota,
                'used_bytes'      => $used,
                'reserved_bytes'  => $reserved,
                'available_bytes' => $quota === null ? null : max(0, $quota - $used - $reserved),
                'percent'         => QuotaService::percent($used, $quota),
                'files'           => (int) ($files[$id]['n'] ?? 0),
                'files_bytes'     => (int) ($files[$id]['b'] ?? 0),
                'trash_files'     => (int) ($trash[$id]['n'] ?? 0),
                'trash_bytes'     => (int) ($trash[$id]['b'] ?? 0),
                'versions'        => (int) ($versions[$id]['n'] ?? 0),
                'version_bytes'   => (int) ($versions[$id]['b'] ?? 0),
            ];
        }
        $bytes = self::byteTotals();
        $blobs = Db::one('SELECT COUNT(*) AS n, COALESCE(SUM(ref_count = 0), 0) AS unreferenced FROM file_blobs') ?? [];
        $byEnc = [];
        foreach (Db::all('SELECT encryption, COUNT(*) AS n, COALESCE(SUM(stored_size), 0) AS b FROM file_blobs GROUP BY encryption') as $r) {
            $byEnc[(string) $r['encryption']] = ['count' => (int) $r['n'], 'stored_bytes' => (int) $r['b']];
        }
        $capacity = self::capacity($bytes['physical']);
        return [
            'users'    => $items,
            'total'    => $total,
            'totals'   => [
                'users'               => (int) Db::value('SELECT COUNT(*) FROM users WHERE deleted_at IS NULL'),
                'files'               => (int) Db::value('SELECT COUNT(*) FROM files WHERE deleted_at IS NULL'),
                'logical_bytes'       => $bytes['logical'],
                'referenced_bytes'    => $bytes['referenced'],
                'unique_bytes'        => $bytes['unique'],
                'physical_bytes'      => $bytes['physical'],
                'dedup_saved_bytes'   => $bytes['dedup_saved'],
                'trash_bytes'         => $bytes['trash'],
                'version_bytes'       => $bytes['versions'],
                'blobs'               => (int) ($blobs['n'] ?? 0),
                'blobs_unreferenced'  => (int) ($blobs['unreferenced'] ?? 0),
                'blobs_by_encryption' => $byEnc,
                'capacity_bytes'      => $capacity['capacity_bytes'],
                'available_bytes'     => $capacity['available_bytes'],
            ],
            'capacity' => $capacity,
        ];
    }

    /**
     * Global audit log with filters. @return array{items:array,total:int}
     * Filters: category, action (exact, or a prefix such as "file." / "file.*"), user_id (actor),
     * owner_id, target_type, target_id, q (detail/actor/action), date_from, date_to (YYYY-MM-DD).
     */
    public static function activity(array $f, int $page, int $perPage): array
    {
        $where = ['1 = 1'];
        $p = [];
        if (($f['category'] ?? '') !== '') {
            $where[] = 'a.category = :cat';
            $p['cat'] = (string) $f['category'];
        }
        $action = (string) ($f['action'] ?? '');
        if ($action !== '') {
            if (str_ends_with($action, '*') || str_ends_with($action, '.')) {
                $where[] = 'a.action LIKE :act';
                $p['act'] = Db::like(rtrim($action, '*')) . '%';
            } else {
                $where[] = 'a.action = :act';
                $p['act'] = $action;
            }
        }
        foreach (['user_id' => 'a.user_id', 'owner_id' => 'a.owner_id', 'target_id' => 'a.target_id'] as $k => $col) {
            if (isset($f[$k]) && (int) $f[$k] > 0) {
                $where[] = "{$col} = :{$k}";
                $p[$k] = (int) $f[$k];
            }
        }
        if (($f['target_type'] ?? '') !== '') {
            $where[] = 'a.target_type = :tt';
            $p['tt'] = (string) $f['target_type'];
        }
        if (($f['q'] ?? '') !== '') {
            $like = '%' . Db::like((string) $f['q']) . '%';
            $where[] = '(a.detail LIKE :q1 OR a.actor_label LIKE :q2 OR a.action LIKE :q3)';
            $p['q1'] = $like;
            $p['q2'] = $like;
            $p['q3'] = $like;
        }
        if (($f['date_from'] ?? null) !== null) {
            $where[] = 'a.created_at >= :df';
            $p['df'] = (string) $f['date_from'];
        }
        if (($f['date_to'] ?? null) !== null) {
            $where[] = 'a.created_at < :dt';
            $p['dt'] = (string) $f['date_to'];
        }
        $sql = implode(' AND ', $where);
        $total = (int) Db::value("SELECT COUNT(*) FROM audit_logs a WHERE {$sql}", $p);
        $p['lim'] = $perPage;
        $p['off'] = ($page - 1) * $perPage;
        $rows = Db::all("SELECT a.* FROM audit_logs a WHERE {$sql} ORDER BY a.created_at DESC, a.id DESC LIMIT :lim OFFSET :off", $p);
        $ids = [];
        foreach ($rows as $r) {
            foreach (['user_id', 'owner_id'] as $c) {
                if ($r[$c] !== null) {
                    $ids[] = (int) $r[$c];
                }
            }
        }
        $refs = self::userRefs($ids);
        $items = array_map(static function (array $r) use ($refs): array {
            $meta = $r['meta'] !== null ? json_decode((string) $r['meta'], true) : null;
            return [
                'id'          => (int) $r['id'],
                'action'      => (string) $r['action'],
                'category'    => (string) $r['category'],
                'actor'       => $r['user_id'] !== null ? ($refs[(int) $r['user_id']] ?? null) : null,
                'actor_label' => $r['actor_label'],
                'target_type' => $r['target_type'],
                'target_id'   => $r['target_id'] !== null ? (int) $r['target_id'] : null,
                'owner'       => $r['owner_id'] !== null ? ($refs[(int) $r['owner_id']] ?? null) : null,
                'detail'      => $r['detail'],
                'meta'        => is_array($meta) ? $meta : null,
                'ip'          => $r['ip'],
                'user_agent'  => $r['user_agent'],
                'created_at'  => Db::iso((string) $r['created_at']),
            ];
        }, $rows);
        return ['items' => $items, 'total' => $total];
    }

    // ================================================================== system

    /** Health / diagnostics for Admin → System. $basePath is the app's URL path ("/" or "/sub/"). */
    public static function system(string $basePath): array
    {
        $status = [];
        try {
            $status = Migrator::status();
        } catch (\Throwable $e) {
            Logger::warning('app', 'Migration status unavailable', ['error' => $e->getMessage()]);
        }
        $pending = array_values(array_map(static fn ($s) => $s['version'], array_filter($status, static fn ($s) => !$s['applied'])));
        $marker = Install::marker() ?? [];
        $jobs = Queue::counts();
        $failedJobs = array_map(static fn ($r) => [
            'id'         => (int) $r['id'],
            'type'       => self::shortJobType((string) $r['type']),
            'attempts'   => (int) $r['attempts'],
            'last_error' => self::scrub((string) $r['last_error'], 300),
            'failed_at'  => Db::iso($r['failed_at']),
            'created_at' => Db::iso((string) $r['created_at']),
        ], Db::all('SELECT id, type, attempts, last_error, failed_at, created_at FROM jobs WHERE failed_at IS NOT NULL ORDER BY failed_at DESC LIMIT 20'));
        $byType = [];
        foreach (Db::all('SELECT type, COUNT(*) AS n, COALESCE(SUM(failed_at IS NOT NULL), 0) AS failed FROM jobs GROUP BY type ORDER BY n DESC LIMIT 20') as $r) {
            $byType[] = ['type' => self::shortJobType((string) $r['type']), 'count' => (int) $r['n'], 'failed' => (int) $r['failed']];
        }
        $runs = array_map(static fn ($r) => [
            'run_id'      => (string) $r['run_id'],
            'trigger'     => (string) $r['trig'],
            'started_at'  => Db::iso((string) $r['started']),
            'finished_at' => Db::iso($r['finished']),
            'tasks'       => (int) $r['tasks'],
            'items'       => (int) $r['items'],
            'errors'      => (int) $r['errors'],
            'duration_ms' => (int) $r['ms'],
        ], Db::all(
            "SELECT run_id, MIN(trigger_source) AS trig, MIN(started_at) AS started, MAX(finished_at) AS finished, COUNT(*) AS tasks,
                    COALESCE(SUM(items), 0) AS items, COALESCE(SUM(status = 'error'), 0) AS errors, COALESCE(SUM(duration_ms), 0) AS ms
               FROM maintenance_logs GROUP BY run_id ORDER BY started DESC LIMIT 10"
        ));
        $ocrProvider = self::ocrProvider();
        return [
            'app'           => [
                'name'                  => (string) Settings::string('site_name', 'FastTransfer'),
                'version'               => FT_VERSION,
                'env'                   => (string) Config::get('app.env'),
                'debug'                 => (bool) Config::get('app.debug'),
                'pretty_urls'           => (bool) Config::get('app.pretty_urls'),
                'force_https'           => (bool) Config::get('app.force_https'),
                'encryption_enabled'    => Crypto::enabled(),
                'encryption_key_id'     => Crypto::enabled() ? Crypto::currentKeyId() : null,
                'mail_driver'           => (string) Config::get('mail.driver'),
                'realtime_mode'         => (string) Config::get('realtime.mode'),
                'ocr_provider'          => $ocrProvider,
                'ocr_configured'        => $ocrProvider !== null && (string) Config::get('ocr.api_key') !== '',
                'slack_configured'      => (string) Config::get('slack.webhook') !== '' || Settings::string('slack_webhook_override') !== '',
                'vapid_configured'      => (string) Config::get('vapid.public') !== '' && (string) Config::get('vapid.private') !== '',
                'maintenance_url_enabled' => strlen((string) Config::get('maintenance.token')) >= 16,
                // Should be removed from .env once installation is finished.
                'install_token_present' => (string) Config::get('install.token') !== '',
            ],
            'capabilities'  => $caps = Capabilities::report(),
            'php'           => $caps,
            'database'      => self::dbInfo(),
            'migrations'    => [
                'latest'    => Install::latestMigration(),
                'applied'   => count($status) - count($pending),
                'pending'   => $pending,
                'installed' => ['schema' => $marker['schema'] ?? null, 'version' => $marker['version'] ?? null, 'updated_at' => $marker['updated_at'] ?? null],
            ],
            'jobs'          => $jobs + ['failed_recent' => $failedJobs, 'by_type' => $byType],
            'encryption'    => EncryptionMigrator::status(),
            'legacy_import' => LegacyImporter::status(),
            'pseudo_cron'   => PseudoCron::status(),
            'last_maintenance' => $runs[0] ?? null,
            'maintenance'   => [
                'last_run'    => MaintenanceRunner::state()['last_run'] ?? null,
                'recent_runs' => $runs,
                'tasks'       => MaintenanceRunner::TASKS,
                'on_demand'   => MaintenanceRunner::ON_DEMAND,
            ],
            'storage'       => [
                'canary_url'    => self::canaryUrl($basePath),
                'segment_bytes' => BlobStore::SEGMENT_BYTES,
                'capacity'      => self::capacity(),
            ],
            'egress'        => self::egressResults(),
        ];
    }

    /** @return array<string,mixed> server version and the limits that matter on shared hosts */
    public static function dbInfo(): array
    {
        $out = ['server' => null, 'version' => null, 'variables' => [], 'size_bytes' => null];
        try {
            $v = (string) Db::value('SELECT VERSION()');
            $out['version'] = $v;
            $out['server'] = stripos($v, 'mariadb') !== false ? 'MariaDB' : 'MySQL';
            foreach (Db::all("SHOW VARIABLES WHERE Variable_name IN ('max_allowed_packet', 'wait_timeout', 'max_user_connections', 'max_connections', 'innodb_lock_wait_timeout')") as $r) {
                $vals = array_values($r);
                $out['variables'][(string) $vals[0]] = is_numeric($vals[1]) ? (int) $vals[1] : (string) $vals[1];
            }
            $out['size_bytes'] = (int) Db::value('SELECT COALESCE(SUM(data_length + index_length), 0) FROM information_schema.tables WHERE table_schema = DATABASE()');
        } catch (\Throwable $e) {
            Logger::warning('app', 'Database info unavailable', ['error' => $e->getMessage()]);
        }
        return $out;
    }

    /**
     * Capacity from STORAGE_CAPACITY_GB, else disk_total_space() when the host allows it.
     * @return array{capacity_bytes:?int,available_bytes:?int,free_bytes:?int,source:?string}
     */
    public static function capacity(?int $physical = null): array
    {
        $physical ??= (int) (Db::value('SELECT COALESCE(SUM(stored_size), 0) FROM file_blobs') ?? 0);
        $configured = (int) Config::get('storage.capacity_bytes', 0);
        $free = null;
        $total = null;
        try {
            $root = Paths::root();
            if (function_exists('disk_free_space')) {
                $f = @disk_free_space($root);
                $free = $f !== false ? (int) $f : null;
            }
            if (function_exists('disk_total_space')) {
                $t = @disk_total_space($root);
                $total = $t !== false ? (int) $t : null;
            }
        } catch (\Throwable) {
            // disabled on this host
        }
        if ($configured > 0) {
            $available = max(0, $configured - $physical);
            if ($free !== null) {
                $available = min($available, $free);
            }
            return ['capacity_bytes' => $configured, 'available_bytes' => $available, 'free_bytes' => $free, 'source' => 'config'];
        }
        if ($total !== null) {
            return ['capacity_bytes' => $total, 'available_bytes' => $free, 'free_bytes' => $free, 'source' => 'disk'];
        }
        return ['capacity_bytes' => null, 'available_bytes' => $free, 'free_bytes' => $free, 'source' => null];
    }

    // ================================================================== egress self-test

    /**
     * Can this server reach the third-party hosts FastTransfer depends on? Hosts are sometimes
     * blocked platform-wide on free hosting. One HEAD request at a time (connect 5 s, total
     * ≤ 10 s), stopping when the budget is spent; results are cached in runtime/egress.json.
     * Only fixed, well-known hosts are contacted — never a user-supplied URL.
     */
    public static function egressCheck(float $budgetSeconds = 20.0): array
    {
        $deadline = microtime(true) + max(1.0, $budgetSeconds);
        $targets = [
            'slack'         => 'https://hooks.slack.com/',
            'ocr'           => self::ocrProvider() === 'googlevision' ? 'https://vision.googleapis.com/' : 'https://api.ocr.space/',
            'push_google'   => 'https://fcm.googleapis.com/',
            'push_mozilla'  => 'https://updates.push.services.mozilla.com/',
            'push_apple'    => 'https://web.push.apple.com/',
        ];
        $hosts = [];
        foreach ($targets as $name => $url) {
            $host = (string) parse_url($url, PHP_URL_HOST);
            $left = $deadline - microtime(true);
            if (!Capabilities::hasCurl()) {
                $hosts[] = ['name' => $name, 'host' => $host, 'ok' => null, 'status' => null, 'ms' => null, 'error' => 'The PHP curl extension is not available.'];
                continue;
            }
            if ($left < 1.0) {
                $hosts[] = ['name' => $name, 'host' => $host, 'ok' => null, 'status' => null, 'ms' => null, 'error' => 'Not checked (time budget used up).'];
                continue;
            }
            $t0 = microtime(true);
            $ch = curl_init($url);
            curl_setopt_array($ch, [
                CURLOPT_NOBODY         => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => (int) max(1, min(5, floor($left))),
                CURLOPT_TIMEOUT        => (int) max(1, min(10, floor($left))),
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_PROTOCOLS      => CURLPROTO_HTTPS,
                CURLOPT_USERAGENT      => 'FastTransfer/' . FT_VERSION . ' (egress self-test)',
            ]);
            curl_exec($ch);
            $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $err = curl_errno($ch) !== 0 ? curl_error($ch) : null;
            curl_close($ch);
            $hosts[] = [
                'name'   => $name,
                'host'   => $host,
                'ok'     => $status > 0,
                'status' => $status > 0 ? $status : null,
                'ms'     => (int) ((microtime(true) - $t0) * 1000),
                'error'  => $status > 0 ? null : mb_substr((string) $err, 0, 200),
            ];
        }
        $result = ['checked_at' => gmdate('Y-m-d\TH:i:s\Z'), 'hosts' => $hosts];
        @file_put_contents(Paths::runtime() . '/egress.json', (string) json_encode($result, JSON_UNESCAPED_SLASHES), LOCK_EX);
        return $result;
    }

    /** Cached egress results, or null when never checked. */
    public static function egressResults(): ?array
    {
        $file = Paths::runtime() . '/egress.json';
        if (!is_file($file)) {
            return null;
        }
        $d = json_decode((string) @file_get_contents($file), true);
        return is_array($d) ? $d : null;
    }

    // ================================================================== settings

    /**
     * Whitelist + rules for PUT /admin/settings (every key of Settings::DEFAULTS except the
     * maintenance-owned ones). @return array<string,array<string,mixed>>
     */
    public static function settingsSchema(): array
    {
        $int = static fn (int $min, int $max) => ['type' => 'int', 'min' => $min, 'max' => $max];
        return [
            'site_name'                    => ['type' => 'string', 'max' => 100],
            'default_quota_bytes'          => $int(0, PHP_INT_MAX - 1),
            'guest_quota_bytes'            => $int(0, PHP_INT_MAX - 1),
            'max_upload_bytes'             => $int(1048576, 1099511627776),
            'blocked_extensions'           => ['type' => 'extensions'],
            'trash_retention_days'         => ['type' => 'enum_int', 'options' => [0, 7, 30, 60, 90]],
            'version_retention_count'      => $int(0, 100),
            'version_retention_days'       => $int(0, 3650),
            'auto_expire_hours'            => $int(0, 8760),
            'text_auto_expire_hours'       => $int(0, 8760),
            'dedup_scope'                  => ['type' => 'enum', 'options' => ['user', 'global']],
            'event_retention_days'         => $int(1, 90),
            'audit_retention_days'         => $int(0, 3650),
            'login_history_retention_days' => $int(0, 3650),
            'notification_retention_days'  => $int(0, 3650),
            'upload_session_ttl_hours'     => $int(1, 168),
            'bundle_ttl_hours'             => $int(1, 720),
            'quota_warning_percent'        => $int(50, 100),
            'session_idle_minutes'         => $int(5, 43200),
            'remember_days'                => $int(1, 365),
            'login_max_attempts'           => $int(3, 100),
            'login_window_minutes'         => $int(1, 1440),
            'registration_enabled'         => ['type' => 'bool'],
            'ocr_enabled'                  => ['type' => 'bool'],
            'slack_events'                 => ['type' => 'set', 'options' => self::SLACK_EVENTS],
            'slack_webhook_override'       => ['type' => 'slack_webhook', 'secret' => true],
        ];
    }

    /**
     * Validate and normalise a settings update. Unknown or read-only keys and invalid values
     * are rejected with VALIDATION_FAILED (field => message); nothing is saved on error.
     * @return array<string,string> key => value to store
     */
    public static function validateSettings(array $in): array
    {
        $schema = self::settingsSchema();
        $errors = [];
        $out = [];
        if ($in === []) {
            throw ApiException::validation(['settings' => 'Send at least one setting to change.']);
        }
        foreach ($in as $key => $value) {
            $key = (string) $key;
            if (in_array($key, self::READ_ONLY_SETTINGS, true)) {
                $errors[$key] = 'This setting is managed automatically and cannot be changed.';
                continue;
            }
            if (!isset($schema[$key]) || !array_key_exists($key, Settings::DEFAULTS)) {
                $errors[$key] = 'Unknown setting.';
                continue;
            }
            $rule = $schema[$key];
            $err = null;
            $norm = null;
            switch ($rule['type']) {
                case 'string':
                    if (!is_string($value) || trim($value) === '' || mb_strlen(trim($value)) > $rule['max'] || preg_match('/[\x00-\x1F\x7F]/u', $value)) {
                        $err = 'Enter 1–' . $rule['max'] . ' characters.';
                    } else {
                        $norm = trim($value);
                    }
                    break;
                case 'int':
                case 'enum_int':
                    if (is_string($value) && preg_match('/^-?\d+$/', trim($value))) {
                        $value = (int) trim($value);
                    }
                    if (is_float($value) && floor($value) === $value && abs($value) < 9.0e18) {
                        $value = (int) $value;
                    }
                    if (!is_int($value)) {
                        $err = 'Enter a whole number.';
                    } elseif ($rule['type'] === 'enum_int' && !in_array($value, $rule['options'], true)) {
                        $err = 'Choose one of: ' . implode(', ', $rule['options']) . '.';
                    } elseif ($rule['type'] === 'int' && ($value < $rule['min'] || $value > $rule['max'])) {
                        $err = 'Enter a number between ' . $rule['min'] . ' and ' . $rule['max'] . '.';
                    } else {
                        $norm = (string) $value;
                    }
                    break;
                case 'bool':
                    if (is_bool($value) || $value === 0 || $value === 1 || in_array($value, ['0', '1', 'true', 'false'], true)) {
                        $norm = filter_var($value, FILTER_VALIDATE_BOOLEAN) ? '1' : '0';
                    } else {
                        $err = 'Choose on or off.';
                    }
                    break;
                case 'enum':
                    if (!is_string($value) || !in_array($value, $rule['options'], true)) {
                        $err = 'Choose one of: ' . implode(', ', $rule['options']) . '.';
                    } else {
                        $norm = $value;
                    }
                    break;
                case 'extensions':
                    $list = is_array($value) ? $value : (is_string($value) ? explode(',', $value) : null);
                    if ($list === null) {
                        $err = 'Enter a comma-separated list of file extensions.';
                        break;
                    }
                    $exts = [];
                    foreach ($list as $e) {
                        $e = strtolower(ltrim(trim((string) $e), '.'));
                        if ($e === '') {
                            continue;
                        }
                        if (!preg_match('/^[a-z0-9]{1,16}$/', $e)) {
                            $err = 'Extensions may only contain letters and numbers (e.g. exe, bat).';
                            break 2;
                        }
                        $exts[$e] = true;
                    }
                    if (count($exts) > 200) {
                        $err = 'Block at most 200 extensions.';
                    } else {
                        $norm = implode(',', array_keys($exts));
                    }
                    break;
                case 'set':
                    $list = is_array($value) ? $value : (is_string($value) ? explode(',', $value) : null);
                    if ($list === null) {
                        $err = 'Enter a list.';
                        break;
                    }
                    $items = [];
                    foreach ($list as $e) {
                        $e = strtolower(trim((string) $e));
                        if ($e === '') {
                            continue;
                        }
                        if (!in_array($e, $rule['options'], true)) {
                            $err = 'Unknown event "' . mb_substr($e, 0, 30) . '". Allowed: ' . implode(', ', $rule['options']) . '.';
                            break 2;
                        }
                        $items[$e] = true;
                    }
                    $norm = implode(',', array_keys($items));
                    break;
                case 'slack_webhook':
                    if (!is_string($value)) {
                        $err = 'Enter a Slack webhook URL, or leave it empty to use the one in .env.';
                    } elseif (trim($value) === '') {
                        $norm = '';
                    } elseif (!self::isSlackWebhook(trim($value))) {
                        $err = 'Only Slack incoming webhooks (https://hooks.slack.com/…) are allowed.';
                    } else {
                        $norm = trim($value);
                    }
                    break;
            }
            if ($err !== null) {
                $errors[$key] = $err;
            } else {
                $out[$key] = (string) $norm;
            }
        }
        if ($errors !== []) {
            throw ApiException::validation($errors);
        }
        return $out;
    }

    public static function isSlackWebhook(string $url): bool
    {
        if (strlen($url) > 500 || !preg_match('~^https://hooks\.slack\.com/[A-Za-z0-9/_\-]+$~', $url)) {
            return false;
        }
        $parts = parse_url($url);
        return is_array($parts) && ($parts['host'] ?? '') === 'hooks.slack.com' && !isset($parts['port']) && !isset($parts['user']) && !isset($parts['query']);
    }

    // ================================================================== helpers

    /** @return array<int,array{id:int,username:string,display_name:string}> */
    public static function userRefs(array $ids): array
    {
        $ids = array_values(array_unique(array_filter(array_map('intval', $ids), static fn ($i) => $i > 0)));
        if ($ids === []) {
            return [];
        }
        [$in, $p] = Db::inList($ids, 'ur');
        $out = [];
        foreach (Db::all("SELECT id, username, display_name FROM users WHERE id IN {$in}", $p) as $u) {
            $out[(int) $u['id']] = [
                'id'           => (int) $u['id'],
                'username'     => (string) $u['username'],
                'display_name' => (string) (($u['display_name'] ?? '') !== '' ? $u['display_name'] : $u['username']),
            ];
        }
        return $out;
    }

    /** Remove physical paths from diagnostic text before it reaches a browser. */
    public static function scrub(string $text, int $max = 500): string
    {
        $text = str_replace('\\', '/', $text);
        $text = str_replace(
            [str_replace('\\', '/', FT_ROOT), str_replace('\\', '/', (string) Config::get('storage.path')), str_replace('\\', '/', (string) Config::get('legacy.uploads_path'))],
            '…',
            $text
        );
        return mb_substr($text, 0, $max);
    }

    public static function ocrProvider(): ?string
    {
        return \FT\Ocr\OcrService::provider();
    }

    /** @return array{logical:int,physical:int,referenced:int,unique:int,dedup_saved:int,trash:int,versions:int} */
    private static function byteTotals(): array
    {
        $logical = (int) (Db::value('SELECT COALESCE(SUM(used_bytes), 0) FROM users') ?? 0);
        $b = Db::one('SELECT COALESCE(SUM(stored_size), 0) AS physical, COALESCE(SUM(CASE WHEN ref_count > 0 THEN size ELSE 0 END), 0) AS uniq FROM file_blobs') ?? [];
        $v = Db::one(
            'SELECT COALESCE(SUM(v.size), 0) AS referenced,
                    COALESCE(SUM(CASE WHEN f.deleted_at IS NOT NULL THEN v.size ELSE 0 END), 0) AS trash,
                    COALESCE(SUM(CASE WHEN v.version <> f.version THEN v.size ELSE 0 END), 0) AS versions
               FROM file_versions v JOIN files f ON f.id = v.file_id'
        ) ?? [];
        $referenced = (int) ($v['referenced'] ?? 0);
        $unique = (int) ($b['uniq'] ?? 0);
        return [
            'logical'     => $logical,
            'physical'    => (int) ($b['physical'] ?? 0),
            'referenced'  => $referenced,
            'unique'      => $unique,
            'dedup_saved' => max(0, $referenced - $unique),
            'trash'       => (int) ($v['trash'] ?? 0),
            'versions'    => (int) ($v['versions'] ?? 0),
        ];
    }

    /** @return array<string,int> today's daily_stats counters */
    private static function today(array $metrics): array
    {
        $out = array_fill_keys($metrics, 0);
        [$in, $p] = self::strIn($metrics);
        foreach (Db::all("SELECT metric, value FROM daily_stats WHERE day = UTC_DATE() AND metric IN {$in}", $p) as $r) {
            $out[(string) $r['metric']] = (int) $r['value'];
        }
        return $out;
    }

    /** @return array{0:string,1:array<string,string>} */
    private static function strIn(array $values): array
    {
        $ph = [];
        $p = [];
        foreach (array_values($values) as $i => $v) {
            $ph[] = ':m' . $i;
            $p['m' . $i] = (string) $v;
        }
        return ['(' . implode(',', $ph) . ')', $p];
    }

    /** Public URL path of the storage canary file, or null when storage is outside the web root. */
    private static function canaryUrl(string $basePath): ?string
    {
        try {
            $root = str_replace('\\', '/', Paths::root());
        } catch (\Throwable) {
            return null;
        }
        $app = str_replace('\\', '/', FT_ROOT) . '/';
        if (!str_starts_with($root . '/', $app)) {
            return null;
        }
        $rel = substr($root, strlen($app));
        if ($rel === '' || str_contains($rel, '..')) {
            return null;
        }
        return $basePath . implode('/', array_map('rawurlencode', explode('/', $rel))) . '/canary.json';
    }

    private static function shortJobType(string $type): string
    {
        // "FT\Notifications\WebPush::deliverJob" → "WebPush::deliverJob"
        $pos = strrpos($type, '\\');
        return $pos === false ? $type : substr($type, $pos + 1);
    }
}
