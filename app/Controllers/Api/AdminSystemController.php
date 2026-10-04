<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Admin\StatsService;
use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Settings;
use FT\Database\Migrator;
use FT\Events\EventBus;
use FT\Http\Request;
use FT\Http\Response;
use FT\Legacy\EncryptionMigrator;
use FT\Legacy\LegacyImporter;
use FT\Maintenance\MaintenanceRunner;
use FT\Security\RateLimiter;
use FT\Support\Capabilities;
use FT\Support\Install;

/**
 * Admin → System APIs (docs/ARCHITECTURE.md §9.4 "Admin [A6]"): health/diagnostics, runtime
 * settings, maintenance, migrations, legacy import, encryption migration, failed jobs, VAPID key
 * generation and the Slack test. All routes: role admin + permission admin.system.
 *
 * Every state change is audited (category admin/system) and settings changes are announced on
 * the admin real-time channel. Secrets are write-only: GET never returns them (masked) and
 * generated VAPID keys are returned once and never stored or logged.
 */
final class AdminSystemController
{
    /** GET /api/v1/admin/system */
    public function system(Request $req): array
    {
        return StatsService::system($req->basePath());
    }

    /** GET /api/v1/admin/settings → Settings::all() (secrets masked) + the validation schema. */
    public function settings(Request $req): Response
    {
        return Response::ok(self::settingsView(), ['schema' => StatsService::settingsSchema()]);
    }

    /** PUT|PATCH /api/v1/admin/settings {key: value, …} (or {"settings": {…}}) */
    public function updateSettings(Request $req): Response
    {
        $in = $req->json() ?? $req->all();
        if (isset($in['settings']) && is_array($in['settings']) && count($in) === 1) {
            $in = $in['settings'];
        }
        $values = StatsService::validateSettings($in);
        $before = Settings::all(true);
        $uid = (int) $req->user['id'];
        Db::transaction(static function () use ($values, $uid): void {
            foreach ($values as $k => $v) {
                Settings::set($k, $v, $uid);
            }
        });
        Settings::forget();
        $keys = array_keys($values);
        $changes = [];
        foreach ($values as $k => $v) {
            if (in_array($k, Settings::SECRET_KEYS, true)) {
                $changes[$k] = $v === '' ? 'cleared' : 'changed';
            } elseif ((string) ($before[$k] ?? '') !== $v) {
                $changes[$k] = ['from' => (string) ($before[$k] ?? ''), 'to' => $v];
            }
        }
        Audit::log('admin.settings', [
            'user_id'     => $uid,
            'category'    => 'admin',
            'target_type' => 'system',
            'detail'      => 'Settings changed: ' . implode(', ', $keys),
            'meta'        => ['keys' => $keys, 'changes' => $changes],
        ]);
        EventBus::publish('settings.updated', ['keys' => $keys], [], ['admin' => true, 'actor_id' => $uid]);
        return Response::ok(self::settingsView(), ['updated' => $keys]);
    }

    /** POST /api/v1/admin/maintenance/run {task?: "name" | ["a","b"]} */
    public function runMaintenance(Request $req): array
    {
        $task = $req->input('task');
        $tasks = null;
        if (is_string($task) && trim($task) !== '') {
            $tasks = array_values(array_filter(array_map('trim', explode(',', $task)), static fn ($t) => $t !== ''));
        } elseif (is_array($task) && $task !== []) {
            $tasks = array_values(array_map(static fn ($t) => is_string($t) ? trim($t) : '', $task));
        }
        foreach ($tasks ?? [] as $t) {
            if (!MaintenanceRunner::isTask($t)) {
                throw ApiException::validation(['task' => 'Unknown maintenance task.']);
            }
        }
        $r = MaintenanceRunner::run('admin', $tasks, 20.0);
        Audit::log('system.maintenance', [
            'user_id'  => (int) $req->user['id'],
            'category' => 'system',
            'detail'   => $tasks === null ? 'Maintenance run started by an administrator' : 'Maintenance task(s) run: ' . implode(', ', $tasks),
            'meta'     => ['run_id' => $r['run_id'], 'skipped' => $r['skipped'], 'tasks' => count($r['tasks'])],
        ]);
        return $r;
    }

    /** GET /api/v1/admin/maintenance/logs?task=&status=&run_id=&trigger=&page= */
    public function maintenanceLogs(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $where = ['1 = 1'];
        $p = [];
        $task = $req->string('task', '', 64);
        if ($task !== '') {
            $where[] = 'task = :task';
            $p['task'] = $task;
        }
        $status = $req->string('status', '', 16);
        if ($status !== '') {
            if (!in_array($status, ['ok', 'partial', 'error', 'skipped'], true)) {
                throw ApiException::validation(['status' => 'Choose ok, partial, error or skipped.']);
            }
            $where[] = 'status = :status';
            $p['status'] = $status;
        }
        $run = $req->string('run_id', '', 16);
        if ($run !== '') {
            $where[] = 'run_id = :run';
            $p['run'] = $run;
        }
        $trigger = $req->string('trigger', '', 16);
        if ($trigger !== '') {
            $where[] = 'trigger_source = :trig';
            $p['trig'] = $trigger;
        }
        $sql = implode(' AND ', $where);
        $total = (int) Db::value("SELECT COUNT(*) FROM maintenance_logs WHERE {$sql}", $p);
        $p['lim'] = $per;
        $p['off'] = ($page - 1) * $per;
        $rows = Db::all("SELECT * FROM maintenance_logs WHERE {$sql} ORDER BY id DESC LIMIT :lim OFFSET :off", $p);
        $items = array_map(static fn ($r) => [
            'id'          => (int) $r['id'],
            'run_id'      => (string) $r['run_id'],
            'task'        => (string) $r['task'],
            'trigger'     => (string) $r['trigger_source'],
            'status'      => (string) $r['status'],
            'items'       => (int) $r['items'],
            'message'     => $r['message'] !== null ? StatsService::scrub((string) $r['message']) : null,
            'started_at'  => Db::iso((string) $r['started_at']),
            'finished_at' => Db::iso($r['finished_at']),
            'duration_ms' => $r['duration_ms'] !== null ? (int) $r['duration_ms'] : null,
        ], $rows);
        return Response::paginated($items, $total, $page, $per);
    }

    /** POST /api/v1/admin/migrations/run — apply pending migrations (with a backup), then mark installed. */
    public function runMigrations(Request $req): array
    {
        $uid = (int) $req->user['id'];
        Capabilities::setTimeLimit(120);
        try {
            $applied = Migrator::migrate(true);
        } catch (\RuntimeException $e) {
            if (str_contains($e->getMessage(), 'already running')) {
                throw ApiException::conflict('Another migration is already running. Try again in a minute.');
            }
            throw $e;
        }
        Install::markInstalled(['upgraded_by' => $uid]);
        Audit::log('system.migration', [
            'user_id'  => $uid,
            'category' => 'system',
            'detail'   => $applied === [] ? 'Database already up to date' : 'Database migrations applied: ' . implode(', ', $applied),
            'meta'     => ['applied' => $applied, 'schema' => Install::latestMigration()],
        ]);
        return ['applied' => $applied, 'pending' => Migrator::pending(), 'schema' => Install::latestMigration()];
    }

    /**
     * POST /api/v1/admin/legacy-import {step?: "run"|"status", options?: {share_imported_with_all_users,
     * create_legacy_users, user_map, retry_failed}} — call repeatedly until data.done is true.
     */
    public function legacyImport(Request $req): array
    {
        $step = $req->string('step', 'run', 10);
        if (!in_array($step, ['run', 'status'], true)) {
            throw ApiException::validation(['step' => 'Use "run" or "status".']);
        }
        if ($step === 'status') {
            return LegacyImporter::status();
        }
        $in = $req->input('options');
        $in = is_array($in) ? $in : [];
        $options = [
            'admin_user_id' => (int) $req->user['id'],
            'share_imported_with_all_users' => array_key_exists('share_imported_with_all_users', $in) ? (bool) filter_var($in['share_imported_with_all_users'], FILTER_VALIDATE_BOOLEAN) : true,
            'create_legacy_users' => array_key_exists('create_legacy_users', $in) ? (bool) filter_var($in['create_legacy_users'], FILTER_VALIDATE_BOOLEAN) : true,
            'retry_failed' => (bool) filter_var($in['retry_failed'] ?? false, FILTER_VALIDATE_BOOLEAN),
        ];
        if (isset($in['user_map'])) {
            if (!is_array($in['user_map']) || count($in['user_map']) > 500) {
                throw ApiException::validation(['user_map' => 'Map old usernames to user ids, e.g. {"alice": 4}.']);
            }
            $map = [];
            foreach ($in['user_map'] as $legacy => $uid) {
                if (!is_string($legacy) || !is_numeric($uid) || (int) $uid <= 0 || Db::value('SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL', [(int) $uid]) === null) {
                    throw ApiException::validation(['user_map' => 'Every entry must map an old username to an existing user id.']);
                }
                $map[$legacy] = (int) $uid;
            }
            $options['user_map'] = $map;
        }
        if (!LegacyImporter::hasLegacyData()) {
            throw ApiException::notFound('legacy data');
        }
        Capabilities::setTimeLimit(60);
        $r = LegacyImporter::run($options, 15.0);
        Audit::log('admin.legacy_import', [
            'user_id'  => (int) $req->user['id'],
            'category' => 'admin',
            'detail'   => $r['done'] ? 'Legacy import batch finished the import' : 'Legacy import batch ran',
            'meta'     => ['done' => $r['done'], 'phase' => $r['phase'], 'counts' => $r['counts']],
        ]);
        return $r;
    }

    /** POST /api/v1/admin/encryption/migrate {retry_failed?: bool} → batch progress */
    public function encryptionMigrate(Request $req): array
    {
        if ($req->bool('retry_failed')) {
            EncryptionMigrator::clearFailures();
        }
        Capabilities::setTimeLimit(60);
        $r = EncryptionMigrator::migrateBatch(15.0);
        Audit::log('admin.encryption_migrate', [
            'user_id'  => (int) $req->user['id'],
            'category' => 'admin',
            'detail'   => 'Encryption migration batch: ' . $r['migrated'] . ' converted, ' . $r['failed'] . ' failed',
            'meta'     => ['migrated' => $r['migrated'], 'failed' => $r['failed'], 'remaining' => $r['remaining']],
        ]);
        return $r + ['status' => EncryptionMigrator::status()];
    }

    /** GET /api/v1/admin/encryption → status only */
    public function encryptionStatus(Request $req): array
    {
        return EncryptionMigrator::status();
    }

    /** POST /api/v1/admin/jobs/retry {id?} — re-queue one failed job, or all of them. */
    public function retryJobs(Request $req): array
    {
        $id = $req->int('id', 0, 0);
        $now = Db::now();
        if ($id > 0) {
            $n = Db::run(
                'UPDATE jobs SET failed_at = NULL, attempts = 0, reserved_at = NULL, reserved_by = NULL, available_at = :now WHERE id = :id AND failed_at IS NOT NULL',
                ['now' => $now, 'id' => $id]
            )->rowCount();
            if ($n === 0) {
                throw ApiException::notFound('failed job');
            }
        } else {
            $n = Db::run(
                'UPDATE jobs SET failed_at = NULL, attempts = 0, reserved_at = NULL, reserved_by = NULL, available_at = :now WHERE failed_at IS NOT NULL',
                ['now' => $now]
            )->rowCount();
        }
        Audit::log('admin.jobs_retry', ['user_id' => (int) $req->user['id'], 'category' => 'admin', 'detail' => $n . ' failed job(s) queued again', 'meta' => ['id' => $id > 0 ? $id : null, 'count' => $n]]);
        return ['retried' => $n];
    }

    /** POST /api/v1/admin/vapid/generate → a new key pair, shown once (never stored or logged). */
    public function vapid(Request $req): Response
    {
        $svc = 'FT\\Notifications\\WebPush';
        if (!class_exists($svc) || !method_exists($svc, 'generateVapidKeys') || !Capabilities::hasEcCrypto()) {
            throw ApiException::unavailable('Generating push keys needs OpenSSL with elliptic-curve support on this server.');
        }
        $keys = $svc::generateVapidKeys();
        if (!is_array($keys) || !isset($keys['public_key'], $keys['private_key'])) {
            throw ApiException::server('The key pair could not be generated.');
        }
        Audit::log('admin.vapid_generate', ['user_id' => (int) $req->user['id'], 'category' => 'admin', 'detail' => 'A new push (VAPID) key pair was generated']);
        return Response::ok([
            'public_key'  => (string) $keys['public_key'],
            'private_key' => (string) $keys['private_key'],
            'env'         => 'VAPID_PUBLIC_KEY=' . $keys['public_key'] . "\nVAPID_PRIVATE_KEY=" . $keys['private_key'],
            'note'        => 'Copy both lines into .env now — the private key is not stored and will not be shown again.',
        ]);
    }

    /** POST /api/v1/admin/slack/test {webhook?} — only https://hooks.slack.com/ URLs. */
    public function slackTest(Request $req): array
    {
        $svc = 'FT\\Notifications\\Slack';
        if (!class_exists($svc) || !method_exists($svc, 'test')) {
            throw ApiException::unavailable('Slack notifications are not available in this build.');
        }
        $given = $req->string('webhook', '', 500);
        if ($given !== '') {
            $url = $given;
        } elseif (method_exists($svc, 'webhookUrl')) {
            $url = (string) $svc::webhookUrl();
        } else {
            $url = Settings::string('slack_webhook_override') !== '' ? Settings::string('slack_webhook_override') : (string) Config::get('slack.webhook');
        }
        if ($url === '') {
            throw ApiException::validation(['webhook' => 'No Slack webhook is configured. Enter one to test it.']);
        }
        if (!StatsService::isSlackWebhook($url)) {
            throw ApiException::validation(['webhook' => 'Only Slack incoming webhooks (https://hooks.slack.com/…) are allowed.']);
        }
        RateLimiter::enforce('share_create', 'slack-test|u' . (int) $req->user['id']);
        $ok = (bool) $svc::test($url);
        Audit::log('admin.slack_test', ['user_id' => (int) $req->user['id'], 'category' => 'admin', 'detail' => $ok ? 'Slack test message delivered' : 'Slack test message failed']);
        return ['delivered' => $ok];
    }

    /** Settings for the admin UI: masked secrets, typed values. */
    private static function settingsView(): array
    {
        $out = [];
        $schema = StatsService::settingsSchema();
        foreach (Settings::all(false) as $k => $v) {
            $type = $schema[$k]['type'] ?? 'string';
            $out[$k] = match ($type) {
                'int', 'enum_int' => is_numeric($v) ? (int) $v : $v,
                'bool'            => in_array(strtolower((string) $v), ['1', 'true', 'yes', 'on'], true),
                default           => $v,
            };
            if ($k === 'events_pruned_before_id') {
                $out[$k] = (int) $v;
            }
        }
        return $out;
    }
}
