<?php
/**
 * FastTransfer maintenance runner (docs/ARCHITECTURE.md §13.1).
 *
 * CLI (cron, SSH):
 *     php maintenance.php                       run every scheduled task (time-boxed, resumable)
 *     php maintenance.php --task=purge_trash    run named task(s), comma-separated
 *     php maintenance.php --verbose             one line per task
 *     php maintenance.php --budget=120 --json   longer budget; machine-readable output
 *
 * Web (hosts without cron; e.g. an external pinger where the host allows it):
 *     https://example.com/maintenance.php?token=<MAINTENANCE_TOKEN>[&task=name]
 *   Returns JSON. Refused when MAINTENANCE_TOKEN is unset/short or the token is wrong
 *   (constant-time comparison, failed attempts rate-limited per IP). The token may also be sent
 *   in an "X-Maintenance-Token" header so it does not end up in access logs.
 *
 * Without cron, the built-in pseudo-cron and the browser "tick" run the same tasks automatically.
 */
declare(strict_types=1);

require __DIR__ . '/app/bootstrap.php';

use FT\Core\RequestContext;
use FT\Maintenance\MaintenanceRunner;
use FT\Support\Capabilities;
use FT\Support\Install;

if (PHP_SAPI === 'cli') {
    RequestContext::initCli();
    $opts = getopt('', ['task:', 'verbose', 'budget:', 'json', 'help']);
    if (isset($opts['help'])) {
        echo "Usage: php maintenance.php [--task=name[,name]] [--budget=seconds] [--verbose] [--json]\n";
        echo 'Tasks: ' . implode(', ', array_merge(MaintenanceRunner::TASKS, MaintenanceRunner::ON_DEMAND)) . "\n";
        exit(0);
    }
    if (!Install::isReady()) {
        fwrite(STDERR, "FastTransfer is not installed or needs an upgrade. Open /install in a browser first.\n");
        exit(2);
    }
    $budget = isset($opts['budget']) && is_numeric($opts['budget']) ? max(1.0, min(3600.0, (float) $opts['budget'])) : 120.0;
    $tasks = null;
    if (isset($opts['task']) && is_string($opts['task']) && trim($opts['task']) !== '') {
        $tasks = array_values(array_filter(array_map('trim', explode(',', $opts['task'])), static fn ($t) => $t !== ''));
        foreach ($tasks as $t) {
            if (!MaintenanceRunner::isTask($t)) {
                fwrite(STDERR, "Unknown task: {$t}\nRun with --help to list the tasks.\n");
                exit(2);
            }
        }
    }
    Capabilities::setTimeLimit((int) $budget + 120);
    $result = MaintenanceRunner::run('cli', $tasks, $budget);
    if (isset($opts['json'])) {
        echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), "\n";
    } elseif ($result['skipped']) {
        echo 'Skipped: ' . ($result['reason'] ?? 'another run is in progress') . "\n";
    } else {
        if (isset($opts['verbose'])) {
            foreach ($result['tasks'] as $name => $t) {
                printf("%-22s %-8s %6d item(s) %6d ms%s\n", $name, $t['status'], $t['items'], $t['duration_ms'], $t['message'] !== null && $t['message'] !== '' ? '  ' . $t['message'] : '');
            }
        }
        printf("Run %s: %d task(s) in %d ms%s\n", $result['run_id'], count($result['tasks']), $result['duration_ms'], $result['complete'] ? '' : ' (budget used up; the next run continues)');
    }
    $errors = count(array_filter($result['tasks'], static fn ($t) => $t['status'] === 'error'));
    exit($errors > 0 ? 1 : 0);
}

// ---------------------------------------------------------------- web mode
RequestContext::init(
    filter_var($_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ? (string) $_SERVER['REMOTE_ADDR'] : '0.0.0.0',
    isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : null
);
$token = $_SERVER['HTTP_X_MAINTENANCE_TOKEN'] ?? ($_POST['token'] ?? ($_GET['token'] ?? null));
$task = $_POST['task'] ?? ($_GET['task'] ?? null);
try {
    [$status, $payload] = MaintenanceRunner::httpRun(
        is_string($token) ? $token : null,
        is_string($task) ? $task : null,
        (string) RequestContext::ip()
    );
} catch (Throwable $e) {
    FT\Core\Logger::exception('maintenance', $e);
    [$status, $payload] = [500, ['success' => false, 'error' => ['code' => 'SERVER_ERROR', 'message' => 'Maintenance failed. See the server logs.']]];
}
if (!headers_sent()) {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    header('X-FT-Api: 1');
    header('X-Robots-Tag: noindex');
}
echo json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
