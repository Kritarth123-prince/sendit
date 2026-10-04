<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\Config;
use FT\Core\RequestContext;
use FT\Http\Request;
use FT\Http\Response;
use FT\Jobs\Queue;
use FT\Maintenance\MaintenanceRunner;
use FT\Maintenance\PseudoCron;

/**
 * POST /api/v1/tick — the leader browser tab calls this about once a minute (§10.3). On hosts
 * where nothing runs after the response, this is what drains the job queue (Web Push, e-mail,
 * thumbnails, OCR) and, when due, runs a pseudo-cron maintenance slice.
 *
 * GET /maintenance?token=… — the token-protected maintenance URL (same as maintenance.php).
 */
final class TickController
{
    /** Seconds of queue work per tick. */
    private const QUEUE_SECONDS = 2.5;
    /** Budget of the maintenance slice a tick may run. */
    private const SLICE_SECONDS = 5.0;

    public function tick(Request $req): array
    {
        // Jobs belong to whoever queued them, never to the user whose tab happens to tick.
        $prev = RequestContext::userId();
        RequestContext::setUserId(null);
        try {
            $jobs = Queue::work(self::QUEUE_SECONDS, 10);
        } finally {
            RequestContext::setUserId($prev);
        }
        $maintenance = null;
        if (Config::get('pseudo_cron.enabled') && PseudoCron::due()) {
            $r = PseudoCron::runSlice('tick', self::SLICE_SECONDS);
            if ($r !== null) {
                // Deliberately minimal: details are for administrators (Admin → System).
                $maintenance = ['ran' => !$r['skipped'], 'complete' => (bool) $r['complete']];
            }
        }
        return ['jobs' => $jobs, 'maintenance' => $maintenance];
    }

    public function maintenance(Request $req): Response
    {
        $token = $req->header('X-Maintenance-Token') ?? (is_string($req->query('token')) ? (string) $req->query('token') : null);
        $task = is_string($req->query('task')) ? (string) $req->query('task') : null;
        [$status, $payload] = MaintenanceRunner::httpRun($token, $task, $req->ip());
        return Response::json($payload, $status, ['X-Robots-Tag' => 'noindex']);
    }
}
