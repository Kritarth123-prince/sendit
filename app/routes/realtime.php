<?php
declare(strict_types=1);

use FT\Events\RealtimeController;
use FT\Http\Router;

// Owner: A5 (real-time transport, docs/ARCHITECTURE.md §10.3). All GET (no CSRF).
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        // Missed-event recovery, called after every (re)connect.
        $r->get('/events', [RealtimeController::class, 'recover'], ['rate' => 'realtime']);
        // Server-Sent Events (503 FEATURE_UNAVAILABLE where the host cannot hold requests).
        $r->get('/events/stream', [RealtimeController::class, 'stream'], ['rate' => 'realtime']);
        // Long-poll / short poll. Registered without auth and without the DB rate limiter: the
        // controller authenticates itself so an unchanged short poll never opens a DB connection.
        $r->get('/events/poll', [RealtimeController::class, 'poll'], ['auth' => 'none', 'rate' => null]);
    });
};
