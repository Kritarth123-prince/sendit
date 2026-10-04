<?php
declare(strict_types=1);

use FT\Controllers\Api\SecurityController;
use FT\Http\Router;

// Owner: A1 — Security Centre. Everything is scoped to the signed-in user's own rows.
return static function (Router $r): void {
    $r->group('/api/v1/security', static function (Router $r): void {
        $r->get('/overview', [SecurityController::class, 'overview']);
        $r->get('/sessions', [SecurityController::class, 'sessions']);
        $r->post('/sessions/revoke-all', [SecurityController::class, 'revokeAll']);
        $r->delete('/sessions/{id:\d+}', [SecurityController::class, 'revokeSession']);
        $r->get('/logins', [SecurityController::class, 'logins']);
        $r->get('/events', [SecurityController::class, 'events']);
        $r->get('/devices', [SecurityController::class, 'devices']);
        $r->get('/tokens', [SecurityController::class, 'tokens']);
        $r->post('/tokens', [SecurityController::class, 'createToken']);
        $r->delete('/tokens/{id:\d+}', [SecurityController::class, 'revokeToken']);
    });
};
