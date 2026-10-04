<?php
declare(strict_types=1);

use FT\Controllers\Api\ShareController;
use FT\Http\Router;

// Owner: A4 — shares (links + user shares, bundles, folders), Shared With Me, admin share list.
// Creating shares has its own rate bucket (share_create: 30 per 10 minutes) and is closed to guests.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/shares', [ShareController::class, 'index']);
        $r->post('/shares', [ShareController::class, 'store'], ['rate' => 'share_create', 'guest' => false]);
        $r->get('/shares/with-me', [ShareController::class, 'withMe']);
        $r->get('/shares/{id:\d+}', [ShareController::class, 'show']);
        $r->patch('/shares/{id:\d+}', [ShareController::class, 'update'], ['guest' => false]);
        $r->delete('/shares/{id:\d+}', [ShareController::class, 'destroy'], ['guest' => false]);

        $r->post('/files/{id:\d+}/share', [ShareController::class, 'shareFile'], ['rate' => 'share_create', 'guest' => false]);
        $r->get('/files/{id:\d+}/shares', [ShareController::class, 'forFile']);
        $r->post('/folders/{id:\d+}/share', [ShareController::class, 'shareFolder'], ['rate' => 'share_create', 'guest' => false]);

        $r->get('/admin/shares', [ShareController::class, 'adminIndex'], ['auth' => 'admin', 'perm' => 'admin.shares']);
    });
};
