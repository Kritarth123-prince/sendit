<?php
declare(strict_types=1);

use FT\Controllers\Api\EditorController;
use FT\Http\Router;

// Owner: A4 — in-browser text editor (optimistic concurrency) and editor presence.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/files/{id:\d+}/text', [EditorController::class, 'show']);
        $r->put('/files/{id:\d+}/text', [EditorController::class, 'save']);
        $r->post('/files/{id:\d+}/presence', [EditorController::class, 'presence'], ['rate' => 'realtime']);
    });
};
