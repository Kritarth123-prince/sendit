<?php
declare(strict_types=1);

use FT\Controllers\Api\TextController;
use FT\Http\Router;

// Owner: A4 — clipboard texts (legacy "Save Text or URL", now per user) and link previews.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/texts', [TextController::class, 'index']);
        $r->post('/texts', [TextController::class, 'store']);
        $r->get('/texts/{id:\d+}', [TextController::class, 'show']);
        $r->patch('/texts/{id:\d+}', [TextController::class, 'update']);
        $r->delete('/texts/{id:\d+}', [TextController::class, 'destroy']);
        $r->get('/url-meta', [TextController::class, 'urlMeta']);
    }, ['perm' => 'texts.manage', 'guest' => false]);
};
