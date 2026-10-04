<?php
declare(strict_types=1);

use FT\Controllers\Api\TickController;
use FT\Http\Router;

// Owner: A6. Background work driven by the leader browser tab (docs/ARCHITECTURE.md §10.3):
// CSRF-protected, at most 4 calls per minute per user.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->post('/tick', [TickController::class, 'tick'], ['rate' => 'tick']);
    });
};
