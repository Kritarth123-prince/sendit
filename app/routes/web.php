<?php
declare(strict_types=1);

use FT\Controllers\Web\ShellController;
use FT\Http\Router;

// Owner: FE-CORE. The app shell (signed-in users) or the sign-in page (signed-out visitors),
// and the boot data the web client can re-fetch (e.g. after an in-place re-login).
return static function (Router $r): void {
    $r->get('/', [ShellController::class, 'show'], ['auth' => 'optional', 'json' => false, 'rate' => null]);

    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/bootstrap', [ShellController::class, 'bootstrap']);
    });
};
