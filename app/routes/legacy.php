<?php
declare(strict_types=1);

use FT\Controllers\Web\LegacyController;
use FT\Http\Router;

// Owner: A6. Legacy single-file URLs ("/?share=…", "/?download=…", "/?logout", …). index.php
// rewrites such root requests to /legacy (see FT\Legacy\LegacyRoutes::matches()).
// POST is accepted for the old share password form; the controller only redirects (no state
// change), so no CSRF token is required.
return static function (Router $r): void {
    $opts = ['auth' => 'optional', 'csrf' => false, 'json' => false, 'rate' => 'public'];
    $r->get('/legacy', [LegacyController::class, 'handle'], $opts);
    $r->post('/legacy', [LegacyController::class, 'handle'], $opts);
};
