<?php
declare(strict_types=1);

use FT\Controllers\Web\InstallController;
use FT\Http\Router;

// Web installer / upgrader. Reachable even when the app is not installed (see index.php).
// The controller manages its own session, CSRF token and INSTALL_TOKEN gate (the database may
// not exist yet, so none of the DB-backed middleware can run here).
return static function (Router $r): void {
    $opts = ['auth' => 'none', 'csrf' => false, 'rate' => null, 'json' => false];
    $r->get('/install', [InstallController::class, 'show'], $opts);
    $r->post('/install', [InstallController::class, 'act'], $opts);
};
