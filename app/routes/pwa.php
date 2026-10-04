<?php
declare(strict_types=1);

use FT\Controllers\Web\PwaController;
use FT\Http\Router;

// Owner: W2-ADMIN (PWA, docs/ARCHITECTURE.md §12.6). Served by PHP so they carry the right base
// path, version and headers (Apache Header/AddType are unavailable on byethost). Public: the
// manifest is fetched with credentials, the service worker and the offline page need no session.
return static function (Router $r): void {
    $public = ['auth' => 'none', 'json' => false, 'rate' => null];
    $r->get('/manifest.webmanifest', [PwaController::class, 'manifest'], $public);
    $r->get('/service-worker.js', [PwaController::class, 'serviceWorker'], $public);
    $r->get('/offline', [PwaController::class, 'offline'], $public);
};
