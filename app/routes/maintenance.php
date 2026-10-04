<?php
declare(strict_types=1);

use FT\Controllers\Api\TickController;
use FT\Http\Router;

// Owner: A6. Token-protected maintenance URL, the routed twin of maintenance.php's web mode.
// No session/CSRF: the MAINTENANCE_TOKEN is the credential (checked in constant time,
// wrong tokens rate-limited per IP by MaintenanceRunner::httpRun()).
return static function (Router $r): void {
    $r->get('/maintenance', [TickController::class, 'maintenance'], ['auth' => 'none', 'csrf' => false, 'rate' => 'public', 'json' => true]);
};
