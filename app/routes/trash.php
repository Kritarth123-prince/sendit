<?php
declare(strict_types=1);

use FT\Controllers\Api\TrashController;
use FT\Http\Router;

// Owner: A3 (trash). Admins may restore/purge anyone's items through the same routes.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/trash', [TrashController::class, 'index']);
        $r->delete('/trash', [TrashController::class, 'empty']);
        $r->post('/trash/{id:\d+}/restore', [TrashController::class, 'restore']);
        $r->delete('/trash/{id:\d+}', [TrashController::class, 'destroy']);
        $r->get('/admin/trash', [TrashController::class, 'adminIndex'], ['auth' => 'admin', 'perm' => 'admin.storage']);
    });
};
