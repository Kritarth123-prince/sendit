<?php
declare(strict_types=1);

use FT\Controllers\Api\FolderController;
use FT\Http\Router;

// Owner: A3 (folders). POST /folders/{id}/share is A4's.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/folders', [FolderController::class, 'index']);
        $r->get('/folders/tree', [FolderController::class, 'tree']);
        $r->post('/folders', [FolderController::class, 'store']);
        $r->get('/folders/{id:\d+}', [FolderController::class, 'show']);
        $r->patch('/folders/{id:\d+}', [FolderController::class, 'update']);
        $r->delete('/folders/{id:\d+}', [FolderController::class, 'destroy']);
        $r->post('/folders/{id:\d+}/restore', [FolderController::class, 'restore']);
        $r->get('/folders/{id:\d+}/zip', [FolderController::class, 'zip'], ['rate' => 'download']);
    });
};
