<?php
declare(strict_types=1);

use FT\Controllers\Api\FileController;
use FT\Controllers\Api\TagController;
use FT\Controllers\Api\VersionController;
use FT\Http\Router;

// Owner: A3 (files domain). POST /files and /uploads are A2's; /files/{id}/share, /shares,
// /comments, /text and /presence are A4's; /files/{id}/ocr is A6's. Numeric ids are always
// constrained so /files/batch and /files/zip are never captured by /files/{id}.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/files', [FileController::class, 'index']);
        $r->post('/files/batch', [FileController::class, 'batch']);
        $r->post('/files/zip', [FileController::class, 'zip'], ['rate' => 'download']);
        $r->get('/files/{id:\d+}', [FileController::class, 'show']);
        $r->patch('/files/{id:\d+}', [FileController::class, 'update']);
        $r->delete('/files/{id:\d+}', [FileController::class, 'destroy']);
        $r->post('/files/{id:\d+}/restore', [FileController::class, 'restore']);
        $r->get('/files/{id:\d+}/download', [FileController::class, 'download'], ['rate' => 'download']);
        $r->get('/files/{id:\d+}/content', [FileController::class, 'content']);
        $r->get('/files/{id:\d+}/thumbnail', [FileController::class, 'thumbnail']);
        $r->get('/files/{id:\d+}/activity', [FileController::class, 'activity']);
        $r->get('/files/{id:\d+}/versions', [VersionController::class, 'index']);
        $r->get('/files/{id:\d+}/versions/{version:\d+}/download', [VersionController::class, 'download'], ['rate' => 'download']);
        $r->post('/files/{id:\d+}/versions/{version:\d+}/restore', [VersionController::class, 'restore']);
        $r->get('/tags', [TagController::class, 'index']);
    });
};
