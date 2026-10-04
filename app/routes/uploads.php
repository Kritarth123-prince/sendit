<?php
declare(strict_types=1);

use FT\Controllers\Api\UploadController;
use FT\Http\Router;

// Owner: A2 (storage engine). Upload protocol — docs/ARCHITECTURE.md §8.4.
// Upload ids are validated by UploadService (32 lower-case hex); the looser pattern here makes
// every unknown id answer UPLOAD_NOT_FOUND rather than a generic 404.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->post('/uploads', [UploadController::class, 'start']);
        $r->get('/uploads', [UploadController::class, 'index']);
        $r->get('/uploads/{id:[A-Za-z0-9]+}', [UploadController::class, 'show']);
        // Constraints must not contain "{…}" quantifiers: the Router's placeholder syntax ends at "}".
        $r->put('/uploads/{id:[A-Za-z0-9]+}/chunks/{index:\d+}', [UploadController::class, 'chunk'], ['rate' => 'upload_chunk']);
        $r->post('/uploads/{id:[A-Za-z0-9]+}/chunks/{index:\d+}', [UploadController::class, 'chunk'], ['rate' => 'upload_chunk']);
        $r->post('/uploads/{id:[A-Za-z0-9]+}/complete', [UploadController::class, 'complete']);
        $r->delete('/uploads/{id:[A-Za-z0-9]+}', [UploadController::class, 'abort']);
        $r->post('/files', [UploadController::class, 'simple']);
        $r->post('/files/{id:\d+}/versions', [UploadController::class, 'version']);
    });
};
