<?php
declare(strict_types=1);

use FT\Controllers\Api\CommentController;
use FT\Http\Router;

// Owner: A4 — file comments. Reading needs access to the file; writing the files.comment
// permission plus the comment capability (checked in CommentService).
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/files/{id:\d+}/comments', [CommentController::class, 'index']);
        $r->post('/files/{id:\d+}/comments', [CommentController::class, 'store'], ['perm' => 'files.comment']);
        $r->delete('/comments/{id:\d+}', [CommentController::class, 'destroy']);
    });
};
