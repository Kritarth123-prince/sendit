<?php
declare(strict_types=1);

use FT\Controllers\Api\SearchController;
use FT\Http\Router;

// Owner: A6 — keyword search and on-demand OCR (docs/ARCHITECTURE.md §9.4 "Search").
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/search', [SearchController::class, 'search'], ['perm' => 'search.use']);
        $r->post('/files/{id:\d+}/ocr', [SearchController::class, 'ocr'], ['perm' => 'files.edit']);
    });
};
