<?php
declare(strict_types=1);

use FT\Controllers\Web\PublicShareController;
use FT\Http\Router;

// Owner: A4 — public link pages (no sign-in). Tokens: 22-char base62, legacy 32-hex (length is
// checked in the controller: the router's {name:regex} syntax cannot contain "{n,m}").
// Rate buckets are per IP: page views "public", file transfer "download", comments
// "public_comment"; password attempts use "share_password" per IP + share inside the controller.
// POSTs verify the page's CSRF token themselves so a stale form can be re-shown with a message.
return static function (Router $r): void {
    $r->group('/s/{token:[A-Za-z0-9]+}', static function (Router $r): void {
        $r->get('', [PublicShareController::class, 'show'], ['rate' => 'public']);
        $r->post('/unlock', [PublicShareController::class, 'unlock'], ['csrf' => false, 'rate' => 'public']);
        $r->get('/download', [PublicShareController::class, 'download'], ['rate' => 'download']);
        $r->get('/content/{fileId:\d+}', [PublicShareController::class, 'content'], ['rate' => 'download']);
        $r->get('/thumbnail/{fileId:\d+}', [PublicShareController::class, 'thumbnail'], ['rate' => 'download']);
        $r->get('/zip', [PublicShareController::class, 'zip'], ['rate' => 'download']);
        $r->get('/folder/{folderId:\d+}', [PublicShareController::class, 'folder'], ['rate' => 'public', 'json' => true]);
        $r->get('/comments', [PublicShareController::class, 'comments'], ['rate' => 'public', 'json' => true]);
        $r->post('/comments', [PublicShareController::class, 'comment'], ['csrf' => false, 'rate' => 'public_comment']);
        $r->post('/upload', [PublicShareController::class, 'upload'], ['csrf' => false, 'rate' => 'public']);
    }, ['auth' => 'none']);
};
