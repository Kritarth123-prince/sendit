<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Files\TagService;
use FT\Http\Request;

/** /api/v1/tags (A3): the signed-in user's own tags with usage counts. */
final class TagController
{
    /** GET /tags (?all=1 includes tags no live file uses any more) */
    public function index(Request $req): array
    {
        return TagService::listForOwner((int) $req->user['id'], $req->bool('all'));
    }
}
