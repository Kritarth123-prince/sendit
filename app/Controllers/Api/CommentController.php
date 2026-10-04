<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Comments\CommentService;
use FT\Http\Request;
use FT\Http\Response;

/** File comments (docs/ARCHITECTURE.md §9.4 "Comments"). */
final class CommentController
{
    /** GET /files/{id}/comments */
    public function index(Request $req): array
    {
        return CommentService::list($req->user, $req->intParam('id'));
    }

    /** POST /files/{id}/comments {body} */
    public function store(Request $req): Response
    {
        return Response::created(CommentService::create($req->user, $req->intParam('id'), $req->input('body')));
    }

    /** DELETE /comments/{id} */
    public function destroy(Request $req): Response
    {
        CommentService::delete($req->user, $req->intParam('id'));
        return Response::noContent();
    }
}
