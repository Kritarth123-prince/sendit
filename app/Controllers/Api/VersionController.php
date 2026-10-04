<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Files\FileRepository;
use FT\Files\VersionService;
use FT\Http\Request;
use FT\Http\Response;

/** /api/v1/files/{id}/versions… (A3). New versions are uploaded through A2's upload sessions. */
final class VersionController
{
    /** GET /files/{id}/versions */
    public function index(Request $req): array
    {
        return VersionService::list($req->user, $req->intParam('id'));
    }

    /** GET /files/{id}/versions/{version}/download */
    public function download(Request $req): ?Response
    {
        VersionService::download($req, $req->user, $req->intParam('id'), $req->intParam('version'));
        return null;
    }

    /** POST /files/{id}/versions/{version}/restore → FileSummary */
    public function restore(Request $req): array
    {
        $row = VersionService::restore($req->user, $req->intParam('id'), $req->intParam('version'));
        return FileRepository::summary($row, $req->user);
    }
}
