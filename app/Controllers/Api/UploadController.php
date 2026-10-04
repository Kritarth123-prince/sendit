<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Auth\Auth;
use FT\Core\ApiException;
use FT\Http\Request;
use FT\Http\Response;
use FT\Uploads\UploadService;

/**
 * Resumable uploads (/api/v1/uploads…) and the single-request upload (POST /api/v1/files).
 * All validation and authorisation lives in UploadService; this class only maps HTTP.
 *
 * Chunk and complete requests release the PHP session lock immediately (after the Router has
 * authenticated the user and verified CSRF): PHP sessions are exclusive, and a locked session
 * would serialise a browser's parallel chunk uploads and block its other tabs.
 */
final class UploadController
{
    /** POST /uploads {name,size,folder_id?,file_id?,mime?,tags?,is_permanent?,on_conflict?,last_modified?} → 201 */
    public function start(Request $req): Response
    {
        $in = $req->json();
        if ($in === null) {
            $in = $_POST;
        }
        return Response::created(UploadService::start($req->user, $in));
    }

    /** GET /uploads?status=active — this user's uploads on every device. */
    public function index(Request $req): Response
    {
        $status = $req->string('status', 'active', 16);
        $items = UploadService::listFor($req->user, $status === '' ? 'active' : $status);
        return Response::ok($items, ['total' => count($items)]);
    }

    /** GET /uploads/{id} */
    public function show(Request $req): array
    {
        return UploadService::status($req->user, (string) $req->param('id'));
    }

    /** PUT|POST /uploads/{id}/chunks/{index} — raw body (application/octet-stream). */
    public function chunk(Request $req): array
    {
        Auth::closeSession();
        $len = $req->header('Content-Length');
        $declared = ($len !== null && ctype_digit(trim($len))) ? (int) trim($len) : null;
        $sha = $req->header('X-Chunk-Sha256');
        $sha = $sha !== null && trim($sha) !== '' ? trim($sha) : null;
        $contentType = strtolower((string) ($req->header('Content-Type') ?? ''));
        if (str_starts_with($contentType, 'multipart/') || str_starts_with($contentType, 'application/x-www-form-urlencoded')) {
            throw new ApiException('CHUNK_INVALID', 'Send each chunk as the raw request body (Content-Type: application/octet-stream).', 415);
        }
        $body = $req->bodyStream();
        try {
            return UploadService::putChunk($req->user, (string) $req->param('id'), $req->intParam('index'), $body, $declared, $sha);
        } finally {
            fclose($body);
        }
    }

    /** POST /uploads/{id}/complete → 201 FileSummary (idempotent). */
    public function complete(Request $req): Response
    {
        Auth::closeSession();
        return Response::created(UploadService::complete($req->user, (string) $req->param('id')));
    }

    /** DELETE /uploads/{id} → 204 */
    public function abort(Request $req): Response
    {
        UploadService::abort($req->user, (string) $req->param('id'));
        return Response::noContent();
    }

    /** POST /files (multipart: file, folder_id?, file_id?, tags?, is_permanent?, on_conflict?, name?) → 201 FileSummary */
    public function simple(Request $req): Response
    {
        Auth::closeSession();
        $file = $_FILES['file'] ?? null;
        $in = [];
        foreach (['folder_id', 'file_id', 'tags', 'is_permanent', 'on_conflict', 'name', 'description'] as $k) {
            if (array_key_exists($k, $_POST)) {
                $in[$k] = $_POST[$k];
            }
        }
        return Response::created(UploadService::simpleUpload($req->user, is_array($file) ? $file : null, $in));
    }

    /**
     * POST /files/{id}/versions — documented alias for a new version (§9.4): a multipart body
     * uploads it in one request (→ FileSummary); a JSON body {name,size} starts a resumable
     * session for that file (→ session shape, then chunks + complete as usual).
     */
    public function version(Request $req): Response
    {
        $fileId = $req->intParam('id');
        if (str_starts_with(strtolower((string) ($req->header('Content-Type') ?? '')), 'multipart/form-data')) {
            Auth::closeSession();
            $file = $_FILES['file'] ?? null;
            $in = ['file_id' => $fileId];
            if (isset($_POST['name'])) {
                $in['name'] = $_POST['name'];
            }
            return Response::created(UploadService::simpleUpload($req->user, is_array($file) ? $file : null, $in));
        }
        $in = $req->json() ?? $_POST;
        $in['file_id'] = $fileId;
        return Response::created(UploadService::start($req->user, $in));
    }
}
