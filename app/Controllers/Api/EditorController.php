<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Collab\EditorService;
use FT\Core\ApiException;
use FT\Http\Request;

/**
 * In-browser text editor and presence (docs/ARCHITECTURE.md §9.4).
 *
 * PUT /files/{id}/text accepts JSON {content, base_version} or — for files close to the 2 MB
 * limit, whose JSON encoding would exceed the 2 MB JSON body cap — a raw text/plain body with
 * base_version in the query string or an X-Base-Version header.
 */
final class EditorController
{
    /** GET /files/{id}/text */
    public function show(Request $req): array
    {
        return EditorService::read($req->user, $req->intParam('id'));
    }

    /** PUT /files/{id}/text */
    public function save(Request $req): array
    {
        $ctype = strtolower((string) ($req->header('Content-Type') ?? ''));
        if (str_starts_with($ctype, 'text/plain')) {
            $declared = (int) ($req->header('Content-Length') ?? 0);
            if ($declared > EditorService::MAX_BYTES) {
                throw ApiException::tooLarge('Files larger than 2 MB cannot be saved from the browser editor.');
            }
            $h = $req->bodyStream();
            $content = (string) stream_get_contents($h, EditorService::MAX_BYTES + 1);
            fclose($h);
            $base = $req->header('X-Base-Version') ?? $req->query('base_version');
            return EditorService::save($req->user, $req->intParam('id'), $content, is_string($base) ? trim($base) : $base);
        }
        return EditorService::save($req->user, $req->intParam('id'), $req->input('content'), $req->input('base_version'));
    }

    /** POST /files/{id}/presence {leave?:bool} → {users:[UserRef]} */
    public function presence(Request $req): array
    {
        return EditorService::heartbeat($req->user, $req->intParam('id'), $req->clientId(), $req->bool('leave'));
    }
}
