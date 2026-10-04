<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\ApiException;
use FT\Http\Request;
use FT\Http\Response;
use FT\Notepads\NotepadService;

/**
 * Notepads (docs/API.md §5.12a): team and private notepads, autosave with optimistic
 * concurrency, history and presence.
 *
 * PUT /notepads/{id}/content accepts JSON {content, base_version, client_id?} or — for texts
 * close to the 1 MiB limit, whose JSON encoding could pass the 2 MiB JSON body cap — a raw
 * text/plain body with base_version in an X-Base-Version header (or the query string) and the
 * editor's client id in X-Notepad-Client.
 */
final class NotepadController
{
    /** GET /notepads */
    public function index(Request $req): array
    {
        return NotepadService::list($req->user);
    }

    /** POST /notepads {title, visibility} */
    public function store(Request $req): Response
    {
        return Response::created(NotepadService::create($req->user, $req->input('title'), $req->input('visibility')));
    }

    /** GET /notepads/{id} */
    public function show(Request $req): array
    {
        return NotepadService::get($req->user, $req->intParam('id'));
    }

    /** PATCH /notepads/{id} {title?, visibility?} */
    public function update(Request $req): array
    {
        $in = $req->json() ?? $_POST;
        return NotepadService::update($req->user, $req->intParam('id'), is_array($in) ? $in : []);
    }

    /** DELETE /notepads/{id} */
    public function destroy(Request $req): Response
    {
        NotepadService::delete($req->user, $req->intParam('id'));
        return Response::noContent();
    }

    /** PUT /notepads/{id}/content */
    public function saveContent(Request $req): array
    {
        $id = $req->intParam('id');
        $ctype = strtolower((string) ($req->header('Content-Type') ?? ''));
        if (str_starts_with($ctype, 'text/plain')) {
            NotepadService::assertSize((int) ($req->header('Content-Length') ?? 0));
            $h = $req->bodyStream();
            $content = (string) stream_get_contents($h, NotepadService::MAX_BYTES + 1);
            fclose($h);
            $base = $req->header('X-Base-Version') ?? $req->query('base_version');
            return NotepadService::saveContent($req->user, $id, $content, is_string($base) ? trim($base) : $base, $req->header('X-Notepad-Client') ?? $req->clientId());
        }
        return NotepadService::saveContent($req->user, $id, $req->input('content'), $req->input('base_version'), self::clientId($req));
    }

    /** GET /notepads/{id}/revisions */
    public function revisions(Request $req): array
    {
        return NotepadService::revisions($req->user, $req->intParam('id'));
    }

    /** GET /notepads/{id}/revisions/{rid} */
    public function revision(Request $req): array
    {
        return NotepadService::revision($req->user, $req->intParam('id'), $req->intParam('rid'));
    }

    /** POST /notepads/{id}/revisions/{rid}/restore {client_id?} */
    public function restore(Request $req): array
    {
        return NotepadService::restore($req->user, $req->intParam('id'), $req->intParam('rid'), self::clientId($req));
    }

    /** POST /notepads/{id}/presence {client_id} → {users, version, …} */
    public function presence(Request $req): array
    {
        return NotepadService::heartbeat($req->user, $req->intParam('id'), self::clientId($req));
    }

    /** DELETE /notepads/{id}/presence {client_id} */
    public function leave(Request $req): array
    {
        return NotepadService::heartbeat($req->user, $req->intParam('id'), self::clientId($req), true);
    }

    /** The editor's own id (one per open tab) from the body, else the browser's X-Client-Id. */
    private static function clientId(Request $req): ?string
    {
        try {
            $c = $req->input('client_id');
        } catch (ApiException) {
            $c = null;
        }
        return is_string($c) && $c !== '' ? $c : $req->clientId();
    }
}
