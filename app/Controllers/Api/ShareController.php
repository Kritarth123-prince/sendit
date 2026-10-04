<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\ApiException;
use FT\Http\Request;
use FT\Http\Response;
use FT\Sharing\ShareService;

/**
 * Shares REST API (docs/ARCHITECTURE.md §9.4 "Shares"). All authorisation lives in
 * ShareService / FileAccess; this class only maps HTTP input to service calls and shapes.
 */
final class ShareController
{
    /** GET /shares ?status=active|expired|revoked|exhausted|all &kind=link|user &file_id= &folder_id= */
    public function index(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        [$rows, $total] = ShareService::listMine($req->user, $this->filters($req), $page, $per);
        return Response::paginated(ShareService::summaries($rows, $req->user), $total, $page, $per);
    }

    /** POST /shares → [ShareSummary] */
    public function store(Request $req): Response
    {
        $rows = ShareService::create($req->user, $this->body($req));
        return Response::created(ShareService::summaries($rows, $req->user));
    }

    /** POST /files/{id}/share — same body as POST /shares, for this file. */
    public function shareFile(Request $req): Response
    {
        $in = $this->body($req);
        unset($in['folder_id'], $in['file_id']);
        $in['file_ids'] = [$req->intParam('id')];
        $rows = ShareService::create($req->user, $in);
        return Response::created(ShareService::summaries($rows, $req->user));
    }

    /** POST /folders/{id}/share — same body as POST /shares, for this folder. */
    public function shareFolder(Request $req): Response
    {
        $in = $this->body($req);
        unset($in['file_ids'], $in['file_id']);
        $in['folder_id'] = $req->intParam('id');
        $rows = ShareService::create($req->user, $in);
        return Response::created(ShareService::summaries($rows, $req->user));
    }

    /** GET /shares/{id} */
    public function show(Request $req): array
    {
        $share = ShareService::requireVisible($req->user, $req->intParam('id'));
        if (!ShareService::canManage($req->user, $share) && $share['kind'] === 'user') {
            // The recipient opened their share: Shared With Me "last accessed".
            if ($share['target_type'] === 'folder' && $share['folder_id'] !== null) {
                ShareService::markFolderOpened((int) $req->user['id'], (int) $share['folder_id']);
            } elseif ($share['target_type'] === 'file' && $share['file_id'] !== null) {
                $file = \FT\Core\Db::one('SELECT * FROM files WHERE id = ? AND deleted_at IS NULL', [(int) $share['file_id']]);
                if ($file !== null) {
                    ShareService::markOpened((int) $req->user['id'], $file);
                }
            }
        }
        return ShareService::summary($share, $req->user);
    }

    /** PATCH /shares/{id} */
    public function update(Request $req): array
    {
        $share = ShareService::update($req->user, $req->intParam('id'), $this->body($req));
        return ShareService::summary($share, $req->user);
    }

    /** DELETE /shares/{id} → 204 */
    public function destroy(Request $req): Response
    {
        ShareService::revoke($req->user, $req->intParam('id'));
        return Response::noContent();
    }

    /** GET /shares/with-me ?type=file|folder */
    public function withMe(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $type = $req->string('type', '', 10);
        if (!in_array($type, ['', 'file', 'folder', 'all'], true)) {
            throw ApiException::validation(['type' => 'Type must be file or folder.']);
        }
        [$items, $total] = ShareService::sharedWithMe($req->user, $page, $per, in_array($type, ['file', 'folder'], true) ? $type : null);
        return Response::paginated($items, $total, $page, $per);
    }

    /** GET /files/{id}/shares (owner or admin) */
    public function forFile(Request $req): array
    {
        $status = $req->string('status', 'all', 16);
        $rows = ShareService::forFile($req->user, $req->intParam('id'), $status);
        return ShareService::summaries($rows, $req->user);
    }

    /** GET /admin/shares ?status=&owner_id=&recipient_id=&kind= (admin.shares) */
    public function adminIndex(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $filters = $this->filters($req) + [
            'owner_id'     => $req->int('owner_id', 0, 0),
            'recipient_id' => $req->int('recipient_id', 0, 0),
        ];
        [$rows, $total] = ShareService::adminList($filters, $page, $per);
        return Response::paginated(ShareService::summaries($rows, $req->user), $total, $page, $per);
    }

    // ------------------------------------------------------------------ helpers

    private function filters(Request $req): array
    {
        return [
            'status'    => $req->string('status', 'all', 16),
            'kind'      => $req->string('kind', '', 8),
            'file_id'   => $req->int('file_id', 0, 0),
            'folder_id' => $req->int('folder_id', 0, 0),
        ];
    }

    /** JSON or form body (never the query string: passwords must not travel in URLs). */
    private function body(Request $req): array
    {
        $in = $req->json() ?? $_POST;
        unset($in['_csrf'], $in['csrf']);
        return is_array($in) ? $in : [];
    }
}
