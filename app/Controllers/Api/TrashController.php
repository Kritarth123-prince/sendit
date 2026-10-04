<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\ApiException;
use FT\Files\FileAccess;
use FT\Files\FileRepository;
use FT\Files\FileService;
use FT\Files\TrashService;
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\Policy;

/**
 * /api/v1/trash… and /api/v1/admin/trash (A3). Restore and permanent delete accept admins on
 * anyone's items (FileAccess grants admins access to trashed content).
 */
final class TrashController
{
    /** GET /trash ?kind=file|folder &q= &page= */
    public function index(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $r = TrashService::listing($req->user, (int) $req->user['id'], [
            'kind' => $req->string('kind', '', 10),
            'q'    => $req->string('q', '', 200),
        ], $page, $per);
        return Response::paginated($r['items'], $r['total'], $page, $per, $r['meta']);
    }

    /** GET /admin/trash ?owner_id= &kind= &q= (perm admin.storage) */
    public function adminIndex(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $owner = $req->int('owner_id', 0, 0);
        $r = TrashService::listing($req->user, $owner > 0 ? $owner : null, [
            'kind' => $req->string('kind', '', 10),
            'q'    => $req->string('q', '', 200),
        ], $page, $per);
        return Response::paginated($r['items'], $r['total'], $page, $per, $r['meta']);
    }

    /** POST /trash/{id}/restore (?kind=folder) */
    public function restore(Request $req): array
    {
        $id = $req->intParam('id');
        if ($this->isFolder($req)) {
            $folder = FileAccess::requireFolder($req->user, $id, 'delete', true);
            $r = TrashService::restoreFolder($folder, $req->user);
            FileAccess::reset();
            return FileRepository::folderSummary($r['folder'], $req->user) + ['restored_files' => $r['files'], 'restored_folders' => $r['folders']];
        }
        return FileService::restore($req->user, $id);
    }

    /** DELETE /trash/{id} (?kind=folder) — permanent */
    public function destroy(Request $req): array
    {
        $this->requireDelete($req);
        $id = $req->intParam('id');
        if ($this->isFolder($req)) {
            $folder = FileAccess::requireFolder($req->user, $id, 'delete', true);
            $r = TrashService::purgeFolder($folder, $req->user);
            return ['purged_files' => $r['files'], 'purged_folders' => $r['folders'], 'freed_bytes' => $r['bytes'], 'complete' => $r['complete']];
        }
        $file = FileAccess::require($req->user, $id, 'delete', true);
        $bytes = TrashService::purgeFile($file, $req->user);
        return ['purged_files' => 1, 'purged_folders' => 0, 'freed_bytes' => $bytes, 'complete' => true];
    }

    /** DELETE /trash — empty the signed-in user's Trash */
    public function empty(Request $req): array
    {
        $this->requireDelete($req);
        return TrashService::emptyTrash((int) $req->user['id'], $req->user);
    }

    private function isFolder(Request $req): bool
    {
        $kind = $req->string('kind', 'file', 10);
        if (!in_array($kind, ['file', 'folder'], true)) {
            throw ApiException::validation(['kind' => 'Kind must be file or folder.']);
        }
        return $kind === 'folder';
    }

    private function requireDelete(Request $req): void
    {
        if (!Policy::isAdmin($req->user)) {
            Policy::requirePermission($req->user, 'files.delete');
        }
    }
}
