<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\ApiException;
use FT\Files\FileAccess;
use FT\Files\FileRepository;
use FT\Files\FileService;
use FT\Files\FolderService;
use FT\Files\TrashService;
use FT\Http\Request;
use FT\Http\Response;

/** /api/v1/folders… (A3). Folder shares (POST /folders/{id}/share) belong to A4. */
final class FolderController
{
    /** GET /folders ?parent_id=|root=1 */
    public function index(Request $req): Response
    {
        [$page, $per] = $req->pagination(200, 500);
        $parent = $req->bool('root') ? null : FolderService::parseFolderId($req->query('parent_id'), 'parent_id');
        $r = FolderService::children($req->user, $parent, $page, $per, $req->string('q', '', 200));
        return Response::paginated($r['items'], $r['total'], $page, $per, $r['meta']);
    }

    /** GET /folders/tree */
    public function tree(Request $req): array
    {
        return FolderService::tree($req->user);
    }

    /** POST /folders {name, parent_id?} */
    public function store(Request $req): Response
    {
        $name = $req->input('name');
        if (!is_string($name)) {
            throw ApiException::validation(['name' => 'Enter a folder name.']);
        }
        $row = FolderService::create($req->user, $name, FolderService::parseFolderId($req->input('parent_id'), 'parent_id'));
        return Response::created(FileRepository::folderSummary($row, $req->user));
    }

    /** GET /folders/{id} */
    public function show(Request $req): array
    {
        return FolderService::show($req->user, $req->intParam('id'));
    }

    /** PATCH /folders/{id} {name?, parent_id?} */
    public function update(Request $req): array
    {
        $row = FolderService::update($req->user, $req->intParam('id'), $req->all());
        FileAccess::reset();
        return FileRepository::folderSummary($row, $req->user);
    }

    /** DELETE /folders/{id} → Trash (folder + contents) */
    public function destroy(Request $req): Response
    {
        FolderService::trash($req->user, $req->intParam('id'));
        return Response::noContent();
    }

    /** POST /folders/{id}/restore */
    public function restore(Request $req): array
    {
        $folder = FileAccess::requireFolder($req->user, $req->intParam('id'), 'delete', true);
        $r = TrashService::restoreFolder($folder, $req->user);
        FileAccess::reset();
        return FileRepository::folderSummary($r['folder'], $req->user) + ['restored_files' => $r['files'], 'restored_folders' => $r['folders']];
    }

    /** GET /folders/{id}/zip */
    public function zip(Request $req): ?Response
    {
        FileService::zip($req->user, [], [$req->intParam('id')], $req->string('name', '', 200));
        return null;
    }
}
