<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\ApiException;
use FT\Files\ActivityService;
use FT\Files\FileService;
use FT\Files\FolderService;
use FT\Files\ZipService;
use FT\Http\Request;
use FT\Http\Response;

/**
 * /api/v1/files… (A3). Thin HTTP layer: parse and bound the input, call FileService.
 * Uploads (POST /files) belong to A2; sharing/comments/text/presence to A4; OCR to A6.
 */
final class FileController
{
    /** GET /files ?folder_id=|root=1 &view=all|recent|favorites &kind=&tag=&q=&sort=&order=&page=&per_page= */
    public function index(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $r = FileService::listing($req->user, [
            'folder_id' => FolderService::parseFolderId($req->query('folder_id')),
            'root'      => $req->bool('root'),
            'view'      => $req->string('view', 'all', 20),
            'kind'      => $req->string('kind', '', 20),
            'tag'       => $req->string('tag', '', 64),
            'q'         => $req->string('q', '', 200),
            'sort'      => $req->string('sort', '', 20),
            'order'     => $req->string('order', '', 4),
            'page'      => $page,
            'per_page'  => $per,
        ]);
        return Response::paginated($r['items'], $r['total'], $r['page'], $r['per_page'], $r['meta']);
    }

    /** GET /files/{id} */
    public function show(Request $req): array
    {
        return FileService::show($req->user, $req->intParam('id'));
    }

    /** PATCH /files/{id} {name?, folder_id?, description?, is_permanent?, tags?, favorite?} */
    public function update(Request $req): array
    {
        return FileService::update($req->user, $req->intParam('id'), $req->all());
    }

    /** DELETE /files/{id} (?permanent=1 for an item already in the Trash) */
    public function destroy(Request $req): Response
    {
        FileService::destroy($req->user, $req->intParam('id'), $req->bool('permanent'));
        return Response::noContent();
    }

    /** POST /files/{id}/restore */
    public function restore(Request $req): array
    {
        return FileService::restore($req->user, $req->intParam('id'));
    }

    /** GET /files/{id}/download */
    public function download(Request $req): ?Response
    {
        FileService::download($req, $req->user, $req->intParam('id'));
        return null;
    }

    /** GET /files/{id}/content */
    public function content(Request $req): ?Response
    {
        FileService::content($req, $req->user, $req->intParam('id'));
        return null;
    }

    /** GET /files/{id}/thumbnail */
    public function thumbnail(Request $req): ?Response
    {
        FileService::thumbnail($req, $req->user, $req->intParam('id'));
        return null;
    }

    /** GET /files/{id}/activity */
    public function activity(Request $req): Response
    {
        [$page, $per] = $req->pagination(ActivityService::PER_PAGE, 200);
        $r = ActivityService::timeline($req->intParam('id'), $req->user, $page, $per);
        return Response::paginated($r['items'], $r['total'], $r['page'], $r['per_page']);
    }

    /** POST /files/batch {action, ids, folder_id?, tag?, value?} */
    public function batch(Request $req): array
    {
        return FileService::batch($req->user, $req->all());
    }

    /** POST /files/zip {file_ids, folder_ids, name?} (JSON or a plain form POST) */
    public function zip(Request $req): ?Response
    {
        $fileIds = FileService::parseIds($req->input('file_ids'), 'file_ids', ZipService::MAX_ENTRIES, false);
        $folderIds = FileService::parseIds($req->input('folder_ids'), 'folder_ids', 100, false);
        if ($fileIds === [] && $folderIds === []) {
            throw ApiException::validation(['file_ids' => 'Choose at least one file or folder.']);
        }
        FileService::zip($req->user, $fileIds, $folderIds, $req->string('name', '', 200));
        return null;
    }
}
