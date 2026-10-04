<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Settings;
use FT\Files\FileAccess;
use FT\Http\Request;
use FT\Http\Response;
use FT\Ocr\OcrService;
use FT\Search\SearchService;
use FT\Security\Policy;
use FT\Security\RateLimiter;

/**
 * GET  /api/v1/search          keyword search (docs/ARCHITECTURE.md §9.4 "Search")
 * POST /api/v1/files/{id}/ocr  queue text recognition for an image/PDF now (edit capability)
 */
final class SearchController
{
    /**
     * ?q=&in=name,ext,tags,folder,description,owner,content,ocr&kind=&ext=&owner=&owner_id=
     * &date_from=&date_to=&date_field=created_at|updated_at&size_min=&size_max=&folder_id=&recursive=1
     * &tag=&shared=1|with_me|by_me&favorite=1&trash=1&scope=all(admin)&sort=&order=&page=&per_page=
     */
    public function search(Request $req): Response
    {
        $p = self::params($req);
        $r = SearchService::search($req->user, $p);
        return Response::paginated($r['items'], $r['total'], $r['page'], $r['per_page'], [
            'query'  => ['q' => $p['q'], 'terms' => $p['terms'], 'fields' => $p['fields'], 'trash' => $p['trash'], 'scope' => $p['scope'] === 'all' ? 'all' : 'mine'],
        ]);
    }

    /** POST /api/v1/files/{id}/ocr → {queued:true} */
    public function ocr(Request $req): array
    {
        $id = $req->intParam('id');
        $file = FileAccess::require($req->user, $id, 'edit');
        if (!OcrService::configured()) {
            throw ApiException::unavailable('Text recognition (OCR) is not set up on this server. An administrator can add OCR_PROVIDER and OCR_API_KEY to .env.');
        }
        if (!Settings::bool('ocr_enabled', true)) {
            throw ApiException::unavailable('Text recognition (OCR) is switched off in the admin settings.');
        }
        if (!OcrService::supports($file)) {
            throw ApiException::validation(['file' => 'Text can only be recognised in images' . (OcrService::provider() === 'googlevision' ? '' : ' and PDF files') . '.']);
        }
        if ((int) $file['size'] > OcrService::maxBytes()) {
            throw ApiException::tooLarge('This file is too large for the text recognition service.');
        }
        // OCR uses a (possibly paid) external API: keep manual requests modest.
        RateLimiter::enforce('ocr', 'u' . (int) $req->user['id']);
        OcrService::queue($id, true);
        Audit::log('file.ocr_request', [
            'user_id'     => (int) $req->user['id'],
            'target_type' => 'file',
            'target_id'   => $id,
            'owner_id'    => (int) $file['owner_id'],
            'detail'      => (string) $file['name'],
        ]);
        return ['queued' => true];
    }

    /** Validate and normalise the query string. @return array<string,mixed> */
    public static function params(Request $req): array
    {
        $errors = [];
        $q = $req->string('q', '', 300);
        $fields = SearchService::FIELDS;
        $in = $req->string('in', '', 200);
        if ($in !== '') {
            $fields = [];
            foreach (explode(',', strtolower($in)) as $f) {
                $f = trim($f) === 'tag' ? 'tags' : trim($f);
                if ($f === '') {
                    continue;
                }
                if (!in_array($f, SearchService::FIELDS, true)) {
                    $errors['in'] = 'Search in: ' . implode(', ', SearchService::FIELDS) . '.';
                    break;
                }
                $fields[] = $f;
            }
            $fields = array_values(array_unique($fields)) ?: SearchService::FIELDS;
        }

        $list = static function (string $key, int $maxLen) use ($req): array {
            $v = $req->query($key);
            $items = is_array($v) ? $v : (is_string($v) ? explode(',', $v) : []);
            $out = [];
            foreach ($items as $i) {
                if (is_string($i) && trim($i) !== '') {
                    $out[] = mb_substr(trim($i), 0, $maxLen);
                }
            }
            return array_slice(array_values(array_unique($out)), 0, 20);
        };

        $kinds = array_map('strtolower', $list('kind', 16));
        try {
            $kinds = SearchService::kinds($kinds);
        } catch (ApiException $e) {
            $errors['kind'] = $e->details['fields']['kind'] ?? 'Unknown kind.';
        }
        $exts = [];
        foreach ($list('ext', 33) as $e) {
            $e = strtolower(ltrim($e, '.'));
            if (!preg_match('/^[a-z0-9]{1,32}$/', $e)) {
                $errors['ext'] = 'Extensions may only contain letters and numbers.';
                break;
            }
            $exts[] = $e;
        }
        $tags = [];
        foreach ($list('tag', 64) as $t) {
            $tags[] = mb_strtolower($t);
        }

        $sizeMin = self::optionalInt($req, 'size_min', $errors);
        $sizeMax = self::optionalInt($req, 'size_max', $errors);
        if ($sizeMin !== null && $sizeMax !== null && $sizeMin > $sizeMax) {
            $errors['size_max'] = 'The maximum size must be at least the minimum size.';
        }
        $folderId = self::optionalInt($req, 'folder_id', $errors);
        if ($folderId !== null && $folderId <= 0) {
            $errors['folder_id'] = 'Unknown folder.';
        }

        $dateFrom = null;
        $dateTo = null;
        try {
            $dateFrom = AdminController::date($req->string('date_from', '', 30), 'date_from', false);
            $dateTo = AdminController::date($req->string('date_to', '', 30), 'date_to', true);
        } catch (ApiException $e) {
            $errors += $e->details['fields'] ?? ['date' => 'Use the format YYYY-MM-DD.'];
        }
        $dateField = $req->string('date_field', 'created_at', 12);
        if (!in_array($dateField, ['created_at', 'updated_at'], true)) {
            $errors['date_field'] = 'Use created_at or updated_at.';
        }

        $shared = strtolower($req->string('shared', '', 10));
        $shared = match ($shared) {
            '', '0', 'false' => '',
            '1', 'true', 'any' => 'any',
            'with_me', 'by_me' => $shared,
            default => null,
        };
        if ($shared === null) {
            $errors['shared'] = 'Use shared=1, shared=with_me or shared=by_me.';
            $shared = '';
        }

        $scope = $req->string('scope', '', 8);
        if ($scope !== '' && !in_array($scope, ['all', 'mine'], true)) {
            $errors['scope'] = 'Use scope=all or scope=mine.';
        }
        $ownerId = self::optionalInt($req, 'owner_id', $errors);
        if ($scope === 'all' && !Policy::isAdmin($req->user)) {
            throw ApiException::forbidden('Only administrators can search everyone\'s files.');
        }
        // An administrator filtering by another owner searches that owner's whole drive.
        if ($ownerId !== null && $ownerId !== (int) $req->user['id'] && Policy::isAdmin($req->user) && $scope === '') {
            $scope = 'all';
        }

        $sort = $req->string('sort', '', 16);
        if ($sort !== '' && !in_array($sort, SearchService::SORTS, true)) {
            $errors['sort'] = 'Sort by: ' . implode(', ', SearchService::SORTS) . '.';
        }
        $order = strtolower($req->string('order', 'desc', 4));
        if (!in_array($order, ['asc', 'desc'], true)) {
            $errors['order'] = 'Use asc or desc.';
        }
        if ($errors !== []) {
            throw ApiException::validation($errors);
        }
        [$page, $per] = $req->pagination(50, 200);
        return [
            'q'          => $q,
            'terms'      => SearchService::terms($q),
            'fields'     => $fields,
            'kind'       => $kinds,
            'ext'        => $exts,
            'tag'        => $tags,
            'owner'      => $req->string('owner', '', 64),
            'owner_id'   => $ownerId,
            'date_from'  => $dateFrom,
            'date_to'    => $dateTo,
            'date_field' => $dateField,
            'size_min'   => $sizeMin,
            'size_max'   => $sizeMax,
            'folder_id'  => $folderId,
            'recursive'  => $req->bool('recursive'),
            'shared'     => $shared,
            'favorite'   => $req->bool('favorite') || $req->bool('favourite'),
            'trash'      => $req->bool('trash'),
            'scope'      => $scope,
            'sort'       => $sort,
            'order'      => $order,
            'page'       => $page,
            'per_page'   => $per,
        ];
    }

    private static function optionalInt(Request $req, string $key, array &$errors): ?int
    {
        $v = $req->query($key);
        if ($v === null || $v === '') {
            return null;
        }
        if (!is_string($v) || !preg_match('/^\d{1,18}$/', trim($v))) {
            $errors[$key] = 'Enter a whole number.';
            return null;
        }
        return (int) trim($v);
    }
}
