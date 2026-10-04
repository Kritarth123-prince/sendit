<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\ApiException;
use FT\Core\Logger;
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\RateLimiter;
use FT\Texts\TextService;

/** Clipboard texts and link previews (docs/ARCHITECTURE.md §9.4 "Clipboard texts & URL previews"). */
final class TextController
{
    /** GET /texts ?page=&per_page= */
    public function index(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        [$items, $total] = TextService::list($req->user, $page, $per);
        return Response::paginated($items, $total, $page, $per);
    }

    /** GET /texts/{id} */
    public function show(Request $req): array
    {
        return TextService::get($req->user, $req->intParam('id'));
    }

    /** POST /texts {content, is_permanent?} */
    public function store(Request $req): Response
    {
        return Response::created(TextService::create($req->user, $req->input('content'), $req->bool('is_permanent')));
    }

    /** PATCH /texts/{id} {content?, is_permanent?} */
    public function update(Request $req): array
    {
        $in = $req->json() ?? $_POST;
        return TextService::update($req->user, $req->intParam('id'), is_array($in) ? $in : []);
    }

    /** DELETE /texts/{id} */
    public function destroy(Request $req): Response
    {
        TextService::delete($req->user, $req->intParam('id'));
        return Response::noContent();
    }

    /** GET /url-meta?url= */
    public function urlMeta(Request $req): array
    {
        $url = $req->query('url');
        if (!is_string($url) || trim($url) === '') {
            throw ApiException::validation(['url' => 'Enter a web address.']);
        }
        // Separate (stricter) allowance on top of the general API bucket (RateLimiter 'url_meta').
        $hit = RateLimiter::hit('url_meta', 'u' . (int) $req->user['id']);
        if (!$hit['allowed']) {
            throw ApiException::tooManyRequests(max(1, $hit['retry_after']));
        }
        try {
            return TextService::urlMeta($req->user, $url);
        } catch (ApiException $e) {
            if ($e->errorCode === 'VALIDATION_FAILED') {
                Logger::security('Link preview refused', ['host' => mb_substr((string) parse_url(trim($url), PHP_URL_HOST), 0, 120)]);
            }
            throw $e;
        }
    }
}
