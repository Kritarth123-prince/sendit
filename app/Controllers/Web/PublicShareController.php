<?php
declare(strict_types=1);

namespace FT\Controllers\Web;

use FT\Auth\Auth;
use FT\Comments\CommentService;
use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Secrets;
use FT\Core\Settings;
use FT\Core\Stats;
use FT\Events\EventBus;
use FT\Files\FileAccess;
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\Csrf;
use FT\Security\RateLimiter;
use FT\Sharing\ShareService;
use FT\Storage\BlobStore;
use FT\Storage\MimeDetector;
use FT\Storage\Paths;
use FT\Storage\QuotaService;
use FT\Support\Capabilities;

/**
 * Public link pages: /s/{token} (docs/ARCHITECTURE.md §9.4 "Public link pages").
 *
 * No sign-in. A first-contact GET in a browser must work (hosts with a JavaScript cookie
 * challenge only let real browsers through), so the page is server-rendered and every feature
 * also works without JavaScript; assets/js/public-share.js only enhances it.
 *
 * Security:
 *  - every file access goes through FileAccess::forLinkShare / inLinkScope (scope + flags);
 *  - revoked / expired / unknown links, a disabled or deleted owner, or a trashed item all give
 *    the same "Link unavailable" page (404, or 410 for expired/revoked) — no detail leaks;
 *  - password: the unlocked state lives in the PHP session for 12 h per share, bound to the
 *    current password hash (changing the password locks everyone out again); attempts are
 *    limited per IP + share (share_password bucket, IPv6 per /48) AND per share from all
 *    addresses together (ShareService::passwordAttempt); after 10 wrong passwords in a row the
 *    owner is notified (once per hour); forms carry the session CSRF token;
 *  - /content serves inline previews only (never a non-previewable type as an attachment), and
 *    once the download limit is reached only image/video/audio previews — a PDF or text
 *    "preview" is the whole file;
 *  - a link made from a re-share is honoured only while its chain is (FileAccess::honoured());
 *  - downloads are counted with one atomic UPDATE (never more than max_downloads), once per
 *    download (a resumed Range request of a download this browser already counted is free);
 *    a ZIP counts once;
 *  - strict CSP with a per-request nonce, no inline handlers, noindex, no Referer leakage of
 *    the token (Referrer-Policy: no-referrer).
 */
final class PublicShareController
{
    private const UNLOCK_TTL = 43200;          // 12 h
    private const ACCESS_LOG_INTERVAL = 600;   // audit page views at most every 10 min per browser
    private const RESUME_WINDOW = 21600;       // a counted download may be resumed for 6 h
    private const TEXT_PREVIEW_BYTES = 262144;
    private const SESSION_KEY = 'ft_share';
    private const ANON = ShareService::ANON_LABEL;
    /** Preview types still shown once a link's download limit is reached (not the file itself). */
    private const MEDIA_PREVIEWS = ['image', 'video', 'audio'];

    // ================================================================== pages

    /** GET /s/{token} (?folder=<id> inside folder shares) */
    public function show(Request $req): Response
    {
        [$share, $problem] = $this->lookup($req);
        if ($problem !== null) {
            return $this->unavailable($problem);
        }
        Auth::startSession();
        if ($this->locked($share)) {
            return $this->passwordPage($share, null, 200);
        }
        $folderId = null;
        if ($share['target_type'] === 'folder') {
            $q = $req->query('folder');
            $folderId = is_string($q) && ctype_digit($q) ? (int) $q : (int) $share['folder_id'];
        }
        $this->noteAccess($share, 'page');
        try {
            return $this->sharePage($share, $folderId);
        } catch (ApiException $e) {
            if ($e->errorCode === 'FOLDER_NOT_FOUND') {
                return $this->messagePage($share, 'Folder not found', 'This folder is not part of the shared folder, or it was removed.', 404);
            }
            throw $e;
        }
    }

    /** POST /s/{token}/unlock {password | share_password, _csrf} */
    public function unlock(Request $req): Response
    {
        [$share, $problem] = $this->lookup($req);
        if ($problem !== null) {
            return $this->unavailable($problem);
        }
        Auth::startSession();
        if (($share['password_hash'] ?? null) === null || $share['password_hash'] === '') {
            return $this->redirectToPage($share);
        }
        if (!$this->csrfOk($req, $share)) {
            return $this->passwordPage($share, 'Your page expired. Please enter the password again.', 419);
        }
        $pw = $req->input('password');
        if (!is_string($pw) || $pw === '') {
            $pw = $req->input('share_password'); // legacy form field
        }
        if (!is_string($pw) || $pw === '') {
            return $this->passwordPage($share, 'Enter the password to open this link.', 422);
        }
        // Two buckets, both counted before the password is checked: per address (IPv6 per /48)
        // and per link from all addresses together, so rotating addresses does not help.
        $shareId = (int) $share['id'];
        $subject = 'ip' . ShareService::passwordIpSubject($req->ip()) . '|share' . $shareId;
        $hit = RateLimiter::hit('share_password', $subject);
        if ($hit['allowed']) {
            $linkHit = ShareService::passwordAttempt($shareId);
            if (!$linkHit['allowed']) {
                RateLimiter::refund('share_password', $subject);
                $hit = ['allowed' => false, 'retry_after' => $linkHit['retry_after']];
            }
        }
        if (!$hit['allowed']) {
            Logger::security('Share link password attempts rate limited', ['share_id' => $shareId]);
            $minutes = max(1, (int) ceil($hit['retry_after'] / 60));
            return $this->passwordPage($share, 'Too many attempts. Please try again in ' . $minutes . ' minute' . ($minutes === 1 ? '' : 's') . '.', 429, ['Retry-After' => (string) $hit['retry_after']]);
        }
        if (!$this->verifyPassword($share, $pw)) {
            Logger::security('Wrong share link password', ['share_id' => $shareId]);
            Audit::log('share.password_failed', [
                'user_id' => null, 'actor_label' => self::ANON, 'target_type' => 'share', 'target_id' => $shareId,
                'owner_id' => (int) $share['owner_id'], 'category' => 'security',
            ]);
            ShareService::passwordFailed($share);
            return $this->passwordPage($share, 'That password is not right. Please try again.', 401);
        }
        RateLimiter::refund('share_password', $subject);
        ShareService::passwordAttemptRefund($shareId);
        ShareService::passwordSucceeded($shareId);
        $share = $this->effective(ShareService::find($shareId) ?? $share); // the hash may have been upgraded
        $_SESSION[self::SESSION_KEY]['u'][(int) $share['id']] = ['until' => time() + self::UNLOCK_TTL, 'h' => $this->fingerprint($share)];
        $this->pruneSession();
        return $this->redirectToPage($share);
    }

    // ================================================================== content

    /** GET /s/{token}/download ?file={id} (optional for single-file shares) */
    public function download(Request $req): ?Response
    {
        [$share, $problem] = $this->lookup($req);
        if ($problem !== null) {
            return $this->unavailable($problem);
        }
        Auth::startSession();
        if ($this->locked($share)) {
            return $this->redirectToPage($share);
        }
        $fileId = $this->fileParam($req, $share);
        if ($fileId === null) {
            return $this->messagePage($share, 'Choose a file', 'Pick a file on the shared page to download it.', 400);
        }
        try {
            $file = FileAccess::forLinkShare($share, $fileId);
        } catch (ApiException) {
            return $this->messagePage($share, 'File not found', 'This file is not part of the shared link, or it was removed.', 404);
        }
        if (empty($file['access']['download'])) {
            return $this->messagePage($share, 'Downloads are turned off', 'The person who shared this link allows viewing only.', 403);
        }
        $blob = $this->intactBlob($file);
        if ($blob === null) {
            return $this->messagePage($share, 'File not available', 'This file cannot be downloaded right now. Please let the person who shared it know.', 500);
        }
        // HEAD (link-preview bots, download managers probing) never counts as a download.
        if ($req->realMethod() !== 'HEAD' && !$this->isResume($req, $share, (int) $file['id'])) {
            if (!ShareService::consumeDownload($share)) {
                return $this->messagePage($share, 'Download limit reached', 'This link has reached its download limit. Ask the person who shared it for a new link.', 403);
            }
            $_SESSION[self::SESSION_KEY]['d'][(int) $share['id'] . ':' . (int) $file['id']] = time();
            $this->afterDownload($share, $file, null);
        }
        $this->stream($file, $blob, $req, false);
        return null;
    }

    /** GET /s/{token}/content/{fileId} — inline preview (Range) when previews are allowed. */
    public function content(Request $req): ?Response
    {
        [$share, $problem] = $this->lookup($req);
        if ($problem !== null) {
            return $this->unavailable($problem);
        }
        Auth::startSession();
        if ($this->locked($share)) {
            return $this->messagePage($share, 'Password required', 'Open the shared page and enter the password first.', 403);
        }
        try {
            $file = FileAccess::forLinkShare($share, $req->intParam('fileId'));
        } catch (ApiException) {
            return $this->messagePage($share, 'File not found', 'This file is not part of the shared link, or it was removed.', 404);
        }
        if (empty($file['access']['preview'])) {
            return $this->messagePage($share, 'Preview turned off', 'The person who shared this link does not allow previews.', 403);
        }
        // A preview is only ever an inline rendering: a type the browser cannot show inline would
        // go out as a plain attachment, i.e. a download the link may not allow (and that is never
        // counted). Same rule as GET /api/v1/files/{id}/content.
        $type = $this->previewType($file);
        if ($type === null) {
            return $this->messagePage($share, 'No preview available', 'This type of file cannot be previewed. Download it instead.', 415);
        }
        // Once the download limit is reached the link stays viewable, but for documents (PDF,
        // text) the "preview" IS the whole file, so only images and media are still shown.
        if (!in_array($type, self::MEDIA_PREVIEWS, true) && ShareService::status($share) === 'exhausted') {
            return $this->messagePage($share, 'Download limit reached', 'This link has reached its download limit, so this file can no longer be opened. Ask the person who shared it for a new link.', 403);
        }
        $blob = $this->intactBlob($file);
        if ($blob === null) {
            return $this->messagePage($share, 'File not available', 'This file cannot be shown right now.', 500);
        }
        $this->noteAccess($share, 'preview', $file);
        $this->stream($file, $blob, $req, true);
        return null;
    }

    /** GET /s/{token}/thumbnail/{fileId} */
    public function thumbnail(Request $req): ?Response
    {
        [$share, $problem] = $this->lookup($req);
        if ($problem !== null) {
            return new Response('', $problem === 'expired' || $problem === 'revoked' ? 410 : 404);
        }
        Auth::startSession();
        if ($this->locked($share)) {
            return new Response('', 403);
        }
        try {
            $file = FileAccess::forLinkShare($share, $req->intParam('fileId'));
        } catch (ApiException) {
            return new Response('', 404);
        }
        $thumb = 'FT\\Storage\\Thumbnailer';
        if (empty($file['access']['preview']) || $file['thumb_version'] === null || !class_exists($thumb) || !method_exists($thumb, 'send')) {
            return new Response('', 404);
        }
        Auth::closeSession();
        try {
            $thumb::send($file, $req);
        } catch (ApiException) {
            return new Response('', 404);
        }
        return null;
    }

    /** GET /s/{token}/zip — whole bundle or folder as one streamed ZIP (counts one download). */
    public function zip(Request $req): ?Response
    {
        [$share, $problem] = $this->lookup($req);
        if ($problem !== null) {
            return $this->unavailable($problem);
        }
        Auth::startSession();
        if ($this->locked($share)) {
            return $this->redirectToPage($share);
        }
        if ($share['target_type'] === 'file') {
            return Response::redirect($this->link($share, '/download'), 303);
        }
        $caps = FileAccess::combine([$share]) ?? [];
        if (empty($caps['download'])) {
            return $this->messagePage($share, 'Downloads are turned off', 'The person who shared this link allows viewing only.', 403);
        }
        $zipClass = 'FT\\Files\\ZipService';
        if (!class_exists($zipClass)) {
            return $this->messagePage($share, 'Not available', 'Downloading everything as a ZIP is not available on this server. Download the files one by one instead.', 503);
        }
        $title = ShareService::summary($share, null, false)['title'];
        if ($share['target_type'] === 'bundle') {
            $entries = array_map(static fn (array $f): array => ['file' => $f, 'path' => (string) $f['name']], ShareService::bundleFiles($share));
        } else {
            $folder = Db::one('SELECT * FROM folders WHERE id = ? AND deleted_at IS NULL', [(int) $share['folder_id']]);
            $entries = $folder !== null ? $zipClass::folderEntries($folder) : [];
        }
        $m = $zipClass::measure($entries);
        if ($m['files'] === 0) {
            return $this->messagePage($share, 'Nothing to download', 'There are no files in this shared link right now.', 404);
        }
        $maxBytes = max(1, Settings::int('max_upload_bytes', 209715200)) * 10;
        if ($m['bytes'] > $maxBytes || $m['entries'] > $zipClass::MAX_ENTRIES) {
            return $this->messagePage($share, 'Too large for one ZIP', 'This shared folder is too large to download as one ZIP. Open it and download the files you need.', 413);
        }
        if ($req->realMethod() !== 'HEAD') {
            if (!ShareService::consumeDownload($share)) {
                return $this->messagePage($share, 'Download limit reached', 'This link has reached its download limit. Ask the person who shared it for a new link.', 403);
            }
            $this->afterDownload($share, null, $m['files']);
        }
        Auth::closeSession();
        $zipClass::stream($entries, $title);
        return null;
    }

    // ================================================================== JSON for the page script

    /** GET /s/{token}/folder/{folderId} — browse inside a shared folder. */
    public function folder(Request $req): array
    {
        $share = $this->requireJsonShare($req);
        $listing = ShareService::linkFolder($share, $req->intParam('folderId'));
        $caps = FileAccess::combine([$share]) ?? [];
        return $this->folderView($share, $listing, $caps);
    }

    /** GET /s/{token}/comments ?file= */
    public function comments(Request $req): array
    {
        $share = $this->requireJsonShare($req);
        $file = $this->requireJsonFile($share, $this->fileParam($req, $share));
        if (empty($file['access']['comment'])) {
            throw ApiException::forbidden('Comments are turned off for this link.');
        }
        return CommentService::listForLink($file);
    }

    /** POST /s/{token}/comments {file_id?, name, body} — JSON (page script) or a plain form. */
    public function comment(Request $req): Response
    {
        $json = $req->wantsJson();
        [$share, $problem] = $this->lookup($req);
        if ($problem !== null) {
            if ($json) {
                throw $this->problemException($problem);
            }
            return $this->unavailable($problem);
        }
        Auth::startSession();
        if (!$this->csrfOk($req, $share)) {
            if ($json) {
                throw ApiException::csrf();
            }
            return $this->flashRedirect($share, 'err', 'Your page expired. Please write your comment again.');
        }
        if ($this->locked($share)) {
            if ($json) {
                throw new ApiException('SHARE_PASSWORD_REQUIRED', 'Enter the password for this link first.', 401);
            }
            return $this->redirectToPage($share);
        }
        try {
            $file = $this->requireJsonFile($share, $this->fileParam($req, $share));
            $comment = CommentService::createAnonymous($share, $file, $req->input('name'), $req->input('body'));
        } catch (ApiException $e) {
            if ($json) {
                throw $e;
            }
            $msg = $e->details['fields'] ?? null;
            return $this->flashRedirect($share, 'err', is_array($msg) && $msg !== [] ? (string) reset($msg) : $e->getMessage());
        }
        if ($json) {
            return Response::created($comment)->withHeader('X-FT-Api', '1');
        }
        return $this->flashRedirect($share, 'ok', 'Thanks — your comment was added.', '#comments');
    }

    /** POST /s/{token}/upload — editor links: a new version of the shared file (one request). */
    public function upload(Request $req): Response
    {
        $json = $req->wantsJson();
        [$share, $problem] = $this->lookup($req);
        if ($problem !== null) {
            if ($json) {
                throw $this->problemException($problem);
            }
            return $this->unavailable($problem);
        }
        Auth::startSession();
        if (!$this->csrfOk($req, $share)) {
            if ($json) {
                throw ApiException::csrf();
            }
            return $this->flashRedirect($share, 'err', 'Your page expired. Please choose the file again.');
        }
        if ($this->locked($share)) {
            if ($json) {
                throw new ApiException('SHARE_PASSWORD_REQUIRED', 'Enter the password for this link first.', 401);
            }
            return $this->redirectToPage($share);
        }
        try {
            $result = $this->receiveVersion($req, $share);
        } catch (ApiException $e) {
            if ($json) {
                throw $e;
            }
            $msg = $e->details['fields'] ?? null;
            return $this->flashRedirect($share, 'err', is_array($msg) && $msg !== [] ? (string) reset($msg) : $e->getMessage());
        }
        if ($json) {
            return Response::created($result)->withHeader('X-FT-Api', '1');
        }
        return $this->flashRedirect($share, 'ok', 'Your new version was uploaded.');
    }

    // ================================================================== internals: share state

    /** @return array{0:?array,1:?string} [share, problem] */
    private function lookup(Request $req): array
    {
        $token = (string) $req->param('token');
        $share = strlen($token) >= 16 && strlen($token) <= 64 ? ShareService::findByToken($token) : null;
        $problem = ShareService::linkProblem($share);
        return [$problem === null ? $this->effective($share) : $share, $problem];
    }

    /**
     * A link made from a re-share grants at most what its chain still grants (level and flags
     * capped, bundle items its chain no longer reaches dropped — FileAccess::honoured()), so every
     * page-level decision below (preview/download/comment/upload, ZIP contents) uses that view.
     */
    private function effective(array $share): array
    {
        if ($share['parent_share_id'] === null) {
            return $share;
        }
        // (empty only if the chain broke since linkProblem() looked: then it grants nothing)
        return FileAccess::honoured([$share])[0]
            ?? ['allow_preview' => 0, 'allow_download' => 0, 'allow_comments' => 0, 'allow_edit' => 0, '_items' => []] + $share;
    }

    private function requireJsonShare(Request $req): array
    {
        [$share, $problem] = $this->lookup($req);
        if ($problem !== null) {
            throw $this->problemException($problem);
        }
        Auth::startSession();
        if ($this->locked($share)) {
            throw new ApiException('SHARE_PASSWORD_REQUIRED', 'Enter the password for this link first.', 401);
        }
        return $share;
    }

    private function requireJsonFile(array $share, ?int $fileId): array
    {
        if ($fileId === null) {
            throw ApiException::validation(['file_id' => 'Choose a file.']);
        }
        return FileAccess::forLinkShare($share, $fileId);
    }

    private function problemException(string $problem): ApiException
    {
        return match ($problem) {
            'expired' => new ApiException('SHARE_EXPIRED', 'This link is no longer available.', 410),
            'revoked' => new ApiException('SHARE_REVOKED', 'This link is no longer available.', 410),
            default   => ApiException::notFound('share', 'SHARE_NOT_FOUND'),
        };
    }

    /**
     * The checks of Csrf::verify() (same origin + session token from a header or the body, never
     * the query string) without its log line: that one records the request path, and here the
     * path contains the link token, which is a secret. The share id is logged instead.
     */
    private function csrfOk(Request $req, array $share): bool
    {
        try {
            Csrf::assertSameOrigin($req);
        } catch (ApiException) {
            return false;
        }
        $given = $req->header('X-CSRF-Token') ?? '';
        if ($given === '') {
            $json = $req->json();
            foreach (['_csrf', 'csrf'] as $k) {
                if (is_array($json) && is_string($json[$k] ?? null)) {
                    $given = $json[$k];
                    break;
                }
                if (is_string($_POST[$k] ?? null)) {
                    $given = $_POST[$k];
                    break;
                }
            }
        }
        $expected = Csrf::token();
        if ($given === '' || !hash_equals($expected, $given)) {
            Logger::security('Share page form token mismatch', ['share_id' => (int) $share['id']]);
            return false;
        }
        return true;
    }

    private function locked(array $share): bool
    {
        if (($share['password_hash'] ?? null) === null || $share['password_hash'] === '') {
            return false;
        }
        $u = $_SESSION[self::SESSION_KEY]['u'][(int) $share['id']] ?? null;
        return !(is_array($u) && (int) ($u['until'] ?? 0) > time() && is_string($u['h'] ?? null) && hash_equals($this->fingerprint($share), $u['h']));
    }

    /** Binds an unlock to the current password: changing it locks every browser out again. */
    private function fingerprint(array $share): string
    {
        return substr(Secrets::hmac((string) $share['password_hash'], 'share-unlock:' . (int) $share['id']), 0, 32);
    }

    private function verifyPassword(array $share, string $pw): bool
    {
        $hash = (string) $share['password_hash'];
        if (strlen($pw) > 4 * ShareService::PASSWORD_MAX) {
            return false;
        }
        $info = password_get_info($hash);
        if (($info['algo'] ?? null) !== null && ($info['algoName'] ?? 'unknown') !== 'unknown') {
            if (!password_verify($pw, $hash)) {
                return false;
            }
            if (password_needs_rehash($hash, PASSWORD_DEFAULT)) {
                Db::update('shares', ['password_hash' => password_hash($pw, PASSWORD_DEFAULT)], ['id' => (int) $share['id']]);
            }
            return true;
        }
        // Legacy rows that hold something other than a password_hash() value: compare in constant
        // time once, then upgrade to a real hash.
        if ($hash !== '' && hash_equals($hash, $pw)) {
            Db::update('shares', ['password_hash' => password_hash($pw, PASSWORD_DEFAULT)], ['id' => (int) $share['id']]);
            return true;
        }
        return false;
    }

    private function pruneSession(): void
    {
        foreach (['u', 'd', 'a'] as $k) {
            $list = $_SESSION[self::SESSION_KEY][$k] ?? [];
            if (!is_array($list)) {
                $_SESSION[self::SESSION_KEY][$k] = [];
                continue;
            }
            $now = time();
            foreach ($list as $id => $v) {
                $t = is_array($v) ? (int) ($v['until'] ?? 0) : (int) $v + self::RESUME_WINDOW;
                if ($t < $now) {
                    unset($list[$id]);
                }
            }
            $_SESSION[self::SESSION_KEY][$k] = array_slice($list, -100, null, true);
        }
    }

    private function fileParam(Request $req, array $share): ?int
    {
        $v = $req->input('file_id');
        if ($v === null || $v === '') {
            $v = $req->query('file');
        }
        if (is_int($v) && $v > 0) {
            return $v;
        }
        if (is_string($v) && ctype_digit($v) && strlen($v) < 19 && (int) $v > 0) {
            return (int) $v;
        }
        return $share['target_type'] === 'file' ? (int) $share['file_id'] : null;
    }

    /** A Range request continuing a download this browser already counted (≤ 6 h ago). */
    private function isResume(Request $req, array $share, int $fileId): bool
    {
        $range = (string) ($req->header('Range') ?? '');
        if ($range === '' || preg_match('/^bytes=0-/i', trim($range))) {
            return false;
        }
        $t = (int) ($_SESSION[self::SESSION_KEY]['d'][(int) $share['id'] . ':' . $fileId] ?? 0);
        return $t > 0 && $t + self::RESUME_WINDOW > time();
    }

    private function intactBlob(array $file): ?array
    {
        try {
            $blob = BlobStore::get((int) $file['blob_id']);
            return BlobStore::isIntact($blob) ? $blob : null;
        } catch (\Throwable $e) {
            Logger::error('download', 'Shared file data missing', ['file_id' => (int) $file['id'], 'error' => $e->getMessage()]);
            return null;
        }
    }

    // ================================================================== internals: side effects

    /**
     * share.access audit + access counters, at most once per browser per share (page) or per file
     * (preview) every 10 minutes so reloads and media seeking do not flood the log.
     */
    private function noteAccess(array $share, string $what, ?array $file = null): void
    {
        $key = (int) $share['id'] . ':' . $what . ':' . ($file !== null ? (int) $file['id'] : 0);
        $last = (int) ($_SESSION[self::SESSION_KEY]['a'][$key] ?? 0);
        if ($last + self::ACCESS_LOG_INTERVAL > time() || Request::capture()->realMethod() === 'HEAD') {
            return;
        }
        $_SESSION[self::SESSION_KEY]['a'][$key] = time();
        if ($what === 'page') {
            ShareService::recordAccess($share);
        }
        $target = $file !== null
            ? ['target_type' => 'file', 'target_id' => (int) $file['id'], 'owner_id' => (int) $file['owner_id']]
            : ($share['target_type'] === 'file'
                ? ['target_type' => 'file', 'target_id' => (int) $share['file_id'], 'owner_id' => (int) (Db::value('SELECT owner_id FROM files WHERE id = ?', [(int) $share['file_id']]) ?? $share['owner_id'])]
                : ['target_type' => 'share', 'target_id' => (int) $share['id'], 'owner_id' => (int) $share['owner_id']]);
        Audit::log('share.access', $target + [
            'user_id' => null, 'actor_label' => self::ANON, 'category' => 'activity', 'detail' => $what,
            'meta' => ['share_id' => (int) $share['id']],
        ]);
    }

    /** Audit, counters, stats, owner notification and live events for a counted download. */
    private function afterDownload(array $share, ?array $file, ?int $zipFiles): void
    {
        try {
            $title = ShareService::summary($share, null, false)['title'];
            if ($file !== null) {
                Audit::log('share.download', [
                    'user_id' => null, 'actor_label' => self::ANON, 'target_type' => 'file', 'target_id' => (int) $file['id'],
                    'owner_id' => (int) $file['owner_id'], 'detail' => (string) $file['name'], 'meta' => ['share_id' => (int) $share['id']],
                ]);
                Db::run('UPDATE files SET download_count = download_count + 1, last_accessed_at = :now WHERE id = :id', ['now' => Db::now(), 'id' => (int) $file['id']]);
                $fresh = Db::one('SELECT * FROM files WHERE id = ?', [(int) $file['id']]);
                if ($fresh !== null) {
                    EventBus::publish('file.updated', ['file' => ShareService::fileSummary($fresh, null), 'changes' => ['download_count']], EventBus::fileAudience((int) $file['id']), [
                        'actor_id' => null, 'file_id' => (int) $file['id'], 'share_id' => (int) $share['id'],
                    ]);
                }
                $what = '“' . $file['name'] . '”';
            } else {
                Audit::log('share.download', [
                    'user_id' => null, 'actor_label' => self::ANON, 'target_type' => 'share', 'target_id' => (int) $share['id'],
                    'owner_id' => (int) $share['owner_id'], 'detail' => 'ZIP', 'meta' => ['share_id' => (int) $share['id'], 'zip' => true, 'files' => (int) $zipFiles],
                ]);
                $what = '“' . $title . '” as a ZIP';
            }
            Stats::bump('downloads');
            EventBus::publish('stats.updated', ['metric' => 'downloads', 'delta' => 1], [], ['admin' => true, 'actor_id' => null]);
            $fresh = ShareService::find((int) $share['id']);
            if ($fresh !== null) {
                ShareService::publish('share.updated', $fresh, false, null);
            }
            $hour = gmdate('YmdH');
            $recipients = array_values(array_unique(array_merge([(int) $share['owner_id']], $file !== null ? [(int) $file['owner_id']] : [])));
            foreach ($recipients as $uid) {
                ShareService::notify($uid, 'download', 'share.download', 'Someone downloaded ' . $what . ' via your share link', '', array_filter([
                    'share_id' => (int) $share['id'],
                    'file_id'  => $file !== null ? (int) $file['id'] : null,
                    'link'     => '#/shared',
                ], static fn ($v) => $v !== null), 'share-dl:' . (int) $share['id'] . ':' . $hour, null);
            }
        } catch (\Throwable $e) {
            Logger::exception('share', $e, ['share_id' => (int) $share['id']]);
        }
    }

    /** Store an uploaded replacement and add it as the shared file's new version. */
    private function receiveVersion(Request $req, array $share): array
    {
        if ($share['target_type'] !== 'file') {
            throw ApiException::forbidden('Uploads are only possible on links to a single file.');
        }
        $file = FileAccess::forLinkShare($share, (int) $share['file_id']);
        if (empty($file['access']['edit'])) {
            throw ApiException::forbidden('This link does not allow uploading a new version.');
        }
        $writer = 'FT\\Files\\FileWriter';
        if (!class_exists($writer) || !method_exists($writer, 'addVersion')) {
            throw ApiException::unavailable('Uploading is not available on this server yet.');
        }
        $limit = $this->uploadLimit();
        $ownerId = (int) $file['owner_id'];
        $tmp = Paths::userDir($ownerId, 'temp') . '/share-' . bin2hex(random_bytes(12)) . '.part';
        $origName = '';
        try {
            if (isset($_FILES['file']) && is_array($_FILES['file'])) {
                $f = $_FILES['file'];
                if (is_array($f['error'] ?? null)) {
                    throw ApiException::validation(['file' => 'Upload one file at a time.']);
                }
                $err = (int) ($f['error'] ?? UPLOAD_ERR_NO_FILE);
                if ($err === UPLOAD_ERR_INI_SIZE || $err === UPLOAD_ERR_FORM_SIZE || (int) ($f['size'] ?? 0) > $limit) {
                    throw ApiException::tooLarge('This file is too large to upload here (maximum ' . $this->humanBytes($limit) . ').');
                }
                if ($err !== UPLOAD_ERR_OK) {
                    throw ApiException::validation(['file' => 'Choose a file to upload.']);
                }
                if (!is_uploaded_file((string) $f['tmp_name']) || !move_uploaded_file((string) $f['tmp_name'], $tmp)) {
                    throw ApiException::server('The upload could not be stored. Please try again.');
                }
                $origName = (string) ($f['name'] ?? '');
            } else {
                $declared = (int) ($req->header('Content-Length') ?? 0);
                if ($declared <= 0) {
                    throw ApiException::validation(['file' => 'Choose a file to upload.']);
                }
                if ($declared > $limit) {
                    throw ApiException::tooLarge('This file is too large to upload here (maximum ' . $this->humanBytes($limit) . ').');
                }
                $in = $req->bodyStream();
                $out = @fopen($tmp, 'wb');
                if ($out === false) {
                    fclose($in);
                    throw ApiException::server('The upload could not be stored. Please try again.');
                }
                $copied = stream_copy_to_stream($in, $out, $limit + 1);
                fclose($in);
                fclose($out);
                if ($copied === false || $copied > $limit) {
                    throw ApiException::tooLarge('This file is too large to upload here (maximum ' . $this->humanBytes($limit) . ').');
                }
                $hdr = $req->header('X-File-Name');
                $origName = is_string($hdr) ? rawurldecode($hdr) : '';
            }
            $ext = MimeDetector::extension($origName);
            if ($origName !== '' && $ext !== strtolower((string) $file['ext'])) {
                throw ApiException::validation(['file' => 'Upload a ' . ($file['ext'] !== '' ? '.' . $file['ext'] . ' ' : '') . 'file to replace “' . $file['name'] . '”.']);
            }
            clearstatcache(true, $tmp);
            $size = (int) @filesize($tmp);
            QuotaService::assertCanStore($ownerId, $size);
            $blob = BlobStore::putFile($tmp, BlobStore::scopeFor($ownerId), null, (string) $file['name']);
        } finally {
            if (is_file($tmp)) {
                @unlink($tmp);
            }
        }
        // user id 0 = anonymous: the version has no created_by and everyone with access is told
        // "Someone uploaded version N".
        $new = $writer::addVersion((int) $file['id'], $blob, 0, 'Uploaded via share link');
        $version = (int) ($new['version'] ?? 0);
        Audit::log('share.upload', [
            'user_id' => null, 'actor_label' => self::ANON, 'target_type' => 'file', 'target_id' => (int) $file['id'],
            'owner_id' => $ownerId, 'detail' => (string) $file['name'], 'meta' => ['share_id' => (int) $share['id'], 'version' => $version, 'size' => $size],
        ]);
        return ['file_id' => (int) $file['id'], 'name' => (string) $file['name'], 'version' => $version, 'size' => $size];
    }

    private function uploadLimit(): int
    {
        $max = min(BlobStore::SEGMENT_BYTES, Capabilities::maxRequestBytes() - 65536);
        $setting = Settings::int('max_upload_bytes', 209715200);
        return max(1, $setting > 0 ? min($max, $setting) : $max);
    }

    private function stream(array $file, array $blob, Request $req, bool $inline): void
    {
        $streamer = 'FT\\Storage\\FileStreamer';
        if (!class_exists($streamer)) {
            throw ApiException::unavailable('File delivery is not available on this server yet.');
        }
        $streamer::send($file, $blob, $req, $inline);
    }

    // ================================================================== internals: rendering

    private function sharePage(array $share, ?int $folderId): Response
    {
        $caps = FileAccess::combine([$share]) ?? [];
        $sum = ShareService::summary($share, null, false);
        $owner = Db::one('SELECT id, username, display_name FROM users WHERE id = ?', [(int) $share['owner_id']]);
        $exhausted = $sum['status'] === 'exhausted';
        $v = $this->baseView($share) + [
            'state'          => 'share',
            'title'          => $sum['title'],
            'heading'        => $sum['title'],
            'owner'          => ShareService::displayName($owner),
            'message'        => $sum['message'],
            'target'         => (string) $share['target_type'],
            'expires_at'     => $sum['expires_at'],
            'expires_label'  => $share['expires_at'] !== null ? gmdate('d M Y, H:i', (int) Db::toUnix((string) $share['expires_at'])) . ' UTC' : null,
            'exhausted'      => $exhausted,
            'downloads_left' => $share['max_downloads'] !== null ? max(0, (int) $share['max_downloads'] - (int) $share['download_count']) : null,
            'can_preview'    => !empty($caps['preview']),
            'can_download'   => !empty($caps['download']) && !$exhausted,
            'download_off'   => empty($caps['download']),
            'can_comment'    => !empty($caps['comment']),
            'can_upload'     => !empty($caps['edit']) && $share['target_type'] === 'file',
            'upload_limit'   => $this->humanBytes($this->uploadLimit()),
            'zip_url'        => $share['target_type'] !== 'file' ? $this->link($share, '/zip') : null,
            'flash'          => $this->takeFlash($share),
        ];
        if ($share['target_type'] === 'file') {
            $file = FileAccess::forLinkShare($share, (int) $share['file_id']);
            $v['file'] = $this->fileView($share, $file, $caps, true);
            $v['comments'] = !empty($caps['comment']) ? CommentService::listForLink($file) : [];
            $v['comment_file_id'] = (int) $file['id'];
        } elseif ($share['target_type'] === 'bundle') {
            $v['files'] = array_map(fn (array $f): array => $this->fileView($share, $f, $caps, false), ShareService::bundleFiles($share));
        } else {
            $v['folder'] = $this->folderView($share, ShareService::linkFolder($share, $folderId ?? (int) $share['folder_id']), $caps);
        }
        return $this->render($v, 200);
    }

    private function passwordPage(array $share, ?string $error, int $status, array $headers = []): Response
    {
        $sum = ShareService::summary($share, null, false);
        $owner = Db::one('SELECT id, username, display_name FROM users WHERE id = ?', [(int) $share['owner_id']]);
        return $this->render($this->baseView($share) + [
            'state'      => 'password',
            'title'      => 'Password required',
            'heading'    => 'This link is password protected',
            'owner'      => ShareService::displayName($owner),
            'item_title' => $sum['title'],
            'error'      => $error,
            'unlock_url' => $this->link($share, '/unlock'),
        ], $status, $headers);
    }

    private function unavailable(string $problem): Response
    {
        $status = in_array($problem, ['expired', 'revoked'], true) ? 410 : 404;
        return $this->render([
            'state'   => 'unavailable',
            'title'   => 'Link unavailable',
            'heading' => 'This link is not available',
            'text'    => 'The link may have expired or been turned off by the person who shared it. Ask them to send you a new one.',
        ] + $this->assetView(), $status);
    }

    private function messagePage(array $share, string $heading, string $text, int $status): Response
    {
        return $this->render($this->baseView($share) + [
            'state'    => 'message',
            'title'    => $heading,
            'heading'  => $heading,
            'text'     => $text,
            'back_url' => $this->link($share),
        ], $status);
    }

    private function baseView(array $share): array
    {
        return [
            'token'    => (string) $share['token'],
            'page_url' => $this->link($share),
            'csrf'     => Csrf::token(),
            'urls'     => [
                'page'     => $this->link($share),
                'folder'   => $this->link($share, '/folder/'),
                'comments' => $this->link($share, '/comments'),
                'upload'   => $this->link($share, '/upload'),
                'download' => $this->link($share, '/download'),
                'content'  => $this->link($share, '/content/'),
                'thumb'    => $this->link($share, '/thumbnail/'),
            ],
        ] + $this->assetView();
    }

    private function assetView(): array
    {
        $base = Request::capture()->basePath();
        return [
            'base'   => $base,
            'css'    => $base . 'assets/css/public.css?v=' . rawurlencode(FT_VERSION),
            'js'     => $base . 'assets/js/public-share.js?v=' . rawurlencode(FT_VERSION),
            'app'    => (string) Settings::string('site_name', 'FastTransfer'),
        ];
    }

    /** View model of one file (no ids of anything outside the share). */
    private function fileView(array $share, array $file, array $caps, bool $withText): array
    {
        $id = (int) $file['id'];
        $preview = !empty($caps['preview']) ? $this->previewType($file) : null;
        if ($preview !== null && !in_array($preview, self::MEDIA_PREVIEWS, true) && ShareService::status($share) === 'exhausted') {
            $preview = null; // see content(): a PDF/text preview is the whole file
        }
        $view = [
            'id'            => $id,
            'name'          => (string) $file['name'],
            'ext'           => (string) $file['ext'],
            'kind'          => (string) $file['kind'],
            'size'          => (int) $file['size'],
            'size_label'    => $this->humanBytes((int) $file['size']),
            'updated_label' => gmdate('d M Y, H:i', (int) Db::toUnix((string) $file['updated_at'])) . ' UTC',
            'updated_at'    => Db::iso((string) $file['updated_at']),
            'preview'       => $preview,
            'thumb_url'     => !empty($caps['preview']) && $file['thumb_version'] !== null ? $this->link($share, '/thumbnail/' . $id) : null,
            'content_url'   => $preview !== null ? $this->link($share, '/content/' . $id) : null,
            'download_url'  => $this->link($share, '/download', ['file' => $id]),
            'text'          => null,
            'text_truncated' => false,
        ];
        if ($withText && $preview === 'text') {
            [$view['text'], $view['text_truncated']] = $this->textPreview($file);
            if ($view['text'] === null) {
                $view['preview'] = null;
            }
        }
        return $view;
    }

    private function folderView(array $share, array $listing, array $caps): array
    {
        $folders = [];
        foreach ($listing['folders'] as $f) {
            $folders[] = [
                'id'   => (int) $f['id'],
                'name' => (string) $f['name'],
                'url'  => $this->link($share, '', ['folder' => (int) $f['id']]),
                'api'  => $this->link($share, '/folder/' . (int) $f['id']),
            ];
        }
        $crumbs = [];
        foreach ($listing['breadcrumbs'] as $c) {
            $crumbs[] = ['id' => (int) $c['id'], 'name' => (string) $c['name'], 'url' => $this->link($share, '', ['folder' => (int) $c['id']]), 'api' => $this->link($share, '/folder/' . (int) $c['id'])];
        }
        return [
            'folder'      => ['id' => (int) $listing['folder']['id'], 'name' => (string) $listing['folder']['name'], 'is_root' => (bool) $listing['folder']['is_root']],
            'breadcrumbs' => $crumbs,
            'folders'     => $folders,
            'files'       => array_map(fn (array $f): array => $this->fileView($share, $f, $caps, false), $listing['files']),
            'truncated'   => (bool) $listing['truncated'],
            'can_download' => !empty($caps['download']) && ShareService::status($share) !== 'exhausted',
            'can_comment' => !empty($caps['comment']),
        ];
    }

    private function previewType(array $file): ?string
    {
        $type = MimeDetector::inlineType((string) $file['mime'], (string) $file['ext']);
        if ($type === null) {
            return null;
        }
        return match (true) {
            str_starts_with($type, 'image/') => 'image',
            str_starts_with($type, 'video/') => 'video',
            str_starts_with($type, 'audio/') => 'audio',
            str_starts_with($type, 'application/pdf') => 'pdf',
            str_starts_with($type, 'text/plain') => 'text',
            default => null,
        };
    }

    /** @return array{0:?string,1:bool} escaped later by the template; null when unreadable */
    private function textPreview(array $file): array
    {
        try {
            $blob = BlobStore::get((int) $file['blob_id']);
            $reader = BlobStore::open($blob);
            $data = '';
            try {
                while (strlen($data) < self::TEXT_PREVIEW_BYTES && ($chunk = $reader->read(self::TEXT_PREVIEW_BYTES - strlen($data))) !== '') {
                    $data .= $chunk;
                }
            } finally {
                $reader->close();
            }
            $truncated = (int) $file['size'] > strlen($data);
            if ($truncated) {
                // do not cut a multi-byte character in half
                $data = (string) preg_replace('/[\x80-\xBF]*[\xC0-\xFF]?$/', '', $data);
            }
            return [mb_scrub($data, 'UTF-8'), $truncated];
        } catch (\Throwable $e) {
            Logger::warning('share', 'Text preview unavailable', ['file_id' => (int) $file['id'], 'error' => $e->getMessage()]);
            return [null, false];
        }
    }

    private function render(array $v, int $status, array $headers = []): Response
    {
        $nonce = class_exists(\FT\Support\Csp::class) ? \FT\Support\Csp::nonce() : base64_encode(random_bytes(16));
        $v['nonce'] = $nonce;
        $csp = class_exists(\FT\Support\Csp::class)
            ? \FT\Support\Csp::header($nonce)
            : "default-src 'self'; script-src 'self' 'nonce-{$nonce}' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
              . "font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; "
              . "worker-src 'self' blob:; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'";
        $view = static function (array $v): string {
            ob_start();
            try {
                include FT_ROOT . '/views/share.php';
            } catch (\Throwable $e) {
                ob_end_clean();
                throw $e;
            }
            return (string) ob_get_clean();
        };
        return Response::html($view($v), $status, $headers + [
            'Content-Security-Policy' => $csp,
            'Cache-Control'           => 'no-store, no-cache, must-revalidate, private',
            'Pragma'                  => 'no-cache',
            'Referrer-Policy'         => 'no-referrer',
            'X-Robots-Tag'            => 'noindex, nofollow, noarchive',
            'X-Frame-Options'         => 'SAMEORIGIN',
            'Vary'                    => 'Cookie',
        ]);
    }

    /** URL of the share page or one of its sub-resources, honouring PRETTY_URLS. */
    private function link(array $share, string $suffix = '', array $query = []): string
    {
        $base = Request::capture()->basePath();
        $token = (string) $share['token'];
        if (Config::get('app.pretty_urls')) {
            $qs = http_build_query($query);
            return $base . 's/' . $token . $suffix . ($qs !== '' ? '?' . $qs : '');
        }
        return $base . 'index.php?' . http_build_query(['r' => '/s/' . $token . $suffix] + $query);
    }

    private function redirectToPage(array $share): Response
    {
        return Response::redirect($this->link($share), 303);
    }

    private function flashRedirect(array $share, string $type, string $text, string $anchor = ''): Response
    {
        $_SESSION[self::SESSION_KEY]['f'][(int) $share['id']] = ['type' => $type, 'text' => mb_substr($text, 0, 300)];
        return Response::redirect($this->link($share) . $anchor, 303);
    }

    private function takeFlash(array $share): ?array
    {
        $f = $_SESSION[self::SESSION_KEY]['f'][(int) $share['id']] ?? null;
        unset($_SESSION[self::SESSION_KEY]['f'][(int) $share['id']]);
        return is_array($f) && isset($f['text']) ? ['type' => $f['type'] === 'ok' ? 'ok' : 'err', 'text' => (string) $f['text']] : null;
    }

    private function humanBytes(int $n): string
    {
        $units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
        $i = 0;
        $v = (float) $n;
        while ($v >= 1024 && $i < count($units) - 1) {
            $v /= 1024;
            $i++;
        }
        return $i === 0 ? $n . ' bytes' : number_format($v, $v >= 100 ? 0 : 1) . ' ' . $units[$i];
    }
}
