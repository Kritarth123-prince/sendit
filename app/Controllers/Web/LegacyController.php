<?php
declare(strict_types=1);

namespace FT\Controllers\Web;

use FT\Core\ApiException;
use FT\Core\Config;
use FT\Core\Db;
use FT\Files\FileAccess;
use FT\Http\Request;
use FT\Http\Response;
use FT\Legacy\LegacyRoutes;

/**
 * Legacy URL shims (docs/ARCHITECTURE.md §14). index.php routes every root URL that carries a
 * legacy query trigger ("/?share=…", "/?download=…", "/?logout", …) here, so links, bookmarks and
 * QR codes made with the single-file app keep working after the upgrade:
 *
 *   ?share=T            GET  → 302 s/T            POST (password form) → 307 s/T/unlock (body kept)
 *   ?download=NAME      → 302 to the API download of the migrated file (files.legacy_name) when the
 *                         signed-in user can download it; otherwise a 404 page (existence is never
 *                         revealed). Signed-out visitors are sent to sign in first.
 *   ?serve=NAME         → same, to the inline preview endpoint (needs the preview capability)
 *   ?logout             → 302 to /logout (A1's sign-out page)
 *   anything else       → 302 to the app root
 *
 * Every target is built from the app's own base path plus a sanitised token or numeric id, so
 * these redirects can never point at another site.
 */
final class LegacyController
{
    public function handle(Request $req): Response
    {
        $get = $_GET;
        unset($get['r']);

        if (array_key_exists('share', $get)) {
            $token = LegacyRoutes::cleanToken($get['share']);
            if ($token === null) {
                return Response::redirect($req->basePath(), 302);
            }
            if ($req->realMethod() === 'POST') {
                // 307 keeps the method and the form body (share_password), which A4 accepts.
                return Response::redirect(self::url($req, 's/' . $token . '/unlock'), 307);
            }
            return Response::redirect(self::url($req, 's/' . $token), 302);
        }

        if (array_key_exists('logout', $get)) {
            return Response::redirect(self::url($req, 'logout'), 302);
        }

        foreach (['download' => ['download', 'download'], 'serve' => ['content', 'preview']] as $key => [$endpoint, $capability]) {
            if (!array_key_exists($key, $get)) {
                continue;
            }
            $name = LegacyRoutes::cleanName($get[$key]);
            if ($name === null) {
                throw ApiException::fileNotFound();
            }
            if ($req->user === null) {
                // Sign in first, then come back to the same legacy link.
                $next = '/?' . $key . '=' . rawurlencode($name);
                return Response::redirect($req->basePath() . '?next=' . rawurlencode($next), 302);
            }
            $fileId = self::findVisible($req->user, $name, $capability);
            if ($fileId === null) {
                throw ApiException::fileNotFound();
            }
            return Response::redirect(self::url($req, 'api/v1/files/' . $fileId . '/' . $endpoint), 302);
        }

        return Response::redirect($req->basePath(), 302);
    }

    /**
     * The id of a live migrated file with this legacy name that $user may $capability, or null.
     * Re-loaded from the database and checked with FileAccess — the name alone grants nothing.
     */
    public static function findVisible(array $user, string $legacyName, string $capability): ?int
    {
        $rows = Db::all(
            'SELECT * FROM files WHERE legacy_name = ? AND deleted_at IS NULL ORDER BY id ASC LIMIT 20',
            [$legacyName]
        );
        if ($rows === []) {
            return null;
        }
        $caps = FileAccess::accessForMany($user, $rows);
        // Prefer the user's own copy, then anything shared with them.
        usort($rows, static fn ($a, $b) => ((int) $b['owner_id'] === (int) $user['id']) <=> ((int) $a['owner_id'] === (int) $user['id']));
        foreach ($rows as $row) {
            $c = $caps[(int) $row['id']] ?? null;
            if ($c !== null && !empty($c[$capability])) {
                return (int) $row['id'];
            }
        }
        return null;
    }

    /** App URL that works with and without mod_rewrite ("s/abc" → "/base/s/abc" or "/base/index.php?r=/s/abc"). */
    public static function url(Request $req, string $path): string
    {
        $base = $req->basePath();
        if ($path === '' || Config::get('app.pretty_urls', true)) {
            return $base . $path;
        }
        $q = strpos($path, '?');
        $route = $q === false ? $path : substr($path, 0, $q);
        $rest = $q === false ? '' : '&' . substr($path, $q + 1);
        return $base . 'index.php?r=/' . $route . $rest;
    }
}
