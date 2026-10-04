<?php
declare(strict_types=1);

namespace FT\Search;

use FT\Core\ApiException;
use FT\Core\Db;
use FT\Files\FileAccess;
use FT\Files\FileRepository;
use FT\Files\FileWriter;
use FT\Security\Policy;
use FT\Storage\MimeDetector;

/**
 * Keyword search over the files a user may see (docs/ARCHITECTURE.md §9.4 "Search"). No
 * semantic/vector/AI search — plain, escaped LIKE matching over:
 *   name · extension · tags · folder name · description · owner · file content (text/code
 *   files, file_texts source "content") · OCR text (file_texts source "ocr")
 * plus filters (kind, extension, owner, dates, size, folder (optionally recursive), tags,
 * shared, favourite, trash).
 *
 * Scope (never leaks inaccessible files):
 *   default  own files + files shared with the user (direct user shares, bundle items, and
 *            everything below a shared folder reached through live folders — the same rule as
 *            FileAccess), never trashed;
 *   trash=1  the user's own trashed files only (administrators: everyone's with scope=all);
 *   scope=all (administrators only) every live file.
 * Shares count only while FileAccess would honour them (creator and item owner active, re-share
 * chains intact). Indexed file content and OCR text are matched only for files the viewer may
 * PREVIEW (own files + files reached through shares that allow previews): that restriction is
 * part of the SQL, so neither results, snippets nor the total reveal text the viewer may not read.
 * The SQL scope is followed by FileAccess::accessForMany() on the page, so anything the SQL
 * might let through is dropped before it reaches the response.
 *
 * Each result is a FileSummary plus match {field, snippet, text}: "snippet" is HTML-escaped
 * with the hits wrapped in <mark> (safe to insert as HTML), "text" is the same excerpt as plain
 * text (for textContent).
 */
final class SearchService
{
    public const FIELDS = ['name', 'ext', 'tags', 'folder', 'description', 'owner', 'content', 'ocr'];
    public const SORTS = ['relevance', 'name', 'size', 'created_at', 'updated_at', 'kind'];
    public const MAX_TERMS = 6;
    private const MAX_SCOPE_FOLDERS = 10000;
    private const SNIPPET_BEFORE = 60;
    private const SNIPPET_AFTER = 120;

    /**
     * @param array<string,mixed> $p validated parameters (see SearchController::params())
     * @return array{items:array,total:int,page:int,per_page:int}
     */
    public static function search(array $viewer, array $p): array
    {
        $uid = (int) $viewer['id'];
        $isAdmin = Policy::isAdmin($viewer);
        $all = $isAdmin && ($p['scope'] ?? '') === 'all';
        $params = [];
        $where = [];

        // ---------------------------------------------------------------- scope
        $sharedFolders = [];
        $preview = null; // null = every file in scope may be previewed (own trash, admin scope=all)
        if (!empty($p['trash'])) {
            $where[] = 'f.deleted_at IS NOT NULL';
            if (!$all) {
                $where[] = 'f.owner_id = ' . self::bind($params, $uid);
            }
        } else {
            $where[] = 'f.deleted_at IS NULL';
            if (!$all) {
                [$scopeSql, $sharedFolders, $preview] = self::scope($uid, $params);
                $where[] = $scopeSql;
            }
        }

        // ---------------------------------------------------------------- filters
        if (!empty($p['kind'])) {
            $where[] = 'f.kind IN (' . self::bindList($params, $p['kind']) . ')';
        }
        if (!empty($p['ext'])) {
            $where[] = 'f.ext IN (' . self::bindList($params, $p['ext']) . ')';
        }
        if (($p['owner_id'] ?? 0) > 0) {
            $where[] = 'f.owner_id = ' . self::bind($params, (int) $p['owner_id']);
        }
        if (($p['owner'] ?? '') !== '') {
            $like = '%' . Db::like((string) $p['owner']) . '%';
            $where[] = 'EXISTS (SELECT 1 FROM users ou WHERE ou.id = f.owner_id AND (ou.username LIKE ' . self::bind($params, $like) . ' OR ou.display_name LIKE ' . self::bind($params, $like) . '))';
        }
        $dateCol = ($p['date_field'] ?? 'created_at') === 'updated_at' ? 'f.updated_at' : 'f.created_at';
        if (($p['date_from'] ?? null) !== null) {
            $where[] = $dateCol . ' >= ' . self::bind($params, (string) $p['date_from']);
        }
        if (($p['date_to'] ?? null) !== null) {
            $where[] = $dateCol . ' < ' . self::bind($params, (string) $p['date_to']);
        }
        if (($p['size_min'] ?? null) !== null) {
            $where[] = 'f.size >= ' . self::bind($params, (int) $p['size_min']);
        }
        if (($p['size_max'] ?? null) !== null) {
            $where[] = 'f.size <= ' . self::bind($params, (int) $p['size_max']);
        }
        if (($p['folder_id'] ?? null) !== null) {
            $folderId = (int) $p['folder_id'];
            // Must be a folder the user can see at all (404 otherwise; existence not revealed).
            FileAccess::requireFolder($viewer, $folderId, 'view', !empty($p['trash']));
            if (!empty($p['recursive'])) {
                $ids = self::liveDescendants([$folderId], !empty($p['trash']));
                $where[] = 'f.folder_id IN (' . self::bindList($params, $ids) . ')';
            } else {
                $where[] = 'f.folder_id = ' . self::bind($params, $folderId);
            }
        }
        foreach ($p['tag'] ?? [] as $tag) {
            $where[] = 'EXISTS (SELECT 1 FROM file_tags ftf JOIN tags tf ON tf.id = ftf.tag_id WHERE ftf.file_id = f.id AND tf.name = ' . self::bind($params, (string) $tag) . ')';
        }
        if (!empty($p['favorite'])) {
            $where[] = 'EXISTS (SELECT 1 FROM favorites fv WHERE fv.file_id = f.id AND fv.user_id = ' . self::bind($params, $uid) . ')';
        }
        $shared = (string) ($p['shared'] ?? '');
        if ($shared !== '') {
            // Bind only what the chosen branch uses: native prepares reject unused parameters.
            $where[] = match ($shared) {
                'with_me' => 'f.owner_id <> ' . self::bind($params, $uid),
                'by_me'   => '(f.owner_id = ' . self::bind($params, $uid) . ' AND ' . self::hasActiveShareSql($params) . ')',
                default   => '((f.owner_id = ' . self::bind($params, $uid) . ' AND ' . self::hasActiveShareSql($params) . ') OR f.owner_id <> ' . self::bind($params, $uid) . ')',
            };
        }

        // ---------------------------------------------------------------- keywords
        $terms = $p['terms'] ?? [];
        $fields = $p['fields'] ?? self::FIELDS;
        foreach ($terms as $term) {
            $or = self::termConditions($term, $fields, $params, $uid, $all, $sharedFolders, $preview);
            if ($or === []) {
                // e.g. a one-character term with only content/ocr selected: nothing can match
                $where[] = '1 = 0';
                continue;
            }
            $where[] = '(' . implode(' OR ', $or) . ')';
        }

        $sql = implode(' AND ', $where);
        $total = (int) Db::value("SELECT COUNT(*) FROM files f WHERE {$sql}", $params);

        // ---------------------------------------------------------------- page
        $orderParams = $params;
        $sort = (string) ($p['sort'] ?? '');
        $dir = strtolower((string) ($p['order'] ?? 'desc')) === 'asc' ? 'ASC' : 'DESC';
        if ($sort === '' || $sort === 'relevance') {
            if ($terms !== []) {
                $order = 'CASE WHEN f.name LIKE ' . self::bind($orderParams, '%' . Db::like($terms[0]) . '%') . ' THEN 0 ELSE 1 END ASC, f.updated_at DESC, f.id DESC';
            } else {
                $order = 'f.updated_at DESC, f.id DESC';
            }
        } else {
            $col = ['name' => 'f.name', 'size' => 'f.size', 'created_at' => 'f.created_at', 'updated_at' => 'f.updated_at', 'kind' => 'f.kind'][$sort] ?? 'f.updated_at';
            $order = "{$col} {$dir}, f.id {$dir}";
        }
        $page = max(1, (int) ($p['page'] ?? 1));
        $per = max(1, min(200, (int) ($p['per_page'] ?? 50)));
        $pageParams = $orderParams + ['lim' => $per, 'off' => ($page - 1) * $per];
        $rows = Db::all(
            "SELECT f.*, b.encryption AS blob_encryption FROM files f LEFT JOIN file_blobs b ON b.id = f.blob_id
              WHERE {$sql} ORDER BY {$order} LIMIT :lim OFFSET :off",
            $pageParams
        );

        // Defence in depth: the authoritative access decision for every row on the page.
        $caps = FileAccess::accessForMany($viewer, $rows);
        $rows = array_values(array_filter($rows, static fn ($r) => ($caps[(int) $r['id']] ?? null) !== null));

        $summaries = self::summaries($rows, $viewer, $caps, !empty($p['trash']));
        $matches = $terms !== [] ? self::matches($rows, $terms, $fields, $uid, $all, $sharedFolders, $caps) : [];
        foreach ($summaries as $i => $s) {
            $summaries[$i]['match'] = $matches[(int) $s['id']] ?? null;
        }
        return ['items' => $summaries, 'total' => $total, 'page' => $page, 'per_page' => $per];
    }

    /** Split a query into up to MAX_TERMS distinct terms ("quoted phrases" stay together). */
    public static function terms(string $q): array
    {
        $q = trim((string) preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $q));
        if ($q === '') {
            return [];
        }
        preg_match_all('/"([^"]+)"|(\S+)/u', $q, $m, PREG_SET_ORDER);
        $out = [];
        foreach ($m as $x) {
            $t = trim($x[1] !== '' ? $x[1] : ($x[2] ?? ''));
            $t = mb_substr($t, 0, 100);
            if ($t !== '' && !in_array(mb_strtolower($t), array_map('mb_strtolower', $out), true)) {
                $out[] = $t;
            }
            if (count($out) >= self::MAX_TERMS) {
                break;
            }
        }
        return $out;
    }

    // ================================================================== SQL pieces

    /**
     * "(own OR ((directly shared OR in a shared bundle OR below a shared live folder) AND the
     * owner is active))", from the shares that still grant access (FileAccess::viewerShares():
     * not revoked/expired, creator active, re-shares honoured, bundle re-shares trimmed).
     * Also returns the same scope restricted to shares that allow PREVIEWS: indexed file content
     * and OCR text may only be matched (and quoted) for files the viewer may preview — anything
     * else would leak the content through results, snippets or even the total count.
     * @return array{0:string,1:int[],2:array} SQL, folder ids reachable through folder shares,
     *         preview scope spec (for previewSql())
     */
    private static function scope(int $uid, array &$params): array
    {
        $all = ['uid' => $uid, 'files' => [], 'bundles' => [], 'folders' => []];
        $preview = $all;
        $rootFolders = [];
        $previewRoots = [];
        foreach (FileAccess::viewerShares($uid) as $s) {
            $canPreview = !empty(FileAccess::combine([$s])['preview']);
            $files = [];
            $bundles = [];
            if ($s['target_type'] === 'file' && $s['file_id'] !== null) {
                $files[] = (int) $s['file_id'];
            } elseif ($s['target_type'] === 'bundle') {
                if (isset($s['_items'])) {
                    $files = $s['_items']; // a bundle re-share: only what its chain still reaches
                } else {
                    $bundles[] = (int) $s['id'];
                }
            } elseif ($s['target_type'] === 'folder' && $s['folder_id'] !== null) {
                $rootFolders[] = (int) $s['folder_id'];
                if ($canPreview) {
                    $previewRoots[] = (int) $s['folder_id'];
                }
            }
            array_push($all['files'], ...$files);
            array_push($all['bundles'], ...$bundles);
            if ($canPreview) {
                array_push($preview['files'], ...$files);
                array_push($preview['bundles'], ...$bundles);
            }
        }
        $all['folders'] = $rootFolders !== [] ? self::liveDescendants($rootFolders, false) : [];
        $previewRoots = array_values(array_unique($previewRoots));
        $preview['folders'] = count($previewRoots) === count(array_unique($rootFolders)) ? $all['folders']
            : ($previewRoots !== [] ? self::liveDescendants($previewRoots, false) : []);
        foreach (['files', 'bundles'] as $k) {
            $all[$k] = array_values(array_unique($all[$k]));
            $preview[$k] = array_values(array_unique($preview[$k]));
        }
        return [self::sharedSql($params, $all), $all['folders'], $preview];
    }

    /** SQL for a scope spec from scope(), with fresh placeholders (usable several times per statement). */
    private static function sharedSql(array &$params, array $spec): string
    {
        $own = 'f.owner_id = ' . self::bind($params, (int) $spec['uid']);
        $parts = [];
        if ($spec['files'] !== []) {
            $parts[] = 'f.id IN (' . self::bindList($params, $spec['files']) . ')';
        }
        if ($spec['bundles'] !== []) {
            $parts[] = 'f.id IN (SELECT si.file_id FROM share_items si WHERE si.share_id IN (' . self::bindList($params, $spec['bundles']) . '))';
        }
        if ($spec['folders'] !== []) {
            $parts[] = 'f.folder_id IN (' . self::bindList($params, $spec['folders']) . ')';
        }
        if ($parts === []) {
            return '(' . $own . ')';
        }
        // someone else's file counts only while its owner's account is active
        return '(' . $own . ' OR ((' . implode(' OR ', $parts) . ") AND EXISTS (SELECT 1 FROM users so WHERE so.id = f.owner_id AND so.status = 'active' AND so.deleted_at IS NULL)))";
    }

    /** OR-conditions matching one term in the selected fields. @return string[] */
    private static function termConditions(string $term, array $fields, array &$params, int $uid, bool $all, array $sharedFolders, ?array $preview = null): array
    {
        $like = '%' . Db::like($term) . '%';
        $or = [];
        foreach ($fields as $field) {
            switch ($field) {
                case 'name':
                    $or[] = 'f.name LIKE ' . self::bind($params, $like);
                    break;
                case 'ext':
                    $ext = strtolower(ltrim($term, '.'));
                    if (preg_match('/^[a-z0-9]{1,32}$/', $ext)) {
                        $or[] = 'f.ext = ' . self::bind($params, $ext);
                    }
                    break;
                case 'tags':
                    $or[] = 'EXISTS (SELECT 1 FROM file_tags ftq JOIN tags tq ON tq.id = ftq.tag_id WHERE ftq.file_id = f.id AND tq.name LIKE ' . self::bind($params, $like) . ')';
                    break;
                case 'folder':
                    // Only folder names the user can see: their own, or inside a folder shared with them.
                    $visible = $all ? '' : ' AND (f.owner_id = ' . self::bind($params, $uid) . ($sharedFolders !== [] ? ' OR f.folder_id IN (' . self::bindList($params, $sharedFolders) . ')' : '') . ')';
                    $or[] = '(EXISTS (SELECT 1 FROM folders fo WHERE fo.id = f.folder_id AND fo.name LIKE ' . self::bind($params, $like) . ')' . $visible . ')';
                    break;
                case 'description':
                    $or[] = 'f.description LIKE ' . self::bind($params, $like);
                    break;
                case 'owner':
                    $or[] = 'EXISTS (SELECT 1 FROM users uq WHERE uq.id = f.owner_id AND (uq.username LIKE ' . self::bind($params, $like) . ' OR uq.display_name LIKE ' . self::bind($params, $like) . '))';
                    break;
                case 'content':
                case 'ocr':
                    if (mb_strlen($term) >= 2) {
                        // only files the viewer may preview (part of the query itself, so neither
                        // the results nor the total can reveal what the text contains)
                        $or[] = "(EXISTS (SELECT 1 FROM file_texts tx WHERE tx.file_id = f.id AND tx.source = '{$field}' AND tx.`text` LIKE " . self::bind($params, $like) . ')'
                            . ($preview !== null ? ' AND ' . self::sharedSql($params, $preview) : '') . ')';
                    }
                    break;
            }
        }
        return $or;
    }

    private static function hasActiveShareSql(array &$params): string
    {
        return '(EXISTS (SELECT 1 FROM shares sx WHERE sx.file_id = f.id AND sx.revoked_at IS NULL AND (sx.expires_at IS NULL OR sx.expires_at > ' . self::bind($params, Db::now()) . '))'
            . ' OR EXISTS (SELECT 1 FROM share_items sxi JOIN shares sy ON sy.id = sxi.share_id WHERE sxi.file_id = f.id AND sy.revoked_at IS NULL AND (sy.expires_at IS NULL OR sy.expires_at > ' . self::bind($params, Db::now()) . ')))';
    }

    /**
     * The given folders plus all descendants reached through live (non-trashed) folders, level by
     * level (no recursive CTEs on MySQL 5.7 / MariaDB 10.3). Trashed roots are dropped unless
     * $includeTrashed. @return int[]
     */
    public static function liveDescendants(array $rootIds, bool $includeTrashed): array
    {
        $rootIds = array_values(array_unique(array_filter(array_map('intval', $rootIds), static fn ($i) => $i > 0)));
        if ($rootIds === []) {
            return [];
        }
        [$in, $p] = Db::inList($rootIds, 'dr');
        $live = array_map('intval', Db::column('SELECT id FROM folders WHERE id IN ' . $in . ($includeTrashed ? '' : ' AND deleted_at IS NULL'), $p));
        $all = array_fill_keys($live, true);
        $frontier = $live;
        for ($depth = 0; $frontier !== [] && $depth < 64 && count($all) < self::MAX_SCOPE_FOLDERS; $depth++) {
            $next = [];
            foreach (array_chunk($frontier, 1000) as $chunk) {
                [$in, $p] = Db::inList($chunk, 'dc');
                foreach (Db::column('SELECT id FROM folders WHERE parent_id IN ' . $in . ($includeTrashed ? '' : ' AND deleted_at IS NULL'), $p) as $id) {
                    $id = (int) $id;
                    if (!isset($all[$id])) {
                        $all[$id] = true;
                        $next[] = $id;
                    }
                }
            }
            $frontier = $next;
        }
        return array_keys($all);
    }

    // ================================================================== results

    private static function summaries(array $rows, array $viewer, array $caps, bool $trash): array
    {
        if ($rows === []) {
            return [];
        }
        if (class_exists(FileRepository::class) && method_exists(FileRepository::class, 'summaries')) {
            return FileRepository::summaries($rows, $viewer, ['access' => $caps, 'trash' => $trash]);
        }
        return array_map(static fn ($r) => FileWriter::summary($r, $viewer), $rows);
    }

    /**
     * Which field matched first (in FIELDS order, among the selected ones) and a short excerpt.
     * Content/OCR excerpts only for files the viewer may preview ($caps from FileAccess).
     * @return array<int,array{field:string,snippet:string,text:string}>
     */
    private static function matches(array $rows, array $terms, array $fields, int $uid, bool $all, array $sharedFolders, array $caps = []): array
    {
        if ($rows === []) {
            return [];
        }
        $ids = array_map(static fn ($r) => (int) $r['id'], $rows);
        [$in, $p] = Db::inList($ids, 'mi');
        $tags = [];
        if (in_array('tags', $fields, true)) {
            foreach (Db::all("SELECT ft.file_id, t.name FROM file_tags ft JOIN tags t ON t.id = ft.tag_id WHERE ft.file_id IN {$in}", $p) as $t) {
                $tags[(int) $t['file_id']][] = (string) $t['name'];
            }
        }
        $folderNames = [];
        if (in_array('folder', $fields, true)) {
            $fids = array_values(array_unique(array_filter(array_map(static fn ($r) => $r['folder_id'] !== null ? (int) $r['folder_id'] : 0, $rows))));
            if ($fids !== []) {
                [$fin, $fp] = Db::inList($fids, 'mf');
                foreach (Db::all("SELECT id, name FROM folders WHERE id IN {$fin}", $fp) as $f) {
                    $folderNames[(int) $f['id']] = (string) $f['name'];
                }
            }
        }
        $owners = [];
        if (in_array('owner', $fields, true)) {
            $oids = array_values(array_unique(array_map(static fn ($r) => (int) $r['owner_id'], $rows)));
            [$oin, $op] = Db::inList($oids, 'mo');
            foreach (Db::all("SELECT id, username, display_name FROM users WHERE id IN {$oin}", $op) as $u) {
                $owners[(int) $u['id']] = trim((string) $u['display_name'] . ' ' . (string) $u['username']);
            }
        }
        // Excerpts of content/OCR text around the first term, computed in SQL so whole texts
        // (up to 100 KB each) never travel to PHP.
        $windows = [];
        $textFields = array_values(array_intersect(['content', 'ocr'], $fields));
        $previewable = array_values(array_filter($ids, static fn (int $id): bool => !empty($caps[$id]['preview'])));
        if ($textFields !== [] && $previewable !== []) {
            [$inP, $pP] = Db::inList($previewable, 'mp');
            foreach ($terms as $term) {
                if (mb_strlen($term) < 2) {
                    continue;
                }
                $pp = $pP + ['t1' => $term, 't2' => $term, 'b' => self::SNIPPET_BEFORE * 2];
                foreach (Db::all(
                    "SELECT file_id, source, SUBSTRING(`text`, GREATEST(1, LOCATE(:t1, `text`) - :b), 480) AS win
                       FROM file_texts WHERE file_id IN {$inP} AND LOCATE(:t2, `text`) > 0",
                    $pp
                ) as $w) {
                    $windows[(int) $w['file_id']][(string) $w['source']] ??= [(string) $w['win'], $term];
                }
            }
        }

        $out = [];
        foreach ($rows as $r) {
            $id = (int) $r['id'];
            $folderVisible = $all || (int) $r['owner_id'] === $uid || ($r['folder_id'] !== null && in_array((int) $r['folder_id'], $sharedFolders, true));
            foreach (self::FIELDS as $field) {
                if (!in_array($field, $fields, true)) {
                    continue;
                }
                $hit = null;
                switch ($field) {
                    case 'name':
                    case 'description':
                        $hit = self::firstHit((string) ($r[$field] ?? ''), $terms);
                        break;
                    case 'ext':
                        foreach ($terms as $t) {
                            if (strtolower(ltrim($t, '.')) === strtolower((string) $r['ext']) && $r['ext'] !== '') {
                                $hit = [(string) $r['name'], $t];
                                break;
                            }
                        }
                        break;
                    case 'tags':
                        foreach ($tags[$id] ?? [] as $tag) {
                            if (($h = self::firstHit($tag, $terms)) !== null) {
                                $hit = $h;
                                break;
                            }
                        }
                        break;
                    case 'folder':
                        if ($folderVisible && $r['folder_id'] !== null && isset($folderNames[(int) $r['folder_id']])) {
                            $hit = self::firstHit($folderNames[(int) $r['folder_id']], $terms);
                        }
                        break;
                    case 'owner':
                        $hit = self::firstHit($owners[(int) $r['owner_id']] ?? '', $terms);
                        break;
                    case 'content':
                    case 'ocr':
                        if (!empty($caps[$id]['preview']) && isset($windows[$id][$field])) {
                            $hit = $windows[$id][$field];
                        }
                        break;
                }
                if ($hit !== null) {
                    // The field covering the most query terms wins (ties: FIELDS order), so
                    // "invoice 2026" on scan-2026.png reports the OCR text, not the name.
                    [$text, $term] = $hit;
                    $excerpt = self::excerpt($text, $term);
                    $covered = 0;
                    foreach ($terms as $t) {
                        if (mb_stripos($excerpt, $t) !== false) {
                            $covered++;
                        }
                    }
                    if (!isset($out[$id]) || $covered > $out[$id]['covered']) {
                        $out[$id] = ['field' => $field, 'snippet' => self::highlight($excerpt, $terms), 'text' => $excerpt, 'covered' => $covered];
                    }
                    if ($covered >= count($terms)) {
                        break;
                    }
                }
            }
        }
        foreach ($out as $id => $m) {
            unset($out[$id]['covered']);
        }
        return $out;
    }

    /** @return array{0:string,1:string}|null [text, matching term] */
    private static function firstHit(string $text, array $terms): ?array
    {
        if ($text === '') {
            return null;
        }
        foreach ($terms as $t) {
            if (mb_stripos($text, $t) !== false) {
                return [$text, $t];
            }
        }
        return null;
    }

    /** A short single-line excerpt around the first occurrence of $term. */
    public static function excerpt(string $text, string $term): string
    {
        $text = trim((string) preg_replace('/\s+/u', ' ', (string) mb_scrub($text, 'UTF-8')));
        $pos = mb_stripos($text, $term);
        if ($pos === false) {
            return mb_strlen($text) > self::SNIPPET_BEFORE + self::SNIPPET_AFTER ? mb_substr($text, 0, self::SNIPPET_BEFORE + self::SNIPPET_AFTER) . '…' : $text;
        }
        $start = max(0, $pos - self::SNIPPET_BEFORE);
        $len = self::SNIPPET_BEFORE + mb_strlen($term) + self::SNIPPET_AFTER;
        $out = mb_substr($text, $start, $len);
        return ($start > 0 ? '…' : '') . $out . ($start + $len < mb_strlen($text) ? '…' : '');
    }

    /** HTML-escape $text and wrap every case-insensitive occurrence of a term in <mark>. */
    public static function highlight(string $text, array $terms): string
    {
        $esc = static fn (string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $terms = array_values(array_filter($terms, static fn ($t) => $t !== ''));
        if ($terms === []) {
            return $esc($text);
        }
        usort($terms, static fn ($a, $b) => mb_strlen($b) <=> mb_strlen($a));
        $pattern = '/(' . implode('|', array_map(static fn ($t) => preg_quote($t, '/'), $terms)) . ')/iu';
        $parts = @preg_split($pattern, $text, -1, PREG_SPLIT_DELIM_CAPTURE);
        if (!is_array($parts)) {
            return $esc($text);
        }
        $out = '';
        foreach ($parts as $i => $part) {
            $out .= $i % 2 === 1 ? '<mark>' . $esc($part) . '</mark>' : $esc($part);
        }
        return $out;
    }

    /** Validate a kind list against MimeDetector::KINDS. @return string[] */
    public static function kinds(array $kinds): array
    {
        $valid = class_exists(MimeDetector::class) ? MimeDetector::KINDS : ['image', 'video', 'audio', 'pdf', 'document', 'spreadsheet', 'presentation', 'code', 'text', 'archive', 'other'];
        foreach ($kinds as $k) {
            if (!in_array($k, $valid, true)) {
                throw ApiException::validation(['kind' => 'Choose one of: ' . implode(', ', $valid) . '.']);
            }
        }
        return array_values(array_unique($kinds));
    }

    /** Bind a value under a fresh placeholder (a named placeholder may appear only once per statement). */
    private static function bind(array &$params, mixed $value): string
    {
        $name = 'sq' . (count($params) + 1);
        $params[$name] = $value;
        return ':' . $name;
    }

    private static function bindList(array &$params, array $values): string
    {
        $values = array_values($values);
        if ($values === []) {
            return 'NULL';
        }
        $out = [];
        foreach ($values as $v) {
            $out[] = self::bind($params, $v);
        }
        return implode(',', $out);
    }
}
