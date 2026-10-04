<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Admin\StatsService;
use FT\Core\ApiException;
use FT\Http\Request;
use FT\Http\Response;

/**
 * Admin dashboard read APIs (docs/ARCHITECTURE.md §9.4 "Admin [A6]", §13.2). Routes require the
 * admin role plus the matching permission (app/routes/admin.php).
 */
final class AdminController
{
    /** GET /api/v1/admin/stats */
    public function stats(Request $req): array
    {
        return StatsService::counters();
    }

    /** GET /api/v1/admin/stats/charts?days=30 */
    public function charts(Request $req): array
    {
        return StatsService::charts($req->int('days', 30, 1, 365));
    }

    /** GET /api/v1/admin/storage?page=&per_page=&sort=used_bytes|username|created_at|quota_bytes&order=&q= */
    public function storage(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $sort = $req->string('sort', 'used_bytes', 20);
        $order = $req->string('order', 'desc', 4);
        $r = StatsService::storage($page, $per, $sort, $order, $req->string('q', '', 100));
        return Response::ok(
            ['users' => $r['users'], 'totals' => $r['totals'], 'capacity' => $r['capacity']],
            [
                'page'        => $page,
                'per_page'    => $per,
                'total'       => $r['total'],
                'total_pages' => (int) ceil($r['total'] / $per),
                'has_more'    => $page * $per < $r['total'],
            ]
        );
    }

    /** GET /api/v1/admin/activity?category=&action=&user_id=&owner_id=&target_type=&target_id=&q=&date_from=&date_to=&page= */
    public function activity(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $category = $req->string('category', '', 16);
        if ($category !== '' && !in_array($category, ['activity', 'security', 'admin', 'system'], true)) {
            throw ApiException::validation(['category' => 'Choose activity, security, admin or system.']);
        }
        $action = $req->string('action', '', 48);
        if ($action !== '' && !preg_match('/^[a-z0-9_.*]{1,48}$/', $action)) {
            throw ApiException::validation(['action' => 'Unknown action.']);
        }
        $targetType = $req->string('target_type', '', 16);
        if ($targetType !== '' && !preg_match('/^[a-z_]{1,16}$/', $targetType)) {
            throw ApiException::validation(['target_type' => 'Unknown target type.']);
        }
        $filters = [
            'category'    => $category,
            'action'      => $action,
            'user_id'     => $req->int('user_id', 0, 0),
            'owner_id'    => $req->int('owner_id', 0, 0),
            'target_type' => $targetType,
            'target_id'   => $req->int('target_id', 0, 0),
            'q'           => $req->string('q', '', 100),
            'date_from'   => self::date($req->string('date_from', '', 25), 'date_from', false),
            'date_to'     => self::date($req->string('date_to', '', 25), 'date_to', true),
        ];
        $r = StatsService::activity($filters, $page, $per);
        return Response::paginated($r['items'], $r['total'], $page, $per);
    }

    /** "YYYY-MM-DD" (or ISO date-time) → UTC DATETIME; date_to is exclusive of the next day. */
    public static function date(string $v, string $field, bool $endOfDay): ?string
    {
        if ($v === '') {
            return null;
        }
        if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $v)) {
            $ts = strtotime($v . ' 00:00:00 UTC');
            if ($ts === false) {
                throw ApiException::validation([$field => 'Use the format YYYY-MM-DD.']);
            }
            return gmdate('Y-m-d H:i:s', $endOfDay ? $ts + 86400 : $ts);
        }
        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2})?(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/', $v)) {
            $ts = strtotime($v);
            if ($ts !== false) {
                return gmdate('Y-m-d H:i:s', $ts);
            }
        }
        throw ApiException::validation([$field => 'Use the format YYYY-MM-DD.']);
    }
}
