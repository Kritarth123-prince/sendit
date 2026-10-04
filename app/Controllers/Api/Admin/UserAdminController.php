<?php
declare(strict_types=1);

namespace FT\Controllers\Api\Admin;

use FT\Core\ApiException;
use FT\Http\Request;
use FT\Http\Response;
use FT\Users\UserService;

/**
 * Admin user management (/api/v1/admin/users*, auth admin + permission admin.users — enforced
 * by the route group). Every id from the URL is re-loaded by UserService, which also enforces the
 * invariants (no self-delete/demote/disable, always one active administrator) and writes the
 * audit entries, events and notifications.
 */
final class UserAdminController
{
    /** GET /admin/users ?q=&status=active|disabled|suspended|locked&role=&sort=&order=&page=&per_page= */
    public function index(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $filters = [
            'q'      => $req->string('q', '', 100),
            'status' => $req->string('status', '', 16),
            'role'   => $req->string('role', '', 16),
            'sort'   => $req->string('sort', '', 32),
            'order'  => $req->string('order', '', 4),
        ];
        $result = UserService::adminList($filters, $page, $per);
        return Response::paginated($result['items'], $result['total'], $page, $per);
    }

    /** POST /admin/users {username, password?, email?, display_name?, role, quota_bytes?, must_change_password?} */
    public function store(Request $req): Response
    {
        $in = $req->all();
        $created = UserService::create($req->user, [
            'username'             => $in['username'] ?? null,
            'password'             => is_string($in['password'] ?? null) ? $in['password'] : null,
            'email'                => $in['email'] ?? null,
            'display_name'         => $in['display_name'] ?? null,
            'role'                 => $in['role'] ?? 'user',
            'must_change_password' => $in['must_change_password'] ?? false,
        ] + (array_key_exists('quota_bytes', $in) ? ['quota_bytes' => $in['quota_bytes']] : []));
        $out = ['user' => $created['user']];
        if ($created['temporary_password'] !== null) {
            $out['temporary_password'] = $created['temporary_password'];
        }
        return Response::created($out);
    }

    /** GET /admin/users/{id} → AdminUser + sessions + recent activity */
    public function show(Request $req): array
    {
        return UserService::detail(UserService::require($req->intParam('id')));
    }

    /** PATCH /admin/users/{id} {display_name?, email?, role?, quota_bytes? (null = role default, -1 = unlimited), must_change_password?, status?, reason?} */
    public function update(Request $req): array
    {
        $id = $req->intParam('id');
        $in = $req->all();
        $fields = array_intersect_key($in, ['display_name' => 1, 'email' => 1, 'role' => 1, 'quota_bytes' => 1, 'must_change_password' => 1]);
        $status = $in['status'] ?? null;
        if ($fields === [] && $status === null) {
            throw ApiException::validation(['user' => 'Nothing to update.']);
        }
        $result = $fields !== [] ? UserService::adminUpdate($req->user, $id, $fields) : UserService::detail(UserService::require($id));
        if ($status !== null) {
            if (!is_string($status)) {
                throw ApiException::validation(['status' => 'Status must be active, disabled or suspended.']);
            }
            $result = UserService::setStatus($req->user, $id, $status, $this->reason($req));
        }
        return $result;
    }

    /** DELETE /admin/users/{id} → 204 (soft delete, sessions/tokens/shares revoked, data purge queued) */
    public function destroy(Request $req): Response
    {
        UserService::delete($req->user, $req->intParam('id'));
        return Response::noContent();
    }

    /** POST /admin/users/{id}/disable {reason?} */
    public function disable(Request $req): array
    {
        return UserService::setStatus($req->user, $req->intParam('id'), 'disabled', $this->reason($req));
    }

    /** POST /admin/users/{id}/enable */
    public function enable(Request $req): array
    {
        return UserService::setStatus($req->user, $req->intParam('id'), 'active', null);
    }

    /** POST /admin/users/{id}/suspend {reason?} */
    public function suspend(Request $req): array
    {
        return UserService::setStatus($req->user, $req->intParam('id'), 'suspended', $this->reason($req));
    }

    /**
     * POST /admin/users/{id}/reset-password {password?}
     * → {temporary_password (shown once), must_change_password, sessions_revoked, tokens_revoked}
     */
    public function resetPassword(Request $req): array
    {
        $pw = $req->input('password');
        return UserService::resetPassword($req->user, $req->intParam('id'), is_string($pw) && $pw !== '' ? $pw : null);
    }

    /**
     * POST /admin/users/{id}/force-logout — every session and API token of the account.
     * → {revoked (= sessions_revoked, kept for older clients), sessions_revoked, tokens_revoked}
     */
    public function forceLogout(Request $req): array
    {
        $counts = UserService::forceLogout($req->user, $req->intParam('id'));
        return ['revoked' => $counts['sessions_revoked']] + $counts;
    }

    /** POST /admin/users/{id}/2fa/disable */
    public function disableTwoFactor(Request $req): array
    {
        $id = $req->intParam('id');
        UserService::require($id);
        return UserService::detail(UserService::disableTwoFactor($id, true));
    }

    /** GET /admin/users/{id}/activity ?page=&per_page= */
    public function activity(Request $req): Response
    {
        $id = $req->intParam('id');
        // Deleted accounts keep their history; only a user that never existed is "not found".
        if (\FT\Core\Db::value('SELECT id FROM users WHERE id = ?', [$id]) === null) {
            throw ApiException::notFound('user', 'USER_NOT_FOUND');
        }
        [$page, $per] = $req->pagination(50, 200);
        $result = UserService::activity($id, $page, $per);
        return Response::paginated($result['items'], $result['total'], $page, $per);
    }

    private function reason(Request $req): ?string
    {
        $r = $req->string('reason', '', 255);
        return $r === '' ? null : $r;
    }
}
