<?php
declare(strict_types=1);

use FT\Controllers\Api\Admin\UserAdminController;
use FT\Http\Router;

// Owner: A1 — administrator user management (role admin + permission admin.users).
return static function (Router $r): void {
    $r->group('/api/v1/admin/users', static function (Router $r): void {
        $r->get('', [UserAdminController::class, 'index']);
        $r->post('', [UserAdminController::class, 'store']);
        $r->get('/{id:\d+}', [UserAdminController::class, 'show']);
        $r->patch('/{id:\d+}', [UserAdminController::class, 'update']);
        $r->delete('/{id:\d+}', [UserAdminController::class, 'destroy']);
        $r->post('/{id:\d+}/disable', [UserAdminController::class, 'disable']);
        $r->post('/{id:\d+}/enable', [UserAdminController::class, 'enable']);
        $r->post('/{id:\d+}/suspend', [UserAdminController::class, 'suspend']);
        $r->post('/{id:\d+}/reset-password', [UserAdminController::class, 'resetPassword']);
        $r->post('/{id:\d+}/force-logout', [UserAdminController::class, 'forceLogout']);
        $r->post('/{id:\d+}/2fa/disable', [UserAdminController::class, 'disableTwoFactor']);
        $r->get('/{id:\d+}/activity', [UserAdminController::class, 'activity']);
    }, ['auth' => 'admin', 'perm' => 'admin.users']);
};
