<?php
declare(strict_types=1);

use FT\Controllers\Api\UserController;
use FT\Http\Router;

// Owner: A1 — the signed-in user's own account (profile, password, two-factor) and the user
// lookup used by the share dialog.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/user', [UserController::class, 'show']);
        $r->patch('/user', [UserController::class, 'update']);
        $r->post('/user/password', [UserController::class, 'changePassword']);
        $r->post('/user/2fa/setup', [UserController::class, 'twoFactorSetup']);
        $r->post('/user/2fa/enable', [UserController::class, 'twoFactorEnable']);
        $r->post('/user/2fa/disable', [UserController::class, 'twoFactorDisable']);
        $r->post('/user/2fa/recovery-codes', [UserController::class, 'regenerateRecoveryCodes']);
        // Guests only see what is shared with them and cannot share, so they cannot list people.
        $r->get('/users/lookup', [UserController::class, 'lookup'], ['guest' => false]);
    });
};
