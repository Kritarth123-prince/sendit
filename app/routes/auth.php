<?php
declare(strict_types=1);

use FT\Controllers\Api\AuthController;
use FT\Controllers\Web\AuthPageController;
use FT\Http\Router;

// Owner: A1 — sign-in API and the sign-in / sign-out pages.
//
// /auth/login, /auth/2fa and /auth/password/* are CSRF-exempt by necessity (an API client has no
// session token yet); their controllers call Csrf::assertSameOrigin() instead (login CSRF) and
// apply their own rate limits (login, two_factor and password buckets) before doing any work.
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $public = ['auth' => 'none', 'csrf' => false, 'rate' => null];
        $r->post('/auth/login', [AuthController::class, 'login'], $public);
        $r->post('/auth/2fa', [AuthController::class, 'twoFactor'], $public);
        $r->post('/auth/password/forgot', [AuthController::class, 'forgotPassword'], $public);
        $r->post('/auth/password/reset', [AuthController::class, 'resetPassword'], $public);
        $r->post('/auth/logout', [AuthController::class, 'logout'], ['auth' => 'optional', 'rate' => null]);
        $r->get('/auth/csrf', [AuthController::class, 'csrf'], ['auth' => 'optional', 'rate' => null]);
    });

    // HTML pages. The forms carry their own CSRF token, checked inside the controller so an
    // expired form shows a friendly message instead of an error page.
    $page = ['auth' => 'none', 'csrf' => false, 'rate' => null, 'json' => false];
    $r->get('/login', [AuthPageController::class, 'show'], $page);
    $r->post('/login', [AuthPageController::class, 'submit'], $page);
    $r->get('/logout', [AuthPageController::class, 'logoutPage'], $page);
    $r->post('/logout', [AuthPageController::class, 'logout'], $page);
};
