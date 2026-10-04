<?php
declare(strict_types=1);

use FT\Controllers\Api\AdminController;
use FT\Controllers\Api\AdminSystemController;
use FT\Http\Router;

// Owner: A6 — admin dashboard, storage, activity and system APIs (docs/ARCHITECTURE.md §9.4).
// Every route needs the admin role; each group additionally checks its permission slug.
// (/admin/users is A1's, /admin/trash A3's and /admin/shares A4's — registered in their files.)
return static function (Router $r): void {
    $r->group('/api/v1/admin', static function (Router $r): void {
        $r->get('/stats', [AdminController::class, 'stats'], ['perm' => 'admin.access']);
        $r->get('/stats/charts', [AdminController::class, 'charts'], ['perm' => 'admin.access']);
        $r->get('/storage', [AdminController::class, 'storage'], ['perm' => 'admin.storage']);
        $r->get('/activity', [AdminController::class, 'activity'], ['perm' => 'admin.activity']);

        $r->group('', static function (Router $r): void {
            $r->get('/system', [AdminSystemController::class, 'system']);
            $r->get('/settings', [AdminSystemController::class, 'settings']);
            $r->put('/settings', [AdminSystemController::class, 'updateSettings']);
            $r->patch('/settings', [AdminSystemController::class, 'updateSettings']);
            $r->post('/maintenance/run', [AdminSystemController::class, 'runMaintenance']);
            $r->get('/maintenance/logs', [AdminSystemController::class, 'maintenanceLogs']);
            $r->post('/migrations/run', [AdminSystemController::class, 'runMigrations']);
            $r->post('/legacy-import', [AdminSystemController::class, 'legacyImport']);
            $r->get('/encryption', [AdminSystemController::class, 'encryptionStatus']);
            $r->post('/encryption/migrate', [AdminSystemController::class, 'encryptionMigrate']);
            $r->post('/jobs/retry', [AdminSystemController::class, 'retryJobs']);
            $r->post('/vapid/generate', [AdminSystemController::class, 'vapid']);
            $r->post('/slack/test', [AdminSystemController::class, 'slackTest']);
        }, ['perm' => 'admin.system']);
    }, ['auth' => 'admin']);
};
