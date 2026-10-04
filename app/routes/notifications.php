<?php
declare(strict_types=1);

use FT\Controllers\Api\NotificationController;
use FT\Controllers\Api\PushController;
use FT\Http\Router;

// Owner: A5 (notification centre, preferences, Web Push — docs/ARCHITECTURE.md §9.4, §11).
return static function (Router $r): void {
    $r->group('/api/v1', static function (Router $r): void {
        $r->get('/notifications', [NotificationController::class, 'index']);
        $r->post('/notifications/read-all', [NotificationController::class, 'readAll']);
        $r->get('/notifications/preferences', [NotificationController::class, 'preferences']);
        $r->put('/notifications/preferences', [NotificationController::class, 'updatePreferences']);
        $r->get('/notifications/{id:\d+}', [NotificationController::class, 'show']);
        $r->post('/notifications/{id:\d+}/read', [NotificationController::class, 'read']);
        $r->delete('/notifications/{id:\d+}', [NotificationController::class, 'destroy']);

        $r->get('/push/vapid-key', [PushController::class, 'vapidKey'], ['auth' => 'optional']);
        $r->post('/push/subscribe', [PushController::class, 'subscribe']);
        $r->delete('/push/subscribe', [PushController::class, 'unsubscribe']);
        $r->post('/push/test', [PushController::class, 'test']);
    });
};
