<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\ApiException;
use FT\Http\Request;
use FT\Http\Response;
use FT\Notifications\NotificationService;
use FT\Notifications\Notifier;

/**
 * Notification centre (/api/v1/notifications/*). Every action is scoped to the signed-in user;
 * ids of other users' notifications are indistinguishable from missing ones (404).
 */
final class NotificationController
{
    /** GET /notifications?unread=1&category=&page=&per_page= → [Notification], meta {…, unread_count} */
    public function index(Request $req): Response
    {
        [$page, $per] = $req->pagination(50, 200);
        $category = $req->string('category', '', 32);
        if ($category !== '' && !Notifier::isCategory($category)) {
            throw ApiException::validation(['category' => 'Unknown notification category.']);
        }
        $res = NotificationService::list($this->uid($req), $req->bool('unread'), $page, $per, $category !== '' ? $category : null);
        return Response::paginated($res['items'], $res['total'], $page, $per, ['unread_count' => $res['unread_count']]);
    }

    /** GET /notifications/{id} */
    public function show(Request $req): array
    {
        return NotificationService::find($this->uid($req), $req->intParam('id'));
    }

    /** POST /notifications/{id}/read → Notification, meta {unread_count} */
    public function read(Request $req): Response
    {
        $uid = $this->uid($req);
        $n = NotificationService::markRead($uid, $req->intParam('id'));
        return Response::ok($n, ['unread_count' => NotificationService::unreadCount($uid)]);
    }

    /** POST /notifications/read-all → {updated, unread_count} */
    public function readAll(Request $req): array
    {
        $uid = $this->uid($req);
        $n = NotificationService::markAllRead($uid);
        return ['updated' => $n, 'unread_count' => NotificationService::unreadCount($uid)];
    }

    /** DELETE /notifications/{id} → 204 */
    public function destroy(Request $req): Response
    {
        NotificationService::delete($this->uid($req), $req->intParam('id'));
        return Response::noContent();
    }

    /** GET /notifications/preferences → [{category, label, in_app, push, email}] */
    public function preferences(Request $req): array
    {
        return NotificationService::preferences($this->uid($req));
    }

    /** PUT /notifications/preferences {preferences:[{category, in_app?, push?, email?}]} */
    public function updatePreferences(Request $req): array
    {
        $input = $req->input('preferences');
        if ($input === null) {
            $body = $req->all();
            $input = $body !== [] && !array_is_list($body) && isset($body['category']) ? [$body] : null;
        }
        return NotificationService::updatePreferences($this->uid($req), $input);
    }

    private function uid(Request $req): int
    {
        if ($req->user === null) {
            throw ApiException::unauthorized();
        }
        return (int) $req->user['id'];
    }
}
