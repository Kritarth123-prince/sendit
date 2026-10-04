<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Core\ApiException;
use FT\Http\Request;
use FT\Http\Response;
use FT\Notifications\WebPush;

/**
 * Web Push subscriptions (/api/v1/push/*). The browser subscribes with the VAPID public key from
 * GET /push/vapid-key and posts its PushSubscription here. Endpoints are restricted to the known
 * push services (SSRF protection, see WebPush::isAllowedEndpoint).
 */
final class PushController
{
    /** GET /push/vapid-key (auth optional) → {public_key|null} */
    public function vapidKey(Request $req): array
    {
        return ['public_key' => WebPush::publicKey()];
    }

    /** POST /push/subscribe {endpoint, keys:{p256dh, auth}} → 201 {id, device_id} */
    public function subscribe(Request $req): Response
    {
        $uid = $this->uid($req);
        if (!WebPush::enabled()) {
            throw ApiException::unavailable('Push notifications are not set up on this server.');
        }
        $sub = WebPush::validateSubscription($req->all());
        $res = WebPush::subscribe($uid, $sub, $req->clientId(), $req->userAgent());
        return Response::created(['id' => $res['id'], 'device_id' => $res['device_id'], 'subscribed' => true]);
    }

    /** DELETE /push/subscribe {endpoint} → 204 (idempotent; only the caller's own subscription) */
    public function unsubscribe(Request $req): Response
    {
        $uid = $this->uid($req);
        $endpoint = $req->input('endpoint');
        if (!is_string($endpoint) || trim($endpoint) === '' || strlen($endpoint) > 2048) {
            throw ApiException::validation(['endpoint' => 'The subscription endpoint is missing.']);
        }
        WebPush::unsubscribe($uid, trim($endpoint));
        return Response::noContent();
    }

    /** POST /push/test → {queued: n} */
    public function test(Request $req): array
    {
        return ['queued' => WebPush::sendTest($this->uid($req))];
    }

    private function uid(Request $req): int
    {
        if ($req->user === null) {
            throw ApiException::unauthorized();
        }
        return (int) $req->user['id'];
    }
}
