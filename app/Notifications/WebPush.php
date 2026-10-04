<?php
declare(strict_types=1);

namespace FT\Notifications;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Events\EventBus;
use FT\Jobs\Queue;
use FT\Storage\Paths;
use FT\Support\Capabilities;

/**
 * Web Push without third-party libraries, GMP or sodium (shared hosts rarely have them):
 *
 *  - RFC 8291 message encryption, "aes128gcm" content coding (RFC 8188): ECDH P-256 with
 *    openssl_pkey_derive, HKDF-SHA-256 with hash_hkdf, AES-128-GCM with openssl_encrypt,
 *    a single record of rs = 4096 with the 0x02 last-record padding delimiter.
 *  - RFC 8292 VAPID: an ES256 JWT signed with openssl_sign; OpenSSL returns a DER
 *    ECDSA-Sig-Value, which JWS requires as the raw 64-byte R||S.
 *
 * Keys (.env): VAPID_PUBLIC_KEY = base64url of the 65-byte uncompressed point (0x04||X||Y),
 * VAPID_PRIVATE_KEY = base64url of the 32-byte private scalar, VAPID_SUBJECT = mailto:/https:.
 *
 * SSRF: the push endpoint is chosen by the browser, i.e. by the client. Only HTTPS endpoints on
 * the known push services are accepted — when subscribing and again right before sending — and
 * the HTTP call never follows redirects.
 */
final class WebPush
{
    public const RECORD_SIZE = 4096;
    public const MAX_PAYLOAD_BYTES = 3072;
    public const DEFAULT_TTL = 86400;

    /** Exact push-service hosts. */
    public const ALLOWED_HOSTS = ['fcm.googleapis.com', 'updates.push.services.mozilla.com', 'web.push.apple.com'];
    /** Push-service host suffixes ("*.push.apple.com"). */
    public const ALLOWED_SUFFIXES = ['.push.services.mozilla.com', '.notify.windows.com', '.push.apple.com'];

    private const MAX_SUBSCRIPTIONS_PER_USER = 20;
    private const MAX_FAILURES = 15;
    private const JWT_LIFETIME = 43200; // 12 h (RFC 8292 allows at most 24 h)

    /** DER prefix of a P-256 SubjectPublicKeyInfo, followed by the 65-byte point. */
    private const SPKI_PREFIX = '3059301306072a8648ce3d020106082a8648ce3d030107034200';

    // ------------------------------------------------------------------ configuration

    /** True when VAPID keys are configured and valid and the OpenSSL EC primitives exist. */
    public static function enabled(): bool
    {
        return self::keys() !== null && Capabilities::hasEcCrypto() && function_exists('hash_hkdf');
    }

    /** The VAPID public key (base64url) the browser needs to subscribe, or null when push is off. */
    public static function publicKey(): ?string
    {
        $k = self::keys();
        return $k !== null && Capabilities::hasEcCrypto() ? self::b64uEncode($k['public']) : null;
    }

    /**
     * A fresh VAPID key pair for the installer / admin screen (shown once, pasted into .env).
     * @return array{public_key:string,private_key:string} base64url (65-byte point, 32-byte scalar)
     */
    public static function generateVapidKeys(): array
    {
        [$d, $pub] = self::newKeyPair();
        return ['public_key' => self::b64uEncode($pub), 'private_key' => self::b64uEncode($d)];
    }

    /**
     * Is this a push endpoint we are willing to POST to? HTTPS, default port, no credentials,
     * and a host that is (or ends with) one of the known push services. Rejects look-alikes such
     * as "fcm.googleapis.com.evil.example" and "evilpush.apple.com".
     */
    public static function isAllowedEndpoint(string $endpoint): bool
    {
        if ($endpoint === '' || strlen($endpoint) > 2048 || preg_match('/[\x00-\x20\x7F]/', $endpoint)) {
            return false;
        }
        $p = parse_url($endpoint);
        if (!is_array($p) || strtolower($p['scheme'] ?? '') !== 'https' || empty($p['host'])) {
            return false;
        }
        if (isset($p['user']) || isset($p['pass']) || (isset($p['port']) && (int) $p['port'] !== 443)) {
            return false;
        }
        $host = strtolower((string) $p['host']);
        if (filter_var(trim($host, '[]'), FILTER_VALIDATE_IP) || !preg_match('/^[a-z0-9.-]+$/', $host)) {
            return false;
        }
        if (in_array($host, self::ALLOWED_HOSTS, true)) {
            return true;
        }
        foreach (self::ALLOWED_SUFFIXES as $suffix) {
            if (str_ends_with($host, $suffix) && strlen($host) > strlen($suffix)) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ subscriptions

    /**
     * Validate a PushSubscription JSON ({endpoint, keys:{p256dh, auth}}).
     * @param array<string,mixed> $input
     * @return array{endpoint:string,p256dh:string,auth:string} normalised (keys base64url without padding)
     */
    public static function validateSubscription(array $input): array
    {
        if (isset($input['subscription']) && is_array($input['subscription'])) {
            $input = $input['subscription']; // legacy client wrapper
        }
        $endpoint = is_string($input['endpoint'] ?? null) ? trim($input['endpoint']) : '';
        $keys = is_array($input['keys'] ?? null) ? $input['keys'] : [];
        $p256 = is_string($keys['p256dh'] ?? null) ? trim($keys['p256dh']) : '';
        $auth = is_string($keys['auth'] ?? null) ? trim($keys['auth']) : '';
        $errors = [];
        if ($endpoint === '') {
            $errors['endpoint'] = 'The subscription endpoint is missing.';
        } elseif (!self::isAllowedEndpoint($endpoint)) {
            $errors['endpoint'] = 'This push service is not supported.';
        }
        $rawP256 = self::b64uDecode($p256);
        if ($rawP256 === null || strlen($rawP256) !== 65 || $rawP256[0] !== "\x04" || !self::isValidPoint($rawP256)) {
            $errors['keys.p256dh'] = 'The subscription public key is invalid.';
        }
        $rawAuth = self::b64uDecode($auth);
        if ($rawAuth === null || strlen($rawAuth) !== 16) {
            $errors['keys.auth'] = 'The subscription auth secret is invalid.';
        }
        if ($errors !== []) {
            throw ApiException::validation($errors, 'This push subscription is not valid.');
        }
        return ['endpoint' => $endpoint, 'p256dh' => self::b64uEncode((string) $rawP256), 'auth' => self::b64uEncode((string) $rawAuth)];
    }

    /**
     * Store (or move to this user) a validated subscription, linked to the user's device when the
     * browser sent X-Client-Id. Keeps at most MAX_SUBSCRIPTIONS_PER_USER per user.
     * @param array{endpoint:string,p256dh:string,auth:string} $sub
     * @return array{id:int,device_id:?int}
     */
    public static function subscribe(int $userId, array $sub, ?string $clientId, ?string $userAgent): array
    {
        $deviceId = null;
        if ($clientId !== null && $clientId !== '') {
            $d = Db::value('SELECT id FROM user_devices WHERE user_id = ? AND client_hash = ?', [$userId, hash('sha256', $clientId)]);
            $deviceId = $d !== null ? (int) $d : null;
        }
        $hash = hash('sha256', $sub['endpoint']);
        $id = Db::transaction(static function () use ($userId, $sub, $hash, $deviceId, $userAgent): int {
            Db::run(
                'INSERT INTO push_subscriptions (user_id, endpoint, endpoint_hash, p256dh, auth_secret, device_id, user_agent, created_at, failure_count)
                 VALUES (:u, :ep, :h, :p, :a, :d, :ua, :t, 0)
                 ON DUPLICATE KEY UPDATE user_id = VALUES(user_id), endpoint = VALUES(endpoint), p256dh = VALUES(p256dh),
                    auth_secret = VALUES(auth_secret), device_id = VALUES(device_id), user_agent = VALUES(user_agent), failure_count = 0',
                ['u' => $userId, 'ep' => $sub['endpoint'], 'h' => $hash, 'p' => $sub['p256dh'], 'a' => $sub['auth'],
                 'd' => $deviceId, 'ua' => $userAgent !== null ? mb_substr($userAgent, 0, 255) : null, 't' => Db::now()]
            );
            $id = (int) Db::value('SELECT id FROM push_subscriptions WHERE endpoint_hash = ?', [$hash]);
            $ids = array_map('intval', Db::column('SELECT id FROM push_subscriptions WHERE user_id = ? ORDER BY id DESC', [$userId]));
            $stale = array_slice($ids, self::MAX_SUBSCRIPTIONS_PER_USER);
            if ($stale !== []) {
                [$in, $p] = Db::inList($stale, 'st');
                Db::run("DELETE FROM push_subscriptions WHERE id IN {$in}", $p);
            }
            return $id;
        });
        Audit::log('push.subscribe', [
            'user_id' => $userId, 'category' => 'security', 'target_type' => 'user', 'target_id' => $userId, 'owner_id' => $userId,
            'meta' => ['subscription_id' => $id, 'device_id' => $deviceId, 'service' => self::host($sub['endpoint'])],
        ]);
        self::publishDevicesChanged($userId);
        return ['id' => $id, 'device_id' => $deviceId];
    }

    /** Remove this user's subscription for an endpoint. Returns true when one was removed. */
    public static function unsubscribe(int $userId, string $endpoint): bool
    {
        $n = Db::run('DELETE FROM push_subscriptions WHERE endpoint_hash = ? AND user_id = ?', [hash('sha256', $endpoint), $userId])->rowCount();
        if ($n > 0) {
            Audit::log('push.unsubscribe', [
                'user_id' => $userId, 'category' => 'security', 'target_type' => 'user', 'target_id' => $userId, 'owner_id' => $userId,
                'meta' => ['service' => self::host($endpoint)],
            ]);
            self::publishDevicesChanged($userId);
        }
        return $n > 0;
    }

    /**
     * Queue one delivery job per subscription of the user. The message is stored in the job so a
     * later edit/deletion of the notification does not matter.
     * @param array{title:string,body:string,url:string,tag:string,notification_id:?int} $message
     */
    public static function queueForUser(int $userId, array $message, string $urgency = 'normal', int $ttl = self::DEFAULT_TTL): int
    {
        if (!self::enabled()) {
            return 0;
        }
        $ids = Db::column('SELECT id FROM push_subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT ' . self::MAX_SUBSCRIPTIONS_PER_USER, [$userId]);
        foreach ($ids as $sid) {
            Queue::push(self::class . '::deliverJob', [
                'subscription_id' => (int) $sid,
                'message'         => $message,
                'urgency'         => in_array($urgency, ['very-low', 'low', 'normal', 'high'], true) ? $urgency : 'normal',
                'ttl'             => max(0, min(2419200, $ttl)),
            ]);
        }
        return count($ids);
    }

    /** "Send a test notification" button: queues a test push to each of the user's devices. */
    public static function sendTest(int $userId): int
    {
        if (!self::enabled()) {
            throw ApiException::unavailable('Push notifications are not set up on this server.');
        }
        $count = (int) Db::value('SELECT COUNT(*) FROM push_subscriptions WHERE user_id = ?', [$userId]);
        if ($count === 0) {
            throw ApiException::validation(['subscription' => 'Turn on push notifications on this device first.'], 'No device is subscribed to push notifications.');
        }
        $site = Notifier::siteName();
        $queued = self::queueForUser($userId, [
            'title'           => "{$site} test notification",
            'body'            => 'Push notifications are working. You will get alerts like this for the categories you choose in Settings.',
            'url'             => Notifier::linkUrl('#/settings'),
            'tag'             => 'ft-test',
            'notification_id' => null,
        ], 'normal', 3600);
        Audit::log('push.test', [
            'user_id' => $userId, 'category' => 'security', 'target_type' => 'user', 'target_id' => $userId, 'owner_id' => $userId,
            'meta' => ['devices' => $queued],
        ]);
        return $queued;
    }

    /**
     * Queue handler: deliver one message to one subscription. 2xx ⇒ last_success_at; 404/410 ⇒
     * the subscription is gone and is removed; anything else ⇒ failure_count + 1 (removed after
     * MAX_FAILURES), and throttling/server/network errors are rethrown so the queue retries.
     * @param array<string,mixed> $payload {subscription_id, message, urgency?, ttl?}
     */
    public static function deliverJob(array $payload): void
    {
        $id = (int) ($payload['subscription_id'] ?? 0);
        if ($id <= 0) {
            return;
        }
        if (!self::enabled()) {
            Logger::info('push', 'Push delivery skipped: VAPID keys are not configured');
            return;
        }
        $sub = Db::one(
            'SELECT s.*, u.status AS user_status, u.deleted_at AS user_deleted_at
             FROM push_subscriptions s JOIN users u ON u.id = s.user_id WHERE s.id = ?',
            [$id]
        );
        if ($sub === null || (string) $sub['user_status'] !== 'active' || $sub['user_deleted_at'] !== null) {
            return;
        }
        if (!self::isAllowedEndpoint((string) $sub['endpoint'])) {
            Db::delete('push_subscriptions', ['id' => $id]);
            Logger::security('Removed a push subscription with a disallowed endpoint', ['subscription_id' => $id]);
            return;
        }
        $message = is_array($payload['message'] ?? null) ? $payload['message'] : [];
        $urgency = is_string($payload['urgency'] ?? null) ? $payload['urgency'] : 'normal';
        $ttl = isset($payload['ttl']) ? (int) $payload['ttl'] : self::DEFAULT_TTL;

        $res = self::send($sub, $message, $urgency, $ttl);
        $status = $res['status'];
        $host = self::host((string) $sub['endpoint']);
        if ($status >= 200 && $status < 300) {
            Db::update('push_subscriptions', ['last_success_at' => Db::now(), 'failure_count' => 0], ['id' => $id]);
            return;
        }
        if ($status === 404 || $status === 410) {
            Db::delete('push_subscriptions', ['id' => $id]);
            Logger::info('push', 'Push subscription expired and was removed', ['subscription_id' => $id, 'status' => $status, 'service' => $host]);
            return;
        }
        Db::run('UPDATE push_subscriptions SET failure_count = failure_count + 1 WHERE id = ?', [$id]);
        $failures = (int) Db::value('SELECT failure_count FROM push_subscriptions WHERE id = ?', [$id]);
        if ($failures >= self::MAX_FAILURES) {
            Db::delete('push_subscriptions', ['id' => $id]);
            Logger::warning('push', 'Push subscription removed after repeated failures', ['subscription_id' => $id, 'service' => $host]);
            return;
        }
        Logger::warning('push', 'Push delivery failed', ['subscription_id' => $id, 'status' => $status, 'service' => $host, 'error' => $res['error']]);
        if ($status === 0 || $status === 429 || $status >= 500) {
            throw new \RuntimeException('Push service unavailable (HTTP ' . $status . ')'); // let the queue retry
        }
    }

    /**
     * Encrypt and POST one message. Does not touch the database.
     * @param array<string,mixed> $sub push_subscriptions row
     * @param array<string,mixed> $message
     * @return array{status:int,body:string,error:?string}
     */
    public static function send(array $sub, array $message, string $urgency = 'normal', int $ttl = self::DEFAULT_TTL): array
    {
        $endpoint = (string) $sub['endpoint'];
        if (!self::isAllowedEndpoint($endpoint)) {
            return ['status' => 0, 'body' => '', 'error' => 'Endpoint not allowed'];
        }
        $ua = self::b64uDecode((string) $sub['p256dh']);
        $auth = self::b64uDecode((string) $sub['auth_secret']);
        if ($ua === null || strlen($ua) !== 65 || $auth === null || strlen($auth) !== 16) {
            return ['status' => 410, 'body' => '', 'error' => 'Stored subscription keys are invalid'];
        }
        $body = self::encrypt(self::payload($message), $ua, $auth);
        $headers = [
            'TTL: ' . max(0, $ttl),
            'Urgency: ' . (in_array($urgency, ['very-low', 'low', 'normal', 'high'], true) ? $urgency : 'normal'),
            'Content-Type: application/octet-stream',
            'Content-Encoding: aes128gcm',
            'Authorization: ' . self::vapidAuthorization($endpoint),
        ];
        return Notifier::httpPost($endpoint, $body, $headers, 'push');
    }

    /**
     * The push message JSON (≤ 3 KB): {title, body, url, tag, notification_id}. The service
     * worker shows it without contacting the server, so it must be self-contained — and it must
     * never carry secrets.
     * @param array<string,mixed> $message
     */
    public static function payload(array $message): string
    {
        $data = [
            'title'           => mb_substr((string) ($message['title'] ?? Notifier::siteName()), 0, 200),
            'body'            => mb_substr((string) ($message['body'] ?? ''), 0, 1000),
            'url'             => mb_substr((string) ($message['url'] ?? './'), 0, 500),
            'tag'             => mb_substr((string) ($message['tag'] ?? 'ft'), 0, 64),
            'notification_id' => isset($message['notification_id']) ? (int) $message['notification_id'] : null,
        ];
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE;
        $json = (string) json_encode($data, $flags);
        while (strlen($json) > self::MAX_PAYLOAD_BYTES && $data['body'] !== '') {
            $data['body'] = mb_substr($data['body'], 0, max(0, mb_strlen($data['body']) - 100)) . '…';
            if (mb_strlen($data['body']) <= 1) {
                $data['body'] = '';
            }
            $json = (string) json_encode($data, $flags);
        }
        return $json;
    }

    // ------------------------------------------------------------------ RFC 8291 encryption

    /**
     * Encrypt a push message for one subscription (RFC 8291 / RFC 8188 aes128gcm, one record).
     * $asPrivate/$asPublic/$salt are injectable for deterministic tests (RFC 8291 Appendix A);
     * normally a fresh ephemeral key pair and salt are generated for every message.
     *
     * @param string $uaPublic raw 65-byte subscription key (p256dh)
     * @param string $authSecret raw 16-byte auth secret
     * @return string binary request body: salt(16) | rs(4) | idlen(1) | keyid(65) | ciphertext
     */
    public static function encrypt(string $plaintext, string $uaPublic, string $authSecret, ?string $asPrivate = null, ?string $asPublic = null, ?string $salt = null): string
    {
        if (strlen($uaPublic) !== 65 || $uaPublic[0] !== "\x04" || strlen($authSecret) !== 16) {
            throw new \InvalidArgumentException('Invalid subscription keys');
        }
        if (strlen($plaintext) > self::RECORD_SIZE - 17) {
            throw new \InvalidArgumentException('Push payload too large');
        }
        if ($asPrivate === null || $asPublic === null) {
            [$asPrivate, $asPublic] = self::newKeyPair();
        }
        $salt ??= random_bytes(16);
        if (strlen($salt) !== 16 || strlen($asPrivate) !== 32 || strlen($asPublic) !== 65) {
            throw new \InvalidArgumentException('Invalid server key material');
        }
        $key = openssl_pkey_get_private(self::privateKeyPem($asPrivate, $asPublic));
        if ($key === false) {
            self::drainOpensslErrors();
            throw new \RuntimeException('Invalid application server key');
        }
        $ecdh = openssl_pkey_derive(self::publicKeyPem($uaPublic), $key, 32);
        self::drainOpensslErrors();
        if ($ecdh === false || strlen($ecdh) !== 32) {
            throw new \RuntimeException('ECDH key agreement failed');
        }
        // IKM = HKDF(salt = auth_secret, ikm = ecdh_secret, info = "WebPush: info" 0x00 ua_public as_public, L = 32)
        $ikm = hash_hkdf('sha256', $ecdh, 32, "WebPush: info\0" . $uaPublic . $asPublic, $authSecret);
        $cek = hash_hkdf('sha256', $ikm, 16, "Content-Encoding: aes128gcm\0", $salt);
        $nonce = hash_hkdf('sha256', $ikm, 12, "Content-Encoding: nonce\0", $salt);
        $tag = '';
        $ct = openssl_encrypt($plaintext . "\x02", 'aes-128-gcm', $cek, OPENSSL_RAW_DATA, $nonce, $tag, '', 16);
        if ($ct === false) {
            throw new \RuntimeException('AES-GCM encryption failed');
        }
        return $salt . pack('N', self::RECORD_SIZE) . chr(65) . $asPublic . $ct . $tag;
    }

    // ------------------------------------------------------------------ RFC 8292 VAPID

    /** Authorization header value: "vapid t=<jwt>, k=<public key>". */
    public static function vapidAuthorization(string $endpoint, ?int $now = null): string
    {
        $keys = self::keys();
        if ($keys === null) {
            throw new \RuntimeException('VAPID keys are not configured');
        }
        $p = parse_url($endpoint);
        $aud = 'https://' . strtolower((string) ($p['host'] ?? '')) . (isset($p['port']) && (int) $p['port'] !== 443 ? ':' . (int) $p['port'] : '');
        $jwt = self::vapidJwt($aud, ($now ?? time()) + self::JWT_LIFETIME, $keys);
        return 'vapid t=' . $jwt . ', k=' . self::b64uEncode($keys['public']);
    }

    /**
     * ES256-signed JWT {aud, exp, sub}.
     * @param array{public:string,private:string}|null $keys raw keys (default: configured ones)
     */
    public static function vapidJwt(string $audience, int $expires, ?array $keys = null): string
    {
        $keys ??= self::keys();
        if ($keys === null) {
            throw new \RuntimeException('VAPID keys are not configured');
        }
        $subject = (string) Config::get('vapid.subject', '');
        if (!preg_match('~^(mailto:[^\s@]+@[^\s@]+|https://\S+)$~i', $subject)) {
            $subject = 'mailto:admin@example.com';
        }
        $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
        $input = self::b64uEncode((string) json_encode(['typ' => 'JWT', 'alg' => 'ES256'], $flags)) . '.'
            . self::b64uEncode((string) json_encode(['aud' => $audience, 'exp' => $expires, 'sub' => $subject], $flags));
        $key = openssl_pkey_get_private(self::privateKeyPem($keys['private'], $keys['public']));
        if ($key === false || !openssl_sign($input, $der, $key, OPENSSL_ALGO_SHA256)) {
            self::drainOpensslErrors();
            throw new \RuntimeException('Could not sign the VAPID token');
        }
        return $input . '.' . self::b64uEncode(self::derToRaw($der));
    }

    /** DER ECDSA-Sig-Value (SEQUENCE {INTEGER r, INTEGER s}) → raw 64-byte R||S. */
    public static function derToRaw(string $der): string
    {
        $pos = 0;
        $len = strlen($der);
        $readLen = static function () use ($der, &$pos, $len): int {
            if ($pos >= $len) {
                throw new \InvalidArgumentException('Truncated DER');
            }
            $l = ord($der[$pos++]);
            if ($l < 0x80) {
                return $l;
            }
            $n = $l & 0x7F;
            if ($n < 1 || $n > 2 || $pos + $n > $len) {
                throw new \InvalidArgumentException('Bad DER length');
            }
            $v = 0;
            for ($i = 0; $i < $n; $i++) {
                $v = ($v << 8) | ord($der[$pos++]);
            }
            return $v;
        };
        if ($len < 8 || $der[$pos++] !== "\x30") {
            throw new \InvalidArgumentException('Not a DER sequence');
        }
        $readLen();
        $out = '';
        for ($i = 0; $i < 2; $i++) {
            if ($pos >= $len || $der[$pos++] !== "\x02") {
                throw new \InvalidArgumentException('Expected a DER integer');
            }
            $l = $readLen();
            $int = substr($der, $pos, $l);
            $pos += $l;
            $int = ltrim($int, "\x00");
            if (strlen($int) > 32) {
                throw new \InvalidArgumentException('Integer too large for P-256');
            }
            $out .= str_pad($int, 32, "\x00", STR_PAD_LEFT);
        }
        return $out;
    }

    /** Raw 64-byte R||S → DER ECDSA-Sig-Value (for verification with openssl_verify). */
    public static function rawToDer(string $raw): string
    {
        if (strlen($raw) !== 64) {
            throw new \InvalidArgumentException('Raw signature must be 64 bytes');
        }
        $ints = '';
        foreach ([substr($raw, 0, 32), substr($raw, 32)] as $part) {
            $part = ltrim($part, "\x00");
            if ($part === '' || (ord($part[0]) & 0x80)) {
                $part = "\x00" . $part;
            }
            $ints .= "\x02" . chr(strlen($part)) . $part;
        }
        return "\x30" . chr(strlen($ints)) . $ints;
    }

    // ------------------------------------------------------------------ key helpers

    /** PEM SubjectPublicKeyInfo for a raw 65-byte P-256 point. */
    public static function publicKeyPem(string $point): string
    {
        $der = (string) hex2bin(self::SPKI_PREFIX) . $point;
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    /**
     * PEM "EC PRIVATE KEY" (RFC 5915 ECPrivateKey) built from the raw scalar and its public point:
     * SEQUENCE { INTEGER 1, OCTET STRING d, [0] OID prime256v1, [1] BIT STRING 0x00||point }.
     */
    public static function privateKeyPem(string $d, string $point): string
    {
        if (strlen($d) !== 32 || strlen($point) !== 65) {
            throw new \InvalidArgumentException('Invalid EC key material');
        }
        $der = "\x30\x77\x02\x01\x01\x04\x20" . $d
            . "\xa0\x0a\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
            . "\xa1\x44\x03\x42\x00" . $point;
        return "-----BEGIN EC PRIVATE KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END EC PRIVATE KEY-----\n";
    }

    public static function b64uEncode(string $bin): string
    {
        return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
    }

    public static function b64uDecode(string $s): ?string
    {
        $s = trim($s);
        if ($s === '' || !preg_match('/^[A-Za-z0-9_\-+\/]+={0,2}$/', $s)) {
            return null;
        }
        $s = rtrim(strtr($s, '-_', '+/'), '=');
        $bin = base64_decode($s . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
        return $bin === false ? null : $bin;
    }

    /**
     * Configured raw VAPID keys, or null when missing or malformed.
     * @return array{public:string,private:string}|null
     */
    private static function keys(): ?array
    {
        $pub = self::b64uDecode((string) Config::get('vapid.public', ''));
        $priv = self::b64uDecode((string) Config::get('vapid.private', ''));
        if ($pub === null || $priv === null || strlen($pub) !== 65 || $pub[0] !== "\x04" || strlen($priv) !== 32) {
            return null;
        }
        return ['public' => $pub, 'private' => $priv];
    }

    /** @return array{0:string,1:string} [raw 32-byte private scalar, raw 65-byte public point] */
    private static function newKeyPair(): array
    {
        $opts = ['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1'];
        $key = @openssl_pkey_new($opts);
        if ($key === false) {
            // Windows/XAMPP builds often lack a readable openssl.cnf; an empty one is enough.
            $cfg = self::opensslConfigFile();
            if ($cfg !== null) {
                $key = @openssl_pkey_new($opts + ['config' => $cfg, 'private_key_bits' => 2048]);
            }
        }
        self::drainOpensslErrors();
        if ($key === false) {
            throw new \RuntimeException('Could not create an EC key pair (OpenSSL).');
        }
        $details = openssl_pkey_get_details($key);
        $ec = is_array($details) ? ($details['ec'] ?? null) : null;
        if (!is_array($ec) || !isset($ec['d'], $ec['x'], $ec['y'])) {
            throw new \RuntimeException('Could not read the EC key pair.');
        }
        $pad = static fn (string $v): string => str_pad($v, 32, "\x00", STR_PAD_LEFT);
        return [$pad($ec['d']), "\x04" . $pad($ec['x']) . $pad($ec['y'])];
    }

    private static function opensslConfigFile(): ?string
    {
        $env = getenv('OPENSSL_CONF');
        if (is_string($env) && $env !== '' && is_file($env)) {
            return $env;
        }
        try {
            $file = Paths::runtime('ssl') . '/openssl.cnf';
            if (!is_file($file)) {
                @file_put_contents($file, "# Minimal OpenSSL configuration used for EC key generation.\n");
            }
            return is_file($file) ? $file : null;
        } catch (\Throwable) {
            return null;
        }
    }

    private static function isValidPoint(string $point): bool
    {
        if (!function_exists('openssl_pkey_get_public')) {
            return false;
        }
        $k = @openssl_pkey_get_public(self::publicKeyPem($point));
        self::drainOpensslErrors();
        return $k !== false;
    }

    private static function drainOpensslErrors(): void
    {
        for ($i = 0; $i < 50 && openssl_error_string() !== false; $i++) {
            // OpenSSL keeps an error queue per process; stale entries would confuse later calls.
        }
    }

    private static function host(string $endpoint): string
    {
        return strtolower((string) parse_url($endpoint, PHP_URL_HOST));
    }

    private static function publishDevicesChanged(int $userId): void
    {
        $u = Db::one('SELECT id, username, display_name, status FROM users WHERE id = ?', [$userId]);
        if ($u === null) {
            return;
        }
        EventBus::publish('user.updated', [
            'user' => [
                'id' => (int) $u['id'], 'username' => (string) $u['username'],
                'display_name' => (string) (($u['display_name'] ?? '') !== '' ? $u['display_name'] : $u['username']),
                'status' => (string) $u['status'],
            ],
            'changes' => ['push_subscriptions'],
        ], [$userId]);
    }
}
