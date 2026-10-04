<?php
declare(strict_types=1);

namespace FT\Events;

use FT\Auth\Auth;
use FT\Core\ApiException;
use FT\Core\Config;
use FT\Core\Db;
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\RateLimiter;
use FT\Storage\Paths;
use FT\Support\Capabilities;

/**
 * Real-time transport endpoints (docs/ARCHITECTURE.md §10.3).
 *
 *   GET /api/v1/events          recovery after (re)connect: events after ?after=N, meta {last_id, reset, has_more}
 *   GET /api/v1/events/stream   Server-Sent Events (only where Capabilities::canHold(); else 503)
 *   GET /api/v1/events/poll     long-poll (?wait=1..25, only where the host can hold) or short poll (wait=0)
 *
 * The short poll is the hot path on hosts like byethost (no held connections, 50k hits/day,
 * 4 MySQL connections): it is registered with auth "none" and no DB rate limiter, reads the user
 * id from the PHP session with read_and_close (no session lock held) and compares the cheap
 * per-user signal file (RealtimeSignal) with ?after. When nothing changed it answers 204 without
 * ever opening a database connection. Only when something did change does it run the full
 * Auth::resolve() (session row, account status) and query EventBus::since(). A file guard
 * (≥ 1 s between short polls) replaces the database rate limiter on that path. It is keyed on
 * the server-side session row id found in the session (never on a client-chosen cookie or bearer
 * value), else on the client IP; a request without such a session also passes the per-IP
 * "public" limiter before the full authentication runs.
 *
 * Held requests (SSE, long-poll) are capped at MAX_HELD_PER_USER per account with non-blocking
 * flock() slot files (runtime/rt/hold-<uid>-<n>.lock) plus the "realtime_hold" bucket; when no
 * slot is free the answer is 429 + Retry-After and the client falls back to short polling.
 *
 * Every response — JSON, 204 and the event stream — carries X-FT-Api: 1 so the client can tell
 * a real answer from the host's JavaScript cookie-check page.
 */
final class RealtimeController
{
    public const MAX_WAIT = 25;
    /** Held (SSE / long-poll) requests one account may have open at the same time. */
    public const MAX_HELD_PER_USER = 2;
    private const MIN_POLL_INTERVAL = 1.0;
    /** Short-poll guard files unused for this long are removed by the probabilistic sweep. */
    private const GUARD_FILE_TTL = 3600;
    private const SWEEP_ODDS = 100;
    private const SWEEP_MAX_ENTRIES = 2000;
    private const HEARTBEAT_SECONDS = 10;
    private const PADDING_BYTES = 2048;
    private const RETRY_MS = 3000;
    private const PAGE = 200;
    private const MAX_PAGES_PER_TICK = 5;
    private const MAX_EMPTY_RETRIES = 3;

    /** GET /api/v1/events?after=<event_id>&limit= → [Event], meta {last_id, reset, has_more} */
    public function recover(Request $req): Response
    {
        [$uid, $admin] = self::identity($req);
        $after = self::cursor($req, false);
        $limit = $req->int('limit', self::PAGE, 1, 500);
        return self::eventsResponse(EventBus::since($uid, $after, $limit, $admin));
    }

    /** GET /api/v1/events/stream?after=N (or Last-Event-ID) — Server-Sent Events. */
    public function stream(Request $req): ?Response
    {
        if (!Capabilities::canHold()) {
            throw ApiException::unavailable('Live updates over a held connection are not available on this server. The app will use polling instead.');
        }
        [$uid, $admin] = self::identity($req);
        $after = self::cursor($req, true);
        RateLimiter::enforce('realtime_hold', 'u' . $uid);
        $slot = self::acquireHoldSlot($uid);
        if ($slot === null) {
            throw self::tooManyHeld();
        }
        try {
            return self::runStream($uid, $admin, $after);
        } finally {
            self::releaseHoldSlot($slot);
        }
    }

    /** The SSE loop itself (the caller holds one of the account's hold slots). */
    private static function runStream(int $uid, bool $admin, int $after): ?Response
    {
        $hold = self::holdSeconds();
        Capabilities::setTimeLimit($hold + 15);
        Auth::closeSession(); // never hold the session lock while waiting

        // Catch up before the first byte is sent, so a database error is still a proper JSON error.
        $first = self::drain($uid, $after, $admin);
        Db::disconnect(); // never hold one of the host's few MySQL connections while waiting

        self::openStream();
        // 2 KB comment first: pushes the response through proxy buffers so the client sees the
        // stream is alive (it falls back to long-poll when this never arrives).
        self::out(':' . str_repeat(' ', self::PADDING_BYTES) . "\n\n" . 'retry: ' . self::RETRY_MS . "\n\n");
        $last = self::emit($first, $after);

        $deadline = microtime(true) + $hold;
        $lastWrite = microtime(true);
        $seen = -1;
        $tries = 0;
        while (($remaining = $deadline - microtime(true)) > 0) {
            if (!Capabilities::sleep(min(1.0, $remaining))) {
                break;
            }
            if (connection_aborted()) {
                return null;
            }
            $signal = self::signal($uid, $admin);
            if ($signal > $last) {
                if ($signal !== $seen) {
                    $seen = $signal;
                    $tries = 0;
                }
                // A publisher inside a still-open transaction bumps the signal before its rows are
                // visible: retry a few ticks, then wait for the signal to move again.
                if ($tries < self::MAX_EMPTY_RETRIES) {
                    $tries++;
                    $res = self::drain($uid, $last, $admin);
                    Db::disconnect();
                    $before = $last;
                    $last = self::emit($res, $last);
                    if ($last !== $before || $res['reset']) {
                        $tries = 0;
                        $lastWrite = microtime(true);
                    }
                }
            }
            if (microtime(true) - $lastWrite >= self::HEARTBEAT_SECONDS) {
                self::out(": hb\n\n");
                $lastWrite = microtime(true);
            }
        }
        self::out("event: bye\ndata: {}\n\n");
        return null;
    }

    /**
     * GET /api/v1/events/poll?after=N&wait=0..25 — long-poll (wait > 0, only where the host can
     * hold; otherwise wait is treated as 0) or short poll. Same JSON shape as /events; 204 when
     * nothing changed.
     */
    public function poll(Request $req): ?Response
    {
        $after = self::cursor($req, false);
        $wait = self::effectiveWait($req->int('wait', 0, 0, self::MAX_WAIT));

        // --- short-poll fast path: no database ------------------------------------------------
        $session = $req->bearerToken() === null ? self::sessionIdentity() : null;
        if ($wait === 0) {
            self::throttle($req, $session);
            if ($session !== null && self::signal($session['uid'], $session['admin']) <= $after) {
                return self::nothing();
            }
        }

        // --- something changed (or no session / long-poll): full authentication --------------
        if ($session === null) {
            // Nothing server-side vouches for this client (bearer token, remember-me cookie, or
            // nothing at all): the database-backed authentication below is limited per IP.
            RateLimiter::enforce('public', 'ip' . RateLimiter::ipSubject($req->ip()));
        }
        Auth::resolve($req); // validates the session row + account status; bearer tokens; remember-me
        if ($req->user === null) {
            throw ApiException::unauthorized();
        }
        [$uid, $admin] = self::identity($req);
        if ($wait > 0) {
            RateLimiter::enforce('realtime', 'u' . $uid);
        }
        $signal = self::signal($uid, $admin);
        if ($signal > $after) {
            $res = EventBus::since($uid, $after, self::PAGE, $admin);
            if ($res['events'] !== [] || $res['reset']) {
                return self::eventsResponse($res);
            }
        }
        if ($wait === 0) {
            return self::nothing();
        }

        // --- long-poll: at most MAX_HELD_PER_USER held requests per account -------------------
        RateLimiter::enforce('realtime_hold', 'u' . $uid);
        $slot = self::acquireHoldSlot($uid);
        if ($slot === null) {
            throw self::tooManyHeld();
        }
        try {
            return self::holdPoll($uid, $admin, $after, $wait, $signal);
        } finally {
            self::releaseHoldSlot($slot);
        }
    }

    /** Wait for the signal file without the session lock or a DB connection (caller holds a slot). */
    private static function holdPoll(int $uid, bool $admin, int $after, int $wait, int $signal): ?Response
    {
        Capabilities::setTimeLimit($wait + 15);
        Auth::closeSession();
        Db::disconnect();
        $deadline = microtime(true) + $wait;
        $seen = $signal;
        $tries = $signal > $after ? 1 : 0;
        while (($remaining = $deadline - microtime(true)) > 0) {
            if (!Capabilities::sleep(min(1.0, $remaining))) {
                break;
            }
            if (connection_aborted()) {
                return null;
            }
            $s = self::signal($uid, $admin);
            if ($s <= $after) {
                continue;
            }
            if ($s !== $seen) {
                $seen = $s;
                $tries = 0;
            }
            if ($tries >= self::MAX_EMPTY_RETRIES) {
                continue;
            }
            $tries++;
            $res = EventBus::since($uid, $after, self::PAGE, $admin);
            Db::disconnect();
            if ($res['events'] !== [] || $res['reset']) {
                return self::eventsResponse($res);
            }
        }
        return self::nothing();
    }

    /** Seconds a long-poll may wait: 0 when the host cannot hold requests, else ≤ REALTIME_HOLD_SECONDS. */
    public static function effectiveWait(int $requested): int
    {
        if ($requested <= 0 || !Capabilities::canHold()) {
            return 0;
        }
        return max(0, min($requested, self::MAX_WAIT, self::holdSeconds()));
    }

    // ------------------------------------------------------------------ helpers

    /** @return array{0:int,1:bool} [user id, receives the admin channel] */
    private static function identity(Request $req): array
    {
        if ($req->user === null) {
            throw ApiException::unauthorized();
        }
        return [(int) $req->user['id'], ($req->user['role'] ?? '') === 'admin'];
    }

    /** ?after=N, or (SSE reconnects) the Last-Event-ID header, which is the more recent position. */
    private static function cursor(Request $req, bool $allowHeader): int
    {
        if ($allowHeader) {
            $h = trim((string) ($req->header('Last-Event-ID') ?? ''));
            if ($h !== '' && preg_match('/^\d{1,18}$/', $h)) {
                return (int) $h;
            }
        }
        $v = $req->query('after');
        if ($v === null || $v === '') {
            return 0;
        }
        if (!is_string($v) || !preg_match('/^\d{1,18}$/', $v)) {
            throw ApiException::validation(['after' => 'Use the id of the last event you received (a whole number).']);
        }
        return (int) $v;
    }

    private static function holdSeconds(): int
    {
        return max(1, (int) Config::get('realtime.hold_seconds', 20));
    }

    /** Latest event id signalled for the user (and the admin channel for administrators). */
    private static function signal(int $uid, bool $admin): int
    {
        $s = RealtimeSignal::read($uid);
        if ($admin) {
            $s = max($s, RealtimeSignal::read(EventBus::ADMIN_CHANNEL));
        }
        return $s;
    }

    /**
     * The signed-in user from the PHP session without a database connection and without keeping
     * the session locked: A1's Auth::peekSession() (read_and_close, no Settings lookup, no session
     * GC). Only a hint — the full Auth::resolve() runs before any data is returned.
     * @return array{uid:int,sid:int,admin:bool}|null
     */
    private static function sessionIdentity(): ?array
    {
        $s = Auth::peekSession();
        if ($s === null) {
            return null;
        }
        return ['uid' => (int) $s['uid'], 'sid' => (int) $s['sid'], 'admin' => ($s['role'] ?? '') === 'admin'];
    }

    /**
     * File-based guard: at most one short poll per second per signed-in session — keyed on the
     * user_sessions row id stored server-side in the PHP session — or per client IP (/64 for
     * IPv6) for everything else (API tokens, remember-me only, anonymous). Never keyed on a value
     * the client chooses, so random cookies or tokens cannot mint a new guard file per request.
     * Answers 429 with Retry-After: 1. Fails open if the file cannot be used.
     * @param array{uid:int,sid:int,admin:bool}|null $session
     */
    private static function throttle(Request $req, ?array $session): void
    {
        $key = $session !== null ? 's|' . (int) $session['sid'] : 'ip|' . RateLimiter::ipSubject($req->ip());
        try {
            $dir = Paths::runtime('rt');
        } catch (\Throwable) {
            return;
        }
        $file = $dir . '/poll-' . substr(hash('sha256', 'ft-poll|' . $key), 0, 32) . '.t';
        $fp = @fopen($file, 'c+');
        if ($fp === false) {
            return;
        }
        $limited = false;
        try {
            if (!flock($fp, LOCK_EX)) {
                return;
            }
            $prev = (float) stream_get_contents($fp);
            $now = microtime(true);
            if ($prev > 0 && $now >= $prev && $now - $prev < self::MIN_POLL_INTERVAL) {
                $limited = true;
            } else {
                ftruncate($fp, 0);
                rewind($fp);
                fwrite($fp, sprintf('%.6F', $now));
                fflush($fp);
            }
            flock($fp, LOCK_UN);
        } finally {
            fclose($fp);
        }
        if ($limited) {
            throw ApiException::tooManyRequests(1);
        }
        if (random_int(1, self::SWEEP_ODDS) === 1) {
            self::sweepThrottleFiles($dir);
        }
    }

    /**
     * Remove guard files nobody has used for GUARD_FILE_TTL (runs on ~1 % of short polls).
     * Reads the directory as a stream and stops after SWEEP_MAX_ENTRIES entries, so it stays
     * cheap however many files there are. Returns the number of files removed.
     */
    public static function sweepThrottleFiles(string $dir, ?int $now = null): int
    {
        $cutoff = ($now ?? time()) - self::GUARD_FILE_TTL;
        $h = @opendir($dir);
        if ($h === false) {
            return 0;
        }
        $seen = 0;
        $removed = 0;
        try {
            while (($f = readdir($h)) !== false && $seen < self::SWEEP_MAX_ENTRIES) {
                $seen++;
                if (!preg_match('/^poll-[0-9a-f]{32}\.t$/', $f)) {
                    continue;
                }
                $m = @filemtime($dir . '/' . $f);
                if ($m !== false && $m < $cutoff && @unlink($dir . '/' . $f)) {
                    $removed++;
                }
            }
        } finally {
            closedir($h);
        }
        return $removed;
    }

    /**
     * Take one of the account's MAX_HELD_PER_USER hold slots (non-blocking flock on
     * runtime/rt/hold-<uid>-<n>.lock). Returns null when every slot is taken; a slot without a
     * handle when slot files cannot be used at all (fails open, like the short-poll guard).
     * The lock is released by releaseHoldSlot() — or by PHP when the request ends.
     * @return array{fp:resource|null}|null
     */
    public static function acquireHoldSlot(int $uid): ?array
    {
        try {
            $dir = Paths::runtime('rt');
        } catch (\Throwable) {
            return ['fp' => null];
        }
        $usable = false;
        for ($n = 0; $n < self::MAX_HELD_PER_USER; $n++) {
            $fp = @fopen($dir . '/hold-' . $uid . '-' . $n . '.lock', 'c');
            if ($fp === false) {
                continue;
            }
            $usable = true;
            if (@flock($fp, LOCK_EX | LOCK_NB)) {
                return ['fp' => $fp];
            }
            fclose($fp);
        }
        return $usable ? null : ['fp' => null];
    }

    /** @param array{fp:resource|null}|null $slot */
    public static function releaseHoldSlot(?array $slot): void
    {
        if ($slot === null || !is_resource($slot['fp'] ?? null)) {
            return;
        }
        @flock($slot['fp'], LOCK_UN);
        @fclose($slot['fp']);
    }

    /** 429 for a held request when the account already has MAX_HELD_PER_USER open. */
    private static function tooManyHeld(): ApiException
    {
        $retry = self::holdSeconds();
        return new ApiException(
            'RATE_LIMITED',
            'Too many live connections are open for your account. Updates will be checked regularly instead.',
            429,
            ['retry_after' => $retry, 'reason' => 'held_connections', 'max_held' => self::MAX_HELD_PER_USER],
            ['Retry-After' => (string) $retry]
        );
    }

    /**
     * Up to MAX_PAGES_PER_TICK pages of events (SSE catch-up after a busy period).
     * @return array{events:array<int,array<string,mixed>>,reset:bool,last_id:int,has_more:bool}
     */
    private static function drain(int $uid, int $after, bool $admin): array
    {
        $events = [];
        $cursor = $after;
        for ($i = 0; $i < self::MAX_PAGES_PER_TICK; $i++) {
            $r = EventBus::since($uid, $cursor, self::PAGE, $admin);
            if ($r['reset']) {
                return $events === [] ? $r : ['events' => $events, 'reset' => false, 'last_id' => $cursor, 'has_more' => true];
            }
            foreach ($r['events'] as $e) {
                $events[] = $e;
            }
            $cursor = (int) $r['last_id'];
            if (!$r['has_more']) {
                return ['events' => $events, 'reset' => false, 'last_id' => $cursor, 'has_more' => false];
            }
        }
        return ['events' => $events, 'reset' => false, 'last_id' => $cursor, 'has_more' => true];
    }

    /**
     * Write SSE frames for a since()/drain() result. Returns the new last delivered id.
     * @param array{events:array<int,array<string,mixed>>,reset:bool,last_id:int} $res
     */
    private static function emit(array $res, int $last): int
    {
        if ($res['reset']) {
            // The id line moves the browser's Last-Event-ID too, so a reconnect does not reset again.
            $id = (int) $res['last_id'];
            self::out('id: ' . $id . "\nevent: reset\ndata: " . self::json(['last_id' => $id]) . "\n\n");
            return $id;
        }
        $buf = '';
        foreach ($res['events'] as $e) {
            $id = (int) $e['event_id'];
            $buf .= 'id: ' . $id . "\nevent: ft\ndata: " . self::json($e) . "\n\n";
            $last = max($last, $id);
        }
        if ($buf !== '') {
            self::out($buf);
        }
        return $last;
    }

    private static function openStream(): void
    {
        if (function_exists('apache_setenv')) {
            @apache_setenv('no-gzip', '1');
        }
        @ini_set('zlib.output_compression', '0');
        @ini_set('implicit_flush', '1');
        for ($i = 0; $i < 10 && ob_get_level() > 0; $i++) {
            if (!@ob_end_clean()) {
                break;
            }
        }
        if (!headers_sent()) {
            http_response_code(200);
            header('Content-Type: text/event-stream; charset=utf-8');
            header('Cache-Control: no-cache, no-transform');
            header('X-Accel-Buffering: no');
            header('X-FT-Api: 1');
            header_remove('Content-Length');
        }
    }

    private static function out(string $chunk): void
    {
        echo $chunk;
        @flush();
    }

    private static function json(mixed $v): string
    {
        return (string) json_encode($v, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_INVALID_UTF8_SUBSTITUTE);
    }

    /** @param array{events:array<int,array<string,mixed>>,reset:bool,last_id:int,has_more:bool} $res */
    private static function eventsResponse(array $res): Response
    {
        return Response::ok($res['events'], [
            'last_id'  => (int) $res['last_id'],
            'reset'    => (bool) $res['reset'],
            'has_more' => (bool) $res['has_more'],
        ]);
    }

    /** 204 No Content, still marked as a real API answer. */
    private static function nothing(): Response
    {
        return Response::noContent()->withHeader('X-FT-Api', '1')->withHeader('Cache-Control', 'no-store');
    }
}
