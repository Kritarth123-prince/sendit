<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Auth\ApiTokens;
use FT\Auth\Auth;
use FT\Auth\Passwords;
use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\Policy;
use FT\Support\UserAgent;
use FT\Users\UserService;

/**
 * Security Centre (/api/v1/security/*). Every query is scoped to the signed-in user's own id —
 * ids from the URL are only ever used together with "AND user_id = <me>", so another user's
 * session/token id simply is not found (404).
 */
final class SecurityController
{
    /** GET /security/overview */
    public function overview(Request $req): array
    {
        $id = (int) $req->user['id'];
        $row = UserService::require($id);
        $now = Db::now();
        $changed = $row['password_changed_at'] !== null ? (string) $row['password_changed_at'] : null;
        $sessions = (int) Db::value('SELECT COUNT(*) FROM user_sessions WHERE user_id = ? AND revoked_at IS NULL AND expires_at > ?', [$id, $now]);
        $links = Db::one(
            "SELECT COUNT(*) AS active,
                    SUM(CASE WHEN expires_at IS NOT NULL AND expires_at <= :soon THEN 1 ELSE 0 END) AS expiring
             FROM shares WHERE owner_id = :u AND kind = 'link' AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > :now)",
            ['soon' => Db::ts(time() + 7 * 86400), 'u' => $id, 'now' => $now]
        ) ?? [];
        $suspicious = (int) Db::value('SELECT COUNT(*) FROM login_history WHERE user_id = ? AND suspicious = 1 AND created_at > ?', [$id, Db::ts(time() - 30 * 86400)]);
        $failed = (int) Db::value('SELECT COUNT(*) FROM login_history WHERE user_id = ? AND success = 0 AND created_at > ?', [$id, Db::ts(time() - 30 * 86400)]);
        $tokens = (int) Db::value('SELECT COUNT(*) FROM api_tokens WHERE user_id = ? AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > ?)', [$id, $now]);
        $devices = (int) Db::value('SELECT COUNT(*) FROM user_devices WHERE user_id = ?', [$id]);
        $age = $changed !== null ? intdiv(max(0, time() - (Db::toUnix($changed) ?? time())), 86400) : null;
        return [
            'account_status' => (string) $row['status'],
            'password'       => [
                'changed_at'           => Db::iso($changed),
                'age_days'             => $age,
                'weak'                 => Passwords::isFlaggedWeak($row),
                'must_change_password' => (bool) $row['must_change_password'],
            ],
            'two_factor'               => (bool) $row['totp_enabled'],
            'recovery_codes_remaining' => (bool) $row['totp_enabled'] ? \FT\Auth\Totp::remainingRecoveryCodes($row) : 0,
            'sessions_count'        => $sessions,
            'active_links'          => (int) ($links['active'] ?? 0),
            'expiring_links'        => (int) ($links['expiring'] ?? 0),
            'suspicious_logins_30d' => $suspicious,
            'failed_logins_30d'     => $failed,
            'api_tokens'            => $tokens,
            'devices'               => $devices,
            'last_login_at'         => Db::iso($row['last_login_at'] ?? null),
            'last_login_ip'         => $row['last_login_ip'] ?? null,
            'locked_until'          => $row['locked_until'] !== null && (string) $row['locked_until'] > $now ? Db::iso((string) $row['locked_until']) : null,
        ];
    }

    /** GET /security/sessions */
    public function sessions(Request $req): array
    {
        $id = (int) $req->user['id'];
        $current = Auth::sessionRowId();
        $rows = Db::all(
            'SELECT s.*, d.name AS device_name FROM user_sessions s LEFT JOIN user_devices d ON d.id = s.device_id
             WHERE s.user_id = ? AND s.revoked_at IS NULL AND s.expires_at > ? ORDER BY s.last_seen_at DESC, s.id DESC LIMIT 200',
            [$id, Db::now()]
        );
        return array_map(static fn (array $s): array => [
            'id'           => (int) $s['id'],
            'current'      => $current !== null && (int) $s['id'] === $current,
            'ip'           => $s['ip'],
            'device'       => ($s['device_name'] ?? '') !== '' ? (string) $s['device_name'] : UserAgent::describe($s['user_agent']),
            'user_agent'   => $s['user_agent'],
            'created_at'   => Db::iso($s['created_at']),
            'last_seen_at' => Db::iso($s['last_seen_at']),
            'expires_at'   => Db::iso($s['expires_at']),
            'method'       => (string) $s['auth_method'],
            'remember'     => $s['remember_selector'] !== null,
            'two_factor'   => (bool) $s['two_factor_passed'],
        ], $rows);
    }

    /** DELETE /security/sessions/{id} */
    public function revokeSession(Request $req): Response
    {
        $id = (int) $req->user['id'];
        $sid = $req->intParam('id');
        $row = Db::one('SELECT id FROM user_sessions WHERE id = ? AND user_id = ? AND revoked_at IS NULL', [$sid, $id]);
        if ($row === null) {
            throw ApiException::notFound('session');
        }
        $isCurrent = $sid === Auth::sessionRowId();
        Auth::revokeSession($sid, $isCurrent ? 'logout' : 'user_revoked');
        Audit::log('auth.session_revoked', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'meta' => ['session_id' => $sid, 'current' => $isCurrent]]);
        if ($isCurrent) {
            Auth::logout($req);
        }
        return Response::noContent();
    }

    /**
     * POST /security/sessions/revoke-all {include_current?:false, include_tokens?:true}
     * Signs out every other session and (unless include_tokens is false) revokes every API token.
     * The session or token making the request survives unless include_current is true.
     * → {revoked (= sessions_revoked, kept for older clients), sessions_revoked, tokens_revoked, signed_out}
     */
    public function revokeAll(Request $req): array
    {
        $id = (int) $req->user['id'];
        $includeCurrent = $req->bool('include_current');
        $includeTokens = $req->bool('include_tokens', true);
        $current = $req->authVia === 'session' ? Auth::sessionRowId() : null;
        $currentToken = $req->authVia === 'token' && isset($req->user['token_id']) ? (int) $req->user['token_id'] : null;
        $counts = Auth::signOutEverywhere(
            $id,
            'user_revoked_all',
            $includeCurrent ? null : $current,
            $includeCurrent ? null : $currentToken,
            $includeTokens
        );
        Audit::log('auth.session_revoked', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'meta' => [
            'all' => true, 'count' => $counts['sessions_revoked'], 'api_clients_revoked' => $counts['tokens_revoked'],
            'include_current' => $includeCurrent, 'include_api_clients' => $includeTokens,
        ]]);
        $signedOut = Auth::describeSignOut($counts);
        if ($signedOut !== '') {
            Passwords::notifySecurity($id, 'security.sessions_revoked', 'You signed out everywhere',
                'From the Security Centre: ' . $signedOut . '. If this was not you, change your password straight away.', $counts);
        }
        if ($includeCurrent && ($current !== null || $currentToken !== null)) {
            Auth::logout($req);
        }
        return [
            'revoked'          => $counts['sessions_revoked'],
            'sessions_revoked' => $counts['sessions_revoked'],
            'tokens_revoked'   => $counts['tokens_revoked'],
            'signed_out'       => $includeCurrent,
        ];
    }

    /** GET /security/logins ?status=success|failed|suspicious&page=&per_page= */
    public function logins(Request $req): Response
    {
        $id = (int) $req->user['id'];
        [$page, $per, $offset] = $req->pagination(50, 200);
        $where = 'user_id = :u';
        $params = ['u' => $id];
        $status = (string) $req->query('status', '');
        if ($status === 'success') {
            $where .= ' AND success = 1';
        } elseif ($status === 'failed') {
            $where .= ' AND success = 0';
        } elseif ($status === 'suspicious') {
            $where .= ' AND suspicious = 1';
        }
        $total = (int) Db::value("SELECT COUNT(*) FROM login_history WHERE {$where}", $params);
        $rows = Db::all("SELECT * FROM login_history WHERE {$where} ORDER BY id DESC LIMIT :lim OFFSET :off", $params + ['lim' => $per, 'off' => $offset]);
        $items = array_map(static fn (array $r): array => [
            'id'                => (int) $r['id'],
            'success'           => (bool) $r['success'],
            'status'            => (bool) $r['success'] ? ((bool) $r['suspicious'] ? 'suspicious' : 'success') : 'failed',
            'method'            => (string) $r['method'],
            'failure_reason'    => $r['failure_reason'],
            'suspicious'        => (bool) $r['suspicious'],
            'suspicious_reason' => $r['suspicious_reason'],
            'ip'                => $r['ip'],
            'device'            => UserAgent::describe($r['user_agent']),
            'user_agent'        => $r['user_agent'],
            'created_at'        => Db::iso($r['created_at']),
        ], $rows);
        return Response::paginated($items, $total, $page, $per);
    }

    /** GET /security/events — security audit entries about me (plus admin actions on my account). */
    public function events(Request $req): Response
    {
        $id = (int) $req->user['id'];
        [$page, $per, $offset] = $req->pagination(50, 200);
        $where = "((category = 'security' AND (user_id = :u1 OR owner_id = :o1))
                   OR (category = 'admin' AND target_type = 'user' AND target_id = :t1 AND owner_id = :o2))";
        $params = ['u1' => $id, 'o1' => $id, 't1' => $id, 'o2' => $id];
        $total = (int) Db::value("SELECT COUNT(*) FROM audit_logs WHERE {$where}", $params);
        $rows = Db::all("SELECT * FROM audit_logs WHERE {$where} ORDER BY id DESC LIMIT :lim OFFSET :off", $params + ['lim' => $per, 'off' => $offset]);
        return Response::paginated(UserService::auditShapes($rows), $total, $page, $per);
    }

    /** GET /security/devices */
    public function devices(Request $req): array
    {
        $id = (int) $req->user['id'];
        $currentDevice = null;
        $sid = Auth::sessionRowId();
        if ($sid !== null) {
            $d = Db::value('SELECT device_id FROM user_sessions WHERE id = ?', [$sid]);
            $currentDevice = $d !== null ? (int) $d : null;
        }
        $client = $req->clientId();
        $clientHash = $client !== null ? hash('sha256', $client) : null;
        $rows = Db::all(
            'SELECT d.*, (SELECT COUNT(*) FROM push_subscriptions p WHERE p.device_id = d.id AND p.user_id = d.user_id) AS push_count,
                    (SELECT COUNT(*) FROM user_sessions s WHERE s.device_id = d.id AND s.revoked_at IS NULL AND s.expires_at > :now) AS session_count
             FROM user_devices d WHERE d.user_id = :u ORDER BY d.last_seen_at DESC LIMIT 200',
            ['now' => Db::now(), 'u' => $id]
        );
        return array_map(static fn (array $d): array => [
            'id'              => (int) $d['id'],
            'name'            => (string) ($d['name'] !== '' ? $d['name'] : UserAgent::describe($d['user_agent'])),
            'user_agent'      => $d['user_agent'],
            'last_ip'         => $d['last_ip'],
            'first_seen_at'   => Db::iso($d['first_seen_at']),
            'last_seen_at'    => Db::iso($d['last_seen_at']),
            'push_enabled'    => (int) $d['push_count'] > 0,
            'active_sessions' => (int) $d['session_count'],
            'current'         => ($currentDevice !== null && (int) $d['id'] === $currentDevice) || ($clientHash !== null && hash_equals((string) $d['client_hash'], $clientHash)),
        ], $rows);
    }

    /** GET /security/tokens */
    public function tokens(Request $req): array
    {
        return ApiTokens::listFor((int) $req->user['id'], $req->bool('all'));
    }

    /**
     * POST /security/tokens {current_password, name, scopes?:'*'|'read', expires_in_days?} → token shown once
     *
     * Needs the current password (a stolen session cookie must not be able to mint long-lived
     * credentials). expires_in_days: omitted/null/"" ⇒ ApiTokens::DEFAULT_EXPIRY_DAYS (90);
     * 1…3650 ⇒ that many days; an explicit 0 ⇒ never expires (shown as such in the Security Centre).
     */
    public function createToken(Request $req): Response
    {
        Auth::requireInteractive($req);
        if (!Policy::can($req->user, 'api.tokens')) {
            throw ApiException::forbidden('Your account cannot create API tokens.');
        }
        $scopes = $req->input('scopes', '*');
        if (is_array($scopes)) {
            $scopes = in_array('*', $scopes, true) ? '*' : (in_array('read', $scopes, true) && count($scopes) === 1 ? 'read' : 'invalid');
        }
        $days = $req->input('expires_in_days');
        if ($days === null || $days === '') {
            $days = ApiTokens::DEFAULT_EXPIRY_DAYS;
        } elseif ($days === 0 || $days === '0') {
            $days = null; // explicitly "never"
        } else {
            $days = (is_int($days) || (is_string($days) && preg_match('/^\d{1,6}$/', $days))) ? (int) $days : -1;
        }
        Auth::reauthenticate($req, 'current_password');
        $created = ApiTokens::create((int) $req->user['id'], $req->string('name', '', 200), is_string($scopes) ? $scopes : 'invalid', $days);
        return Response::created(['token' => $created['token']] + ApiTokens::shape($created['row']));
    }

    /** DELETE /security/tokens/{id} */
    public function revokeToken(Request $req): Response
    {
        if (!ApiTokens::revoke((int) $req->user['id'], $req->intParam('id'))) {
            throw ApiException::notFound('API token');
        }
        return Response::noContent();
    }
}
