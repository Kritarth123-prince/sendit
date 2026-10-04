<?php
declare(strict_types=1);

namespace FT\Controllers\Api;

use FT\Auth\Auth;
use FT\Auth\Passwords;
use FT\Auth\Totp;
use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Db;
use FT\Core\Secrets;
use FT\Http\Request;
use FT\Http\Response;
use FT\Security\RateLimiter;
use FT\Users\UserService;

/**
 * The signed-in user's own account: profile, preferences, password and two-factor settings,
 * plus the user lookup used by the share dialog.
 */
final class UserController
{
    /** GET /user → User(me) */
    public function show(Request $req): array
    {
        return Auth::me($req->user);
    }

    /** PATCH /user {display_name?, email?, preferences?, current_password? (needed to change e-mail when reset by e-mail is on)} */
    public function update(Request $req): array
    {
        $in = $req->all();
        $known = array_intersect_key($in, ['display_name' => 1, 'email' => 1, 'preferences' => 1]);
        if ($known === []) {
            throw ApiException::validation(['user' => 'Nothing to update.']);
        }
        if (array_key_exists('email', $known) && Passwords::resetAvailable()) {
            // With password reset by e-mail, the address is a credential: changing it needs the password.
            $current = UserService::find((int) $req->user['id']);
            $newEmail = is_string($known['email']) ? mb_strtolower(trim($known['email'])) : null;
            if ($current !== null && ($newEmail ?: null) !== $current['email']) {
                RateLimiter::enforce('password', 'u' . (int) $req->user['id']);
                $pw = $in['current_password'] ?? '';
                if (!is_string($pw) || $pw === '' || !Passwords::verify($pw, (string) $current['password_hash'])) {
                    throw ApiException::validation(['current_password' => 'Enter your current password to change your e-mail address.']);
                }
            }
        }
        UserService::updateProfile($req->user, $known);
        Auth::refresh();
        return Auth::me(Auth::user() ?? $req->user);
    }

    /**
     * POST /user/password {current_password, new_password} — signs out every other session and
     * revokes every API token (except the token making this request, if any).
     * → {changed, other_sessions_revoked (= sessions_revoked, kept for older clients), sessions_revoked, tokens_revoked, user}
     */
    public function changePassword(Request $req): array
    {
        $current = $req->input('current_password');
        $new = $req->input('new_password');
        $current = is_string($current) ? $current : '';
        $new = is_string($new) ? $new : '';
        if ($current === '' || $new === '') {
            throw ApiException::validation(array_filter([
                'current_password' => $current === '' ? 'Enter your current password.' : null,
                'new_password'     => $new === '' ? 'Choose a new password.' : null,
            ]));
        }
        $counts = UserService::changePassword($req->user, $current, $new, $req);
        return [
            'changed'                => true,
            'other_sessions_revoked' => $counts['sessions_revoked'],
            'sessions_revoked'       => $counts['sessions_revoked'],
            'tokens_revoked'         => $counts['tokens_revoked'],
            'user'                   => Auth::me(Auth::user() ?? $req->user),
        ];
    }

    /**
     * POST /user/2fa/setup {current_password} → {secret, otpauth_uri} (pending until enabled with
     * a valid code). Needs the current password: a stolen session cookie alone must not be able
     * to attach the attacker's authenticator to the account.
     */
    public function twoFactorSetup(Request $req): array
    {
        Auth::requireInteractive($req);
        $id = (int) $req->user['id'];
        $row = Auth::reauthenticate($req, 'current_password');
        if ((int) $row['totp_enabled'] === 1) {
            throw ApiException::conflict('Two-factor authentication is already on. Turn it off first to set up a new authenticator.');
        }
        $secret = Totp::generateSecret();
        Db::update('users', ['totp_secret_enc' => Secrets::encrypt($secret), 'totp_last_step' => null, 'updated_at' => Db::now()], ['id' => $id]);
        Audit::log('auth.2fa_setup_started', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id]);
        return [
            'secret'      => $secret,
            'otpauth_uri' => Totp::uri($secret, (string) $row['username']),
            'digits'      => Totp::DIGITS,
            'period'      => Totp::PERIOD,
            'algorithm'   => 'SHA1',
        ];
    }

    /** POST /user/2fa/enable {current_password, code} → {recovery_codes:[…]} (shown once) */
    public function twoFactorEnable(Request $req): array
    {
        Auth::requireInteractive($req);
        $id = (int) $req->user['id'];
        RateLimiter::enforce('two_factor', 'u' . $id);
        $row = Auth::reauthenticate($req, 'current_password');
        if ((int) $row['totp_enabled'] === 1) {
            throw ApiException::conflict('Two-factor authentication is already on.');
        }
        if (Totp::secretFor($row) === null) {
            throw ApiException::badRequest('Start the set-up first to get a new secret.', 'BAD_REQUEST');
        }
        $code = self::codeInput($req->input('code')) ?? '';
        if ($code === '') {
            throw ApiException::validation(['code' => 'Enter the 6-digit code from your authenticator app.']);
        }
        if (!Totp::verifyForUser($row, $code)) {
            throw new ApiException('TWO_FACTOR_INVALID', 'That code did not work. Check the time on your phone and try again.', 422, ['fields' => ['code' => 'That code did not work.']]);
        }
        $codes = Db::transaction(static function () use ($id): array {
            Db::update('users', ['totp_enabled' => 1, 'updated_at' => Db::now()], ['id' => $id]);
            return Totp::regenerateRecoveryCodes($id);
        });
        $sid = Auth::sessionRowId();
        if ($sid !== null) {
            Db::update('user_sessions', ['two_factor_passed' => 1], ['id' => $sid]);
        }
        Audit::log('auth.2fa_enabled', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id]);
        Passwords::notifySecurity($id, 'security.2fa_enabled', 'Two-factor authentication is on', 'Your account now asks for a code from your authenticator app when you sign in. Keep your recovery codes somewhere safe.');
        \FT\Events\EventBus::publish('user.updated', ['user' => UserService::eventRef(UserService::require($id)), 'changes' => ['two_factor_enabled']], [$id], ['admin' => true]);
        Auth::refresh();
        return ['enabled' => true, 'recovery_codes' => $codes];
    }

    /** POST /user/2fa/disable {password, code} — code may be a TOTP code or a recovery code. */
    public function twoFactorDisable(Request $req): array
    {
        Auth::requireInteractive($req);
        $id = (int) $req->user['id'];
        $row = $this->reauthenticate($req, $id);
        if ((int) $row['totp_enabled'] !== 1) {
            throw ApiException::conflict('Two-factor authentication is not on.');
        }
        $this->requireSecondFactor($req, $row);
        UserService::disableTwoFactor($id, false);
        Auth::refresh();
        return ['enabled' => false];
    }

    /** POST /user/2fa/recovery-codes {password, code} → fresh recovery codes (old ones stop working). */
    public function regenerateRecoveryCodes(Request $req): array
    {
        Auth::requireInteractive($req);
        $id = (int) $req->user['id'];
        $row = $this->reauthenticate($req, $id);
        if ((int) $row['totp_enabled'] !== 1) {
            throw ApiException::conflict('Two-factor authentication is not on.');
        }
        $this->requireSecondFactor($req, $row);
        $codes = Totp::regenerateRecoveryCodes($id);
        Audit::log('auth.recovery_codes_regenerated', ['target_type' => 'user', 'target_id' => $id, 'owner_id' => $id]);
        Passwords::notifySecurity($id, 'security.recovery_codes', 'New recovery codes were created', 'Your previous recovery codes no longer work.');
        return ['recovery_codes' => $codes];
    }

    /** GET /users/lookup?q= (≥ 2 characters; not for guests) → [UserRef] (max 10, never e-mails) */
    public function lookup(Request $req): array
    {
        $q = $req->query('q', '');
        return UserService::lookup($req->user, is_string($q) ? $q : '', 10);
    }

    // ------------------------------------------------------------------ helpers

    /** A code typed by the user; JSON numbers keep their leading zeros ("012345"). */
    private static function codeInput(mixed $v): ?string
    {
        if (is_int($v) && $v >= 0) {
            $v = str_pad((string) $v, Totp::DIGITS, '0', STR_PAD_LEFT);
        }
        if (!is_string($v)) {
            return null;
        }
        $v = trim($v);
        return $v === '' ? null : mb_substr($v, 0, 64);
    }

    /** Current password check for 2FA disable / recovery codes (field "password"; "current_password" accepted too). */
    private function reauthenticate(Request $req, int $id): array
    {
        $row = Auth::reauthenticate($req, 'password');
        if ((int) $row['id'] !== $id) {
            throw ApiException::forbidden();
        }
        return $row;
    }

    private function requireSecondFactor(Request $req, array $row): void
    {
        RateLimiter::enforce('two_factor', 'u' . (int) $row['id']);
        $used = Totp::verifyAny($row, self::codeInput($req->input('code')), self::codeInput($req->input('recovery_code')));
        if ($used === null) {
            throw new ApiException('TWO_FACTOR_INVALID', 'That code did not work.', 422, ['fields' => ['code' => 'That code did not work.']]);
        }
    }
}
