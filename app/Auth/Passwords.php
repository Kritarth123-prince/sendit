<?php
declare(strict_types=1);

namespace FT\Auth;

use FT\Core\ApiException;
use FT\Core\Audit;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\RequestContext;
use FT\Core\Secrets;
use FT\Core\Settings;
use FT\Http\Request;
use FT\Jobs\Queue;
use FT\Security\RateLimiter;

/**
 * Password policy, hashing and the optional self-service reset by e-mail.
 *
 * Policy (deliberately simple, NIST 800-63B style — length over composition rules):
 *   - at least 10 characters (and at most 200, so hashing stays cheap and predictable)
 *   - not equal to and not containing the username
 *   - not one of the most common passwords (embedded list, also matched with trailing
 *     digits/symbols removed, so "Password123!" is rejected too)
 *   - not a single repeated character or a straight keyboard/alphabet/number run
 */
final class Passwords
{
    public const MIN_LENGTH = 10;
    public const MAX_LENGTH = 200;
    public const RESET_TTL_SECONDS = 3600;

    /** Common passwords and base words (lower case). Kept short: the length rule does most of the work. */
    private const COMMON = [
        'password', 'passw0rd', 'p@ssword', 'p@ssw0rd', 'pass', 'qwerty', 'qwertyuiop', 'qwertyui', 'asdfghjkl',
        'zxcvbnm', 'azerty', 'qwertz', '1q2w3e4r', '1q2w3e4r5t', '1q2w3e4r5t6y', 'q1w2e3r4', 'q1w2e3r4t5', 'q1w2e3r4t5y6',
        '1qaz2wsx', '1qaz2wsx3edc', 'zaq12wsx', 'zaq1zaq1', 'qazwsx', 'qazwsxedc', 'qazwsxedcrfv', 'letmein', 'welcome',
        'welcome1', 'admin', 'administrator', 'root', 'toor', 'login', 'iloveyou', 'monkey', 'dragon', 'master',
        'shadow', 'sunshine', 'princess', 'football', 'baseball', 'soccer', 'hockey', 'superman', 'batman', 'trustno1',
        'trustno', 'starwars', 'whatever', 'freedom', 'computer', 'michael', 'jennifer', 'jordan', 'hunter', 'ranger',
        'buster', 'harley', 'charlie', 'hello', 'hellohello', 'secret', 'changeme', 'changeit', 'default', 'abc',
        'abcabc', 'abc123', 'abcd1234', 'test', 'testtest', 'tester', 'testing', 'guest', 'user', 'mustang', 'access',
        'flower', 'cookie', 'cheese', 'pokemon', 'liverpool', 'chelsea', 'arsenal', 'killer', 'pepper', 'summer',
        'winter', 'spring', 'autumn', 'january', 'february', 'september', 'october', 'november', 'december',
        'qwerty123', 'password1', 'iloveyou1', 'fasttransfer', 'fast transfer', 'transfer', 'sendit', 'mts',
        '123456789a', 'a123456789', '1234567890', '0987654321', '9876543210', '1234512345', '1122334455',
        '1111111111', '0000000000', '1234567891', '12345678910', '123123123', '123123123123', '147258369',
        '159753', '159357', '741852963', '987654321', '123qwe', '123qweasd', '123qweasdzxc', 'qweasdzxc',
        'football1', 'superman1', 'baseball1', 'princess1', 'sunshine1', 'letmein1', 'monkey1', 'dragon1',
    ];

    /** Keyboard rows and sequences used for the "straight run" check. */
    private const RUNS = ['abcdefghijklmnopqrstuvwxyz', '01234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'qwertzuiop', 'azertyuiop'];

    // ------------------------------------------------------------------ policy

    /**
     * Validate a new password. Returns user-facing problems (British English); empty = acceptable.
     * @return string[]
     */
    public static function problems(string $password, string $username = '', ?string $email = null): array
    {
        $errors = [];
        $len = mb_strlen($password);
        if ($len < self::MIN_LENGTH) {
            $errors[] = 'Use at least ' . self::MIN_LENGTH . ' characters.';
        }
        if ($len > self::MAX_LENGTH) {
            $errors[] = 'Use at most ' . self::MAX_LENGTH . ' characters.';
        }
        if (preg_match('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', $password)) {
            $errors[] = 'Remove control characters from the password.';
        }
        $lower = mb_strtolower($password);
        $user = mb_strtolower(trim($username));
        if ($user !== '' && mb_strlen($user) >= 3 && str_contains($lower, $user)) {
            $errors[] = 'Do not use your username in your password.';
        }
        if ($email !== null && $email !== '') {
            $local = mb_strtolower((string) strstr($email, '@', true));
            if (mb_strlen($local) >= 4 && str_contains($lower, $local)) {
                $errors[] = 'Do not use your e-mail address in your password.';
            }
        }
        if ($len >= self::MIN_LENGTH && self::isCommon($lower)) {
            $errors[] = 'This password is too common. Choose something harder to guess.';
        } elseif ($len >= self::MIN_LENGTH && self::isTrivial($lower)) {
            $errors[] = 'Avoid repeated characters and simple sequences such as "abcdef" or "123456".';
        }
        return $errors;
    }

    /** Throw PASSWORD_TOO_WEAK (422) with field details when the password breaks the policy. */
    public static function assertAcceptable(string $password, string $username = '', ?string $email = null, string $field = 'password'): void
    {
        $problems = self::problems($password, $username, $email);
        if ($problems !== []) {
            throw new ApiException('PASSWORD_TOO_WEAK', $problems[0], 422, ['fields' => [$field => implode(' ', $problems)], 'problems' => $problems]);
        }
    }

    public static function isAcceptable(string $password, string $username = '', ?string $email = null): bool
    {
        return self::problems($password, $username, $email) === [];
    }

    private static function isCommon(string $lower): bool
    {
        static $set = null;
        $set ??= array_flip(self::COMMON);
        if (isset($set[$lower])) {
            return true;
        }
        // "Password123!", "!!qwerty2024" → strip leading/trailing digits and symbols.
        $core = (string) preg_replace('/^[^a-z]+|[^a-z]+$/u', '', $lower);
        if ($core !== '' && isset($set[$core])) {
            return true;
        }
        // Simple leetspeak normalisation ("p4ssw0rd", "@dmin").
        $leet = strtr($core !== '' ? $core : $lower, ['0' => 'o', '1' => 'l', '3' => 'e', '4' => 'a', '5' => 's', '7' => 't', '@' => 'a', '$' => 's']);
        $leet = (string) preg_replace('/[^a-z]+$/', '', $leet);
        if ($leet !== '' && isset($set[$leet])) {
            return true;
        }
        // The same common word repeated ("passwordpassword").
        foreach ([2, 3] as $n) {
            if (strlen($core) % $n === 0 && $core !== '') {
                $part = substr($core, 0, intdiv(strlen($core), $n));
                if (isset($set[$part]) && str_repeat($part, $n) === $core) {
                    return true;
                }
            }
        }
        return false;
    }

    private static function isTrivial(string $lower): bool
    {
        if (count(array_unique(mb_str_split($lower))) <= 2) {
            return true; // "aaaaaaaaaa", "abababababab"
        }
        foreach (self::RUNS as $run) {
            if (str_contains($run, $lower) || str_contains(strrev($run), $lower)) {
                return true;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ hashing

    public static function hash(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    public static function verify(string $password, ?string $hash): bool
    {
        if ($hash === null || $hash === '') {
            // Still spend the time of a real verification so timing does not reveal anything.
            password_verify($password, self::dummyHash());
            return false;
        }
        return password_verify($password, $hash);
    }

    public static function needsRehash(string $hash): bool
    {
        return password_needs_rehash($hash, PASSWORD_DEFAULT);
    }

    /**
     * A valid bcrypt hash with the platform's default cost, used to make "unknown user" take as
     * long as "wrong password" (PHP 8.4 raised the default cost from 10 to 12).
     */
    public static function dummyHash(): string
    {
        $cost = defined('PASSWORD_BCRYPT_DEFAULT_COST') ? (int) PASSWORD_BCRYPT_DEFAULT_COST : 10;
        return $cost >= 12
            ? '$2y$12$hdeaYqjHy3.IiRMZGkZALu0HXWJuZrdFD80ojzNwXfiMyrdAtW/Om'
            : '$2y$10$GLf38RH5RNOFS3.d.s3l9.uH0vNnteNjIWgCNnD0mRMXB9hQSyl1i';
    }

    /**
     * A random temporary password that satisfies the policy, e.g. "Kp7m-Xq2r-Wd9t-Hn4v".
     * Shown to the administrator exactly once; the user must change it at next sign-in.
     */
    public static function generateTemporary(): string
    {
        $alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
        $max = strlen($alphabet) - 1;
        do {
            $groups = [];
            for ($g = 0; $g < 4; $g++) {
                $s = '';
                for ($i = 0; $i < 4; $i++) {
                    $s .= $alphabet[random_int(0, $max)];
                }
                $groups[] = $s;
            }
            $pw = implode('-', $groups);
        } while (!preg_match('/[A-Z]/', $pw) || !preg_match('/[a-z]/', $pw) || !preg_match('/\d/', $pw));
        return $pw;
    }

    // ------------------------------------------------------------------ change

    /**
     * Store a new password for a user (already validated by the caller). Clears the
     * must-change flag, the brute-force counters and any outstanding reset tokens.
     */
    public static function store(int $userId, string $newPassword, bool $mustChange = false): void
    {
        Db::update('users', [
            'password_hash'        => self::hash($newPassword),
            'password_changed_at'  => Db::now(),
            'must_change_password' => $mustChange ? 1 : 0,
            'failed_login_count'   => 0,
            'locked_until'         => null,
            'updated_at'           => Db::now(),
        ], ['id' => $userId]);
        Db::run('UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL', [Db::now(), $userId]);
        self::setWeakFlag($userId, false);
    }

    /**
     * Remember whether the password used at the last sign-in breaks the current policy (the
     * Security Centre shows "weak password"). Kept in users.preferences under a private key.
     */
    public static function setWeakFlag(int $userId, bool $weak): void
    {
        $raw = Db::value('SELECT preferences FROM users WHERE id = ?', [$userId]);
        $prefs = json_decode((string) $raw, true);
        $prefs = is_array($prefs) ? $prefs : [];
        $current = !empty($prefs['_pw_weak']);
        if ($current === $weak) {
            return;
        }
        if ($weak) {
            $prefs['_pw_weak'] = true;
        } else {
            unset($prefs['_pw_weak']);
        }
        Db::update('users', ['preferences' => $prefs === [] ? null : json_encode($prefs, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)], ['id' => $userId]);
    }

    public static function isFlaggedWeak(array $userRow): bool
    {
        $prefs = json_decode((string) ($userRow['preferences'] ?? ''), true);
        return is_array($prefs) && !empty($prefs['_pw_weak']);
    }

    // ------------------------------------------------------------------ self-service reset

    /** Password reset by e-mail is offered only when an e-mail driver is configured. */
    public static function resetAvailable(): bool
    {
        return strtolower((string) Config::get('mail.driver', 'none')) !== 'none';
    }

    /**
     * Start a reset for the account with this e-mail address. Always behaves the same whether or
     * not the address exists (the caller always answers 202), so it cannot be used to discover
     * accounts. Rate limited per IP and per address.
     */
    public static function requestReset(string $email, Request $req): void
    {
        if (!self::resetAvailable()) {
            throw ApiException::unavailable('Password reset by e-mail is not available on this server. Please ask an administrator.');
        }
        $email = mb_strtolower(trim($email));
        if ($email === '' || mb_strlen($email) > 191 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw ApiException::validation(['email' => 'Enter a valid e-mail address.']);
        }
        RateLimiter::enforce('password', 'reset-ip' . RateLimiter::ipSubject($req->ip()));
        $perAddress = RateLimiter::hit('password', 'reset-mail' . hash('sha256', $email));
        if (!$perAddress['allowed']) {
            return; // silently drop: do not reveal anything about the address
        }
        $user = Db::one("SELECT id, username, email FROM users WHERE email = ? AND status = 'active' AND deleted_at IS NULL LIMIT 1", [$email]);
        if ($user === null) {
            Logger::info('auth', 'Password reset requested for an unknown address');
            return;
        }
        $token = self::createResetToken((int) $user['id'], $req->ip());
        $configured = (string) Config::get('app.url');
        Queue::push(self::class . '::sendResetMailJob', [
            'user_id'   => (int) $user['id'],
            'token_enc' => Secrets::encrypt($token),
            // Only a configured APP_URL is trusted for links (a forged Host header must never
            // end up in a reset e-mail); without it the e-mail carries the code to paste instead.
            'base_url'  => $configured !== '' ? rtrim($configured, '/') . '/' : null,
        ], 0, 'default', 3);
        Audit::log('auth.password_reset_requested', ['user_id' => null, 'actor_label' => 'Password reset', 'target_type' => 'user', 'target_id' => (int) $user['id'], 'owner_id' => (int) $user['id']]);
    }

    /** Create a single-use reset token (returns the raw token; only its hash is stored). */
    public static function createResetToken(int $userId, ?string $ip = null): string
    {
        // Keep at most a handful of live tokens per user.
        Db::run(
            'UPDATE password_resets SET used_at = ? WHERE user_id = ? AND used_at IS NULL AND id NOT IN (
               SELECT id FROM (SELECT id FROM password_resets WHERE user_id = ? AND used_at IS NULL ORDER BY id DESC LIMIT 2) AS recent_tokens)',
            [Db::now(), $userId, $userId]
        );
        $token = Secrets::token(43);
        Db::insert('password_resets', [
            'user_id'    => $userId,
            'token_hash' => hash('sha256', $token),
            'ip'         => $ip,
            'created_at' => Db::now(),
            'expires_at' => Db::ts(time() + self::RESET_TTL_SECONDS),
        ]);
        return $token;
    }

    /**
     * Complete a reset: validates the token (single use, 1 h), applies the policy, stores the new
     * password and signs the account out everywhere. Returns the users row.
     */
    public static function completeReset(string $token, string $newPassword, Request $req): array
    {
        RateLimiter::enforce('password', 'reset-ip' . RateLimiter::ipSubject($req->ip()));
        $token = trim($token);
        $invalid = new ApiException('TOKEN_INVALID', 'This reset link is invalid or has expired. Please request a new one.', 400);
        if (!preg_match('/^[A-Za-z0-9]{20,100}$/', $token)) {
            throw $invalid;
        }
        $row = Db::one('SELECT * FROM password_resets WHERE token_hash = ?', [hash('sha256', $token)]);
        if ($row === null || $row['used_at'] !== null || (string) $row['expires_at'] <= Db::now()) {
            throw $invalid;
        }
        $user = Db::one("SELECT * FROM users WHERE id = ? AND status = 'active' AND deleted_at IS NULL", [(int) $row['user_id']]);
        if ($user === null) {
            throw $invalid;
        }
        self::assertAcceptable($newPassword, (string) $user['username'], $user['email'] ?? null);
        // Claim the token atomically so two concurrent submissions cannot both succeed.
        $claimed = Db::run('UPDATE password_resets SET used_at = ? WHERE id = ? AND used_at IS NULL', [Db::now(), (int) $row['id']])->rowCount();
        if ($claimed !== 1) {
            throw $invalid;
        }
        $uid = (int) $user['id'];
        Db::transaction(static function () use ($uid, $newPassword): void {
            self::store($uid, $newPassword);
        });
        // Signed out everywhere: every session AND every API token (a leaked token must not
        // survive the owner taking the account back).
        $counts = Auth::signOutEverywhere($uid, 'password_reset');
        Audit::log('auth.password_reset', ['user_id' => $uid, 'target_type' => 'user', 'target_id' => $uid, 'owner_id' => $uid, 'meta' => [
            'via' => 'email', 'sessions_revoked' => $counts['sessions_revoked'], 'api_clients_revoked' => $counts['tokens_revoked'],
        ]]);
        $signedOut = Auth::describeSignOut($counts);
        self::notifySecurity($uid, 'security.password_reset', 'Your password was reset',
            'Your FastTransfer password was reset using a link sent to your e-mail address' . ($signedOut !== '' ? '; ' . $signedOut : '')
            . '. If this was not you, contact an administrator straight away.',
            ['sessions_revoked' => $counts['sessions_revoked'], 'tokens_revoked' => $counts['tokens_revoked']]);
        return Db::one('SELECT * FROM users WHERE id = ?', [$uid]) ?? $user;
    }

    /** Queue handler: e-mail the reset code/link (A5 Mailer; fails soft when unavailable). */
    public static function sendResetMailJob(array $payload): void
    {
        $uid = (int) ($payload['user_id'] ?? 0);
        $token = Secrets::decrypt(is_string($payload['token_enc'] ?? null) ? $payload['token_enc'] : null);
        if ($uid <= 0 || $token === null) {
            return;
        }
        $user = Db::one("SELECT id, username, display_name, email FROM users WHERE id = ? AND status = 'active' AND deleted_at IS NULL", [$uid]);
        if ($user === null || empty($user['email'])) {
            return;
        }
        $mailer = 'FT\\Notifications\\Mailer';
        try {
            $available = class_exists($mailer) && method_exists($mailer, 'send');
        } catch (\Throwable) {
            $available = false;
        }
        if (!$available) {
            Logger::warning('mail', 'Password reset e-mail not sent: no mailer available');
            return;
        }
        $site = Settings::string('site_name', 'FastTransfer') ?: 'FastTransfer';
        $name = (string) (($user['display_name'] ?? '') !== '' ? $user['display_name'] : $user['username']);
        $lines = [
            "Hello {$name},",
            '',
            "Someone (hopefully you) asked to reset the password for your {$site} account \"{$user['username']}\".",
            '',
        ];
        $base = is_string($payload['base_url'] ?? null) ? $payload['base_url'] : null;
        if ($base !== null && preg_match('~^https?://~i', $base)) {
            $lines[] = 'Choose a new password here (the link works once and expires in 1 hour):';
            $lines[] = $base . 'login?reset=' . rawurlencode($token);
            $lines[] = '';
            $lines[] = 'Or open the sign-in page, choose "Forgotten your password?" > "I have a reset code" and paste this code:';
        } else {
            $lines[] = 'Open the sign-in page, choose "Forgotten your password?" > "I have a reset code" and paste this code (it works once and expires in 1 hour):';
        }
        $lines[] = $token;
        $lines[] = '';
        $lines[] = 'If you did not ask for this, you can ignore this e-mail; your password will not change.';
        $lines[] = '';
        $lines[] = "— {$site}";
        try {
            $mailer::send((string) $user['email'], "Reset your {$site} password", implode("\n", $lines));
        } catch (\Throwable $e) {
            Logger::warning('mail', 'Password reset e-mail failed', ['error' => $e->getMessage()]);
        }
    }

    // ------------------------------------------------------------------ helpers

    /** Security notification via A5 (guarded: the notification module may be absent). */
    public static function notifySecurity(int $userId, string $type, string $title, string $body = '', array $data = [], ?string $dedupe = null): void
    {
        $notifier = 'FT\\Notifications\\Notifier';
        try {
            if (!class_exists($notifier)) {
                return;
            }
            $notifier::notify($userId, 'security', $type, $title, $body, $data + ['link' => '#/security'], $dedupe, RequestContext::userId());
        } catch (\Throwable $e) {
            Logger::warning('auth', 'Security notification failed', ['error' => $e->getMessage()]);
        }
    }
}
