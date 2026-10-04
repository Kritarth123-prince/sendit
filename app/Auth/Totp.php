<?php
declare(strict_types=1);

namespace FT\Auth;

use FT\Core\Db;
use FT\Core\Secrets;
use FT\Core\Settings;

/**
 * Time-based one-time passwords (RFC 6238 over RFC 4226): HMAC-SHA1, 6 digits, 30-second steps,
 * accepting one step either side for clock drift.
 *
 * Replay protection: the last accepted time-step is stored in users.totp_last_step and only a
 * strictly later step is accepted afterwards. The update is a compare-and-set, so two concurrent
 * requests carrying the same code cannot both succeed.
 *
 * Secrets are 160-bit, Base32 encoded and stored encrypted with FT\Core\Secrets (APP_KEY).
 * The client renders the otpauth:// URI as a QR code locally — never through a third party.
 *
 * Recovery codes: 10 single-use codes ("k7m2p-x9q4r"), shown once; only keyed hashes are stored.
 */
final class Totp
{
    public const DIGITS = 6;
    public const PERIOD = 30;
    public const WINDOW = 1;
    public const RECOVERY_CODES = 10;

    private const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    private const RECOVERY_ALPHABET = 'abcdefghjkmnpqrstuvwxyz23456789';

    // ------------------------------------------------------------------ RFC 6238 primitives

    public static function generateSecret(): string
    {
        return self::base32Encode(random_bytes(20));
    }

    /** The code for a time-step (or for "now" when $step is null). */
    public static function code(string $secretBase32, ?int $step = null): string
    {
        $key = self::base32Decode($secretBase32);
        $step ??= self::currentStep();
        $counter = pack('N2', ($step >> 32) & 0xFFFFFFFF, $step & 0xFFFFFFFF);
        $hash = hash_hmac('sha1', $counter, $key, true);
        $offset = ord($hash[19]) & 0x0F;
        $bin = ((ord($hash[$offset]) & 0x7F) << 24)
            | ((ord($hash[$offset + 1]) & 0xFF) << 16)
            | ((ord($hash[$offset + 2]) & 0xFF) << 8)
            | (ord($hash[$offset + 3]) & 0xFF);
        return str_pad((string) ($bin % (10 ** self::DIGITS)), self::DIGITS, '0', STR_PAD_LEFT);
    }

    public static function currentStep(?int $time = null): int
    {
        return intdiv($time ?? time(), self::PERIOD);
    }

    /**
     * Check a code against the secret within ±WINDOW steps. Returns the matching step, or null.
     * Steps at or before $lastStep are rejected (replay protection).
     */
    public static function match(string $secretBase32, string $code, ?int $lastStep = null, ?int $time = null): ?int
    {
        $code = preg_replace('/\s+/', '', $code) ?? '';
        if (!preg_match('/^\d{' . self::DIGITS . '}$/', $code)) {
            return null;
        }
        $now = self::currentStep($time);
        $found = null;
        // Check every step in the window (no early exit) so timing does not reveal which matched.
        for ($i = -self::WINDOW; $i <= self::WINDOW; $i++) {
            $step = $now + $i;
            if (hash_equals(self::code($secretBase32, $step), $code) && ($lastStep === null || $step > $lastStep)) {
                $found ??= $step;
            }
        }
        return $found;
    }

    /** otpauth:// URI for authenticator apps (Google Authenticator, Aegis, 1Password, …). */
    public static function uri(string $secretBase32, string $account, ?string $issuer = null): string
    {
        $issuer = trim((string) ($issuer ?? Settings::string('site_name', 'FastTransfer'))) ?: 'FastTransfer';
        $label = rawurlencode($issuer) . ':' . rawurlencode($account);
        return 'otpauth://totp/' . $label . '?' . http_build_query([
            'secret'    => $secretBase32,
            'issuer'    => $issuer,
            'algorithm' => 'SHA1',
            'digits'    => self::DIGITS,
            'period'    => self::PERIOD,
        ], '', '&', PHP_QUERY_RFC3986);
    }

    // ------------------------------------------------------------------ per-user operations

    /** Decrypted secret of a users row, or null. */
    public static function secretFor(array $userRow): ?string
    {
        $secret = Secrets::decrypt(isset($userRow['totp_secret_enc']) ? (string) $userRow['totp_secret_enc'] : null);
        return ($secret !== null && preg_match('/^[A-Z2-7]{16,128}$/', $secret)) ? $secret : null;
    }

    /**
     * Verify a TOTP code for a user and consume its time-step atomically.
     * Works for the pending secret during setup as well (totp_enabled = 0).
     */
    public static function verifyForUser(array $userRow, string $code): bool
    {
        $secret = self::secretFor($userRow);
        if ($secret === null) {
            return false;
        }
        $last = isset($userRow['totp_last_step']) && $userRow['totp_last_step'] !== null ? (int) $userRow['totp_last_step'] : null;
        $step = self::match($secret, $code, $last);
        if ($step === null) {
            return false;
        }
        $n = Db::run(
            'UPDATE users SET totp_last_step = :s WHERE id = :id AND (totp_last_step IS NULL OR totp_last_step < :s2)',
            ['s' => $step, 'id' => (int) $userRow['id'], 's2' => $step]
        )->rowCount();
        return $n === 1;
    }

    /** @return string[] fresh recovery codes (plain, to show once) — stores their hashes. */
    public static function regenerateRecoveryCodes(int $userId): array
    {
        $codes = [];
        $max = strlen(self::RECOVERY_ALPHABET) - 1;
        while (count($codes) < self::RECOVERY_CODES) {
            $s = '';
            for ($i = 0; $i < 10; $i++) {
                $s .= self::RECOVERY_ALPHABET[random_int(0, $max)];
            }
            $codes[substr($s, 0, 5) . '-' . substr($s, 5)] = true;
        }
        $codes = array_keys($codes);
        $hashes = array_map(static fn (string $c): string => self::recoveryHash($userId, $c), $codes);
        Db::update('users', ['recovery_codes_enc' => json_encode(['v' => 1, 'codes' => $hashes])], ['id' => $userId]);
        return $codes;
    }

    /** Consume a recovery code (single use; compare-and-set so it cannot be used twice). */
    public static function useRecoveryCode(array $userRow, string $code): bool
    {
        $norm = self::normaliseRecovery($code);
        if ($norm === null) {
            return false;
        }
        $uid = (int) $userRow['id'];
        $raw = Db::value('SELECT recovery_codes_enc FROM users WHERE id = ?', [$uid]);
        $data = json_decode((string) $raw, true);
        $hashes = is_array($data) && is_array($data['codes'] ?? null) ? array_values($data['codes']) : [];
        $want = self::recoveryHash($uid, $norm);
        $hit = null;
        foreach ($hashes as $i => $h) {
            if (is_string($h) && hash_equals($h, $want)) {
                $hit = $i;
            }
        }
        if ($hit === null) {
            return false;
        }
        unset($hashes[$hit]);
        $n = Db::run(
            'UPDATE users SET recovery_codes_enc = :new WHERE id = :id AND recovery_codes_enc = :old',
            ['new' => json_encode(['v' => 1, 'codes' => array_values($hashes)]), 'id' => $uid, 'old' => (string) $raw]
        )->rowCount();
        return $n === 1;
    }

    public static function remainingRecoveryCodes(array $userRow): int
    {
        $data = json_decode((string) ($userRow['recovery_codes_enc'] ?? ''), true);
        return is_array($data) && is_array($data['codes'] ?? null) ? count($data['codes']) : 0;
    }

    /** Verify either a 6-digit TOTP code or a recovery code. Returns 'totp', 'recovery' or null. */
    public static function verifyAny(array $userRow, ?string $code, ?string $recoveryCode): ?string
    {
        $code = trim((string) $code);
        $recoveryCode = trim((string) $recoveryCode);
        if ($code !== '' && preg_match('/^\d[\d\s]*$/', $code)) {
            return self::verifyForUser($userRow, $code) ? 'totp' : null;
        }
        $candidate = $recoveryCode !== '' ? $recoveryCode : $code;
        if ($candidate !== '' && self::useRecoveryCode($userRow, $candidate)) {
            return 'recovery';
        }
        return null;
    }

    private static function normaliseRecovery(string $code): ?string
    {
        $c = strtolower((string) preg_replace('/[\s-]+/', '', $code));
        if (!preg_match('/^[a-z0-9]{10}$/', $c)) {
            return null;
        }
        return substr($c, 0, 5) . '-' . substr($c, 5);
    }

    private static function recoveryHash(int $userId, string $code): string
    {
        return Secrets::hmac($userId . ':' . $code, 'totp-recovery');
    }

    // ------------------------------------------------------------------ Base32 (RFC 4648)

    public static function base32Encode(string $bin): string
    {
        $out = '';
        $buffer = 0;
        $bits = 0;
        $len = strlen($bin);
        for ($i = 0; $i < $len; $i++) {
            $buffer = ($buffer << 8) | ord($bin[$i]);
            $bits += 8;
            while ($bits >= 5) {
                $bits -= 5;
                $out .= self::B32[($buffer >> $bits) & 31];
            }
            $buffer &= (1 << $bits) - 1;
        }
        if ($bits > 0) {
            $out .= self::B32[($buffer << (5 - $bits)) & 31];
        }
        return $out;
    }

    public static function base32Decode(string $b32): string
    {
        $b32 = strtoupper((string) preg_replace('/[\s=-]+/', '', $b32));
        $out = '';
        $buffer = 0;
        $bits = 0;
        $len = strlen($b32);
        for ($i = 0; $i < $len; $i++) {
            $v = strpos(self::B32, $b32[$i]);
            if ($v === false) {
                throw new \InvalidArgumentException('Invalid Base32 secret');
            }
            $buffer = ($buffer << 5) | $v;
            $bits += 5;
            if ($bits >= 8) {
                $bits -= 8;
                $out .= chr(($buffer >> $bits) & 0xFF);
            }
            $buffer &= (1 << $bits) - 1;
        }
        return $out;
    }
}
