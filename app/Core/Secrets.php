<?php
declare(strict_types=1);

namespace FT\Core;

/**
 * Small-secret encryption (TOTP secrets, secret settings such as a Slack webhook override)
 * using AES-256-GCM with a key derived from APP_KEY. File contents use FT\Storage\Crypto.
 *
 * APP_KEY formats accepted: "base64:<44 chars>", 64 hex chars, or any string >= 32 chars.
 */
final class Secrets
{
    private static ?string $key = null;

    public static function isConfigured(): bool
    {
        return strlen(self::rawAppKey()) >= 32;
    }

    public static function encrypt(string $plain): string
    {
        $nonce = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($plain, 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, $nonce, $tag, 'ft-secret-v1', 16);
        if ($ct === false) {
            throw new \RuntimeException('Encryption failed');
        }
        return 'v1:' . base64_encode($nonce . $tag . $ct);
    }

    public static function decrypt(?string $encoded): ?string
    {
        if ($encoded === null || $encoded === '' || !str_starts_with($encoded, 'v1:')) {
            return null;
        }
        $raw = base64_decode(substr($encoded, 3), true);
        if ($raw === false || strlen($raw) < 29) {
            return null;
        }
        $pt = openssl_decrypt(substr($raw, 28), 'aes-256-gcm', self::key(), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16), 'ft-secret-v1');
        return $pt === false ? null : $pt;
    }

    /** Keyed hash for tokens/identifiers that must not be reversible (e.g. client ids). */
    public static function hmac(string $data, string $purpose = 'generic'): string
    {
        return hash_hmac('sha256', $purpose . '|' . $data, self::key());
    }

    /** Random URL-safe token (base62-ish) of $length characters. */
    public static function token(int $length = 32): string
    {
        $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        $out = '';
        $max = strlen($alphabet) - 1;
        for ($i = 0; $i < $length; $i++) {
            $out .= $alphabet[random_int(0, $max)];
        }
        return $out;
    }

    private static function key(): string
    {
        if (self::$key !== null) {
            return self::$key;
        }
        $raw = self::rawAppKey();
        if (strlen($raw) < 32) {
            throw new \RuntimeException('APP_KEY is missing or too short. Set APP_KEY in .env (see .env.example).');
        }
        return self::$key = hash_hkdf('sha256', $raw, 32, 'ft-app-secrets');
    }

    private static function rawAppKey(): string
    {
        $k = (string) Config::get('app.key');
        if (str_starts_with($k, 'base64:')) {
            $d = base64_decode(substr($k, 7), true);
            return $d === false ? '' : $d;
        }
        if (strlen($k) === 64 && ctype_xdigit($k)) {
            return (string) hex2bin($k);
        }
        return $k;
    }

    /** For tests after Env::set('APP_KEY', …). */
    public static function reset(): void
    {
        self::$key = null;
    }
}
