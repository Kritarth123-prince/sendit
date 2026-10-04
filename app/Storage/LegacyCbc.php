<?php
declare(strict_types=1);

namespace FT\Storage;

use FT\Core\Config;

/**
 * Read-only support for the pre-upgrade encryption format "legacy_cbc" (§8.2).
 *
 * The single-file app stored encrypted uploads as ASCII text:
 *     base64(iv[16]) . "::" . base64(AES-256-CBC/PKCS#7 ciphertext)
 * with the key as 64 hex characters in uploads/.enc_key (LEGACY_ENCRYPTION_KEY_FILE).
 *
 * Unlike the legacy code this class NEVER creates a missing key file (the old app did, which
 * made recovery impossible) and never writes anything. CBC is unauthenticated, so callers that
 * need integrity compare the plaintext SHA-256 with the value recorded at import time
 * (BlobStore::importLegacyCbc / reencode do). BlobReader streams these blobs window by window,
 * so large legacy files never have to fit in memory.
 */
final class LegacyCbc
{
    /** Upper bound for the whole-file helpers below (BlobReader streams instead). */
    public const MAX_WHOLE_FILE_BYTES = 48 * 1024 * 1024;

    private static ?string $key = null;
    private static ?string $override = null;

    /** True when a usable legacy key is configured. */
    public static function available(): bool
    {
        try {
            self::key();
            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /** Raw 32-byte legacy key. */
    public static function key(): string
    {
        if (self::$override !== null) {
            return self::$override;
        }
        if (self::$key !== null) {
            return self::$key;
        }
        $file = (string) Config::get('encryption.legacy_key_file', '');
        if ($file === '' || !is_file($file) || !is_readable($file)) {
            throw new \RuntimeException('The legacy encryption key file is not available');
        }
        $hex = trim((string) @file_get_contents($file, false, null, 0, 1024));
        if (strlen($hex) !== 64 || !ctype_xdigit($hex)) {
            throw new \RuntimeException('The legacy encryption key file is malformed');
        }
        return self::$key = (string) hex2bin($hex);
    }

    /** Test hook: use this hex key instead of the key file (null restores normal behaviour). */
    public static function useKey(?string $hexKey): void
    {
        if ($hexKey !== null && (strlen($hexKey) !== 64 || !ctype_xdigit($hexKey))) {
            throw new \InvalidArgumentException('Legacy key must be 64 hex characters');
        }
        self::$override = $hexKey !== null ? (string) hex2bin($hexKey) : null;
        self::$key = null;
    }

    /** The legacy detection rule (first 80 bytes look like "base64::base64"). */
    public static function looksEncrypted(string $head): bool
    {
        return (bool) preg_match('~^[A-Za-z0-9+/]+=*::[A-Za-z0-9+/]~', substr($head, 0, 80));
    }

    public static function isEncryptedFile(string $path): bool
    {
        $h = @fopen($path, 'rb');
        if ($h === false) {
            return false;
        }
        $head = (string) fread($h, 80);
        fclose($h);
        return self::looksEncrypted($head);
    }

    /** Decrypt a whole legacy file (bounded in size; prefer BlobReader for streaming). */
    public static function decryptFile(string $path): string
    {
        $size = @filesize($path);
        if ($size === false) {
            throw new \RuntimeException('Legacy file is missing');
        }
        if ($size > self::MAX_WHOLE_FILE_BYTES) {
            throw new \RuntimeException('Legacy file is too large to decrypt in memory');
        }
        $raw = @file_get_contents($path);
        if ($raw === false) {
            throw new \RuntimeException('Legacy file could not be read');
        }
        return self::decryptString($raw);
    }

    /** Decrypt "base64(iv)::base64(ct)" text; throws on any format or padding error. */
    public static function decryptString(string $raw): string
    {
        $raw = rtrim($raw);
        $sep = strpos($raw, '::');
        if ($sep === false || $sep > 80) {
            throw new \RuntimeException('Not a legacy encrypted file');
        }
        $iv = base64_decode(substr($raw, 0, $sep), true);
        $ct = base64_decode(substr($raw, $sep + 2), true);
        if ($iv === false || strlen($iv) !== 16 || $ct === false || $ct === '' || strlen($ct) % 16 !== 0) {
            throw new \RuntimeException('Legacy encrypted file is malformed');
        }
        $pt = openssl_decrypt($ct, 'aes-256-cbc', self::key(), OPENSSL_RAW_DATA, $iv);
        if ($pt === false) {
            throw new \RuntimeException('Legacy decryption failed (wrong key or damaged file)');
        }
        return $pt;
    }

    /**
     * Produce the legacy format. Only used to build test fixtures and to verify imports — new
     * data is never written in this format.
     */
    public static function encryptString(string $plain, string $rawKey): string
    {
        $iv = random_bytes(16);
        $ct = openssl_encrypt($plain, 'aes-256-cbc', $rawKey, OPENSSL_RAW_DATA, $iv);
        if ($ct === false) {
            throw new \RuntimeException('Encryption failed');
        }
        return base64_encode($iv) . '::' . base64_encode($ct);
    }
}
