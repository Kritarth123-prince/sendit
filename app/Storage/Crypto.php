<?php
declare(strict_types=1);

namespace FT\Storage;

use FT\Core\Config;

/**
 * File-content encryption at rest — format "gcm1" (docs/ARCHITECTURE.md §8.1).
 *
 * Envelope encryption: every blob gets its own random 32-byte data key (DEK). The DEK encrypts
 * the content with AES-256-GCM in 1 MiB chunks, and is itself stored wrapped (AES-256-GCM) by
 * the master key (KEK) from ENCRYPTION_KEY. Rotating the KEK therefore only re-wraps 60-byte
 * DEKs instead of re-encrypting every file (see BlobStore::reencode()).
 *
 *   Header (32 bytes): "FTG1" | 0x01 | 20 (log2 chunk) | 0x0000 | base_nonce(12) | uint64 BE plaintext size | 0x00000000
 *   Chunk i:           AES-256-GCM(DEK, nonce_i, plaintext_i, aad_i) ciphertext || tag(16)
 *                      nonce_i = base_nonce XOR uint32 BE i (right-aligned)
 *                      aad_i   = header || uint32 BE i || final flag (1 byte)
 *   DEK wrap:          base64(nonce(12) || tag(16) || AES-256-GCM(KEK, DEK, aad = "ft-dek|<key_id>"))
 *
 * The header is part of every chunk's AAD and the final flag marks the last chunk, so any
 * modification, reordering, truncation (missing final chunk) or extension is detected. Readers
 * must never return plaintext from a chunk whose tag failed (BlobReader enforces this).
 *
 * Keys never leave this class except as derived per-purpose keys; they are never logged.
 */
final class Crypto
{
    public const MAGIC = 'FTG1';
    public const FORMAT_VERSION = 1;
    public const CHUNK_LOG2 = 20;
    public const CHUNK_BYTES = 1048576;
    public const HEADER_BYTES = 32;
    public const TAG_BYTES = 16;

    private const CIPHER = 'aes-256-gcm';
    private const STRING_MAGIC = 'FTS1';
    private const KEK_INFO = 'ft-kek-v1';

    /** @var array<string,string>|null key id => 32-byte KEK */
    private static ?array $keys = null;
    private static ?string $currentId = null;

    // ------------------------------------------------------------------ configuration

    /** Encryption is on when enabled in .env AND a usable master key is configured. */
    public static function enabled(): bool
    {
        return (bool) Config::get('encryption.enabled') && self::currentKeyId() !== null;
    }

    /** Id of the key new data is wrapped with, or null when no valid ENCRYPTION_KEY exists. */
    public static function currentKeyId(): ?string
    {
        self::load();
        return self::$currentId;
    }

    /** True when $keyId (current or one of ENCRYPTION_OLD_KEYS) can be used for reading. */
    public static function hasKey(string $keyId): bool
    {
        self::load();
        return isset(self::$keys[$keyId]);
    }

    /** Forget cached keys (tests, or after Env::set + Config::reset). */
    public static function reset(): void
    {
        self::$keys = null;
        self::$currentId = null;
    }

    /**
     * Normalise a configured key into 32 raw bytes:
     * "base64:<32 bytes>", 64 hex characters, or any string of ≥ 32 characters (stretched with
     * HKDF-SHA256 so a passphrase-like value still yields a uniformly random key).
     */
    public static function parseKey(string $raw): ?string
    {
        $raw = trim($raw);
        if ($raw === '') {
            return null;
        }
        if (str_starts_with($raw, 'base64:')) {
            $decoded = base64_decode(substr($raw, 7), true);
            if ($decoded === false) {
                return null;
            }
            if (strlen($decoded) === 32) {
                return $decoded;
            }
            return strlen($decoded) >= 32 ? hash_hkdf('sha256', $decoded, 32, self::KEK_INFO) : null;
        }
        if (strlen($raw) === 64 && ctype_xdigit($raw)) {
            return (string) hex2bin($raw);
        }
        return strlen($raw) >= 32 ? hash_hkdf('sha256', $raw, 32, self::KEK_INFO) : null;
    }

    // ------------------------------------------------------------------ data keys

    /** @return array{enc_key_id:string, enc_dek:string} the DEK wrapped by the current (or given) KEK */
    public static function wrapDek(string $dek, ?string $keyId = null): array
    {
        if (strlen($dek) !== 32) {
            throw new \InvalidArgumentException('A data key must be 32 bytes');
        }
        $keyId ??= self::requireCurrentId();
        $nonce = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($dek, self::CIPHER, self::kek($keyId), OPENSSL_RAW_DATA, $nonce, $tag, 'ft-dek|' . $keyId, self::TAG_BYTES);
        if ($ct === false || strlen($tag) !== self::TAG_BYTES) {
            throw new \RuntimeException('Data key wrapping failed');
        }
        return ['enc_key_id' => $keyId, 'enc_dek' => base64_encode($nonce . $tag . $ct)];
    }

    public static function unwrapDek(string $keyId, string $encDek): string
    {
        $raw = base64_decode($encDek, true);
        if ($raw === false || strlen($raw) !== 12 + self::TAG_BYTES + 32) {
            throw new \RuntimeException('The encrypted data key is malformed');
        }
        $dek = openssl_decrypt(substr($raw, 28), self::CIPHER, self::kek($keyId), OPENSSL_RAW_DATA, substr($raw, 0, 12), substr($raw, 12, 16), 'ft-dek|' . $keyId);
        if ($dek === false || strlen($dek) !== 32) {
            throw new \RuntimeException('The data key could not be unwrapped (wrong or changed master key)');
        }
        return $dek;
    }

    // ------------------------------------------------------------------ gcm1 primitives

    public static function chunkCount(int $plainSize): int
    {
        return max(1, intdiv($plainSize + self::CHUNK_BYTES - 1, self::CHUNK_BYTES));
    }

    /** Exact stored size of a gcm1 stream for a plaintext of $plainSize bytes. */
    public static function encryptedSize(int $plainSize): int
    {
        return self::HEADER_BYTES + $plainSize + self::TAG_BYTES * self::chunkCount($plainSize);
    }

    public static function header(int $plainSize, string $baseNonce): string
    {
        if (strlen($baseNonce) !== 12 || $plainSize < 0) {
            throw new \InvalidArgumentException('Invalid gcm1 header parameters');
        }
        return self::MAGIC . chr(self::FORMAT_VERSION) . chr(self::CHUNK_LOG2) . "\0\0" . $baseNonce . pack('J', $plainSize) . "\0\0\0\0";
    }

    /** @return array{base_nonce:string, plain_size:int} */
    public static function parseHeader(string $header): array
    {
        if (strlen($header) !== self::HEADER_BYTES || substr($header, 0, 4) !== self::MAGIC) {
            throw new \RuntimeException('Not a gcm1 stream');
        }
        if (ord($header[4]) !== self::FORMAT_VERSION || ord($header[5]) !== self::CHUNK_LOG2) {
            throw new \RuntimeException('Unsupported gcm1 version or chunk size');
        }
        $size = unpack('J', substr($header, 20, 8));
        if (!is_array($size) || !is_int($size[1]) || $size[1] < 0) {
            throw new \RuntimeException('Invalid gcm1 plaintext size');
        }
        return ['base_nonce' => substr($header, 8, 12), 'plain_size' => $size[1]];
    }

    public static function chunkNonce(string $baseNonce, int $index): string
    {
        return substr($baseNonce, 0, 8) . (substr($baseNonce, 8, 4) ^ pack('N', $index));
    }

    /** @return string ciphertext || tag */
    public static function encryptChunk(string $dek, string $header, int $index, string $plain, bool $final): string
    {
        $tag = '';
        $ct = openssl_encrypt($plain, self::CIPHER, $dek, OPENSSL_RAW_DATA, self::chunkNonce(substr($header, 8, 12), $index), $tag,
            $header . pack('N', $index) . ($final ? "\x01" : "\x00"), self::TAG_BYTES);
        if ($ct === false || strlen($tag) !== self::TAG_BYTES) {
            throw new \RuntimeException('Encryption failed');
        }
        return $ct . $tag;
    }

    /** Decrypt one chunk (ciphertext || tag); throws on any authentication failure. */
    public static function decryptChunk(string $dek, string $header, int $index, string $data, bool $final): string
    {
        if (strlen($data) < self::TAG_BYTES) {
            throw new \RuntimeException('Encrypted chunk is truncated');
        }
        $pt = openssl_decrypt(substr($data, 0, -self::TAG_BYTES), self::CIPHER, $dek, OPENSSL_RAW_DATA,
            self::chunkNonce(substr($header, 8, 12), $index), substr($data, -self::TAG_BYTES),
            $header . pack('N', $index) . ($final ? "\x01" : "\x00"));
        if ($pt === false) {
            throw new \RuntimeException('Integrity check failed: the stored file was modified or damaged');
        }
        return $pt;
    }

    // ------------------------------------------------------------------ streaming encryption

    /**
     * Begin a streaming gcm1 encryption of exactly $plainSize bytes. Ciphertext is handed to
     * $write (string): void in order; memory use stays at about one chunk.
     * @return array<string,mixed> opaque state for feedEncrypt()/finishEncrypt()
     */
    public static function beginEncrypt(int $plainSize, callable $write): array
    {
        $dek = random_bytes(32);
        $header = self::header($plainSize, random_bytes(12));
        $write($header);
        return [
            'dek' => $dek, 'header' => $header, 'size' => $plainSize, 'chunks' => self::chunkCount($plainSize),
            'index' => 0, 'buf' => '', 'fed' => 0, 'stored' => self::HEADER_BYTES, 'write' => $write,
        ];
    }

    public static function feedEncrypt(array &$st, string $plain): void
    {
        if ($plain === '') {
            return;
        }
        $st['fed'] += strlen($plain);
        if ($st['fed'] > $st['size']) {
            throw new \RuntimeException('More data than declared was supplied for encryption');
        }
        $st['buf'] .= $plain;
        // Emit every full chunk except the last one (the final chunk is emitted by finishEncrypt
        // because its AAD carries the final flag).
        while (strlen($st['buf']) >= self::CHUNK_BYTES && $st['index'] < $st['chunks'] - 1) {
            $chunk = substr($st['buf'], 0, self::CHUNK_BYTES);
            $st['buf'] = (string) substr($st['buf'], self::CHUNK_BYTES);
            $out = self::encryptChunk($st['dek'], $st['header'], $st['index'], $chunk, false);
            ($st['write'])($out);
            $st['stored'] += strlen($out);
            $st['index']++;
        }
    }

    /** @return array{encryption:string, enc_key_id:string, enc_dek:string, stored_size:int} */
    public static function finishEncrypt(array &$st): array
    {
        $lastLen = $st['size'] - ($st['chunks'] - 1) * self::CHUNK_BYTES;
        if ($st['fed'] !== $st['size'] || $st['index'] !== $st['chunks'] - 1 || strlen($st['buf']) !== $lastLen) {
            throw new \RuntimeException('Encryption input size mismatch');
        }
        $out = self::encryptChunk($st['dek'], $st['header'], $st['index'], $st['buf'], true);
        ($st['write'])($out);
        $st['stored'] += strlen($out);
        $st['buf'] = '';
        $wrapped = self::wrapDek($st['dek']);
        $st['dek'] = '';
        if ($st['stored'] !== self::encryptedSize($st['size'])) {
            throw new \RuntimeException('Encrypted size mismatch');
        }
        return ['encryption' => 'gcm1', 'enc_key_id' => $wrapped['enc_key_id'], 'enc_dek' => $wrapped['enc_dek'], 'stored_size' => $st['stored']];
    }

    /**
     * Encrypt a plaintext file into a SEGMENTED gcm1 stream at base path $dst ($dst.0, $dst.1, …,
     * each ≤ BlobStore::SEGMENT_BYTES) — physical files never exceed the host's file-size cap.
     * @return array{enc_key_id:string, enc_dek:string, stored_size:int, encryption:string}
     */
    public static function encryptFile(string $src, string $dst): array
    {
        self::requireCurrentId();
        $in = @fopen($src, 'rb');
        if ($in === false) {
            throw new \RuntimeException('Cannot open the file to encrypt');
        }
        $w = BlobStore::segmentWriter($dst);
        try {
            $size = (int) fstat($in)['size'];
            $st = self::beginEncrypt($size, static function (string $b) use (&$w): void {
                BlobStore::segmentWrite($w, $b);
            });
            while (!feof($in)) {
                $piece = fread($in, self::CHUNK_BYTES);
                if ($piece === false) {
                    throw new \RuntimeException('Read error while encrypting');
                }
                self::feedEncrypt($st, $piece);
            }
            $meta = self::finishEncrypt($st);
            BlobStore::segmentClose($w);
            return $meta;
        } catch (\Throwable $e) {
            BlobStore::segmentAbort($w);
            throw $e;
        } finally {
            fclose($in);
        }
    }

    /**
     * Open a gcm1 stream for reading. $path is a segmented base path ($path.0, $path.1, …) or a
     * single file. Every chunk is authenticated as it is read.
     */
    public static function openDecryptStream(string $path, string $keyId, string $encDek): BlobReader
    {
        $files = [];
        if (is_file($path . '.0')) {
            for ($i = 0; is_file($path . '.' . $i); $i++) {
                $files[] = $path . '.' . $i;
            }
        } elseif (is_file($path)) {
            $files[] = $path;
        } else {
            throw new \RuntimeException('Stored file is missing or damaged');
        }
        return BlobReader::fromFiles($files, 'gcm1', $keyId, $encDek, null);
    }

    // ------------------------------------------------------------------ derived keys / small strings

    /** Per-purpose key derived (HKDF-SHA256) from the current master key, e.g. "thumb:<fileId>". */
    public static function deriveKey(string $purpose): string
    {
        return self::deriveFor(self::requireCurrentId(), $purpose);
    }

    /**
     * Encrypt a small value (thumbnails, cached previews) with a key derived for $purpose.
     * Format: "FTS1" | len(key id) | key id | nonce(12) | tag(16) | ciphertext. The key id is
     * embedded so values stay readable after a KEK rotation while the old key is configured.
     */
    public static function encryptString(string $data, string $purpose): string
    {
        $keyId = self::requireCurrentId();
        $nonce = random_bytes(12);
        $tag = '';
        $ct = openssl_encrypt($data, self::CIPHER, self::deriveFor($keyId, $purpose), OPENSSL_RAW_DATA, $nonce, $tag, 'ft-str|' . $purpose . '|' . $keyId, self::TAG_BYTES);
        if ($ct === false) {
            throw new \RuntimeException('Encryption failed');
        }
        return self::STRING_MAGIC . chr(strlen($keyId)) . $keyId . $nonce . $tag . $ct;
    }

    public static function decryptString(string $data, string $purpose): string
    {
        if (!self::isEncryptedString($data)) {
            throw new \RuntimeException('Not an encrypted value');
        }
        $idLen = ord($data[4]);
        $keyId = substr($data, 5, $idLen);
        $p = 5 + $idLen;
        if (strlen($data) < $p + 28) {
            throw new \RuntimeException('Encrypted value is truncated');
        }
        $pt = openssl_decrypt(substr($data, $p + 28), self::CIPHER, self::deriveFor($keyId, $purpose), OPENSSL_RAW_DATA,
            substr($data, $p, 12), substr($data, $p + 12, 16), 'ft-str|' . $purpose . '|' . $keyId);
        if ($pt === false) {
            throw new \RuntimeException('Integrity check failed');
        }
        return $pt;
    }

    public static function isEncryptedString(string $data): bool
    {
        return strlen($data) >= 5 && substr($data, 0, 4) === self::STRING_MAGIC;
    }

    // ------------------------------------------------------------------ internals

    private static function deriveFor(string $keyId, string $purpose): string
    {
        return hash_hkdf('sha256', self::kek($keyId), 32, 'ft-derive|' . $purpose);
    }

    private static function requireCurrentId(): string
    {
        $id = self::currentKeyId();
        if ($id === null) {
            throw new \RuntimeException('Encryption is not configured (ENCRYPTION_KEY is missing or invalid)');
        }
        return $id;
    }

    private static function kek(string $keyId): string
    {
        self::load();
        if (!isset(self::$keys[$keyId])) {
            throw new \RuntimeException('Unknown encryption key id; add the old key to ENCRYPTION_OLD_KEYS');
        }
        return self::$keys[$keyId];
    }

    private static function load(): void
    {
        if (self::$keys !== null) {
            return;
        }
        $keys = [];
        $current = null;
        $id = trim((string) Config::get('encryption.key_id', 'k1'));
        $kek = self::parseKey((string) Config::get('encryption.key', ''));
        if ($kek !== null && self::validId($id)) {
            $keys[$id] = $kek;
            $current = $id;
        }
        // "id:key,id2:key2" — split on the FIRST colon only ("old:base64:…" is valid).
        foreach (explode(',', (string) Config::get('encryption.old_keys', '')) as $entry) {
            $entry = trim($entry);
            $colon = strpos($entry, ':');
            if ($entry === '' || $colon === false) {
                continue;
            }
            $oid = trim(substr($entry, 0, $colon));
            if (!self::validId($oid) || isset($keys[$oid])) {
                continue;
            }
            $k = self::parseKey(substr($entry, $colon + 1));
            if ($k !== null) {
                $keys[$oid] = $k;
            }
        }
        self::$keys = $keys;
        self::$currentId = $current;
    }

    private static function validId(string $id): bool
    {
        return (bool) preg_match('/^[A-Za-z0-9_-]{1,16}$/', $id);
    }
}
