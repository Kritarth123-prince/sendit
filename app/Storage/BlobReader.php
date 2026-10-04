<?php
declare(strict_types=1);

namespace FT\Storage;

/**
 * Random-access plaintext reader over a stored blob (§8.1a).
 *
 * The stored byte stream (plain bytes, a gcm1 stream or legacy_cbc text) is spread over segment
 * files of BlobStore::SEGMENT_BYTES. This class maps plaintext offsets to stored offsets, reads
 * across segment boundaries and decrypts on the fly:
 *   - none:       stored bytes are the plaintext;
 *   - gcm1:       1 MiB chunks, each authenticated before a single byte of it is returned;
 *   - legacy_cbc: base64 text decoded and CBC-decrypted in 1 MiB windows (the IV of a window is
 *                 the previous ciphertext block), so even large legacy files stream in constant
 *                 memory and support Range requests.
 *
 * Missing or short segments, a bad header, a size mismatch or a failed tag throw
 * RuntimeException — data is never silently truncated. Memory: about one decrypted chunk.
 */
final class BlobReader
{
    public const PIECE = 1048576;

    /** @var array<int,array{0:string,1:int,2:int}> [path, size, start offset] */
    private array $segs = [];
    private int $stored = 0;
    private string $encoding;
    private int $size = 0;
    private int $pos = 0;
    private string $label;

    // gcm1
    private string $dek = '';
    private string $header = '';
    private int $chunks = 1;

    // legacy_cbc
    private string $lkey = '';
    private string $liv = '';
    private int $lb64Start = 0;
    private int $lb64Len = 0;
    private int $lctLen = 0;

    private int $cacheIdx = -1;
    private string $cache = '';
    /** @var array<int,resource> */
    private array $fh = [];

    /**
     * Open a file_blobs row. Every segment must exist with exactly the expected size, so a
     * damaged blob fails here — before any response header has been sent.
     */
    public static function open(array $blob): self
    {
        $label = 'blob #' . (int) ($blob['id'] ?? 0);
        $stored = (int) $blob['stored_size'];
        $base = Paths::absolute((string) $blob['storage_path']);
        $seg = BlobStore::SEGMENT_BYTES;
        $n = max(1, intdiv($stored + $seg - 1, $seg));
        $files = [];
        for ($i = 0; $i < $n; $i++) {
            $expected = $i < $n - 1 ? $seg : $stored - ($n - 1) * $seg;
            $path = $base . '.' . $i;
            clearstatcache(true, $path);
            $actual = is_file($path) ? @filesize($path) : false;
            if ($actual === false || $actual !== $expected) {
                throw self::damagedFor($label);
            }
            $files[] = [$path, $expected];
        }
        return new self($files, (string) $blob['encryption'], $blob['enc_key_id'] ?? null, $blob['enc_dek'] ?? null, (int) $blob['size'], $label);
    }

    /**
     * Open an arbitrary list of physical files forming one stored stream (e.g. temp segments
     * during import verification, or Crypto::openDecryptStream()).
     * @param string[] $paths
     */
    public static function fromFiles(array $paths, string $encoding, ?string $keyId, ?string $encDek, ?int $expectedSize): self
    {
        $files = [];
        foreach ($paths as $p) {
            clearstatcache(true, $p);
            $s = is_file($p) ? @filesize($p) : false;
            if ($s === false) {
                throw self::damagedFor('stream');
            }
            $files[] = [$p, $s];
        }
        if ($files === []) {
            throw self::damagedFor('stream');
        }
        return new self($files, $encoding, $keyId, $encDek, $expectedSize, 'stream');
    }

    /** @param array<int,array{0:string,1:int}> $files */
    private function __construct(array $files, string $encoding, ?string $keyId, ?string $encDek, ?int $expectedSize, string $label)
    {
        $this->label = $label;
        $this->encoding = $encoding;
        $offset = 0;
        foreach ($files as [$path, $size]) {
            $this->segs[] = [$path, $size, $offset];
            $offset += $size;
        }
        $this->stored = $offset;

        switch ($encoding) {
            case 'none':
                $this->size = $this->stored;
                break;
            case 'gcm1':
                $this->initGcm($keyId, $encDek);
                break;
            case 'legacy_cbc':
                $this->initLegacy();
                break;
            default:
                throw new \RuntimeException('Unknown storage encoding');
        }
        if ($expectedSize !== null && $expectedSize !== $this->size) {
            $this->close();
            throw new \RuntimeException('Stored file size does not match its record (' . $this->label . ')');
        }
    }

    public function __destruct()
    {
        $this->close();
    }

    // ------------------------------------------------------------------ public API

    /** Plaintext size in bytes. */
    public function size(): int
    {
        return $this->size;
    }

    public function tell(): int
    {
        return $this->pos;
    }

    public function eof(): bool
    {
        return $this->pos >= $this->size;
    }

    public function seek(int $offset): void
    {
        if ($offset < 0 || $offset > $this->size) {
            throw new \InvalidArgumentException('Seek offset out of range');
        }
        $this->pos = $offset;
    }

    /** Read up to $length plaintext bytes from the current position ('' at EOF). */
    public function read(int $length): string
    {
        if ($length <= 0 || $this->pos >= $this->size) {
            return '';
        }
        $length = min($length, $this->size - $this->pos);
        if ($this->encoding === 'none') {
            $data = $this->readStored($this->pos, $length);
            $this->pos += $length;
            return $data;
        }
        $out = '';
        while ($length > 0) {
            $idx = intdiv($this->pos, self::PIECE);
            $piece = $this->piece($idx);
            $take = (string) substr($piece, $this->pos - $idx * self::PIECE, $length);
            if ($take === '') {
                throw $this->damaged();
            }
            $out .= $take;
            $this->pos += strlen($take);
            $length -= strlen($take);
        }
        return $out;
    }

    public function close(): void
    {
        foreach ($this->fh as $h) {
            if (is_resource($h)) {
                fclose($h);
            }
        }
        $this->fh = [];
        $this->cache = '';
        $this->cacheIdx = -1;
    }

    public function encoding(): string
    {
        return $this->encoding;
    }

    // ------------------------------------------------------------------ gcm1

    private function initGcm(?string $keyId, ?string $encDek): void
    {
        if ($keyId === null || $keyId === '' || $encDek === null || $encDek === '') {
            throw new \RuntimeException('Encrypted blob has no data key (' . $this->label . ')');
        }
        if ($this->stored < Crypto::HEADER_BYTES + Crypto::TAG_BYTES) {
            throw $this->damaged();
        }
        $this->header = $this->readStored(0, Crypto::HEADER_BYTES);
        try {
            $h = Crypto::parseHeader($this->header);
        } catch (\RuntimeException) {
            throw $this->damaged();
        }
        $this->size = $h['plain_size'];
        $this->chunks = Crypto::chunkCount($this->size);
        // Any truncation (e.g. a missing final chunk) or appended data changes the stored size.
        if ($this->stored !== Crypto::encryptedSize($this->size)) {
            throw $this->damaged();
        }
        $this->dek = Crypto::unwrapDek($keyId, $encDek);
    }

    private function gcmChunk(int $i): string
    {
        if ($i < 0 || $i >= $this->chunks) {
            throw $this->damaged();
        }
        $plainLen = $i === $this->chunks - 1 ? $this->size - $i * Crypto::CHUNK_BYTES : Crypto::CHUNK_BYTES;
        $offset = Crypto::HEADER_BYTES + $i * (Crypto::CHUNK_BYTES + Crypto::TAG_BYTES);
        $data = $this->readStored($offset, $plainLen + Crypto::TAG_BYTES);
        $pt = Crypto::decryptChunk($this->dek, $this->header, $i, $data, $i === $this->chunks - 1);
        if (strlen($pt) !== $plainLen) {
            throw $this->damaged();
        }
        return $pt;
    }

    // ------------------------------------------------------------------ legacy_cbc

    private function initLegacy(): void
    {
        $this->lkey = LegacyCbc::key();
        $head = $this->readStored(0, min($this->stored, 100));
        $sep = strpos($head, '::');
        if ($sep === false || $sep > 80) {
            throw $this->damaged();
        }
        $iv = base64_decode(substr($head, 0, $sep), true);
        if ($iv === false || strlen($iv) !== 16) {
            throw $this->damaged();
        }
        $this->liv = $iv;
        $this->lb64Start = $sep + 2;
        // Tolerate trailing whitespace/newlines after the base64 text.
        $tailLen = min(8, $this->stored - $this->lb64Start);
        $tail = $tailLen > 0 ? $this->readStored($this->stored - $tailLen, $tailLen) : '';
        $trimmed = rtrim($tail);
        $end = $this->stored - (strlen($tail) - strlen($trimmed));
        $this->lb64Len = $end - $this->lb64Start;
        if ($this->lb64Len <= 0 || $this->lb64Len % 4 !== 0) {
            throw $this->damaged();
        }
        $pad = strlen($trimmed) - strlen(rtrim($trimmed, '='));
        $this->lctLen = intdiv($this->lb64Len, 4) * 3 - $pad;
        if ($this->lctLen < 16 || $this->lctLen % 16 !== 0) {
            throw $this->damaged();
        }
        // Decrypt only the final block to learn (and validate) the PKCS#7 padding.
        $ivLast = $this->lctLen === 16 ? $this->liv : $this->ctBytes($this->lctLen - 32, $this->lctLen - 16);
        $last = openssl_decrypt($this->ctBytes($this->lctLen - 16, $this->lctLen), 'aes-256-cbc', $this->lkey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $ivLast);
        if ($last === false || strlen($last) !== 16) {
            throw $this->damaged();
        }
        $p = ord($last[15]);
        if ($p < 1 || $p > 16 || substr($last, 16 - $p) !== str_repeat(chr($p), $p)) {
            throw new \RuntimeException('Legacy decryption failed: wrong key or damaged file (' . $this->label . ')');
        }
        $this->size = $this->lctLen - $p;
    }

    private function legacyWindow(int $w): string
    {
        $start = $w * self::PIECE;
        if ($start >= $this->lctLen) {
            throw $this->damaged();
        }
        $end = min($start + self::PIECE, $this->lctLen);
        $iv = $w === 0 ? $this->liv : $this->ctBytes($start - 16, $start);
        $pt = openssl_decrypt($this->ctBytes($start, $end), 'aes-256-cbc', $this->lkey, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
        if ($pt === false || strlen($pt) !== $end - $start) {
            throw $this->damaged();
        }
        if ($end === $this->lctLen) {
            $pt = (string) substr($pt, 0, $this->size - $start);
        }
        return $pt;
    }

    /** Ciphertext bytes [$s, $e) decoded from the base64 text. */
    private function ctBytes(int $s, int $e): string
    {
        $cs = intdiv($s, 3) * 4;
        $ce = min($this->lb64Len, intdiv($e + 2, 3) * 4);
        $raw = $this->readStored($this->lb64Start + $cs, $ce - $cs);
        $dec = base64_decode($raw, true);
        if ($dec === false) {
            throw $this->damaged();
        }
        $out = (string) substr($dec, $s - intdiv($s, 3) * 3, $e - $s);
        if (strlen($out) !== $e - $s) {
            throw $this->damaged();
        }
        return $out;
    }

    // ------------------------------------------------------------------ stored bytes

    private function piece(int $idx): string
    {
        if ($idx === $this->cacheIdx) {
            return $this->cache;
        }
        $this->cache = '';
        $this->cacheIdx = -1;
        $data = $this->encoding === 'gcm1' ? $this->gcmChunk($idx) : $this->legacyWindow($idx);
        $this->cacheIdx = $idx;
        return $this->cache = $data;
    }

    private function readStored(int $offset, int $length): string
    {
        if ($offset < 0 || $length < 0 || $offset + $length > $this->stored) {
            throw $this->damaged();
        }
        $out = '';
        while ($length > 0) {
            $i = $this->segmentAt($offset);
            [, $segSize, $segStart] = $this->segs[$i];
            $h = $this->handle($i);
            $local = $offset - $segStart;
            $n = min($length, $segSize - $local);
            if (fseek($h, $local) !== 0) {
                throw $this->damaged();
            }
            $got = '';
            while (strlen($got) < $n) {
                $r = fread($h, $n - strlen($got));
                if ($r === false || $r === '') {
                    break;
                }
                $got .= $r;
            }
            if (strlen($got) !== $n) {
                throw $this->damaged();
            }
            $out .= $got;
            $offset += $n;
            $length -= $n;
        }
        return $out;
    }

    private function segmentAt(int $offset): int
    {
        $count = count($this->segs);
        for ($i = $count - 1; $i >= 0; $i--) {
            if ($offset >= $this->segs[$i][2] && ($offset < $this->segs[$i][2] + $this->segs[$i][1])) {
                return $i;
            }
        }
        throw $this->damaged();
    }

    /** @return resource */
    private function handle(int $i)
    {
        if (isset($this->fh[$i]) && is_resource($this->fh[$i])) {
            return $this->fh[$i];
        }
        if (count($this->fh) >= 2) { // keep at most two segment files open
            foreach ($this->fh as $k => $h) {
                if (is_resource($h)) {
                    fclose($h);
                }
                unset($this->fh[$k]);
                break;
            }
        }
        $h = @fopen($this->segs[$i][0], 'rb');
        if ($h === false) {
            throw $this->damaged();
        }
        return $this->fh[$i] = $h;
    }

    private function damaged(): \RuntimeException
    {
        return self::damagedFor($this->label);
    }

    private static function damagedFor(string $label): \RuntimeException
    {
        return new \RuntimeException('Stored file is missing or damaged (' . $label . ')');
    }
}
