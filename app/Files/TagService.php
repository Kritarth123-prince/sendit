<?php
declare(strict_types=1);

namespace FT\Files;

use FT\Core\ApiException;
use FT\Core\Db;
use FT\Storage\MimeDetector;

/**
 * Tags live in the OWNER's namespace (tags.owner_id): an editor tagging someone else's file adds
 * the tag to the owner's set, never to their own. Names follow the legacy rule — lower case,
 * [a-z0-9-_] only — and are at most 32 characters.
 *
 * Also hosts the legacy automatic tag rules (image, video, audio, document, code, archive, text)
 * that A2's FileWriter applies to new uploads.
 */
final class TagService
{
    public const MAX_LENGTH = 32;
    public const MAX_PER_FILE = 25;

    /** Legacy $autoTagRules (used when MimeDetector does not provide them). */
    private const LEGACY_RULES = [
        'image'    => ['jpg', 'jpeg', 'png', 'gif', 'webp', 'bmp', 'svg'],
        'video'    => ['mp4', 'webm', 'mov', 'avi', 'mkv'],
        'audio'    => ['mp3', 'wav', 'aac', 'flac', 'm4a', 'opus'],
        'document' => ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'],
        'code'     => ['php', 'js', 'ts', 'py', 'sh', 'css', 'html', 'json', 'xml', 'yaml', 'yml'],
        'archive'  => ['zip', 'rar', '7z', 'tar', 'gz'],
        'text'     => ['txt', 'md', 'csv', 'log'],
    ];

    /** Canonical tag name, or null when nothing valid is left. */
    public static function normalise(mixed $name): ?string
    {
        if (!is_string($name) && !is_int($name)) {
            return null;
        }
        $n = (string) preg_replace('/[^a-z0-9\-_]/', '', strtolower(trim((string) $name)));
        $n = substr($n, 0, self::MAX_LENGTH);
        return $n === '' ? null : $n;
    }

    /**
     * Normalise a list (array or comma-separated string) into unique valid names.
     * @return string[]
     */
    public static function normaliseList(mixed $input): array
    {
        if (is_string($input)) {
            $input = $input === '' ? [] : explode(',', $input);
        }
        if (!is_array($input)) {
            throw ApiException::validation(['tags' => 'Tags must be a list of names.']);
        }
        $out = [];
        foreach ($input as $t) {
            $n = self::normalise($t);
            if ($n !== null && !in_array($n, $out, true)) {
                $out[] = $n;
            }
        }
        if (count($out) > self::MAX_PER_FILE) {
            throw ApiException::validation(['tags' => 'A file can have at most ' . self::MAX_PER_FILE . ' tags.']);
        }
        return $out;
    }

    /** Legacy automatic tags for an extension. @return string[] */
    public static function autoTagsFor(string $ext): array
    {
        $ext = strtolower(ltrim(trim($ext), '.'));
        if ($ext === '') {
            return [];
        }
        if (class_exists(MimeDetector::class) && method_exists(MimeDetector::class, 'legacyTags')) {
            return MimeDetector::legacyTags($ext);
        }
        $tags = [];
        foreach (self::LEGACY_RULES as $tag => $exts) {
            if (in_array($ext, $exts, true)) {
                $tags[] = $tag;
            }
        }
        return $tags;
    }

    /** Current tag names of a file (sorted). @return string[] */
    public static function tagsFor(int $fileId): array
    {
        return array_map('strval', Db::column(
            'SELECT t.name FROM file_tags ft JOIN tags t ON t.id = ft.tag_id WHERE ft.file_id = ? ORDER BY t.name',
            [$fileId]
        ));
    }

    /**
     * Replace the tags of a file with $names (normalised) in the owner's namespace.
     * @return string[] the file's tags afterwards
     */
    public static function setTags(int $fileId, int $ownerId, array $names): array
    {
        $names = self::normaliseList($names);
        Db::transaction(static function () use ($fileId, $ownerId, $names): void {
            $ids = self::ensureTags($ownerId, $names);
            if ($ids === []) {
                Db::run('DELETE FROM file_tags WHERE file_id = ?', [$fileId]);
                return;
            }
            [$in, $p] = Db::inList(array_values($ids), 'tg');
            $p['f'] = $fileId;
            Db::run("DELETE FROM file_tags WHERE file_id = :f AND tag_id NOT IN {$in}", $p);
            self::link($fileId, array_values($ids));
        });
        return self::tagsFor($fileId);
    }

    /** Add tags (keeps existing ones). @return string[] */
    public static function addTags(int $fileId, int $ownerId, array $names): array
    {
        $names = self::normaliseList($names);
        if ($names === []) {
            return self::tagsFor($fileId);
        }
        $current = self::tagsFor($fileId);
        if (count(array_unique(array_merge($current, $names))) > self::MAX_PER_FILE) {
            throw ApiException::validation(['tags' => 'A file can have at most ' . self::MAX_PER_FILE . ' tags.']);
        }
        Db::transaction(static function () use ($fileId, $ownerId, $names): void {
            self::link($fileId, array_values(self::ensureTags($ownerId, $names)));
        });
        return self::tagsFor($fileId);
    }

    /** Remove tags from a file (the owner's tag rows are kept for suggestions). @return string[] */
    public static function removeTags(int $fileId, int $ownerId, array $names): array
    {
        $names = self::normaliseList($names);
        if ($names !== []) {
            $p = ['f' => $fileId, 'o' => $ownerId];
            $ph = [];
            foreach ($names as $i => $n) {
                $ph[] = ':n' . $i;
                $p['n' . $i] = $n;
            }
            Db::run(
                'DELETE ft FROM file_tags ft JOIN tags t ON t.id = ft.tag_id
                  WHERE ft.file_id = :f AND t.owner_id = :o AND t.name IN (' . implode(',', $ph) . ')',
                $p
            );
        }
        return self::tagsFor($fileId);
    }

    /**
     * GET /tags: the owner's tags with the number of live files carrying them.
     * @return array<int,array{name:string,count:int}>
     */
    public static function listForOwner(int $ownerId, bool $includeUnused = false): array
    {
        $rows = Db::all(
            'SELECT t.name, COUNT(f.id) AS cnt FROM tags t
               LEFT JOIN file_tags ft ON ft.tag_id = t.id
               LEFT JOIN files f ON f.id = ft.file_id AND f.deleted_at IS NULL
              WHERE t.owner_id = ? GROUP BY t.id, t.name ORDER BY t.name ASC LIMIT 1000',
            [$ownerId]
        );
        $out = [];
        foreach ($rows as $r) {
            if ($includeUnused || (int) $r['cnt'] > 0) {
                $out[] = ['name' => (string) $r['name'], 'count' => (int) $r['cnt']];
            }
        }
        return $out;
    }

    /** Create missing tag rows. @return array<string,int> name => tag id */
    private static function ensureTags(int $ownerId, array $names): array
    {
        if ($names === []) {
            return [];
        }
        $now = Db::now();
        $values = [];
        $p = [];
        foreach ($names as $i => $n) {
            $values[] = "(:o{$i}, :n{$i}, :c{$i})";
            $p["o{$i}"] = $ownerId;
            $p["n{$i}"] = $n;
            $p["c{$i}"] = $now;
        }
        Db::run('INSERT IGNORE INTO tags (owner_id, name, created_at) VALUES ' . implode(',', $values), $p);
        $q = ['o' => $ownerId];
        $ph = [];
        foreach ($names as $i => $n) {
            $ph[] = ':n' . $i;
            $q['n' . $i] = $n;
        }
        $out = [];
        foreach (Db::all('SELECT id, name FROM tags WHERE owner_id = :o AND name IN (' . implode(',', $ph) . ')', $q) as $r) {
            $out[(string) $r['name']] = (int) $r['id'];
        }
        return $out;
    }

    /** @param int[] $tagIds */
    private static function link(int $fileId, array $tagIds): void
    {
        if ($tagIds === []) {
            return;
        }
        $now = Db::now();
        $values = [];
        $p = [];
        foreach ($tagIds as $i => $tid) {
            $values[] = "(:f{$i}, :t{$i}, :c{$i})";
            $p["f{$i}"] = $fileId;
            $p["t{$i}"] = $tid;
            $p["c{$i}"] = $now;
        }
        Db::run('INSERT IGNORE INTO file_tags (file_id, tag_id, created_at) VALUES ' . implode(',', $values), $p);
    }
}
