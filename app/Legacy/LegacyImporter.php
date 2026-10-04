<?php
declare(strict_types=1);

namespace FT\Legacy;

use FT\Core\Audit;
use FT\Core\Config;
use FT\Core\Db;
use FT\Core\Logger;
use FT\Core\Secrets;
use FT\Events\EventBus;
use FT\Files\FileAccess;
use FT\Files\FileWriter;
use FT\Jobs\Queue;
use FT\Notepads\NotepadService;
use FT\Storage\BlobReader;
use FT\Storage\BlobStore;
use FT\Storage\LegacyCbc;
use FT\Storage\Paths;

/**
 * Imports the data of the pre-upgrade single-file app (uploads/*.json + the files next to them)
 * into the database and blob storage. docs/ARCHITECTURE.md §14 and the legacy inventory (B, C, F).
 *
 * Guarantees:
 *  - NEVER modifies or deletes anything in the legacy uploads directory (read-only source).
 *  - Backs up every legacy JSON store first (Paths::backups()/legacy-json-<timestamp>/, each copy
 *    below 8 MB — larger stores are split into numbered parts because some hosts delete big files).
 *  - Idempotent and resumable: every imported item is recorded in the legacy_import ledger
 *    (item_type, legacy_key) and skipped on the next run. Each run is time-boxed ($budgetSeconds)
 *    so it fits a shared-host request; call run() again until it returns done = true.
 *  - Secrets of the old app are NOT imported: user password hashes (compromised — they are in the
 *    old source), remember-me tokens, push subscriptions (old VAPID keys are compromised) and the
 *    Slack webhook in ft_config.json. Imported accounts get temporary passwords and must change them.
 *
 * Phases (in order): backup → users → folders → files (+ versions, tags, favourites) → shares →
 * comments → texts → audit history → OCR index → notepads (collab.json → team notepads) → tag registry → access
 * (folder shares that keep everyone's previous access).
 *
 * Mapping decisions (documented for the admin):
 *  - File owner = the uploader recorded in audit.json (newest "upload" entry for the name) when
 *    that legacy username maps to an account; otherwise the importing administrator.
 *  - With share_imported_with_all_users (default) each owner's imported content goes into a folder
 *    "Imported files" that is shared with every other imported user (editor for users, downloader
 *    for guests), because in the old app everyone could see every file.
 *  - Files not marked "Keep forever" get expires_at = upload time + 72 h exactly like before; ones
 *    already past it are moved to the Trash by maintenance (never deleted outright).
 *  - Legacy encrypted files (AES-256-CBC) are copied byte-for-byte as legacy_cbc blobs; the
 *    encryption migration converts them to gcm1 later. A file that cannot be decrypted (key file
 *    missing or wrong) is recorded as failed with a warning and retried on the next run with
 *    retry_failed — the original stays untouched in the uploads directory.
 */
final class LegacyImporter
{
    /** Legacy system files that are never user content. */
    public const SYSTEM_FILES = [
        'metadata.json', 'texts.json', 'shares.json', 'folders.json', 'tags.json', 'comments.json',
        'audit.json', 'activity.json', 'collab.json', 'presence.json', 'ocr_index.json', 'push_subs.json',
        'remember_tokens.json', 'ft_config.json', '.htaccess', '.enc_key', 'index.php', 'index.html',
    ];

    /** Legacy auto-delete window (72 h). */
    public const LEGACY_TTL = 259200;

    public const CONTAINER_NAME = 'Imported files';

    /** Ledger key suffix of an owner's "Imported files" folder ("<ownerId>|<container>"). */
    private const CONTAINER_KEY = '|<container>';

    private const PHASES = ['backup', 'users', 'folders', 'files', 'shares', 'comments', 'texts', 'audit', 'ocr', 'collab', 'tags', 'access'];

    /** Bytes per second assumed when deciding whether a file still fits into this run's budget. */
    private const THROUGHPUT = 12 * 1024 * 1024;

    private const MAX_WARNINGS = 100;
    private const BACKUP_PART_BYTES = 8 * 1024 * 1024 - 65536;

    private const AUDIT_ACTIONS = [
        'upload'     => 'file.upload',
        'download'   => 'file.download',
        'delete'     => 'file.purge',
        'share'      => 'share.create',
        'bulk-share' => 'share.create',
        'comment'    => 'file.comment',
        'restore'    => 'file.version_restore',
        'text-save'  => 'text.create',
    ];

    private const COUNT_KEYS = [
        'user' => 'users', 'folder' => 'folders', 'file' => 'files', 'share' => 'shares', 'comment' => 'comments',
        'text' => 'texts', 'audit' => 'history', 'ocr' => 'ocr_texts', 'collab' => 'notepads', 'tag' => 'tags',
        'ushare' => 'access_shares',
    ];

    // ---- per-run state (reset at the start of every run)
    /** @var array<string,mixed> */
    private static array $opts = [];
    /** @var array<string,mixed> parsed legacy JSON stores */
    private static array $data = [];
    /** @var array<string,array<string,array{new_id:?int,status:string,message:?string}>> */
    private static array $ledger = [];
    /** @var array<string,?int> lower-case legacy username => user id (null = unmapped) */
    private static array $users = [];
    /** @var string[] */
    private static array $warnings = [];
    private static float $deadline = 0.0;
    private static int $workDone = 0;
    /** @var array<string,string>|null */
    private static ?array $uploaders = null;

    // ================================================================== public API

    /**
     * Import progress without doing any work (admin System page, installer).
     * @return array<string,mixed>
     */
    public static function status(): array
    {
        $dir = self::dir();
        $started = false;
        $done = false;
        $last = null;
        $counts = [];
        $warnings = [];
        try {
            $started = (int) Db::value('SELECT COUNT(*) FROM legacy_import') > 0;
            $done = Db::value("SELECT 1 FROM legacy_import WHERE item_type = 'run' AND legacy_key = 'complete' AND status = 'done'") !== null;
            $last = Db::value('SELECT MAX(created_at) FROM legacy_import');
            $counts = self::counts();
            $warnings = self::ledgerWarnings(20);
        } catch (\Throwable $e) {
            Logger::warning('app', 'Legacy import status unavailable', ['error' => $e->getMessage()]);
        }
        return [
            'available'        => self::hasLegacyData($dir),
            'source'           => basename($dir),
            'files_on_disk'    => self::countLegacyFiles($dir),
            'started'          => $started,
            'done'             => $done,
            'last_activity_at' => $last !== null ? Db::iso((string) $last) : null,
            'counts'           => $counts,
            'warnings'         => $warnings,
        ];
    }

    /**
     * Run (or continue) the import for at most $budgetSeconds.
     *
     * $options: admin_user_id (int; owner of everything without a known uploader, default the first
     *           administrator), share_imported_with_all_users (bool, default true),
     *           create_legacy_users (bool, default true), user_map (legacy username => user id),
     *           retry_failed (bool, default false).
     * @return array{done:bool,phase:?string,counts:array<string,int>,warnings:string[],created_users:array,temporary_passwords:object,busy?:bool}
     */
    public static function run(array $options = [], float $budgetSeconds = 15.0): array
    {
        $started = microtime(true);
        self::$deadline = $started + max(1.0, min(300.0, $budgetSeconds));
        self::$warnings = [];
        self::$ledger = [];
        self::$users = [];
        self::$data = [];
        self::$workDone = 0;
        self::$uploaders = null;

        $dir = self::dir();
        if (!self::hasLegacyData($dir)) {
            return ['done' => true, 'phase' => null, 'counts' => [], 'warnings' => ['No data from the old version of FastTransfer was found.'], 'created_users' => [], 'temporary_passwords' => (object) []];
        }

        $lockFile = Paths::runtime('locks') . '/legacy_import.lock';
        $lock = @fopen($lockFile, 'c');
        if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
            if (is_resource($lock)) {
                fclose($lock);
            }
            return ['done' => false, 'busy' => true, 'phase' => null, 'counts' => self::counts(), 'warnings' => ['Another import batch is still running. Try again in a moment.'], 'created_users' => [], 'temporary_passwords' => (object) []];
        }

        $phase = null;
        $done = false;
        try {
            self::$opts = self::resolveOptions($options);
            self::loadData();
            self::globalWarnings();
            $done = true;
            foreach (self::PHASES as $p) {
                $phase = $p;
                $complete = match ($p) {
                    'backup'   => self::phaseBackup(),
                    'users'    => self::phaseUsers(),
                    'folders'  => self::phaseFolders(),
                    'files'    => self::phaseFiles(),
                    'shares'   => self::phaseShares(),
                    'comments' => self::phaseComments(),
                    'texts'    => self::phaseTexts(),
                    'audit'    => self::phaseAudit(),
                    'ocr'      => self::phaseOcr(),
                    'collab'   => self::phaseCollab(),
                    'tags'     => self::phaseTags(),
                    'access'   => self::phaseAccess(),
                };
                if (!$complete) {
                    $done = false;
                    break;
                }
            }
            if ($done) {
                $phase = null;
                $first = self::ledgerRow('run', 'complete') === null;
                self::record('run', 'complete', null, 'done', gmdate('c'));
                if ($first) {
                    $counts = self::counts();
                    Audit::log('system.import', [
                        'user_id'  => self::$opts['admin_user_id'],
                        'category' => 'system',
                        'detail'   => 'Data from the old version of FastTransfer was imported',
                        'meta'     => ['counts' => $counts],
                    ]);
                    EventBus::publish('stats.updated', ['metric' => 'legacy_import', 'delta' => (int) ($counts['files'] ?? 0)], [], ['admin' => true, 'actor_id' => null]);
                }
            }
        } catch (\Throwable $e) {
            Logger::exception('app', $e, ['legacy_import_phase' => $phase]);
            self::warn('The import stopped in the "' . (string) $phase . '" step: ' . self::safeMessage($e) . ' Run it again to continue.');
            $done = false;
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }

        $created = self::createdUsers($done);
        $passwords = [];
        foreach ($created as $u) {
            if (isset($u['temporary_password'])) {
                $passwords[$u['username']] = $u['temporary_password'];
            }
        }
        return [
            'done'                => $done,
            'phase'               => $done ? null : $phase,
            'counts'              => self::counts(),
            'warnings'            => array_slice(array_values(array_unique(array_merge(self::$warnings, self::ledgerWarnings(50)))), 0, self::MAX_WARNINGS),
            'created_users'       => $created,
            // username => one-time password; present only in the response that finishes the import
            'temporary_passwords' => (object) $passwords,
            'duration_ms'         => (int) ((microtime(true) - $started) * 1000),
        ];
    }

    /** Absolute legacy uploads directory (Config legacy.uploads_path). Never sent to clients. */
    public static function dir(): string
    {
        return rtrim(str_replace('\\', '/', (string) Config::get('legacy.uploads_path')), '/');
    }

    public static function hasLegacyData(?string $dir = null): bool
    {
        $dir ??= self::dir();
        if ($dir === '' || !is_dir($dir)) {
            return false;
        }
        foreach (['metadata.json', 'shares.json', 'texts.json', 'audit.json', 'comments.json', 'collab.json'] as $f) {
            if (is_file($dir . '/' . $f)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The sanitizeFileName() rule of the old app: basename, no control/format characters,
     * anything outside [A-Za-z0-9._ -] becomes "_"; empty, ".", ".." or a leading dot → "file".
     * Used to locate uploads/versions/<name>/.
     */
    public static function legacySanitize(string $name): string
    {
        $name = basename(str_replace('\\', '/', $name));
        $name = (string) preg_replace('/\p{C}+/u', '', $name);
        $name = (string) preg_replace('/[^A-Za-z0-9._ \-]/', '_', $name);
        if ($name === '' || $name === '.' || $name === '..' || $name[0] === '.') {
            return 'file';
        }
        return $name;
    }

    /**
     * Legacy usernames referenced by the data, with the role inferred from comments (or the
     * old fixed accounts admin/guest). @return array<string,array{name:string,role:string}>
     */
    public static function discoverUsers(): array
    {
        if (self::$data === []) {
            self::loadData();
        }
        $out = [];
        $add = static function (mixed $name, ?string $role = null) use (&$out): void {
            if (!is_string($name)) {
                return;
            }
            $name = trim($name);
            if ($name === '' || mb_strlen($name) > 64) {
                return;
            }
            $k = mb_strtolower($name);
            if (!isset($out[$k])) {
                $out[$k] = ['name' => $name, 'role' => null];
            }
            if ($role !== null && in_array($role, ['admin', 'user', 'guest'], true) && $out[$k]['role'] === null) {
                $out[$k]['role'] = $role;
            }
        };
        foreach (self::listOf(self::$data['audit'] ?? null) as $e) {
            if (is_array($e)) {
                $add($e['user'] ?? null);
            }
        }
        foreach (self::mapOf(self::$data['comments'] ?? null) as $list) {
            foreach (self::listOf($list) as $c) {
                if (is_array($c)) {
                    $add($c['user'] ?? null, is_string($c['role'] ?? null) ? strtolower($c['role']) : null);
                }
            }
        }
        foreach (self::mapOf(self::$data['shares'] ?? null) as $s) {
            if (is_array($s)) {
                $add($s['created_by'] ?? null);
            }
        }
        foreach (self::mapOf(self::$data['collab'] ?? null) as $d) {
            if (is_array($d)) {
                $add($d['last_user'] ?? null);
            }
        }
        foreach ($out as $k => $u) {
            if ($u['role'] === null) {
                $out[$k]['role'] = $k === 'admin' ? 'admin' : ($k === 'guest' ? 'guest' : 'user');
            }
        }
        ksort($out);
        return $out;
    }

    // ================================================================== phases

    private static function phaseBackup(): bool
    {
        if (self::ledgerRow('backup', 'json') !== null) {
            return true;
        }
        $dir = self::dir();
        $target = Paths::backups() . '/legacy-json-' . gmdate('Ymd-His');
        Paths::ensureDir($target);
        $copied = 0;
        foreach (scandir($dir) ?: [] as $f) {
            if (!str_ends_with(strtolower($f), '.json') || !is_file($dir . '/' . $f) || in_array(strtolower($f), ['push_subs.json', 'remember_tokens.json', 'ft_config.json'], true)) {
                continue; // secrets of the old app are deliberately not copied around
            }
            self::copyInParts($dir . '/' . $f, $target . '/' . self::legacySanitize($f));
            $copied++;
        }
        self::record('backup', 'json', null, 'done', basename($target) . ' (' . $copied . ' files)');
        return true;
    }

    private static function phaseUsers(): bool
    {
        $admin = (int) self::$opts['admin_user_id'];
        $map = self::$opts['user_map'];
        $actor = Db::one('SELECT * FROM users WHERE id = ?', [$admin]);
        $pending = [];
        foreach (self::discoverUsers() as $k => $u) {
            $row = self::ledgerRow('user', (string) $k);
            if ($row !== null && ($row['new_id'] !== null || $row['status'] !== 'failed' || !self::$opts['retry_failed'])) {
                continue;
            }
            $pending[] = [(string) $k, $u];
        }
        $ok = self::inBatches($pending, static function (array $it) use ($admin, $map, $actor): void {
            [$k, $u] = $it;
            $id = null;
            $how = 'unmapped';
            if (isset($map[$k])) {
                $id = (int) $map[$k];
                $how = 'mapped';
            } else {
                $existing = Db::value('SELECT id FROM users WHERE LOWER(username) = ? AND deleted_at IS NULL LIMIT 1', [$k]);
                if ($existing !== null) {
                    $id = (int) $existing;
                    $how = 'existing';
                } elseif ($u['role'] === 'admin') {
                    $id = $admin;
                    $how = 'admin';
                } elseif (self::$opts['create_legacy_users']) {
                    try {
                        [$id, $password] = self::createUser($u['name'], $u['role'], $actor);
                        $how = 'created:' . Secrets::encrypt($password);
                    } catch (\Throwable $e) {
                        self::warn('An account for the old user "' . $u['name'] . '" could not be created: ' . self::safeMessage($e));
                        $id = null;
                        $how = 'unmapped';
                    }
                }
            }
            self::record('user', $k, $id, 'done', $how);
        }, 20);
        foreach (self::ledgerType('user') as $k => $row) {
            self::$users[$k] = $row['new_id'];
        }
        return $ok;
    }

    private static function phaseFolders(): bool
    {
        // Every named legacy folder exists at least for the administrator (empty folders survive).
        $names = [];
        foreach (self::listOf(self::$data['folders'] ?? null) as $n) {
            if (is_string($n) && trim($n) !== '') {
                $names[] = trim($n);
            }
        }
        $admin = (int) self::$opts['admin_user_id'];
        self::rootFolderFor($admin);
        $pending = array_values(array_filter(array_unique($names), static fn ($n) => self::ledgerRow('folder', $admin . '|' . $n) === null));
        return self::inBatches($pending, static function (string $name) use ($admin): void {
            self::folderFor($admin, $name);
        }, 50);
    }

    private static function phaseFiles(): bool
    {
        $files = self::legacyFiles();
        foreach ($files as $name => $info) {
            if (self::processed('file', $name)) {
                continue;
            }
            if ($info['missing']) {
                self::record('file', $name, null, 'skipped', 'The file was listed in metadata.json but is missing from the uploads folder.');
                continue;
            }
            $estimate = 0.3 + self::bytesWithVersions((string) $info['name'], (string) $info['path']) / self::THROUGHPUT;
            if (!self::hasTime($estimate)) {
                return false;
            }
            self::importFile($name, $info);
            self::$workDone++;
        }
        return true;
    }

    private static function phaseShares(): bool
    {
        $pending = [];
        foreach (self::mapOf(self::$data['shares'] ?? null) as $token => $s) {
            if (!self::processed('share', (string) $token)) {
                $pending[] = [(string) $token, is_array($s) ? $s : []];
            }
        }
        return self::inBatches($pending, static function (array $it): void {
            try {
                self::importShare($it[0], $it[1]);
            } catch (\Throwable $e) {
                Logger::exception('app', $e, ['legacy_import' => 'share']);
                self::record('share', $it[0], null, 'failed', 'A share link could not be imported: ' . self::safeMessage($e));
            }
        }, 25);
    }

    private static function phaseComments(): bool
    {
        $pending = [];
        foreach (self::mapOf(self::$data['comments'] ?? null) as $fileName => $list) {
            foreach (self::listOf($list) as $i => $c) {
                if (!is_array($c)) {
                    continue;
                }
                $legacyId = is_scalar($c['id'] ?? null) ? mb_substr((string) $c['id'], 0, 32) : '';
                $key = (string) $fileName . '|' . ($legacyId !== '' ? $legacyId : '#' . $i);
                if (!self::processed('comment', $key)) {
                    $pending[] = [$key, (string) $fileName, $legacyId, $c];
                }
            }
        }
        return self::inBatches($pending, static function (array $it): void {
            [$key, $fileName, $legacyId, $c] = $it;
            $fileId = self::fileIdFor($fileName);
            $body = is_string($c['text'] ?? null) ? trim($c['text']) : '';
            if ($fileId === null || $body === '') {
                self::record('comment', $key, null, 'skipped', $fileId === null ? 'Comment on “' . $fileName . '” skipped: the file was not imported.' : 'Empty comment skipped.');
                return;
            }
            $author = is_string($c['user'] ?? null) ? trim($c['user']) : '';
            $id = Db::insert('comments', [
                'file_id'     => $fileId,
                'user_id'     => self::userId($author),
                'author_name' => $author !== '' ? mb_substr($author, 0, 100) : 'Someone',
                'share_id'    => null,
                'body'        => mb_substr($body, 0, 5000),
                'created_at'  => self::ts($c['time'] ?? null) ?? Db::now(),
                'legacy_id'   => $legacyId !== '' ? $legacyId : null,
            ]);
            self::record('comment', $key, $id, 'done');
        });
    }

    private static function phaseTexts(): bool
    {
        $admin = (int) self::$opts['admin_user_id'];
        $seen = [];
        $pending = [];
        foreach (self::listOf(self::$data['texts'] ?? null) as $t) {
            if (!is_array($t) || !is_string($t['content'] ?? null)) {
                continue;
            }
            $content = mb_substr($t['content'], 0, 50000);
            $time = is_numeric($t['time'] ?? null) ? (int) $t['time'] : 0;
            $base = 't:' . sha1($time . '|' . $content);
            $seen[$base] = ($seen[$base] ?? 0) + 1;
            $key = $base . ':' . $seen[$base];
            if (!self::processed('text', $key)) {
                $pending[] = [$key, $content, $time, self::truthy($t['permanent'] ?? false)];
            }
        }
        return self::inBatches($pending, static function (array $it) use ($admin): void {
            [$key, $content, $time, $permanent] = $it;
            if (trim($content) === '' || (!$permanent && $time <= 0)) {
                // The old app purged non-permanent texts without a time on the next page load.
                self::record('text', $key, null, 'skipped');
                return;
            }
            $isUrl = self::isUrl($content);
            $created = $time > 0 ? Db::ts($time) : Db::now();
            $id = Db::insert('texts', [
                'owner_id'     => $admin,
                'content'      => $isUrl ? trim($content) : $content,
                'is_url'       => $isUrl ? 1 : 0,
                'url_meta'     => null,
                'is_permanent' => $permanent ? 1 : 0,
                'expires_at'   => $permanent ? null : Db::ts($time + self::LEGACY_TTL),
                'created_at'   => $created,
                'updated_at'   => $created,
            ]);
            self::record('text', $key, $id, 'done');
        }, 25);
    }

    private static function phaseAudit(): bool
    {
        // audit.json is newest first: insert chronologically.
        $seen = [];
        $pending = [];
        foreach (array_reverse(self::listOf(self::$data['audit'] ?? null)) as $e) {
            if (!is_array($e)) {
                continue;
            }
            $base = 'a:' . sha1((string) json_encode($e));
            $seen[$base] = ($seen[$base] ?? 0) + 1;
            $key = $base . ':' . $seen[$base];
            if (!self::processed('audit', $key)) {
                $pending[] = [$key, $e];
            }
        }
        return self::inBatches($pending, static function (array $it): void {
            [$key, $e] = $it;
            $legacyAction = is_string($e['action'] ?? null) ? strtolower(trim($e['action'])) : '';
            $action = self::AUDIT_ACTIONS[$legacyAction] ?? ('legacy.' . (preg_replace('/[^a-z0-9_]/', '_', $legacyAction) ?: 'event'));
            $detail = is_string($e['detail'] ?? null) ? $e['detail'] : '';
            $user = is_string($e['user'] ?? null) ? trim($e['user']) : '';
            [$fileName, $cleanDetail, $meta] = self::parseAuditDetail($legacyAction, $detail);
            $fileId = $fileName !== null ? self::fileIdFor($fileName) : null;
            $ownerId = $fileId !== null ? (int) Db::value('SELECT owner_id FROM files WHERE id = ?', [$fileId]) : null;
            $targetType = $fileId !== null ? 'file' : ($legacyAction === 'text-save' ? 'text' : null);
            $ip = is_string($e['ip'] ?? null) ? mb_substr(trim($e['ip']), 0, 64) : null;
            $id = Db::insert('audit_logs', [
                'user_id'     => self::userId($user),
                'actor_label' => $user !== '' ? mb_substr($user, 0, 100) : 'Someone',
                'action'      => mb_substr($action, 0, 48),
                'category'    => 'activity',
                'target_type' => $targetType,
                'target_id'   => $fileId,
                'owner_id'    => $ownerId,
                'detail'      => $cleanDetail !== '' ? mb_substr($cleanDetail, 0, 500) : null,
                'meta'        => json_encode(['legacy' => true, 'legacy_action' => $legacyAction] + $meta, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE),
                'ip'          => $ip !== '' ? $ip : null,
                'user_agent'  => null,
                'created_at'  => self::ts($e['time'] ?? null) ?? Db::now(),
            ]);
            self::record('audit', $key, $id, 'done');
        }, 100);
    }

    private static function phaseOcr(): bool
    {
        $pending = [];
        foreach (self::mapOf(self::$data['ocr'] ?? null) as $fileName => $text) {
            if (!self::processed('ocr', (string) $fileName)) {
                $pending[] = [(string) $fileName, $text];
            }
        }
        return self::inBatches($pending, static function (array $it): void {
            [$fileName, $text] = $it;
            $fileId = self::fileIdFor($fileName);
            if ($fileId === null || !is_string($text) || trim($text) === '') {
                self::record('ocr', $fileName, null, 'skipped');
                return;
            }
            $version = (int) Db::value('SELECT version FROM files WHERE id = ?', [$fileId]);
            $clean = mb_strcut(mb_scrub(trim($text), 'UTF-8'), 0, 102400, 'UTF-8');
            Db::run(
                'INSERT INTO file_texts (file_id, source, version, `text`, updated_at) VALUES (:f, :s, :v, :t, :u)
                 ON DUPLICATE KEY UPDATE version = VALUES(version), `text` = VALUES(`text`), updated_at = VALUES(updated_at)',
                ['f' => $fileId, 's' => 'ocr', 'v' => max(1, $version), 't' => $clean, 'u' => Db::now()]
            );
            self::record('ocr', $fileName, $fileId, 'done');
        });
    }

    /**
     * collab.json → team notepads (NotepadService::importLegacy): the document "shared" fills the
     * automatic "Team notepad" while it is still empty (or becomes it when there is none yet;
     * otherwise "Team notepad (imported)"); other documents become team notepads titled from their
     * id. The ledger plus notepads.legacy_key keep this idempotent and resumable.
     */
    private static function phaseCollab(): bool
    {
        $admin = (int) self::$opts['admin_user_id'];
        foreach (self::mapOf(self::$data['collab'] ?? null) as $doc => $d) {
            $doc = (string) $doc;
            if (self::processed('collab', $doc)) {
                continue;
            }
            if (!self::hasTime(1.0)) {
                return false;
            }
            $content = is_array($d) && is_string($d['content'] ?? null) ? $d['content'] : '';
            if (trim($content) === '') {
                self::record('collab', $doc, null, 'skipped');
                continue;
            }
            $content = mb_scrub($content, 'UTF-8');
            if (strlen($content) > NotepadService::MAX_BYTES) {
                self::warn('The notepad “' . mb_substr($doc, 0, 60) . '” is larger than 1 MB; only its first 1 MB was imported.');
            }
            $time = is_array($d) && is_numeric($d['updated'] ?? null) && (int) $d['updated'] > 0 ? Db::ts((int) $d['updated']) : Db::now();
            $editor = is_array($d) && is_string($d['last_user'] ?? null) ? self::userId($d['last_user']) : null;
            try {
                Db::transaction(static function () use ($doc, $content, $editor, $time, $admin): void {
                    $id = NotepadService::importLegacy($doc, $content, $editor, $time, $admin);
                    self::record('collab', $doc, $id, 'done');
                });
            } catch (\Throwable $e) {
                self::$ledger = [];
                Logger::warning('app', 'Legacy notepad import failed', ['error' => $e->getMessage()]);
                self::record('collab', $doc, null, 'failed', 'The notepad “' . mb_substr($doc, 0, 60) . '” could not be imported: ' . self::safeMessage($e));
            }
            self::$workDone++;
        }
        return true;
    }

    private static function phaseTags(): bool
    {
        $admin = (int) self::$opts['admin_user_id'];
        $pending = [];
        foreach (self::listOf(self::$data['tags'] ?? null) as $t) {
            $norm = is_string($t) ? FileWriter::normaliseTags([$t]) : [];
            if ($norm !== [] && !self::processed('tag', $norm[0]) && !in_array($norm[0], $pending, true)) {
                $pending[] = $norm[0];
            }
        }
        return self::inBatches($pending, static function (string $tag) use ($admin): void {
            Db::run('INSERT IGNORE INTO tags (owner_id, name, created_at) VALUES (?, ?, ?)', [$admin, $tag, Db::now()]);
            self::record('tag', $tag, null, 'done');
        }, 100);
    }

    /**
     * Keep the old "everyone sees everything" access: share each owner's "Imported files" folder
     * with every other imported account (editor for users, downloader for guests; administrators
     * see everything anyway).
     */
    private static function phaseAccess(): bool
    {
        if (!self::$opts['share_imported_with_all_users']) {
            return true;
        }
        $containers = [];
        foreach (self::ledgerType('folder') as $key => $row) {
            if (str_ends_with((string) $key, self::CONTAINER_KEY) && $row['new_id'] !== null) {
                $containers[(int) explode('|', (string) $key, 2)[0]] = (int) $row['new_id'];
            }
        }
        $recipients = [];
        foreach (array_unique(array_filter(self::$users, static fn ($v) => $v !== null)) as $uid) {
            $u = Db::one('SELECT id, role_id, status, deleted_at FROM users WHERE id = ?', [(int) $uid]);
            if ($u !== null && $u['deleted_at'] === null && (int) $u['role_id'] !== 1) {
                $recipients[(int) $u['id']] = (int) $u['role_id'] === 3 ? 'downloader' : 'editor';
            }
        }
        $pending = [];
        foreach ($containers as $ownerId => $folderId) {
            if (Db::value('SELECT 1 FROM folders WHERE id = ? AND deleted_at IS NULL', [$folderId]) === null) {
                continue;
            }
            foreach ($recipients as $uid => $permission) {
                if ($uid !== $ownerId && !self::processed('ushare', $folderId . '|' . $uid)) {
                    $pending[] = [$ownerId, $folderId, $uid, $permission];
                }
            }
        }
        return self::inBatches($pending, static function (array $it): void {
            [$ownerId, $folderId, $uid, $permission] = $it;
            $existing = Db::value(
                "SELECT id FROM shares WHERE kind = 'user' AND folder_id = ? AND recipient_id = ? AND revoked_at IS NULL LIMIT 1",
                [$folderId, $uid]
            );
            if ($existing === null) {
                $now = Db::now();
                $flags = FileAccess::defaultFlags($permission);
                $existing = Db::insert('shares', [
                    'owner_id'       => $ownerId,
                    'kind'           => 'user',
                    'target_type'    => 'folder',
                    'file_id'        => null,
                    'folder_id'      => $folderId,
                    'token'          => null,
                    'recipient_id'   => $uid,
                    'permission'     => $permission,
                    'allow_preview'  => $flags['allow_preview'],
                    'allow_download' => $flags['allow_download'],
                    'allow_comments' => $flags['allow_comments'],
                    'allow_edit'     => $flags['allow_edit'],
                    'allow_reshare'  => 0,
                    'title'          => self::CONTAINER_NAME,
                    'message'        => 'Files from the previous version of FastTransfer',
                    'legacy'         => 1,
                    'created_at'     => $now,
                    'updated_at'     => $now,
                ]);
            }
            self::record('ushare', $folderId . '|' . $uid, (int) $existing, 'done');
        });
    }

    /**
     * Run $body for every pending item, committing every $size items. Few commits matter: on
     * some hosts every commit is a disk flush (tens of milliseconds each). A failure rolls back
     * the whole chunk (the ledger cache is dropped so it is re-read) and stops the run. Returns
     * false when the time budget ran out; the next run continues with what is left.
     * @param array<int,mixed> $items
     */
    private static function inBatches(array $items, callable $body, int $size = 50): bool
    {
        foreach (array_chunk($items, max(1, $size)) as $chunk) {
            if (!self::hasTime()) {
                return false;
            }
            try {
                Db::transaction(static function () use ($chunk, $body): void {
                    foreach ($chunk as $item) {
                        $body($item);
                    }
                });
            } catch (\Throwable $e) {
                self::$ledger = [];
                throw $e;
            }
            self::$workDone += count($chunk);
        }
        return true;
    }

    // ================================================================== files

    /**
     * Candidate files: everything in the uploads directory except system files, joined with
     * metadata.json (all shape variants), plus metadata entries whose file is missing (recorded as
     * skipped). Sorted by upload time so new ids follow the original order.
     * @return array<string,array<string,mixed>>
     */
    private static function legacyFiles(): array
    {
        $dir = self::dir();
        $meta = self::mapOf(self::$data['metadata'] ?? null);
        $out = [];
        $onDisk = [];
        foreach (scandir($dir) ?: [] as $f) {
            if ($f === '' || $f[0] === '.' || in_array(strtolower($f), self::SYSTEM_FILES, true) || !is_file($dir . '/' . $f)) {
                continue;
            }
            $onDisk[$f] = true;
        }
        foreach (array_keys($onDisk) as $f) {
            $path = $dir . '/' . $f;
            $name = $f;
            // "<name>_plain" is plaintext left behind by a crashed encryption in the old app.
            if (str_ends_with($f, '_plain') && strlen($f) > 6) {
                $orig = substr($f, 0, -6);
                if (isset($onDisk[$orig])) {
                    continue;
                }
                $name = $orig;
                self::warn('“' . $f . '” (left over from an interrupted encryption) was imported as “' . $orig . '”.');
            }
            $m = self::normaliseMeta($meta[$name] ?? ($meta[$f] ?? null), $path);
            $out[$f] = $m + ['name' => $name, 'path' => $path, 'missing' => false];
        }
        foreach ($meta as $name => $m) {
            $name = (string) $name;
            if (!isset($onDisk[$name]) && !isset($onDisk[$name . '_plain']) && $name !== '' && $name[0] !== '.' && !in_array(strtolower($name), self::SYSTEM_FILES, true)) {
                $out[$name] = ['name' => $name, 'path' => '', 'missing' => true, 'time' => 0];
            }
        }
        uasort($out, static fn ($a, $b) => [(int) ($a['time'] ?? 0), $a['name']] <=> [(int) ($b['time'] ?? 0), $b['name']]);
        return $out;
    }

    /** Normalise every metadata.json shape variant (inventory B.2). */
    private static function normaliseMeta(mixed $m, string $path): array
    {
        $d = ['time' => 0, 'permanent' => false, 'fav' => false, 'folder' => '', 'downloads' => 0, 'tags' => [], 'encrypted' => null, 'bundle' => false];
        if (is_int($m) || is_float($m) || (is_string($m) && is_numeric($m))) {
            $d['time'] = (int) $m;
        } elseif (is_array($m)) {
            $d['time'] = is_numeric($m['time'] ?? null) ? (int) $m['time'] : 0;
            $d['permanent'] = self::truthy($m['permanent'] ?? false);
            $d['fav'] = self::truthy($m['fav'] ?? false);
            $d['folder'] = is_string($m['folder'] ?? null) ? trim($m['folder']) : '';
            $d['downloads'] = is_numeric($m['downloads'] ?? null) ? max(0, (int) $m['downloads']) : 0;
            $d['tags'] = array_values(array_filter(self::listOf($m['tags'] ?? []), 'is_string'));
            $d['encrypted'] = array_key_exists('encrypted', $m) ? self::truthy($m['encrypted']) : null;
            $d['bundle'] = self::truthy($m['bundle'] ?? false);
        }
        if ($d['time'] <= 0) {
            $mt = $path !== '' ? @filemtime($path) : false;
            $d['time'] = $mt !== false ? (int) $mt : time();
        }
        return $d;
    }

    private static function importFile(string $key, array $info): void
    {
        $name = (string) $info['name'];
        $path = (string) $info['path'];
        $isBundle = $info['bundle'] || (bool) preg_match('/^share_bundle_[0-9a-f]{8}\.zip$/i', $name);

        // owner: uploader from audit.json, the bundle's share creator, else the administrator
        $ownerId = null;
        $uploader = self::uploaders()[$name] ?? null;
        if ($uploader !== null) {
            $ownerId = self::userId($uploader);
        }
        if ($ownerId === null && $isBundle) {
            foreach (self::mapOf(self::$data['shares'] ?? null) as $s) {
                if (is_array($s) && ($s['file'] ?? null) === $name && is_string($s['created_by'] ?? null)) {
                    $ownerId = self::userId($s['created_by']);
                    break;
                }
            }
        }
        $defaulted = $ownerId === null || !self::activeUser($ownerId);
        if ($defaulted) {
            $ownerId = (int) self::$opts['admin_user_id'];
        }

        // A file left by a crashed earlier run (created, ledger not yet written): adopt it.
        $existing = Db::value('SELECT id FROM files WHERE owner_id = ? AND legacy_name = ? ORDER BY id LIMIT 1', [$ownerId, mb_substr($name, 0, 255)]);
        if ($existing !== null) {
            self::record('file', $key, (int) $existing, 'done', 'recovered');
            return;
        }

        $folderId = self::folderFor($ownerId, (string) $info['folder']);
        $scope = BlobStore::scopeFor($ownerId);

        // versions (oldest first), then the current file last
        $entries = [];
        foreach (self::versionFiles($name) as $v) {
            $entries[] = ['path' => $v['path'], 'time' => $v['time'], 'flag' => null, 'current' => false];
        }
        $entries[] = ['path' => $path, 'time' => (int) $info['time'], 'flag' => $info['encrypted'], 'current' => true];

        $stored = [];
        try {
            foreach ($entries as $e) {
                try {
                    $blob = self::storeBlob($e['path'], $scope, $name, $e['current'] ? $e['flag'] : null);
                } catch (\Throwable $ex) {
                    if ($e['current']) {
                        throw $ex;
                    }
                    self::warn('An old version of “' . $name . '” could not be imported: ' . self::safeMessage($ex));
                    continue;
                }
                // Skip a snapshot identical to the next state (the old app snapshotted every upload).
                if ($stored !== [] && $stored[count($stored) - 1]['blob']['sha256'] === $blob['sha256']) {
                    BlobStore::release((int) $blob['id']);
                    $stored[count($stored) - 1]['time'] = max($stored[count($stored) - 1]['time'], $e['time']);
                    continue;
                }
                $stored[] = ['blob' => $blob, 'time' => $e['time']];
            }
        } catch (\Throwable $ex) {
            foreach ($stored as $s) {
                self::safeRelease((int) $s['blob']['id']);
            }
            Logger::warning('app', 'Legacy file import failed', ['error' => $ex->getMessage()]);
            self::record('file', $key, null, 'failed', '“' . $name . '” could not be imported: ' . self::safeMessage($ex));
            return;
        }

        $tags = array_values(array_filter(
            FileWriter::normaliseTags($info['tags']),
            static fn ($t) => $t !== 'encrypted' // encryption is shown by FastTransfer itself now
        ));
        $currentTime = (int) $info['time'];
        $createdAt = Db::ts(min($stored[0]['time'], $currentTime));
        $times = [];
        foreach ($stored as $i => $s) {
            $times[$i + 1] = $s['time'];
        }
        $times[count($stored)] = $currentTime;
        try {
            // One transaction per file: its rows (file, every version, tags, favourite, history,
            // ledger) appear together or not at all — and cost a single commit.
            Db::transaction(static function () use ($ownerId, $folderId, $name, $stored, $info, $currentTime, $createdAt, $isBundle, $tags, $times, $uploader, $key, $defaulted): void {
                $file = FileWriter::createFile($ownerId, $folderId, $name, $stored[0]['blob'], [
                    'created_by'   => $ownerId,
                    'is_permanent' => (bool) $info['permanent'],
                    'expires_at'   => $info['permanent'] ? null : Db::ts($currentTime + self::LEGACY_TTL),
                    'created_at'   => $createdAt,
                    'legacy_name'  => $name,
                    'is_bundle'    => $isBundle,
                    'tags'         => $tags,
                    'auto_tags'    => false,
                    'on_conflict'  => 'rename',
                    'note'         => count($stored) > 1 ? 'Imported version' : 'Imported',
                    'silent'       => true,
                    'queue_jobs'   => false,
                ]);
                $fileId = (int) $file['id'];
                for ($i = 1, $n = count($stored); $i < $n; $i++) {
                    $file = FileWriter::addVersion($fileId, $stored[$i]['blob'], $ownerId, $i === $n - 1 ? 'Imported' : 'Imported version', ['silent' => true, 'queue_jobs' => false, 'notify' => false]);
                }
                self::afterCreate($fileId, $uploader, Db::ts($currentTime), $times, $createdAt, (int) $info['downloads'], $info['fav'] ? $ownerId : null);
                self::queueThumbnail($file);
                self::queueIndexing($file);
                self::record('file', $key, $fileId, 'done', $defaulted ? 'owner=default' : null);
            });
        } catch (\Throwable $ex) {
            // Rolled back as a whole — including FileWriter's own releases — so nothing references
            // the stored blobs: give every reference back exactly once (sweep deletes them later).
            self::$ledger = [];
            foreach ($stored as $s) {
                self::safeRelease((int) $s['blob']['id']);
            }
            Logger::warning('app', 'Legacy file import failed', ['error' => $ex->getMessage()]);
            self::record('file', $key, null, 'failed', '“' . $name . '” could not be imported: ' . self::safeMessage($ex));
        }
    }

    /**
     * Post-creation fix-ups for imported files: original timestamps, download counter, favourite,
     * and audit history (the import itself must not appear as "uploaded just now" — the legacy
     * audit entries are imported separately; a synthesised entry is added only when none exists).
     * @param array<int,int> $versionTimes version number => unix time
     */
    private static function afterCreate(int $fileId, ?string $uploader, string $updatedAt, array $versionTimes, ?string $createdAt, int $downloads = 0, ?int $favouriteFor = null): void
    {
        foreach ($versionTimes as $version => $time) {
            Db::run('UPDATE file_versions SET created_at = ? WHERE file_id = ? AND version = ?', [Db::ts((int) $time), $fileId, (int) $version]);
        }
        $set = ['updated_at' => $updatedAt, 'download_count' => max(0, $downloads)];
        if ($createdAt !== null) {
            $set['created_at'] = $createdAt;
        }
        Db::update('files', $set, ['id' => $fileId]);
        if ($favouriteFor !== null) {
            Db::run('INSERT IGNORE INTO favorites (user_id, file_id, created_at) VALUES (?, ?, ?)', [$favouriteFor, $fileId, Db::now()]);
        }
        Db::run("DELETE FROM audit_logs WHERE target_type = 'file' AND target_id = ? AND action IN ('file.upload', 'file.version_upload')", [$fileId]);
        $file = Db::one('SELECT name, owner_id, created_at, size FROM files WHERE id = ?', [$fileId]);
        if ($file !== null && $uploader === null) {
            Db::insert('audit_logs', [
                'user_id'     => null,
                'actor_label' => 'Someone (before the upgrade)',
                'action'      => 'file.upload',
                'category'    => 'activity',
                'target_type' => 'file',
                'target_id'   => $fileId,
                'owner_id'    => (int) $file['owner_id'],
                'detail'      => mb_substr((string) $file['name'], 0, 500),
                'meta'        => json_encode(['legacy' => true, 'synthesised' => true, 'size' => (int) $file['size']]),
                'ip'          => null,
                'user_agent'  => null,
                'created_at'  => (string) $file['created_at'],
            ]);
        }
    }

    /**
     * Store one legacy file as a blob (retained +1). Encrypted legacy files (metadata flag, or the
     * old "base64::base64" detection rule as a fallback) are copied byte-for-byte as legacy_cbc
     * after computing the plaintext checksum; a plaintext file that merely looks encrypted (the old
     * rule had false positives such as "std::string") is stored as plain content.
     */
    private static function storeBlob(string $path, string $scope, string $name, ?bool $flag): array
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new \RuntimeException('the file is missing or unreadable');
        }
        $looks = LegacyCbc::isEncryptedFile($path);
        if ($flag === true || $looks) {
            if (!LegacyCbc::available()) {
                // Without the key we cannot tell ciphertext from a false positive, so never store
                // possible ciphertext as content — unless metadata says the file is plain.
                if ($flag !== false) {
                    throw new \RuntimeException('it is encrypted and the old encryption key file (uploads/.enc_key) is missing. Restore the key file and run the import again with "retry failed items".');
                }
            } else {
                try {
                    [$sha, $size] = self::legacyPlainInfo($path);
                    return BlobStore::importLegacyCbc($path, $scope, $sha, $size, null);
                } catch (\Throwable $e) {
                    if ($flag === true) {
                        throw new \RuntimeException('it is encrypted and could not be decrypted with the old key (wrong key or damaged file).');
                    }
                    // false positive of the old detection rule (e.g. text starting "std::"): plain content
                }
            }
        }
        return BlobStore::putFile($path, $scope, null, $name);
    }

    /** @return array{0:string,1:int} plaintext SHA-256 and size of a legacy encrypted file (streamed). */
    private static function legacyPlainInfo(string $path): array
    {
        $r = BlobReader::fromFiles([$path], 'legacy_cbc', null, null, null);
        $h = hash_init('sha256');
        $n = 0;
        try {
            while (($d = $r->read(BlobReader::PIECE)) !== '') {
                hash_update($h, $d);
                $n += strlen($d);
            }
        } finally {
            $r->close();
        }
        return [hash_final($h), $n];
    }

    /**
     * uploads/versions/<sanitised name>/<YYYYmmdd_HHiiss>_<name> snapshots, oldest first.
     * @return array<int,array{path:string,time:int}>
     */
    private static function versionFiles(string $name): array
    {
        $dir = self::dir() . '/versions/' . self::legacySanitize($name);
        if (!is_dir($dir)) {
            return [];
        }
        $out = [];
        foreach (scandir($dir) ?: [] as $f) {
            if (!preg_match('/^(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})_(.+)$/', $f, $m) || !is_file($dir . '/' . $f)) {
                continue;
            }
            // The old server's local time zone is unknown; UTC is the best available assumption.
            $t = gmmktime((int) $m[4], (int) $m[5], (int) $m[6], (int) $m[2], (int) $m[3], (int) $m[1]);
            $out[] = ['path' => $dir . '/' . $f, 'time' => $t !== false ? $t : (int) @filemtime($dir . '/' . $f), 'f' => $f];
        }
        usort($out, static fn ($a, $b) => [$a['time'], $a['f']] <=> [$b['time'], $b['f']]);
        return array_map(static fn ($v) => ['path' => $v['path'], 'time' => $v['time']], $out);
    }

    private static function bytesWithVersions(string $name, string $path): int
    {
        $n = (int) @filesize($path);
        foreach (self::versionFiles($name) as $v) {
            $n += (int) @filesize($v['path']);
        }
        return $n;
    }

    /** filename => legacy username of the newest "upload" audit entry (audit.json is newest first). */
    private static function uploaders(): array
    {
        if (self::$uploaders !== null) {
            return self::$uploaders;
        }
        $cache = [];
        foreach (self::listOf(self::$data['audit'] ?? null) as $e) {
            if (!is_array($e) || ($e['action'] ?? null) !== 'upload' || !is_string($e['detail'] ?? null) || !is_string($e['user'] ?? null)) {
                continue;
            }
            $f = $e['detail'];
            if (!isset($cache[$f]) && trim($e['user']) !== '') {
                $cache[$f] = trim($e['user']);
            }
        }
        return self::$uploaders = $cache;
    }

    // ================================================================== shares

    private static function importShare(string $token, array $s): void
    {
        if (!preg_match('/^[A-Za-z0-9]{16,64}$/', $token)) {
            self::record('share', $token, null, 'skipped', 'A share link with an invalid token was skipped.');
            return;
        }
        $existing = Db::value('SELECT id FROM shares WHERE token = ?', [$token]);
        if ($existing !== null) {
            self::record('share', $token, (int) $existing, 'done', 'recovered');
            return;
        }
        $fileName = is_string($s['file'] ?? null) ? $s['file'] : '';
        $fileId = $fileName !== '' ? self::fileIdFor($fileName) : null;
        $file = $fileId !== null ? Db::one('SELECT id, owner_id, name FROM files WHERE id = ?', [$fileId]) : null;
        if ($file === null) {
            self::record('share', $token, null, 'skipped', 'A share link for “' . mb_substr($fileName, 0, 120) . '” was skipped: the file no longer exists.');
            return;
        }
        $owner = is_string($s['created_by'] ?? null) ? self::userId($s['created_by']) : null;
        if ($owner === null || !self::activeUser($owner)) {
            $owner = (int) $file['owner_id'];
        }
        $hash = null;
        $raw = $s['password'] ?? '';
        if (is_string($raw) && $raw !== '') {
            $info = password_get_info($raw);
            if (($info['algo'] ?? null) !== null && ($info['algo'] ?? 0) !== 0) {
                $hash = $raw; // bcrypt/argon hash kept exactly as it was
            } else {
                $hash = password_hash($raw, PASSWORD_DEFAULT);
                self::warn('A share password for “' . (string) $file['name'] . '” was stored unhashed in the old app; it has been hashed.');
            }
        }
        $expires = is_numeric($s['expires'] ?? null) && (int) $s['expires'] > 0 ? (int) $s['expires'] : null;
        $max = is_numeric($s['max_downloads'] ?? null) && (int) $s['max_downloads'] > 0 ? (int) $s['max_downloads'] : null;
        $created = self::ts($s['created'] ?? null) ?? Db::now();
        $now = Db::now();
        $id = Db::insert('shares', [
            'owner_id'            => $owner,
            'kind'                => 'link',
            'target_type'         => 'file',
            'file_id'             => (int) $file['id'],
            'folder_id'           => null,
            'token'               => $token,
            'recipient_id'        => null,
            'permission'          => 'downloader',
            'allow_preview'       => 1,
            'allow_download'      => 1,
            'allow_comments'      => 0,
            'allow_edit'          => 0,
            'allow_reshare'       => 0,
            'password_hash'       => $hash,
            'expires_at'          => $expires !== null ? Db::ts($expires) : null,
            'max_downloads'       => $max,
            'download_count'      => is_numeric($s['downloads'] ?? null) ? max(0, (int) $s['downloads']) : 0,
            'access_count'        => 0,
            'title'               => mb_substr((string) $file['name'], 0, 255),
            'legacy'              => 1,
            'created_at'          => $created,
            'updated_at'          => $created,
            // Links that expired before the upgrade must not notify their owner now.
            'expired_notified_at' => $expires !== null && $expires <= time() ? $now : null,
        ]);
        self::record('share', $token, $id, 'done');
    }

    // ================================================================== users & folders

    /** @return array{0:int,1:string} new user id and its temporary password */
    private static function createUser(string $legacyName, string $role, ?array $actor): array
    {
        $username = trim($legacyName);
        if (!preg_match('/^[A-Za-z0-9._-]{3,32}$/', $username)) {
            throw new \RuntimeException('the name is not a valid username (3–32 letters, numbers, dots, hyphens or underscores)');
        }
        $role = in_array($role, ['user', 'guest'], true) ? $role : 'user';
        $svc = 'FT\\Users\\UserService';
        if ($actor !== null && class_exists($svc) && method_exists($svc, 'create')) {
            $r = $svc::create($actor, ['username' => $username, 'display_name' => ucfirst($username), 'role' => $role, 'must_change_password' => true]);
            $id = (int) ($r['user']['id'] ?? 0);
            $pw = (string) ($r['temporary_password'] ?? '');
            if ($id > 0 && $pw !== '') {
                return [$id, $pw];
            }
            throw new \RuntimeException('the account service returned no temporary password');
        }
        $pwClass = 'FT\\Auth\\Passwords';
        $pw = class_exists($pwClass) && method_exists($pwClass, 'generateTemporary') ? $pwClass::generateTemporary() : Secrets::token(20);
        $now = Db::now();
        $id = Db::insert('users', [
            'username'             => $username,
            'display_name'         => ucfirst($username),
            'password_hash'        => password_hash($pw, PASSWORD_DEFAULT),
            'role_id'              => $role === 'guest' ? 3 : 2,
            'status'               => 'active',
            'must_change_password' => 1,
            'password_changed_at'  => $now,
            'created_by'           => $actor !== null ? (int) $actor['id'] : null,
            'created_at'           => $now,
            'updated_at'           => $now,
        ]);
        Audit::log('admin.user_create', ['user_id' => $actor !== null ? (int) $actor['id'] : null, 'category' => 'admin', 'target_type' => 'user', 'target_id' => $id, 'owner_id' => $id, 'detail' => $username, 'meta' => ['legacy_import' => true, 'role' => $role]]);
        return [$id, $pw];
    }

    /** Folder that holds an owner's imported root-level content ("Imported files" or the root). */
    private static function rootFolderFor(int $ownerId): ?int
    {
        if (!self::$opts['share_imported_with_all_users']) {
            return null;
        }
        $key = $ownerId . self::CONTAINER_KEY;
        $row = self::ledgerRow('folder', $key);
        if ($row !== null && $row['new_id'] !== null && Db::value('SELECT 1 FROM folders WHERE id = ? AND deleted_at IS NULL', [(int) $row['new_id']]) !== null) {
            return (int) $row['new_id'];
        }
        $id = self::ensureFolder($ownerId, null, self::CONTAINER_NAME, null);
        self::record('folder', $key, $id, 'done');
        return $id;
    }

    /** The owner's folder for a legacy folder name (flat in the old app), created on demand. */
    private static function folderFor(int $ownerId, string $legacyFolder): ?int
    {
        $legacyFolder = trim($legacyFolder);
        if ($legacyFolder === '') {
            return self::rootFolderFor($ownerId);
        }
        $key = $ownerId . '|' . $legacyFolder;
        $row = self::ledgerRow('folder', $key);
        if ($row !== null && $row['new_id'] !== null && Db::value('SELECT 1 FROM folders WHERE id = ? AND deleted_at IS NULL', [(int) $row['new_id']]) !== null) {
            return (int) $row['new_id'];
        }
        $name = FileWriter::sanitizeName($legacyFolder);
        $id = self::ensureFolder($ownerId, self::rootFolderFor($ownerId), $name, $legacyFolder);
        self::record('folder', $key, $id, 'done');
        return $id;
    }

    private static function ensureFolder(int $ownerId, ?int $parentId, string $name, ?string $legacyName): int
    {
        $id = Db::value(
            'SELECT id FROM folders WHERE owner_id = :o AND parent_id <=> :p AND name = :n AND deleted_at IS NULL ORDER BY id LIMIT 1',
            ['o' => $ownerId, 'p' => $parentId, 'n' => $name]
        );
        if ($id !== null) {
            return (int) $id;
        }
        $now = Db::now();
        return Db::insert('folders', [
            'owner_id'    => $ownerId,
            'parent_id'   => $parentId,
            'name'        => $name,
            'created_by'  => $ownerId,
            'created_at'  => $now,
            'updated_at'  => $now,
            'legacy_name' => $legacyName !== null ? mb_substr($legacyName, 0, 100) : null,
        ]);
    }

    // ================================================================== helpers

    /** @return array<string,mixed> */
    private static function resolveOptions(array $in): array
    {
        $stored = self::ledgerRow('run', 'options');
        $saved = $stored !== null ? (json_decode((string) $stored['message'], true) ?: []) : [];

        $adminId = (int) ($saved['admin_user_id'] ?? ($in['admin_user_id'] ?? 0));
        $admin = $adminId > 0 ? Db::one("SELECT id FROM users WHERE id = ? AND role_id = 1 AND status = 'active' AND deleted_at IS NULL", [$adminId]) : null;
        if ($admin === null) {
            $adminId = (int) (Db::value("SELECT id FROM users WHERE role_id = 1 AND status = 'active' AND deleted_at IS NULL ORDER BY id LIMIT 1") ?? 0);
            if ($adminId <= 0) {
                throw new \RuntimeException('Create an administrator account before importing.');
            }
        }
        $share = array_key_exists('share_imported_with_all_users', $saved)
            ? (bool) $saved['share_imported_with_all_users']
            : (array_key_exists('share_imported_with_all_users', $in) ? self::truthy($in['share_imported_with_all_users']) : true);

        $map = [];
        foreach ((is_array($in['user_map'] ?? null) ? $in['user_map'] : []) as $legacy => $uid) {
            if (is_string($legacy) && trim($legacy) !== '' && is_numeric($uid) && Db::value('SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL', [(int) $uid]) !== null) {
                $map[mb_strtolower(trim($legacy))] = (int) $uid;
            }
        }
        $opts = [
            'admin_user_id'                 => $adminId,
            'share_imported_with_all_users' => $share,
            'create_legacy_users'           => array_key_exists('create_legacy_users', $in) ? self::truthy($in['create_legacy_users']) : true,
            'user_map'                      => $map,
            'retry_failed'                  => self::truthy($in['retry_failed'] ?? false),
        ];
        if ($stored === null) {
            // Structural choices are fixed by the first run so later batches stay consistent.
            self::record('run', 'options', null, 'done', (string) json_encode(['admin_user_id' => $adminId, 'share_imported_with_all_users' => $share]));
        }
        return $opts;
    }

    private static function loadData(): void
    {
        $files = [
            'metadata' => 'metadata.json', 'texts' => 'texts.json', 'shares' => 'shares.json', 'folders' => 'folders.json',
            'tags' => 'tags.json', 'comments' => 'comments.json', 'audit' => 'audit.json', 'collab' => 'collab.json',
            'ocr' => 'ocr_index.json',
        ];
        $data = [];
        foreach ($files as $k => $f) {
            $data[$k] = self::readJson($f);
        }
        self::$data = $data;
    }

    private static function readJson(string $file): mixed
    {
        $path = self::dir() . '/' . $file;
        if (!is_file($path)) {
            return null;
        }
        $size = (int) @filesize($path);
        if ($size > 64 * 1024 * 1024) {
            self::warn($file . ' is too large to import (' . (int) round($size / 1048576) . ' MB).');
            return null;
        }
        $raw = (string) @file_get_contents($path);
        if (strncmp($raw, "\xEF\xBB\xBF", 3) === 0) {
            $raw = substr($raw, 3);
        }
        if (trim($raw) === '' || trim($raw) === 'null') {
            return null;
        }
        $d = json_decode($raw, true, 512, JSON_BIGINT_AS_STRING);
        if ($d === null) {
            self::warn($file . ' could not be read (it is not valid JSON) and was skipped.');
        }
        return $d;
    }

    private static function globalWarnings(): void
    {
        $roots = array_unique([dirname(self::dir()), FT_ROOT]);
        foreach ($roots as $root) {
            if (is_file($root . '/ft_config.json')) {
                $cfg = json_decode((string) @file_get_contents($root . '/ft_config.json'), true);
                if (is_array($cfg) && !empty($cfg['slack_webhook'])) {
                    self::warn('The Slack webhook in ft_config.json was not imported. It was exposed in the old app: create a new webhook in Slack, put it in SLACK_WEBHOOK in .env, then delete ft_config.json.');
                }
            }
            if (is_file($root . '/push_subs.json')) {
                self::warn('Push notification subscriptions were not imported (the old keys are compromised). Users can switch notifications on again; delete push_subs.json.');
            }
            if (is_file($root . '/remember_tokens.json')) {
                self::warn('Saved sign-ins (remember_tokens.json) were not imported; everyone signs in again. Delete remember_tokens.json.');
            }
        }
        self::warn('Old passwords were not imported. Imported accounts have one-time passwords and must choose a new password at their first sign-in.');
        if (self::hasEncryptedLegacyData() && !LegacyCbc::available()) {
            self::warn('Some old files are encrypted but the old key file (uploads/.enc_key) is missing; those files cannot be imported until it is restored.');
        }
    }

    private static function hasEncryptedLegacyData(): bool
    {
        foreach (self::mapOf(self::$data['metadata'] ?? null) as $m) {
            if (is_array($m) && self::truthy($m['encrypted'] ?? false)) {
                return true;
            }
        }
        return false;
    }

    private static function counts(): array
    {
        $out = [];
        try {
            foreach (Db::all("SELECT item_type, status, COUNT(*) AS n FROM legacy_import WHERE item_type NOT IN ('run', 'backup') GROUP BY item_type, status") as $r) {
                $base = self::COUNT_KEYS[(string) $r['item_type']] ?? (string) $r['item_type'];
                $k = $r['status'] === 'done' ? $base : $base . '_' . $r['status'];
                $out[$k] = ($out[$k] ?? 0) + (int) $r['n'];
            }
            $created = (int) Db::value("SELECT COUNT(*) FROM legacy_import WHERE item_type = 'user' AND message LIKE 'created%'");
            if ($created > 0) {
                $out['users_created'] = $created;
            }
            $defaulted = (int) Db::value("SELECT COUNT(*) FROM legacy_import WHERE item_type = 'file' AND message = 'owner=default'");
            if ($defaulted > 0) {
                $out['files_owned_by_admin'] = $defaulted;
            }
            $versions = (int) Db::value(
                "SELECT COUNT(*) FROM file_versions v JOIN legacy_import l ON l.item_type = 'file' AND l.status = 'done' AND l.new_id = v.file_id
                  JOIN files f ON f.id = v.file_id WHERE v.version <> f.version"
            );
            if ($versions > 0) {
                $out['old_versions'] = $versions;
            }
            $favs = (int) Db::value("SELECT COUNT(*) FROM favorites fa JOIN legacy_import l ON l.item_type = 'file' AND l.status = 'done' AND l.new_id = fa.file_id");
            if ($favs > 0) {
                $out['favourites'] = $favs;
            }
        } catch (\Throwable) {
            // ledger not available yet (not installed)
        }
        ksort($out);
        return $out;
    }

    /** @return string[] messages of failed/skipped ledger rows and explicit warnings ("!…") */
    private static function ledgerWarnings(int $limit): array
    {
        try {
            $rows = Db::all(
                "SELECT message FROM legacy_import WHERE message IS NOT NULL AND message <> ''
                   AND (status IN ('failed', 'skipped') OR message LIKE '!%') AND item_type NOT IN ('user', 'run', 'backup')
                 ORDER BY id DESC LIMIT " . max(1, min(500, $limit))
            );
        } catch (\Throwable) {
            return [];
        }
        return array_values(array_unique(array_map(static fn ($r) => ltrim((string) $r['message'], '!'), $rows)));
    }

    /**
     * Accounts created by the import. Their one-time passwords are kept encrypted (APP_KEY) only
     * until the import completes, are returned exactly once with the final result, then erased.
     * @return array<int,array{username:string,role:string,temporary_password?:string}>
     */
    private static function createdUsers(bool $final): array
    {
        try {
            $rows = Db::all(
                "SELECT l.legacy_key, l.message, u.username, u.role_id FROM legacy_import l JOIN users u ON u.id = l.new_id
                  WHERE l.item_type = 'user' AND l.message LIKE 'created%' ORDER BY u.username"
            );
        } catch (\Throwable) {
            return [];
        }
        $out = [];
        foreach ($rows as $r) {
            $item = ['username' => (string) $r['username'], 'role' => (int) $r['role_id'] === 3 ? 'guest' : ((int) $r['role_id'] === 1 ? 'admin' : 'user')];
            $msg = (string) $r['message'];
            if ($final && str_starts_with($msg, 'created:')) {
                $pw = Secrets::decrypt(substr($msg, 8));
                if ($pw !== null) {
                    $item['temporary_password'] = $pw;
                }
                Db::run("UPDATE legacy_import SET message = 'created' WHERE item_type = 'user' AND legacy_key = ?", [(string) $r['legacy_key']]);
            }
            $out[] = $item;
        }
        return $out;
    }

    private static function parseAuditDetail(string $action, string $detail): array
    {
        $meta = [];
        $file = null;
        $clean = $detail;
        switch ($action) {
            case 'upload':
            case 'download':
            case 'delete':
                $file = trim($detail);
                break;
            case 'share':
                // "<file> → <token>" — the token is a secret link: never copied into the history.
                $parts = explode('→', $detail, 2);
                $file = trim($parts[0]);
                $clean = $file;
                if (isset($parts[1])) {
                    $meta['token_prefix'] = substr(trim($parts[1]), 0, 6);
                }
                break;
            case 'bulk-share':
                $parts = explode('→', $detail, 2);
                $clean = trim($parts[0]);
                if (isset($parts[1])) {
                    $meta['token_prefix'] = substr(trim($parts[1]), 0, 6);
                }
                $meta['bundle'] = true;
                break;
            case 'comment':
                $parts = explode('—', $detail, 2);
                $file = trim($parts[0]);
                break;
            case 'restore':
                $parts = explode('←', $detail, 2);
                $file = trim($parts[0]);
                if (isset($parts[1])) {
                    $meta['version'] = mb_substr(trim($parts[1]), 0, 255);
                }
                break;
        }
        return [$file !== '' ? $file : null, $clean, $meta];
    }

    private static function fileIdFor(string $legacyName): ?int
    {
        $row = self::ledgerRow('file', $legacyName);
        if ($row === null) {
            $row = self::ledgerRow('file', $legacyName . '_plain');
        }
        if ($row === null || $row['new_id'] === null || $row['status'] !== 'done') {
            return null;
        }
        return Db::value('SELECT 1 FROM files WHERE id = ?', [(int) $row['new_id']]) !== null ? (int) $row['new_id'] : null;
    }

    private static function userId(string $legacyName): ?int
    {
        $k = mb_strtolower(trim($legacyName));
        if ($k === '') {
            return null;
        }
        if (self::$users === []) {
            foreach (self::ledgerType('user') as $key => $row) {
                self::$users[$key] = $row['new_id'];
            }
        }
        $id = self::$users[$k] ?? null;
        return $id !== null && $id > 0 ? $id : null;
    }

    private static function activeUser(int $id): bool
    {
        return Db::value("SELECT 1 FROM users WHERE id = ? AND deleted_at IS NULL AND status = 'active'", [$id]) !== null;
    }

    private static function queueThumbnail(array $file): void
    {
        $t = 'FT\\Storage\\Thumbnailer';
        try {
            if (class_exists($t) && method_exists($t, 'supports') && method_exists($t, 'generateJob') && $t::supports($file)) {
                Queue::push($t . '::generateJob', ['file_id' => (int) $file['id'], 'version' => (int) $file['version']]);
            }
        } catch (\Throwable $e) {
            Logger::warning('app', 'Could not queue a thumbnail for an imported file', ['error' => $e->getMessage()]);
        }
    }

    private static function queueIndexing(array $file): void
    {
        try {
            if (in_array((string) $file['kind'], ['text', 'code'], true)) {
                Queue::push(\FT\Ocr\OcrService::class . '::indexContentJob', ['file_id' => (int) $file['id'], 'version' => (int) $file['version']]);
            }
        } catch (\Throwable $e) {
            Logger::warning('app', 'Could not queue content indexing for an imported file', ['error' => $e->getMessage()]);
        }
    }

    private static function isUrl(string $content): bool
    {
        $svc = 'FT\\Texts\\TextService';
        if (class_exists($svc) && method_exists($svc, 'isUrl')) {
            try {
                return (bool) $svc::isUrl($content);
            } catch (\Throwable) {
                // fall through to the legacy rule
            }
        }
        $t = trim($content);
        return $t !== '' && !preg_match('/\s/', $t) && preg_match('~^https?://~i', $t) === 1 && filter_var($t, FILTER_VALIDATE_URL) !== false;
    }

    /** Copy a file into $target, splitting it into ≤ 8 MB numbered parts when larger. */
    private static function copyInParts(string $src, string $target): void
    {
        $size = (int) @filesize($src);
        $in = @fopen($src, 'rb');
        if ($in === false) {
            self::warn('Could not back up ' . basename($src) . '.');
            return;
        }
        try {
            if ($size <= self::BACKUP_PART_BYTES) {
                $out = @fopen($target, 'wb');
                if ($out === false) {
                    throw new \RuntimeException('Cannot write the backup');
                }
                stream_copy_to_stream($in, $out);
                fclose($out);
                return;
            }
            $part = 1;
            while (!feof($in)) {
                $out = @fopen($target . '.part' . $part, 'wb');
                if ($out === false) {
                    throw new \RuntimeException('Cannot write the backup');
                }
                stream_copy_to_stream($in, $out, self::BACKUP_PART_BYTES);
                fclose($out);
                $part++;
            }
        } finally {
            fclose($in);
        }
    }

    private static function countLegacyFiles(string $dir): int
    {
        if (!is_dir($dir)) {
            return 0;
        }
        $n = 0;
        foreach (scandir($dir) ?: [] as $f) {
            if ($f !== '' && $f[0] !== '.' && !in_array(strtolower($f), self::SYSTEM_FILES, true) && is_file($dir . '/' . $f)) {
                $n++;
            }
        }
        return $n;
    }

    // ---- ledger

    private static function key(string $key): string
    {
        return strlen($key) <= 180 ? $key : 'h:' . sha1($key);
    }

    /** @return array<string,array{new_id:?int,status:string,message:?string}> */
    private static function ledgerType(string $type): array
    {
        if (!isset(self::$ledger[$type])) {
            $rows = [];
            foreach (Db::all('SELECT legacy_key, new_id, status, message FROM legacy_import WHERE item_type = ?', [$type]) as $r) {
                $rows[(string) $r['legacy_key']] = [
                    'new_id'  => $r['new_id'] !== null ? (int) $r['new_id'] : null,
                    'status'  => (string) $r['status'],
                    'message' => $r['message'] !== null ? (string) $r['message'] : null,
                ];
            }
            self::$ledger[$type] = $rows;
        }
        return self::$ledger[$type];
    }

    private static function ledgerRow(string $type, string $key): ?array
    {
        return self::ledgerType($type)[self::key($key)] ?? null;
    }

    /** Already handled (done/skipped, or failed unless retry_failed was requested). */
    private static function processed(string $type, string $key): bool
    {
        $row = self::ledgerRow($type, $key);
        if ($row === null) {
            return false;
        }
        return $row['status'] !== 'failed' || empty(self::$opts['retry_failed']);
    }

    private static function record(string $type, string $key, ?int $newId, string $status, ?string $message = null): void
    {
        $k = self::key($key);
        $msg = $message !== null ? mb_substr($message, 0, 500) : null;
        Db::run(
            'INSERT INTO legacy_import (item_type, legacy_key, new_id, status, message, created_at) VALUES (:t, :k, :n, :s, :m, :c)
             ON DUPLICATE KEY UPDATE new_id = VALUES(new_id), status = VALUES(status), message = VALUES(message), created_at = VALUES(created_at)',
            ['t' => $type, 'k' => $k, 'n' => $newId, 's' => $status, 'm' => $msg, 'c' => Db::now()]
        );
        self::ledgerType($type);
        self::$ledger[$type][$k] = ['new_id' => $newId, 'status' => $status, 'message' => $msg];
    }

    // ---- small utilities

    private static function hasTime(float $needed = 0.0): bool
    {
        $left = self::$deadline - microtime(true);
        if ($left <= 0.25) {
            return false;
        }
        // Always make progress: the first item of a run may take longer than the estimate.
        return self::$workDone === 0 || $left >= $needed;
    }

    private static function warn(string $message): void
    {
        if (count(self::$warnings) < self::MAX_WARNINGS) {
            self::$warnings[] = $message;
        }
    }

    private static function safeMessage(\Throwable $e): string
    {
        $m = $e->getMessage();
        // never echo physical paths
        $m = str_replace([str_replace('\\', '/', FT_ROOT), FT_ROOT, self::dir()], '…', str_replace('\\', '/', $m));
        return mb_substr($m, 0, 300);
    }

    private static function safeRelease(int $blobId): void
    {
        try {
            BlobStore::release($blobId);
        } catch (\Throwable) {
            // ref_count drift is repaired by maintenance (unreferenced_blobs)
        }
    }

    private static function ts(mixed $v): ?string
    {
        return is_numeric($v) && (int) $v > 0 ? Db::ts((int) $v) : null;
    }

    private static function truthy(mixed $v): bool
    {
        if (is_bool($v)) {
            return $v;
        }
        if (is_int($v) || is_float($v)) {
            return $v != 0;
        }
        return is_string($v) && in_array(strtolower(trim($v)), ['1', 'true', 'yes', 'on'], true);
    }

    /** Object-or-empty-list tolerant map with string keys (PHP wrote empty maps as []). */
    private static function mapOf(mixed $v): array
    {
        if (!is_array($v)) {
            return [];
        }
        $out = [];
        foreach ($v as $k => $x) {
            $out[(string) $k] = $x;
        }
        return $out;
    }

    private static function listOf(mixed $v): array
    {
        return is_array($v) ? array_values($v) : [];
    }
}
