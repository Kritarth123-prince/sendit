# FastTransfer 2 — Architecture & Implementation Contract

This document is the **binding contract** for everyone implementing FastTransfer 2. Module
owners must implement the signatures, data shapes, routes and events exactly as written here so
that independently built parts fit together. If you must deviate, keep the old signature working
and note the deviation in your final report.

Status of each section: **[KERNEL — exists]** means the code is already written and tested;
everything else is to be implemented by the module owner named in §2.

---

## 0. Ground rules (read first)

### 0.1 Product context
FastTransfer was a single 3,487-line `index.php` storing everything in JSON files (original kept at
`D:/working/php/Sendit-backup-2026-10-03/index.php` — **read-only reference**, it contains real
secrets: never copy them anywhere). It is being upgraded into a multi-user, MySQL-backed,
real-time private cloud drive **without losing any existing feature**. Legacy inventories:
`C:/tmp/claude/d--working-php-Sendit/7672faad-2854-4307-9580-68084a55f223/scratchpad/discovery/*.md`.

### 0.2 Hosting constraints — byethost / iFastNet FREE plan (researched; full report in discovery/hosting-constraints.md)
The app must run well on a normal host **and** degrade gracefully on byethost free. Rules:

- **No SSH, Composer, Node, daemons, cron or WebSockets.** Apache + mod_rewrite. The root
  `.htaccess` may only use `Options -Indexes`, `DirectoryIndex`, `RewriteEngine/Cond/Rule`,
  `Require all denied`, `ErrorDocument` (no `Header`, `AddType`, `Expires`, `php_value`,
  `<FilesMatch>`): **send every header from PHP.** Storage dirs get `Require all denied` + stub index files.
- **Disabled functions** on byethost: `sleep`, `set_time_limit`, `ignore_user_abort`,
  `fastcgi_finish_request`, `mail`, `curl_multi_exec`, `getallheaders`/`apache_request_headers`,
  `disk_total_space`… Calling a disabled function throws `Error` in PHP 8 (`@` does not help).
  **Always use `FT\Support\Capabilities`** (`sleep()`, `setTimeLimit()`, `ignoreUserAbort()`,
  `canHold()`, `canFinishEarly()`, `hasGd()`, `hasZipArchive()`, `maxRequestBytes()`) or guard with `function_exists`.
- **Request budget: ≤ 25 s wall time** (hard 60 s → 502), memory ≤ 64–128 MB → stream all file
  I/O; batch work (imports, migrations, maintenance, encryption migration) is time-boxed
  (≤ 15–20 s per HTTP call) and resumable. **Nothing reliably runs after the response** on
  byethost: `Lifecycle` callbacks get `Lifecycle::budget()` seconds (1.5 s there) — keep them tiny.
- **10 MB maximum per physical file** (larger files are deleted by the host; appending past 10 MB
  is blocked). ⇒ blobs are stored as **segments of `STORAGE_SEGMENT_MB` (default 8 MiB)**;
  ZIPs are **streamed** (never written to a temp file); logs/backups rotate below 8 MB.
- Upload chunks: raw request bodies, ≤ 8 MiB and ≤ `Capabilities::maxRequestBytes() − 64 KiB`.
  Prefer ≤ 2 parallel chunk uploads per user.
- **MariaDB: 4 connections per account, `wait_timeout` 20 s, `max_allowed_packet` 3 MB.** One
  lazy connection per request; `Db::disconnect()` before any wait; never store file bytes in the DB;
  keep statements < 1 MB. Target MariaDB 10.3+/11.x and MySQL 5.7+ syntax (no CTEs, window
  functions, JSON functions, `SKIP LOCKED`, `RETURNING`). JSON lives in TEXT columns.
- **No held connections on byethost:** SSE/long-poll need `usleep` and a free entry process —
  real-time transport is chosen by capability (§10.3): SSE/long-poll where `Capabilities::canHold()`,
  otherwise **adaptive short polling with a no-database fast path**. 50,000 hits/day budget ⇒
  one poller per browser (leader tab), visibility-aware intervals, service-worker cache-first for
  static assets.
- **JavaScript cookie check (`__test`, rotates ~6 h)** sits in front of PHP: non-browser clients
  (curl, external cron, API scripts) are blocked; an expired cookie turns `fetch()` responses into
  an HTML page with status 200. Every JSON response carries header **`X-FT-Api: 1`**; the client
  treats a response without it as "challenge intercepted" (PHP never ran ⇒ safe to retry) and
  recovers via a hidden iframe, falling back to a reload (§12.3). Tolerate the extra `?i=1..3`
  query parameter the challenge appends. **Never compute or forge the `__test` cookie** (ToS).
- `open_basedir` = htdocs (+/tmp): storage and `.env` live **inside** the web root, protected by
  rewrite rules, `Require all denied` and random/opaque names. PHP 8.3/8.4 on the host.
- Outbound HTTP: one call at a time, connect timeout 5 s, total 10 s, fail soft (log + continue).
  SMTP only on 587 (often blocked). PWA manifest must be linked with `crossorigin="use-credentials"`.
- **Terms of Service:** byethost/iFastNet free hosting prohibits file-hosting/sharing sites.
  This is the owner's decision; the code stays portable (no host-specific paths, all limits
  configurable, capability probes instead of assumptions).
- PHP target: **8.1+** syntax (readonly properties, enums, `never`, first-class callables); no
  8.2+-only features. Required extensions: pdo_mysql, openssl, mbstring, json, fileinfo, curl,
  zlib. Optional (guard them): gd, zip, sodium, exif, intl.

### 0.3 Coding conventions
- Namespace `FT\` ⇒ `app/` (autoloaded by `app/bootstrap.php`). One class per file. `declare(strict_types=1);`
- Services are classes with **static methods** (matches the kernel style). Controllers are classes
  with instance methods `public function name(Request $req): mixed` and no constructor arguments.
- **No third-party PHP packages.** Front-end libraries only from `https://cdnjs.cloudflare.com`
  (Chart.js, pdf.js, highlight.js, qrcode-generator), version-pinned, loaded with Subresource
  Integrity through `features/lib-loader.js` and allowed by the CSP folder by folder (§12.5), or
  vendored into `assets/vendor/`.
- **SQL:** always `Db::run/one/all/value/insert/update/delete` with bound parameters. Never
  interpolate input into SQL. `Db::inList()` for IN lists, `Db::like()` for LIKE.
  **A named placeholder may appear only once per statement** (native prepares, `:a`…`:a` fails).
- Times are UTC in the DB (`Db::now()`), ISO-8601 with `Z` in JSON (`Db::iso()`). The UI renders
  **24-hour time** in the browser's locale/timezone using **en-GB** formatting (e.g. `03 Oct 2026, 14:31`).
- **All user-facing text in British English** (colour, organise, favourite, licence, cancelled…).
  The product is called **FastTransfer**; the company is **MTS** (never "MTS Global").
- Errors: throw `FT\Core\ApiException` (named constructors) with an error code from §9.3 and a
  message that is safe to show users. Never leak paths, SQL, stack traces or secrets.
- Every state change must: (1) authorise server-side, (2) write an `Audit::log()` entry (§7),
  (3) publish an `EventBus::publish()` event to the authorised audience (§10), (4) create
  notifications where §11 says so. Wrap multi-row changes in `Db::transaction()`.
- Never trust ids from the browser: re-load the row and check access (`FileAccess`, §6).
- Escape everything rendered into HTML (`htmlspecialchars` in PHP; DOM `textContent` in JS —
  **never assign untrusted data to `innerHTML`**).
- Validation helpers live on `Request` (`int()`, `string()`, `bool()`, `pagination()`).
- Logging: `Logger::info/warning/error/security(channel, msg, ctx)`; never log passwords, tokens,
  keys, share passwords or file contents.

---

## 1. Directory layout

```
index.php                     front controller (all requests)            [KERNEL]
maintenance.php               CLI + token-protected web maintenance runner [A6]
GET /service-worker.js        PWA service worker (PHP route, root scope)  [W2-ADMIN]
GET /manifest.webmanifest     PWA manifest (PHP route)                    [W2-ADMIN]
GET /offline                  offline fallback page (PHP route rendering views/offline.php) [W2-ADMIN]
.htaccess  .env.example  .gitignore                                         [KERNEL]
app/
  bootstrap.php                                                             [KERNEL]
  Core/      Env Config Db Logger RequestContext ApiException ErrorHandler
             Lifecycle Secrets Settings Audit Stats                         [KERNEL]
  Http/      Request Response Router                                        [KERNEL]
  Database/  Migrator                                                       [KERNEL]
  Events/    EventBus RealtimeSignal                                        [KERNEL]
             RealtimeController                                             [A5]
  Jobs/      Queue                                                          [KERNEL]
  Support/   HostCompat Install                                             [KERNEL]
             ClientConfig Csp                                               [FE-CORE]
             UserAgent                                                      [A1]
             Capabilities                                                   [KERNEL]
  Storage/   Paths                                                          [KERNEL]
             Crypto LegacyCbc BlobStore BlobReader MimeDetector FileStreamer
             Thumbnailer QuotaService                                       [A2]
  Uploads/   UploadService                                                  [A2]
  Files/     FileWriter                                                     [A2]
             FileAccess FileRepository FileService FolderService TrashService
             VersionService TagService ZipService ActivityService           [A3]
  Auth/      Auth Totp ApiTokens Passwords                                  [A1]
  Security/  Csrf RateLimiter Policy                                        [A1]
  Users/     UserService                                                    [A1]
  Sharing/   ShareService                                                   [A4]
  Comments/  CommentService                                                 [A4]
  Texts/     TextService UrlMeta                                            [A4]
  Collab/    EditorService                                                  [A4]
  Notepads/  NotepadService (team/private notepads, merge-friendly saves)
  Notifications/ Notifier NotificationService WebPush Mailer Slack          [A5]
  Search/    SearchService                                                  [A6]
  Ocr/       OcrService                                                     [A6]
  Admin/     StatsService                                                   [A6]
  Maintenance/ MaintenanceRunner PseudoCron                                 [A6]
  Legacy/    LegacyImporter EncryptionMigrator LegacyRoutes                 [A6]
  Controllers/Api/   *Controller.php   (owner = module that owns the route file)
  Controllers/Web/   ShellController [FE-CORE] AuthPageController [A1]
                     PublicShareController [A4] InstallController LegacyController [A6]
  routes/    one file per module, each returns static function (Router $r): void
views/       PHP templates: app.php [FE-CORE] login.php [A1] share.php [A4] install.php [A6]
             offline.php [W2-ADMIN]
assets/
  css/app.css                                                               [FE-CORE]
  js/app.js  js/core/*.js                                                   [FE-CORE]
  js/views/*.js  js/features/*.js  js/views/admin/*.js                      [WAVE 2]
  js/public-share.js                                                        [A4]
  img/  icons/                                                              [FE-CORE / W2-ADMIN]
database/migrations/001…009                                                 [KERNEL]
tests/       run.php lib.php server.php .env.testing                       [KERNEL]
             <Area>Test.php                                                 [each module]
             js/run.mjs js/*.test.mjs  (node: JS syntax checks + unit tests)
docs/        ARCHITECTURE.md (this) + API.md EVENTS.md DEPLOYMENT.md UPGRADE.md SECURITY.md TESTING.md
storage/     runtime data (denied over HTTP; prefer STORAGE_PATH outside web root)
```

**File ownership is exclusive.** Do not edit files owned by another module. If you need a change
in someone else's file, write it in your final report under "Requests for other modules".
Shared kernel files may only receive *additive* fixes if they are genuinely broken; report them.

---

## 2. Module owners (build waves)

| Id | Module | Wave |
|----|--------|------|
| KERNEL | bootstrap, Env, Config, Db, Logger, errors, Request/Response/Router, Migrator, Settings, Secrets, Audit, Stats, EventBus, RealtimeSignal, Queue, Paths, Install, HostCompat, migrations, test harness | done |
| A1 | Auth, sessions, 2FA, API tokens, CSRF, rate limiting, roles/permissions policy, users, admin user management API, Security Centre API, login page | 1 |
| A2 | Storage engine: AES-256-GCM crypto, legacy CBC reader, blob store + dedup + refcount, MIME detection, Range streaming, thumbnails, quotas, resumable uploads, FileWriter | 1 |
| A3 | Files domain: access control (FileAccess), listing, folders, rename/move, favourites, tags, trash/restore/purge, versions API, ZIP, downloads/preview endpoints, activity timeline | 1 |
| A4 | Sharing (links + users + bundles + folders, permissions, password, expiry, limits), public share pages, Shared With Me, comments, clipboard texts + URL previews, in-browser text editor + presence | 1 |
| A5 | Real-time endpoints (SSE / long-poll / poll / recovery), notification centre, preferences, Web Push (RFC 8291 + VAPID), e-mail (SMTP), Slack | 1 |
| A6 | Maintenance runner + pseudo-cron + CLI, admin dashboard/system APIs, search, OCR, legacy JSON importer, encryption migration, legacy URL shims, web installer | 1 |
| FE-CORE | App shell, design system CSS, JS core (api, bus, store, dom, format, ui, router, realtime, filelist, icons), boot config, CSP | 1 |
| W2-FILES | Views: dashboard, My Files, Recent, Favourites, Shared With Me, Trash, Clipboard, Search, Uploads; details panel; move dialog; editor UI | 2 |
| W2-FEAT | Upload manager (mobile-first), previewer, share dialog + QR + drag-and-drop sharing, notification centre UI, Security Centre UI, Settings UI | 2 |
| W2-ADMIN | Admin UI (dashboard with live charts, users, storage, shares, activity, system), PWA (manifest, service worker, icons, offline) | 2 |

---

## 3. Kernel API reference [KERNEL — exists]

```php
// Config & env
Env::get(string $key, ?string $default=null): ?string;  Env::bool(); Env::int(); Env::set() (tests)
Config::get('db.host'|'storage.path'|'encryption.key'|'realtime.hold_seconds'|…)  // see app/Core/Config.php
Settings::get/int/bool/string(string $key, $default=null); Settings::set($key, $value, ?int $by); Settings::all()
  // keys & defaults: Settings::DEFAULTS (app/Core/Settings.php) — trash_retention_days, default_quota_bytes, …

// Database
Db::run(sql, params): PDOStatement   Db::one()  Db::all()  Db::value()  Db::column()
Db::insert(table, row): int   Db::update(table, set, where): int   Db::delete(table, where): int
Db::transaction(fn): mixed (nestable)   Db::inList(ids, prefix): [sql, params]   Db::like(str)
Db::now(): 'Y-m-d H:i:s' UTC   Db::ts(unix)   Db::iso(?datetime): ?string   Db::toUnix(?datetime)
Db::disconnect()  // call before sleeping in long requests

// HTTP
Request::capture(); $req->method() path() isApi() query() input() all() json() int() string() bool()
  pagination(defaultPer, maxPer): [page, perPage, offset]  header() bearerToken() ip() userAgent()
  clientId() isHttps() basePath() baseUrl() param() intParam() bodyStream()
  $req->user (array|null, set by Router via Auth::resolve)  $req->authVia ('session'|'token'|null)
Response::ok($data, $meta=[], $status=200)  Response::created()  Response::paginated(items, total, page, per, extraMeta)
  Response::json()  Response::html()  Response::redirect()  Response::noContent()
  Response::finishEarly()  Response::contentDisposition(filename, inline)
Router: $r->get/post/put/patch/delete(pattern, [Controller::class,'method'], opts); $r->group(prefix, fn, opts)
  opts: auth none|optional|user|admin (default user for /api, none for web), csrf bool (default true),
        rate ?string bucket (default 'api' for /api), perm ?string permission slug, json bool, guest bool
  Controllers return array (=> {"success":true,"data":…}), a Response, or null (already streamed).

// Cross-cutting
Audit::log(string $action, ['user_id','actor_label','category','target_type','target_id','owner_id','detail','meta'])
Stats::bump(string $metric, int $by=1)   Stats::setToday()   Stats::series(metrics, days)
EventBus::publish(type, data, recipientIds, ['actor_id','file_id','folder_id','share_id','origin','admin'=>bool]): int
EventBus::fileAudience(int $fileId): int[]   EventBus::folderAudience(int $folderId): int[]
EventBus::ancestorFolderIds(int $folderId): int[]
EventBus::since(userId, afterId, limit=200, includeAdminChannel=false): ['events','reset','last_id','has_more']
EventBus::latestIdFor(userId, includeAdmin=false): int   EventBus::format(row): array
RealtimeSignal::bump(userId, eventId)  RealtimeSignal::read(userId): int    // user 0 = admin channel
Queue::push('FT\Some\Class::nameJob', payload, delaySeconds=0, queue='default', maxAttempts=3): int
Queue::work(maxSeconds, maxJobs): int   Queue::counts()
Lifecycle::onTerminate(key, callable)   // run after the response is flushed
Secrets::encrypt(string): string  Secrets::decrypt(?string): ?string  Secrets::hmac(data, purpose)  Secrets::token(len)
Paths::root() userDir(uid, ''|'files'|'temp'|'bundles'|'thumbs') sharedBlobs() runtime(sub) logs() backups()
  Paths::absolute(relative) Paths::relative(absolute)
RequestContext::userId() ip() userAgent() clientId() id()
Install::isReady() markInstalled(extra) latestMigration()
Capabilities::canHold() sleep(sec) setTimeLimit(sec) ignoreUserAbort() canFinishEarly() hasGd() hasZipArchive()
  hasCurl() hasEcCrypto() maxRequestBytes() iniBytes(str) report()      // ALWAYS use these for possibly-disabled functions
Lifecycle::budget(): float   // seconds of post-response work allowed (1.5 s when the host cannot detach)
Migrator::migrate(backupFirst=true) status() pending() isInstalled() backup(label)
```

Request lifecycle: `index.php` → `HostCompat::apply()` → legacy shim check → `Install::isReady()`
(else redirect to `/install`) → `Router::loadRouteFiles(app/routes)` → `dispatch()`:
`RequestContext::init` → route match → baseline headers → `Auth::resolve()` (A1) → auth/role
checks → `Csrf::verify()` (A1, unsafe methods with session auth) → `RateLimiter::enforce()` (A1)
→ `Policy::requirePermission()` (A1) → controller → send → `Lifecycle::terminate()` (queue,
pseudo-cron).

---

## 4. Database schema [KERNEL — exists]

Migrations `database/migrations/001_users.sql … 009_seed.sql` (read them — they are the
authoritative column list). Key invariants:

| Concept | Rule |
|---|---|
| Blobs / dedup | `file_blobs` is content-addressed per `scope` (`u<ownerId>` by default; `global` if setting `dedup_scope=global`). **`ref_count = number of file_versions rows referencing the blob`.** The physical file is deleted only when ref_count reaches 0. FK `file_versions.blob_id → file_blobs.id` (RESTRICT) makes deleting a referenced blob row impossible. |
| Versions | **Every** version including the current one has a `file_versions` row. `files.blob_id/version/size/sha256/mime` mirror the current version. Restoring version N creates version M+1 pointing to N's blob (non-destructive). |
| Quota | `users.used_bytes = SUM(file_versions.size)` over files the user owns, **including trashed files and all versions**. Available = effective quota − used − active upload reservations (`upload_sessions.size − received_bytes`… simplified: the declared `size` of `active`/`assembling` sessions). Effective quota: `users.quota_bytes` if not NULL (`PHP_INT_MAX` sentinel = unlimited), else role default: admin = unlimited, user = `default_quota_bytes`, guest = `guest_quota_bytes`. |
| Trash | Soft delete: `deleted_at`, `deleted_by`, `trash_batch`, `trash_original_folder_id` / `trash_original_parent_id`, `trash_reason` on `files` and `folders`. Trashing a folder trashes all descendants with the same `trash_batch`; restoring the folder restores that batch. Purge date = `deleted_at + trash_retention_days` (0 = never). Trashed items never appear in listings, search (unless `trash=1`), Shared With Me or link shares. |
| Auto-expiry | Legacy behaviour preserved: a new upload not marked "Keep forever" gets `is_permanent=0, expires_at = now + auto_expire_hours` (setting, default 72; 0 disables). Maintenance moves expired files to **Trash** (reason `expired`) instead of deleting them. Same for clipboard texts (`text_auto_expire_hours`, texts are hard-deleted when expired). |
| Shares | `shares.kind` link/user, `target_type` file/folder/bundle (`share_items`). Status = revoked if `revoked_at`; expired if `expires_at <= now`; exhausted if `max_downloads` reached (still viewable, not downloadable). Legacy 32-hex tokens are preserved; new tokens are 22-char base62 (`Secrets::token(22)`). |
| Events | `events` + `event_recipients` (fan-out on write, user 0 = admin channel). Retention `event_retention_days`; maintenance stores the first retained id in setting `events_pruned_before_id`. |
| Audit | `audit_logs` is durable activity history; `owner_id` = owner of the target so owners can read activity on their items. |
| Sessions | PHP native session + a `user_sessions` row per login (`sid_hash = sha256(session_id())`). Every request validates the row (not revoked, not expired, user active) ⇒ disabling a user or revoking a session takes effect on the next request (and a `session.revoked` event closes open tabs immediately). |
| Time | All DATETIME columns are UTC. |

---

## 5. Roles & permissions (A1)

Roles: `admin` (1), `user` (2), `guest` (3). Permission slugs (seeded in 009): `files.view`
`files.upload` `files.edit` `files.delete` `files.share` `files.comment` `texts.manage`
`search.use` `api.tokens` `admin.access` `admin.users` `admin.storage` `admin.shares`
`admin.activity` `admin.system`. Guests: `files.view`, `files.comment`, `search.use` only —
they see only what is shared with them, cannot upload (quota 0) and cannot create shares.

```php
Policy::can(?array $user, string $perm): bool        // role_permissions, cached per request
Policy::requirePermission(?array $user, string $perm): void   // throws FORBIDDEN / UNAUTHENTICATED
Policy::isAdmin(?array $user): bool
```

The `user` array used everywhere (`$req->user`, `Auth::user()`) is the `users` row plus
`role` (slug) and `session_id` (user_sessions.id or null) — **never** includes `password_hash`
or `totp_secret_enc` once it leaves A1 code (strip them in `Auth::resolve`).

---

## 6. File access control (A3) — the single source of truth

```php
FileAccess::accessFor(?array $user, array $fileRow): ?array     // capabilities or null (no access)
FileAccess::require(?array $user, int $fileId, string $capability, bool $includeTrashed = false): array
    // returns the files row + ['access' => caps]; throws FILE_NOT_FOUND (404) if the user has no
    // access at all (do not reveal existence), FORBIDDEN (403) if they can see it but lack $capability
FileAccess::folderAccessFor(?array $user, array $folderRow): ?array
FileAccess::requireFolder(?array $user, int $folderId, string $capability, bool $includeTrashed = false): array
FileAccess::requireFolderWrite(?array $user, ?int $folderId): ?int   // upload/create target check; null = own root
FileAccess::forLinkShare(array $share, int $fileId): array          // file within a link share's scope + caps
FileAccess::sharesFor(int $userId, array $fileRow): array           // active user shares granting access
```

Capabilities map (`caps`):
```json
{"role":"owner|admin|editor|commenter|downloader|viewer",
 "preview":true,"download":true,"comment":true,"edit":true,"share":true,"delete":true,
 "move":true,"versions":true,"activity":true,"manage":true}
```
Resolution order:
1. Trashed file ⇒ only owner/admin (and only with `$includeTrashed`).
2. Owner ⇒ everything (`role:"owner"`).
3. Admin ⇒ everything (`role:"admin"`); admin access to someone else's content is audit-logged with category `admin`.
4. Active (not revoked, not expired) **user shares** for this user on the file, on a bundle
   containing it, or on any ancestor folder: take the highest level; flags OR-combined across
   shares. Level grants: viewer ⇒ preview; downloader ⇒ +download; commenter ⇒ +comment;
   editor ⇒ +edit (+ upload into a shared folder, rename, new version, in-browser edit).
   A flag (`allow_preview/download/comments/edit`) set to 0 removes that grant. `share` = owner
   or `allow_reshare` (a re-sharer may grant at most their own level). `delete`, `move` and
   `manage` are owner/admin only. `versions` and `activity` = owner/admin/editor.
5. Otherwise no access.

Folder caps: `view`, `upload` (owner/admin/editor via folder share), `edit` (rename; owner/admin/editor),
`share`, `delete`/`move`/`manage` (owner/admin). Files uploaded into someone else's shared
folder are **owned by the folder owner** (quota charged to them) with `created_by` = uploader.

---

## 7. Audit actions & activity timeline

Use the action names listed in `app/Core/Audit.php`. File timeline entries
(`GET /files/{id}/activity`, A3 `ActivityService`) read `audit_logs WHERE target_type='file' AND target_id=?`
and render human sentences in British English, e.g.:
`file.upload` "Kritarth uploaded the file", `file.download` "Rahul downloaded the file",
`share.create` "File was shared with Rahul" / "Kritarth created a share link",
`file.version_upload` "Kritarth uploaded version 2", `file.comment` "Rahul added a comment",
`file.preview` "Rahul viewed the file" (log previews at most once per user/file per 10 minutes),
`file.rename` "… renamed the file from A to B", `file.move` "… moved the file to Work",
`file.trash`, `file.restore`, `share.revoke` "… stopped sharing with Rahul",
`share.update` "… changed Rahul's permission to Editor", `file.version_restore` "… restored version 1".
Anonymous link actors: `actor_label = "Someone with the link"`.

---

## 8. Storage engine (A2)

### 8.1 Encryption format `gcm1` (AES-256-GCM, chunked, authenticated)
```
Header (32 bytes):
  0  magic "FTG1" (4)   4  version 0x01 (1)   5  chunk_size_log2 = 20 (1 MiB) (1)   6 reserved 0x0000 (2)
  8  base_nonce (12, random)   20 plaintext_size (8, uint64 big-endian)   28 reserved 0x00000000 (4)
Body: chunk i = AES-256-GCM(DEK, nonce_i, plaintext_i, aad_i) ciphertext || tag(16)
  plaintext chunk = 1 MiB except the last; an empty file has exactly one empty chunk
  nonce_i = base_nonce XOR (uint32 BE i right-aligned in 12 bytes)
  aad_i   = header(32) || uint32 BE i || final_flag (1 byte: 1 for the last chunk)
DEK: 32 random bytes per blob. file_blobs.enc_dek = base64(nonce(12)||tag(16)||AES-256-GCM(KEK, DEK, aad="ft-dek|<key_id>"))
KEK: ENCRYPTION_KEY ("base64:…" 32 bytes, 64 hex chars, or ≥32-char string → HKDF-SHA256), id ENCRYPTION_KEY_ID;
     ENCRYPTION_OLD_KEYS "id:key,…" for reading blobs wrapped with older keys. Keys never leave the server.
```
Any tag failure, truncation (missing final chunk) or size mismatch ⇒ throw (never return
partial plaintext as success). Random access: chunk index = floor(offset / 1 MiB).

### 8.1a Physical layout: segments (all encodings)
The stored byte stream of a blob (gcm1 stream, plain bytes, or legacy_cbc text) is split into
**segment files of exactly 8 MiB (8 388 608 bytes) except the last** — a fixed constant
`BlobStore::SEGMENT_BYTES`, never changed, so every blob ever written stays readable.
(`STORAGE_SEGMENT_MB` / `Config storage.segment_bytes` only caps upload *chunk* sizes.)
Files: `<dir>/<sha256>.0`, `<sha256>.1`, … where `<dir>` = `users/<ownerId>/files/<aa>`
(scope `u<id>`) or `shared/blobs/<aa>` (scope `global`), `<aa>` = first two hex chars of the hash.
`file_blobs.storage_path` stores the **base path without the segment suffix** (relative to
STORAGE_PATH) and `stored_size` the total stored bytes; segment count =
`max(1, ceil(stored_size / SEGMENT_BYTES))`. `BlobReader` maps a stored offset to
(segment, offset) and reads across segment boundaries; a missing or short segment ⇒
`RuntimeException` ("stored file is missing or damaged") — never silently truncated. Writers
create segments in a temp dir under the owner's `temp/` area and move them into place only after
the whole blob is written; the dedup check happens after hashing (if `(scope, sha256)` exists:
discard the temp copy and `retain()` the existing blob).

### 8.2 Legacy `legacy_cbc`
Pre-upgrade format: file contents `base64(iv) . '::' . base64(AES-256-CBC ciphertext)`, key =
hex string in `uploads/.enc_key` (`LEGACY_ENCRYPTION_KEY_FILE`). Read-only support
(`LegacyCbc::decryptFile(path): string`) until the encryption migration (A6) converts every
`legacy_cbc` blob to `gcm1` with verification.

### 8.3 Services
```php
Crypto::enabled(): bool
Crypto::encryptFile(string $src, string $dst): array{enc_key_id:string, enc_dek:string, stored_size:int}
Crypto::openDecryptStream(string $path, string $keyId, string $encDek): BlobReader
Crypto::deriveKey(string $purpose): string            // HKDF from the current KEK (e.g. "thumb:<fileId>")
Crypto::encryptString(string $data, string $purpose): string / decryptString(...)  // for thumbnails

BlobStore::SEGMENT_BYTES = 8388608                               // fixed on-disk segment size (§8.1a)
BlobStore::scopeFor(int $ownerId): string                       // 'u12' or 'global'
BlobStore::putStream(resource $plainStream, string $scope, ?string $mime = null): array // used by upload assembly (reads chunk files in order)
BlobStore::putFile(string $tmpPlainPath, string $scope, ?string $mime = null): array   // dedup + retain(+1) — returns file_blobs row
BlobStore::putString(string $data, string $scope, ?string $mime = null): array
BlobStore::retain(int $blobId): void          // ref_count + 1
BlobStore::release(int $blobId): void         // ref_count − 1; deletes the physical file after commit when 0
BlobStore::get(int $blobId): array
BlobStore::open(array $blobRow): BlobReader   // read(int), seek(int), size(), eof(), close()
BlobStore::readAll(array $blobRow, int $maxBytes): string     // throws if larger
BlobStore::toTempFile(array $blobRow): string  // decrypted temp copy (caller unlinks) for OCR/thumbs (≤ 8 MiB; else throw)
BlobStore::importLegacyCbc(string $legacyPath, string $scope, string $plainSha256, int $plainSize, ?string $mime): array
   // A6 importer: copies a legacy AES-256-CBC file byte-for-byte into segments (encryption 'legacy_cbc'),
   // dedups on (scope, plainSha256), retains, returns the blob row. Never modifies the legacy file.
BlobStore::reencode(array $blobRow): array
   // A6 encryption migration: legacy_cbc|none → gcm1 (when Crypto::enabled()). Decrypts/streams, verifies the
   // plaintext SHA-256 equals blob.sha256, writes new segments, swaps storage_path/encryption/enc_* atomically,
   // then deletes the old segments. Throws (and leaves the blob untouched) on any mismatch.
BlobStore::sweep(int $minAgeSeconds = 3600, int $limit = 200): int
   // maintenance: delete physical segments + rows of blobs with ref_count = 0 untouched for $minAgeSeconds.
   // release() only decrements (deferred deletion avoids races with concurrent dedup).

MimeDetector::detect(string $path, string $filename): array{mime:string, ext:string, kind:string}
MimeDetector::kindFor(string $ext, string $mime): string   // image|video|audio|pdf|document|spreadsheet|presentation|code|text|archive|other
MimeDetector::inlineType(string $mime, string $ext): ?string  // safe Content-Type for inline, or null => attachment only
MimeDetector::isBlockedExtension(string $ext): bool            // settings.blocked_extensions

FileStreamer::send(array $fileRow, array $blobRow, Request $req, bool $inline, ?string $name = null): void
  // Range (single range), ETag/If-None-Match (sha256+version), 206/416, Accept-Ranges,
  // Content-Disposition via Response::contentDisposition, X-Content-Type-Options: nosniff,
  // Content-Security-Policy: "default-src 'none'; img-src 'self' data:; media-src 'self'; style-src 'unsafe-inline'; sandbox"
  // text/* and code are ALWAYS served as text/plain; charset=utf-8; html/svg never as active content.

Thumbnailer::generateJob(array $payload): void   // queue handler: ['file_id'=>int]; GD; max 400 px; JPEG q78 (WebP if available)
Thumbnailer::send(array $fileRow, Request $req): void

QuotaService::effectiveQuota(array $userRow): ?int     // null = unlimited
QuotaService::usage(int $userId): array{quota_bytes:?int, used_bytes:int, reserved_bytes:int, available_bytes:?int, percent:float}
QuotaService::assertCanStore(int $ownerId, int $bytes, ?string $excludeUploadId = null): void   // QUOTA_EXCEEDED
QuotaService::adjust(int $userId, int $deltaBytes): void  // updates used_bytes, publishes quota.updated, warns once over quota_warning_percent
QuotaService::recalculate(int $userId): int               // authoritative SUM; used by maintenance

FileWriter::createFile(int $ownerId, ?int $folderId, string $name, array $blob, array $o = []): array   // returns files row
   // $o: created_by, tags[], is_permanent(bool), expires_at, description, on_conflict ('rename'|'replace'|'error'),
   //     note, legacy_name, is_bundle, created_at (import), mime/kind overrides, silent (no events; importer)
   // conflict 'rename' => "name (1).ext"; 'replace' => addVersion to the existing file
FileWriter::addVersion(int $fileId, array $blob, int $userId, string $note = ''): array   // new current version
FileWriter::restoreVersion(int $fileId, int $version, int $userId): array
FileWriter::pruneVersions(int $fileId): int   // enforce version_retention_count/days (never the current)
FileWriter::uniqueName(int $ownerId, ?int $folderId, string $name, ?int $exceptFileId = null): string
FileWriter::sanitizeName(string $name): string   // strip control chars, / \ : * ? " < > |, trim dots/spaces, max 255 bytes, never empty
```
FileWriter is responsible for: version rows, `files` mirror columns, blob refcounts, quota
`adjust`, `file.created`/`version.created`/`file.updated` events, audit (`file.upload`,
`file.version_upload`, `file.version_restore`), Stats (`uploads`, `upload_bytes`), queueing
`Thumbnailer::generateJob`, `OcrService::ocrJob` and `OcrService::indexContentJob` (A6; guard
with `class_exists`), and Slack (`Slack::notify`, A5; guard with `class_exists`).

### 8.4 Upload protocol (A2: UploadService + UploadController)
```
POST   /api/v1/uploads                       {name,size,folder_id?,file_id?,mime?,tags?:[],is_permanent?:bool,
                                              on_conflict?:'rename'|'replace'|'error',last_modified?:int}
       201 {id, chunk_size, total_chunks, received:[], expires_at}
       checks: files.upload perm, name, size ≤ max_upload_bytes, blocked ext, folder write access (or file edit
       access for file_id), quota (reserve `size`). Emits upload.started.
PUT    /api/v1/uploads/{id}/chunks/{index}   raw body (application/octet-stream); POST also accepted
       body length must equal the expected chunk length; idempotent (re-sending a chunk overwrites it);
       written to Paths::userDir(uid,'temp')/<id>/<index>.part atomically (tmp + rename).
       200 {received_chunks, received_bytes, total_chunks}. Emits upload.progress at most every 2 s.
GET    /api/v1/uploads/{id}                  {id,name,size,status,received:[…],received_bytes,total_chunks,chunk_size,result_file_id?}
POST   /api/v1/uploads/{id}/complete         assemble → hash → MIME detect → BlobStore::putFile → FileWriter
       201 FileSummary  (idempotent: a completed session returns its file). Emits upload.completed (+file events).
DELETE /api/v1/uploads/{id}                  abort; frees temp + reservation; emits upload.failed {reason:'aborted'}
GET    /api/v1/uploads?status=active         this user's in-progress uploads (all devices)
POST   /api/v1/files                         multipart single-request upload (field "file", + folder_id, tags,
                                              is_permanent, on_conflict) for small files and API clients
```
Upload sessions expire after `upload_session_ttl_hours`; maintenance removes stale temp data.
Assembly must stream (never load whole files into memory) and must re-check quota.

---

## 9. REST API (`/api/v1`)

### 9.1 Conventions
- JSON in/out. Success: `{"success":true,"data":…,"meta":{…}}`. Lists: `meta` has
  `page, per_page, total, total_pages, has_more` (+ extras). Error:
  `{"success":false,"error":{"code":"FILE_NOT_FOUND","message":"The requested file could not be found.","details":{…}}}`.
- Auth: cookie session (web app; send `X-CSRF-Token` on unsafe methods) **or**
  `Authorization: Bearer <api token>` (no CSRF). `X-Client-Id` identifies the browser/device.
- Method override: `POST` + `X-HTTP-Method-Override: PATCH|PUT|DELETE` is accepted everywhere.
- Pagination params `page` (1-based), `per_page` (default 50, max 200). Sorting `sort`
  (`name|size|created_at|updated_at|kind`), `order` (`asc|desc`).
- Status codes: 200, 201, 204, 304, 400, 401, 403, 404, 405, 409, 413, 415, 419 (CSRF), 422, 429, 500, 503.
- Rate-limit buckets (A1 `RateLimiter`): `api` 300/min per user (or IP); `login` 10 per 15 min per IP
  and 5 per 15 min per username (settings `login_max_attempts`/`login_window_minutes`);
  `password` 5/hour; `share_create` 30/10 min; `download` 120/min; `share_password` 10/15 min per IP+share;
  `upload_chunk` 900/min; `realtime` 240/min; `public_comment` 10/10 min per IP; `public` 120/min per IP.
  429 responses carry `Retry-After`.

### 9.2 Shapes
**User (me)** — `GET /api/v1/user`, also in boot data:
```json
{"id":1,"username":"admin","display_name":"Admin","email":null,"role":"admin","status":"active",
 "quota":{"quota_bytes":null,"used_bytes":1234,"reserved_bytes":0,"available_bytes":null,"percent":0},
 "two_factor_enabled":false,"must_change_password":false,"password_changed_at":"…Z",
 "created_at":"…Z","last_login_at":"…Z","preferences":{"theme":"dark","view":"grid","sort":"created_at","order":"desc"},
 "permissions":["files.view","files.upload", "…"]}
```
**UserRef**: `{"id":2,"username":"alice","display_name":"Alice"}`

**FileSummary** (A3 `FileRepository::summary($row, $viewer)`; lists hydrate tags/favourites/
comment counts/share flags in a constant number of queries — no N+1):
```json
{"id":123,"type":"file","name":"report.pdf","ext":"pdf","mime":"application/pdf","kind":"pdf",
 "size":12345,"folder_id":5,"owner":UserRef,"created_at":"…Z","updated_at":"…Z",
 "version":2,"favorite":false,"tags":["work"],"is_permanent":true,"expires_at":null,
 "download_count":4,"comment_count":1,"is_shared":true,"has_thumbnail":true,"encrypted":true,
 "is_bundle":false,"description":null,
 "access":Capabilities, "trash":null}
```
`trash` (only in Trash listings): `{"deleted_at":"…Z","deleted_by":UserRef,"original_folder_id":5,
"original_path":"/Work/Reports","reason":"user","purge_at":"…Z"|null,"days_left":29|null}`.
In **events**, `data.file` is a FileSummary **without** `access` and `favorite` (they are per-viewer):
clients assume `owner` access when `file.owner.id === me.id`, otherwise fetch `GET /files/{id}`.

**FolderSummary**: `{"id":5,"type":"folder","name":"Work","parent_id":null,"owner":UserRef,
"created_at":"…Z","updated_at":"…Z","is_shared":false,"access":FolderCaps,"trash":null}`

**ShareSummary**:
```json
{"id":9,"kind":"link","target_type":"file","file_id":123,"folder_id":null,"file_ids":[123],
 "title":"report.pdf","url":"https://host/s/AbC123xyz…","recipient":null,"owner":UserRef,
 "permission":"downloader","allow_preview":true,"allow_download":true,"allow_comments":false,
 "allow_edit":false,"allow_reshare":false,"has_password":true,"expires_at":null,
 "max_downloads":null,"download_count":0,"access_count":3,"status":"active|expired|revoked|exhausted",
 "created_at":"…Z","updated_at":"…Z","last_accessed_at":"…Z","message":null}
```
`url` is present only for link shares and only for the share owner/file owner/admin.
Shared-with-me items: `{"share":ShareSummary(without url),"item":FileSummary|FolderSummary,"shared_at":"…Z","last_accessed_at":"…Z"}`.

**Notification**: `{"id":1,"category":"share","type":"share.received","title":"Alice shared “report.pdf” with you",
"body":"","data":{"file_id":123,"share_id":9,"link":"#/shared"},"actor":UserRef|null,"read":false,"created_at":"…Z"}`

**Event**: see §10.

### 9.3 Error codes
`BAD_REQUEST INVALID_JSON VALIDATION_FAILED UNAUTHENTICATED FORBIDDEN CSRF_TOKEN_INVALID NOT_FOUND
FILE_NOT_FOUND FOLDER_NOT_FOUND SHARE_NOT_FOUND USER_NOT_FOUND UPLOAD_NOT_FOUND COMMENT_NOT_FOUND
NOTIFICATION_NOT_FOUND METHOD_NOT_ALLOWED CONFLICT NAME_CONFLICT VERSION_CONFLICT FOLDER_CYCLE
NOT_IN_TRASH ALREADY_IN_TRASH QUOTA_EXCEEDED PAYLOAD_TOO_LARGE BLOCKED_FILE_TYPE CHUNK_INVALID
UPLOAD_INCOMPLETE UPLOAD_EXPIRED RATE_LIMITED INVALID_CREDENTIALS ACCOUNT_DISABLED ACCOUNT_SUSPENDED
ACCOUNT_LOCKED TWO_FACTOR_REQUIRED TWO_FACTOR_INVALID PASSWORD_CHANGE_REQUIRED PASSWORD_TOO_WEAK
TOKEN_INVALID SESSION_REVOKED SHARE_EXPIRED SHARE_REVOKED SHARE_PASSWORD_REQUIRED
SHARE_PASSWORD_INVALID SHARE_DOWNLOAD_LIMIT FEATURE_UNAVAILABLE NOT_INSTALLED SERVER_ERROR
FILE_UNAVAILABLE` (stored data missing or damaged, e.g. removed by the host) · client-only: `HOST_CHALLENGE`

### 9.4 Endpoints (owner in brackets)
Route files are loaded alphabetically and the first match wins, so **always constrain numeric ids**
(`/files/{id:\d+}`) — otherwise `/files/zip` or `/files/batch` would be captured by `/files/{id}`.
Each route is registered by exactly one module (the owner in brackets), even when it shares a
prefix with another module's routes (e.g. `/files/{id:\d+}/comments` is A4's, `/files/{id:\d+}/ocr` A6's).
```
# Auth & user [A1]
POST   /api/v1/auth/login            {username,password,remember?,totp_code?,issue_token?,token_name?}
                                     200 {user, csrf_token, token?}  | 401 INVALID_CREDENTIALS
                                     | 403 ACCOUNT_DISABLED/SUSPENDED | 200 {two_factor_required:true, challenge:"…"}
POST   /api/v1/auth/2fa              {challenge, code, remember?} → {user, csrf_token}
POST   /api/v1/auth/logout           → 204 (revokes current session + remember cookie)
GET    /api/v1/auth/csrf             (auth optional) → {csrf_token}
GET    /api/v1/user                  → User(me)
PATCH  /api/v1/user                  {display_name?, email?, preferences?}
POST   /api/v1/user/password         {current_password, new_password} → revokes other sessions
POST   /api/v1/user/2fa/setup        → {secret, otpauth_uri}   (QR rendered client-side; never via third parties)
POST   /api/v1/user/2fa/enable       {code} → {recovery_codes:[…]} (shown once)
POST   /api/v1/user/2fa/disable      {password, code}
GET    /api/v1/users/lookup?q=       (≥2 chars, not guests) → [UserRef] for the share dialog (max 10)

# Security Centre [A1]
GET    /api/v1/security/overview     {account_status, password:{changed_at, age_days, weak}, two_factor, sessions_count,
                                      active_links, expiring_links, suspicious_logins_30d, api_tokens, devices}
GET    /api/v1/security/sessions     [{id,current,ip,device,user_agent,created_at,last_seen_at,expires_at,method}]
DELETE /api/v1/security/sessions/{id}
POST   /api/v1/security/sessions/revoke-all   {include_current?:false}
GET    /api/v1/security/logins       paginated login_history (success/failed/suspicious)
GET    /api/v1/security/events       paginated audit_logs category=security for me
GET    /api/v1/security/devices      [{id,name,last_ip,first_seen_at,last_seen_at,push_enabled,current}]
GET    /api/v1/security/tokens       [{id,name,token_prefix,scopes,last_used_at,expires_at,created_at}]
POST   /api/v1/security/tokens       {name, scopes?, expires_in_days?} → {token:"ft_…" (shown once), …}
DELETE /api/v1/security/tokens/{id}

# Admin users [A1]  (auth admin, perm admin.users)
GET    /api/v1/admin/users           ?q=&status=&role=&page= → [AdminUser] (+usage, last_login_at, created_at, two_factor)
POST   /api/v1/admin/users           {username,password?,email?,display_name?,role,quota_bytes?,must_change_password?}
                                     → {user, temporary_password?}
GET    /api/v1/admin/users/{id}      AdminUser + recent activity
PATCH  /api/v1/admin/users/{id}      {display_name?,email?,role?,quota_bytes?(null=role default, -1=unlimited)}
DELETE /api/v1/admin/users/{id}      soft delete + revoke sessions + queue data purge (cannot delete self/last admin)
POST   /api/v1/admin/users/{id}/disable|enable|suspend     {reason?}
POST   /api/v1/admin/users/{id}/reset-password             {password?} → {temporary_password} (must_change_password=1)
POST   /api/v1/admin/users/{id}/force-logout               revoke all sessions + publish session.revoked
POST   /api/v1/admin/users/{id}/2fa/disable
GET    /api/v1/admin/users/{id}/activity                    paginated audit_logs by/for the user

# Files [A3] (content endpoints use A2 FileStreamer)
GET    /api/v1/files                 ?folder_id=|root=1 &view=all|recent|favorites &kind=&tag=&q=&sort=&order=&page=&per_page=
                                     → [FileSummary], meta{…, folder:FolderSummary|null, breadcrumbs:[{id,name}], folders:[FolderSummary] (page 1 only)}
POST   /api/v1/files                 [A2] simple multipart upload
GET    /api/v1/files/{id}            → FileSummary (+ "versions_count", "shares" (owner only), "path")
PATCH  /api/v1/files/{id}            {name?, folder_id?, description?, is_permanent?, tags?:[…], favorite?}
DELETE /api/v1/files/{id}            → move to Trash (204)            ?permanent=1 only for items already in trash
POST   /api/v1/files/{id}/restore    → FileSummary (restores into original folder, or root if that is gone; renames on conflict)
POST   /api/v1/files/{id}/share      [A4] same body as POST /shares with file_ids=[id]
GET    /api/v1/files/{id}/download   attachment (Range) — perm download; increments download_count; notifies owner (download category) for non-owners
GET    /api/v1/files/{id}/content    inline safe preview (Range) — perm preview; logs file.preview (throttled)
GET    /api/v1/files/{id}/thumbnail  image/jpeg|webp or 404
GET    /api/v1/files/{id}/activity   timeline [{id,action,text,actor:UserRef|null,actor_label,created_at,meta}]
GET    /api/v1/files/{id}/versions   [{version,size,sha256,name,created_by:UserRef,created_at,note,current}]
GET    /api/v1/files/{id}/versions/{version}/download
POST   /api/v1/files/{id}/versions/{version}/restore   → FileSummary
POST   /api/v1/files/{id}/versions   [A2 via upload sessions: POST /uploads {file_id}] (documented alias)
POST   /api/v1/files/batch           {action:'trash'|'move'|'tag'|'untag'|'favorite'|'unfavorite'|'permanent', ids:[…], folder_id?, tag?, value?}
                                     → {done:[ids], failed:[{id,code,message}]}
POST   /api/v1/files/zip             {file_ids:[…], folder_ids:[…], name?} → application/zip stream (form POST allowed)
                                     ZipService MUST stream the archive (no temp ZIP file — hosts delete files > 10 MB):
                                     STORE method, general-purpose bit 3 (data descriptor) + bit 11 (UTF-8 names),
                                     CRC-32 via hash_init('crc32b') while streaming, ZIP64 records when sizes ≥ 4 GiB.
                                     Limits: max 2,000 entries / max_upload_bytes × 10 total; folder ZIPs keep relative paths.
GET    /api/v1/tags                  → [{name,count}] (own tags)

# Folders [A3]
GET    /api/v1/folders               ?parent_id=|root=1 → [FolderSummary]
GET    /api/v1/folders/tree          → [{id,name,parent_id}] all own (non-trashed) folders (+ shared folders flagged)
POST   /api/v1/folders               {name, parent_id?} → FolderSummary (NAME_CONFLICT if duplicate in parent)
GET    /api/v1/folders/{id}          → FolderSummary + breadcrumbs
PATCH  /api/v1/folders/{id}          {name?, parent_id?} (FOLDER_CYCLE)
DELETE /api/v1/folders/{id}          → trash folder + contents
POST   /api/v1/folders/{id}/restore
POST   /api/v1/folders/{id}/share    [A4]
GET    /api/v1/folders/{id}/zip

# Trash [A3]
GET    /api/v1/trash                 ?kind=file|folder&q=&page= → [FileSummary|FolderSummary with trash{}], meta{retention_days,total_bytes}
POST   /api/v1/trash/{id}/restore    ?kind=folder for folders
DELETE /api/v1/trash/{id}            permanent delete (?kind=folder)
DELETE /api/v1/trash                 empty trash → {purged_files, purged_folders, freed_bytes}
GET    /api/v1/admin/trash           [admin.storage] all users' trash (+owner); same restore/delete routes accept admins

# Uploads [A2] — see §8.4

# Shares [A4]
GET    /api/v1/shares                ?status=active|expired|revoked|all &kind= → [ShareSummary] (created by me)
POST   /api/v1/shares                {kind:'link'|'user', file_ids?:[…], folder_id?, recipients?:[userId|username],
                                      permission:'viewer'|'downloader'|'commenter'|'editor', password?, expires_at?|expires_in?(seconds),
                                      max_downloads?, allow_preview?, allow_download?, allow_comments?, allow_edit?, allow_reshare?,
                                      title?, message?} → [ShareSummary] (one per recipient for user shares)
GET    /api/v1/shares/{id}           → ShareSummary
PATCH  /api/v1/shares/{id}           {permission?, password?(""=remove), expires_at?, max_downloads?, allow_*?, title?}
DELETE /api/v1/shares/{id}           revoke immediately → 204
GET    /api/v1/shares/with-me        → Shared-with-me items (active only; owner, permission, shared date, expiry, last accessed)
GET    /api/v1/files/{id}/shares     owner/admin: shares on this file
GET    /api/v1/admin/shares          [admin.shares] all shares, filters ?status=&owner_id=

# Public link pages [A4] (no login; HTML; CSRF via per-page token in a hidden field)
GET    /s/{token}                    page (password form if needed). Legacy `/?share=<32hex>` redirects here.
POST   /s/{token}/unlock             {password} (also accepts legacy field "share_password")
GET    /s/{token}/download           ?file={id} (single-file share: file param optional) attachment, counts downloads
GET    /s/{token}/content/{fileId}   inline preview (Range) if allow_preview
GET    /s/{token}/thumbnail/{fileId}
GET    /s/{token}/zip                bundle/folder ZIP (counts one download)
GET    /s/{token}/folder/{folderId}  browse inside a shared folder (JSON for the page script)
POST   /s/{token}/comments           {name, body} if allow_comments (rate limited)
POST   /s/{token}/upload             editor link shares: new version of a single-file share (≤ one request)

# Comments [A4]
GET    /api/v1/files/{id}/comments   → [{id,body,author:UserRef|null,author_name,created_at,edited_at,can_delete}]
POST   /api/v1/files/{id}/comments   {body} (perm comment) → comment; notifies owner + other participants
DELETE /api/v1/comments/{id}         author, file owner or admin

# Clipboard texts & URL previews [A4]
GET    /api/v1/texts                 ?page= → [{id,content,is_url,url_meta,is_permanent,expires_at,created_at,updated_at}]
POST   /api/v1/texts                 {content, is_permanent?}
PATCH  /api/v1/texts/{id}            {content?, is_permanent?}
DELETE /api/v1/texts/{id}
GET    /api/v1/url-meta?url=         SSRF-hardened OpenGraph fetch (cached in texts.url_meta)

# In-browser text editor & presence [A4]
GET    /api/v1/files/{id}/text       → {content, version, encoding:'utf-8', editable}  (≤ 2 MB text files)
PUT    /api/v1/files/{id}/text       {content, base_version} → FileSummary | 409 VERSION_CONFLICT {current_version}
POST   /api/v1/files/{id}/presence   → {users:[UserRef]} (heartbeat every 10 s; entries expire after 30 s); emits presence.updated

# Notifications & push [A5]
GET    /api/v1/notifications         ?unread=1&page= → [Notification], meta{unread_count}
POST   /api/v1/notifications/{id}/read
POST   /api/v1/notifications/read-all
DELETE /api/v1/notifications/{id}
GET    /api/v1/notifications/preferences  → [{category,label,in_app,push,email}]
PUT    /api/v1/notifications/preferences  {preferences:[{category,in_app,push,email}]}
GET    /api/v1/push/vapid-key        (auth optional) → {public_key|null}
POST   /api/v1/push/subscribe        {endpoint, keys:{p256dh, auth}}
DELETE /api/v1/push/subscribe        {endpoint}
POST   /api/v1/push/test

# Events / real-time [A5] — see §10
GET    /api/v1/events                ?after=<event_id>&limit= → [Event], meta{last_id, reset, has_more}
GET    /api/v1/events/stream         SSE (?after= or Last-Event-ID)
GET    /api/v1/events/poll           ?after=&wait=0..25 long-poll JSON (same shape as /events)

# Search [A6]
GET    /api/v1/search                ?q=&kind=&ext=&owner=&owner_id=&date_from=&date_to=&size_min=&size_max=&folder_id=
                                      &tag=&shared=1&favorite=1&trash=1&in=name,content,ocr,tags&page=
                                      → [FileSummary + "match":{field, snippet}] (default scope: own + shared-with-me, not trashed)
POST   /api/v1/files/{id}/ocr        queue OCR now → {queued:true}

# Admin [A6] (auth admin)
GET    /api/v1/admin/stats           counters (see §13.2)
GET    /api/v1/admin/stats/charts    ?days=30 → series
GET    /api/v1/admin/storage         per-user usage, totals, dedup savings, versions/trash bytes, disk info
GET    /api/v1/admin/activity        audit log ?category=&action=&user_id=&q=&page=
GET    /api/v1/admin/system          php/ext/limits, db version, migrations, jobs, encryption status, legacy import status, pseudo-cron status
GET    /api/v1/admin/settings        → Settings::all()
PUT    /api/v1/admin/settings        {key: value, …} (whitelisted keys, validated)
POST   /api/v1/admin/maintenance/run {task?} → results
GET    /api/v1/admin/maintenance/logs
POST   /api/v1/admin/migrations/run
POST   /api/v1/admin/legacy-import   {step?, options?} → progress (resumable)
POST   /api/v1/admin/encryption/migrate → progress (legacy_cbc → gcm1, plain → gcm1 if enabled)
POST   /api/v1/admin/jobs/retry      {id?}
POST   /api/v1/admin/vapid/generate  → {public_key, private_key} (display once; admin pastes into .env)
POST   /api/v1/admin/slack/test

# Boot [FE-CORE]
GET    /api/v1/bootstrap             → boot data (§12.1)
```

---

## 10. Real-time events

### 10.1 Wire format (exists: `EventBus::format`)
```json
{"event_id":1234,"type":"file.created","timestamp":"2026-10-03T14:00:00Z",
 "user_id":10,"actor":{"id":10,"name":"Kritarth"},
 "file_id":123,"folder_id":5,"share_id":null,"origin":"<X-Client-Id>","data":{…}}
```

### 10.2 Catalogue (publisher → recipients → data)
| type | publisher | recipients | data |
|---|---|---|---|
| file.created | A2 FileWriter (upload, import silent) | fileAudience | `{file}` |
| file.updated | A2/A3/A4 (metadata, tags, permanent, thumbnail ready, download_count, new version) | fileAudience | `{file, changes:[…]}` |
| file.renamed | A3 | fileAudience | `{file, old_name}` |
| file.moved | A3 | union(before, after audience) | `{file, from_folder_id, to_folder_id}` |
| file.deleted | A3 (to trash) | audience before trashing | `{file_id, folder_id, file:FileSummary+trash}` |
| file.restored | A3 | fileAudience | `{file}` |
| file.purged | A3 | owner | `{file_id}` |
| folder.created / folder.updated / folder.deleted / folder.restored / folder.purged | A3 | folderAudience (union on move) | `{folder}` / `{folder_id}` |
| upload.started / upload.progress / upload.completed / upload.failed | A2 | uploader (owner of session) + folder owner if different | `{upload_id,name,size,folder_id,received_bytes,percent,file_id?,reason?}` |
| share.created / share.updated / share.revoked / share.expired | A4 (A6 for expired) | share owner + file owner + recipient (user shares) | `{share:ShareSummary (no url for recipients), file_id?, folder_id?}` |
| comment.created / comment.deleted | A4 | fileAudience | `{comment, file_id}` / `{comment_id, file_id}` |
| version.created / version.restored | A2 FileWriter | fileAudience | `{file, version}` |
| notification.created / notification.read | A5 | the user | `{notification}` / `{ids:[…]|"all", unread_count}` |
| user.created / user.updated / user.deleted | A1 | the user (+ admin channel) | `{user:UserRef + status/role}` |
| quota.updated | A2 QuotaService | the user | `{quota}` |
| trash.emptied | A3 | owner | `{purged_files, purged_folders, freed_bytes}` |
| text.created / text.updated / text.deleted | A4 | owner | `{text}` / `{id}` |
| presence.updated | A4 | fileAudience | `{file_id, users:[UserRef]}` |
| session.revoked | A1 | the user | `{session_id|null (all), reason}` — clients for that session show the login screen |
| stats.updated | A6/any | admin channel only | `{metric, delta}` |
| settings.updated | A6 | admin channel | `{keys:[…]}` |

Admin channel (`'admin'=>true`) must receive: user.created/updated/deleted, file.created,
file.deleted, file.purged, share.created, share.revoked, upload.failed, stats.updated
(`downloads`, `logins`), so the admin dashboard updates live. **Admin-channel payloads must not
contain file contents or other users' share URLs.**

### 10.3 Transport protocol [A5 server, FE-CORE client]
The server advertises what it can do in boot data `config.realtime`:
`{"mode":"auto|sse|longpoll|poll","can_hold":bool,"hold_seconds":20,"poll_seconds":4,"last_event_id":N}`
(`can_hold = Capabilities::canHold()`; `REALTIME_MODE` env can force a mode). Client choice in
`auto`: `can_hold` ⇒ SSE, falling back to long-poll if SSE never delivers its opening padding /
heartbeat within 8 s (proxy buffering), then to poll; `!can_hold` ⇒ **poll**.

- **SSE** `GET /api/v1/events/stream?after=N` (or `Last-Event-ID`): only if `can_hold`, else 503
  `FEATURE_UNAVAILABLE`. Headers `Content-Type: text/event-stream`, `Cache-Control: no-cache, no-transform`,
  `X-Accel-Buffering: no`, `X-FT-Api: 1`; disable `zlib.output_compression`, end all output buffers;
  send a 2 KB comment padding first, then `retry: 3000`. Loop for `REALTIME_HOLD_SECONDS`:
  `session_write_close()`, `Db::disconnect()`, every 1 s (`Capabilities::sleep(1)`) compare
  `RealtimeSignal::read(uid)` (and `read(0)` for admins) to the last seen id; on change query
  `EventBus::since()` and emit `id: <event_id>\nevent: ft\ndata: <json>\n\n`. Heartbeat
  `: hb\n\n` every 10 s. On `reset` emit `event: reset\ndata: {"last_id":N}\n\n`. Finish with
  `event: bye\ndata: {}\n\n`. Check `connection_aborted()` each tick.
- **Long-poll** `GET /api/v1/events/poll?after=N&wait=20`: same wait loop (only when `can_hold`;
  otherwise `wait` is treated as 0), returns as soon as there are events.
- **Short poll (fast path)** `GET /api/v1/events/poll?after=N&wait=0`. Must be extremely cheap:
  the controller is registered with `'auth' => 'none', 'rate' => null` and does its own check:
  `session_start(['read_and_close' => true])`, read the user id + session row id from `$_SESSION`
  (no DB). If there is no session ⇒ fall back to full `Auth::resolve()` (bearer tokens).
  If `RealtimeSignal::read(uid)` (and admin channel when the session says role admin) is
  `<= after` ⇒ respond **204 No Content** (with `X-FT-Api: 1`) **without opening a DB connection**.
  Otherwise run full `Auth::resolve()` (validates the session row / account status) and return
  `EventBus::since()` as JSON (shape of `/events`). A file-based rate guard (≥ 1 s between polls per
  session) replaces the DB rate limiter on this path.
- **Recovery** `GET /api/v1/events?after=N` — called after every (re)connect before resuming;
  `meta.reset=true` ⇒ lightweight refresh of the visible view + counters (never a page reload).
- **Client poll cadence** (poll mode): leader tab only; `poll_seconds` (default 4 s, at least 2 s)
  while the page is visible and the user was active in the last 2 min; max(15 s, 2 × `poll_seconds`)
  when visible but idle; max(60 s, 4 × `poll_seconds`) when hidden — so a larger
  `REALTIME_POLL_SECONDS` never makes active polling slower than idle polling. Polls are at least
  1.15 s apart (the server's short-poll guard allows one per second); immediate poll on `focus`,
  `visibilitychange→visible`, `online`, and ~800 ms after any local mutation. Back off on errors
  (1, 2, 4, 8, 16, 30 s).
- **429 is never a disconnection.** A short poll answered 429 waits for `Retry-After` (1–30 s).
  When a held connection is refused with 429 (long-poll; an SSE stream that never opens is retried
  as a long-poll, because `EventSource` cannot see the status), the client short-polls quietly for
  1, 2, 4, 8, then 10 min (or `Retry-After` if longer) before trying the held transport again; the
  live indicator never shows "Reconnecting" for it. A recovery request answered 429 is retried after
  `Retry-After`; `403 PASSWORD_CHANGE_REQUIRED` pauses sync for 30 s at a time.
- **Tick** `POST /api/v1/tick` [A6]: the leader tab calls it every ~60 s while visible. It runs
  ≤ 2.5 s of `Queue::work()` and, when due, a pseudo-cron maintenance slice. This replaces cron
  and post-response work on hosts that cannot finish requests early. Response `{jobs, maintenance}`.
- Route options: SSE/long-poll/recovery use `'rate' => 'realtime'`; all are GET (no CSRF);
  tick uses CSRF and `'rate' => 'tick'` (max 4/min per user).

---

## 11. Notifications (A5)

```php
Notifier::notify(int $userId, string $category, string $type, string $title, string $body = '',
                 array $data = [], ?string $dedupeKey = null, ?int $actorId = null): ?int
```
Categories (preference rows; defaults in brackets in_app/push/email):
`share` "File shared with you" [1/1/0] · `download` "File downloaded" [1/0/0] · `comment` "New comment" [1/1/0] ·
`version` "New version" [1/0/0] · `share_expired` "Share expired" [1/0/0] · `login` "Account login" [1/0/0] ·
`security` "Security event" [1/1/1] · `quota` "Storage quota warning" [1/1/1] · `upload` "Upload completed / failed" [1/0/0].
`notify` honours preferences: in-app ⇒ insert + `notification.created` event; push ⇒ queue
`WebPush::deliverJob` per subscription; email ⇒ queue `Mailer::sendJob` (when MAIL_DRIVER≠none
and the user has an e-mail). `dedupeKey` suppresses duplicates (unique per user). Never notify the
actor about their own action (except security/login/quota/upload).
Who notifies what: A4 share.received/comment; A3 download (on non-owner download) & version
(to recipients with access); A6 share_expired (maintenance, once); A1 login (new device/IP) &
security (password changed, 2FA changed, sessions revoked, suspicious attempts); A2 quota
(crossing warning threshold, once per crossing) & upload (completed/failed).

Web Push must be **RFC 8291 (aes128gcm) + RFC 8292 VAPID (ES256, raw R||S signature)** using
openssl (`openssl_pkey_new` EC prime256v1, `openssl_pkey_derive`, `hash_hkdf`). Remove
subscriptions on 404/410. Payload: `{"title","body","url","tag","notification_id"}` (no secrets).
Slack: `Slack::notify(string $event, array $fields)` queues a job; only `https://hooks.slack.com/`
URLs; respects setting `slack_events`; webhook = setting `slack_webhook_override` or env
`SLACK_WEBHOOK`. Events: upload, delete, share, download, comment, text, favorite, version_restore,
batch_delete (legacy set). Message times use 24-hour format.

---

## 12. Front-end architecture (FE-CORE contract for wave 2)

No build step: native **ES modules** under `assets/js/`, one shared stylesheet
`assets/css/app.css`. The design language of the legacy UI is preserved: dark theme by default
with light theme toggle, an accent gradient, glassy cards, fonts **Syne** (headings) + **DM Sans**
(body) from Google Fonts, rounded corners, chips, toasts. The accent is a palette chosen per user in
Settings → Appearance (`html[data-accent]`, `assets/js/core/theme.js`): **Champagne** (default,
gold on graphite), Platinum, Rose gold, Aurora, Sapphire and Violet (classic — the original
`#7c6aff → #a78bfa`). Components use only the palette tokens (`--accent`, `--accent2`, `--accent-g`,
`--accent-text` for accent-coloured text, `--on-accent` for text on accent fills, `--accent-rgb`
tints), which meet WCAG AA in both themes. Mobile-first: sidebar on ≥ 900 px, bottom navigation bar + slide-in drawer on small
screens, touch targets ≥ 44 px, dialogs become full-height sheets below 600 px.

### 12.1 Boot data
`views/app.php` embeds `<script id="ft-boot" type="application/json">` built by
`ClientConfig::build($user)` and also served by `GET /api/v1/bootstrap`:
```json
{"csrf_token":"…","user":User(me),"unread_notifications":3,
 "config":{"app_name":"FastTransfer","version":"2.0.0","base":"/","api_base":"/api/v1","share_base":"https://host/s/",
   "method_override":true,
   "upload":{"chunk_size":8388608,"max_upload_bytes":209715200,"max_parallel":2,"blocked_extensions":[]},
   "realtime":{"mode":"auto","can_hold":false,"hold_seconds":20,"poll_seconds":4,"last_event_id":123},
   "features":{"ocr":true,"push":true,"email":false,"encryption":true},
   "vapid_public_key":"…|null","auto_expire_hours":72,"trash_retention_days":30,
   "settings":{"quota_warning_percent":90}}}
```

### 12.2 Navigation (hash router)
`#/` dashboard · `#/files` · `#/files/<folderId>` · `#/shared` (Shared With Me; tab "Shared by me")
· `#/favorites` · `#/recent` · `#/trash` · `#/clipboard` · `#/uploads` · `#/search?q=` ·
`#/notifications` · `#/settings` · `#/security` · `#/admin` · `#/admin/users` · `#/admin/storage`
· `#/admin/shares` · `#/admin/activity` · `#/admin/system`. Sidebar groups exactly as the brief:
Dashboard / My Files, Shared With Me, Favourites, Recent, Trash / Uploads / Notifications /
Settings, Security Centre / Admin (Users, Storage, Shares, Activity, System). Clipboard (legacy
"Save Text or URL") and Notepad (`#/notepad`, `#/notepad/<id>`: the legacy collaborative notepad, now team and private notepads with live merging, history and presence — §5.12a of docs/API.md) sit under My Files.

### 12.3 Core modules (exact exports)
```js
// core/api.js
export class ApiError extends Error { code; status; details; }
export const api = {
  get(path, query) , post(path, body), put(path, body), patch(path, body), del(path, body),
     // all resolve to {data, meta}; path is relative to config.api_base, e.g. api.get('/files', {folder_id: 3})
  raw(method, path, {body, headers, signal, onUploadProgress, query}) ,  // XHR-based when onUploadProgress
  url(path, query),           // absolute URL (img src, <a download>, EventSource)
  setCsrf(token), clientId    // X-Client-Id persisted in localStorage 'ft:client-id'
};
// Behaviour: sends X-CSRF-Token + X-Client-Id + Accept: application/json; PUT/PATCH/DELETE are sent as
// POST + X-HTTP-Method-Override when config.method_override; 419 → GET /auth/csrf then retry once;
// 401 → bus.emit('auth:expired') and reject; 204 → {data:null, meta:{}};
// 403 with code PASSWORD_CHANGE_REQUIRED → bus.emit('auth:password-change-required') and reject
// (the shell opens its single "choose a new password" dialog);
// a response WITHOUT header `X-FT-Api: 1` (e.g. text/html from the host's JS cookie check) means
// PHP never ran → load a hidden iframe to config.base, wait ≤10 s for it, retry once; if it still
// fails, bus.emit('host:challenge') (the shell offers a one-tap reload) and reject with
// ApiError('HOST_CHALLENGE'). Never cache or parse such HTML as data.

// core/bus.js
export const bus = { on(type, fn) /* returns off(); type may be '*' or 'file.*' */, once(type, fn), emit(type, payload) };

// core/store.js
export const store = { get(key), set(key, value), update(key, fn), on(key, fn) /* returns off() */ };
//   keys: 'user', 'quota', 'unread', 'live' ('connecting'|'connected'|'reconnecting'|'reconnected'|'disconnected'),
//         'uploads' (array of upload items, owned by features/uploader.js), 'config', 'route'

// core/dom.js
export function h(tag, attrs = {}, ...children)   // attrs: class, style{}, dataset{}, on{event:fn}, any prop/attr; children: Node|string|array|null
export function icon(name, size = 18)             // inline SVG from core/icons.js
export function clear(el); export function qs(sel, root); export function qsa(sel, root);

// core/format.js  (en-GB, 24-hour)
export function bytes(n); export function dateTime(iso); export function date(iso); export function time(iso);
export function relative(iso); export function dayLabel(iso) /* Today|Yesterday|03 Oct 2026 */;
export function countdown(iso); export function percent(part, whole); export function kindOf(ext, mime);
export function kindIcon(kind); export function plural(n, one, many);

// core/ui.js
export function toast(message, {type = 'ok'|'err'|'info'|'warn', timeout = 3500, action, id} = {})
export function modal({title, content, actions = [], size = 'md', onClose, dismissible = true})  // → {el, body, close(), setBusy(bool)}
export function confirm({title, message, confirmText = 'Confirm', danger = false})              // → Promise<boolean>
export function prompt({title, label, value = '', placeholder = '', confirmText = 'Save', validate})  // → Promise<string|null>
export function menu(anchorEl, items)   // items: [{label, icon, onClick, danger, disabled} | '-']; bottom sheet on mobile
export function emptyState({icon, title, text, action}); export function errorState(err, onRetry); export function spinner(); export function skeleton(rows);

// core/router.js
export const router = { register(name, {path, load, title, nav}), start(), go(path), back(), current() };
//   path patterns like '/files/:folderId?'; load: () => import('../views/files.js');
//   view module default export: { mount(container, params, query), unmount?(), title? }

// core/realtime.js
export const realtime = { start({userId, lastEventId, isAdmin}), stop(), status(), lastEventId() };
//   emits bus events: each server event under its type ('file.created' …) and 'event' (all);
//   'sync.reset' when history is gone; updates store 'live'. Leader election across tabs with
//   navigator.locks ('ft-realtime-<uid>') or a localStorage heartbeat fallback; only the leader
//   holds the network connection and relays events through BroadcastChannel('ft-events-<uid>')
//   (fallback: localStorage 'storage' events). Dedupe by event_id. Backoff 1,2,4,8,16,30 s (max 30)
//   with jitter. Transport auto-select: SSE → long-poll → poll (remember choice per browser).
//   lastEventId persisted per user in localStorage 'ft:last-event:<uid>'.

// core/filelist.js
export function createFileList(container, {
  source,            // async ({page, perPage, sort, order}) => ({items, meta})
  variant = 'files', // 'files'|'trash'|'shared'|'search'|'recent'|'favorites'
  mode = 'grid',     // 'grid'|'list' (persisted in user preferences)
  selectable = true, emptyState, onOpen(item), itemActions(item) => menuItems, batchActions(items) => buttons,
  accept(item) => bool   // whether a realtime upsert belongs in this list
}) // → { reload(), upsert(item), remove(id, type='file'), selected(), clearSelection(), setMode(m), destroy() }
//   Infinite scroll via IntersectionObserver ("Load more" button fallback); never more than
//   ~400 cards in the DOM (older pages are recycled); keyboard + shift-click range selection;
//   drag files onto folder cards to move; long-press opens the context menu on touch.
```

### 12.4 Shared feature modules (wave 2 exports used across views)
```js
features/uploader.js     export const uploader = { add(files, {folderId, fileId, tags, isPermanent, onConflict, shareAfter}), pause(id), resume(id), retry(id), cancel(id), items() }
features/preview.js      export function openPreview(file, {list = [file], index = 0, shareToken} = {})
features/share-dialog.js export function openShareDialog({files = [], folder = null})
features/qr.js           export function renderQr(container, text, {size = 220}); export function qrPngDataUrl(text, size)
features/details.js      export function openDetails(fileId, tab = 'info')   // tabs: info, activity, comments, versions, sharing
features/move-dialog.js  export function pickFolder({title, excludeIds = []}) // → Promise<folderId|null|undefined(cancelled)>
features/editor.js       export function openEditor(file)
features/dropshare.js    export function mountDropShare(container)            // drag file → upload → share dialog → copy link
```

### 12.5 CSP for HTML pages (FE-CORE `Csp::header($nonce)`)
`default-src 'self'; script-src 'self' 'nonce-<n>' <CDN_SCRIPTS>; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self';
worker-src 'self' blob: <CDN_WORKERS>; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'`.

`CDN_SCRIPTS` / `CDN_WORKERS` (constants in `Csp`) are the exact, version-pinned cdnjs folders the
front end loads, never the whole CDN:
`https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/`, `…/highlight.js/11.9.0/`,
`…/qrcode-generator/1.4.4/`, `…/Chart.js/4.4.1/` (workers: the pdf.js folder only; the pdf.js worker
runs from a `blob:` wrapper that `importScripts()` it). Every third-party script is loaded through
`features/lib-loader.js` (`loadLib('pdfjs'|'hljs'|'qrcode'|'chart')`) with a `sha384` Subresource
Integrity hash and `crossorigin="anonymous"`; `tests/js/csp.test.mjs` keeps the two lists in step.
Upgrading a library means changing its URL, hash and the CSP folder together.
No inline event handlers anywhere. Untrusted SVG is only ever shown in an `<img>` from a `data:`
URL (never a `blob:` URL, which would open as a same-origin document in a new tab).

### 12.6 PWA (W2-ADMIN)
Both PWA files are **served by PHP routes** (route file `app/routes/pwa.php`, controller
`Controllers/Web/PwaController.php`) so they carry the right base path, version and headers
(Apache `Header`/`AddType` are unavailable on byethost):
- `GET /manifest.webmanifest` → `application/manifest+json`: name "FastTransfer", short_name,
  icons 192/512 + maskable (PNG files in `assets/icons/`), `display: standalone`, theme/background
  colours from the design tokens, `start_url` `<base>#/`, `scope` `<base>`. The shell links it with
  `<link rel="manifest" href="manifest.webmanifest" crossorigin="use-credentials">` (the host's
  cookie check would block an anonymous manifest fetch).
- `GET /service-worker.js` → `application/javascript`, `Cache-Control: no-cache`,
  `Service-Worker-Allowed: <base>`; the script embeds `FT_VERSION` and the precache list
  (app shell assets: CSS, every JS module under assets/js, icons, and the offline page from the
  `GET /offline` route, rendered from `views/offline.php`). Strategy: **cache-first for versioned static assets** (saves the host's
  daily hit budget; a new app version installs a new cache and deletes old ones), network-first for
  navigations with the offline page as fallback, and **never cache** `/api/`, `/s/`, file content,
  thumbnails or anything with `no-store`/`private`. Responses that are HTML where JS/CSS was
  expected (host challenge) must never be cached. Push handler: show the payload as a
  notification **without fetching from the server**; click focuses an open client or opens the
  payload `url`. Background Sync tag `ft-retry-uploads` posts a message to clients to resume uploads.

---

## 13. Maintenance, admin, search (A6)

### 13.1 Maintenance tasks (idempotent, time-boxed, each logged to maintenance_logs)
expire_shares (status + notify owners once via `expired_notified_at` + share.expired event) ·
expire_sessions · cleanup_uploads (expired sessions, orphan temp dirs) · auto_expire_files
(→ Trash, reason expired) · expire_texts · purge_trash (retention; per-user preference override
`preferences.trash_retention_days` if set and shorter) · prune_versions (count/days) ·
cleanup_bundles (bundle ZIP cache older than `bundle_ttl_hours`) · prune_events (+ update
`events_pruned_before_id`) · prune_audit · prune_login_history · prune_notifications ·
prune_rate_limits · prune_presence · orphan_records (favorites/file_tags/share_items/shares
pointing at purged rows; edit_presence) · unreferenced_blobs (ref_count=0 rows older than 1 h →
delete file + row; reconcile ref_counts from file_versions; **never** delete a physical file that
any row references) · reconcile_quotas · process_jobs · snapshot_stats (`storage_bytes`) ·
encryption_migration (optional batch). Runner API: `MaintenanceRunner::run(string $trigger,
?array $tasks = null, float $budgetSeconds = 20.0): array` and lock file
`Paths::runtime('locks')/maintenance.lock` (flock, non-blocking).
`PseudoCron::maybeRun()` runs at most every `PSEUDO_CRON_INTERVAL` seconds with an 8 s budget.

### 13.2 Admin dashboard counters (`GET /api/v1/admin/stats`)
`users_total, users_active, users_disabled, users_suspended, files_total, storage_used_bytes
(logical), storage_physical_bytes (blobs), storage_capacity_bytes (setting/env or disk_total_space),
storage_available_bytes, uploads_today, downloads_today, shares_created_today, shares_total,
shares_active, shares_expired, trash_bytes, trash_files, version_bytes, failed_uploads_today,
dedup_saved_bytes, jobs_pending, jobs_failed`. Charts: storage over time, uploads, downloads,
new users (daily_stats), file kinds (by count and bytes), most downloaded files (top 10).

---

## 14. Legacy compatibility (A6)
- `LegacyRoutes::matches($_GET)`: true when the root URL carries any of `share`, `download`,
  `serve`, `logout`, `download_zip`, `delete_day`, `bulk_share`, `activity_stream`,
  `activity_poll`, `fetch_meta`, … (all legacy query triggers). index.php then routes to
  `/legacy` (A6 `LegacyController`): `?share=T` → 302 `s/T` (POST with `share_password` → 307
  `s/T/unlock`); `?download=NAME` / `?serve=NAME` → the migrated file visible to the user
  (by `files.legacy_name`) → 302 to the new endpoint; `?logout` → logout; anything else → 302 home.
- Importer maps legacy JSON → tables, copies files into blob storage (never deletes the legacy
  `uploads/` directory; admin can remove it later), keeps share tokens, imports `legacy_cbc`
  blobs byte-for-byte (then the encryption migration converts them), records every item in
  `legacy_import` so it is resumable and idempotent, and backs up the JSON files first.

---

## 15. Testing requirements (every module)
- Add `tests/<Area>Test.php` files using `tests/lib.php` helpers. Run your suite in isolation:
  `php tests/run.php --suite=<yourmodule> <Area>` (separate DB + port + storage per suite).
- Test the happy path **and** authorisation failures (other user's ids → 404, guest → 403,
  missing CSRF → 419), validation errors, and the events/audit rows your code must write.
- Use the HTTP client (`TestClient`) for endpoint tests: it starts `php -S` with the test env.
- `php -l` every PHP file you create. JS: `node --check` every file (ES modules:
  `node --input-type=module --check < file.js` or `node --check file.mjs` copy).
