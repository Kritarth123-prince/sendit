# Deploying FastTransfer

This guide covers:

1. [Before you start](#1-before-you-start) (including the byethost terms-of-service warning)
2. [byethost / iFastNet free hosting, step by step](#2-byethost-free-hosting-step-by-step)
3. [Every `.env` setting](#3-the-env-file-every-setting)
4. [Background maintenance without cron](#background-maintenance-without-cron)
5. [Known byethost limits and how FastTransfer adapts](#5-known-byethost-limits-and-how-fasttransfer-adapts)
6. [Normal hosts and VPSs (Apache, Nginx, cron, SSE)](#6-normal-hosts-and-vpss)
7. [Troubleshooting](#7-troubleshooting)

Upgrading from the old single-file version? Read this guide **and** [UPGRADE.md](UPGRADE.md).

---

## 1. Before you start

> **Terms of service warning (byethost / iFastNet free plan).** The host's terms prohibit
> "file hosting / file sharing" sites and "archives … used for downloading / sharing". iFastNet
> staff have said that any file-hosting or file-sharing component is forbidden, and the account
> can be suspended without notice. FastTransfer is exactly that kind of site. Running it there is
> your decision and your risk. For real use, pick a host whose terms allow a private cloud drive
> (section 6). FastTransfer itself is portable: nothing in it is tied to byethost.

You will need:

- An FTP client (for example FileZilla on Windows) and the FTP details from your hosting panel.
- A text editor for `.env`. Windows Notepad is fine: FastTransfer ignores the UTF-8 byte-order
  mark Notepad adds and accepts Windows line endings.
- Optionally PHP on your PC, to generate keys (you can also let the installer generate them).
- **A backup.** byethost provides no backups. If the old version is live, download the whole web
  folder (including `uploads/` and the `*.json` files next to `index.php`) before you change anything.

---

## 2. byethost free hosting, step by step

### 2.1 Check the PHP version

In VistaPanel, look at the PHP version shown for your account. FastTransfer needs **PHP 8.1 or
newer**; byethost free accounts currently run PHP 8.3 or 8.4, and the version usually cannot be
changed on the free plan. The installer's *Server check* step shows the exact version running.

Do **not** use VistaPanel's "Alter PHP config" options to add `php_value` lines: FastTransfer does
not need them, and extra directives in `.htaccess` can break the site (HTTP 500/502).

### 2.2 Create the MySQL database

1. VistaPanel → **MySQL Databases** → create a database (for example `ft`). The panel adds your
   account prefix, so the full name looks like `b7_12345678_ft`.
2. Note the four values the panel shows:
   - **database name** (with the prefix) → `DATABASE_NAME`
   - **MySQL user name** (normally your hosting account user name, e.g. `b7_12345678`) → `DATABASE_USER`
   - **MySQL password** (normally your hosting account password) → `DATABASE_PASSWORD`
   - **MySQL host name**, which looks like `sql123.byethost7.com` → `DATABASE_HOST`.
     It is **not** `localhost`; with `localhost` the connection fails.
3. The database only accepts connections from byethost's own servers. You cannot connect to it
   from your PC, so a local copy of FastTransfer must use a local MySQL/MariaDB.

FastTransfer creates the tables itself (installer step *Create tables*). Do not import anything
in phpMyAdmin.

### 2.3 Create `.env`

Copy `.env.example` to a new file called `.env` on your PC and fill it in. Every setting is
explained in [section 3](#3-the-env-file-every-setting). A typical byethost `.env`
(placeholders only, use your own values):

```ini
APP_ENV=production
APP_DEBUG=false
APP_URL=https://yourname.byethost7.com
APP_KEY=base64:REPLACE_WITH_A_NEW_RANDOM_KEY
PRETTY_URLS=true
# Set to true once HTTPS works (2.7)
FORCE_HTTPS=false
METHOD_OVERRIDE=true
TRUST_PROXY_HEADERS=false
TRUSTED_PROXIES=

DATABASE_HOST=sql123.byethost7.com
DATABASE_PORT=3306
DATABASE_NAME=b7_12345678_ft
DATABASE_USER=b7_12345678
DATABASE_PASSWORD=your-hosting-password

STORAGE_PATH=storage
STORAGE_CAPACITY_GB=5
# Empty = <app folder>/uploads (where the old version kept its data)
LEGACY_UPLOADS_PATH=

ENCRYPTION_KEY=base64:REPLACE_WITH_ANOTHER_NEW_RANDOM_KEY
ENCRYPTION_KEY_ID=k1
ENCRYPTION_ENABLED=true
ENCRYPTION_OLD_KEYS=
# Empty = <app folder>/uploads/.enc_key
LEGACY_ENCRYPTION_KEY_FILE=

MAIL_DRIVER=none
INSTALL_TOKEN=REPLACE_WITH_A_LONG_RANDOM_STRING
MAINTENANCE_TOKEN=
PSEUDO_CRON=true
PSEUDO_CRON_INTERVAL=300

# Important on byethost, see 5.1 and 5.2
REALTIME_MODE=poll
REALTIME_HOLD_SECONDS=20
REALTIME_POLL_SECONDS=8
```

Put comments on their own lines. A `#` after a value only counts as a comment when there is a
space before it, and never after an empty value (`NAME=   # note` sets `NAME` to `# note`).

Where `.env` goes: FastTransfer first looks one folder **above** the app folder, then in the app
folder itself. On byethost anything outside `htdocs` is deleted automatically, so put `.env` in
the same folder as `index.php`. The shipped `.htaccess` refuses every request for dot-files, so
it cannot be downloaded.

### 2.4 Generate the keys

You need new random values for `APP_KEY`, `ENCRYPTION_KEY` and `INSTALL_TOKEN` (and
`MAINTENANCE_TOKEN` if you will use it). Never reuse values from the old version. Three ways:

- **Let the installer do it.** If `APP_KEY`, `ENCRYPTION_KEY`, `INSTALL_TOKEN` or
  `MAINTENANCE_TOKEN` is missing, `/install` shows freshly generated lines to paste into `.env`.
  (Without `INSTALL_TOKEN` the installer cannot be unlocked, so add that one first: it is shown on
  the very first screen.)
- **PHP on your PC** (PowerShell):

  ```powershell
  php -r "echo 'base64:'.base64_encode(random_bytes(32)), PHP_EOL;"   # APP_KEY / ENCRYPTION_KEY
  php -r "echo bin2hex(random_bytes(24)), PHP_EOL;"                    # INSTALL_TOKEN / MAINTENANCE_TOKEN
  ```

- **PowerShell only** (no PHP needed):

  ```powershell
  $b = New-Object byte[] 32; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b); 'base64:' + [Convert]::ToBase64String($b)
  ```

Accepted key formats for `APP_KEY` and `ENCRYPTION_KEY`: `base64:` followed by 32 bytes in
base64, 64 hexadecimal characters, or any string of at least 32 characters.

**Back up `ENCRYPTION_KEY` (and `APP_KEY`) somewhere safe and offline**, for example in a password
manager. Without `ENCRYPTION_KEY` your encrypted files cannot be recovered. Changing `APP_KEY`
later makes stored two-factor secrets and the Slack webhook override unreadable, so set it once.

**Web Push keys (optional).** Push notifications need a new VAPID key pair in
`VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY`. The easiest way is after installing: sign in as an
administrator, open **Admin → System → Web Push keys** and click **Generate Web Push keys**. It
shows the two lines `VAPID_PUBLIC_KEY=…` and `VAPID_PRIVATE_KEY=…` **once**, with copy buttons:
paste both into `.env` (replacing any old `VAPID_` lines), set `VAPID_SUBJECT` to a `mailto:`
address or your site's URL, upload `.env` again and reload. The private key is not stored on the
server. (Behind the button is `POST /api/v1/admin/vapid/generate`, see
[API.md](API.md#admin-system); it needs OpenSSL with elliptic-curve support.) Alternatively, with
PHP on your PC, run from the project folder:

```powershell
php -r "require 'app/bootstrap.php'; echo json_encode(FT\Notifications\WebPush::generateVapidKeys(), JSON_PRETTY_PRINT), PHP_EOL;"
```

and copy `public_key` and `private_key` into `.env`. Any standard Web Push VAPID key generator
(P-256, base64url) also works. Replacing existing keys means everyone has to turn push on again.

### 2.5 Upload the files

Upload into `htdocs` (or the folder of your add-on domain), with binary transfer mode:

| Upload | Do **not** upload |
| --- | --- |
| `index.php` | `tests/` |
| `maintenance.php` | `docs/` |
| `.htaccess` (FTP clients sometimes hide dot-files: make sure it is there) | the **contents** of your local `storage/` folder (see below) |
| `.env` (the production one you just made) | your **local** `.env` (it has your local database details) |
| `app/` | `.env.example`, `.gitignore`, `.dist/`, `README.md` (not needed; most are refused by `.htaccess` anyway) |
| `assets/` | the backup of the old `index.php` (it contains compromised credentials) |
| `database/` | |
| `views/` | |

About `storage/`: FastTransfer creates `storage/` itself on first use and protects it
(`.htaccess` with `Require all denied`, stub `index.php`/`index.html`). Never upload your local
`storage/`: its `runtime/installed.json` describes your local installation, and its `users/`,
`logs/` and `backups/` folders contain local data.

**Upgrading over the old version on the same account:** leave the old `uploads/` folder and the
old `*.json` files where they are. The new `index.php` replaces the old one. Make sure you have
the old `index.php` saved on your PC (for rollback, see [UPGRADE.md](UPGRADE.md#rollback-plan)),
and do **not** keep a renamed copy such as `index-old.php` on the server: `.htaccess` lets real
`.php` files run, so it would still be reachable and it contains compromised credentials.

### 2.6 Run the installer

Open `https://yourname.byethost7.com/install` (with `PRETTY_URLS=false`:
`/index.php?r=/install`). Until installation is finished, every other page redirects there.
The installer walks through these steps:

1. **Unlock.** Enter `INSTALL_TOKEN`. After 10 wrong tokens from one IP address it refuses for 15 minutes.
2. **Server check.** Required: PHP 8.1+, the extensions `pdo_mysql`, `openssl`, `mbstring`,
   `json`, `fileinfo` and `zlib`, a `.env` file, `APP_KEY`, `ENCRYPTION_KEY`, `DATABASE_NAME` and a
   writable storage folder. Optional: `curl`, `gd`, `zip`, `sodium` and HTTPS. Missing secrets are
   shown as ready-to-paste lines. Fix the problems, upload `.env` again and reload.
3. **Database.** Tests the connection. If it fails you get advice (see
   [Troubleshooting](#database-connection-errors)).
4. **Create tables.** Applies the migrations in `database/migrations/`. If the database already
   holds data, it is backed up first into `storage/backups/` (gzip parts below 8 MB).
5. **Administrator.** Choose a user name (3–32 letters, digits, `.`, `-`, `_`) and a **new**
   password of at least 10 characters that does not contain the user name. E-mail is optional.
6. **Import & finish.**
   - **Import files from the old version** appears on a first installation when old data is found
     in `LEGACY_UPLOADS_PATH` (a `metadata.json`, `shares.json` or `texts.json`). Two options, both
     ticked by default:
     - *Share imported files with every imported user* keeps the old "everyone sees everything"
       access (each owner's files go into an **Imported files** folder shared with the others).
     - *Create accounts for the old users* creates an account for every old user name found in
       the old data.
   - The import runs in batches of about 15 seconds and the page continues by itself until it is
     done. Warnings (for example a file that could not be decrypted) are listed; you can run it
     again later from **Admin → System → Import from the old version** to retry.
   - **One-time passwords** for the created accounts are shown **once**. Copy them now and give
     each person theirs. At first sign-in they must choose a new password: the server refuses
     everything else (`403 PASSWORD_CHANGE_REQUIRED`) until they do, and the web app shows the
     change-password dialog.
   - Click **Finish and open FastTransfer**, then sign in with your administrator account.

What exactly is imported is described in [UPGRADE.md](UPGRADE.md#what-is-imported).

### 2.7 After installing: checklist

- [ ] **Remove `INSTALL_TOKEN`** from `.env` and upload `.env` again. (When a future version
      brings database updates you add a new token temporarily, see
      [UPGRADE.md](UPGRADE.md#future-upgrades).)
- [ ] **Rotate every credential from the old version** (Slack webhook, OCR.space key, VAPID keys,
      passwords), see [SECURITY.md](SECURITY.md). Put only the **new** values in `.env`.
- [ ] **Delete the old JSON files in the app folder** once the import is complete:
      `remember_tokens.json`, `push_subs.json` and `ft_config.json`. They are not imported and
      hold old secrets.
- [ ] **Encryption upgrade:** *Admin → System → Encryption upgrade* converts imported files to
      AES-256-GCM (maintenance also does this in the background). When nothing is pending, delete
      `uploads/.enc_key`. Keep an offline backup of the old `uploads/` folder until you are sure
      everything was imported, then delete `uploads/` from the server.
- [ ] **HTTPS:** open the site with `https://`. byethost's free subdomains have a certificate;
      `www.` and other sub-subdomains do not, so use the bare name. When HTTPS works, set
      `FORCE_HTTPS=true` and an `https://` `APP_URL`. This redirects plain-HTTP page requests,
      marks cookies `Secure` and sends HSTS.
- [ ] **`REALTIME_MODE=poll`** and **`REALTIME_POLL_SECONDS=8`** on byethost (see
      [5.1](#51-live-updates-on-byethost-set-realtime_modepoll) and [5.2](#52-hits-budget-and-realtime_poll_seconds)).
- [ ] **Push notifications (optional):** generate keys in *Admin → System → Web Push keys* (2.4).
- [ ] **Storage is private:** *Admin → System* shows a "Storage folder private" check. It must
      pass. Users of the platform have reported `.htaccess` files being reset; re-check after uploads.
- [ ] **Back up `ENCRYPTION_KEY` and `APP_KEY`** offline, and download `storage/backups/` from
      time to time (the host keeps no backups).
- [ ] Make sure `APP_DEBUG=false`.

---

## 3. The `.env` file: every setting

Rules: one `NAME=value` per line; `#` starts a comment; values may be quoted. An **empty value
counts as not set**, so the default applies. Real environment variables (on a VPS) take
precedence over `.env`.

### Application

| Variable | Default | What it does |
| --- | --- | --- |
| `APP_ENV` | `production` | Shown on the admin System page. The tests use `testing`. |
| `APP_DEBUG` | `false` | When `true`, server errors include the exception class, message and file:line in the response, and debug lines are logged. Only switch it on briefly for diagnosis. |
| `APP_URL` | empty (detected from the request) | Public base URL **without** a trailing slash, including a sub-folder if the app lives in one (`https://example.com/drive`). Used for links, share URLs and the base path. Password-reset e-mails only contain a clickable link when `APP_URL` is set. |
| `APP_NAME` | `FastTransfer` | Fallback product name when the admin setting *site name* is empty. (Not in `.env.example`.) |
| `APP_KEY` | none (required) | 32+ random bytes. Encrypts two-factor secrets and secret settings and keys internal HMACs. Do not change it after installing. |
| `PRETTY_URLS` | `true` | `true`: URLs like `/api/v1/files` and `/s/<token>` (needs `mod_rewrite`). `false`: `index.php?r=/api/v1/files`. |
| `FORCE_HTTPS` | `false` | `true`: plain-HTTP GET requests are redirected to HTTPS, cookies are marked `Secure`, HSTS is sent (180 days). |
| `METHOD_OVERRIDE` | `true` | Tells the web app to send PUT/PATCH/DELETE as POST with `X-HTTP-Method-Override` (some hosts block those methods). The server always accepts the override. |
| `TRUST_PROXY_HEADERS` | `false` | `true`: behind a reverse proxy **you** control, the client IP is taken from `X-Forwarded-For` (else `X-Real-IP`, else `CF-Connecting-IP`), but **only** for requests that come from an address listed in `TRUSTED_PROXIES`. Anyone can send these headers, so otherwise clients could fake their IP and dodge rate limits. Keep `false` on byethost. |
| `TRUSTED_PROXIES` | empty | Comma-separated IP addresses and/or CIDR ranges (IPv4 and IPv6) of your proxies, for example `127.0.0.1,10.0.0.0/8,2001:db8::/32`. Used only with `TRUST_PROXY_HEADERS=true`; with an empty list no forwarding header is believed. `X-Forwarded-For` is read from right to left and the first address that is not one of your proxies is the client. Behind Cloudflare without a proxy of your own, list Cloudflare's published IP ranges. |
| `LEGACY_HOST_COOKIE_SHIM` | `false` | Old byethost cookie workaround carried over from the single-file version. Leave it off: it sets the host's `__test` cookie itself, which the host's terms forbid. (Not in `.env.example`.) |

### Database

| Variable | Default | What it does |
| --- | --- | --- |
| `DATABASE_HOST` | `localhost` | MySQL/MariaDB host. byethost: the `sqlNNN.byethostNN.com` host from VistaPanel. |
| `DATABASE_PORT` | `3306` | |
| `DATABASE_NAME` | none (required) | Must already exist. |
| `DATABASE_USER` / `DATABASE_PASSWORD` | empty | |

### Storage

| Variable | Default | What it does |
| --- | --- | --- |
| `STORAGE_PATH` | `storage` | Where files, logs, backups and runtime state live. Absolute, or relative to the app folder. Prefer a folder outside the web root where the host allows it (byethost does not). Created and protected automatically. |
| `STORAGE_CAPACITY_GB` | `0` (unknown) | Total capacity shown on the admin dashboard (hosts often disable `disk_total_space()`). byethost free: `5`. (Not in `.env.example`.) |
| `STORAGE_SEGMENT_MB` | `8` (1–64) | Advanced: caps the upload chunk size. Files are always stored in 8 MiB segments whatever this says. Leave it alone. (Not in `.env.example`.) |
| `LEGACY_UPLOADS_PATH` | `<app folder>/uploads` | Where the old version kept its files and JSON data (read by the importer, never modified). Absolute, or relative to the app folder (like `STORAGE_PATH`; PHP's working directory does not matter). |

### Encryption at rest

| Variable | Default | What it does |
| --- | --- | --- |
| `ENCRYPTION_KEY` | none (required by the installer) | Master key that wraps each file's own key. **Back it up offline.** |
| `ENCRYPTION_KEY_ID` | `k1` | Label stored with every file key. Change it only when rotating keys. |
| `ENCRYPTION_ENABLED` | `true` when `ENCRYPTION_KEY` is set | `false` stores new files unencrypted. |
| `ENCRYPTION_OLD_KEYS` | empty | After a key rotation, previous keys so older files stay readable: `k0:base64:…,k-old:base64:…` (id, colon, key). The encryption upgrade re-wraps files with the current key. |
| `LEGACY_ENCRYPTION_KEY_FILE` | `<app folder>/uploads/.enc_key` | Key file of the old version's AES-256-CBC files, used only to import and convert them. Absolute, or relative to the app folder. To retire it, **delete the file** once *Admin → System → Encryption upgrade* reports nothing remaining (an empty value just means the default path, so emptying the setting does not retire it). |

### Integrations

| Variable | Default | What it does |
| --- | --- | --- |
| `SLACK_WEBHOOK` | empty | Slack incoming-webhook URL (only `https://hooks.slack.com/…` is accepted). Can be overridden in *Admin → System*. Which events are sent is an admin setting. |
| `OCR_PROVIDER` | empty (off) | `ocrspace` or `googlevision`. Needs the `curl` extension. |
| `OCR_API_KEY` | empty | Key for that provider. |
| `OCR_MAX_BYTES` | 1 MiB for OCR.space | Largest file sent to OCR.space (paid plans allow more; capped at 8 MiB). Google Vision uses a fixed 7 MiB. (Not in `.env.example`.) |
| `VAPID_PUBLIC_KEY` / `VAPID_PRIVATE_KEY` | empty | Web Push key pair. Push is offered only when both are set. Generate a **new** pair in *Admin → System → Web Push keys* (2.4). |
| `VAPID_SUBJECT` | `mailto:admin@example.com` | Contact address sent to push services. Use your own. |
| `MAIL_DRIVER` | `none` | `none`, `smtp` or `log`. `log` only writes a log line (no message body), for testing. Password reset by e-mail is offered whenever this is not `none`. |
| `MAIL_FROM` / `MAIL_FROM_NAME` | empty / `FastTransfer` | Sender. |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` | – / `587` / – / – | SMTP server. byethost only allows outbound SMTP on port 587. |
| `SMTP_ENCRYPTION` | `tls` | `tls` (STARTTLS), `ssl` or `none`. |

### Operations

| Variable | Default | What it does |
| --- | --- | --- |
| `INSTALL_TOKEN` | empty | Unlocks `/install`. Without it the installer cannot be used. Remove it after installing. |
| `MAINTENANCE_TOKEN` | empty | Enables `maintenance.php?token=…` and `/maintenance?token=…` for an external scheduler. Must be at least 16 characters, otherwise HTTP maintenance is refused. Useless on byethost free (see below). |
| `PSEUDO_CRON` | `true` | Run maintenance slices in the background of normal requests (hosts without cron). |
| `PSEUDO_CRON_INTERVAL` | `300` (minimum 60) | Seconds between pseudo-cron slices. |

### Real-time sync

| Variable | Default | What it does |
| --- | --- | --- |
| `REALTIME_MODE` | `auto` | `auto`, `sse`, `longpoll` or `poll`. `auto` uses Server-Sent Events whenever PHP can sleep (`usleep()`), except on byethost/iFastNet free hosting, which it recognises by the host's `__test` cookie and then uses polling. **Still set `poll` there** (5.1). |
| `REALTIME_HOLD_SECONDS` | `20` (5–55) | How long one SSE or long-poll request stays open. At most 2 held requests per account at a time; further ones are answered `429` and that browser short-polls instead. |
| `REALTIME_POLL_SECONDS` | `4` (2–60) | Poll interval while the page is visible and in use; idle and hidden pages poll less often (see 5.2). byethost: `8`. |

`FT_ENV_FILE` is not a `.env` setting: it is a process environment variable that points PHP at a
different env file. The test runner uses it.

---

<a id="background-maintenance-without-cron"></a>

## 4. Background maintenance without cron

FastTransfer has regular housekeeping: expiring shares, sessions, files and texts, purging the
Trash, pruning old versions, events, logs and rate-limit rows, cleaning up abandoned uploads,
reconciling quotas and reference counts, converting old encrypted files, and running queued jobs
(Web Push, e-mail, thumbnails, OCR, Slack). Every task is idempotent and time-boxed, runs are
exclusive (a lock file), and a cursor makes short runs take turns so every task gets its go.

Scheduled tasks: `expire_shares`, `expire_sessions`, `auto_expire_files`, `expire_texts`,
`cleanup_uploads`, `purge_trash`, `prune_versions`, `cleanup_bundles`, `prune_events`,
`prune_audit`, `prune_login_history`, `prune_notifications`, `prune_rate_limits`,
`prune_presence`, `orphan_records`, `unreferenced_blobs`, `reconcile_quotas`, `process_jobs`,
`snapshot_stats`, `encryption_migration`, `prune_logs`. On demand only: `egress_check` (tests the
outbound connections to the integration hosts).

What drives it, depending on the host:

| Driver | Where it works | How |
| --- | --- | --- |
| **Pseudo-cron** | everywhere (`PSEUDO_CRON=true`) | After a normal request, at most once per `PSEUDO_CRON_INTERVAL`, one request runs a maintenance slice. Where PHP can finish the response early (PHP-FPM, LiteSpeed) the slice gets 6 s after the response; on byethost it gets 1.5 s and that visitor's request waits for it, so slices stay tiny. |
| **Tick from open browsers** | everywhere | The leader tab of each signed-in browser calls `POST /api/v1/tick` about every 60 s while the page is visible: up to 2.5 s of queued jobs, plus a 5 s maintenance slice when one is due (at most 4 ticks a minute per user). |
| **After the request that queued a job** | everywhere | Jobs also run right after the request that created them (1.5 s budget on byethost). |
| **External scheduler + `MAINTENANCE_TOKEN`** | only hosts **without** a JavaScript cookie check | Call `https://example.com/maintenance.php` (or `/maintenance`) with the token in an `X-Maintenance-Token` header (preferred: keeps it out of access logs) or as `?token=`. Optional `task=name[,name]`. Runs for up to 20 s and returns JSON. Wrong tokens are rate-limited per IP. **Not usable on byethost free:** the host's cookie check blocks non-browser clients, and the host prohibits automated background requests. |
| **CLI / real cron** | hosts with SSH or cron (section 6) | `php maintenance.php` (options below). |
| **By hand** | everywhere | *Admin → System → Maintenance → Run now* (20 s budget). |

`maintenance.php` on the command line:

```text
php maintenance.php                        run the scheduled tasks (budget 120 s)
php maintenance.php --task=purge_trash     run named task(s), comma-separated
php maintenance.php --budget=300           longer budget (1–3600 s)
php maintenance.php --verbose              one line per task
php maintenance.php --json                 machine-readable result
php maintenance.php --help                 list the tasks
```

Exit codes: `0` all tasks fine, `1` at least one task failed, `2` not installed or unknown task.
Results of every run are listed in *Admin → System → Maintenance* (`maintenance_logs`).

On byethost the combination of pseudo-cron and ticks is all you need. Nothing to configure.

---

## 5. Known byethost limits and how FastTransfer adapts

| byethost free limit | What FastTransfer does |
| --- | --- |
| **10 MB maximum per file on disk** (bigger files are deleted; appending past 10 MB is blocked) | Every stored file is split into **8 MiB segments** and reassembled only while streaming a download. ZIP downloads are streamed (never written to disk). Logs rotate below 8 MB; database and import backups are written in parts below 8 MB. |
| Request body limits (`upload_max_filesize` 20 MB, `post_max_size` 30 MB) | Uploads go in chunks of at most 8 MiB and at most the request limit minus 64 KiB. The single-request upload (`POST /api/v1/files`) is limited to 8 MiB. |
| No held connections: `sleep()` disabled, a buffering proxy in front, few PHP processes | No SSE or long-poll there: with `REALTIME_MODE=poll` the app uses **adaptive short polling**. An unchanged poll is answered `204 No Content` without opening a database connection. |
| **50,000 hits a day** (every request counts, including polls, ticks, chunks, thumbnails and static files) | One poller per browser (a leader tab shares events with the other tabs), slower polling when idle or hidden, the cheap 204 fast path, and a service worker that serves the versioned static files from the browser's cache. See 5.2. |
| **JavaScript cookie check** (`__test` cookie, rotated about every 6 h) in front of PHP | Every API response carries `X-FT-Api: 1`. When a response lacks it (the host answered with its challenge page), the web app re-runs the check in a hidden frame and retries once; if that fails it asks you to reload the page. Non-browser clients (curl, scripts, API tokens, external cron, link-preview bots) are blocked. FastTransfer never forges the cookie (the terms forbid it). |
| 60 s execution limit (shows as a 502), `set_time_limit()` disabled | All long work is time-boxed (about 15–20 s per request) and resumable: migrations, the import, the encryption upgrade, maintenance. |
| No cron | Pseudo-cron and ticks (section 4). |
| MariaDB: 4 connections, `wait_timeout` 20 s, `max_allowed_packet` 3 MB | One lazy connection per request, released before any waiting; file bytes never go into the database. |
| `.htaccess` hardening (`Header`, `php_value`, `Expires` and similar break the site) | The shipped `.htaccess` only uses `Options -Indexes`, `DirectoryIndex` and rewrite rules; all headers are sent from PHP. |
| Nothing may live outside `htdocs`; `open_basedir` | `.env` and `storage/` live inside the web folder, refused by `.htaccess`, `Require all denied` and stub index files. *Admin → System* checks that a canary file in `storage/` is not publicly readable. |
| No `mail()`; outbound SMTP only on port 587 | Use `MAIL_DRIVER=smtp` with port 587 and `tls`, or leave e-mail off. |
| 5 GB disk | Set `STORAGE_CAPACITY_GB=5` for the dashboard; use quotas (default 1 GiB per user, admin-editable). |
| The host's malware scanner may delete stored files | A file whose stored data has vanished answers `410 FILE_UNAVAILABLE` instead of sending something broken. |

### 5.1 Live updates on byethost: set `REALTIME_MODE=poll`

byethost has `usleep()`, so a plain capability check would choose Server-Sent Events there. The
host's proxy does not stream responses, so the browser would wait 8 seconds, fall back to
long-polling, and keep PHP processes busy, which the host's terms and limits do not allow.

`REALTIME_MODE=auto` therefore recognises byethost/iFastNet free hosting: when a request carries
the `__test` cookie that the host's JavaScript check sets (FastTransfer never sets or forges it),
the server reports that it cannot hold connections and the web app uses short polling. Still set
**`REALTIME_MODE=poll`** explicitly: it does not depend on the cookie being present on every
request, and it states your intent. With `poll`, the stream endpoint answers `503`, long-poll
requests return immediately, and the web app uses short polling only.

### 5.2 Hits budget and `REALTIME_POLL_SECONDS`

How often the leader tab polls (from `assets/js/core/realtime.js`):

| Page state | Interval | With `REALTIME_POLL_SECONDS=8` |
| --- | --- | --- |
| Visible and used in the last 2 minutes | `REALTIME_POLL_SECONDS` | 8 s |
| Visible but idle for more than 2 minutes | the longer of 15 s and 2 × `REALTIME_POLL_SECONDS` | 16 s |
| Hidden (another tab or app in front) | the longer of 60 s and 4 × `REALTIME_POLL_SECONDS` | 60 s |

So a larger value never makes active polling slower than idle polling. Polls are always at least
1.15 s apart. Plus one tick every 60 s while visible, and an immediate poll on focus, when the
network returns, and shortly after your own changes. An answer `429 Too Many Requests` is never
shown as a lost connection: the browser waits as the server asks (`Retry-After`) and carries on.

Rough arithmetic for one browser with the page visible and in use:

| `REALTIME_POLL_SECONDS` | Hits per hour (polls + ticks) | 8 hours a day |
| --- | --- | --- |
| 4 (default) | about 960 | about 7,700 |
| 8 (recommended on byethost) | about 510 | about 4,100 |
| 15 | about 300 | about 2,400 |

With the default, six people working all day would use more than 46,000 of the 50,000 daily
hits on polling alone; with **`REALTIME_POLL_SECONDS=8`** they use about 25,000, and changes still
appear within a few seconds. Use 8 on byethost (raise it further for more people). Page loads,
assets, thumbnails and upload chunks come on top.

---

## 6. Normal hosts and VPSs

Everything in section 2 applies, with these differences:

- **`.env`:** put it one folder above the web root (FastTransfer looks there first), or set real
  environment variables (they override `.env`).
- **Storage outside the web root:** `STORAGE_PATH=/var/lib/fasttransfer` (absolute), writable by
  the PHP user.
- **Real-time:** `REALTIME_MODE=auto` gives Server-Sent Events. The browser falls back to
  long-polling if the stream does not open within 8 seconds (for example because a proxy buffers
  it), and to short polling if that fails too. Each open browser holds **one PHP worker** for up
  to `REALTIME_HOLD_SECONDS` per connection, then reconnects. Size PHP-FPM accordingly
  (`pm.max_children` comfortably above the number of open browsers), and keep proxy and FastCGI
  timeouts above `REALTIME_HOLD_SECONDS` + 15 s.
- **PHP limits:** `upload_max_filesize` and `post_max_size` of at least 9M (chunks are 8 MiB),
  `max_execution_time` 60 or more.
- **Maintenance:** use real cron (below) and you may set `PSEUDO_CRON=false`.
- **Proxy:** behind your own reverse proxy (Nginx, Cloudflare), set `TRUST_PROXY_HEADERS=true`
  **and** list the proxy addresses in `TRUSTED_PROXIES` (for a proxy on the same machine:
  `TRUSTED_PROXIES=127.0.0.1,::1`). Without the list no forwarding header is believed.
  HTTPS is detected from `X-Forwarded-Proto` automatically.
- **HTTPS:** for example Let's Encrypt, then `FORCE_HTTPS=true` and an `https://` `APP_URL`.

### Apache

The shipped `.htaccess` does everything (routing, refusing internal folders, dot-files and data
files, passing the `Authorization` header to PHP). It only needs `mod_rewrite` and permission to
use `.htaccess`:

```apache
<VirtualHost *:443>
    ServerName drive.example.com
    DocumentRoot /var/www/fasttransfer

    <Directory /var/www/fasttransfer>
        AllowOverride All
        Require all granted
    </Directory>

    # Optional, for SSE through PHP-FPM: do not compress the event stream
    SetEnvIf Request_URI "^/api/v1/events/stream" no-gzip=1

    # SSLEngine on, certificate lines, …
</VirtualHost>
```

If Server-Sent Events never arrive with PHP-FPM behind `mod_proxy_fcgi`, the app falls back to
long-polling by itself. Enabling packet flushing for the FastCGI proxy (`flushpackets=on`)
usually makes SSE work.

<a id="nginx"></a>

### Nginx + PHP-FPM

Nginx ignores `.htaccess`, so the same rules must be in the server block. Adjust the paths and
the PHP-FPM socket:

```nginx
server {
    listen 443 ssl http2;
    server_name drive.example.com;
    root /var/www/fasttransfer;
    index index.php;

    # Upload chunks are up to 8 MiB; the Nginx default (1 MB) would reject them.
    client_max_body_size 16m;

    # Never serve application internals, data, legacy JSON, dot-files or data files
    location ~ ^/(app|database|storage|tests|docs|uploads|vendor|node_modules|views)(/|$) { return 404; }
    location ~ /\.(?!well-known/) { return 404; }
    location ~ ^/(remember_tokens|push_subs|ft_config|composer|package|package-lock)\.json$ { return 404; }
    location ~* \.(sql|log|md|lock|ini|sh|bak|dist|env|gz|txt)$ { return 404; }

    # Real static files directly, everything else through the front controller
    location / {
        try_files $uri /index.php$is_args$args;
    }

    location = /index.php {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root/index.php;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
        fastcgi_read_timeout 60s;   # above REALTIME_HOLD_SECONDS + 15
    }

    location = /maintenance.php {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root/maintenance.php;
        fastcgi_pass unix:/run/php/php8.3-fpm.sock;
    }

    # No other PHP file may run
    location ~ \.php$ { return 404; }
}
```

FastTransfer sends `X-Accel-Buffering: no` on the event stream, which tells Nginx not to buffer
it. Nginx passes the `Authorization` header to PHP by default.

### Cron

```cron
*/5 * * * * cd /var/www/fasttransfer && php maintenance.php >> /var/log/fasttransfer-maintenance.log 2>&1
```

Relative paths in `.env` (`STORAGE_PATH`, `LEGACY_UPLOADS_PATH`, `LEGACY_ENCRYPTION_KEY_FILE`) are
resolved from the app folder, so the working directory of the cron job does not matter.
Overlapping runs are harmless: a second run sees the lock and skips.

On a host with cron but without a shell, point the host's scheduler at
`https://drive.example.com/maintenance.php` with `MAINTENANCE_TOKEN` set (only where the host has
no JavaScript cookie check).

---

## 7. Troubleshooting

### The installer says "FastTransfer is installed" but you never installed on this server

`/install` decides from `storage/runtime/installed.json`, which records the database host, port and
name it belongs to and the latest migration. If you uploaded your local `storage/` folder and your
local `.env` pointed at a database with the same host, port and name, the server believes it is
already installed. Delete `storage/runtime/installed.json` on the server (or the whole uploaded
`storage/` folder if it holds nothing from this server) and open `/install` again. A marker from a
different database is ignored automatically.

The opposite case, every page redirecting to `/install` (and API calls answering
`503 NOT_INSTALLED`) after uploading a new version, is expected: the new version brings database
updates. Add a temporary `INSTALL_TOKEN` to `.env`, open `/install`, click **Upgrade now** and
**Finish the upgrade**, then remove the token again. See [UPGRADE.md](UPGRADE.md#future-upgrades).

### HTTP 500 or 502 straight after uploading

- **`.htaccess`:** byethost answers 500/502 when `.htaccess` contains directives it no longer
  accepts (`Header`, `php_value`, `Expires`, `AddType`, `Options` other than `-Indexes` …). Use the
  shipped `.htaccess` unchanged and make sure no old `.htaccess` with such lines is left in
  `htdocs`. Remove any `php_value` lines VistaPanel's PHP options may have added.
- **PHP too old:** below PHP 8.0 you get "FastTransfer requires PHP 8.0 or newer"; the
  installer requires 8.1.
- **A 502 after about 60 seconds** means a request hit the host's time limit. All FastTransfer
  batch work is time-boxed; tell the developers which page it was.
- **Logs:** PHP errors are written to `storage/logs/` (one JSON line per entry, files named by
  channel and date, for example `php-2026-10-04.log`). Download them by FTP. For a short
  diagnosis you may set `APP_DEBUG=true` to see the error message in the response; switch it off
  again straight away.

<a id="database-connection-errors"></a>

### Database connection errors

The installer translates the common ones:

| Message | Fix |
| --- | --- |
| Could not reach the database server | Wrong `DATABASE_HOST`/`DATABASE_PORT`. On byethost use the `sqlNNN…` host, not `localhost`. A local copy cannot reach the byethost database: use a local MySQL with `DATABASE_HOST=127.0.0.1`. |
| The database refused the user name or password | Check `DATABASE_USER` / `DATABASE_PASSWORD` (byethost: your hosting account user and password). |
| That database does not exist | Create it first (VistaPanel → MySQL Databases) and use the full prefixed name. |
| The database user has no access to that database | Grant access, or check `DATABASE_NAME`. |
| DATABASE_NAME is empty | Fill it in `.env` and upload `.env` again. |

### "The connection needs to be refreshed. Please reload the page."

On byethost the host's cookie check expired (about every 6 hours) and could not be renewed in the
background. Reload the page. Nothing was lost: the request never reached PHP, and uploads resume.

### Live updates do not arrive

- byethost: `REALTIME_MODE=poll` and `REALTIME_POLL_SECONDS=8`, see 5.1 and 5.2.
- VPS: check that proxy timeouts exceed `REALTIME_HOLD_SECONDS`; the browser falls back by itself
  if SSE is buffered.
- Events older than the retention period (setting *event retention*, 7 days by default) cannot be
  replayed; the app then refreshes the visible page instead.

### An API token stopped working, or the app asks for a password again

This is by design:

- **Changing a password** (in *Settings*, by e-mail reset, or an administrator's reset) signs the
  account out of every other session and **revokes all its API tokens**. So does *Security
  Centre → Sign out all other devices* and an administrator's forced sign-out. Create a new token
  afterwards and update your scripts.
- **Turning on two-factor authentication** and **creating an API token** ask for the current
  password again (as does turning two-factor off), so a stolen session cookie alone cannot do it.
- An account with a temporary password **must choose a new one** first: until then the server
  answers every other API request with `403 PASSWORD_CHANGE_REQUIRED` and the web app shows the
  change-password dialog. Sign-in with `issue_token` gives no API token until then either.

### Push notifications, OCR or Slack do nothing

They need `curl` (OCR, link previews), the keys in `.env`, and queued jobs to run (an open
browser tab, pseudo-cron or cron, section 4). *Admin → System* lists failed jobs and can retry
them; the `egress_check` maintenance task tests outbound connections. byethost blocks some
outbound hosts without notice.

### "Maintenance over HTTP is disabled"

`MAINTENANCE_TOKEN` is missing or shorter than 16 characters.
