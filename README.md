# FastTransfer

FastTransfer is a self-hosted private cloud drive written in plain PHP 8.1 with a MySQL/MariaDB
database. It needs no Composer packages, no Node build step, no daemon and no cron, so it runs on
cheap shared hosting (including byethost/iFastNet free hosting, within that host's limits) and
just as well on a normal web host or a VPS.

Version 2 replaces the original single-file `index.php` (which kept everything in JSON files)
with a multi-user application. Existing data, files and share links can be imported, and old share
links keep working. See [docs/UPGRADE.md](docs/UPGRADE.md).

> **Security notice for upgraders:** the old single-file version had real credentials written in
> its source code (Slack webhook, OCR.space key, Web Push keys, account passwords). Treat them all
> as compromised and rotate them. Never copy them into the new `.env`.
> See [docs/SECURITY.md](docs/SECURITY.md) §1.

---

## Features

Everything below is implemented on the server and exposed through the REST API
([docs/API.md](docs/API.md)) and the web app.

### Accounts and security

- Roles: administrator, user and guest (guests only see what others share with them and cannot upload or share).
- Sign-in with optional "remember me", TOTP two-factor authentication with single-use recovery codes.
- Accounts given a temporary password must choose a new one before they can do anything else (enforced by the server). Changing your password signs out your other devices and revokes your API tokens; turning on two-factor authentication and creating API tokens ask for your current password.
- Security Centre: active sessions (sign out one or all), devices, sign-in history, security events, personal API tokens (full access or read-only).
- Password reset by e-mail (only when e-mail sending is configured).
- Brute-force protection (per IP and per username), account lock-out, rate limits on the API, sign-in, sharing, downloads and public pages.
- Encryption at rest: AES-256-GCM in 1 MiB authenticated chunks, a random key per file, wrapped by your master key.

### Files

- Resumable chunked uploads (pause, resume, resume from another device), plus a single-request upload for small files.
- Folders, rename, move, tags, favourites, descriptions, batch actions, streamed ZIP download of files and folders.
- "Keep forever" or automatic expiry (72 hours by default, as in the old version; expired files go to the Trash).
- Version history: download or restore any version (restoring is non-destructive).
- Trash with restore and automatic purge (30 days by default).
- Inline previews with HTTP Range support (audio/video seeking), thumbnails for images (needs the GD extension).
- Per-user storage quotas and de-duplication (per user, or global if an administrator chooses it).
- Search across names, extensions, tags, folders, descriptions, owners, text content and OCR text, with filters.
- Optional OCR (OCR.space or Google Vision) for images and PDFs.
- In-browser text and code editor for files up to 2 MB (open a file and choose **Edit**): line numbers, Ctrl+S to save, every save kept as a version, conflict handling when someone else saved first, and "who is editing" presence. The same features are available through the API.

### Sharing and collaboration

- Share links with optional password, expiry, download limit and preview/download/comment/edit switches, and a QR code for each link.
- Sharing with named users at four levels (viewer, downloader, commenter, editor), re-sharing, sharing folders and bundles of several files.
- "Shared With Me" and "Shared by me" views; public link pages with previews, ZIP download, comments and (for editor links) uploading a new version.
- Comments on files.
- Clipboard: saved texts and links, with safe link previews.
- Notepad (the old Collaborative Notepad): team and private notepads that several people edit at the same time — changes appear live and are merged, nothing is overwritten; autosave, offline drafts, who-is-here, history with restore, all encrypted at rest.

### Live updates and notifications

- Real-time sync across tabs and devices (Server-Sent Events, long-polling or adaptive short polling, chosen by what the host supports). Only one tab per browser talks to the server.
- Installable as an app (PWA) on phones and desktops: web app manifest with icons, an offline page (served by the `/offline` route), and a service worker that keeps the versioned static files in the browser's cache (which also saves requests on hosts with a daily hit limit). It never caches your files, API answers or share pages. Push notifications arrive through the same service worker.
- Notification centre with per-category preferences; Web Push (VAPID), e-mail over SMTP and Slack incoming webhooks are optional.

### Administration

- Dashboard with live counters and charts, storage per user, all shares, the full audit/activity log.
- User management: create, edit, disable, suspend, delete, reset passwords, force sign-out, turn off 2FA, quotas.
- System page: server diagnostics, runtime settings, maintenance, database updates, the import from the old version, the encryption upgrade, generating Web Push (VAPID) keys and failed background jobs.
- Background maintenance without cron (see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#background-maintenance-without-cron)).

### Compatibility

- Old links keep working: `/?share=<token>`, `/?download=<name>`, `/?serve=<name>` and `/?logout`.

---

## Requirements

| | Minimum |
| --- | --- |
| PHP | **8.1 or newer** (8.3 and 8.4 are fine) |
| Required PHP extensions | `pdo_mysql`, `openssl`, `mbstring`, `json`, `fileinfo`, `zlib` |
| Optional PHP extensions | `curl` (Slack, OCR, Web Push, link previews), `gd` (thumbnails), `sodium`, `zip` |
| Database | **MySQL 5.7+** or **MariaDB 10.3+** (InnoDB, `utf8mb4`) |
| Web server | Apache with `mod_rewrite` and `.htaccess` (the shipped `.htaccess` is enough), or Nginx with the rules in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md#nginx) |
| HTTPS | Strongly recommended (secure cookies; Web Push needs it) |

The web installer (`/install`) checks all of this for you and tells you what is missing.

---

## Quick start

### Local (Windows)

1. Install PHP 8.1+ and MySQL or MariaDB. In `php.ini`, enable at least `extension=pdo_mysql`,
   `openssl`, `mbstring`, `fileinfo` (and `curl`, `gd` if you want those features).
2. Create an empty database, for example in the MySQL client:

   ```sql
   CREATE DATABASE fasttransfer CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   ```

3. Copy `.env.example` to `.env` in the project folder and fill in `DATABASE_*`, `APP_KEY`,
   `ENCRYPTION_KEY` and `INSTALL_TOKEN`. In PowerShell you can generate a key with:

   ```powershell
   php -r "echo 'base64:'.base64_encode(random_bytes(32)), PHP_EOL;"
   ```

   Also set `REALTIME_MODE=poll`: PHP's built-in server handles one request at a time, so a held
   live-update connection would block every other request.
4. Start PHP's built-in server from the project folder. `tests/server.php` applies the same
   access rules as `.htaccess`:

   ```powershell
   php -S 127.0.0.1:8080 -t . tests/server.php
   ```

5. Open <http://127.0.0.1:8080/install>, enter your `INSTALL_TOKEN` and follow the steps.

### Production

Upload the application by FTP, create the database, put a `.env` next to `index.php` (or one
level above the web root where the host allows it) and run `/install`. The full step-by-step guide,
including byethost free hosting, Apache/Nginx and cron, is in
**[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

Do not upload `tests/`, `docs/`, your local `.env` or the contents of your local `storage/` folder.

---

## Documentation

| Document | What it covers |
| --- | --- |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | Installing on byethost free hosting, normal hosts and VPSs; every `.env` setting; maintenance; troubleshooting |
| [docs/UPGRADE.md](docs/UPGRADE.md) | Upgrading from the single-file version: what is imported, old links, encryption upgrade, rollback, future upgrades |
| [docs/API.md](docs/API.md) | REST API v1 reference with curl examples |
| [docs/EVENTS.md](docs/EVENTS.md) | Real-time event format, the full event catalogue and the transports |
| [docs/TESTING.md](docs/TESTING.md) | Running the PHP test suites, the JavaScript checks and the browser test approach |
| [docs/SECURITY.md](docs/SECURITY.md) | Credentials to rotate, where secrets live, the security model |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Internal design contract for developers |

---

## Security notes

- **Rotate every credential from the old version** (Slack webhook, OCR.space key, VAPID keys,
  passwords) and delete `remember_tokens.json`, `push_subs.json` and `ft_config.json` from the app
  root after the import. Details: [docs/SECURITY.md](docs/SECURITY.md).
- **Back up `ENCRYPTION_KEY` offline.** Files encrypted with a lost key cannot be recovered.
- **Remove `INSTALL_TOKEN` from `.env`** once installation is complete.
- `.env` is never committed (it is in `.gitignore`) and is denied over HTTP by `.htaccess`.
- **byethost/iFastNet free hosting:** the host's terms of service prohibit file-hosting and
  file-sharing sites, so the account can be suspended. Its JavaScript cookie check also blocks
  non-browser clients, so the REST API can only be used by the web app there. Use a host whose
  terms allow a private cloud drive for real use.

---

## Licence

_To be confirmed._ Copyright © 2026 MTS. Until a licence file is added, all rights are reserved.
