# Upgrading to FastTransfer 2

This guide is for moving from the old **single-file FastTransfer** (one large `index.php` that
kept everything in JSON files under `uploads/`) to FastTransfer 2, and for installing later
versions of FastTransfer 2.

The installation itself (database, `.env`, uploading, `/install`) is described step by step in
[DEPLOYMENT.md](DEPLOYMENT.md). This document explains what happens to your data and links, what
is deliberately left behind, how the encryption upgrade works and how to roll back.

What the importer does is taken from `app/Legacy/LegacyImporter.php`; the old-link handling from
`app/Legacy/LegacyRoutes.php` and `app/Controllers/Web/LegacyController.php`.

---

## What changes

| Old version | FastTransfer 2 |
| --- | --- |
| One `index.php` with users, passwords and API keys written in the source code | An application in `app/`, secrets in `.env`, settings in the database |
| Data in `uploads/*.json` | MySQL/MariaDB tables |
| Files as plain files in `uploads/` (optionally AES-256-CBC) | Content-addressed, de-duplicated blobs in `storage/`, stored as 8 MiB segments and encrypted with AES-256-GCM |
| A few fixed accounts, everyone sees every file | Real accounts with roles, private drives, sharing with people and links |
| Polling the whole page state | Real-time events (see [EVENTS.md](EVENTS.md)) |

The importer **never changes or deletes anything** in the old `uploads/` folder or the old JSON
files. You remove them yourself when you are satisfied.

---

## Before you start

1. **Back up everything** by FTP: `index.php`, `uploads/` (including `uploads/versions/` and
   `uploads/.enc_key`) and the JSON files next to `index.php` (`remember_tokens.json`,
   `push_subs.json`, `ft_config.json`). byethost keeps no backups for you.
2. **Keep the old `index.php` on your PC only** (your copy is
   `D:/working/php/Sendit-backup-2026-10-03/index.php`). It contains real credentials; never upload
   it again except for a rollback, and never under another name.
3. **Plan the credential rotation** in [SECURITY.md](SECURITY.md) §1: Slack webhook, OCR.space key,
   VAPID keys and every password written in the old source. Use only **new** values in `.env`.
4. **Check the disk space.** The import copies every file (and every old version) into `storage/`
   while the originals stay in `uploads/`, so you need roughly the size of `uploads/` free again
   until you delete the old folder. byethost free accounts have 5 GB in total.

---

## Upgrade steps (summary)

1. Create the MySQL database and a production `.env` ([DEPLOYMENT.md 2.2–2.4](DEPLOYMENT.md#22-create-the-mysql-database)).
   Leave `LEGACY_UPLOADS_PATH` and `LEGACY_ENCRYPTION_KEY_FILE` empty: they then point at
   `uploads/` and `uploads/.enc_key` next to `index.php`.
2. Upload the new files over the old installation ([DEPLOYMENT.md 2.5](DEPLOYMENT.md#25-upload-the-files)).
   The new `index.php` replaces the old one; `uploads/` and the old JSON files stay where they are.
3. Open `/install` and go through the steps. On the last step, **Import files from the old
   version** appears because old data was found. Choose the options and run it; it continues by
   itself in batches of about 15 seconds until it is done.
4. **Copy the one-time passwords** shown for the imported accounts (they are shown once) and give
   them to their owners.
5. Finish, sign in, check your files, then work through the post-install checklist
   ([DEPLOYMENT.md 2.7](DEPLOYMENT.md#27-after-installing-checklist)).

You can also run or continue the import later from **Admin → System → Import from the old
version** (or `POST /api/v1/admin/legacy-import`, which additionally accepts `user_map` to map old
user names to existing accounts and `retry_failed` to retry items that failed).

---

## What is imported

First, every old JSON file (except the three secret-bearing ones, see below) is copied to
`storage/backups/legacy-json-<date>-<time>/`, split into parts below 8 MB if necessary.

| Old data | Becomes |
| --- | --- |
| **User names** found in `audit.json`, `comments.json`, `shares.json` and `collab.json` | Accounts (option *Create accounts for the old users*, on by default). The role comes from the old comment data where recorded; otherwise the name `guest` becomes a guest and every other name a user. The old `admin` account maps to the administrator running the import, and an existing account with the same user name is reused. New accounts get a **one-time password**; the web app makes them choose a new one at first sign-in. User names must be 3–32 letters, digits, `.`, `-` or `_`; others are reported as warnings. |
| **Files** in `uploads/` (with their `metadata.json` entries) | Files owned by their uploader (taken from `audit.json`) when that account exists, otherwise by the importing administrator. Upload time, download count, "keep forever" and tags are kept (the old automatic `encrypted` tag is dropped: encryption is shown by FastTransfer itself). Files listed in `metadata.json` but missing on disk are skipped with a warning. |
| **Folders** (`folders.json` and each file's folder) | Folders. With *Share imported files with every imported user* (on by default) each owner's imported content goes into a folder called **Imported files**, with the old folders inside it. |
| **Versions** in `uploads/versions/<name>/` | Version history (oldest first, the current file last). Consecutive identical snapshots are merged. |
| **Favourites** | Favourites of the file's owner. |
| **Tags** (`tags.json` and per-file tags) | Tags. |
| **Comments** (`comments.json`) | Comments on the same files, with the original author name and time. |
| **Share links** (`shares.json`) | Share links with **the same tokens**, so links people already have keep working. Password, expiry, download limit and download count are kept; old password hashes are kept as they are (a password stored unhashed is hashed, with a warning). Links that had already expired stay expired without notifying anyone. Links to files that could not be imported are skipped. |
| **Bundles** (`share_bundle_*.zip`) | Imported as files marked as bundles, so their links keep working. |
| **Saved texts and links** (`texts.json`) | Clipboard entries of the importing administrator, with their "keep" flag; others expire 72 hours after their original time, as before. |
| **History** (`audit.json`) | The audit/activity history, with the original times, users and IP addresses. Old actions are mapped (upload, download, delete, share, comment, restore, text-save); unknown ones are kept as `legacy.<action>`. |
| **OCR text** (`ocr_index.json`) | The search index, so old OCR results are searchable at once. |
| **Notepads** (`collab.json`) | Team notepads (*Notepad* in the sidebar). The old shared notepad fills the empty automatic "Team notepad" (or becomes "Team notepad (imported)" if the team already wrote in it); other documents become team notepads named after them. The last editor is kept. Text over 1 MB is cut to 1 MB with a warning. |
| **Access** | With the share-all option, each owner's *Imported files* folder is shared with every other imported account: **editor** for users, **downloader** for guests (administrators see everything anyway). This reproduces the old "everyone sees everything". |

Expiry is preserved: files not marked "keep forever" expire 72 hours after their original upload
time. Those already past it are moved to the **Trash** by the next maintenance run (not deleted),
so you can still restore them.

**Safe to repeat.** Every imported item is recorded in the `legacy_import` table, so running the
import again skips what is done and only picks up new or failed items (with *retry failed*). A
crash in the middle of a file leaves nothing half-imported. Only one import batch runs at a time.

---

## What is deliberately not imported

| Not imported | Why |
| --- | --- |
| **Old passwords** (the bcrypt hashes in the old source code) | The plain-text passwords were written next to them in the source. Treat them as known to anyone who ever saw the file. Imported accounts get new one-time passwords instead. |
| **Remember-me tokens** (`remember_tokens.json`) | That file was readable over HTTP on many hosts, so the tokens may be stolen. Everyone signs in once. Delete the file. |
| **Web Push subscriptions** (`push_subs.json`) | They are tied to the old VAPID key pair, which was exposed in the source. Generate a new pair; people switch push on again in *Settings*. Delete the file. |
| **Slack webhook** (`ft_config.json` and the source code) | Exposed. Create a new webhook in Slack and put it in `SLACK_WEBHOOK`. Delete the file. |
| **OCR.space key, VAPID keys** (in the source code) | Exposed. Create new ones. |
| `activity.json` | A short live-feed buffer; the durable history comes from `audit.json`. |
| `presence.json`, `uploads/chunks/` | Temporary state (who was editing; unfinished uploads). |

These three JSON files are also left out of the import backup on purpose.

---

## Old links keep working

Links, bookmarks and QR codes made with the old version point at the site root with a query
parameter. FastTransfer 2 recognises them and redirects:

| Old URL | Now |
| --- | --- |
| `/?share=<token>` | `302` to `/s/<token>`, the new share page (same token). |
| `/?share=<token>` as a POST with `share_password` (the old password form) | `307` to `/s/<token>/unlock`, which accepts the old field name. |
| `/?download=<file name>` | Signed-in users who may download the imported file with that old name: `302` to `/api/v1/files/<id>/download`. Signed-out visitors are sent to sign in first and come back. Otherwise a "not found" page (it never reveals whether the file exists). |
| `/?serve=<file name>` | The same, to the inline preview (`/api/v1/files/<id>/content`). |
| `/?logout` | `302` to `/logout`. |
| Any other old action (`?download_zip`, `?bulk_share`, `?activity_poll`, `?fetch_meta`, …) | `302` to the app's home page. |

With `PRETTY_URLS=false` the targets use `index.php?r=/…` instead. The `?i=1` parameter that
byethost's cookie check adds is not treated as an old link.

Old links to files that could not be imported, and old links that had expired, show the new
"link not available" page.

---

## The encryption upgrade (AES-256-CBC → AES-256-GCM)

The old version could encrypt files with **AES-256-CBC**, using a key stored in
`uploads/.enc_key`. CBC has no integrity check: a damaged or tampered file decrypts to garbage
without any error. FastTransfer 2 uses **AES-256-GCM** in 1 MiB chunks, with a random key per file
wrapped by your `ENCRYPTION_KEY`, which detects damage, truncation and tampering.

How the switch happens:

1. **During the import**, old files that were **not** encrypted are encrypted straight away with
   AES-256-GCM (when `ENCRYPTION_ENABLED`). Old **CBC-encrypted** files are copied byte for byte
   (format `legacy_cbc`) and stay readable through `uploads/.enc_key`. Their checksum is calculated
   from the decrypted content at import time. If the key file is missing or wrong, such a file is
   reported as failed and nothing is stored; restore the key and run the import again with
   *retry failed*.
2. **The encryption upgrade** then converts every `legacy_cbc` file (and any unencrypted one) to
   AES-256-GCM. For each file it decrypts, re-encrypts, **checks that the SHA-256 of the content is
   unchanged**, and only then swaps the stored copy and deletes the old one. On any mismatch the
   file is left exactly as it was and listed as a failure (retried after a day, or at once with
   *retry*).
3. It runs automatically as the `encryption_migration` maintenance task, a little at a time. You
   can speed it up in **Admin → System → Encryption upgrade → Upgrade files** (about 15 seconds per
   click) or with `POST /api/v1/admin/encryption/migrate`. `GET /api/v1/admin/encryption` shows
   how many files are still pending.
4. When nothing is pending, delete `uploads/.enc_key` from the server (keep an offline copy until
   you are sure you will not roll back).

The same mechanism handles a later **key rotation**: put the new key in `ENCRYPTION_KEY` with a new
`ENCRYPTION_KEY_ID`, move the old one to `ENCRYPTION_OLD_KEYS` (`k1:base64:…`), and the upgrade
re-wraps every file's key with the new master key.

---

## Rollback plan

The upgrade is reversible because the old data is never modified.

**Keep, until you are sure:** your PC backup of the old `index.php`, the server's `uploads/`
folder, `uploads/.enc_key`, and an offline copy of all three.

To go back to the old version:

1. Upload the old `index.php` over the new one (by FTP). You can leave the new `.htaccess`; it
   sends every request to `index.php` and still refuses `uploads/` and the old JSON files over HTTP.
   If your old installation had its own `.htaccess`, you can restore that instead.
2. The old version runs again on the untouched `uploads/` folder and JSON files. The new folders
   (`app/`, `storage/` …) and `.env` can stay; the old version ignores them, and `.htaccess`
   refuses them over HTTP.
3. Be aware:
   - Anything added or changed in FastTransfer 2 after the upgrade (new files, shares, comments)
     exists only in FastTransfer 2 and is not visible in the old version.
   - If you deleted `remember_tokens.json` or `push_subs.json`, people simply sign in again and
     re-enable push.
   - Credentials you have rotated (Slack, OCR.space, VAPID) are no longer valid, so those features
     of the old version stop working. The old passwords in its source are still compromised.
   - **If `uploads/.enc_key` was deleted, the old version cannot read its encrypted files** (and
     would create a new, useless key). Restore the key from your backup first.

To go forward again, upload the new `index.php` once more. The database and `storage/` are still
there; run the import again from *Admin → System* to pick up files added in the old version in
the meantime (items imported before are skipped; changes to them made in the old version are not
copied again).

To roll back a **database update** of FastTransfer 2 itself, use the automatic backup that is
written to `storage/backups/` (gzip-compressed SQL in parts) before any migration runs on a
database that already holds data. Restore it with phpMyAdmin or the `mysql` client.

---

## Future upgrades

For later versions of FastTransfer 2:

1. **Back up**: download `storage/` (at least `storage/backups/`) and export the database (for
   example with phpMyAdmin). Keep `.env`.
2. **Upload the new code** over the old: `index.php`, `maintenance.php`, `.htaccess`, `app/`,
   `assets/`, `database/` and `views/`. Do **not** overwrite `.env` or `storage/`.
3. **If the new version brings database updates** (new files in `database/migrations/`), every
   page now shows the installer, and API calls answer `503 NOT_INSTALLED`, until you apply them:
   - add a temporary `INSTALL_TOKEN` to `.env` and upload it;
   - open `/install`, enter the token, check the server check, click **Upgrade now** (the database
     is backed up into `storage/backups/` first) and then **Finish the upgrade**;
   - remove `INSTALL_TOKEN` from `.env` again.

   Do this straight after uploading, because the site is unavailable to users in between.
   *Admin → System → Database updates* (`POST /api/v1/admin/migrations/run`) applies the same
   updates, but it can only be reached while the app is running, so it does not help in this
   situation.
4. **If there are no database updates**, nothing else is needed: the new code is live at once.
5. Check *Admin → System* for warnings and read the release notes of the new version for new
   `.env` settings.

The installer recognises an upgrade (the same database was installed before), so it shows
*Upgrade the database* and *Finish the upgrade* instead of the first-installation steps, and it
does not offer the old-data import again.
