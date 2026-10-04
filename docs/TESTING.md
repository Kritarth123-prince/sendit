# Testing FastTransfer

FastTransfer's tests need nothing but PHP (and, optionally, Node.js for the JavaScript checks):
no Composer, no PHPUnit, no npm packages. The toolkit lives in `tests/`:

| File | Purpose |
| --- | --- |
| `tests/run.php` | The test runner |
| `tests/lib.php` | Assertions, test users, a test web server and an HTTP client |
| `tests/server.php` | Router script for PHP's built-in web server; applies the same access rules as `.htaccess` |
| `tests/.env.testing` | Test configuration (shared defaults) |
| `tests/.env.testing.local` | Your local overrides (git-ignored, optional) |
| `tests/<Area>Test.php` | The tests, one file per area |
| `tests/js/run.mjs` | JavaScript syntax checks and unit tests (Node.js) |
| `tests/_storage/` | Scratch space for test runs (git-ignored, wiped at every run) |

---

## 1. Requirements

- **PHP 8.1+ on the command line** with `pdo_mysql`, `openssl`, `mbstring`, `fileinfo` and
  **`curl`** (the HTTP test client uses curl). `gd` is needed for the thumbnail tests.
- **A throwaway MySQL or MariaDB server.** The runner **drops and re-creates** its test databases
  on every run, so never point the tests at a database you care about. The database user needs
  permission to `CREATE` and `DROP` databases.
- **Node.js** (optional): when `node` is on the `PATH`, the shell tests also run the JavaScript
  checks; otherwise they print "node not found: JS tests skipped".

---

## 2. Configuration

`tests/.env.testing` holds the defaults shared by everyone:

| Setting | Test value | Why |
| --- | --- | --- |
| `DATABASE_HOST` / `DATABASE_PORT` | `127.0.0.1` / `3307` | A dedicated local test server on port 3307 |
| `DATABASE_USER` / `DATABASE_PASSWORD` | `root` / empty | |
| `DATABASE_NAME` | `fasttransfer_test` | Suites add `_<suite>` (see below) |
| `APP_KEY`, `ENCRYPTION_KEY`, `ENCRYPTION_KEY_ID=t1` | fixed test keys | Never use them anywhere else |
| `ENCRYPTION_ENABLED` | `true` | Storage is tested encrypted |
| `PSEUDO_CRON` | `false` | Maintenance only runs when a test asks for it |
| `REALTIME_HOLD_SECONDS` | `5` | Keeps SSE and long-poll tests short |
| `INSTALL_TOKEN`, `MAINTENANCE_TOKEN` | test values | |
| `MAIL_DRIVER` | `log` | No e-mail leaves the machine |

If your database differs (for example the normal MySQL on port 3306 on Windows), create
**`tests/.env.testing.local`** with only the lines to change:

```ini
DATABASE_PORT=3306
DATABASE_USER=root
DATABASE_PASSWORD=your-local-password
```

Values in `.env.testing.local` win over `.env.testing`. For a one-off run against another
server, set `FT_TEST_DATABASE_HOST`, `FT_TEST_DATABASE_PORT`, `FT_TEST_DATABASE_USER` or
`FT_TEST_DATABASE_PASSWORD` in the environment; they win over both files. The runner then forces the per-suite
values (`DATABASE_NAME`, `STORAGE_PATH`, `LEGACY_UPLOADS_PATH`), writes the result to an
"effective" env file and points the app at it through the `FT_ENV_FILE` environment variable.

---

## 3. Running the PHP tests

Run from the project folder (PowerShell, Command Prompt or Git Bash):

```text
php tests/run.php                          every tests/*Test.php file
php tests/run.php Upload                   only files whose name contains "Upload"
php tests/run.php Share PublicShare        several filters (any match)
php tests/run.php --suite=sharing Share    isolated suite "sharing"
php tests/run.php --suite=auth --port=8111 Auth
php tests/run.php --suite=auth --keep Auth  re-run without resetting the suite's data
```

| Option | Meaning |
| --- | --- |
| *filter words* | Run only test files whose name contains one of the words (case-insensitive) |
| `--suite=<name>` | Isolation: database `fasttransfer_test_<name>`, storage `tests/_storage/<name>/`, its own env file `tests/_storage/.env.<name>` and its own web-server port. Default suite: `main` (database `fasttransfer_test`). Lets several people or agents run tests at the same time. |
| `--port=<n>` | Port of the built-in web server (default `8100 + crc32(suite) % 800`) |
| `--keep` | Skip the reset at the start: reuse the suite's database (created if missing; pending migrations are still applied) and keep its storage folder. Quicker re-runs while you work on one area, but tests then see data left by earlier runs, so do a normal run before you finish. |

What one run does:

1. Builds the effective env file and **wipes** the suite's storage folder (not with `--keep`).
2. **Drops and re-creates** the suite's database (`utf8mb4`; with `--keep` it is only created when
   missing), applies all migrations and marks the app as installed.
   Nothing is dropped at the end of a run, so you can inspect what a failing test left behind.
3. Loads each matching test file and runs its tests in order, printing `✔` or `✘` with the time
   in milliseconds, and the failure message with file and line.
4. Prints a summary (`N passed, M failed in S s (suite, db, port)`) and the list of failures.

Exit codes: `0` all passed, `1` at least one failure, `2` the test database could not be prepared
(check that the test MySQL is running and the credentials in `tests/.env.testing` /
`tests/.env.testing.local` are right; the runner's message points here).

HTTP tests start PHP's built-in server once per run
(`php -S 127.0.0.1:<port> -t . tests/server.php`) with the test environment; its output goes to
`tests/_storage/server.log`. The server is stopped when the run ends (on Windows with `taskkill`).

---

## 4. Running the JavaScript checks

```text
node tests/js/run.mjs
```

It syntax-checks every ES module under `assets/js/` exactly as the browser loads them
(`node --input-type=module --check`, vendored libraries excluded), so a typo cannot ship, and then
runs every `tests/js/*.test.mjs` file in its own Node process. No npm packages are needed. The PHP
suite runs it too (`ShellTest`, "JavaScript unit tests and syntax checks pass (node)") when Node
is installed. The unit tests use Node's built-in `node:test` and `node:assert` and import the
browser modules directly (they touch no DOM when imported):

| File | Covers |
| --- | --- |
| `tests/js/format.test.mjs` | `core/format.js`: `bytes`, `countdown`, `dayLabel`, 24-hour times, `percent`, `plural`, `extOf`, `kindOf` |
| `tests/js/realtime.test.mjs` | `core/realtime.js`: `SeenSet`, `backoffDelay`, `pollInterval` (active / idle max(15 s, 2×) / hidden max(60 s, 4×)), `retryAfterSeconds`, `heldCooldown` |
| `tests/js/router.test.mjs` | `core/router.js`: `compile`, `parseHash`, `matchRoute` |
| `tests/js/csp.test.mjs` | Every library in `features/lib-loader.js` is inside a `Csp::CDN_SCRIPTS` folder and has a `sha384` integrity hash; no stale or host-wide CDN allowances; no other module loads cdnjs scripts |
| `tests/js/views.test.mjs` | Notification deep links (`?file=<id>&tab=comments`), the Security Centre sign-out toast, the SVG `data:` URL |

Run one file on its own with `node tests/js/<name>.test.mjs`.

---

## 5. What is covered

Each file returns a list of named tests. Endpoint tests go through real HTTP requests against the
built-in server; service tests call the PHP classes directly. Across the suites the tests check
the happy path **and** the failure paths: other users' ids give `404`, guests get `403`, missing
CSRF tokens give `419`, validation errors give `422`, and the expected audit rows, events and
notifications are written.

| Area | Test files | Highlights |
| --- | --- | --- |
| Kernel | `KernelTest` | JSON 404 with the `X-FT-Api` marker, authentication required, CSRF-protected logout, disabled accounts lose access, per-username sign-in limit, event fan-out only to recipients |
| Sign-in and accounts | `AuthTest`, `AuthPageTest`, `AuthTokensTest`, `UsersTest`, `UsersAdminTest`, `SecurityTest` | TOTP test vectors and replay protection, password policy, account lock-out, rate limits, cross-site protection, remember-me rotation and theft detection, two-factor flows, password reset, the no-JavaScript sign-in page and open-redirect protection, API tokens (read-only scope, revocation, no cookies or CSRF), admin user management (last-admin protection, soft delete), Security Centre |
| Access control | `AccessMatrixTest` | Capabilities for owner, admin, every share level and flag, bundles, ancestor folders, expired/revoked shares, guests, trashed items; `404` for strangers and `403` for missing rights over HTTP |
| Storage engine | `StorageCryptoTest`, `BlobStoreTest`, `StorageStreamTest`, `StorageHttpTest`, `QuotaServiceTest`, `FileWriterTest` | AES-256-GCM round trips at chunk boundaries, multi-segment files, tamper/truncation/reordering detection, old keys, legacy CBC reading, de-duplication and reference counts, Range/ETag/304 handling, safe previews, quotas and reservations, versions, name conflicts, auto-expiry, thumbnails |
| Uploads | `UploadFlowTest` | Session shape, out-of-order and bad chunks, resume, idempotent completion, abort, quota checks at every step, uploads into shared folders, empty files, `on_conflict`, single-request uploads, expiry |
| Files, folders, Trash, versions | `FilesDomainTest`, `FoldersTest`, `TrashTest`, `VersionApiTest`, `ZipStreamTest`, `EditorTest` | Listings, filters and views, rename/move with events and audit, tags, downloads and previews, `FILE_UNAVAILABLE`, batch actions, the activity timeline, folder cycles, Trash batches and retention, version download/restore, streamed ZIPs (CRC-32, UTF-8 names, ZIP64), the text editor with version conflicts and presence |
| Sharing | `ShareTest`, `PublicShareTest`, `CommentTest` | Link and user shares, level defaults and flags, re-sharing and cascades, status transitions, Shared With Me, rate limits, expiry notifications; public link pages (CSP, legacy 32-character tokens, passwords, download counting and limits, folder browsing, ZIPs, anonymous comments, editor-link uploads); comments and their notifications |
| Clipboard and link previews | `TextTest` | Private texts, auto-expiry, and SSRF protection of link previews (private, loopback, IPv6, odd encodings, ports, DNS pinning) |
| Notifications | `NotificationTest`, `WebPushTest`, `MailerTest`, `SlackTest` | Preferences per channel, de-duplication, the notification centre API; Web Push (RFC 8291 test vector, VAPID signatures, endpoint allow-list, delivery and clean-up); SMTP conversations and header-injection protection; Slack message format and webhook validation |
| Real-time | `RealtimeTest` | Short-poll `204` fast path without a database connection, ordering, throttling, admin channel, recovery and resets, API tokens, long-poll, SSE frames, padding, `Last-Event-ID` and reset frames, degraded mode without held connections |
| Search and OCR | `SearchTest`, `OcrTest` | Search fields, filters and validation, escaped snippets, the OCR endpoint, content indexing and OCR job limits |
| Maintenance and admin | `MaintenanceTest`, `AdminApiTest` | Idempotent tasks, exclusive runs, budget and cursor, pseudo-cron interval, `/tick` (CSRF, rate limit, jobs run as the system), the maintenance URL and CLI; admin dashboard, settings, maintenance, migrations, import and encryption endpoints |
| Upgrade from the old version | `LegacyImportTest`, `LegacyEncryptionTest`, `LegacyRoutesTest` | Full import (users, files, versions, folders, favourites, shares, comments, texts, history, notepads, access shares), safe re-runs, the untouched old folder, missing encryption key handling, CBC → GCM conversion and failure handling, old URL redirects without open redirects |
| Web app shell and PWA | `ShellTest`, `PwaTest` | Sign-in page and shell with CSP nonces and no secrets in the boot data, the boot data shape, guests' shell, static assets, the JavaScript checks; manifest, service worker, offline page |
| Cross-module | `IntegrationTest` | Last-access tracking for Shared With Me, timeline sentences for other modules' actions, share tokens never reaching log files, dedicated rate-limit buckets, queue handler validation |

`FilesFixturesTest.php` and `SharingFixturesTest.php` contain no tests; they define helper
functions (create files, shares and so on) that other test files use.

---

## 6. Writing tests

A test file returns an array of `description => closure`:

```php
<?php
declare(strict_types=1);

return [
    'users can create folders; guests cannot' => function () {
        $owner = t_user('user');
        $c = new TestClient();
        $c->login($owner['username'], $owner['password']);
        $r = $c->post('api/v1/folders', ['name' => 'Reports']);
        t_eq(201, $r['status']);
        t_eq('Reports', $r['json']['data']['name']);

        $guest = t_user('guest');
        $g = new TestClient();
        $g->login($guest['username'], $guest['password']);
        t_eq(403, $g->post('api/v1/folders', ['name' => 'Nope'])['status']);
    },
];
```

Helpers from `tests/lib.php`:

| Helper | What it does |
| --- | --- |
| `t_assert($cond, $msg)` | Fail unless `$cond` is true |
| `t_eq($expected, $actual, $msg)` | Strict equality |
| `t_throws($fn, ?$errorCode)` | Expect an exception (optionally an `ApiException` with that code); returns it |
| `t_user($role, $options)` | Create an `admin`, `user` or `guest` directly in the database; returns the row plus `password` |
| `t_server()` | Start (once) the built-in web server with the test environment; returns its base URL |
| `new TestClient()` | HTTP client with a cookie jar, automatic CSRF token and `X-Client-Id`: `login()`, `get()`, `post()`, `patch()`, `put()`, `delete()`, `postRaw()` (raw bodies such as upload chunks), `postForm()`, `request()`. Each returns `['status', 'json', 'body', 'headers']`. |

Guidelines (from the architecture contract):

- Run your area in its own suite while developing: `php tests/run.php --suite=<area> <Area>`.
- Test authorisation failures, not just the happy path.
- Check the side effects your code must have: audit rows, events (and their recipients),
  notifications.
- `php -l` every new PHP file; the JavaScript checks cover `assets/js`.

---

## 7. Browser end-to-end testing

There is no automated browser test suite in the repository yet. `.gitignore` already reserves
`tests/e2e/` for a Playwright project (`tests/e2e/node_modules/`, `test-results/`,
`playwright-report/`). The intended approach:

### Automated (Playwright, when added)

- Start the app exactly as the PHP tests do: `php tests/run.php` prepares a database, or start
  `php -S 127.0.0.1:8099 -t . tests/server.php` with `FT_ENV_FILE` pointing at a test env file
  that has `REALTIME_MODE=poll` (the built-in server handles one request at a time).
- Seed users through the API (or `t_user()` in a small PHP script) and drive the real UI in
  Chromium, Firefox and WebKit, at desktop and phone sizes.
- Core journeys: sign in (with and without 2FA); upload a large file, interrupt and resume it;
  folders, rename, move, Trash and restore; share a link with a password and open it in a fresh
  browser context; share with a second user and watch it appear live in their session; comments;
  version restore; admin user management; the old `/?share=` link redirect.
- Real-time across tabs: open two tabs, check that only one polls (the leader) and that both
  update; close the leader and check that the other takes over.

### By hand on the real host (byethost)

These checks are manual because the host's proxy and cookie check cannot be reproduced
locally:

- Leave a tab open for more than 6 hours (cookie rotation) and check that actions still work or
  that the "reload" prompt appears, and that uploads resume after reloading.
- Upload a file larger than 10 MB and download it again (segments), and download a folder as ZIP.
- Check *Admin → System*: storage folder private, real-time mode `poll`, maintenance running.
- Watch the hit counter in VistaPanel for a working day with the chosen
  `REALTIME_POLL_SECONDS` (see [DEPLOYMENT.md](DEPLOYMENT.md#52-hits-budget-and-realtime_poll_seconds)).
