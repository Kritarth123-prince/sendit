# FastTransfer 2 — Security notes

## 1. Credentials exposed by the pre-upgrade version — rotate now

The original single-file `index.php` stored credentials directly in its source code. Treat every one
of them as compromised, whether or not the file was ever public: it has been copied, edited and
deployed, and anyone who saw the file has them. **Do not copy any of these values into the new
`.env`. Create new ones.**

| What | Where it was (original `index.php`) | Looks live? | What to do |
| --- | --- | --- | --- |
| Slack incoming-webhook URL | config block, `$slackWebhook` (≈ line 97) | Yes (real workspace/channel ids) | In Slack: *Apps → Incoming Webhooks* → remove/regenerate the webhook. Put the **new** URL in `.env` as `SLACK_WEBHOOK`. Also delete `ft_config.json` from the app root (it may hold a saved webhook). |
| OCR.space API key | `$ocrApiKey` (≈ line 110) | Yes | Generate a new key at ocr.space and revoke the old one. Put the new key in `.env` as `OCR_API_KEY`. |
| Web Push VAPID key pair | `$vapidPublicKey`, `$vapidPrivateKey` (≈ lines 115–116) | Yes | Generate a new pair in *Admin → System → Web Push keys → Generate Web Push keys* and paste the two lines it shows into `.env` (see [DEPLOYMENT.md](DEPLOYMENT.md#24-generate-the-keys) for other ways). Old browser push subscriptions are tied to the old key and are not imported; users turn push on again under *Notifications*. |
| Account passwords | comments next to the bcrypt hashes for `admin`, `alice`, `guest` (≈ lines 78–84) | Yes — written in plain text | The installer creates **new** accounts. Imported users get a one-time temporary password and must change it on first sign-in. Never reuse the old passwords anywhere else either. |
| Remember-me tokens | `remember_tokens.json` (app root) | — | Delete the file. It was readable over HTTP on many hosts. |
| Push subscriptions | `push_subs.json` (app root) | — | Delete the file. |
| Legacy encryption key | `uploads/.enc_key` | — | Keep it **only** until *Admin → System → Encryption upgrade* reports nothing remaining, then retire it by **deleting the file `uploads/.enc_key`** from the server (keep an offline copy with your backup of the old `uploads/` folder). Emptying `LEGACY_ENCRYPTION_KEY_FILE` does not retire it: an empty value just means the default path. |

## 2. Where secrets live now

All secrets come from `.env` (see `.env.example`), loaded by `app/Core/Env.php`. Prefer a location one
directory **above** the web root; on hosts that confine PHP to the web root (byethost/iFastNet),
keep it in the app root — the `.htaccess` rewrite rules deny every dot-file. `.env` is listed in
`.gitignore` and must never be committed.

| Variable | Purpose |
| --- | --- |
| `APP_KEY` | Encrypts TOTP secrets and secret settings (AES-256-GCM); keys HMACs. |
| `ENCRYPTION_KEY` (+ `ENCRYPTION_KEY_ID`, `ENCRYPTION_OLD_KEYS`) | Master key that wraps the per-file data keys (envelope encryption). Back it up offline: losing it makes encrypted files unrecoverable. |
| `DATABASE_*` | MySQL / MariaDB credentials. |
| `SLACK_WEBHOOK`, `OCR_API_KEY`, `VAPID_*`, `SMTP_*` | Integrations. |
| `INSTALL_TOKEN`, `MAINTENANCE_TOKEN` | Protect the web installer and the token-based maintenance endpoint. Remove `INSTALL_TOKEN` after installing. |
| `LEGACY_UPLOADS_PATH`, `LEGACY_ENCRYPTION_KEY_FILE` | Where the old version's data and key file are. Not secrets themselves, but the key file is. Empty means `<app folder>/uploads` and `<app folder>/uploads/.enc_key`; a **relative** value is resolved from the app folder (where `index.php` is), whatever PHP's working directory is. |

Keys are never sent to the browser, never logged (`Logger` redacts sensitive keys) and never placed
in API responses or real-time events.

## 3. Security model (summary)

- **Authentication:** PHP session plus one `user_sessions` row per device, validated on every
  request (revocation and account disabling take effect immediately); session id regenerated at
  sign-in; `HttpOnly`, `SameSite=Lax` and (on HTTPS) `Secure` cookies; optional remember-me cookie
  using a selector/validator pair with the validator stored hashed and rotated on every use (reuse of
  an old validator revokes the session); TOTP two-factor authentication with replay protection and
  single-use recovery codes; personal API tokens stored hashed.
- **Sensitive account changes:** setting up two-factor authentication and creating API tokens ask
  for the current password again. Changing the password signs out every other session and revokes
  the account's API tokens. An account marked "must change password" (temporary password from an
  administrator or the importer) is enforced by the server: until the password is changed, API
  requests other than the ones needed to change it or sign out are refused with
  `403 PASSWORD_CHANGE_REQUIRED`, and the web app shows the change-password dialog.
- **Passwords:** `password_hash()` / `password_verify()` (bcrypt/argon via `PASSWORD_DEFAULT`),
  rehash on sign-in, minimum length and common-password checks.
- **Brute force and abuse:** database-backed rate limits for sign-in (per IP and per username),
  2FA, password reset, share creation, share passwords, downloads, public comments and the API.
- **Authorisation:** every file/folder operation goes through `FT\Files\FileAccess`
  (owner / admin / share level and flags); ids from the browser are never trusted; resources the
  user cannot see return 404.
- **CSRF:** token required (`X-CSRF-Token`) on every state-changing request authenticated by
  cookie, plus an `Origin` check. Bearer-token API calls are exempt.
- **XSS:** server templates escape with `htmlspecialchars`; the web client builds DOM with
  `textContent` (no untrusted `innerHTML`); strict Content-Security-Policy with per-request nonces;
  no inline event handlers. Third-party scripts are allowed only from the exact, version-pinned
  cdnjs folders the app uses (pdf.js, highlight.js, qrcode-generator, Chart.js), never from the whole
  CDN, and each is loaded with Subresource Integrity. An SVG shown "as image" in the code viewer is
  rendered from a `data:` URL in an `<img>`, so it can neither run scripts nor be opened as a
  same-origin document.
- **Uploaded files are never executed:** stored as opaque, encrypted segments under a storage
  directory denied by the web server; always served through PHP with `X-Content-Type-Options:
  nosniff`, a sandboxing CSP and a safe `Content-Type` (HTML/SVG/scripts are never served as active
  content; text and code are served as `text/plain`).
- **Encryption at rest:** AES-256-GCM in 1 MiB authenticated chunks with a random data key per
  file wrapped by the master key; truncation, reordering and tampering are detected.
- **SSRF:** URL previews, Web Push endpoints and Slack webhooks are restricted (scheme, port,
  allow-listed hosts, private-address blocking with DNS pinning).
- **Path traversal:** physical paths are derived from content hashes and numeric ids, never from
  user input; `Paths::absolute()` rejects `..`, absolute and drive paths.
- **Logging:** structured JSON logs in `storage/logs/` (rotated below 8 MB) with automatic
  redaction; a durable audit log in the database for security, sharing and admin actions.

## 4. Hosting caveats (byethost / iFastNet free plan)

- The host's terms prohibit file-hosting and file-sharing sites on the free plan; the account can be
  suspended. Use a host whose terms allow a private cloud drive for production use.
- The host's JavaScript cookie check blocks non-browser clients, so the REST API is only usable
  from the web app itself on that plan.
- HTTPS: enable the free certificate and set `FORCE_HTTPS=true` so cookies are marked `Secure`
  and HSTS is sent.
