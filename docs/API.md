# FastTransfer REST API v1

Everything the web app does goes through this JSON API, so anything you can do in the browser
you can also script. This reference is written from the route files in `app/routes/` and the
controllers and services they call.

- **Base URL:** `https://<your host>/<app folder>/api/v1`. With `PRETTY_URLS=false` use
  `index.php?r=/api/v1/...` instead (the path goes into the `r` parameter; any other query
  parameters follow with `&`).
- **byethost / iFastNet free hosting:** the host's JavaScript cookie check sits in front of PHP and
  blocks every non-browser client (curl, scripts, other servers, mobile apps). On that plan the API
  is only usable by the FastTransfer web app itself. The examples in [section 8](#8-curl-examples)
  work on normal hosts.
- Real-time events are documented separately in [EVENTS.md](EVENTS.md).

Contents: [1 Authentication](#1-authentication) · [2 Conventions](#2-conventions) ·
[3 Shapes](#3-common-shapes) · [4 Error codes](#4-error-codes) · [5 Endpoints](#5-endpoints) ·
[6 Public link pages](#6-public-link-pages) · [7 Other routes](#7-other-non-api-routes) ·
[8 curl examples](#8-curl-examples)

---

## 1. Authentication

Unless stated otherwise every `/api/v1` endpoint needs a signed-in user. There are two ways to
authenticate.

### 1.1 Browser session (the web app)

`POST /auth/login` creates a PHP session (cookie `ft_sess`, `HttpOnly`, `SameSite=Lax`, `Secure`
on HTTPS) and, with `remember: true`, a remember-me cookie (`ft_remember`). The session is checked
against the database on every request, so signing out elsewhere, revoking a session or disabling
the account takes effect immediately.

Requests authenticated by cookie that change something (`POST`, `PUT`, `PATCH`, `DELETE`) must send
the CSRF token:

```http
X-CSRF-Token: <csrf_token from the login response, GET /auth/csrf or the boot data>
```

(HTML forms may send it as a `_csrf` or `csrf` body field instead; never in the query string.)
A wrong or missing token gives `419 CSRF_TOKEN_INVALID`. In addition, a browser request whose
`Origin` (or `Referer`) is another host, or whose `Sec-Fetch-Site` is `cross-site`/`same-site`, is
refused. Requests without those headers (scripts) are not affected by the origin check.

### 1.2 Personal API tokens (Bearer)

```http
Authorization: Bearer ft_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```

- Format: `ft_` followed by 40 letters and digits. Only a SHA-256 hash is stored; the token is
  shown **once**.
- No CSRF token is needed with a Bearer token, and no cookies are set.
- **Scopes:** `*` (everything the account may do) or `read`. A `read` token may only make `GET`
  (and `HEAD`) requests; anything else gives `403 FORBIDDEN`, checked centrally for every endpoint.
- **Getting a token:**
  - `POST /auth/login` with `"issue_token": true` (optional `token_name`): returns a full-access
    (`*`) token valid for **90 days** instead of a session.
  - `POST /security/tokens` from a signed-in **browser** session with your **current password**
    (name, scope, expiry from 1 to 3,650 days or never). At most 50 active tokens per user.
- Changing or resetting the account's password, *Sign out all other devices* and an
  administrator's forced sign-out **revoke all of the account's tokens**.
- An account that must change its password gets no token from `issue_token` until it has.
- Guests cannot create tokens (they lack the `api.tokens` permission).
- `POST /auth/logout` with a Bearer token revokes that token.
- An invalid, expired or revoked token gives `401 TOKEN_INVALID`. Bearer attempts are
  rate-limited per IP (bucket `token_auth`, 600 a minute).
- Some security-sensitive actions refuse tokens and need a browser session (`403 FORBIDDEN`):
  setting up, enabling or disabling two-factor authentication, new recovery codes, and creating
  API tokens.

### 1.3 Two-factor sign-in

If the account has two-factor authentication on, `POST /auth/login` either:

- accepts the code in the same request (`totp_code` or `code`, or `recovery_code`), which is the
  easiest for scripts, or
- answers `200` with `{"two_factor_required": true, "challenge": "...", "methods": ["totp","recovery"], "expires_in": 300}`.
  Then call `POST /auth/2fa` with the challenge and a code **using the same session cookie**
  (the challenge is kept in the PHP session). After 5 wrong codes, or after 5 minutes, the
  challenge is void (`401 TWO_FACTOR_REQUIRED` with `details.restart = true`).

---

## 2. Conventions

### Requests

- JSON bodies need `Content-Type: application/json` and may be at most 2 MB. Form-encoded bodies
  are accepted where noted. Upload chunks are raw bytes (`application/octet-stream`).
- **Method override:** a `POST` with `X-HTTP-Method-Override: PUT|PATCH|DELETE` (or a `_method`
  form field) is treated as that method on every endpoint. The web app does this when
  `METHOD_OVERRIDE=true`, because some hosts block PUT/PATCH/DELETE.
- `X-Client-Id` (8–64 letters, digits or `-`) identifies the browser or device. It is stored as the
  `origin` of events you cause, used for "this device" in the Security Centre and for editor
  presence. Optional for scripts.
- Ids in paths are positive integers, except upload ids (32 hex characters) and share tokens.
- A stray `?i=1`, `?i=2` or `?i=3` (added by byethost's cookie check) is ignored.

### Responses

Success:

```json
{"success": true, "data": { … }, "meta": { … }}
```

`meta` is present only when there is something in it. Errors:

```json
{"success": false,
 "error": {"code": "VALIDATION_FAILED",
           "message": "Please check the highlighted fields.",
           "details": {"fields": {"name": "Enter a folder name."}}}}
```

`message` is always safe to show to users (British English). `details.fields` maps input fields
to messages for `422` errors.

- Every JSON response carries `X-FT-Api: 1` and `Cache-Control: no-store`. A response **without**
  `X-FT-Api: 1` did not come from FastTransfer (for example byethost's cookie-check page, which
  is HTML with status 200): do not parse it; retry after re-running the check or reloading.
- `204 No Content` has no body.
- Times are UTC in ISO-8601 with `Z` (`2026-10-04T14:31:00Z`). Sizes are bytes.
- `429` responses carry `Retry-After` (seconds); the same value is in `details.retry_after`.

Status codes used: 200, 201, 202, 204, 206 (ranges), 301/302/303/307 (pages only), 304, 400,
401, 403, 404, 405, 409, 410, 413, 415, 416, 419, 422, 429, 500, 503.

### Pagination

List endpoints take `page` (from 1) and `per_page` (default 50, maximum 200 unless stated) and
return:

```json
"meta": {"page": 1, "per_page": 50, "total": 123, "total_pages": 3, "has_more": true}
```

plus endpoint-specific extras. Sorting, where offered: `sort` and `order` (`asc` or `desc`).

### Rate limits

Fixed windows, per signed-in user (`u<id>`) or per IP when signed out:

| Bucket | Limit | Used by |
| --- | --- | --- |
| `api` | 300 per minute | every `/api/v1` route unless another bucket is named |
| `login` | 2 × *Failed sign-ins allowed* per *sign-in window* per IP (default 10 per 15 min) | sign-in |
| `login_user` | *Failed sign-ins allowed* per *sign-in window* per user name (default 5 per 15 min) | sign-in; only failures count |
| `two_factor` | 10 per 15 min per IP and per account | 2FA codes |
| `password` | 5 per hour | password checks, password reset requests, e-mail changes |
| `share_create` | 30 per 10 min | creating shares; also manual OCR requests and the Slack test (own subjects) |
| `download` | 120 per minute | downloads, ZIPs, version downloads, link-page content |
| `share_password` | 10 per 15 min per IP + share | link passwords; wrong maintenance tokens per IP |
| `upload_chunk` | 900 per minute | upload chunks |
| `realtime` | 240 per minute | `/events`, `/events/stream`, long-poll, editor presence |
| `tick` | 4 per minute | `/tick` |
| `public` | 120 per minute per IP | link pages, legacy URLs, `/maintenance` |
| `public_comment` | 10 per 10 min per IP | comments on link pages |
| `token_auth` | 600 per minute per IP | Bearer-token authentication |
| (link previews) | 30 per minute per user | `/url-meta` |
| (short poll) | 1 per second per session, token or IP | `/events/poll?wait=0` (file-based, no database) |

The sign-in values are admin settings (*Admin → System → Security*).

### Roles and permissions

| Permission | admin | user | guest |
| --- | :---: | :---: | :---: |
| `files.view`, `files.comment`, `search.use` | ✓ | ✓ | ✓ |
| `files.upload`, `files.edit`, `files.delete`, `files.share`, `texts.manage`, `api.tokens` | ✓ | ✓ | – |
| `admin.access`, `admin.users`, `admin.storage`, `admin.shares`, `admin.activity`, `admin.system` | ✓ | – | – |

On top of permissions, every file and folder operation is checked against the item itself (owner,
administrator, or a share and its level). Items you have no access to answer `404`, never `403`,
so their existence is not revealed. Administrators can reach other users' content; such access is
recorded in the audit log.

---

## 3. Common shapes

### User (me)

`GET /user`, the login response and the boot data:

```json
{"id": 1, "username": "admin", "display_name": "Admin", "email": null,
 "role": "admin", "status": "active",
 "quota": {"quota_bytes": null, "used_bytes": 1234, "reserved_bytes": 0, "available_bytes": null, "percent": 0},
 "two_factor_enabled": false, "must_change_password": false,
 "password_changed_at": "2026-10-04T09:00:00Z", "created_at": "…Z", "last_login_at": "…Z",
 "preferences": {"theme": "dark", "view": "grid", "sort": "created_at", "order": "desc"},
 "permissions": ["files.view", "files.upload", "…"],
 "session_id": 17}
```

`quota_bytes: null` means unlimited. `reserved_bytes` is space held by uploads in progress.
`session_id` is null for token requests.

### UserRef

```json
{"id": 2, "username": "alice", "display_name": "Alice"}
```

### FileSummary

```json
{"id": 123, "type": "file", "name": "report.pdf", "ext": "pdf", "mime": "application/pdf", "kind": "pdf",
 "size": 12345, "folder_id": 5, "owner": {UserRef},
 "created_at": "…Z", "updated_at": "…Z", "version": 2, "favorite": false, "tags": ["work"],
 "is_permanent": true, "expires_at": null, "download_count": 4, "comment_count": 1,
 "is_shared": true, "has_thumbnail": true, "encrypted": true, "is_bundle": false,
 "description": null, "access": {Capabilities}, "trash": null}
```

- `kind` is one of `image video audio pdf document spreadsheet presentation code text archive other`.
- `is_permanent: false` files have an `expires_at` (auto-expiry; they then move to the Trash).
- `folder_id` is `null` for a recipient when the folder above the shared item is not visible to them.
- In real-time events `favorite` and `access` are left out (they depend on the viewer).

**Capabilities** (`access`):

```json
{"role": "owner|admin|editor|commenter|downloader|viewer",
 "preview": true, "download": true, "comment": true, "edit": true, "share": true,
 "delete": true, "move": true, "versions": true, "activity": true, "manage": true}
```

**Trash info** (`trash`, only for items in the Trash):

```json
{"deleted_at": "…Z", "deleted_by": {UserRef}|null, "original_folder_id": 5|null,
 "original_path": "/Work/Reports", "reason": "user|folder|expired", "purge_at": "…Z"|null, "days_left": 29|null}
```

Trashed folders also have `contents: {files, folders, bytes}`.

### FolderSummary

```json
{"id": 5, "type": "folder", "name": "Work", "parent_id": null, "owner": {UserRef}, "color": null,
 "created_at": "…Z", "updated_at": "…Z", "is_shared": false, "access": {FolderCaps}, "trash": null}
```

Folder capabilities: `role`, `view`, `upload`, `edit`, `share`, `delete`, `move`, `manage`,
`download`, `comment`.

### ShareSummary

```json
{"id": 9, "kind": "link|user", "target_type": "file|folder|bundle",
 "file_id": 123, "folder_id": null, "file_ids": [123], "title": "report.pdf",
 "url": "https://host/s/AbC123…", "recipient": {UserRef}|null, "owner": {UserRef},
 "permission": "viewer|downloader|commenter|editor",
 "allow_preview": true, "allow_download": true, "allow_comments": false, "allow_edit": false,
 "allow_reshare": false, "has_password": true, "expires_at": null, "max_downloads": null,
 "download_count": 0, "access_count": 3, "status": "active|expired|revoked|exhausted",
 "created_at": "…Z", "updated_at": "…Z", "last_accessed_at": "…Z", "message": null,
 "parent_share_id": null}
```

`url` is filled only for link shares and only for the share owner, the item's owner and
administrators. `exhausted` means the download limit is reached (the page still opens, downloads
do not).

### Notification

```json
{"id": 1, "category": "share", "type": "share.received", "title": "Alice shared “report.pdf” with you",
 "body": "", "data": {"file_id": 123, "share_id": 9, "link": "#/shared"},
 "actor": {UserRef}|null, "read": false, "created_at": "…Z"}
```

Categories: `share`, `download`, `comment`, `version`, `share_expired`, `login`, `security`,
`quota`, `upload`.

### Upload session

```json
{"id": "9f2c…(32 hex)", "name": "video.mp4", "size": 52428800, "status": "active",
 "chunk_size": 8388608, "total_chunks": 7, "received": [0, 1, 2], "received_bytes": 25165824,
 "percent": 48, "folder_id": 5, "file_id": null, "result_file_id": null, "expires_at": "…Z"}
```

`status`: `active`, `assembling`, `completed`, `failed`, `aborted`, `expired`. `file_id` is the
target file when uploading a new version. `GET /uploads` and `GET /uploads/{id}` add `error`,
`created_at` and `updated_at`.

---

## 4. Error codes

| Code | HTTP | Meaning |
| --- | --- | --- |
| `BAD_REQUEST` | 400 (415 for an unpreviewable file) | The request is malformed. |
| `INVALID_JSON` | 400 | The JSON body could not be parsed. |
| `VALIDATION_FAILED` | 422 | See `details.fields`. |
| `UNAUTHENTICATED` | 401 | Not signed in (or the session ended). |
| `TOKEN_INVALID` | 401 / 400 | API token invalid, expired or revoked (401); password-reset token invalid (400). |
| `INVALID_CREDENTIALS` | 401 / 422 | Wrong user name or password (422 when re-entering your own password). |
| `TWO_FACTOR_REQUIRED` | 401 | The 2FA challenge expired or failed too often; sign in again. |
| `TWO_FACTOR_INVALID` | 401 / 422 | Wrong authenticator or recovery code. |
| `ACCOUNT_DISABLED`, `ACCOUNT_SUSPENDED` | 403 | The account is not active. |
| `ACCOUNT_LOCKED` | 403 | Too many failed sign-ins; `details.retry_after`. |
| `PASSWORD_CHANGE_REQUIRED` | 403 | The account has a temporary password and must change it first (`POST /user/password`). Until then only reading your profile and boot data, the CSRF token, the event endpoints, changing the password and signing out work. The web app shows its change-password dialog. |
| `PASSWORD_TOO_WEAK` | 422 | The new password breaks the policy (10+ characters, not common, not trivial). |
| `FORBIDDEN` | 403 | Signed in but not allowed (permission, role, guest, read-only token, wrong maintenance token). |
| `CSRF_TOKEN_INVALID` | 419 | Missing or wrong CSRF token, or a cross-site request. |
| `NOT_FOUND` | 404 | Unknown route or resource. |
| `FILE_NOT_FOUND`, `FOLDER_NOT_FOUND`, `SHARE_NOT_FOUND`, `USER_NOT_FOUND`, `UPLOAD_NOT_FOUND`, `COMMENT_NOT_FOUND`, `NOTIFICATION_NOT_FOUND` | 404 | Not found, or not visible to you. |
| `METHOD_NOT_ALLOWED` | 405 | The path exists with another method. |
| `CONFLICT` | 409 | The action does not fit the current state (for example the upload is already being completed). |
| `NAME_CONFLICT` | 409 | An item with that name already exists there; `details.name`. |
| `VERSION_CONFLICT` | 409 | Someone saved a newer version; `details.current_version`, `details.base_version`. |
| `FOLDER_CYCLE` | 409 | A folder cannot move into itself or its own sub-folder. |
| `NOT_IN_TRASH` | 409 | Permanent delete of an item that is not in the Trash. |
| `ALREADY_IN_TRASH` | 409 | |
| `UPLOAD_INCOMPLETE` | 409 | Chunks missing; `details.missing` (up to 100 indexes) and `details.missing_count`. |
| `UPLOAD_EXPIRED` | 409 | The upload session expired; start again. |
| `QUOTA_EXCEEDED` | 413 | Not enough storage; `details.needed_bytes`, `details.available_bytes`. |
| `PAYLOAD_TOO_LARGE` | 413 | File or body too large; `details.max_upload_bytes` where relevant. |
| `BLOCKED_FILE_TYPE` | 415 | The extension is blocked by the administrator; `details.extension`. |
| `CHUNK_INVALID` | 400 / 415 | Wrong chunk index or length, bad checksum, or a multipart body. |
| `SHARE_PASSWORD_REQUIRED` | 401 | Unlock the link page first. |
| `SHARE_EXPIRED`, `SHARE_REVOKED` | 410 | The link no longer works. |
| `FILE_UNAVAILABLE` | 410 | The stored data is missing or damaged (for example deleted by the host). |
| `RATE_LIMITED` | 429 | Wait `Retry-After` seconds. For held real-time connections `details.reason` is `held_connections` (see `/events/stream`). |
| `FEATURE_UNAVAILABLE` | 503 (403 for HTTP maintenance) | Not configured or not possible on this server (SSE on a host that cannot hold connections, push without VAPID keys, OCR without a key, password reset without e-mail …). |
| `NOT_INSTALLED` | 503 | The app is not installed or needs a database update. |
| `SERVER_ERROR` | 500 | Unexpected error (details are in the server log). |

The web client also uses `HOST_CHALLENGE` (never sent by the server) for a response that lacked
`X-FT-Api: 1`.

---

## 5. Endpoints

Paths are relative to `/api/v1`. "Auth" is the default (any signed-in user) unless stated.
Rate bucket `api` unless stated.

### 5.1 Sign-in

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| POST | `/auth/login` | none | `{username, password, remember?, totp_code?\|code?, recovery_code?, issue_token?, token_name?}` |
| POST | `/auth/2fa` | none | `{challenge, code?\|totp_code?, recovery_code?, remember?}` |
| POST | `/auth/logout` | optional | → `204`. Revokes the current session and remember-me cookie, or the Bearer token used. |
| GET | `/auth/csrf` | optional | → `{csrf_token}` |
| POST | `/auth/password/forgot` | none | `{email}` → `202 {accepted: true, message}` whether or not the address exists. `503 FEATURE_UNAVAILABLE` when `MAIL_DRIVER=none`. |
| POST | `/auth/password/reset` | none | `{token, password}` → `{reset: true, message}`. Reset links last 1 hour. |

`/auth/login`:

- `username` may also be the account's e-mail address.
- Response (session): `{user: User(me), csrf_token}`.
- Response (`issue_token: true`): `{user, csrf_token: null, token: "ft_…", token_info: {id, name, token_prefix, scopes, last_used_at, last_used_ip, expires_at, created_at, revoked_at, status}}`.
- Response (2FA needed): see [1.3](#13-two-factor-sign-in).
- Errors: `422`, `401 INVALID_CREDENTIALS`, `403 ACCOUNT_DISABLED|ACCOUNT_SUSPENDED|ACCOUNT_LOCKED`,
  `401 TWO_FACTOR_INVALID`, `403 FORBIDDEN` (`issue_token` without the `api.tokens` permission), `429`.

These sign-in endpoints have no CSRF token (there is no session yet); browser requests from other
sites are refused by the origin check instead.

### 5.2 Your account

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/user` | → User(me) |
| PATCH | `/user` | `{display_name?, email?, preferences?}`; changing `email` also needs `current_password` when password reset by e-mail is on. → User(me) |
| POST | `/user/password` | `{current_password, new_password}` → `{changed: true, sessions_revoked: n, tokens_revoked: n, other_sessions_revoked: n (same as sessions_revoked, for older clients), user}`. Signs out your other sessions and revokes all your API tokens; clears "must change password". |
| POST | `/user/2fa/setup` | Browser session only. `{current_password}` → `{secret, otpauth_uri, digits: 6, period: 30, algorithm: "SHA1"}`. `409` if 2FA is already on; `422 INVALID_CREDENTIALS` for a wrong password. |
| POST | `/user/2fa/enable` | Browser session only. `{current_password, code}` → `{enabled: true, recovery_codes: […]}` (shown once). |
| POST | `/user/2fa/disable` | Browser session only. `{password, code \| recovery_code}` → `{enabled: false}` |
| POST | `/user/2fa/recovery-codes` | Browser session only. `{password, code \| recovery_code}` → `{recovery_codes: […]}`; old codes stop working. |
| GET | `/users/lookup?q=` | Not for guests. At least 2 characters; → up to 10 UserRef (active users other than you, never e-mail addresses). |

The QR code for `otpauth_uri` is drawn in the browser; the secret never goes to a third party.

### 5.3 Security Centre

All scoped to your own account (another user's ids are simply not found).

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/security/overview` | `{account_status, password: {changed_at, age_days, weak, must_change_password}, two_factor, recovery_codes_remaining, sessions_count, active_links, expiring_links, suspicious_logins_30d, failed_logins_30d, api_tokens, devices, last_login_at, last_login_ip, locked_until}` |
| GET | `/security/sessions` | `[{id, current, ip, device, user_agent, created_at, last_seen_at, expires_at, method, remember, two_factor}]` |
| DELETE | `/security/sessions/{id}` | → `204`. Revoking the current session signs you out. |
| POST | `/security/sessions/revoke-all` | `{include_current?: false, include_tokens?: true}` → `{sessions_revoked, tokens_revoked, revoked (same as sessions_revoked, for older clients), signed_out}`. Also revokes every API token unless `include_tokens` is `false`. |
| GET | `/security/logins` | Paginated sign-in history; `?status=success\|failed\|suspicious`. Items: `{id, success, status, method, failure_reason, suspicious, suspicious_reason, ip, device, user_agent, created_at}` |
| GET | `/security/events` | Paginated security audit entries about you (including administrator actions on your account). |
| GET | `/security/devices` | `[{id, name, user_agent, last_ip, first_seen_at, last_seen_at, push_enabled, active_sessions, current}]` |
| GET | `/security/tokens` | Your active API tokens (`?all=1` includes revoked and expired): `[{id, name, token_prefix, scopes, last_used_at, last_used_ip, expires_at, created_at, revoked_at, status}]` |
| POST | `/security/tokens` | Browser session only, permission `api.tokens`. `{current_password, name, scopes?: "*"\|"read", expires_in_days?: 1–3650 \| null}` → `201 {token: "ft_…", …token fields}` (token shown once). `422 INVALID_CREDENTIALS` for a wrong password. |
| DELETE | `/security/tokens/{id}` | → `204` |

### 5.4 Files

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/files` | List (see below) |
| GET | `/files/{id}` | FileSummary + `versions_count`, `breadcrumbs`, `path`, and `shares` (owner/admin only). Owners and admins also get trashed files. |
| PATCH | `/files/{id}` | `{name?, folder_id?, description?, is_permanent?, tags?: [], favorite?, on_conflict?: "error"\|"rename"}` → FileSummary. `favourite` is accepted as a synonym. Renaming, description, "keep forever" and tags need `edit`; moving needs `move` (owner/admin). `409 NAME_CONFLICT` unless `on_conflict: "rename"`. |
| DELETE | `/files/{id}` | Moves to the Trash → `204`. `?permanent=1` deletes a file that is **already** in the Trash (`409 NOT_IN_TRASH` otherwise). Needs `files.delete`. |
| POST | `/files/{id}/restore` | Restores from the Trash into the original folder (or the root if that is gone; renames on a clash) → FileSummary |
| GET | `/files/{id}/download` | Attachment. Bucket `download`. Counts a download (and notifies the owner) except for resumed ranges and cache revalidations. |
| GET | `/files/{id}/content` | Inline preview with a safe `Content-Type` (text and code always as `text/plain`, HTML/SVG never active). `415 BAD_REQUEST` for types that cannot be previewed. |
| GET | `/files/{id}/thumbnail` | JPEG or WebP, or `404` |
| GET | `/files/{id}/activity` | Paginated timeline: `{id, action, text, actor, actor_label, created_at, meta}`; needs `activity` (owner, admin, editor). |
| POST | `/files/batch` | `{action, ids: [...], folder_id?, tag?, value?}` → `{done: [ids], failed: [{id, code, message}]}` |
| POST | `/files/zip` | `{file_ids: [...], folder_ids: [...], name?}` (JSON or a plain form POST) → streamed `application/zip`. Bucket `download`. |
| GET | `/tags` | Your tags with counts `[{name, count}]`; `?all=1` includes unused ones. |

**`GET /files` query:**

| Parameter | Meaning |
| --- | --- |
| `folder_id` or `root=1` | Folder to list (default: your root). Works for folders shared with you. |
| `view` | `all` (default), `recent` (your files, newest change first) or `favorites` |
| `kind`, `tag`, `q` | Filter by kind, tag, or a name fragment |
| `sort`, `order` | `name`, `size`, `created_at`, `updated_at`, `kind`; defaults from your preferences |
| `page`, `per_page` | Pagination (max 200) |

Response `data` = FileSummary list; `meta` adds `view`, `sort`, `order`, `folder` (FolderSummary
or null), `breadcrumbs: [{id, name}]` and, on page 1 of `view=all`, `folders` (the sub-folders).

**Batch actions:** `trash`, `restore`, `purge` (must be in the Trash), `move` (needs
`folder_id`, `null` = root), `tag` / `untag` (needs `tag`), `favorite` / `unfavorite`,
`permanent` (`value: true|false`). At most 500 ids; each id is authorised on its own; a batch
stops after about 20 seconds and reports the rest as failed with `RATE_LIMITED`.

**Downloads** support `Range` (one range, `206`/`416`), `ETag`/`If-None-Match` (`304`) and send
`X-Content-Type-Options: nosniff` and a sandboxing Content-Security-Policy. **ZIPs** are streamed
(no temporary file), keep folder paths, hold at most 2,000 entries and at most ten times the
maximum upload size; items you cannot download are left out and counted in an `X-FT-Skipped`
header; nothing downloadable → `404`.

### 5.5 Versions

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/files/{id}/versions` | `[{version, size, sha256, name, created_by, created_at, note, current}]` |
| GET | `/files/{id}/versions/{version}/download` | Attachment. Bucket `download`. |
| POST | `/files/{id}/versions/{version}/restore` | Creates a new current version from that one (nothing is lost) → FileSummary |
| POST | `/files/{id}/versions` | Upload a new version: multipart (`file`, optional `name`) in one request → `201` FileSummary, **or** JSON `{name, size, …}` to start a resumable upload for this file → `201` upload session (then chunks and complete, 5.8). |

Old versions are pruned according to the admin settings (count and age; the current version is
never pruned).

### 5.6 Folders

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/folders` | `?parent_id=` or `root=1`, `q`; paginated (default 200, max 500) |
| GET | `/folders/tree` | `[{id, name, parent_id, shared}]`: all your folders plus folders shared with you (`shared: true`) |
| POST | `/folders` | `{name, parent_id?}` → `201` FolderSummary; `409 NAME_CONFLICT` |
| GET | `/folders/{id}` | FolderSummary + `breadcrumbs` |
| PATCH | `/folders/{id}` | `{name?, parent_id?}` → FolderSummary; `409 FOLDER_CYCLE`, `409 NAME_CONFLICT` |
| DELETE | `/folders/{id}` | Folder and everything in it to the Trash → `204` |
| POST | `/folders/{id}/restore` | → FolderSummary + `restored_files`, `restored_folders` |
| GET | `/folders/{id}/zip` | Streamed ZIP of the folder (`?name=` optional). Bucket `download`. |

Files uploaded into someone else's shared folder belong to the folder's owner (their quota) and
record you as the uploader.

### 5.7 Trash

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/trash` | `?kind=file\|folder&q=&page=`; items carry `trash`; `meta` adds `retention_days` and `total_bytes` |
| POST | `/trash/{id}/restore` | `?kind=folder` for folders. → FileSummary, or FolderSummary + `restored_files`, `restored_folders` |
| DELETE | `/trash/{id}` | Permanent delete (`?kind=folder`). → `{purged_files, purged_folders, freed_bytes, complete}` |
| DELETE | `/trash` | Empty your Trash → `{purged_files, purged_folders, freed_bytes, complete}` |
| GET | `/admin/trash` | Admin + `admin.storage`. Everyone's Trash, `?owner_id=&kind=&q=` |

Permanent deletion needs `files.delete` (administrators always may). Items are purged
automatically after the retention period (admin setting, default 30 days; 0 = never).
`complete: false` means a large folder was only partly purged in this request; repeat it.

### 5.8 Uploads (resumable)

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/uploads` | Start: `{name, size, folder_id?, file_id?, mime?, tags?: [], is_permanent?, on_conflict?: "rename"\|"replace"\|"error", last_modified?, description?}` → `201` upload session |
| PUT (or POST) | `/uploads/{id}/chunks/{index}` | Raw chunk body (`Content-Type: application/octet-stream`), optional `X-Chunk-Sha256: <hex>` → `{index, received_chunks, received_bytes, total_chunks}`. Bucket `upload_chunk`. |
| GET | `/uploads/{id}` | Session with the list of `received` chunks (to resume) |
| POST | `/uploads/{id}/complete` | Assemble and store → `201` FileSummary. Idempotent: completing again returns the same file. |
| DELETE | `/uploads/{id}` | Cancel → `204`; frees the reserved space and temporary data |
| GET | `/uploads` | Your uploads on every device; `?status=active` (default) `\|completed\|failed\|aborted\|expired\|assembling\|all`; `meta.total` |
| POST | `/files` | Single-request multipart upload: field `file`, optional `folder_id`, `file_id` (new version), `tags`, `is_permanent`, `on_conflict`, `name`, `description` → `201` FileSummary. **At most 8 MiB**; larger files must use `/uploads`. |

How it works:

1. **Start.** The server checks the name, the size against the maximum upload size
   (admin setting, default 200 MiB), blocked extensions, write access to the folder (or edit
   access to `file_id` for a new version) and the quota, and reserves `size` bytes. The answer
   gives `chunk_size` (at most 8 MiB, and smaller when the server's request limit is lower) and
   `total_chunks`. A zero-byte file has no chunks: go straight to *complete*.
2. **Chunks.** Chunk `i` is bytes `i × chunk_size` up to the next boundary; every chunk except the
   last is exactly `chunk_size` bytes. Send them in any order, at most 2 in parallel is
   recommended. Re-sending a chunk replaces it. A wrong length gives `400 CHUNK_INVALID` with
   `details.expected_bytes`. Multipart bodies are refused (`415`).
3. **Resume.** `GET /uploads/{id}` lists the chunks already received. Sessions expire after the
   admin setting *upload session lifetime* (default 24 hours) → `409 UPLOAD_EXPIRED`.
4. **Complete.** Missing chunks → `409 UPLOAD_INCOMPLETE` with `details.missing`. The quota is
   checked again. `on_conflict`: `rename` (default, "name (1).ext"), `replace` (a new version of the
   same-named file, if you may edit it), `error` (`409 NAME_CONFLICT`, checked at start).

`is_permanent`: `true` keeps the file forever; otherwise it expires after the admin setting
*auto-delete after* (default 72 hours) and then moves to the Trash.

### 5.9 Shares

| Method | Path | Auth | Notes |
| --- | --- | --- | --- |
| GET | `/shares` | | Shares you created; `?status=active\|expired\|revoked\|exhausted\|all&kind=link\|user&file_id=&folder_id=`; paginated |
| POST | `/shares` | not guests; bucket `share_create` | Create (below) → `201 [ShareSummary]` (one per recipient for user shares) |
| GET | `/shares/with-me` | | Shared With Me, active only; `?type=file\|folder`; paginated items `{share, item, shared_at, last_accessed_at, owner, permission, expires_at}` (`share` without `url`; `item` is a FileSummary or FolderSummary) |
| GET | `/shares/{id}` | | ShareSummary (for a recipient this also records "last opened") |
| PATCH | `/shares/{id}` | not guests | `{permission?, password? ("" or null removes it), expires_at?, expires_in?, max_downloads?, allow_*?, title?, message?}` → ShareSummary. `409` for a revoked share. |
| DELETE | `/shares/{id}` | not guests | Revoke now, including re-shares made from it → `204` |
| POST | `/files/{id}/share` | not guests; `share_create` | Same body as `POST /shares`, for this file |
| POST | `/folders/{id}/share` | not guests; `share_create` | Same body, for this folder |
| GET | `/files/{id}/shares` | owner/admin | Shares on this file; `?status=` (default `all`) |
| GET | `/admin/shares` | admin + `admin.shares` | Everyone's shares; `?status=&kind=&owner_id=&recipient_id=&file_id=&folder_id=` |

**Create body:**

| Field | Default | Notes |
| --- | --- | --- |
| `kind` | `link` | `link` or `user` |
| `file_ids` (or `file_id`) / `folder_id` | – | One or more files (several files make a *bundle*, max 200) **or** one folder, not both |
| `recipients` | – | `user` shares: user ids or user names (max 50). An existing active share to the same person for the same item is updated instead of duplicated. |
| `permission` | `downloader` | `viewer`, `downloader`, `commenter`, `editor` |
| `allow_preview`, `allow_download`, `allow_comments`, `allow_edit` | from the level | Set one to `false` to take that right away |
| `allow_reshare` | `false` | `user` shares only; a re-sharer can grant at most their own level |
| `password` | none | `link` shares only, 4–200 characters, stored hashed |
| `expires_at` (ISO date or Unix time) or `expires_in` (seconds, ≥ 60) | never | Within 10 years. A re-share cannot outlive its parent share. |
| `max_downloads` | none | `link` shares only |
| `title`, `message` | – | Up to 255 / 1,000 characters |

Link tokens are 22 letters and digits; links imported from the old version keep their 32-character
tokens. User shares notify the recipient.

### 5.10 Comments

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/files/{id}/comments` | `[{id, file_id, body, author: UserRef\|null, author_name, via_link, created_at, edited_at, can_delete}]` |
| POST | `/files/{id}/comments` | Permission `files.comment` and the `comment` capability. `{body}` → `201` comment. Notifies the owner and other participants. |
| DELETE | `/comments/{id}` | Author, file owner or admin → `204` |

### 5.11 Clipboard texts and link previews

Permission `texts.manage`, not guests. Texts are private to their owner.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/texts` | Paginated `[{id, content, is_url, url_meta, is_permanent, expires_at, created_at, updated_at}]` |
| POST | `/texts` | `{content, is_permanent?}` → `201` text |
| GET | `/texts/{id}` | text |
| PATCH | `/texts/{id}` | `{content?, is_permanent?}` → text |
| DELETE | `/texts/{id}` | → `204` |
| GET | `/url-meta?url=` | Title/description/image of a web page (http/https only; private addresses, odd ports and redirects to them are refused). 30 a minute per user. Needs `curl`. |

Texts not marked permanent expire after the admin setting (default 72 hours) and are deleted.

### 5.12 Text editing and presence

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/files/{id}/text` | `{file_id, name, content, version, size, sha256, encoding: "utf-8", editable}` for text/code files up to 2 MB |
| PUT | `/files/{id}/text` | `{content, base_version}` → FileSummary (a new version). Or a raw `text/plain` body with `base_version` in the query or an `X-Base-Version` header (for files near 2 MB). `409 VERSION_CONFLICT` if someone saved since `base_version`. |
| POST | `/files/{id}/presence` | Heartbeat (about every 10 s; entries expire after 30 s); `{leave?: true}` to leave → `{file_id, users: [UserRef], ttl: 30}`. Bucket `realtime`. |

### 5.12a Notepads

The legacy "Collaborative Notepad" as a feature of its own (web view `#/notepad`). Not for guests
(`403`). **Team** notepads can be opened and edited by every active non-guest account; only their
creator or an administrator may rename, re-scope or delete them. **Private** notepads are their
owner's only — everyone else, administrators included, gets `404 NOTEPAD_NOT_FOUND`. When no team
notepad exists, the first `GET /notepads` creates "Team notepad". Text is UTF-8, at most 1 MiB,
stored deflated and encrypted (AES-256-GCM) when encryption is on.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/notepads` | Team notepads first, then your private ones: `[{id, title, visibility: "team"\|"private", version, size, owner, updated_by, created_at, updated_at, imported, can_manage, present}]` (`owner`/`updated_by` are `{id, name}` or `null`; `present` = people with it open now) |
| POST | `/notepads` | `{title?, visibility?: "team"}` → `201` notepad with `content: ""`. A title is tidied (whitespace) and up to 120 characters; empty → "Untitled notepad". Up to 100 per account. |
| GET | `/notepads/{id}` | Summary + `content` + `present_users: [UserRef]` |
| PATCH | `/notepads/{id}` | `{title?, visibility?}` → summary. Making a team notepad private removes it from everyone else at once. |
| DELETE | `/notepads/{id}` | → `204`; its history goes too |
| PUT | `/notepads/{id}/content` | Save. Raw `text/plain` body with `X-Base-Version` (the version you started from) and optionally `X-Notepad-Client` (your editor's id, echoed in `notepad.updated`) — or JSON `{content, base_version, client_id?}`. → `{id, version, size, updated_at, updated_by, changed}`. Saving the text that is already stored is a no-op (`changed: false`), so retrying a save is safe. If someone saved since `base_version`: `409 VERSION_CONFLICT` with `details: {current_version, base_version, content, updated_at, updated_by}` — merge your edits into `content` and save again with `base_version = current_version`. Over 1 MiB: `422`. Bucket `notepad` (120 a minute). |
| GET | `/notepads/{id}/revisions` | Newest first, up to 50: `[{id, version, size, user, created_at, saved_at, restored_from_version, current}]`. Saves by the same person within 10 minutes share one revision. |
| GET | `/notepads/{id}/revisions/{rid}` | A revision with its `content` |
| POST | `/notepads/{id}/revisions/{rid}/restore` | `{client_id?}` → the notepad (with `content`) at a new version; the text before stays in the history |
| POST | `/notepads/{id}/presence` | Heartbeat `{client_id}` (about every 20 s; entries expire after 30 s) → `{notepad_id, users: [UserRef], version, updated_at, ttl: 30}`. Compare `version` with yours to catch a missed save. Bucket `notepad`. |
| DELETE | `/notepads/{id}/presence` | Leave `{client_id}` → same shape |

### 5.13 Search and OCR

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/search` | Permission `search.use`. Paginated FileSummary list, each with `match: {field, snippet, …}\|null`; `meta.query` echoes the parsed query |
| POST | `/files/{id}/ocr` | Permission `files.edit` and edit access. Queue text recognition now → `{queued: true}`. `503` if OCR is not configured or switched off; images (and PDFs with OCR.space) only. |

`/search` parameters:

| Parameter | Meaning |
| --- | --- |
| `q` | Words to find (up to 6 terms) |
| `in` | Comma list of `name, ext, tags, folder, description, owner, content, ocr` (default all) |
| `kind`, `ext`, `tag` | Comma lists |
| `owner` / `owner_id` | Owner name or id |
| `date_from`, `date_to` | `YYYY-MM-DD` (or ISO date-time); `date_field=created_at\|updated_at` |
| `size_min`, `size_max` | Bytes |
| `folder_id`, `recursive=1` | Limit to a folder (and its sub-folders) |
| `shared` | `1` (anything shared), `with_me`, `by_me` |
| `favorite=1`, `trash=1` | Only favourites / search the Trash |
| `scope` | `mine` (default: your files and what is shared with you) or `all` (administrators only) |
| `sort`, `order` | `relevance` (default), `name`, `size`, `created_at`, `updated_at`, `kind` |

### 5.14 Notifications and Web Push

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/notifications` | `?unread=1&category=&page=` → paginated Notification list; `meta.unread_count` |
| GET | `/notifications/{id}` | Notification |
| POST | `/notifications/{id}/read` | → Notification; `meta.unread_count` |
| POST | `/notifications/read-all` | → `{updated, unread_count}` |
| DELETE | `/notifications/{id}` | → `204` |
| GET | `/notifications/preferences` | `[{category, label, in_app, push, email}]` |
| PUT | `/notifications/preferences` | `{preferences: [{category, in_app?, push?, email?}]}` → the full list |
| GET | `/push/vapid-key` | Auth optional → `{public_key}` (null when push is not set up) |
| POST | `/push/subscribe` | `{endpoint, keys: {p256dh, auth}}` (a browser PushSubscription) → `201 {id, device_id, subscribed: true}`; `503` without VAPID keys; only known push services are accepted |
| DELETE | `/push/subscribe` | `{endpoint}` → `204` |
| POST | `/push/test` | Send yourself a test push → `{queued: n}` |

### 5.15 Real-time events

Full details in [EVENTS.md](EVENTS.md).

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/events?after=&limit=` | Recovery: events after `after` (oldest first), `limit` 1–500 (default 200). `meta: {last_id, reset, has_more}`. Bucket `realtime`. |
| GET | `/events/stream?after=` | Server-Sent Events (or `Last-Event-ID`). `503 FEATURE_UNAVAILABLE` where the host cannot hold requests (`REALTIME_MODE=poll`, or byethost/iFastNet detected by its `__test` cookie). At most 2 held requests (streams and long-polls) per account: more give `429 RATE_LIMITED` with `Retry-After` and `details.reason: "held_connections"`; the web app then short-polls for a while. Bucket `realtime`. |
| GET | `/events/poll?after=&wait=` | `wait=0`: short poll, `204` when nothing changed, `429` with `Retry-After: 1` when polled more than once a second. `wait=1..25`: long-poll (only where the host can hold requests; otherwise treated as 0), subject to the same held-request limit as the stream. Same JSON as `/events`. |

### 5.16 Tick, boot data and maintenance

| Method | Path | Notes |
| --- | --- | --- |
| POST | `/tick` | Bucket `tick` (4 a minute). Runs up to 2.5 s of queued jobs and, when due, a maintenance slice → `{jobs: n, maintenance: {ran, complete}\|null}`. The web app's leader tab calls it about once a minute. |
| GET | `/bootstrap` | Boot data: `{csrf_token, user: User(me), unread_notifications, config: {app_name, version, base, api_base, share_base, pretty_urls, method_override, upload: {chunk_size, max_upload_bytes, max_parallel, blocked_extensions}, realtime: {mode, can_hold, hold_seconds, poll_seconds, last_event_id}, features: {ocr, push, email, encryption}, vapid_public_key, auto_expire_hours, trash_retention_days, settings: {quota_warning_percent}}}` |
| GET | `/maintenance` (not under `/api/v1`) | See [7](#7-other-non-api-routes). |

### 5.17 Admin: users

All need the admin role and the `admin.users` permission.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/admin/users` | `?q=&status=active\|disabled\|suspended\|locked&role=&sort=&order=&page=` → paginated AdminUser list |
| POST | `/admin/users` | `{username, password?, email?, display_name?, role, quota_bytes?, must_change_password?}` → `201 {user, temporary_password?}` (a temporary password is generated when none is given; shown once) |
| GET | `/admin/users/{id}` | AdminUser + `sessions`, `api_tokens` count, `recent_activity` |
| PATCH | `/admin/users/{id}` | `{display_name?, email?, role?, quota_bytes? (null = role default, -1 = unlimited), must_change_password?, status?, reason?}` |
| DELETE | `/admin/users/{id}` | Soft delete: sessions, tokens and shares revoked, data purge queued → `204`. You cannot delete yourself or the last administrator. |
| POST | `/admin/users/{id}/disable` · `/enable` · `/suspend` | `{reason?}` |
| POST | `/admin/users/{id}/reset-password` | `{password?}` → `{temporary_password, must_change_password, sessions_revoked}` |
| POST | `/admin/users/{id}/force-logout` | → `{revoked: n}` |
| POST | `/admin/users/{id}/2fa/disable` | → AdminUser |
| GET | `/admin/users/{id}/activity` | Paginated audit entries by or about the user |

AdminUser: `{id, username, display_name, email, role, status, status_reason, two_factor_enabled, must_change_password, locked, locked_until, failed_login_count, quota_bytes, used_bytes, quota, sessions_active, created_at, updated_at, last_login_at, last_login_ip, last_seen_at, password_changed_at}`
(`quota_bytes`: null = role default, -1 = unlimited).

### 5.18 Admin: dashboard

Admin role plus the permission shown.

| Method | Path | Permission | Notes |
| --- | --- | --- | --- |
| GET | `/admin/stats` | `admin.access` | Counters: users, files, logical/physical storage, capacity, uploads/downloads/shares today, shares by status, Trash and version bytes, failed uploads, de-duplication savings, queued and failed jobs |
| GET | `/admin/stats/charts?days=30` | `admin.access` | Daily series (1–365 days) |
| GET | `/admin/storage` | `admin.storage` | `?sort=used_bytes\|username\|created_at\|quota_bytes&order=&q=&page=` → `{users, totals, capacity}` + pagination meta |
| GET | `/admin/activity` | `admin.activity` | Audit log; `?category=activity\|security\|admin\|system&action=&user_id=&owner_id=&target_type=&target_id=&q=&date_from=&date_to=&page=` |

<a id="admin-system"></a>

### 5.19 Admin: system

Admin role and `admin.system`.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/admin/system` | Diagnostics: PHP, extensions, limits, database, migrations, jobs, encryption, legacy import, pseudo-cron, storage canary |
| GET | `/admin/settings` | All runtime settings (secrets masked) + `meta.schema` (types and ranges) |
| PUT or PATCH | `/admin/settings` | `{key: value, …}` (or `{"settings": {…}}`); unknown keys or bad values → `422`, nothing saved. → settings + `meta.updated` |
| POST | `/admin/maintenance/run` | `{task?: "name" \| ["a", "b"]}` → run result (20 s budget) |
| GET | `/admin/maintenance/logs` | `?task=&status=ok\|partial\|error\|skipped&run_id=&trigger=&page=` |
| POST | `/admin/migrations/run` | Apply database updates (after a backup) → `{applied, pending, schema}`; `409` if one is already running. Note: once new migration files are uploaded, every route except `/install` answers `503 NOT_INSTALLED` until the updates are applied, so after an upgrade use `/install` ([UPGRADE.md](UPGRADE.md#future-upgrades)). |
| POST | `/admin/legacy-import` | `{step?: "run"\|"status", options?: {share_imported_with_all_users, create_legacy_users, user_map: {"oldname": userId}, retry_failed}}`. Each call runs about 15 s; repeat until `done: true`. `404` when there is no old data. |
| GET | `/admin/encryption` | Encryption status: counts by format, pending, failures |
| POST | `/admin/encryption/migrate` | `{retry_failed?}` → one batch (about 15 s) + `status` |
| POST | `/admin/jobs/retry` | `{id?}` → `{retried: n}` (one failed job, or all) |
| POST | `/admin/vapid/generate` | → `{public_key, private_key, env, note}`: a new Web Push key pair, shown once, never stored |
| POST | `/admin/slack/test` | `{webhook?}` (only `https://hooks.slack.com/…`) → `{delivered}` |

Settings keys: `site_name`, `default_quota_bytes`, `guest_quota_bytes`, `max_upload_bytes`,
`blocked_extensions`, `trash_retention_days` (0, 7, 30, 60, 90), `version_retention_count`,
`version_retention_days`, `auto_expire_hours`, `text_auto_expire_hours`, `dedup_scope`
(`user`/`global`), `event_retention_days`, `audit_retention_days`,
`login_history_retention_days`, `notification_retention_days`, `upload_session_ttl_hours`,
`bundle_ttl_hours`, `quota_warning_percent`, `session_idle_minutes`, `remember_days`,
`login_max_attempts`, `login_window_minutes`, `registration_enabled`, `ocr_enabled`,
`slack_events`, `slack_webhook_override` (secret, write-only).

---

## 6. Public link pages

No sign-in; these are HTML pages for people who received a link, plus a few JSON helpers for the
page script. All are rate-limited per IP. Expired or revoked links show a "no longer available"
page (`410`); unknown tokens `404`.

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/s/{token}` | The page (password form first if the link has one). Folder links accept `?folder=<id>`. |
| POST | `/s/{token}/unlock` | Form `{password, _csrf}` (the old field name `share_password` is accepted). 10 wrong passwords per 15 minutes per IP and link. |
| GET | `/s/{token}/download` | `?file=<id>` (optional for single-file links). Counts one download (not for resumed ranges or `HEAD`). |
| GET | `/s/{token}/content/{fileId}` | Inline preview when previews are allowed |
| GET | `/s/{token}/thumbnail/{fileId}` | Thumbnail |
| GET | `/s/{token}/zip` | Whole bundle or folder as one streamed ZIP (counts one download) |
| GET | `/s/{token}/folder/{folderId}` | JSON `{folder, breadcrumbs, folders, files, truncated, …}` for browsing a folder link |
| GET | `/s/{token}/comments?file=` | JSON comments, when comments are allowed |
| POST | `/s/{token}/comments` | `{file_id?, name, body}` (JSON or form, with the page's CSRF token). 10 per 10 minutes per IP. |
| POST | `/s/{token}/upload` | Editor links to a single file: upload a new version in one request (form with the page's CSRF token) |

Old links `/?share=<token>` redirect here (see [UPGRADE.md](UPGRADE.md#old-links-keep-working)).

---

## 7. Other non-API routes

| Method | Path | Notes |
| --- | --- | --- |
| GET | `/` | The web app (signed in) or the sign-in page |
| GET, POST | `/login` | Sign-in page and its no-JavaScript form |
| GET, POST | `/logout` | Sign-out page / form (CSRF-protected) |
| GET, POST | `/install` | Web installer and upgrader (needs `INSTALL_TOKEN`) |
| GET, POST | `/legacy` | Target of old single-file URLs (`/?share=…` etc.); redirects only |
| GET | `/manifest.webmanifest` | Web app manifest (no session needed) |
| GET | `/service-worker.js` | The generated service worker (`Service-Worker-Allowed` = the app's base path) |
| GET | `/offline` | Offline fallback page |
| GET | `/maintenance?token=&task=` | Token-protected maintenance (same as `maintenance.php`); token also accepted as `X-Maintenance-Token` header. `403` without a valid `MAINTENANCE_TOKEN` (16+ characters), `503 NOT_INSTALLED`, `422` unknown task. Result: `{success: true, data: {run_id, trigger, skipped, complete, started_at, duration_ms, tasks: {name: {status, items, duration_ms, message}}}}` |

---

## 8. curl examples

Shell syntax is bash (Git Bash or WSL on Windows; in PowerShell call `curl.exe` and adapt the
quoting). `jq` is used to pick values out of JSON. Remember that byethost free hosting blocks
these clients.

```bash
BASE=https://drive.example.com/api/v1
```

### Sign in and get a token

```bash
TOKEN=$(curl -s "$BASE/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct horse battery","issue_token":true,"token_name":"Backup script"}' \
  | jq -r '.data.token')
AUTH="Authorization: Bearer $TOKEN"
```

With two-factor authentication on, add `"totp_code":"123456"` to the same request.

To use a cookie session instead (needs the CSRF token on changes):

```bash
CSRF=$(curl -s -c jar.txt "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"correct horse battery"}' | jq -r '.data.csrf_token')
curl -s -b jar.txt -H "X-CSRF-Token: $CSRF" -X POST "$BASE/folders" \
  -H 'Content-Type: application/json' -d '{"name":"Reports"}'
```

### List files

```bash
curl -s -H "$AUTH" "$BASE/files?root=1&sort=name&order=asc&per_page=100" | jq '.data[] | {id, name, size}'
curl -s -H "$AUTH" "$BASE/files?folder_id=5" | jq '.meta.folders[].name'
```

### Resumable upload: start, chunks, complete

```bash
FILE=holiday.mp4
SIZE=$(stat -c %s "$FILE")

# 1. start
START=$(curl -s -H "$AUTH" -H 'Content-Type: application/json' "$BASE/uploads" \
  -d "{\"name\":\"$FILE\",\"size\":$SIZE,\"folder_id\":5,\"is_permanent\":true}")
ID=$(echo "$START" | jq -r '.data.id')
CHUNK=$(echo "$START" | jq -r '.data.chunk_size')
TOTAL=$(echo "$START" | jq -r '.data.total_chunks')

# 2. chunks (raw bytes; every chunk but the last is exactly chunk_size)
for ((i=0; i<TOTAL; i++)); do
  dd if="$FILE" bs="$CHUNK" skip="$i" count=1 status=none > part.bin
  curl -s -H "$AUTH" -X PUT -H 'Content-Type: application/octet-stream' \
    -H "X-Chunk-Sha256: $(sha256sum part.bin | cut -d' ' -f1)" \
    --data-binary @part.bin "$BASE/uploads/$ID/chunks/$i" | jq -c '.data'
done

# Resuming later: which chunks has the server got?
curl -s -H "$AUTH" "$BASE/uploads/$ID" | jq -c '.data.received'

# 3. complete
curl -s -H "$AUTH" -X POST "$BASE/uploads/$ID/complete" | jq '.data | {id, name, size, version}'
```

Small files (up to 8 MiB) in one request:

```bash
curl -s -H "$AUTH" -F "file=@notes.txt" -F "folder_id=5" "$BASE/files" | jq '.data.id'
```

### Create a share link

```bash
curl -s -H "$AUTH" -H 'Content-Type: application/json' "$BASE/shares" \
  -d '{"kind":"link","file_ids":[123],"permission":"downloader","password":"open sesame","expires_in":604800,"max_downloads":10}' \
  | jq -r '.data[0].url'
```

Share with people instead:

```bash
curl -s -H "$AUTH" -H 'Content-Type: application/json' "$BASE/folders/5/share" \
  -d '{"kind":"user","recipients":["bob"],"permission":"editor","message":"Quarterly figures"}'
```

### Follow events by polling

```bash
AFTER=$(curl -s -H "$AUTH" "$BASE/bootstrap" | jq '.data.config.realtime.last_event_id')
while true; do
  RESP=$(curl -s -w '\n%{http_code}' -H "$AUTH" "$BASE/events/poll?after=$AFTER&wait=0")
  CODE=$(echo "$RESP" | tail -n1); BODY=$(echo "$RESP" | sed '$d')
  if [ "$CODE" = "200" ]; then
    echo "$BODY" | jq -c '.data[] | {event_id, type}'
    AFTER=$(echo "$BODY" | jq '.meta.last_id')
  fi
  sleep 10   # 204 = nothing new; do not poll faster than once a second
done
```

After a long break, call `GET /events?after=$AFTER` first; if `meta.reset` is `true`, the history
you missed is gone: reload your state and continue from `meta.last_id`.
