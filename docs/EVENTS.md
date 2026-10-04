# FastTransfer real-time events

Every change in FastTransfer (an upload, a rename, a new share, a comment, a notification …)
publishes an **event**. Open browsers receive the events that concern them and update the screen
without reloading: a file you upload on your phone appears in the browser on your PC, a file
someone shares with you appears in *Shared With Me*, and so on.

This document is written from `app/Events/EventBus.php` (format and catalogue), the publishers
across `app/`, `app/Events/RealtimeController.php` (server transports) and
`assets/js/core/realtime.js` (the web client).

---

## 1. How it works

1. **Publish.** A service calls `EventBus::publish(type, data, recipients, options)`. The event is
   stored once in the `events` table and fanned out to an explicit list of **authorised
   recipients** in `event_recipients`. Nobody receives an event about something they cannot see.
2. **Signal.** For every recipient the newest event id is written to a tiny file
   (`storage/runtime/rt/u<userId>.seq`). Waiting and polling requests compare that file with the
   last id they delivered, so they only query the database when something actually changed.
3. **Deliver.** Browsers fetch events after the last id they have seen, over Server-Sent Events,
   long-polling or short polling (section 4).
4. **Recover.** After every (re)connect the client asks for everything after its last id. If that
   part of the history has been pruned, it is told to refresh instead (section 5).

**The admin channel.** Recipient `0` is a pseudo-user: every administrator also receives the
events published to it. It feeds the live admin dashboard (new users, uploads, deletions, shares,
download and sign-in counters). Admin-channel payloads never contain file contents or other
users' share link URLs.

Publishing is best effort: if storing an event fails, the user's action still succeeds (the error
is logged).

---

## 2. Event format

Every transport delivers the same JSON object:

```json
{
  "event_id": 1234,
  "type": "file.created",
  "timestamp": "2026-10-04T14:00:00Z",
  "user_id": 10,
  "actor": {"id": 10, "name": "Kritarth"},
  "file_id": 123,
  "folder_id": 5,
  "share_id": null,
  "origin": "3f1c2a9e-…",
  "data": { }
}
```

| Field | Meaning |
| --- | --- |
| `event_id` | Increasing integer. Events are delivered in ascending order; use it as your cursor and to drop duplicates. |
| `type` | One of the types in section 3. |
| `timestamp` | When it was published (UTC). |
| `user_id`, `actor` | Who caused it (`actor.name` is their display name at that moment). Both `null` for system work: maintenance, background jobs, anonymous visitors of a share link. |
| `file_id`, `folder_id`, `share_id` | The items concerned, when there are any. |
| `origin` | The `X-Client-Id` of the browser or device that caused the change (or `null`). A client can use it to recognise its own changes. |
| `data` | Type-specific payload (section 3). |

In event payloads a **FileSummary** has no `favorite` and no `access` field (both depend on who is
looking). Clients assume owner rights when `file.owner.id` is their own id and otherwise fetch
`GET /api/v1/files/{id}` when they need the rights. The same applies to `folder` objects.
Shapes are described in [API.md](API.md#3-common-shapes).

---

## 3. Event catalogue

"File audience" means the file's owner plus everyone with an active user share on the file, on a
bundle that contains it, or on any folder above it. "Folder audience" is the same for a folder.

### Files

| Type | Published when | Recipients | `data` |
| --- | --- | --- | --- |
| `file.created` | A new file is stored by a resumable or single-request upload. (Uploads that replace an existing file publish `version.created` instead; the import from the old version publishes nothing.) | file audience + admin channel | `{file}` |
| `file.updated` | Something about the file changed; see `changes` below | see below | `{file, changes: [...]}` (+ `favorite` for favourites) |
| `file.renamed` | Renamed | file audience | `{file, old_name}` |
| `file.moved` | Moved to another folder | everyone who could see it before **or** after the move | `{file, from_folder_id, to_folder_id}` |
| `file.deleted` | Moved to the Trash (by a person, with its folder, or by auto-expiry) | the audience **before** trashing + admin channel | `{file_id, folder_id, file}` (`file` includes `trash`) |
| `file.restored` | Restored from the Trash | file audience | `{file}` |
| `file.purged` | Deleted permanently (by hand, emptying the Trash, retention, account deletion) | owner + admin channel | `{file_id}` |

`file.updated` publishers and their `changes` values:

| `changes` | Cause | Recipients |
| --- | --- | --- |
| `["description"]`, `["tags"]`, `["is_permanent", "expires_at"]` (or several of these together) | Details edited, tags changed (also by batch tagging) | file audience |
| `["favorite"]` (+ `data.favorite: true\|false`) | Favourite added or removed | only the user who did it |
| `["download_count"]` | Downloaded by a signed-in user | owner only |
| `["download_count"]` | Downloaded through a share link (`share_id` set, no actor) | file audience |
| `["has_thumbnail"]` | Thumbnail ready (background job) | file audience |
| `["version", "size", "content"]` | New version uploaded or a version restored (follows the `version.*` event) | file audience |
| `["versions"]` | Old versions pruned by the retention rules | file audience |

### Folders

| Type | Published when | Recipients | `data` |
| --- | --- | --- | --- |
| `folder.created` | Folder created | folder audience | `{folder}` |
| `folder.updated` | Renamed | folder audience | `{folder, changes: ["name"], old_name}` |
| `folder.updated` | Moved | audience before and after | `{folder, changes: ["parent_id"], from_parent_id, to_parent_id}` |
| `folder.deleted` | Folder (with all contents) moved to the Trash | audience before trashing + admin channel | `{folder_id, parent_id, folder, file_ids (at most 500), files, folders}` |
| `folder.restored` | Restored with its contents | folder audience | `{folder, files, folders}` |
| `folder.purged` | Deleted permanently | owner + admin channel | `{folder_id, files, folders}` |
| `trash.emptied` | A user's Trash emptied | owner + admin channel | `{purged_files, purged_folders, freed_bytes, complete}` |

### Uploads

| Type | Published when | Recipients | `data` |
| --- | --- | --- | --- |
| `upload.started` | `POST /uploads` | uploader + owner of the target (if different, e.g. a shared folder) | common fields |
| `upload.progress` | A chunk arrived; at most every 2 seconds per upload, plus when the last chunk arrives | same | common fields |
| `upload.completed` | Assembled and stored | same | common fields + `file_id` |
| `upload.failed` | Cancelled (`reason: "aborted"`), expired (`"expired"`, from maintenance or on access), or failed while storing (`reason` = the lower-case error code, e.g. `"quota_exceeded"`, or `"error"`) | same; storing failures also go to the admin channel | common fields + `reason` |

Common fields: `{upload_id, name, size, folder_id, received_bytes, percent}` and `target_file_id`
when the upload is a new version of an existing file. Because every device of the uploader gets
these events, the *Uploads* page shows uploads running on your other devices too.

### Versions

| Type | Published when | Recipients | `data` |
| --- | --- | --- | --- |
| `version.created` | New version uploaded (including text-editor saves and uploads through an editor share link, which have no actor) | file audience | `{file, version, version_info}` |
| `version.restored` | An old version restored (as a new current version) | file audience | `{file, version, version_info, restored_from}` |

`version_info`: `{version, size, sha256, name, created_by, created_at, note, current: true}`.
Each is followed by a `file.updated` with `changes: ["version", "size", "content"]`.

### Sharing and comments

| Type | Published when | Recipients | `data` |
| --- | --- | --- | --- |
| `share.created` | Share link or user share created | managers (share owner + owners of the shared items) **with** the link URL; the recipient of a user share and the admin channel **without** it | `{share, file_id, folder_id}` |
| `share.updated` | Settings changed; an existing user share re-shared with new settings; a re-share adjusted because its parent changed; a link download (counters) | managers with URL; recipient without | `{share, file_id, folder_id}` |
| `share.revoked` | Revoked (with all re-shares made from it) | managers with URL; recipient and admin channel without | `{share, file_id, folder_id}` |
| `share.revoked` | The shared item was deleted permanently, or the owner's account was deleted | share owner and recipient (+ admin channel) | `{share: {id, kind, target_type, status: "revoked"}, file_id, folder_id}` (+ `reason: "deleted"` for deleted items) |
| `share.expired` | Maintenance found the share past its expiry (published once) | managers with URL; recipient without | `{share, file_id, folder_id}` |
| `comment.created` | Comment added (also anonymously on a link page: no actor, `share_id` set) | file audience | `{comment, file_id}` (`comment` has no `can_delete`) |
| `comment.deleted` | Comment removed | file audience | `{comment_id, file_id}` |
| `presence.updated` | Someone started or stopped editing a text file (only when the set of editors changes) | file audience | `{file_id, users: [UserRef]}` |

`share` is a ShareSummary (see [API.md](API.md#sharesummary)).

### Account, notifications, clipboard

| Type | Published when | Recipients | `data` |
| --- | --- | --- | --- |
| `notification.created` | A notification was stored for in-app display | that user | `{notification, unread_count}` |
| `notification.read` | Marked read / all read / deleted | that user | `{ids: [id] \| "all", unread_count}` (+ `deleted: true`) |
| `user.created` | An administrator (or the import) created an account | the new user + admin channel | `{user, changes: ["created"]}` |
| `user.updated` | Profile, role, status, quota, must-change-password, two-factor or password changed | the user; + admin channel except for preference-only and own-password changes | `{user, changes: [...]}` |
| `user.updated` | Notification preferences or push subscriptions changed (lets your other devices refresh Settings) | the user | `{user, changes: ["notification_preferences"]}` or `["push_subscriptions"]` |
| `user.deleted` | Account deleted | the user + admin channel | `{user, changes: ["deleted"]}` |
| `quota.updated` | Storage use or quota changed | the user | `{quota: {quota_bytes, used_bytes, reserved_bytes, available_bytes, percent}}` |
| `session.revoked` | One session or all sessions ended | the user | `{session_id: n \| null (all), reason}` |
| `text.created` | Clipboard text saved | owner | `{text}` |
| `text.updated` | Text edited, "keep" toggled, or its link preview arrived | owner | `{text, changes: ["content" \| "is_permanent" \| "url_meta"]}` |
| `text.deleted` | Deleted, or expired (`reason: "expired"`) | owner | `{id}` (+ `reason`) |

### Notepads

"Everyone" below means every active, non-guest account for a team notepad and the owner for a
private one. Events never carry the notepad's text: open editors fetch it (`GET /notepads/{id}`)
and merge it into what they are typing.

| Type | Published when | Recipients | `data` |
| --- | --- | --- | --- |
| `notepad.created` | Notepad created (or became visible to you: made a team notepad again) | everyone | `{notepad}` (summary without `can_manage`/`present`) |
| `notepad.updated` | Text saved or a revision restored | team: the people who have it open (presence); private: the owner's devices | `{notepad_id, version, size, updated_at, by: {id, name}, client_id}` (+ `restored_from_version`). Ignore it when `client_id` is your editor's own id. |
| `notepad.renamed` | Title or visibility changed | everyone who can still see it | `{notepad, changes: ["title" \| "visibility"], old_title}` |
| `notepad.deleted` | Deleted, or made private (`reason: "private"`) | everyone who could see it | `{notepad_id, title?}` (+ `reason`) |
| `notepad.presence` | Someone opened or left it (only when the set of people changes) | everyone | `{notepad_id, users: [UserRef]}` |

`user` in `user.*` events is a UserRef plus `role` and `status` (`active`, `disabled`,
`suspended` or `deleted`); the preference/push variants carry `id`, `username`, `display_name`
and `status` only. `session.revoked` reasons include `logout`, `user_revoked`,
`user_revoked_all`, `password_changed`, `password_reset`, `admin_force_logout`,
`account_deleted`, `remember_theft` and `revoked`. The web app shows the sign-in screen when
`session_id` is `null` or equals its own session id.

### Administration

| Type | Published when | Recipients | `data` |
| --- | --- | --- | --- |
| `stats.updated` | A counter moved | admin channel only | `{metric, delta}`; metrics: `downloads`, `logins`, `shares_created`, `new_users`, `legacy_import` |
| `settings.updated` | Runtime settings saved | admin channel only | `{keys: [...]}` |

The complete list of types is `EventBus::TYPES`; publishing any other type is a programming error.

---

## 4. Transports

The server tells the web app what it can do in the boot data (`GET /api/v1/bootstrap`,
`config.realtime`):

```json
{"mode": "auto", "can_hold": true, "hold_seconds": 20, "poll_seconds": 4, "last_event_id": 1234}
```

- `mode` comes from `REALTIME_MODE` (`auto`, `sse`, `longpoll`, `poll`).
- `can_hold` is true when PHP can wait without busy-looping (`usleep()` available), the mode is
  not `poll`, and the request does not carry the `__test` cookie of byethost/iFastNet free
  hosting's JavaScript check (`usleep()` exists there, but the host cannot stream or hold
  requests). **On byethost still set `REALTIME_MODE=poll`** (see
  [DEPLOYMENT.md](DEPLOYMENT.md#51-live-updates-on-byethost-set-realtime_modepoll)).
- `last_event_id` is where a freshly loaded page starts.

Every response of these endpoints, including `204` and the event stream, carries `X-FT-Api: 1`.

### 4.1 Server-Sent Events: `GET /api/v1/events/stream?after=N`

Only when `can_hold`; otherwise `503 FEATURE_UNAVAILABLE`. On reconnect the browser's
`Last-Event-ID` header takes precedence over `after`.

1. Before sending anything the server catches up (up to 1,000 events), so an error can still be
   returned as JSON.
2. It releases the session lock and the database connection (byethost allows only 4 MySQL
   connections), then sends a 2 KB comment as padding (to push the stream through proxy buffers)
   and `retry: 3000`.
3. For `REALTIME_HOLD_SECONDS` it checks the signal file once a second and sends new events:

   ```text
   id: 1235
   event: ft
   data: {"event_id":1235,"type":"file.renamed",…}

   ```

4. A heartbeat comment `: hb` every 10 seconds of silence.
5. A reset (section 5): `id: N`, `event: reset`, `data: {"last_id": N}`.
6. At the end `event: bye` with `data: {}`; the client reconnects straight away.

Headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache, no-transform`,
`X-Accel-Buffering: no`. Each open stream occupies one PHP worker, so an account may hold at most
**2** requests (streams and long-polls together) at a time; another one is answered
`429 RATE_LIMITED` with `Retry-After` and `details.reason: "held_connections"`.

### 4.2 Long-poll: `GET /api/v1/events/poll?after=N&wait=20`

Waits up to `min(wait, 25, REALTIME_HOLD_SECONDS)` seconds without a database connection and
returns as soon as there are events (same JSON as `/events`), or `204` when the time is up. Where
the host cannot hold requests, `wait` is treated as `0`. Rate bucket `realtime`; the same limit of
2 held requests per account as the stream (`429` with `Retry-After`).

### 4.3 Short poll (fast path): `GET /api/v1/events/poll?after=N&wait=0`

The hot path on byethost. It is registered without the normal authentication and database rate
limiter so that an unchanged poll is almost free:

1. A file-based guard allows **one short poll per second** per session cookie (or API token, or
   IP); faster polls get `429` with `Retry-After: 1`.
2. With a session cookie, the user id is read from the PHP session without locking it, and the
   signal file is compared with `after`. **Nothing new → `204 No Content`, and no database
   connection is opened at all.**
3. Something new (or a Bearer token, which always takes this route) → full authentication
   (session row, account status) and the events as JSON:

   ```json
   {"success": true, "data": [ {event}, … ],
    "meta": {"last_id": 1240, "reset": false, "has_more": false}}
   ```

   `has_more: true` means more than 200 events are waiting: poll again immediately.

### 4.4 Recovery: `GET /api/v1/events?after=N&limit=200`

Normal authentication, bucket `realtime`, `limit` 1–500. Same JSON as above. The web client calls
it after every connect and reconnect, before resuming the live transport, and repeats it while
`has_more` is true.

---

## 5. Missed events and resets

Events are kept for the admin setting *event retention* (default 7 days, 1–90). Maintenance
prunes older ones and remembers the first id still kept. A request answers with **`reset: true`**
(no events, `last_id` = the newest id for you) when:

- `after` is older than the oldest kept event, or
- `after` is larger than the newest event id in the database (for example the database was
  restored or reinstalled while the browser kept its old cursor).

A client receiving a reset must not try to replay: it continues from `last_id` and refreshes what
is on screen (current listing, counters). The web app emits `sync.reset` on its event bus and the
views reload their data; it never reloads the whole page for this.

---

## 6. The web client (`assets/js/core/realtime.js`)

### One connection per browser

- **Leader election.** Only one tab per browser and user (the *leader*) talks to the server. It
  uses the Web Locks API (`navigator.locks`, lock `ft-realtime-<userId>`); where that is missing,
  a lease in `localStorage` (`ft:leader:<userId>`) refreshed every 3 seconds, taken over by
  another tab after 8 seconds of silence.
- **Relay.** The leader forwards every event (and connection status, resets and "please poll now"
  requests) to the other tabs over `BroadcastChannel('ft-events-<userId>')`, or through
  `localStorage` `storage` events (`ft:relay:<userId>`) in older browsers.
- **De-duplication.** Each tab remembers the last 500 event ids and ignores repeats, so an event
  that arrives both from the server and from another tab is handled once.
- **Cursor.** The last delivered id is saved in `localStorage` (`ft:last-event:<userId>`). On page
  load the client starts from the larger of the saved id and the boot data's `last_event_id`
  (unless the saved id is far ahead, which means the database was reset).

### Choosing a transport

`mode: poll` or `can_hold: false` → short polling. `mode: sse` or `longpoll` → that. In `auto`:
Server-Sent Events, falling back to long-poll if the stream has not opened after 8 seconds
(buffering proxy) or fails before opening (`EventSource` cannot see the status, so the long-poll
finds out what happened, without showing "Reconnecting"); a long-poll answered with `404` or `503`
falls back to short polling. The 8-second fallback is remembered in `localStorage`
(`ft:transport`) so the next page load does not try again.

A held request answered `429` (too many held connections for the account, for example several
devices) is **not** an error: the browser short-polls quietly for 1 minute, then 2, 4, 8 and at
most 10 minutes after repeated refusals (or `Retry-After`, if longer), and then tries the held
transport again.

### Poll cadence

| Situation | Next poll |
| --- | --- |
| Page visible and used (pointer, key or scroll) in the last 2 minutes | `poll_seconds` (`REALTIME_POLL_SECONDS`, default 4 s, at least 2 s) |
| Page visible but idle for more than 2 minutes | the longer of 15 s and 2 × `poll_seconds` |
| Page hidden | the longer of 60 s and 4 × `poll_seconds` |
| Short poll answered `429` | `Retry-After` (1–30 s); never shown as a disconnection |
| Window focused, page becomes visible, network back online, or a local change | about 0.8 s (other tabs ask the leader, which polls within 0.3 s) |
| Error | back-off 1, 2, 4, 8, 16, 30 s (±20 % jitter), then 30 s |
| `401` | stops; the app shows the sign-in screen |
| `403 PASSWORD_CHANGE_REQUIRED` (or another `403`) | 30 s, quietly; the app shows the change-password dialog |

Polls are always at least 1.15 s apart, because the server's short-poll guard allows one a
second.

The leader tab also calls `POST /api/v1/tick` every 60 seconds while the page is visible, which
runs queued jobs and maintenance on hosts without cron (see
[DEPLOYMENT.md](DEPLOYMENT.md#background-maintenance-without-cron)).

### What the rest of the app sees

- Every event is emitted on the client bus under its `type` (for example `file.created`) and as
  `event`.
- `sync.reset` after a reset; `auth:revoked` when `session.revoked` concerns this session.
- The store key `live` holds the connection state: `connecting`, `connected`, `reconnecting`,
  `reconnected` (for 2.5 s, then `connected`) or `disconnected`.
- `realtime.nudge()` asks for a poll soon (used after local changes);
  `realtime.broadcastLocal(evt)` shares a locally produced event with the other tabs.

### byethost's cookie check

When the host's JavaScript cookie check intercepts a request (no `X-FT-Api: 1` header), the API
client re-runs the check in a hidden frame and retries once; if that fails the app offers a
reload. A `204` without the header is treated the same way. See
[DEPLOYMENT.md](DEPLOYMENT.md#5-known-byethost-limits-and-how-fasttransfer-adapts).

---

## 7. Following events from a script

On hosts without byethost's cookie check you can follow events with an API token:

1. Get a starting point: `GET /api/v1/bootstrap` → `data.config.realtime.last_event_id`, or `0`.
2. Loop: `GET /api/v1/events/poll?after=<last>&wait=0` every few seconds (never more than once a
   second). On `200`, handle `data` in order and set `<last>` to `meta.last_id`; if
   `meta.has_more` is true, poll again at once. `204` means nothing new.
3. If `meta.reset` is true, reload your state and continue from `meta.last_id`.
4. After downtime, call `GET /api/v1/events?after=<last>` first.

A curl version is in [API.md](API.md#follow-events-by-polling).
