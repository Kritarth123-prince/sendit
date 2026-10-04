-- 011_notepads (Notepads): shared team notepads and private notepads with history and presence.
-- The first-class successor of the legacy "Collaborative Notepad" (uploads/collab.json).
-- Compatible with MySQL 5.7+ and MariaDB 10.3+. Applied exactly once by the Migrator.
--
-- Text is stored encoded (app/Notepads/NotepadService.php): compressed with deflate when that
-- helps, then encrypted with AES-256-GCM under ENCRYPTION_KEY when encryption is enabled
-- (FT\Storage\Crypto::encryptString, key id embedded so key rotation keeps old rows readable).
-- content_codec records which steps were applied: plain | deflate | aes | aes+deflate.

CREATE TABLE IF NOT EXISTS notepads (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(120) NOT NULL,
  visibility ENUM('team','private') NOT NULL DEFAULT 'team',
  owner_id INT UNSIGNED NULL COMMENT 'creator (manages a team notepad, sole reader of a private one); NULL for the automatic and imported team notepads',
  content MEDIUMBLOB NOT NULL COMMENT 'encoded text, see content_codec',
  content_codec VARCHAR(16) NOT NULL DEFAULT 'plain',
  content_size INT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'plain text bytes (max 1 MiB)',
  version INT UNSIGNED NOT NULL DEFAULT 1,
  updated_by INT UNSIGNED NULL,
  legacy_key VARCHAR(191) NULL COMMENT 'collab.json document id of an imported notepad',
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  UNIQUE KEY uq_notepads_legacy (legacy_key),
  KEY idx_notepads_visibility (visibility, owner_id),
  KEY idx_notepads_owner (owner_id),
  CONSTRAINT fk_notepads_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE SET NULL,
  CONSTRAINT fk_notepads_updated_by FOREIGN KEY (updated_by) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- History snapshots. Saves are coalesced: a save updates the newest revision in place while it is
-- by the same person and less than 10 minutes old (and not a restore); otherwise a new revision
-- starts. The newest 50 revisions per notepad are kept.
CREATE TABLE IF NOT EXISTS notepad_revisions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  notepad_id INT UNSIGNED NOT NULL,
  version INT UNSIGNED NOT NULL COMMENT 'notepad version this snapshot holds (the last save it covers)',
  content MEDIUMBLOB NOT NULL,
  content_codec VARCHAR(16) NOT NULL DEFAULT 'plain',
  content_size INT UNSIGNED NOT NULL DEFAULT 0,
  user_id INT UNSIGNED NULL,
  restored_from_version INT UNSIGNED NULL COMMENT 'set when this snapshot was made by restoring an older one',
  created_at DATETIME NOT NULL COMMENT 'first save covered by this snapshot',
  updated_at DATETIME NOT NULL COMMENT 'last save covered by this snapshot',
  KEY idx_notepad_revisions_notepad (notepad_id, id),
  CONSTRAINT fk_notepad_revisions_notepad FOREIGN KEY (notepad_id) REFERENCES notepads (id) ON DELETE CASCADE,
  CONSTRAINT fk_notepad_revisions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Who has a notepad open (one row per browser tab; heartbeat about every 20 s, 30 s TTL).
CREATE TABLE IF NOT EXISTS notepad_presence (
  notepad_id INT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NOT NULL,
  client_id VARCHAR(64) NOT NULL DEFAULT '',
  seen_at DATETIME NOT NULL,
  PRIMARY KEY (notepad_id, user_id, client_id),
  KEY idx_notepad_presence_seen (seen_at),
  CONSTRAINT fk_notepad_presence_notepad FOREIGN KEY (notepad_id) REFERENCES notepads (id) ON DELETE CASCADE,
  CONSTRAINT fk_notepad_presence_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
