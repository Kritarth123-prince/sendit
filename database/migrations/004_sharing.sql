-- 004_sharing: link shares + user shares with granular permissions, multi-file bundles, comments.
--
-- Permission levels (cumulative):  viewer < downloader < commenter < editor
--   viewer     preview + metadata
--   downloader + download
--   commenter  + comment
--   editor     + rename, modify, upload new version
-- The allow_* flags can further RESTRICT what the level grants (never widen it), except
-- allow_reshare which is an explicit extra right.

CREATE TABLE IF NOT EXISTS shares (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  owner_id INT UNSIGNED NOT NULL COMMENT 'user who created the share',
  kind VARCHAR(8) NOT NULL COMMENT 'link | user',
  target_type VARCHAR(8) NOT NULL COMMENT 'file | folder | bundle',
  file_id BIGINT UNSIGNED NULL,
  folder_id INT UNSIGNED NULL,
  token VARCHAR(64) NULL COMMENT 'link shares: URL token (legacy 32-hex tokens are preserved)',
  recipient_id INT UNSIGNED NULL COMMENT 'user shares: the recipient',
  permission VARCHAR(16) NOT NULL DEFAULT 'downloader' COMMENT 'viewer|downloader|commenter|editor',
  allow_preview TINYINT(1) NOT NULL DEFAULT 1,
  allow_download TINYINT(1) NOT NULL DEFAULT 1,
  allow_comments TINYINT(1) NOT NULL DEFAULT 0,
  allow_edit TINYINT(1) NOT NULL DEFAULT 0,
  allow_reshare TINYINT(1) NOT NULL DEFAULT 0,
  password_hash VARCHAR(255) NULL,
  expires_at DATETIME NULL,
  max_downloads INT UNSIGNED NULL COMMENT 'NULL = unlimited',
  download_count INT UNSIGNED NOT NULL DEFAULT 0,
  access_count INT UNSIGNED NOT NULL DEFAULT 0,
  title VARCHAR(255) NULL COMMENT 'bundle name or note',
  message VARCHAR(1000) NULL COMMENT 'optional note shown to the recipient',
  parent_share_id BIGINT UNSIGNED NULL COMMENT 're-share chain',
  legacy TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  last_accessed_at DATETIME NULL,
  revoked_at DATETIME NULL,
  revoked_by INT UNSIGNED NULL,
  expired_notified_at DATETIME NULL,
  UNIQUE KEY uq_shares_token (token),
  KEY idx_shares_owner (owner_id, revoked_at, created_at),
  KEY idx_shares_recipient (recipient_id, revoked_at),
  KEY idx_shares_file (file_id, revoked_at),
  KEY idx_shares_folder (folder_id, revoked_at),
  KEY idx_shares_expires (expires_at),
  CONSTRAINT fk_shares_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Files in a multi-file ("bundle") share; the ZIP is generated on demand and cached.
CREATE TABLE IF NOT EXISTS share_items (
  share_id BIGINT UNSIGNED NOT NULL,
  file_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (share_id, file_id),
  KEY idx_share_items_file (file_id),
  CONSTRAINT fk_share_items_share FOREIGN KEY (share_id) REFERENCES shares (id) ON DELETE CASCADE,
  CONSTRAINT fk_share_items_file FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS comments (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  file_id BIGINT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NULL COMMENT 'NULL for anonymous comments through a link share',
  author_name VARCHAR(100) NULL,
  share_id BIGINT UNSIGNED NULL,
  body TEXT NOT NULL,
  created_at DATETIME NOT NULL,
  edited_at DATETIME NULL,
  deleted_at DATETIME NULL,
  deleted_by INT UNSIGNED NULL,
  legacy_id VARCHAR(32) NULL,
  KEY idx_comments_file (file_id, deleted_at, created_at),
  CONSTRAINT fk_comments_file FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
