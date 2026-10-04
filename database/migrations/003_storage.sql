-- 003_storage: folders, files (with trash/soft-delete state), versions, tags, favourites,
-- searchable text (OCR + content), clipboard texts, resumable upload sessions, edit presence.

CREATE TABLE IF NOT EXISTS folders (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  owner_id INT UNSIGNED NOT NULL,
  parent_id INT UNSIGNED NULL COMMENT 'NULL = root of the owner''s drive',
  name VARCHAR(255) NOT NULL,
  color VARCHAR(16) NULL,
  created_by INT UNSIGNED NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  -- trash state ---------------------------------------------------------------
  deleted_at DATETIME NULL,
  deleted_by INT UNSIGNED NULL,
  trash_batch CHAR(16) NULL COMMENT 'items trashed together share a batch id (restore folder => restore contents)',
  trash_original_parent_id INT UNSIGNED NULL,
  trash_reason VARCHAR(64) NULL,
  legacy_name VARCHAR(100) NULL,
  KEY idx_folders_owner_parent (owner_id, parent_id, deleted_at),
  KEY idx_folders_deleted (deleted_at),
  KEY idx_folders_batch (trash_batch),
  CONSTRAINT fk_folders_owner FOREIGN KEY (owner_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS files (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  owner_id INT UNSIGNED NOT NULL,
  folder_id INT UNSIGNED NULL,
  name VARCHAR(255) NOT NULL,
  ext VARCHAR(32) NOT NULL DEFAULT '',
  mime VARCHAR(127) NOT NULL DEFAULT 'application/octet-stream' COMMENT 'server-detected',
  kind VARCHAR(16) NOT NULL DEFAULT 'other' COMMENT 'image|video|audio|pdf|document|spreadsheet|presentation|code|text|archive|other',
  size BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'size of the current version',
  blob_id BIGINT UNSIGNED NOT NULL COMMENT 'blob of the current version',
  sha256 CHAR(64) NOT NULL,
  version INT UNSIGNED NOT NULL DEFAULT 1 COMMENT 'current version number',
  description VARCHAR(1000) NULL,
  is_permanent TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'legacy "Keep forever"; when 0, expires_at applies',
  expires_at DATETIME NULL COMMENT 'auto-move to trash at this time (legacy 72h auto-delete)',
  download_count INT UNSIGNED NOT NULL DEFAULT 0,
  thumb_version INT UNSIGNED NULL COMMENT 'version the stored thumbnail was generated from (NULL = none)',
  is_bundle TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'legacy multi-file share ZIP',
  created_by INT UNSIGNED NULL,
  updated_by INT UNSIGNED NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  last_accessed_at DATETIME NULL,
  -- trash state ---------------------------------------------------------------
  deleted_at DATETIME NULL,
  deleted_by INT UNSIGNED NULL,
  trash_batch CHAR(16) NULL,
  trash_original_folder_id INT UNSIGNED NULL,
  trash_reason VARCHAR(64) NULL COMMENT 'user | folder | expired | admin | owner_deleted',
  legacy_name VARCHAR(255) NULL COMMENT 'filename in the legacy uploads/ directory (URL shims)',
  KEY idx_files_owner_folder (owner_id, deleted_at, folder_id, name(100)),
  KEY idx_files_owner_created (owner_id, deleted_at, created_at),
  KEY idx_files_owner_updated (owner_id, deleted_at, updated_at),
  KEY idx_files_owner_kind (owner_id, deleted_at, kind),
  KEY idx_files_deleted (deleted_at),
  KEY idx_files_expires (expires_at),
  KEY idx_files_sha (sha256),
  KEY idx_files_legacy (legacy_name(100)),
  KEY idx_files_batch (trash_batch),
  KEY idx_files_downloads (download_count),
  CONSTRAINT fk_files_owner FOREIGN KEY (owner_id) REFERENCES users (id),
  CONSTRAINT fk_files_blob FOREIGN KEY (blob_id) REFERENCES file_blobs (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Every version INCLUDING the current one has a row here (current = files.version).
CREATE TABLE IF NOT EXISTS file_versions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  file_id BIGINT UNSIGNED NOT NULL,
  version INT UNSIGNED NOT NULL,
  blob_id BIGINT UNSIGNED NOT NULL,
  size BIGINT UNSIGNED NOT NULL,
  sha256 CHAR(64) NOT NULL,
  name VARCHAR(255) NOT NULL COMMENT 'file name at the time of this version',
  mime VARCHAR(127) NOT NULL DEFAULT 'application/octet-stream',
  created_by INT UNSIGNED NULL,
  created_at DATETIME NOT NULL,
  note VARCHAR(255) NULL COMMENT 'e.g. Restored from version 2 | Edited in browser | Imported',
  UNIQUE KEY uq_versions_file_version (file_id, version),
  KEY idx_versions_blob (blob_id),
  KEY idx_versions_created (created_at),
  CONSTRAINT fk_versions_file FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
  CONSTRAINT fk_versions_blob FOREIGN KEY (blob_id) REFERENCES file_blobs (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS tags (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  owner_id INT UNSIGNED NOT NULL,
  name VARCHAR(64) NOT NULL,
  created_at DATETIME NOT NULL,
  UNIQUE KEY uq_tags_owner_name (owner_id, name),
  CONSTRAINT fk_tags_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS file_tags (
  file_id BIGINT UNSIGNED NOT NULL,
  tag_id INT UNSIGNED NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (file_id, tag_id),
  KEY idx_file_tags_tag (tag_id),
  CONSTRAINT fk_file_tags_file FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE,
  CONSTRAINT fk_file_tags_tag FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS favorites (
  user_id INT UNSIGNED NOT NULL,
  file_id BIGINT UNSIGNED NOT NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (user_id, file_id),
  KEY idx_favorites_file (file_id),
  CONSTRAINT fk_favorites_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
  CONSTRAINT fk_favorites_file FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Searchable text extracted from a file: OCR output (images/PDF) or plain-text content.
CREATE TABLE IF NOT EXISTS file_texts (
  file_id BIGINT UNSIGNED NOT NULL,
  source VARCHAR(16) NOT NULL COMMENT 'ocr | content',
  version INT UNSIGNED NOT NULL DEFAULT 1,
  `text` MEDIUMTEXT NOT NULL,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (file_id, source),
  CONSTRAINT fk_file_texts_file FOREIGN KEY (file_id) REFERENCES files (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Legacy "Save Text or URL" clipboard entries, now per user.
CREATE TABLE IF NOT EXISTS texts (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  owner_id INT UNSIGNED NOT NULL,
  content MEDIUMTEXT NOT NULL,
  is_url TINYINT(1) NOT NULL DEFAULT 0,
  url_meta TEXT NULL COMMENT 'JSON: title, description, image, favicon, domain',
  is_permanent TINYINT(1) NOT NULL DEFAULT 0,
  expires_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  deleted_at DATETIME NULL,
  KEY idx_texts_owner (owner_id, deleted_at, created_at),
  KEY idx_texts_expires (expires_at),
  CONSTRAINT fk_texts_owner FOREIGN KEY (owner_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS upload_sessions (
  id CHAR(32) NOT NULL PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  folder_id INT UNSIGNED NULL,
  target_file_id BIGINT UNSIGNED NULL COMMENT 'set when uploading a new version of an existing file',
  name VARCHAR(255) NOT NULL,
  size BIGINT UNSIGNED NOT NULL COMMENT 'declared size; reserved against the quota while active',
  mime_client VARCHAR(127) NULL,
  chunk_size INT UNSIGNED NOT NULL,
  total_chunks INT UNSIGNED NOT NULL,
  received_chunks INT UNSIGNED NOT NULL DEFAULT 0,
  received_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0,
  options TEXT NULL COMMENT 'JSON: tags, permanent, last_modified, via_share_id',
  status VARCHAR(16) NOT NULL DEFAULT 'active' COMMENT 'active|assembling|completed|failed|aborted|expired',
  error VARCHAR(255) NULL,
  client_id VARCHAR(64) NULL,
  result_file_id BIGINT UNSIGNED NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  expires_at DATETIME NOT NULL,
  KEY idx_uploads_user (user_id, status),
  KEY idx_uploads_expiry (status, expires_at),
  CONSTRAINT fk_uploads_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS upload_chunks (
  upload_id CHAR(32) NOT NULL,
  chunk_index INT UNSIGNED NOT NULL,
  size INT UNSIGNED NOT NULL,
  sha256 CHAR(64) NULL,
  created_at DATETIME NOT NULL,
  PRIMARY KEY (upload_id, chunk_index),
  CONSTRAINT fk_chunks_upload FOREIGN KEY (upload_id) REFERENCES upload_sessions (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Who is currently viewing/editing a text file in the in-browser editor (pruned after 30 s).
CREATE TABLE IF NOT EXISTS edit_presence (
  file_id BIGINT UNSIGNED NOT NULL,
  user_id INT UNSIGNED NOT NULL,
  client_id VARCHAR(64) NOT NULL DEFAULT '',
  last_seen_at DATETIME NOT NULL,
  PRIMARY KEY (file_id, user_id, client_id),
  KEY idx_presence_seen (last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
