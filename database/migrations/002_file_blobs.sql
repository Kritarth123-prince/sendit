-- 002_file_blobs: content-addressed physical storage with reference counting (deduplication)
--
-- Invariant: file_blobs.ref_count = COUNT(file_versions rows with this blob_id).
-- A blob's physical file is deleted only when ref_count = 0 (and the FK below makes it
-- impossible to delete a blob row that a version still references).

CREATE TABLE IF NOT EXISTS file_blobs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  scope VARCHAR(24) NOT NULL COMMENT 'u<userId> = per-user dedup (default) | global',
  sha256 CHAR(64) NOT NULL COMMENT 'SHA-256 of the plaintext content',
  size BIGINT UNSIGNED NOT NULL COMMENT 'plaintext size in bytes',
  stored_size BIGINT UNSIGNED NOT NULL COMMENT 'size on disk',
  storage_path VARCHAR(255) NOT NULL COMMENT 'relative to STORAGE_PATH; never sent to clients',
  mime VARCHAR(127) NULL COMMENT 'server-detected MIME type',
  encryption VARCHAR(16) NOT NULL DEFAULT 'none' COMMENT 'none | gcm1 (AES-256-GCM chunked) | legacy_cbc',
  enc_key_id VARCHAR(16) NULL COMMENT 'id of the master key that wraps the data key',
  enc_dek VARCHAR(255) NULL COMMENT 'base64(nonce|tag|AES-256-GCM-wrapped data key)',
  ref_count INT UNSIGNED NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL,
  last_ref_change_at DATETIME NOT NULL,
  UNIQUE KEY uq_blobs_scope_hash (scope, sha256),
  KEY idx_blobs_refcount (ref_count, last_ref_change_at),
  KEY idx_blobs_encryption (encryption)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
