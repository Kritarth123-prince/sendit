-- 008_system: background job queue, maintenance logs, daily statistics, legacy import ledger.

CREATE TABLE IF NOT EXISTS jobs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  queue VARCHAR(32) NOT NULL DEFAULT 'default',
  type VARCHAR(64) NOT NULL,
  payload MEDIUMTEXT NOT NULL,
  attempts TINYINT UNSIGNED NOT NULL DEFAULT 0,
  max_attempts TINYINT UNSIGNED NOT NULL DEFAULT 3,
  available_at DATETIME NOT NULL,
  reserved_at DATETIME NULL,
  reserved_by CHAR(16) NULL,
  last_error VARCHAR(1000) NULL,
  failed_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  KEY idx_jobs_pick (failed_at, reserved_at, available_at),
  KEY idx_jobs_type (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS maintenance_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  run_id CHAR(16) NOT NULL,
  task VARCHAR(64) NOT NULL,
  trigger_source VARCHAR(16) NOT NULL COMMENT 'cli | web | pseudo | admin',
  status VARCHAR(16) NOT NULL COMMENT 'ok | partial | error | skipped',
  items INT UNSIGNED NOT NULL DEFAULT 0,
  message VARCHAR(1000) NULL,
  started_at DATETIME NOT NULL,
  finished_at DATETIME NULL,
  duration_ms INT UNSIGNED NULL,
  KEY idx_maint_task (task, started_at),
  KEY idx_maint_run (run_id),
  KEY idx_maint_started (started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS daily_stats (
  day DATE NOT NULL,
  metric VARCHAR(32) NOT NULL COMMENT 'uploads|upload_bytes|downloads|new_users|shares_created|failed_uploads|storage_bytes|logins|deletes',
  value BIGINT NOT NULL DEFAULT 0,
  PRIMARY KEY (day, metric)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Idempotent, resumable import of the legacy JSON data (one row per imported item).
CREATE TABLE IF NOT EXISTS legacy_import (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  item_type VARCHAR(16) NOT NULL COMMENT 'user|folder|file|version|share|comment|text|tag|audit|push|collab|ocr',
  legacy_key VARCHAR(191) NOT NULL,
  new_id BIGINT UNSIGNED NULL,
  status VARCHAR(16) NOT NULL COMMENT 'done | failed | skipped',
  message VARCHAR(500) NULL,
  created_at DATETIME NOT NULL,
  UNIQUE KEY uq_legacy_item (item_type, legacy_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
