-- 005_notifications: in-app notification centre, per-category channel preferences, Web Push.

CREATE TABLE IF NOT EXISTS notifications (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  category VARCHAR(32) NOT NULL COMMENT 'share|download|comment|version|share_expired|login|security|quota|upload',
  type VARCHAR(48) NOT NULL COMMENT 'fine-grained, e.g. share.received, upload.failed',
  title VARCHAR(200) NOT NULL,
  body VARCHAR(1000) NOT NULL DEFAULT '',
  data TEXT NULL COMMENT 'JSON (file_id, share_id, link) — never secrets',
  actor_id INT UNSIGNED NULL,
  dedupe_key VARCHAR(120) NULL COMMENT 'suppresses duplicates for the same user',
  read_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  KEY idx_notif_user (user_id, read_at, id),
  KEY idx_notif_created (created_at),
  UNIQUE KEY uq_notif_dedupe (user_id, dedupe_key),
  CONSTRAINT fk_notif_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS notification_preferences (
  user_id INT UNSIGNED NOT NULL,
  category VARCHAR(32) NOT NULL,
  in_app TINYINT(1) NOT NULL DEFAULT 1,
  push TINYINT(1) NOT NULL DEFAULT 0,
  email TINYINT(1) NOT NULL DEFAULT 0,
  updated_at DATETIME NOT NULL,
  PRIMARY KEY (user_id, category),
  CONSTRAINT fk_notif_pref_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  endpoint TEXT NOT NULL,
  endpoint_hash CHAR(64) NOT NULL,
  p256dh VARCHAR(255) NOT NULL,
  auth_secret VARCHAR(64) NOT NULL,
  device_id INT UNSIGNED NULL,
  user_agent VARCHAR(255) NULL,
  created_at DATETIME NOT NULL,
  last_success_at DATETIME NULL,
  failure_count INT UNSIGNED NOT NULL DEFAULT 0,
  UNIQUE KEY uq_push_endpoint (endpoint_hash),
  KEY idx_push_user (user_id),
  CONSTRAINT fk_push_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
