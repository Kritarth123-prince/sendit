-- 006_activity_events: real-time event log (short retention, drives multi-device sync and
-- missed-event recovery) and the durable audit/activity log (file timelines, security centre,
-- admin activity).

CREATE TABLE IF NOT EXISTS events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY COMMENT 'event_id: strictly increasing',
  type VARCHAR(48) NOT NULL,
  actor_id INT UNSIGNED NULL,
  file_id BIGINT UNSIGNED NULL,
  folder_id INT UNSIGNED NULL,
  share_id BIGINT UNSIGNED NULL,
  origin VARCHAR(64) NULL COMMENT 'X-Client-Id of the device that caused the event',
  payload MEDIUMTEXT NOT NULL COMMENT 'JSON "data" object',
  created_at DATETIME NOT NULL,
  KEY idx_events_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Fan-out on write: one row per authorised recipient. user_id 0 = admin dashboard channel.
CREATE TABLE IF NOT EXISTS event_recipients (
  user_id INT UNSIGNED NOT NULL,
  event_id BIGINT UNSIGNED NOT NULL,
  PRIMARY KEY (user_id, event_id),
  KEY idx_er_event (event_id),
  CONSTRAINT fk_er_event FOREIGN KEY (event_id) REFERENCES events (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NULL COMMENT 'actor; NULL = anonymous (link) or system',
  actor_label VARCHAR(100) NULL COMMENT 'display label when user_id is NULL or for legacy rows',
  action VARCHAR(48) NOT NULL COMMENT 'e.g. file.upload, file.download, share.create, auth.login',
  category VARCHAR(16) NOT NULL DEFAULT 'activity' COMMENT 'activity|security|admin|system',
  target_type VARCHAR(16) NULL COMMENT 'file|folder|share|user|text|system',
  target_id BIGINT UNSIGNED NULL,
  owner_id INT UNSIGNED NULL COMMENT 'owner of the target, so owners can see activity on their items',
  detail VARCHAR(500) NULL,
  meta TEXT NULL COMMENT 'JSON',
  ip VARCHAR(64) NULL COMMENT 'IP address (legacy rows hold a SHA-256 hash)',
  user_agent VARCHAR(255) NULL,
  created_at DATETIME NOT NULL,
  KEY idx_audit_target (target_type, target_id, created_at),
  KEY idx_audit_user (user_id, created_at),
  KEY idx_audit_owner (owner_id, created_at),
  KEY idx_audit_action (action, created_at),
  KEY idx_audit_category (category, created_at),
  KEY idx_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
