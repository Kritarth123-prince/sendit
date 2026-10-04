-- 001_users: roles, permissions, users, sessions, devices, login history, settings
-- Compatible with MySQL 5.7+ and MariaDB 10.3+ (InnoDB, utf8mb4). All DATETIMEs are UTC.

CREATE TABLE IF NOT EXISTS roles (
  id TINYINT UNSIGNED NOT NULL PRIMARY KEY,
  slug VARCHAR(32) NOT NULL,
  name VARCHAR(64) NOT NULL,
  description VARCHAR(255) NULL,
  UNIQUE KEY uq_roles_slug (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS permissions (
  id SMALLINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  slug VARCHAR(64) NOT NULL,
  description VARCHAR(255) NULL,
  UNIQUE KEY uq_permissions_slug (slug)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS role_permissions (
  role_id TINYINT UNSIGNED NOT NULL,
  permission_id SMALLINT UNSIGNED NOT NULL,
  PRIMARY KEY (role_id, permission_id),
  CONSTRAINT fk_rp_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE,
  CONSTRAINT fk_rp_perm FOREIGN KEY (permission_id) REFERENCES permissions (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS users (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  email VARCHAR(191) NULL,
  display_name VARCHAR(100) NOT NULL DEFAULT '',
  password_hash VARCHAR(255) NOT NULL,
  role_id TINYINT UNSIGNED NOT NULL DEFAULT 2,
  status ENUM('active','disabled','suspended') NOT NULL DEFAULT 'active',
  status_reason VARCHAR(255) NULL,
  quota_bytes BIGINT UNSIGNED NULL COMMENT 'NULL = settings.default_quota_bytes; 0 = cannot upload',
  used_bytes BIGINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'sum of file_versions.size of owned files incl. trash',
  totp_secret_enc VARCHAR(255) NULL COMMENT 'TOTP secret encrypted with APP_KEY',
  totp_enabled TINYINT(1) NOT NULL DEFAULT 0,
  totp_last_step BIGINT NULL COMMENT 'last accepted TOTP time-step (replay protection)',
  recovery_codes_enc TEXT NULL,
  must_change_password TINYINT(1) NOT NULL DEFAULT 0,
  password_changed_at DATETIME NULL,
  preferences TEXT NULL COMMENT 'JSON: theme, view mode, sort, trash retention override',
  last_login_at DATETIME NULL,
  last_login_ip VARCHAR(45) NULL,
  last_seen_at DATETIME NULL,
  failed_login_count INT UNSIGNED NOT NULL DEFAULT 0,
  locked_until DATETIME NULL,
  created_by INT UNSIGNED NULL,
  created_at DATETIME NOT NULL,
  updated_at DATETIME NOT NULL,
  deleted_at DATETIME NULL,
  UNIQUE KEY uq_users_username (username),
  UNIQUE KEY uq_users_email (email),
  KEY idx_users_status (status, deleted_at),
  KEY idx_users_role (role_id),
  CONSTRAINT fk_users_role FOREIGN KEY (role_id) REFERENCES roles (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_devices (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  client_hash CHAR(64) NOT NULL COMMENT 'sha256 of the X-Client-Id the browser generated',
  name VARCHAR(120) NOT NULL DEFAULT '' COMMENT 'e.g. Chrome on Android',
  user_agent VARCHAR(255) NULL,
  last_ip VARCHAR(45) NULL,
  first_seen_at DATETIME NOT NULL,
  last_seen_at DATETIME NOT NULL,
  UNIQUE KEY uq_devices_user_client (user_id, client_hash),
  CONSTRAINT fk_devices_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS user_sessions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  sid_hash CHAR(64) NULL COMMENT 'sha256(PHP session id); rotated on regeneration',
  remember_selector CHAR(24) NULL COMMENT 'remember-me selector (cookie part 1)',
  remember_hash CHAR(64) NULL COMMENT 'sha256(remember-me validator) (cookie part 2)',
  remember_expires_at DATETIME NULL,
  device_id INT UNSIGNED NULL,
  ip VARCHAR(45) NULL,
  user_agent VARCHAR(255) NULL,
  auth_method VARCHAR(16) NOT NULL DEFAULT 'password',
  two_factor_passed TINYINT(1) NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL,
  last_seen_at DATETIME NOT NULL,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME NULL,
  revoked_reason VARCHAR(64) NULL,
  UNIQUE KEY uq_sessions_sid (sid_hash),
  UNIQUE KEY uq_sessions_selector (remember_selector),
  KEY idx_sessions_user (user_id, revoked_at),
  KEY idx_sessions_expiry (expires_at),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS login_history (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NULL,
  username VARCHAR(64) NOT NULL DEFAULT '',
  ip VARCHAR(45) NULL,
  user_agent VARCHAR(255) NULL,
  success TINYINT(1) NOT NULL,
  failure_reason VARCHAR(48) NULL COMMENT 'bad_password|unknown_user|disabled|suspended|2fa_failed|rate_limited|locked',
  method VARCHAR(16) NOT NULL DEFAULT 'password' COMMENT 'password|remember|token|2fa',
  suspicious TINYINT(1) NOT NULL DEFAULT 0,
  suspicious_reason VARCHAR(100) NULL,
  created_at DATETIME NOT NULL,
  KEY idx_login_user (user_id, created_at),
  KEY idx_login_ip (ip, created_at),
  KEY idx_login_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS settings (
  `key` VARCHAR(100) NOT NULL PRIMARY KEY,
  `value` MEDIUMTEXT NULL,
  is_secret TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'value encrypted with APP_KEY',
  updated_by INT UNSIGNED NULL,
  updated_at DATETIME NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
