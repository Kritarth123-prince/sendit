-- 010_auth_password_resets (A1): self-service password reset tokens + remember-me rotation grace.
-- Compatible with MySQL 5.7+ and MariaDB 10.3+. Applied exactly once by the Migrator.

-- Single-use, hashed, short-lived (1 h) password reset tokens. Only used when MAIL_DRIVER is not
-- "none". The raw token is e-mailed once and never stored.
CREATE TABLE IF NOT EXISTS password_resets (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  token_hash CHAR(64) NOT NULL COMMENT 'sha256 of the e-mailed token',
  ip VARCHAR(45) NULL COMMENT 'requesting IP (audit only)',
  created_at DATETIME NOT NULL,
  expires_at DATETIME NOT NULL,
  used_at DATETIME NULL,
  UNIQUE KEY uq_password_resets_hash (token_hash),
  KEY idx_password_resets_user (user_id, used_at),
  KEY idx_password_resets_expiry (expires_at),
  CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Remember-me validators rotate on every use. Two requests that race with the same (old) cookie
-- would otherwise look like cookie theft and sign the user out; the previous validator hash is
-- therefore honoured (without rotating again) for a few seconds after a rotation.
ALTER TABLE user_sessions
  ADD COLUMN remember_prev_hash CHAR(64) NULL COMMENT 'sha256 of the previous remember-me validator' AFTER remember_hash,
  ADD COLUMN remember_rotated_at DATETIME NULL COMMENT 'when the validator last rotated' AFTER remember_prev_hash;
