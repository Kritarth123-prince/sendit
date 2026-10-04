-- 007_api: personal API tokens and the shared rate limiter.

CREATE TABLE IF NOT EXISTS api_tokens (
  id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT UNSIGNED NOT NULL,
  name VARCHAR(100) NOT NULL,
  token_prefix VARCHAR(12) NOT NULL COMMENT 'first characters, safe to display',
  token_hash CHAR(64) NOT NULL COMMENT 'sha256 of the full token; the token itself is shown once',
  scopes VARCHAR(255) NOT NULL DEFAULT '*' COMMENT '* or comma list: files:read,files:write,shares,notifications,admin',
  last_used_at DATETIME NULL,
  last_used_ip VARCHAR(45) NULL,
  expires_at DATETIME NULL,
  created_at DATETIME NOT NULL,
  revoked_at DATETIME NULL,
  UNIQUE KEY uq_api_tokens_hash (token_hash),
  KEY idx_api_tokens_user (user_id, revoked_at),
  CONSTRAINT fk_api_tokens_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Fixed-window counters. bucket = sha256(name|subject|window_start).
CREATE TABLE IF NOT EXISTS rate_limits (
  bucket CHAR(64) NOT NULL PRIMARY KEY,
  hits INT UNSIGNED NOT NULL DEFAULT 0,
  expires_at INT UNSIGNED NOT NULL COMMENT 'unix time',
  KEY idx_rate_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
