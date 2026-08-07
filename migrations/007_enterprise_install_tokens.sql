CREATE TABLE IF NOT EXISTS enterprise_install_tokens (
  id CHAR(36) PRIMARY KEY,
  enterprise_id CHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  token_prefix VARCHAR(32) NOT NULL,
  token_hash BINARY(32) NOT NULL UNIQUE,
  expires_at TIMESTAMP(6) NOT NULL,
  max_enrollments INT UNSIGNED NULL,
  enrollment_count INT UNSIGNED NOT NULL DEFAULT 0,
  last_used_at TIMESTAMP(6) NULL,
  revoked_at TIMESTAMP(6) NULL,
  created_by CHAR(36) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_install_token_enterprise FOREIGN KEY (enterprise_id) REFERENCES enterprises(id),
  CONSTRAINT fk_install_token_creator FOREIGN KEY (created_by) REFERENCES admin_users(id),
  INDEX idx_install_token_enterprise (enterprise_id, created_at),
  INDEX idx_install_token_expiry (expires_at, revoked_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE enrollment_tokens
  ADD COLUMN IF NOT EXISTS install_token_id CHAR(36) NULL AFTER enterprise_id;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='enrollment_tokens' AND CONSTRAINT_NAME='fk_enrollment_install_token'),
  'DO 0',
  'ALTER TABLE enrollment_tokens ADD CONSTRAINT fk_enrollment_install_token FOREIGN KEY (install_token_id) REFERENCES enterprise_install_tokens(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE enrollment_tokens
  ADD INDEX IF NOT EXISTS idx_enrollment_install_token (install_token_id, created_at);
