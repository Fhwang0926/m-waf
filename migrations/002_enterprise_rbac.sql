CREATE TABLE IF NOT EXISTS enterprises (
  id CHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL UNIQUE,
  created_by CHAR(36) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_users (
  id CHAR(36) PRIMARY KEY,
  enterprise_id CHAR(36) NULL,
  username VARCHAR(128) NOT NULL UNIQUE,
  display_name VARCHAR(255) NOT NULL,
  password_hash VARCHAR(512) NOT NULL,
  role VARCHAR(32) NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  bootstrap_key TINYINT UNSIGNED NULL UNIQUE,
  created_by CHAR(36) NULL,
  last_login_at TIMESTAMP(6) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_admin_users_enterprise FOREIGN KEY (enterprise_id) REFERENCES enterprises(id),
  CONSTRAINT fk_admin_users_creator FOREIGN KEY (created_by) REFERENCES admin_users(id),
  CONSTRAINT chk_admin_users_role CHECK (role IN ('enterprise_user', 'enterprise_admin', 'system_admin')),
  CONSTRAINT chk_admin_users_scope CHECK (
    (role = 'system_admin' AND enterprise_id IS NULL) OR
    (role <> 'system_admin' AND enterprise_id IS NOT NULL)
  ),
  INDEX idx_admin_users_enterprise_role (enterprise_id, role, is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='enterprises' AND CONSTRAINT_NAME='fk_enterprises_creator'),
  'DO 0',
  'ALTER TABLE enterprises ADD CONSTRAINT fk_enterprises_creator FOREIGN KEY (created_by) REFERENCES admin_users(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE enrollment_tokens
  ADD COLUMN IF NOT EXISTS enterprise_id CHAR(36) NULL AFTER id;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='enrollment_tokens' AND CONSTRAINT_NAME='fk_enrollment_tokens_enterprise'),
  'DO 0',
  'ALTER TABLE enrollment_tokens ADD CONSTRAINT fk_enrollment_tokens_enterprise FOREIGN KEY (enterprise_id) REFERENCES enterprises(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE enrollment_tokens
  ADD INDEX IF NOT EXISTS idx_enrollment_tokens_enterprise (enterprise_id, created_at);

ALTER TABLE servers
  ADD COLUMN IF NOT EXISTS enterprise_id CHAR(36) NULL AFTER id;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='servers' AND CONSTRAINT_NAME='fk_servers_enterprise'),
  'DO 0',
  'ALTER TABLE servers ADD CONSTRAINT fk_servers_enterprise FOREIGN KEY (enterprise_id) REFERENCES enterprises(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE servers
  ADD INDEX IF NOT EXISTS idx_servers_enterprise_status (enterprise_id, status);
