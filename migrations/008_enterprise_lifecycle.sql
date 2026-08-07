ALTER TABLE enterprises
  ADD COLUMN IF NOT EXISTS status VARCHAR(16) NOT NULL DEFAULT 'ACTIVE' AFTER name,
  ADD COLUMN IF NOT EXISTS terminated_at TIMESTAMP(6) NULL AFTER updated_at,
  ADD COLUMN IF NOT EXISTS terminated_by CHAR(36) NULL AFTER terminated_at;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='enterprises' AND CONSTRAINT_NAME='fk_enterprises_terminator'),
  'DO 0',
  'ALTER TABLE enterprises ADD CONSTRAINT fk_enterprises_terminator FOREIGN KEY (terminated_by) REFERENCES admin_users(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE enterprises
  ADD INDEX IF NOT EXISTS idx_enterprises_status (status, name);
