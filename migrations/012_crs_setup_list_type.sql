-- Repair databases that recorded 010_crs_policy_storage.sql before the
-- supported CRS Setup list type was added to chk_crs_setup_type.
-- Keep this forward-only because an applied 010 migration is not re-run.
SET @mwaf_sql = IF(
  EXISTS(
    SELECT 1
    FROM information_schema.TABLE_CONSTRAINTS
    WHERE CONSTRAINT_SCHEMA = DATABASE()
      AND TABLE_NAME = 'crs_setup_definitions'
      AND CONSTRAINT_NAME = 'chk_crs_setup_type'
  ),
  'ALTER TABLE crs_setup_definitions DROP CONSTRAINT chk_crs_setup_type',
  'DO 0'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE crs_setup_definitions
  ADD CONSTRAINT chk_crs_setup_type
  CHECK (value_type IN ('integer','string','boolean','enum','list'));
