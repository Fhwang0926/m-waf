CREATE TABLE IF NOT EXISTS crs_releases (
  id VARCHAR(255) PRIMARY KEY,
  provider VARCHAR(32) NOT NULL,
  repository VARCHAR(1024) NOT NULL,
  channel VARCHAR(16) NOT NULL,
  version VARCHAR(64) NOT NULL,
  tag VARCHAR(128) NOT NULL,
  commit_sha VARCHAR(64) NOT NULL,
  tag_object_sha VARCHAR(64) NOT NULL DEFAULT '',
  tag_signature_verified BOOLEAN NOT NULL DEFAULT FALSE,
  archive_path VARCHAR(1024) NOT NULL,
  archive_size BIGINT UNSIGNED NOT NULL,
  archive_sha256 CHAR(64) NOT NULL,
  index_path VARCHAR(1024) NOT NULL,
  index_size BIGINT UNSIGNED NOT NULL,
  index_sha256 CHAR(64) NOT NULL,
  status VARCHAR(16) NOT NULL DEFAULT 'VERIFIED',
  verified_at TIMESTAMP(6) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_crs_release_tag (repository(191), tag),
  INDEX idx_crs_release_channel (channel, status, version),
  CONSTRAINT chk_crs_release_channel CHECK (channel IN ('LTS','STABLE')),
  CONSTRAINT chk_crs_release_status CHECK (status IN ('VERIFIED','REJECTED','WITHDRAWN'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS crs_setup_definitions (
  release_id VARCHAR(255) NOT NULL,
  setting_key VARCHAR(128) NOT NULL,
  value_type VARCHAR(16) NOT NULL,
  default_value TEXT NOT NULL,
  minimum_value INT NULL,
  maximum_value INT NULL,
  options_json LONGTEXT NULL,
  description VARCHAR(2048) NOT NULL DEFAULT '',
  PRIMARY KEY (release_id, setting_key),
  CONSTRAINT fk_crs_setup_release FOREIGN KEY (release_id) REFERENCES crs_releases(id),
  CONSTRAINT chk_crs_setup_type CHECK (value_type IN ('integer','string','boolean','enum','list'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS crs_rules (
  release_id VARCHAR(255) NOT NULL,
  rule_id INT UNSIGNED NOT NULL,
  file_path VARCHAR(1024) NOT NULL,
  line_number INT UNSIGNED NOT NULL,
  phase VARCHAR(16) NOT NULL DEFAULT '',
  paranoia_level TINYINT UNSIGNED NOT NULL DEFAULT 0,
  severity VARCHAR(32) NOT NULL DEFAULT '',
  message TEXT NOT NULL,
  operator_name VARCHAR(255) NOT NULL DEFAULT '',
  content_sha256 CHAR(64) NOT NULL,
  directive_text LONGTEXT NOT NULL,
  PRIMARY KEY (release_id, rule_id),
  INDEX idx_crs_rules_filter (release_id, paranoia_level, phase, severity),
  CONSTRAINT fk_crs_rule_release FOREIGN KEY (release_id) REFERENCES crs_releases(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS crs_rule_tags (
  release_id VARCHAR(255) NOT NULL,
  rule_id INT UNSIGNED NOT NULL,
  tag VARCHAR(255) NOT NULL,
  PRIMARY KEY (release_id, rule_id, tag),
  INDEX idx_crs_rule_tag_search (release_id, tag),
  CONSTRAINT fk_crs_rule_tag_rule FOREIGN KEY (release_id, rule_id) REFERENCES crs_rules(release_id, rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS crs_rule_variables (
  release_id VARCHAR(255) NOT NULL,
  rule_id INT UNSIGNED NOT NULL,
  variable_name VARCHAR(512) NOT NULL,
  PRIMARY KEY (release_id, rule_id, variable_name),
  CONSTRAINT fk_crs_rule_variable_rule FOREIGN KEY (release_id, rule_id) REFERENCES crs_rules(release_id, rule_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE system_policy_versions
  ADD COLUMN IF NOT EXISTS config_storage_version TINYINT UNSIGNED NOT NULL DEFAULT 1 AFTER migration_notes_json,
  ADD COLUMN IF NOT EXISTS config_migration_status VARCHAR(32) NOT NULL DEFAULT 'PENDING' AFTER config_storage_version,
  ADD COLUMN IF NOT EXISTS config_migration_detail VARCHAR(1024) NOT NULL DEFAULT '' AFTER config_migration_status;

ALTER TABLE policy_revisions
  ADD COLUMN IF NOT EXISTS config_storage_version TINYINT UNSIGNED NOT NULL DEFAULT 1 AFTER settings_json,
  ADD COLUMN IF NOT EXISTS config_migration_status VARCHAR(32) NOT NULL DEFAULT 'PENDING' AFTER config_storage_version,
  ADD COLUMN IF NOT EXISTS config_migration_detail VARCHAR(1024) NOT NULL DEFAULT '' AFTER config_migration_status;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='system_policy_versions' AND CONSTRAINT_NAME='chk_system_policy_config_migration_status'),
  'DO 0',
  'ALTER TABLE system_policy_versions ADD CONSTRAINT chk_system_policy_config_migration_status CHECK (config_migration_status IN (''PENDING'',''MIGRATED'',''LEGACY_COMPAT'',''LEGACY_LOCKED'',''FAILED''))'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='policy_revisions' AND CONSTRAINT_NAME='chk_policy_revision_config_migration_status'),
  'DO 0',
  'ALTER TABLE policy_revisions ADD CONSTRAINT chk_policy_revision_config_migration_status CHECK (config_migration_status IN (''PENDING'',''MIGRATED'',''LEGACY_COMPAT'',''LEGACY_LOCKED'',''FAILED''))'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

CREATE TABLE IF NOT EXISTS policy_configurations (
  id CHAR(36) PRIMARY KEY,
  system_policy_version_id VARCHAR(255) NULL,
  policy_revision_id CHAR(36) NULL,
  crs_release_id VARCHAR(255) NULL,
  engine_mode VARCHAR(32) NOT NULL,
  blocking_paranoia_level TINYINT UNSIGNED NOT NULL,
  executing_paranoia_level TINYINT UNSIGNED NOT NULL,
  inbound_anomaly_threshold INT UNSIGNED NOT NULL,
  outbound_anomaly_threshold INT UNSIGNED NOT NULL,
  request_body_access BOOLEAN NOT NULL,
  response_body_access BOOLEAN NOT NULL,
  early_blocking BOOLEAN NOT NULL,
  sampling_percentage TINYINT UNSIGNED NOT NULL,
  rule_id_namespace_version SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  config_sha256 CHAR(64) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_policy_config_system (system_policy_version_id),
  UNIQUE KEY uq_policy_config_revision (policy_revision_id),
  INDEX idx_policy_config_release (crs_release_id),
  CONSTRAINT fk_policy_config_system FOREIGN KEY (system_policy_version_id) REFERENCES system_policy_versions(id),
  CONSTRAINT fk_policy_config_revision FOREIGN KEY (policy_revision_id) REFERENCES policy_revisions(id),
  CONSTRAINT fk_policy_config_release FOREIGN KEY (crs_release_id) REFERENCES crs_releases(id),
  CONSTRAINT chk_policy_config_owner CHECK (((system_policy_version_id IS NOT NULL) + (policy_revision_id IS NOT NULL)) = 1),
  CONSTRAINT chk_policy_config_mode CHECK (engine_mode IN ('DetectionOnly','On')),
  CONSTRAINT chk_policy_config_pl CHECK (blocking_paranoia_level BETWEEN 1 AND 4 AND executing_paranoia_level BETWEEN blocking_paranoia_level AND 4),
  CONSTRAINT chk_policy_config_scores CHECK (inbound_anomaly_threshold BETWEEN 1 AND 100 AND outbound_anomaly_threshold BETWEEN 1 AND 100),
  CONSTRAINT chk_policy_config_sampling CHECK (sampling_percentage BETWEEN 1 AND 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS policy_configuration_setup_values (
  configuration_id CHAR(36) NOT NULL,
  setting_key VARCHAR(128) NOT NULL,
  setting_value TEXT NOT NULL,
  source_scope VARCHAR(16) NOT NULL,
  PRIMARY KEY (configuration_id, setting_key),
  CONSTRAINT fk_policy_setup_configuration FOREIGN KEY (configuration_id) REFERENCES policy_configurations(id) ON DELETE CASCADE,
  CONSTRAINT chk_policy_setup_scope CHECK (source_scope IN ('SYSTEM','ENTERPRISE'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS policy_configuration_exclusions (
  id CHAR(36) PRIMARY KEY,
  configuration_id CHAR(36) NOT NULL,
  source_scope VARCHAR(16) NOT NULL,
  exclusion_type VARCHAR(24) NOT NULL,
  load_stage VARCHAR(16) NOT NULL,
  rule_id INT UNSIGNED NULL,
  rule_tag VARCHAR(255) NULL,
  target VARCHAR(512) NULL,
  generated_rule_id INT UNSIGNED NULL,
  reason VARCHAR(1024) NOT NULL DEFAULT '',
  expires_at TIMESTAMP(6) NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  legacy BOOLEAN NOT NULL DEFAULT FALSE,
  order_no INT UNSIGNED NOT NULL,
  UNIQUE KEY uq_policy_exclusion_order (configuration_id, order_no),
  UNIQUE KEY uq_policy_exclusion_generated (configuration_id, generated_rule_id),
  CONSTRAINT fk_policy_exclusion_configuration FOREIGN KEY (configuration_id) REFERENCES policy_configurations(id) ON DELETE CASCADE,
  CONSTRAINT chk_policy_exclusion_scope CHECK (source_scope IN ('SYSTEM','ENTERPRISE')),
  CONSTRAINT chk_policy_exclusion_type CHECK (exclusion_type IN ('RULE','TARGET','TAG','ENGINE_BYPASS')),
  CONSTRAINT chk_policy_exclusion_stage CHECK (load_stage IN ('BEFORE_CRS','AFTER_CRS'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS policy_configuration_exclusion_conditions (
  exclusion_id CHAR(36) NOT NULL,
  order_no INT UNSIGNED NOT NULL,
  field_name VARCHAR(128) NOT NULL,
  operator_name VARCHAR(32) NOT NULL,
  condition_value VARCHAR(1024) NOT NULL,
  PRIMARY KEY (exclusion_id, order_no),
  CONSTRAINT fk_policy_condition_exclusion FOREIGN KEY (exclusion_id) REFERENCES policy_configuration_exclusions(id) ON DELETE CASCADE,
  CONSTRAINT chk_policy_condition_field CHECK (field_name IN ('REQUEST_URI','REQUEST_METHOD','REQUEST_HEADERS:Host','REMOTE_ADDR')),
  CONSTRAINT chk_policy_condition_operator CHECK (operator_name IN ('@beginsWith','@streq','@ipMatch'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS policy_configuration_custom_rules (
  id CHAR(36) PRIMARY KEY,
  configuration_id CHAR(36) NOT NULL,
  source_scope VARCHAR(16) NOT NULL,
  rule_id INT UNSIGNED NOT NULL,
  rule_name VARCHAR(255) NOT NULL DEFAULT '',
  phase VARCHAR(16) NOT NULL,
  severity VARCHAR(32) NOT NULL DEFAULT '',
  canonical_sec_rule LONGTEXT NOT NULL,
  content_sha256 CHAR(64) NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  legacy_id_range BOOLEAN NOT NULL DEFAULT FALSE,
  order_no INT UNSIGNED NOT NULL,
  UNIQUE KEY uq_policy_custom_rule_id (configuration_id, rule_id),
  UNIQUE KEY uq_policy_custom_rule_order (configuration_id, order_no),
  CONSTRAINT fk_policy_custom_configuration FOREIGN KEY (configuration_id) REFERENCES policy_configurations(id) ON DELETE CASCADE,
  CONSTRAINT chk_policy_custom_scope CHECK (source_scope IN ('SYSTEM','ENTERPRISE'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS policy_migration_impacts (
  enterprise_policy_id CHAR(36) NOT NULL,
  target_system_policy_version_id VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL,
  detail VARCHAR(2048) NOT NULL DEFAULT '',
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (enterprise_policy_id, target_system_policy_version_id),
  CONSTRAINT fk_policy_impact_enterprise_policy FOREIGN KEY (enterprise_policy_id) REFERENCES enterprise_policies(id),
  CONSTRAINT fk_policy_impact_system_policy FOREIGN KEY (target_system_policy_version_id) REFERENCES system_policy_versions(id),
  CONSTRAINT chk_policy_impact_status CHECK (status IN ('SAFE','MIGRATION_REQUIRED')),
  INDEX idx_policy_impact_status (target_system_policy_version_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
