-- Repair databases that recorded 010_crs_policy_storage.sql before the
-- policy migration impact table was added to that migration file.
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
