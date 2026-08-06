CREATE TABLE IF NOT EXISTS system_policy_versions (
  id VARCHAR(255) PRIMARY KEY,
  policy_key VARCHAR(128) NOT NULL,
  version VARCHAR(64) NOT NULL,
  schema_version INT UNSIGNED NOT NULL,
  name VARCHAR(255) NOT NULL,
  description VARCHAR(1024) NOT NULL,
  crs_track VARCHAR(32) NOT NULL,
  crs_version VARCHAR(64) NOT NULL,
  status VARCHAR(32) NOT NULL,
  template_sha256 CHAR(64) NOT NULL,
  source_commit VARCHAR(64) NOT NULL,
  defaults_json LONGTEXT NOT NULL,
  migration_notes_json LONGTEXT NULL,
  synced_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_system_policy_key_version (policy_key, version),
  INDEX idx_system_policy_current (policy_key, status, version),
  CONSTRAINT chk_system_policy_status CHECK (status IN ('PUBLISHED','DEPRECATED','WITHDRAWN'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS enterprise_policies (
  id CHAR(36) PRIMARY KEY,
  enterprise_id CHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  description VARCHAR(1024) NOT NULL DEFAULT '',
  target VARCHAR(255) NOT NULL,
  system_policy_key VARCHAR(128) NULL,
  current_system_policy_version_id VARCHAR(255) NULL,
  update_strategy VARCHAR(32) NOT NULL DEFAULT 'MANUAL',
  status VARCHAR(32) NOT NULL DEFAULT 'ACTIVE',
  current_revision_id CHAR(36) NULL,
  previous_revision_id CHAR(36) NULL,
  created_by CHAR(36) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_enterprise_policy_enterprise FOREIGN KEY (enterprise_id) REFERENCES enterprises(id),
  CONSTRAINT fk_enterprise_policy_system_version FOREIGN KEY (current_system_policy_version_id) REFERENCES system_policy_versions(id),
  CONSTRAINT fk_enterprise_policy_creator FOREIGN KEY (created_by) REFERENCES admin_users(id),
  CONSTRAINT chk_enterprise_policy_strategy CHECK (update_strategy IN ('MANUAL','AUTOMATIC','PINNED')),
  CONSTRAINT chk_enterprise_policy_status CHECK (status IN ('ACTIVE','LEGACY_LOCKED')),
  INDEX idx_enterprise_policy_scope (enterprise_id, status, updated_at),
  INDEX idx_enterprise_policy_target (enterprise_id, target)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE policy_revisions
  ADD COLUMN IF NOT EXISTS enterprise_policy_id CHAR(36) NULL AFTER enterprise_id,
  ADD COLUMN IF NOT EXISTS system_policy_version_id VARCHAR(255) NULL AFTER enterprise_policy_id,
  ADD COLUMN IF NOT EXISTS parent_revision_id CHAR(36) NULL AFTER system_policy_version_id,
  ADD COLUMN IF NOT EXISTS policy_origin VARCHAR(32) NOT NULL DEFAULT 'LEGACY' AFTER parent_revision_id;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='policy_revisions' AND CONSTRAINT_NAME='fk_policy_revision_enterprise_policy'),
  'DO 0',
  'ALTER TABLE policy_revisions ADD CONSTRAINT fk_policy_revision_enterprise_policy FOREIGN KEY (enterprise_policy_id) REFERENCES enterprise_policies(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='policy_revisions' AND CONSTRAINT_NAME='fk_policy_revision_system_version'),
  'DO 0',
  'ALTER TABLE policy_revisions ADD CONSTRAINT fk_policy_revision_system_version FOREIGN KEY (system_policy_version_id) REFERENCES system_policy_versions(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='policy_revisions' AND CONSTRAINT_NAME='fk_policy_revision_parent'),
  'DO 0',
  'ALTER TABLE policy_revisions ADD CONSTRAINT fk_policy_revision_parent FOREIGN KEY (parent_revision_id) REFERENCES policy_revisions(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE policy_revisions
  ADD INDEX IF NOT EXISTS idx_policy_revision_enterprise_policy (enterprise_policy_id, created_at),
  ADD INDEX IF NOT EXISTS idx_policy_revision_system_version (system_policy_version_id);

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='enterprise_policies' AND CONSTRAINT_NAME='fk_enterprise_policy_current_revision'),
  'DO 0',
  'ALTER TABLE enterprise_policies ADD CONSTRAINT fk_enterprise_policy_current_revision FOREIGN KEY (current_revision_id) REFERENCES policy_revisions(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='enterprise_policies' AND CONSTRAINT_NAME='fk_enterprise_policy_previous_revision'),
  'DO 0',
  'ALTER TABLE enterprise_policies ADD CONSTRAINT fk_enterprise_policy_previous_revision FOREIGN KEY (previous_revision_id) REFERENCES policy_revisions(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

CREATE TABLE IF NOT EXISTS policy_rollouts (
  id CHAR(36) PRIMARY KEY,
  enterprise_policy_id CHAR(36) NOT NULL,
  rollout_type VARCHAR(32) NOT NULL,
  status VARCHAR(32) NOT NULL,
  from_revision_id CHAR(36) NULL,
  target_system_policy_version_id VARCHAR(255) NOT NULL,
  target_revision_id CHAR(36) NULL,
  expected_revision_id CHAR(36) NULL,
  batch_size INT UNSIGNED NOT NULL DEFAULT 25,
  requested_by CHAR(36) NULL,
  approved_by CHAR(36) NULL,
  detail TEXT NOT NULL,
  started_at TIMESTAMP(6) NULL,
  completed_at TIMESTAMP(6) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_policy_rollout_enterprise_policy FOREIGN KEY (enterprise_policy_id) REFERENCES enterprise_policies(id),
  CONSTRAINT fk_policy_rollout_from_revision FOREIGN KEY (from_revision_id) REFERENCES policy_revisions(id),
  CONSTRAINT fk_policy_rollout_target_system_version FOREIGN KEY (target_system_policy_version_id) REFERENCES system_policy_versions(id),
  CONSTRAINT fk_policy_rollout_target_revision FOREIGN KEY (target_revision_id) REFERENCES policy_revisions(id),
  CONSTRAINT fk_policy_rollout_expected_revision FOREIGN KEY (expected_revision_id) REFERENCES policy_revisions(id),
  CONSTRAINT fk_policy_rollout_requester FOREIGN KEY (requested_by) REFERENCES admin_users(id),
  CONSTRAINT fk_policy_rollout_approver FOREIGN KEY (approved_by) REFERENCES admin_users(id),
  CONSTRAINT chk_policy_rollout_type CHECK (rollout_type IN ('SEED','UPDATE','ROLLBACK','RECOVERY')),
  CONSTRAINT chk_policy_rollout_status CHECK (status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED','APPLIED','FAILED','CANCELLED')),
  INDEX idx_policy_rollout_active (enterprise_policy_id, status, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS policy_rollout_targets (
  rollout_id CHAR(36) NOT NULL,
  server_id CHAR(36) NOT NULL,
  batch_no INT UNSIGNED NOT NULL,
  status VARCHAR(32) NOT NULL,
  resume_status VARCHAR(32) NULL,
  source_agent_package_id VARCHAR(255) NULL,
  source_module_package_id VARCHAR(255) NULL,
  target_agent_package_id VARCHAR(255) NULL,
  target_module_package_id VARCHAR(255) NULL,
  transition_revision_id CHAR(36) NULL,
  final_revision_id CHAR(36) NULL,
  package_deployment_id CHAR(36) NULL,
  detail TEXT NOT NULL,
  stabilized_at TIMESTAMP(6) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (rollout_id, server_id),
  CONSTRAINT fk_policy_rollout_target_rollout FOREIGN KEY (rollout_id) REFERENCES policy_rollouts(id) ON DELETE CASCADE,
  CONSTRAINT fk_policy_rollout_target_server FOREIGN KEY (server_id) REFERENCES servers(id),
  CONSTRAINT fk_policy_rollout_target_transition FOREIGN KEY (transition_revision_id) REFERENCES policy_revisions(id),
  CONSTRAINT fk_policy_rollout_target_final FOREIGN KEY (final_revision_id) REFERENCES policy_revisions(id),
  CONSTRAINT fk_policy_rollout_target_package_deployment FOREIGN KEY (package_deployment_id) REFERENCES package_deployments(id),
  CONSTRAINT chk_policy_rollout_target_status CHECK (status IN ('PENDING','DEFERRED','TRANSITION_PENDING','PACKAGE_PENDING','POLICY_PENDING','APPLIED','FAILED','ROLLBACK_PENDING','ROLLED_BACK')),
  CONSTRAINT chk_policy_rollout_target_resume_status CHECK (resume_status IS NULL OR resume_status IN ('PENDING','TRANSITION_PENDING','PACKAGE_PENDING','POLICY_PENDING','ROLLBACK_PENDING')),
  INDEX idx_policy_rollout_target_progress (rollout_id, batch_no, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE policy_deployments
  ADD COLUMN IF NOT EXISTS rollout_id CHAR(36) NULL AFTER requested_by;

ALTER TABLE package_deployments
  ADD COLUMN IF NOT EXISTS rollout_id CHAR(36) NULL AFTER requested_by;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='policy_deployments' AND CONSTRAINT_NAME='fk_policy_deployment_rollout'),
  'DO 0',
  'ALTER TABLE policy_deployments ADD CONSTRAINT fk_policy_deployment_rollout FOREIGN KEY (rollout_id) REFERENCES policy_rollouts(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='package_deployments' AND CONSTRAINT_NAME='fk_package_deployment_rollout'),
  'DO 0',
  'ALTER TABLE package_deployments ADD CONSTRAINT fk_package_deployment_rollout FOREIGN KEY (rollout_id) REFERENCES policy_rollouts(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;
