ALTER TABLE servers
  ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP(6) NULL AFTER last_heartbeat_at,
  ADD COLUMN IF NOT EXISTS revoked_by CHAR(36) NULL AFTER revoked_at;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='servers' AND CONSTRAINT_NAME='fk_servers_revoker'),
  'DO 0',
  'ALTER TABLE servers ADD CONSTRAINT fk_servers_revoker FOREIGN KEY (revoked_by) REFERENCES admin_users(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE servers
  ADD INDEX IF NOT EXISTS idx_servers_revoked (revoked_at);

ALTER TABLE admin_users
  ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP(6) NULL AFTER is_active,
  ADD INDEX IF NOT EXISTS idx_admin_users_deleted (deleted_at);

ALTER TABLE policy_revisions
  ADD COLUMN IF NOT EXISTS enterprise_id CHAR(36) NULL AFTER id,
  ADD COLUMN IF NOT EXISTS description VARCHAR(1024) NOT NULL DEFAULT '' AFTER revision_name,
  ADD COLUMN IF NOT EXISTS settings_json LONGTEXT NULL AFTER mode;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='policy_revisions' AND CONSTRAINT_NAME='fk_policy_revisions_enterprise'),
  'DO 0',
  'ALTER TABLE policy_revisions ADD CONSTRAINT fk_policy_revisions_enterprise FOREIGN KEY (enterprise_id) REFERENCES enterprises(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE policy_revisions
  ADD INDEX IF NOT EXISTS idx_policy_revisions_enterprise (enterprise_id, created_at);

CREATE TABLE IF NOT EXISTS policy_deployments (
  id CHAR(36) PRIMARY KEY,
  server_id CHAR(36) NOT NULL,
  policy_revision_id CHAR(36) NOT NULL,
  status VARCHAR(32) NOT NULL,
  detail TEXT NOT NULL,
  requested_by CHAR(36) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_policy_deployment_server FOREIGN KEY (server_id) REFERENCES servers(id),
  CONSTRAINT fk_policy_deployment_revision FOREIGN KEY (policy_revision_id) REFERENCES policy_revisions(id),
  CONSTRAINT fk_policy_deployment_requester FOREIGN KEY (requested_by) REFERENCES admin_users(id),
  UNIQUE KEY uq_policy_deployment_server_revision (server_id, policy_revision_id),
  INDEX idx_policy_deployments_status (status, updated_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE package_deployments
  ADD COLUMN IF NOT EXISTS requested_by CHAR(36) NULL AFTER detail;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='package_deployments' AND CONSTRAINT_NAME='fk_package_deployment_requester'),
  'DO 0',
  'ALTER TABLE package_deployments ADD CONSTRAINT fk_package_deployment_requester FOREIGN KEY (requested_by) REFERENCES admin_users(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

ALTER TABLE desired_states
  ADD COLUMN IF NOT EXISTS package_deployment_id CHAR(36) NULL AFTER module_package_id;

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='desired_states' AND CONSTRAINT_NAME='fk_desired_package_deployment'),
  'DO 0',
  'ALTER TABLE desired_states ADD CONSTRAINT fk_desired_package_deployment FOREIGN KEY (package_deployment_id) REFERENCES package_deployments(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

CREATE TABLE IF NOT EXISTS server_groups (
  id CHAR(36) PRIMARY KEY,
  enterprise_id CHAR(36) NOT NULL,
  name VARCHAR(255) NOT NULL,
  created_by CHAR(36) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_server_groups_enterprise FOREIGN KEY (enterprise_id) REFERENCES enterprises(id),
  CONSTRAINT fk_server_groups_creator FOREIGN KEY (created_by) REFERENCES admin_users(id),
  UNIQUE KEY uq_server_groups_enterprise_name (enterprise_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS server_group_members (
  group_id CHAR(36) NOT NULL,
  server_id CHAR(36) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (group_id, server_id),
  CONSTRAINT fk_group_members_group FOREIGN KEY (group_id) REFERENCES server_groups(id) ON DELETE CASCADE,
  CONSTRAINT fk_group_members_server FOREIGN KEY (server_id) REFERENCES servers(id),
  INDEX idx_group_members_server (server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS agent_commands (
  id CHAR(36) PRIMARY KEY,
  server_id CHAR(36) NOT NULL,
  command VARCHAR(32) NOT NULL,
  status VARCHAR(32) NOT NULL,
  detail TEXT NOT NULL,
  requested_by CHAR(36) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  acknowledged_at TIMESTAMP(6) NULL,
  completed_at TIMESTAMP(6) NULL,
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_agent_commands_server FOREIGN KEY (server_id) REFERENCES servers(id),
  CONSTRAINT fk_agent_commands_requester FOREIGN KEY (requested_by) REFERENCES admin_users(id),
  INDEX idx_agent_commands_pending (server_id, status, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
