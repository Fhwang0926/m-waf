CREATE TABLE IF NOT EXISTS enrollment_tokens (
  id CHAR(36) PRIMARY KEY,
  token_hash BINARY(32) NOT NULL UNIQUE,
  label VARCHAR(255) NOT NULL,
  allowed_packages_json LONGTEXT NULL,
  expires_at TIMESTAMP(6) NOT NULL,
  used_at TIMESTAMP(6) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX idx_enrollment_tokens_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS servers (
  id CHAR(36) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  certificate_serial VARCHAR(128) NOT NULL UNIQUE,
  inventory_json LONGTEXT NOT NULL,
  agent_version VARCHAR(64) NOT NULL DEFAULT '',
  module_version VARCHAR(64) NOT NULL DEFAULT '',
  policy_revision VARCHAR(128) NOT NULL DEFAULT '',
  policy_hash CHAR(64) NOT NULL DEFAULT '',
  status VARCHAR(32) NOT NULL DEFAULT 'ENROLLED',
  last_heartbeat_at TIMESTAMP(6) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  INDEX idx_servers_heartbeat (last_heartbeat_at),
  INDEX idx_servers_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS package_bundles (
  bundle_version VARCHAR(128) PRIMARY KEY,
  source_commit VARCHAR(64) NOT NULL,
  manifest_sha256 CHAR(64) NOT NULL,
  verified_at TIMESTAMP(6) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS package_artifacts (
  id VARCHAR(255) PRIMARY KEY,
  bundle_version VARCHAR(128) NOT NULL,
  kind VARCHAR(32) NOT NULL,
  name VARCHAR(255) NOT NULL,
  version VARCHAR(64) NOT NULL,
  target_json LONGTEXT NOT NULL,
  sha256 CHAR(64) NOT NULL,
  image_path VARCHAR(1024) NOT NULL,
  rollback_id VARCHAR(255) NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_package_artifacts_bundle FOREIGN KEY (bundle_version) REFERENCES package_bundles(bundle_version),
  INDEX idx_package_artifacts_target (kind, name, version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS policy_revisions (
  id CHAR(36) PRIMARY KEY,
  revision_name VARCHAR(255) NOT NULL,
  mode VARCHAR(32) NOT NULL,
  artifact_path VARCHAR(1024) NOT NULL,
  artifact_sha256 CHAR(64) NOT NULL,
  artifact_signature TEXT NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS desired_states (
  server_id CHAR(36) PRIMARY KEY,
  policy_revision_id CHAR(36) NULL,
  agent_package_id VARCHAR(255) NULL,
  module_package_id VARCHAR(255) NULL,
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_desired_server FOREIGN KEY (server_id) REFERENCES servers(id),
  CONSTRAINT fk_desired_policy FOREIGN KEY (policy_revision_id) REFERENCES policy_revisions(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS package_deployments (
  id CHAR(36) PRIMARY KEY,
  server_id CHAR(36) NOT NULL,
  agent_package_id VARCHAR(255) NOT NULL,
  module_package_id VARCHAR(255) NOT NULL,
  status VARCHAR(32) NOT NULL,
  detail TEXT NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_package_deployment_server FOREIGN KEY (server_id) REFERENCES servers(id),
  INDEX idx_package_deployments_server (server_id, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS event_ingest_batches (
  agent_id CHAR(36) NOT NULL,
  batch_id VARCHAR(128) NOT NULL,
  event_count INT UNSIGNED NOT NULL,
  committed_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  PRIMARY KEY (agent_id, batch_id),
  CONSTRAINT fk_event_batch_server FOREIGN KEY (agent_id) REFERENCES servers(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS security_events (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  agent_id CHAR(36) NOT NULL,
  batch_id VARCHAR(128) NOT NULL,
  event_id VARCHAR(128) NOT NULL,
  occurred_at TIMESTAMP(6) NOT NULL,
  transaction_id VARCHAR(255) NOT NULL DEFAULT '',
  service VARCHAR(255) NOT NULL DEFAULT '',
  method VARCHAR(16) NOT NULL DEFAULT '',
  uri VARCHAR(2048) NOT NULL DEFAULT '',
  status_code SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  rule_id VARCHAR(64) NOT NULL DEFAULT '',
  message VARCHAR(2048) NOT NULL DEFAULT '',
  severity VARCHAR(32) NOT NULL DEFAULT '',
  blocked BOOLEAN NOT NULL DEFAULT FALSE,
  policy_revision VARCHAR(128) NOT NULL DEFAULT '',
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_security_events_server FOREIGN KEY (agent_id) REFERENCES servers(id),
  UNIQUE KEY uq_security_event (agent_id, event_id),
  INDEX idx_security_events_time (occurred_at),
  INDEX idx_security_events_server_time (agent_id, occurred_at),
  INDEX idx_security_events_rule_time (rule_id, occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_audit_logs (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  request_id CHAR(36) NOT NULL,
  actor VARCHAR(255) NOT NULL,
  action VARCHAR(255) NOT NULL,
  target VARCHAR(512) NOT NULL,
  result VARCHAR(32) NOT NULL,
  remote_addr VARCHAR(255) NOT NULL,
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  INDEX idx_admin_audit_created (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
