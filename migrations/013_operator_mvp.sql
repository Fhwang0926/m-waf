CREATE TABLE IF NOT EXISTS security_incidents (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
  enterprise_id CHAR(36) NOT NULL,
  agent_id CHAR(36) NOT NULL,
  incident_key VARCHAR(128) NOT NULL,
  occurred_at TIMESTAMP(6) NOT NULL,
  category VARCHAR(32) NOT NULL DEFAULT 'OTHER',
  client_ip VARBINARY(16) NULL,
  country_code CHAR(2) NOT NULL DEFAULT 'ZZ',
  method VARCHAR(16) NOT NULL DEFAULT '',
  uri VARCHAR(2048) NOT NULL DEFAULT '',
  status_code SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  blocked BOOLEAN NOT NULL DEFAULT FALSE,
  primary_event_id BIGINT UNSIGNED NULL,
  policy_revision VARCHAR(128) NOT NULL DEFAULT '',
  created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  UNIQUE KEY uq_security_incident (agent_id, incident_key),
  INDEX idx_security_incident_enterprise_time (enterprise_id, occurred_at, id),
  INDEX idx_security_incident_server_time (agent_id, occurred_at, id),
  INDEX idx_security_incident_category_time (enterprise_id, category, occurred_at, id),
  INDEX idx_security_incident_ip_time (enterprise_id, client_ip, occurred_at, id),
  CONSTRAINT fk_security_incident_enterprise FOREIGN KEY (enterprise_id) REFERENCES enterprises(id),
  CONSTRAINT fk_security_incident_server FOREIGN KEY (agent_id) REFERENCES servers(id),
  CONSTRAINT chk_security_incident_category CHECK (category IN ('HTTP_PROTOCOL','INJECTION','XSS','FILE_PATH','SCANNER_BOT','OTHER'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE security_events
  ADD COLUMN IF NOT EXISTS incident_id BIGINT UNSIGNED NULL AFTER id,
  ADD COLUMN IF NOT EXISTS request_id VARCHAR(128) NOT NULL DEFAULT '' AFTER event_id,
  ADD COLUMN IF NOT EXISTS client_ip VARBINARY(16) NULL AFTER request_id,
  ADD COLUMN IF NOT EXISTS matched_variable VARCHAR(512) NOT NULL DEFAULT '' AFTER message,
  ADD COLUMN IF NOT EXISTS rule_tags_json LONGTEXT NULL AFTER matched_variable,
  ADD INDEX IF NOT EXISTS idx_security_event_incident (incident_id, occurred_at);

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='security_events' AND CONSTRAINT_NAME='fk_security_event_incident'),
  'DO 0',
  'ALTER TABLE security_events ADD CONSTRAINT fk_security_event_incident FOREIGN KEY (incident_id) REFERENCES security_incidents(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

CREATE TABLE IF NOT EXISTS policy_configuration_ip_rules (
  id CHAR(36) PRIMARY KEY,
  configuration_id CHAR(36) NOT NULL,
  source_scope VARCHAR(16) NOT NULL,
  action_type VARCHAR(16) NOT NULL,
  network_cidr VARCHAR(64) NOT NULL,
  generated_rule_id INT UNSIGNED NOT NULL,
  reason VARCHAR(1024) NOT NULL,
  expires_at TIMESTAMP(6) NULL,
  created_by VARCHAR(255) NOT NULL DEFAULT '',
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  order_no INT UNSIGNED NOT NULL,
  UNIQUE KEY uq_policy_ip_rule_order (configuration_id, order_no),
  UNIQUE KEY uq_policy_ip_rule_network (configuration_id, action_type, network_cidr),
  UNIQUE KEY uq_policy_ip_rule_generated (configuration_id, generated_rule_id),
  CONSTRAINT fk_policy_ip_rule_configuration FOREIGN KEY (configuration_id) REFERENCES policy_configurations(id) ON DELETE CASCADE,
  CONSTRAINT chk_policy_ip_rule_scope CHECK (source_scope IN ('SYSTEM','ENTERPRISE')),
  CONSTRAINT chk_policy_ip_rule_action CHECK (action_type IN ('BLOCK','TRUST'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE system_policy_versions
  ADD COLUMN IF NOT EXISTS hot_rule_set_version VARCHAR(64) NOT NULL DEFAULT '' AFTER source_commit,
  ADD COLUMN IF NOT EXISTS hot_rule_set_sha256 CHAR(64) NOT NULL DEFAULT '' AFTER hot_rule_set_version;
