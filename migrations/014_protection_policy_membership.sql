CREATE TABLE IF NOT EXISTS enterprise_policy_servers (
  server_id CHAR(36) PRIMARY KEY,
  enterprise_policy_id CHAR(36) NOT NULL,
  assigned_by CHAR(36) NULL,
  assigned_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  CONSTRAINT fk_enterprise_policy_servers_server FOREIGN KEY (server_id) REFERENCES servers(id),
  CONSTRAINT fk_enterprise_policy_servers_policy FOREIGN KEY (enterprise_policy_id) REFERENCES enterprise_policies(id),
  CONSTRAINT fk_enterprise_policy_servers_assigner FOREIGN KEY (assigned_by) REFERENCES admin_users(id),
  INDEX idx_enterprise_policy_servers_policy (enterprise_policy_id, server_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

ALTER TABLE policy_rollout_targets
  ADD COLUMN IF NOT EXISTS source_revision_id CHAR(36) NULL AFTER source_module_package_id,
  ADD INDEX IF NOT EXISTS idx_policy_rollout_target_source_revision (source_revision_id);

SET @mwaf_sql = IF(
  EXISTS(SELECT 1 FROM information_schema.TABLE_CONSTRAINTS WHERE CONSTRAINT_SCHEMA=DATABASE() AND TABLE_NAME='policy_rollout_targets' AND CONSTRAINT_NAME='fk_policy_rollout_target_source_revision'),
  'DO 0',
  'ALTER TABLE policy_rollout_targets ADD CONSTRAINT fk_policy_rollout_target_source_revision FOREIGN KEY (source_revision_id) REFERENCES policy_revisions(id)'
);
PREPARE mwaf_stmt FROM @mwaf_sql;
EXECUTE mwaf_stmt;
DEALLOCATE PREPARE mwaf_stmt;

UPDATE policy_rollout_targets t
JOIN policy_rollouts r ON r.id=t.rollout_id
LEFT JOIN desired_states ds ON ds.server_id=t.server_id
SET t.source_revision_id=COALESCE(r.from_revision_id,ds.policy_revision_id)
WHERE t.source_revision_id IS NULL;

INSERT INTO enterprise_policy_servers(server_id,enterprise_policy_id)
SELECT ranked.server_id,ranked.enterprise_policy_id
FROM (
  SELECT s.id AS server_id,ep.id AS enterprise_policy_id,
    ROW_NUMBER() OVER (
      PARTITION BY s.id
      ORDER BY CASE
        WHEN ep.target=CONCAT('server:',s.id) THEN 3
        WHEN ep.target LIKE 'group:%' THEN 2
        ELSE 1
      END DESC,ep.updated_at DESC,ep.id DESC
    ) AS winner_no
  FROM servers s
  JOIN enterprise_policies ep ON ep.enterprise_id=s.enterprise_id
  WHERE s.revoked_at IS NULL
    AND ep.status='ACTIVE'
    AND ep.current_revision_id IS NOT NULL
    AND (
    ep.target=CONCAT('enterprise:',s.enterprise_id)
    OR ep.target=CONCAT('server:',s.id)
    OR (
      ep.target LIKE 'group:%'
      AND EXISTS (
        SELECT 1 FROM server_groups sg
        JOIN server_group_members gm ON gm.group_id=sg.id
        WHERE sg.id=SUBSTRING(ep.target,7)
          AND sg.enterprise_id=ep.enterprise_id
          AND gm.server_id=s.id
      )
    )
  )
) ranked
WHERE ranked.winner_no=1
ON DUPLICATE KEY UPDATE enterprise_policy_id=VALUES(enterprise_policy_id),updated_at=CURRENT_TIMESTAMP(6);
