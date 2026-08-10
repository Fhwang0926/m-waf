package manager

import (
	"context"
	"database/sql"
	"errors"
)

func (s *Store) ListPolicyServerIDs(ctx context.Context, enterpriseID, policyID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT eps.server_id
FROM enterprise_policy_servers eps
JOIN enterprise_policies ep ON ep.id=eps.enterprise_policy_id
JOIN servers s ON s.id=eps.server_id
WHERE eps.enterprise_policy_id=? AND ep.enterprise_id=? AND s.enterprise_id=ep.enterprise_id AND s.revoked_at IS NULL
ORDER BY s.name,s.id`, policyID, enterpriseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (s *Store) ListPolicyServers(ctx context.Context, enterpriseID, policyID string) ([]ServerRecord, error) {
	servers, err := s.ListServers(ctx, enterpriseID, systemPolicyServerLimit)
	if err != nil {
		return nil, err
	}
	items := make([]ServerRecord, 0)
	for _, server := range servers {
		if server.EnterprisePolicyID == policyID && !server.Revoked {
			items = append(items, server)
		}
	}
	return items, nil
}

func (s *Store) ValidatePolicyServerIDs(ctx context.Context, scopeEnterpriseID, enterpriseID string, serverIDs []string) (string, []string, error) {
	if scopeEnterpriseID != "" {
		enterpriseID = scopeEnterpriseID
	}
	if enterpriseID == "" {
		return "", nil, errors.New("enterprise is required")
	}
	servers, err := s.ListServers(ctx, enterpriseID, systemPolicyServerLimit)
	if err != nil {
		return "", nil, err
	}
	allowed := make(map[string]bool, len(servers))
	for _, server := range servers {
		if !server.Revoked {
			allowed[server.ID] = true
		}
	}
	seen := make(map[string]bool, len(serverIDs))
	validated := make([]string, 0, len(serverIDs))
	for _, serverID := range serverIDs {
		if serverID == "" || seen[serverID] {
			continue
		}
		if !allowed[serverID] {
			return "", nil, sql.ErrNoRows
		}
		seen[serverID] = true
		validated = append(validated, serverID)
	}
	if len(validated) == 0 {
		return "", nil, errors.New("at least one active server is required")
	}
	return enterpriseID, validated, nil
}

func validatePolicyRolloutServersTx(ctx context.Context, tx *sql.Tx, enterpriseID string, serverIDs []string) ([]string, error) {
	seen := make(map[string]bool, len(serverIDs))
	validated := make([]string, 0, len(serverIDs))
	for _, serverID := range serverIDs {
		if serverID == "" || seen[serverID] {
			continue
		}
		seen[serverID] = true
		var accessible int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM servers s JOIN desired_states ds ON ds.server_id=s.id
WHERE s.id=? AND s.enterprise_id=? AND s.revoked_at IS NULL`, serverID, enterpriseID).Scan(&accessible); err != nil {
			return nil, err
		}
		if accessible != 1 {
			return nil, sql.ErrNoRows
		}
		validated = append(validated, serverID)
	}
	if len(validated) == 0 {
		return nil, errors.New("at least one active server is required")
	}
	return validated, nil
}

func ensureNoActivePolicyRolloutsTx(ctx context.Context, tx *sql.Tx, serverIDs []string, excludedRolloutID string) error {
	for _, serverID := range serverIDs {
		var active int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
FROM policy_rollout_targets t JOIN policy_rollouts r ON r.id=t.rollout_id
WHERE t.server_id=? AND r.status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED')
  AND (?='' OR r.id<>?)`, serverID, excludedRolloutID, excludedRolloutID).Scan(&active); err != nil {
			return err
		}
		if active != 0 {
			return errors.New("server already has an active policy rollout")
		}
	}
	return nil
}

func (s *Store) CreatePolicyMembershipRollout(ctx context.Context, policy EnterprisePolicyRecord, userID string, serverIDs []string) (string, int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", 0, err
	}
	defer tx.Rollback()
	if err := lockActiveEnterprise(ctx, tx, policy.EnterpriseID); err != nil {
		return "", 0, err
	}
	var currentRevisionID, currentSystemPolicyID string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(current_revision_id,''),COALESCE(current_system_policy_version_id,'')
FROM enterprise_policies WHERE id=? AND enterprise_id=? AND status='ACTIVE' FOR UPDATE`, policy.ID, policy.EnterpriseID).Scan(&currentRevisionID, &currentSystemPolicyID); err != nil {
		return "", 0, err
	}
	if currentRevisionID == "" || currentSystemPolicyID == "" {
		return "", 0, errors.New("protection policy has no deployable revision")
	}
	validated, err := validatePolicyRolloutServersTx(ctx, tx, policy.EnterpriseID, serverIDs)
	if err != nil {
		return "", 0, err
	}
	selected := make([]string, 0, len(validated))
	for _, serverID := range validated {
		var assignedPolicyID sql.NullString
		err := tx.QueryRowContext(ctx, `SELECT enterprise_policy_id FROM enterprise_policy_servers WHERE server_id=? FOR UPDATE`, serverID).Scan(&assignedPolicyID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return "", 0, err
		}
		if assignedPolicyID.String != policy.ID {
			selected = append(selected, serverID)
		}
	}
	if len(selected) == 0 {
		return "", 0, nil
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_rollouts
WHERE enterprise_policy_id=? AND status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED')`, policy.ID).Scan(&active); err != nil {
		return "", 0, err
	}
	if active != 0 {
		return "", 0, errors.New("enterprise policy already has an active rollout")
	}
	if err := ensureNoActivePolicyRolloutsTx(ctx, tx, selected, ""); err != nil {
		return "", 0, err
	}
	rolloutID := randomID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_rollouts(id,enterprise_policy_id,rollout_type,status,from_revision_id,target_system_policy_version_id,target_revision_id,expected_revision_id,batch_size,requested_by,approved_by,detail)
VALUES (?,?,'SEED','QUEUED',?,?,?,?,25,NULLIF(?,''),NULLIF(?,''),'')`, rolloutID, policy.ID, currentRevisionID, currentSystemPolicyID, currentRevisionID, currentRevisionID, userID, userID); err != nil {
		return "", 0, err
	}
	if err := insertRolloutTargetsTx(ctx, tx, rolloutID, currentRevisionID, selected); err != nil {
		return "", 0, err
	}
	return rolloutID, len(selected), tx.Commit()
}

func (s *Store) PolicyRevisionSystemVersion(ctx context.Context, enterpriseID, revisionID string) (string, error) {
	var systemVersionID string
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(pr.system_policy_version_id,'')
FROM policy_revisions pr JOIN enterprise_policies ep ON ep.id=pr.enterprise_policy_id
WHERE pr.id=? AND ep.enterprise_id=?`, revisionID, enterpriseID).Scan(&systemVersionID)
	return systemVersionID, err
}

func (s *Store) PolicyRevisionOwner(ctx context.Context, enterpriseID, revisionID string) (string, string, error) {
	var policyID, systemVersionID string
	err := s.db.QueryRowContext(ctx, `SELECT ep.id,COALESCE(pr.system_policy_version_id,'')
FROM policy_revisions pr JOIN enterprise_policies ep ON ep.id=pr.enterprise_policy_id
WHERE pr.id=? AND ep.enterprise_id=?`, revisionID, enterpriseID).Scan(&policyID, &systemVersionID)
	return policyID, systemVersionID, err
}

func (s *Store) RestoreUnassignedPolicyAfterFailedMove(ctx context.Context, rolloutID, enterpriseID, serverID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var valid int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*)
FROM policy_rollout_targets t
JOIN policy_rollouts r ON r.id=t.rollout_id
JOIN enterprise_policies ep ON ep.id=r.enterprise_policy_id
JOIN servers s ON s.id=t.server_id
LEFT JOIN enterprise_policy_servers eps ON eps.server_id=s.id
WHERE t.rollout_id=? AND t.server_id=? AND r.rollout_type='SEED' AND t.status='FAILED'
  AND t.source_revision_id IS NULL AND ep.enterprise_id=? AND s.enterprise_id=ep.enterprise_id
  AND eps.server_id IS NULL`, rolloutID, serverID, enterpriseID).Scan(&valid); err != nil {
		return err
	}
	if valid != 1 {
		return errors.New("failed move no longer represents an unassigned server")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_deployments
SET status='SUPERSEDED',detail='보호 정책 이동 실패로 미배정 안전 상태 복구',updated_at=UTC_TIMESTAMP(6)
WHERE server_id=? AND status='PENDING'`, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE desired_states SET policy_revision_id=NULL WHERE server_id=?`, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_rollout_targets
SET status='ROLLED_BACK',detail='보호 정책 이동 실패로 미배정 안전 상태를 유지함'
WHERE rollout_id=? AND server_id=?`, rolloutID, serverID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) RestorePolicyRevisionAfterFailedMove(ctx context.Context, rolloutID, enterpriseID, serverID, sourceRevisionID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var sourceAgentID, sourceModuleID, requestedBy sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT t.source_agent_package_id,t.source_module_package_id,r.requested_by
FROM policy_rollout_targets t
JOIN policy_rollouts r ON r.id=t.rollout_id
JOIN enterprise_policies target_policy ON target_policy.id=r.enterprise_policy_id
JOIN policy_revisions source_revision ON source_revision.id=t.source_revision_id
JOIN enterprise_policies source_policy ON source_policy.id=source_revision.enterprise_policy_id
JOIN enterprise_policy_servers eps ON eps.server_id=t.server_id AND eps.enterprise_policy_id=source_policy.id
JOIN servers s ON s.id=t.server_id
WHERE t.rollout_id=? AND t.server_id=? AND r.rollout_type='SEED' AND t.status='FAILED'
  AND t.source_revision_id=? AND target_policy.enterprise_id=? AND source_policy.enterprise_id=target_policy.enterprise_id
  AND s.enterprise_id=target_policy.enterprise_id AND s.revoked_at IS NULL
FOR UPDATE`, rolloutID, serverID, sourceRevisionID, enterpriseID).Scan(&sourceAgentID, &sourceModuleID, &requestedBy); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_deployments
SET status='SUPERSEDED',detail='보호 정책 이동 실패 복구로 대체됨',updated_at=UTC_TIMESTAMP(6)
WHERE server_id=? AND status='PENDING'`, serverID); err != nil {
		return err
	}
	if sourceAgentID.Valid && sourceAgentID.String != "" && sourceModuleID.Valid && sourceModuleID.String != "" {
		if _, err := tx.ExecContext(ctx, `UPDATE package_deployments
SET status='SUPERSEDED',detail='보호 정책 이동 실패 복구로 대체됨',updated_at=UTC_TIMESTAMP(6)
WHERE server_id=? AND status='PENDING'`, serverID); err != nil {
			return err
		}
		packageDeploymentID := randomID()
		if _, err := tx.ExecContext(ctx, `INSERT INTO package_deployments(id,server_id,agent_package_id,module_package_id,status,detail,requested_by,rollout_id)
VALUES (?,?,?,?,'PENDING','기존 보호 정책 패키지 복구',NULLIF(?,''),?)`, packageDeploymentID, serverID, sourceAgentID, sourceModuleID, requestedBy, rolloutID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE desired_states
SET agent_package_id=?,module_package_id=?,package_deployment_id=? WHERE server_id=?`, sourceAgentID, sourceModuleID, packageDeploymentID, serverID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE desired_states SET policy_revision_id=? WHERE server_id=?`, sourceRevisionID, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_deployments(id,server_id,policy_revision_id,status,detail,requested_by,rollout_id)
VALUES (?,?,?,'PENDING','기존 보호 정책 개정본 복구',NULLIF(?,''),?)
ON DUPLICATE KEY UPDATE status='PENDING',detail=VALUES(detail),requested_by=VALUES(requested_by),rollout_id=VALUES(rollout_id),updated_at=UTC_TIMESTAMP(6)`, randomID(), serverID, sourceRevisionID, requestedBy, rolloutID); err != nil {
		return err
	}
	return tx.Commit()
}
