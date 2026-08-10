package manager

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
)

const packageDeploymentPlanPrefix = "mwaf-plan-v1:"

type packageDeploymentPlan struct {
	WebServerControl string `json:"web_server_control"`
	Detail           string `json:"detail,omitempty"`
}

func encodePackageDeploymentPlan(controlMode string) (string, error) {
	controlMode = model.NormalizeWebServerControl(controlMode)
	if controlMode == model.WebServerControlStandard {
		return "", nil
	}
	if controlMode != model.WebServerControlHooks {
		return "", fmt.Errorf("unsupported web-server control mode %q", controlMode)
	}
	raw, err := json.Marshal(packageDeploymentPlan{WebServerControl: controlMode})
	if err != nil {
		return "", err
	}
	return packageDeploymentPlanPrefix + string(raw), nil
}

func decodePackageDeploymentPlan(detail string) packageDeploymentPlan {
	if !strings.HasPrefix(detail, packageDeploymentPlanPrefix) {
		return packageDeploymentPlan{WebServerControl: model.WebServerControlStandard}
	}
	var plan packageDeploymentPlan
	if json.Unmarshal([]byte(strings.TrimPrefix(detail, packageDeploymentPlanPrefix)), &plan) != nil {
		return packageDeploymentPlan{WebServerControl: model.WebServerControlStandard}
	}
	plan.WebServerControl = model.NormalizeWebServerControl(plan.WebServerControl)
	return plan
}

func encodePackageDeploymentResult(plan packageDeploymentPlan, detail string) (string, error) {
	if model.NormalizeWebServerControl(plan.WebServerControl) != model.WebServerControlHooks {
		return detail, nil
	}
	plan.WebServerControl = model.WebServerControlHooks
	plan.Detail = detail
	raw, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	return packageDeploymentPlanPrefix + string(raw), nil
}

func packageDeploymentDisplayDetail(detail string) string {
	if !strings.HasPrefix(detail, packageDeploymentPlanPrefix) {
		return detail
	}
	return decodePackageDeploymentPlan(detail).Detail
}

func (s *Store) AuthorizeAgent(ctx context.Context, serverID string, certificate *x509.Certificate) error {
	if certificate == nil || serverID == "" {
		return sql.ErrNoRows
	}
	serial := hex.EncodeToString(certificate.SerialNumber.Bytes())
	var currentSerial string
	err := s.db.QueryRowContext(ctx, `SELECT s.certificate_serial
FROM servers s LEFT JOIN enterprises e ON e.id=s.enterprise_id
WHERE s.id=? AND s.revoked_at IS NULL AND (s.enterprise_id IS NULL OR e.status='ACTIVE')`, serverID).Scan(&currentSerial)
	if err != nil {
		return err
	}
	if currentSerial == serial {
		return nil
	}
	// A renewed certificate becomes authoritative on its first authenticated
	// request. Until then the stored certificate remains valid, so a lost renewal
	// response cannot strand the Agent. The short window prevents an arbitrary
	// older certificate for the same identity from replacing the active one.
	now := time.Now().UTC()
	if certificate.NotAfter.After(now) && certificate.NotBefore.After(now.Add(-20*time.Minute)) {
		result, err := s.db.ExecContext(ctx, `UPDATE servers SET certificate_serial=? WHERE id=? AND certificate_serial=? AND revoked_at IS NULL`, serial, serverID, currentSerial)
		if err != nil {
			return err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if changed == 1 {
			return nil
		}
	}
	return sql.ErrNoRows
}

func (s *Store) ServerByID(ctx context.Context, enterpriseID, serverID string) (ServerRecord, error) {
	var item ServerRecord
	var inventory []byte
	err := s.db.QueryRowContext(ctx, `SELECT s.id,COALESCE(s.enterprise_id,''),COALESCE(e.name,'미지정'),s.name,s.status,s.inventory_json,s.policy_revision,s.revoked_at IS NOT NULL,s.last_heartbeat_at,s.created_at
FROM servers s LEFT JOIN enterprises e ON e.id=s.enterprise_id
WHERE s.id=? AND (?='' OR s.enterprise_id=?)`, serverID, enterpriseID, enterpriseID).Scan(
		&item.ID, &item.EnterpriseID, &item.EnterpriseName, &item.Name, &item.Status, &inventory, &item.PolicyRevision, &item.Revoked, &item.LastHeartbeatAt, &item.CreatedAt,
	)
	if err != nil {
		return item, err
	}
	_ = json.Unmarshal(inventory, &item.Inventory)
	markServerOffline(&item, time.Now().UTC())
	return item, nil
}

func (s *Store) RevokeServer(ctx context.Context, enterpriseID, serverID, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE servers SET revoked_at=UTC_TIMESTAMP(6),revoked_by=?,status='REVOKED' WHERE id=? AND revoked_at IS NULL AND (?='' OR enterprise_id=?)`, userID, serverID, enterpriseID, enterpriseID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM enterprise_policy_servers WHERE server_id=?`, serverID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UnregisterAgent(ctx context.Context, serverID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE servers SET revoked_at=UTC_TIMESTAMP(6),revoked_by=NULL,status='REVOKED' WHERE id=? AND revoked_at IS NULL`, serverID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM enterprise_policy_servers WHERE server_id=?`, serverID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) QueueCommand(ctx context.Context, enterpriseID, serverID, command, userID string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var lockedID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM servers WHERE id=? AND revoked_at IS NULL AND (?='' OR enterprise_id=?) FOR UPDATE`, serverID, enterpriseID, enterpriseID).Scan(&lockedID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", sql.ErrNoRows
		}
		return "", err
	}
	if lockedID == "" {
		return "", sql.ErrNoRows
	}
	var pending int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_commands WHERE server_id=? AND status IN ('PENDING','ACCEPTED')`, serverID).Scan(&pending); err != nil {
		return "", err
	}
	if pending != 0 {
		return "", errors.New("server already has a pending command")
	}
	id := randomID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO agent_commands(id,server_id,command,status,detail,requested_by) VALUES (?,?,?,'PENDING','',?)`, id, serverID, command, userID); err != nil {
		return "", err
	}
	return id, tx.Commit()
}

func (s *Store) NextCommand(ctx context.Context, serverID string) (model.AgentCommand, error) {
	var command model.AgentCommand
	err := s.db.QueryRowContext(ctx, `SELECT id,command FROM agent_commands WHERE server_id=? AND status IN ('PENDING','ACCEPTED') ORDER BY created_at LIMIT 1`, serverID).Scan(&command.ID, &command.Command)
	if errors.Is(err, sql.ErrNoRows) {
		return model.AgentCommand{}, nil
	}
	return command, err
}

func (s *Store) UpdateCommandResult(ctx context.Context, serverID, commandID, status, detail string) error {
	var result sql.Result
	var err error
	if status == "ACCEPTED" {
		result, err = s.db.ExecContext(ctx, `UPDATE agent_commands SET status='ACCEPTED',detail=?,acknowledged_at=UTC_TIMESTAMP(6),updated_at=UTC_TIMESTAMP(6) WHERE id=? AND server_id=? AND status='PENDING'`, detail, commandID, serverID)
	} else {
		result, err = s.db.ExecContext(ctx, `UPDATE agent_commands SET status='FAILED',detail=?,completed_at=UTC_TIMESTAMP(6),updated_at=UTC_TIMESTAMP(6) WHERE id=? AND server_id=? AND status IN ('PENDING','ACCEPTED')`, detail, commandID, serverID)
	}
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agent_commands WHERE id=? AND server_id=?`, commandID, serverID).Scan(&exists); err != nil {
			return err
		}
		if exists != 1 {
			return sql.ErrNoRows
		}
	}
	return nil
}

func (s *Store) UpdatePolicyDeploymentResult(ctx context.Context, serverID, revisionID, status, detail string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE policy_deployments SET status=?,detail=?,updated_at=UTC_TIMESTAMP(6) WHERE server_id=? AND policy_revision_id=? AND status<>'SUPERSEDED'`, status, detail, serverID, revisionID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_deployments WHERE server_id=? AND policy_revision_id=?`, serverID, revisionID).Scan(&exists); err != nil {
			return err
		}
		if exists != 1 {
			return sql.ErrNoRows
		}
	}
	return nil
}

func (s *Store) UpdatePackageDeploymentResult(ctx context.Context, serverID, deploymentID, status, detail string) error {
	var currentDetail string
	if err := s.db.QueryRowContext(ctx, `SELECT detail FROM package_deployments WHERE id=? AND server_id=?`, deploymentID, serverID).Scan(&currentDetail); err != nil {
		return err
	}
	storedDetail, err := encodePackageDeploymentResult(decodePackageDeploymentPlan(currentDetail), detail)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE package_deployments SET status=?,detail=?,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND server_id=? AND status<>'SUPERSEDED'`, status, storedDetail, deploymentID, serverID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		var exists int
		if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM package_deployments WHERE id=? AND server_id=?`, deploymentID, serverID).Scan(&exists); err != nil {
			return err
		}
		if exists != 1 {
			return sql.ErrNoRows
		}
	}
	return nil
}

func (s *Store) CurrentPackageIDs(ctx context.Context, serverID string) (string, string, error) {
	var agentID, moduleID sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT agent_package_id,module_package_id FROM desired_states WHERE server_id=?`, serverID).Scan(&agentID, &moduleID)
	return agentID.String, moduleID.String, err
}

func (s *Store) AssignPackages(ctx context.Context, enterpriseID, serverID, agentID, moduleID, userID string) (string, error) {
	return s.AssignPackagesWithControl(ctx, enterpriseID, serverID, agentID, moduleID, userID, model.WebServerControlStandard)
}

func (s *Store) AssignPackagesWithControl(ctx context.Context, enterpriseID, serverID, agentID, moduleID, userID, controlMode string) (string, error) {
	planDetail, err := encodePackageDeploymentPlan(controlMode)
	if err != nil {
		return "", err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var accessible int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM servers WHERE id=? AND revoked_at IS NULL AND (?='' OR enterprise_id=?)`, serverID, enterpriseID, enterpriseID).Scan(&accessible); err != nil {
		return "", err
	}
	if accessible != 1 {
		return "", sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE package_deployments SET status='SUPERSEDED',detail='새 배포 요청으로 대체됨',updated_at=UTC_TIMESTAMP(6) WHERE server_id=? AND status='PENDING'`, serverID); err != nil {
		return "", err
	}
	id := randomID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO package_deployments(id,server_id,agent_package_id,module_package_id,status,detail,requested_by) VALUES (?,?,?,?,'PENDING',?,NULLIF(?,''))`, id, serverID, agentID, moduleID, planDetail, userID); err != nil {
		return "", err
	}
	result, err := tx.ExecContext(ctx, `UPDATE desired_states SET agent_package_id=?,module_package_id=?,package_deployment_id=? WHERE server_id=?`, agentID, moduleID, id, serverID)
	if err != nil {
		return "", err
	}
	if changed, err := result.RowsAffected(); err != nil || changed != 1 {
		if err != nil {
			return "", err
		}
		return "", sql.ErrNoRows
	}
	return id, tx.Commit()
}
