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

type GroupRecord struct {
	ID             string
	EnterpriseID   string
	EnterpriseName string
	Name           string
	Members        []ServerRecord
	CreatedAt      time.Time
}

type PolicyRecord struct {
	ID              string
	EnterpriseName  string
	Name            string
	Description     string
	Mode            string
	Settings        PolicySettings
	TargetCount     int
	PendingCount    int
	AppliedCount    int
	FailedCount     int
	SupersededCount int
	CreatedAt       time.Time
}

func (s *Store) AuthorizeAgent(ctx context.Context, serverID string, certificate *x509.Certificate) error {
	if certificate == nil || serverID == "" {
		return sql.ErrNoRows
	}
	serial := hex.EncodeToString(certificate.SerialNumber.Bytes())
	var currentSerial string
	err := s.db.QueryRowContext(ctx, `SELECT certificate_serial FROM servers WHERE id=? AND revoked_at IS NULL`, serverID).Scan(&currentSerial)
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
	result, err := s.db.ExecContext(ctx, `UPDATE servers SET revoked_at=UTC_TIMESTAMP(6),revoked_by=?,status='REVOKED' WHERE id=? AND revoked_at IS NULL AND (?='' OR enterprise_id=?)`, userID, serverID, enterpriseID, enterpriseID)
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
	return nil
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
	result, err := s.db.ExecContext(ctx, `UPDATE package_deployments SET status=?,detail=?,updated_at=UTC_TIMESTAMP(6) WHERE id=? AND server_id=? AND status<>'SUPERSEDED'`, status, detail, deploymentID, serverID)
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
	if _, err := tx.ExecContext(ctx, `INSERT INTO package_deployments(id,server_id,agent_package_id,module_package_id,status,detail,requested_by) VALUES (?,?,?,?,'PENDING','',NULLIF(?,''))`, id, serverID, agentID, moduleID, userID); err != nil {
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

func (s *Store) AssignPolicyToServers(ctx context.Context, enterpriseID string, serverIDs []string, revisionID, name, description, mode, settingsJSON, artifactPath, hash, signature, userID string) error {
	if enterpriseID == "" || len(serverIDs) == 0 {
		return errors.New("enterprise and target servers are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_revisions(id,enterprise_id,revision_name,description,mode,settings_json,artifact_path,artifact_sha256,artifact_signature) VALUES (?,?,?,?,?,?,?,?,?)`, revisionID, enterpriseID, name, description, mode, settingsJSON, artifactPath, hash, signature); err != nil {
		return err
	}
	for _, serverID := range serverIDs {
		var accessible int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM servers WHERE id=? AND enterprise_id=? AND revoked_at IS NULL`, serverID, enterpriseID).Scan(&accessible); err != nil {
			return err
		}
		if accessible != 1 {
			return fmt.Errorf("server %s: %w", serverID, sql.ErrNoRows)
		}
		if _, err := tx.ExecContext(ctx, `UPDATE policy_deployments SET status='SUPERSEDED',detail='새 정책 배포로 대체됨',updated_at=UTC_TIMESTAMP(6) WHERE server_id=? AND status='PENDING'`, serverID); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `UPDATE desired_states SET policy_revision_id=? WHERE server_id=?`, revisionID, serverID)
		if err != nil {
			return err
		}
		if changed, err := result.RowsAffected(); err != nil || changed != 1 {
			if err != nil {
				return err
			}
			return fmt.Errorf("server %s desired state: %w", serverID, sql.ErrNoRows)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_deployments(id,server_id,policy_revision_id,status,detail,requested_by) VALUES (?,?,?,'PENDING','',NULLIF(?,''))`, randomID(), serverID, revisionID, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListPolicies(ctx context.Context, enterpriseID string, limit int) ([]PolicyRecord, error) {
	query := `SELECT pr.id,COALESCE(e.name,'미지정'),pr.revision_name,pr.description,pr.mode,pr.settings_json,
COUNT(pd.id),COALESCE(SUM(pd.status='PENDING'),0),COALESCE(SUM(pd.status='APPLIED'),0),COALESCE(SUM(pd.status='FAILED'),0),COALESCE(SUM(pd.status='SUPERSEDED'),0),pr.created_at
FROM policy_revisions pr LEFT JOIN enterprises e ON e.id=pr.enterprise_id LEFT JOIN policy_deployments pd ON pd.policy_revision_id=pr.id`
	args := make([]any, 0, 2)
	if enterpriseID != "" {
		query += ` WHERE pr.enterprise_id=?`
		args = append(args, enterpriseID)
	}
	query += ` GROUP BY pr.id,e.name,pr.revision_name,pr.description,pr.mode,pr.settings_json,pr.created_at ORDER BY pr.created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PolicyRecord, 0)
	for rows.Next() {
		var item PolicyRecord
		var settings sql.NullString
		if err := rows.Scan(&item.ID, &item.EnterpriseName, &item.Name, &item.Description, &item.Mode, &settings, &item.TargetCount, &item.PendingCount, &item.AppliedCount, &item.FailedCount, &item.SupersededCount, &item.CreatedAt); err != nil {
			return nil, err
		}
		if settings.Valid {
			_ = json.Unmarshal([]byte(settings.String), &item.Settings)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ResolvePolicyTarget(ctx context.Context, scopeEnterpriseID, target string) (string, []string, error) {
	kind, id, ok := strings.Cut(target, ":")
	if !ok || id == "" {
		return "", nil, errors.New("invalid policy target")
	}
	switch kind {
	case "server":
		server, err := s.ServerByID(ctx, scopeEnterpriseID, id)
		if err != nil || server.Revoked {
			return "", nil, sql.ErrNoRows
		}
		return server.EnterpriseID, []string{server.ID}, nil
	case "group":
		var enterpriseID string
		err := s.db.QueryRowContext(ctx, `SELECT enterprise_id FROM server_groups WHERE id=? AND (?='' OR enterprise_id=?)`, id, scopeEnterpriseID, scopeEnterpriseID).Scan(&enterpriseID)
		if err != nil {
			return "", nil, err
		}
		rows, err := s.db.QueryContext(ctx, `SELECT gm.server_id FROM server_group_members gm JOIN servers s ON s.id=gm.server_id WHERE gm.group_id=? AND s.revoked_at IS NULL ORDER BY s.name`, id)
		if err != nil {
			return "", nil, err
		}
		defer rows.Close()
		ids := make([]string, 0)
		for rows.Next() {
			var serverID string
			if err := rows.Scan(&serverID); err != nil {
				return "", nil, err
			}
			ids = append(ids, serverID)
		}
		if err := rows.Err(); err != nil {
			return "", nil, err
		}
		if len(ids) == 0 {
			return "", nil, errors.New("server group has no active members")
		}
		return enterpriseID, ids, nil
	default:
		return "", nil, errors.New("invalid policy target")
	}
}

func (s *Store) ListGroups(ctx context.Context, enterpriseID string) ([]GroupRecord, error) {
	query := `SELECT g.id,g.enterprise_id,e.name,g.name,g.created_at FROM server_groups g JOIN enterprises e ON e.id=g.enterprise_id`
	args := make([]any, 0, 1)
	if enterpriseID != "" {
		query += ` WHERE g.enterprise_id=?`
		args = append(args, enterpriseID)
	}
	query += ` ORDER BY e.name,g.name`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	groups := make([]GroupRecord, 0)
	for rows.Next() {
		var group GroupRecord
		if err := rows.Scan(&group.ID, &group.EnterpriseID, &group.EnterpriseName, &group.Name, &group.CreatedAt); err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range groups {
		members, err := s.groupMembers(ctx, groups[i].ID)
		if err != nil {
			return nil, err
		}
		groups[i].Members = members
	}
	return groups, nil
}

func (s *Store) groupMembers(ctx context.Context, groupID string) ([]ServerRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT s.id,s.enterprise_id,e.name,s.name,s.status,s.inventory_json,s.policy_revision,s.revoked_at IS NOT NULL,s.last_heartbeat_at,s.created_at
FROM server_group_members gm JOIN servers s ON s.id=gm.server_id JOIN enterprises e ON e.id=s.enterprise_id
WHERE gm.group_id=? ORDER BY s.name`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ServerRecord, 0)
	for rows.Next() {
		var item ServerRecord
		var inventory []byte
		if err := rows.Scan(&item.ID, &item.EnterpriseID, &item.EnterpriseName, &item.Name, &item.Status, &inventory, &item.PolicyRevision, &item.Revoked, &item.LastHeartbeatAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(inventory, &item.Inventory)
		markServerOffline(&item, time.Now().UTC())
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) SaveGroup(ctx context.Context, scopeEnterpriseID, groupID, enterpriseID, name, userID string, serverIDs []string) (string, error) {
	if scopeEnterpriseID != "" {
		enterpriseID = scopeEnterpriseID
	}
	if enterpriseID == "" || name == "" {
		return "", errors.New("enterprise and group name are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if groupID == "" {
		groupID = randomID()
		if _, err := tx.ExecContext(ctx, `INSERT INTO server_groups(id,enterprise_id,name,created_by) VALUES (?,?,?,?)`, groupID, enterpriseID, name, userID); err != nil {
			return "", err
		}
	} else {
		var accessible int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM server_groups WHERE id=? AND enterprise_id=?`, groupID, enterpriseID).Scan(&accessible); err != nil {
			return "", err
		}
		if accessible != 1 {
			return "", sql.ErrNoRows
		}
		if _, err := tx.ExecContext(ctx, `UPDATE server_groups SET name=? WHERE id=?`, name, groupID); err != nil {
			return "", err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM server_group_members WHERE group_id=?`, groupID); err != nil {
			return "", err
		}
	}
	seen := make(map[string]bool)
	for _, serverID := range serverIDs {
		if seen[serverID] {
			continue
		}
		seen[serverID] = true
		var accessible int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM servers WHERE id=? AND enterprise_id=? AND revoked_at IS NULL`, serverID, enterpriseID).Scan(&accessible); err != nil {
			return "", err
		}
		if accessible != 1 {
			return "", fmt.Errorf("server %s is outside the group enterprise", serverID)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO server_group_members(group_id,server_id) VALUES (?,?)`, groupID, serverID); err != nil {
			return "", err
		}
	}
	return groupID, tx.Commit()
}

func (s *Store) DeleteGroup(ctx context.Context, scopeEnterpriseID, groupID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM server_groups WHERE id=? AND (?='' OR enterprise_id=?)`, groupID, scopeEnterpriseID, scopeEnterpriseID)
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
	return nil
}
