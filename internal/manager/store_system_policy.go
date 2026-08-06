package manager

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

type ManagedPolicyRecord struct {
	ID           string
	EnterpriseID string
	Name         string
	Description  string
	Mode         string
	Settings     PolicySettings
	CreatedAt    time.Time
}

func (s *Store) ListManagedPolicyBindings(ctx context.Context) ([]ManagedPolicyRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT pr.id,pr.enterprise_id,pr.revision_name,pr.description,pr.mode,pr.settings_json,pr.created_at
FROM policy_revisions pr
WHERE EXISTS(SELECT 1 FROM desired_states ds WHERE ds.policy_revision_id=pr.id)
ORDER BY pr.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]ManagedPolicyRecord, 0)
	for rows.Next() {
		var item ManagedPolicyRecord
		var raw sql.NullString
		if err := rows.Scan(&item.ID, &item.EnterpriseID, &item.Name, &item.Description, &item.Mode, &raw, &item.CreatedAt); err != nil {
			return nil, err
		}
		if raw.Valid {
			if err := json.Unmarshal([]byte(raw.String), &item.Settings); err != nil {
				return nil, fmt.Errorf("decode managed policy %s settings: %w", item.ID, err)
			}
		}
		if item.Settings.TemplateKey == "" || !item.Settings.AutoUpdate || item.Settings.Target == "" {
			continue
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) AssignExistingPolicyToServers(ctx context.Context, enterpriseID string, serverIDs []string, revisionID, userID string) error {
	if enterpriseID == "" || revisionID == "" || len(serverIDs) == 0 {
		return errors.New("enterprise, policy revision and target servers are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var policyExists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_revisions WHERE id=? AND enterprise_id=?`, revisionID, enterpriseID).Scan(&policyExists); err != nil {
		return err
	}
	if policyExists != 1 {
		return sql.ErrNoRows
	}
	for _, serverID := range serverIDs {
		var currentRevision sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT ds.policy_revision_id FROM servers s JOIN desired_states ds ON ds.server_id=s.id WHERE s.id=? AND s.enterprise_id=? AND s.revoked_at IS NULL FOR UPDATE`, serverID, enterpriseID).Scan(&currentRevision); err != nil {
			return err
		}
		if currentRevision.String == revisionID {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE policy_deployments SET status='SUPERSEDED',detail='시스템 정책 동기화로 대체됨',updated_at=UTC_TIMESTAMP(6) WHERE server_id=? AND status='PENDING'`, serverID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE desired_states SET policy_revision_id=? WHERE server_id=?`, revisionID, serverID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_deployments(id,server_id,policy_revision_id,status,detail,requested_by) VALUES (?,?,?,'PENDING','',NULLIF(?,''))
ON DUPLICATE KEY UPDATE status='PENDING',detail='',requested_by=VALUES(requested_by),updated_at=UTC_TIMESTAMP(6)`, randomID(), serverID, revisionID, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
