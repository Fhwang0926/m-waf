package manager

import (
	"context"
	"database/sql"
	"errors"
)

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
		if _, err := tx.ExecContext(ctx, `UPDATE policy_deployments SET status='SUPERSEDED',detail='기업 정책 우선순위 동기화로 대체됨',updated_at=UTC_TIMESTAMP(6) WHERE server_id=? AND status='PENDING'`, serverID); err != nil {
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
