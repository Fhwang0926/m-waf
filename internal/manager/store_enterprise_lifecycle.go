package manager

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type EnterpriseLifecycleResult string

const (
	EnterpriseDeleted    EnterpriseLifecycleResult = "DELETED"
	EnterpriseTerminated EnterpriseLifecycleResult = "TERMINATED"
)

var ErrEnterpriseNotActive = errors.New("enterprise is not active")
var ErrEnterpriseConfirmation = errors.New("enterprise name confirmation does not match")

func lockActiveEnterprise(ctx context.Context, tx *sql.Tx, enterpriseID string) error {
	var lockedID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM enterprises WHERE id=? AND status='ACTIVE' FOR UPDATE`, enterpriseID).Scan(&lockedID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEnterpriseNotActive
		}
		return err
	}
	return nil
}

func (s *Store) ListEnterpriseManagement(ctx context.Context) ([]EnterpriseRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT e.id,e.name,e.status,e.terminated_at,e.created_at,
  (SELECT COUNT(*) FROM admin_users u WHERE u.enterprise_id=e.id),
  (SELECT COUNT(*) FROM servers srv WHERE srv.enterprise_id=e.id),
  ((SELECT COUNT(*) FROM enterprise_policies ep WHERE ep.enterprise_id=e.id) +
   (SELECT COUNT(*) FROM policy_revisions pr WHERE pr.enterprise_id=e.id AND pr.enterprise_policy_id IS NULL)),
  (SELECT COUNT(*) FROM server_groups sg WHERE sg.enterprise_id=e.id),
  (SELECT COUNT(*) FROM enrollment_tokens et WHERE et.enterprise_id=e.id),
  (SELECT COUNT(*) FROM enterprise_install_tokens it WHERE it.enterprise_id=e.id)
FROM enterprises e ORDER BY e.status,e.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]EnterpriseRecord, 0)
	for rows.Next() {
		var item EnterpriseRecord
		if err := rows.Scan(&item.ID, &item.Name, &item.Status, &item.TerminatedAt, &item.CreatedAt, &item.UserCount, &item.ServerCount, &item.PolicyCount, &item.GroupCount, &item.EnrollmentTokenCount, &item.InstallTokenCount); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) EnterprisePolicyActive(ctx context.Context, scopeEnterpriseID, policyID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*)
FROM enterprise_policies ep JOIN enterprises e ON e.id=ep.enterprise_id
WHERE ep.id=? AND e.status='ACTIVE' AND (?='' OR ep.enterprise_id=?)`, policyID, scopeEnterpriseID, scopeEnterpriseID).Scan(&count)
	return count == 1, err
}

func (s *Store) DeleteOrTerminateEnterprise(ctx context.Context, enterpriseID, expectedName, actorID string) (EnterpriseLifecycleResult, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = tx.Rollback() }()

	var name, status string
	if err := tx.QueryRowContext(ctx, `SELECT name,status FROM enterprises WHERE id=? FOR UPDATE`, enterpriseID).Scan(&name, &status); err != nil {
		return "", err
	}
	if status != "ACTIVE" {
		return "", ErrEnterpriseNotActive
	}
	if expectedName == "" || expectedName != name {
		return "", ErrEnterpriseConfirmation
	}

	var dependencies uint64
	if err := tx.QueryRowContext(ctx, `SELECT
  (SELECT COUNT(*) FROM admin_users WHERE enterprise_id=?) +
  (SELECT COUNT(*) FROM enrollment_tokens WHERE enterprise_id=?) +
  (SELECT COUNT(*) FROM servers WHERE enterprise_id=?) +
  (SELECT COUNT(*) FROM policy_revisions WHERE enterprise_id=?) +
  (SELECT COUNT(*) FROM server_groups WHERE enterprise_id=?) +
  (SELECT COUNT(*) FROM enterprise_policies WHERE enterprise_id=?) +
  (SELECT COUNT(*) FROM enterprise_install_tokens WHERE enterprise_id=?)`, enterpriseID, enterpriseID, enterpriseID, enterpriseID, enterpriseID, enterpriseID, enterpriseID).Scan(&dependencies); err != nil {
		return "", err
	}
	if dependencies == 0 {
		result, err := tx.ExecContext(ctx, `DELETE FROM enterprises WHERE id=? AND status='ACTIVE'`, enterpriseID)
		if err != nil {
			return "", err
		}
		changed, err := result.RowsAffected()
		if err != nil {
			return "", err
		}
		if changed != 1 {
			return "", sql.ErrNoRows
		}
		if err := tx.Commit(); err != nil {
			return "", err
		}
		return EnterpriseDeleted, nil
	}

	now := time.Now().UTC()
	if _, err := tx.ExecContext(ctx, `UPDATE enterprises SET status='TERMINATED',terminated_at=?,terminated_by=? WHERE id=? AND status='ACTIVE'`, now, actorID, enterpriseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE admin_users SET is_active=FALSE WHERE enterprise_id=? AND role<>'system_admin'`, enterpriseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enterprise_install_tokens SET revoked_at=COALESCE(revoked_at,?) WHERE enterprise_id=?`, now, enterpriseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_at=COALESCE(used_at,?) WHERE enterprise_id=?`, now, enterpriseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE servers SET revoked_at=COALESCE(revoked_at,?),revoked_by=COALESCE(revoked_by,?),status='REVOKED' WHERE enterprise_id=?`, now, actorID, enterpriseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_rollouts r JOIN enterprise_policies ep ON ep.id=r.enterprise_policy_id
SET r.status='CANCELLED',r.detail='기업 운영 종료로 취소됨',r.completed_at=?
WHERE ep.enterprise_id=? AND r.status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED')`, now, enterpriseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE agent_commands c JOIN servers s ON s.id=c.server_id
SET c.status='FAILED',c.detail='기업 운영 종료로 취소됨',c.completed_at=?,c.updated_at=?
WHERE s.enterprise_id=? AND c.status IN ('PENDING','ACCEPTED')`, now, now, enterpriseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_deployments d JOIN servers s ON s.id=d.server_id
SET d.status='SUPERSEDED',d.detail='기업 운영 종료로 취소됨',d.updated_at=?
WHERE s.enterprise_id=? AND d.status='PENDING'`, now, enterpriseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE package_deployments d JOIN servers s ON s.id=d.server_id
SET d.status='SUPERSEDED',d.detail='기업 운영 종료로 취소됨',d.updated_at=?
WHERE s.enterprise_id=? AND d.status='PENDING'`, now, enterpriseID); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return EnterpriseTerminated, nil
}
