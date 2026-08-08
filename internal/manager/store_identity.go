package manager

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type EnterpriseRecord struct {
	ID                   string
	Name                 string
	Status               string
	TerminatedAt         sql.NullTime
	SystemAdminCount     uint64
	UserCount            uint64
	ServerCount          uint64
	PolicyCount          uint64
	GroupCount           uint64
	EnrollmentTokenCount uint64
	InstallTokenCount    uint64
	CreatedAt            time.Time
}

func (e EnterpriseRecord) Active() bool    { return e.Status == "ACTIVE" }
func (e EnterpriseRecord) Protected() bool { return e.SystemAdminCount > 0 }
func (e EnterpriseRecord) StatusLabel() string {
	if e.Active() {
		return "운영 중"
	}
	return "운영 종료"
}
func (e EnterpriseRecord) DependencyCount() uint64 {
	return e.UserCount + e.ServerCount + e.PolicyCount + e.GroupCount + e.EnrollmentTokenCount + e.InstallTokenCount
}
func (e EnterpriseRecord) CanDeletePermanently() bool {
	return !e.Protected() && e.DependencyCount() == 0
}

type UserRecord struct {
	ID             string
	EnterpriseID   string
	EnterpriseName string
	Username       string
	DisplayName    string
	PasswordHash   string
	Role           Role
	Active         bool
	Manageable     bool
	LastLoginAt    sql.NullTime
	CreatedAt      time.Time
}

var ErrLastEnterpriseAdmin = errors.New("at least one active enterprise administrator is required")
var ErrActiveSystemAdminNotFound = errors.New("active system administrator not found")

func (u UserRecord) RoleLabel() string { return u.Role.Label() }

func (s *Store) HasAdminUsers(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users WHERE deleted_at IS NULL`).Scan(&count)
	return count != 0, err
}

func (s *Store) CreateInitialSystemAdmin(ctx context.Context, username, displayName, passwordHash string) (UserRecord, error) {
	userID := randomID()
	enterpriseID := randomID()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return UserRecord{}, err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `INSERT INTO enterprises(id,name,status) VALUES (?,'M-WAF 시스템 운영','ACTIVE')`, enterpriseID); err != nil {
		return UserRecord{}, err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO admin_users(id,enterprise_id,username,display_name,password_hash,role,is_active,bootstrap_key)
SELECT ?,?,?,?,?, 'system_admin',TRUE,1 FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM admin_users)`, userID, enterpriseID, username, displayName, passwordHash)
	if err != nil {
		return UserRecord{}, err
	}
	created, err := result.RowsAffected()
	if err != nil {
		return UserRecord{}, err
	}
	if created != 1 {
		return UserRecord{}, ErrSetupComplete
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enterprises SET created_by=? WHERE id=?`, userID, enterpriseID); err != nil {
		return UserRecord{}, err
	}
	if err := tx.Commit(); err != nil {
		return UserRecord{}, err
	}
	return s.UserByID(ctx, userID)
}

func (s *Store) UserByUsername(ctx context.Context, username string) (UserRecord, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT u.id,COALESCE(u.enterprise_id,''),COALESCE(e.name,''),u.username,u.display_name,u.password_hash,u.role,u.is_active,u.last_login_at,u.created_at
FROM admin_users u JOIN enterprises e ON e.id=u.enterprise_id
WHERE u.username=? AND u.deleted_at IS NULL AND e.status='ACTIVE'`, username))
}

func (s *Store) UserByID(ctx context.Context, id string) (UserRecord, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT u.id,COALESCE(u.enterprise_id,''),COALESCE(e.name,''),u.username,u.display_name,u.password_hash,u.role,u.is_active,u.last_login_at,u.created_at
FROM admin_users u JOIN enterprises e ON e.id=u.enterprise_id
WHERE u.id=? AND u.deleted_at IS NULL AND e.status='ACTIVE'`, id))
}

type rowScanner interface {
	Scan(dest ...any) error
}

func scanUser(row rowScanner) (UserRecord, error) {
	var user UserRecord
	err := row.Scan(&user.ID, &user.EnterpriseID, &user.EnterpriseName, &user.Username, &user.DisplayName, &user.PasswordHash, &user.Role, &user.Active, &user.LastLoginAt, &user.CreatedAt)
	return user, err
}

func (s *Store) RecordLogin(ctx context.Context, userID string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE admin_users SET last_login_at=UTC_TIMESTAMP(6) WHERE id=?`, userID)
}

func (s *Store) UpdateOwnPassword(ctx context.Context, userID, passwordHash string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE admin_users SET password_hash=? WHERE id=? AND is_active=TRUE AND deleted_at IS NULL`, passwordHash, userID)
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

func (s *Store) ResetSystemAdminPassword(ctx context.Context, username, passwordHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var userID string
	err = tx.QueryRowContext(ctx, `SELECT id FROM admin_users
WHERE username=? AND role='system_admin' AND is_active=TRUE AND deleted_at IS NULL FOR UPDATE`, username).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrActiveSystemAdminNotFound
	}
	if err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE admin_users SET password_hash=?
WHERE id=? AND role='system_admin' AND is_active=TRUE AND deleted_at IS NULL`, passwordHash, userID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrActiveSystemAdminNotFound
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO admin_audit_logs(request_id,actor,action,target,result,remote_addr)
VALUES (?,?,?,?,?,?)`, randomID(), "system-recovery", "system_admin.password_reset", userID, "success", "local-container"); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListEnterprises(ctx context.Context) ([]EnterpriseRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,status,terminated_at,created_at FROM enterprises WHERE status='ACTIVE' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]EnterpriseRecord, 0)
	for rows.Next() {
		var item EnterpriseRecord
		if err := rows.Scan(&item.ID, &item.Name, &item.Status, &item.TerminatedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) EnterpriseExists(ctx context.Context, id string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM enterprises WHERE id=? AND status='ACTIVE'`, id).Scan(&count)
	return count == 1, err
}

func (s *Store) CreateEnterprise(ctx context.Context, name, creatorID string) (EnterpriseRecord, error) {
	id := randomID()
	_, err := s.db.ExecContext(ctx, `INSERT INTO enterprises(id,name,created_by) VALUES (?,?,?)`, id, name, creatorID)
	if err != nil {
		return EnterpriseRecord{}, err
	}
	var item EnterpriseRecord
	err = s.db.QueryRowContext(ctx, `SELECT id,name,status,terminated_at,created_at FROM enterprises WHERE id=?`, id).Scan(&item.ID, &item.Name, &item.Status, &item.TerminatedAt, &item.CreatedAt)
	return item, err
}

func (s *Store) ListUsers(ctx context.Context, enterpriseID string) ([]UserRecord, error) {
	query := `SELECT u.id,COALESCE(u.enterprise_id,''),COALESCE(e.name,''),u.username,u.display_name,u.password_hash,u.role,u.is_active,u.last_login_at,u.created_at
FROM admin_users u LEFT JOIN enterprises e ON e.id=u.enterprise_id`
	args := make([]any, 0, 1)
	if enterpriseID != "" {
		query += ` WHERE u.enterprise_id=? AND u.deleted_at IS NULL`
		args = append(args, enterpriseID)
	} else {
		query += ` WHERE u.deleted_at IS NULL`
	}
	query += ` ORDER BY COALESCE(e.name,''), u.role DESC, u.username`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]UserRecord, 0)
	for rows.Next() {
		item, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) CreateEnterpriseUser(ctx context.Context, enterpriseID, username, displayName, passwordHash string, role Role, creatorID string) (UserRecord, error) {
	if enterpriseID == "" || !validEnterpriseRole(role) {
		return UserRecord{}, errors.New("valid enterprise and role are required")
	}
	id := randomID()
	result, err := s.db.ExecContext(ctx, `INSERT INTO admin_users(id,enterprise_id,username,display_name,password_hash,role,is_active,created_by)
SELECT ?,e.id,?,?,?,?,TRUE,? FROM enterprises e WHERE e.id=? AND e.status='ACTIVE'`, id, username, displayName, passwordHash, role, creatorID, enterpriseID)
	if err != nil {
		return UserRecord{}, err
	}
	created, err := result.RowsAffected()
	if err != nil {
		return UserRecord{}, err
	}
	if created != 1 {
		return UserRecord{}, ErrEnterpriseNotActive
	}
	return s.UserByID(ctx, id)
}

func (s *Store) UpdateEnterpriseUser(ctx context.Context, enterpriseID, userID, displayName, passwordHash string, role Role, active bool) error {
	if enterpriseID == "" || !validEnterpriseRole(role) {
		return errors.New("valid enterprise and role are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var currentRole Role
	var currentActive bool
	if err := tx.QueryRowContext(ctx, `SELECT role,is_active FROM admin_users WHERE id=? AND enterprise_id=? AND role<>'system_admin' AND deleted_at IS NULL FOR UPDATE`, userID, enterpriseID).Scan(&currentRole, &currentActive); err != nil {
		return err
	}
	if currentRole == RoleEnterpriseAdmin && currentActive && (role != RoleEnterpriseAdmin || !active) {
		hasOther, err := lockOtherActiveEnterpriseAdmin(ctx, tx, enterpriseID, userID)
		if err != nil {
			return err
		}
		if !hasOther {
			return ErrLastEnterpriseAdmin
		}
	}
	query := `UPDATE admin_users SET display_name=?,role=?,is_active=?`
	args := []any{displayName, role, active}
	if passwordHash != "" {
		query += `,password_hash=?`
		args = append(args, passwordHash)
	}
	query += ` WHERE id=? AND enterprise_id=? AND role<>'system_admin' AND deleted_at IS NULL`
	args = append(args, userID, enterpriseID)
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) DeleteEnterpriseUser(ctx context.Context, enterpriseID, userID string) error {
	if enterpriseID == "" {
		return errors.New("valid enterprise is required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	var currentRole Role
	var currentActive bool
	if err := tx.QueryRowContext(ctx, `SELECT role,is_active FROM admin_users WHERE id=? AND enterprise_id=? AND role<>'system_admin' AND deleted_at IS NULL FOR UPDATE`, userID, enterpriseID).Scan(&currentRole, &currentActive); err != nil {
		return err
	}
	if currentRole == RoleEnterpriseAdmin && currentActive {
		hasOther, err := lockOtherActiveEnterpriseAdmin(ctx, tx, enterpriseID, userID)
		if err != nil {
			return err
		}
		if !hasOther {
			return ErrLastEnterpriseAdmin
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE admin_users SET is_active=FALSE,deleted_at=UTC_TIMESTAMP(6) WHERE id=? AND enterprise_id=? AND role<>'system_admin' AND deleted_at IS NULL`, userID, enterpriseID)
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
	return tx.Commit()
}

func lockOtherActiveEnterpriseAdmin(ctx context.Context, tx *sql.Tx, enterpriseID, excludedUserID string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT id FROM admin_users WHERE enterprise_id=? AND role='enterprise_admin' AND is_active=TRUE AND deleted_at IS NULL AND id<>? FOR UPDATE`, enterpriseID, excludedUserID)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	hasOther := false
	for rows.Next() {
		hasOther = true
		var id string
		if err := rows.Scan(&id); err != nil {
			return false, err
		}
	}
	return hasOther, rows.Err()
}
