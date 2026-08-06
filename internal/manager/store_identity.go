package manager

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type EnterpriseRecord struct {
	ID        string
	Name      string
	CreatedAt time.Time
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

func (u UserRecord) RoleLabel() string { return u.Role.Label() }

func (s *Store) HasAdminUsers(ctx context.Context) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users WHERE deleted_at IS NULL`).Scan(&count)
	return count != 0, err
}

func (s *Store) CreateInitialSystemAdmin(ctx context.Context, username, displayName, passwordHash string) (UserRecord, error) {
	id := randomID()
	result, err := s.db.ExecContext(ctx, `INSERT INTO admin_users(id,username,display_name,password_hash,role,is_active,bootstrap_key)
SELECT ?,?,?,?,'system_admin',TRUE,1 FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM admin_users)`, id, username, displayName, passwordHash)
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
	return s.UserByID(ctx, id)
}

func (s *Store) UserByUsername(ctx context.Context, username string) (UserRecord, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT u.id,COALESCE(u.enterprise_id,''),COALESCE(e.name,''),u.username,u.display_name,u.password_hash,u.role,u.is_active,u.last_login_at,u.created_at
FROM admin_users u LEFT JOIN enterprises e ON e.id=u.enterprise_id WHERE u.username=? AND u.deleted_at IS NULL`, username))
}

func (s *Store) UserByID(ctx context.Context, id string) (UserRecord, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT u.id,COALESCE(u.enterprise_id,''),COALESCE(e.name,''),u.username,u.display_name,u.password_hash,u.role,u.is_active,u.last_login_at,u.created_at
FROM admin_users u LEFT JOIN enterprises e ON e.id=u.enterprise_id WHERE u.id=? AND u.deleted_at IS NULL`, id))
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

func (s *Store) ListEnterprises(ctx context.Context) ([]EnterpriseRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,created_at FROM enterprises ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]EnterpriseRecord, 0)
	for rows.Next() {
		var item EnterpriseRecord
		if err := rows.Scan(&item.ID, &item.Name, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) EnterpriseExists(ctx context.Context, id string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM enterprises WHERE id=?`, id).Scan(&count)
	return count == 1, err
}

func (s *Store) CreateEnterprise(ctx context.Context, name, creatorID string) (EnterpriseRecord, error) {
	id := randomID()
	_, err := s.db.ExecContext(ctx, `INSERT INTO enterprises(id,name,created_by) VALUES (?,?,?)`, id, name, creatorID)
	if err != nil {
		return EnterpriseRecord{}, err
	}
	var item EnterpriseRecord
	err = s.db.QueryRowContext(ctx, `SELECT id,name,created_at FROM enterprises WHERE id=?`, id).Scan(&item.ID, &item.Name, &item.CreatedAt)
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
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_users(id,enterprise_id,username,display_name,password_hash,role,is_active,created_by) VALUES (?,?,?,?,?,?,TRUE,?)`, id, enterpriseID, username, displayName, passwordHash, role, creatorID)
	if err != nil {
		return UserRecord{}, err
	}
	return s.UserByID(ctx, id)
}

func (s *Store) UpdateEnterpriseUser(ctx context.Context, enterpriseID, userID, displayName, passwordHash string, role Role, active bool) error {
	if enterpriseID == "" || !validEnterpriseRole(role) {
		return errors.New("valid enterprise and role are required")
	}
	var accessible int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admin_users WHERE id=? AND enterprise_id=? AND role<>'system_admin' AND deleted_at IS NULL`, userID, enterpriseID).Scan(&accessible); err != nil {
		return err
	}
	if accessible != 1 {
		return sql.ErrNoRows
	}
	query := `UPDATE admin_users SET display_name=?,role=?,is_active=?`
	args := []any{displayName, role, active}
	if passwordHash != "" {
		query += `,password_hash=?`
		args = append(args, passwordHash)
	}
	query += ` WHERE id=? AND enterprise_id=? AND role<>'system_admin' AND deleted_at IS NULL`
	args = append(args, userID, enterpriseID)
	_, err := s.db.ExecContext(ctx, query, args...)
	return err
}

func (s *Store) DeleteEnterpriseUser(ctx context.Context, enterpriseID, userID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE admin_users SET is_active=FALSE,deleted_at=UTC_TIMESTAMP(6) WHERE id=? AND enterprise_id=? AND role<>'system_admin' AND deleted_at IS NULL`, userID, enterpriseID)
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
