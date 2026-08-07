package manager

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"
)

var ErrInvalidInstallToken = errors.New("invalid, expired or revoked enterprise install token")

type EnterpriseInstallTokenRecord struct {
	ID              string
	EnterpriseID    string
	EnterpriseName  string
	Name            string
	TokenPrefix     string
	ExpiresAt       time.Time
	MaxEnrollments  sql.NullInt64
	EnrollmentCount uint64
	LastUsedAt      sql.NullTime
	RevokedAt       sql.NullTime
	CreatedAt       time.Time
}

func (r EnterpriseInstallTokenRecord) StatusLabel() string {
	if r.RevokedAt.Valid {
		return "폐기됨"
	}
	if !r.ExpiresAt.After(time.Now().UTC()) {
		return "만료"
	}
	if r.MaxEnrollments.Valid && r.EnrollmentCount >= uint64(r.MaxEnrollments.Int64) {
		return "사용 한도 도달"
	}
	return "활성"
}

func (r EnterpriseInstallTokenRecord) Active() bool { return r.StatusLabel() == "활성" }

func newInstallToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "mwaf_it_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func installTokenPrefix(token string) string {
	const prefixLength = 20
	if len(token) <= prefixLength {
		return token
	}
	return token[:prefixLength]
}

func (s *Store) CreateEnterpriseInstallToken(ctx context.Context, enterpriseID, name, createdBy string, expiresAt time.Time, maxEnrollments int) (EnterpriseInstallTokenRecord, string, error) {
	if enterpriseID == "" || name == "" || !expiresAt.After(time.Now().UTC()) {
		return EnterpriseInstallTokenRecord{}, "", errors.New("enterprise, name and future expiry are required")
	}
	token, err := newInstallToken()
	if err != nil {
		return EnterpriseInstallTokenRecord{}, "", err
	}
	id := randomID()
	createdAt := time.Now().UTC()
	var maximum any
	maximumValue := sql.NullInt64{}
	if maxEnrollments > 0 {
		maximum = maxEnrollments
		maximumValue = sql.NullInt64{Int64: int64(maxEnrollments), Valid: true}
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO enterprise_install_tokens(id,enterprise_id,name,token_prefix,token_hash,expires_at,max_enrollments,created_by)
VALUES (?,?,?,?,?,?,?,?)`, id, enterpriseID, name, installTokenPrefix(token), tokenHash(token), expiresAt, maximum, createdBy)
	if err != nil {
		return EnterpriseInstallTokenRecord{}, "", err
	}
	return EnterpriseInstallTokenRecord{ID: id, EnterpriseID: enterpriseID, Name: name, TokenPrefix: installTokenPrefix(token), ExpiresAt: expiresAt, MaxEnrollments: maximumValue, CreatedAt: createdAt}, token, nil
}

func (s *Store) ListEnterpriseInstallTokens(ctx context.Context, enterpriseScope string, limit int) ([]EnterpriseInstallTokenRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	query := `SELECT t.id,t.enterprise_id,e.name,t.name,t.token_prefix,t.expires_at,t.max_enrollments,t.enrollment_count,t.last_used_at,t.revoked_at,t.created_at
FROM enterprise_install_tokens t JOIN enterprises e ON e.id=t.enterprise_id`
	args := make([]any, 0, 2)
	if enterpriseScope != "" {
		query += ` WHERE t.enterprise_id=?`
		args = append(args, enterpriseScope)
	}
	query += ` ORDER BY t.created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]EnterpriseInstallTokenRecord, 0)
	for rows.Next() {
		var item EnterpriseInstallTokenRecord
		if err := rows.Scan(&item.ID, &item.EnterpriseID, &item.EnterpriseName, &item.Name, &item.TokenPrefix, &item.ExpiresAt, &item.MaxEnrollments, &item.EnrollmentCount, &item.LastUsedAt, &item.RevokedAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) RevokeEnterpriseInstallToken(ctx context.Context, id, enterpriseScope string) error {
	query := `UPDATE enterprise_install_tokens SET revoked_at=UTC_TIMESTAMP(6) WHERE id=? AND revoked_at IS NULL`
	args := []any{id}
	if enterpriseScope != "" {
		query += ` AND enterprise_id=?`
		args = append(args, enterpriseScope)
	}
	result, err := s.db.ExecContext(ctx, query, args...)
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

func (s *Store) ExchangeEnterpriseInstallToken(ctx context.Context, installToken, label string, ttl time.Duration) (string, time.Time, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = tx.Rollback() }()
	var id, enterpriseID string
	var expiresAt time.Time
	var revokedAt sql.NullTime
	var maximum sql.NullInt64
	var enrollmentCount uint64
	if err := tx.QueryRowContext(ctx, `SELECT id,enterprise_id,expires_at,revoked_at,max_enrollments,enrollment_count
FROM enterprise_install_tokens WHERE token_hash=? FOR UPDATE`, tokenHash(installToken)).Scan(&id, &enterpriseID, &expiresAt, &revokedAt, &maximum, &enrollmentCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", time.Time{}, ErrInvalidInstallToken
		}
		return "", time.Time{}, err
	}
	if revokedAt.Valid || !expiresAt.After(time.Now().UTC()) || (maximum.Valid && enrollmentCount >= uint64(maximum.Int64)) {
		return "", time.Time{}, ErrInvalidInstallToken
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	enrollmentToken := base64.RawURLEncoding.EncodeToString(raw)
	sessionExpires := time.Now().UTC().Add(ttl)
	if sessionExpires.After(expiresAt) {
		sessionExpires = expiresAt
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO enrollment_tokens(id,enterprise_id,install_token_id,token_hash,label,expires_at)
VALUES (?,?,?,?,?,?)`, randomID(), enterpriseID, id, tokenHash(enrollmentToken), label, sessionExpires); err != nil {
		return "", time.Time{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enterprise_install_tokens SET last_used_at=UTC_TIMESTAMP(6) WHERE id=?`, id); err != nil {
		return "", time.Time{}, err
	}
	if err := tx.Commit(); err != nil {
		return "", time.Time{}, err
	}
	return enrollmentToken, sessionExpires, nil
}
