package manager

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

var ErrInvalidInstallToken = errors.New("invalid, expired or revoked enterprise install token")
var ErrInvalidEventVerificationToken = errors.New("invalid event verification token")

// persistentInstallTokenExpiry is a storage marker for enterprise tokens that
// remain usable until an operator revokes them. The existing TIMESTAMP column
// stays unchanged so previously issued expiring tokens keep their old meaning.
var persistentInstallTokenExpiry = time.Date(2037, 12, 31, 23, 59, 59, 0, time.UTC)

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
	if !r.Persistent() && !r.ExpiresAt.After(time.Now().UTC()) {
		return "만료"
	}
	if r.MaxEnrollments.Valid && r.EnrollmentCount >= uint64(r.MaxEnrollments.Int64) {
		return "사용 한도 도달"
	}
	return "활성"
}

func (r EnterpriseInstallTokenRecord) Active() bool { return r.StatusLabel() == "활성" }

func (r EnterpriseInstallTokenRecord) Persistent() bool {
	return r.ExpiresAt.UTC().Equal(persistentInstallTokenExpiry)
}

func installTokenUsable(expiresAt time.Time, revokedAt sql.NullTime, maximum sql.NullInt64, enrollmentCount uint64) bool {
	if revokedAt.Valid || (!expiresAt.UTC().Equal(persistentInstallTokenExpiry) && !expiresAt.After(time.Now().UTC())) {
		return false
	}
	return !maximum.Valid || enrollmentCount < uint64(maximum.Int64)
}

func newInstallToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return "mwaf_it_" + base64.RawURLEncoding.EncodeToString(raw), nil
}

func installTokenPrefix(token string) string {
	const prefixLength = 14
	if len(token) <= prefixLength {
		return token
	}
	return token[:prefixLength]
}

func (r EnterpriseInstallTokenRecord) DisplayPrefix() string {
	return installTokenPrefix(r.TokenPrefix)
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
	result, err := s.db.ExecContext(ctx, `INSERT INTO enterprise_install_tokens(id,enterprise_id,name,token_prefix,token_hash,expires_at,max_enrollments,created_by)
SELECT ?,e.id,?,?,?,?,?,? FROM enterprises e WHERE e.id=? AND e.status='ACTIVE'`, id, name, installTokenPrefix(token), tokenHash(token), expiresAt, maximum, createdBy, enterpriseID)
	if err != nil {
		return EnterpriseInstallTokenRecord{}, "", err
	}
	created, err := result.RowsAffected()
	if err != nil {
		return EnterpriseInstallTokenRecord{}, "", err
	}
	if created != 1 {
		return EnterpriseInstallTokenRecord{}, "", ErrEnterpriseNotActive
	}
	return EnterpriseInstallTokenRecord{ID: id, EnterpriseID: enterpriseID, Name: name, TokenPrefix: installTokenPrefix(token), ExpiresAt: expiresAt, MaxEnrollments: maximumValue, CreatedAt: createdAt}, token, nil
}

// EnsurePersistentEnterpriseInstallToken creates the enterprise's reusable
// install token only when no usable token exists. Locking the enterprise row
// keeps simultaneous page loads from issuing multiple active tokens.
func (s *Store) EnsurePersistentEnterpriseInstallToken(ctx context.Context, enterpriseID, name, createdBy string) (EnterpriseInstallTokenRecord, string, bool, error) {
	if enterpriseID == "" || name == "" {
		return EnterpriseInstallTokenRecord{}, "", false, errors.New("enterprise and name are required")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return EnterpriseInstallTokenRecord{}, "", false, err
	}
	defer func() { _ = tx.Rollback() }()

	var enterpriseName string
	if err := tx.QueryRowContext(ctx, `SELECT name FROM enterprises WHERE id=? AND status='ACTIVE' FOR UPDATE`, enterpriseID).Scan(&enterpriseName); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EnterpriseInstallTokenRecord{}, "", false, ErrEnterpriseNotActive
		}
		return EnterpriseInstallTokenRecord{}, "", false, err
	}

	var existing EnterpriseInstallTokenRecord
	err = tx.QueryRowContext(ctx, `SELECT id,enterprise_id,name,token_prefix,expires_at,max_enrollments,enrollment_count,last_used_at,revoked_at,created_at
FROM enterprise_install_tokens
WHERE enterprise_id=? AND revoked_at IS NULL AND expires_at>UTC_TIMESTAMP(6)
  AND (max_enrollments IS NULL OR enrollment_count<max_enrollments)
ORDER BY created_at DESC LIMIT 1 FOR UPDATE`, enterpriseID).Scan(
		&existing.ID, &existing.EnterpriseID, &existing.Name, &existing.TokenPrefix, &existing.ExpiresAt,
		&existing.MaxEnrollments, &existing.EnrollmentCount, &existing.LastUsedAt, &existing.RevokedAt, &existing.CreatedAt,
	)
	if err == nil {
		existing.EnterpriseName = enterpriseName
		if err := tx.Commit(); err != nil {
			return EnterpriseInstallTokenRecord{}, "", false, err
		}
		return existing, "", false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return EnterpriseInstallTokenRecord{}, "", false, err
	}

	token, err := newInstallToken()
	if err != nil {
		return EnterpriseInstallTokenRecord{}, "", false, err
	}
	record := EnterpriseInstallTokenRecord{
		ID:             randomID(),
		EnterpriseID:   enterpriseID,
		EnterpriseName: enterpriseName,
		Name:           name,
		TokenPrefix:    installTokenPrefix(token),
		ExpiresAt:      persistentInstallTokenExpiry,
		CreatedAt:      time.Now().UTC(),
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO enterprise_install_tokens(id,enterprise_id,name,token_prefix,token_hash,expires_at,created_by)
VALUES (?,?,?,?,?,?,?)`, record.ID, enterpriseID, name, record.TokenPrefix, tokenHash(token), record.ExpiresAt, createdBy); err != nil {
		return EnterpriseInstallTokenRecord{}, "", false, err
	}
	if err := tx.Commit(); err != nil {
		return EnterpriseInstallTokenRecord{}, "", false, err
	}
	return record, token, true, nil
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

// AuthorizeEventIngestToken binds the additional event verification secret to
// the same enterprise as the authenticated Agent. Historical install tokens
// remain valid for this scope because operator revocation only blocks new
// installations; mTLS still identifies and authorizes the enrolled server.
func (s *Store) AuthorizeEventIngestToken(ctx context.Context, serverID, token string) error {
	if serverID == "" || strings.TrimSpace(token) == "" {
		return ErrInvalidEventVerificationToken
	}
	hash := tokenHash(strings.TrimSpace(token))
	var authorized bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(
  SELECT 1 FROM servers s
  WHERE s.id=? AND (
    EXISTS(SELECT 1 FROM enterprise_install_tokens it WHERE it.enterprise_id=s.enterprise_id AND it.token_hash=?)
    OR EXISTS(SELECT 1 FROM enrollment_tokens et WHERE et.enterprise_id=s.enterprise_id AND et.token_hash=? AND et.used_at IS NOT NULL)
  )
)`, serverID, hash, hash).Scan(&authorized)
	if err != nil {
		return err
	}
	if !authorized {
		return ErrInvalidEventVerificationToken
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
	if err := tx.QueryRowContext(ctx, `SELECT t.id,t.enterprise_id,t.expires_at,t.revoked_at,t.max_enrollments,t.enrollment_count
FROM enterprise_install_tokens t JOIN enterprises e ON e.id=t.enterprise_id
WHERE t.token_hash=? AND e.status='ACTIVE' FOR UPDATE`, tokenHash(installToken)).Scan(&id, &enterpriseID, &expiresAt, &revokedAt, &maximum, &enrollmentCount); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", time.Time{}, ErrInvalidInstallToken
		}
		return "", time.Time{}, err
	}
	if !installTokenUsable(expiresAt, revokedAt, maximum, enrollmentCount) {
		return "", time.Time{}, ErrInvalidInstallToken
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	enrollmentToken := base64.RawURLEncoding.EncodeToString(raw)
	sessionExpires := time.Now().UTC().Add(ttl)
	if !expiresAt.UTC().Equal(persistentInstallTokenExpiry) && sessionExpires.After(expiresAt) {
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
