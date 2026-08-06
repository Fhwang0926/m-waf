package manager

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/packages"
)

var ErrInvalidEnrollmentToken = errors.New("invalid or expired enrollment token")

const serverOfflineAfter = 2 * time.Minute

type Store struct {
	db *sql.DB
}

type ServerRecord struct {
	ID                      string
	EnterpriseID            string
	EnterpriseName          string
	Name                    string
	Status                  string
	Inventory               model.Inventory
	PolicyRevision          string
	DesiredPolicyRevision   string
	PolicyDeploymentStatus  string
	PolicyDeploymentDetail  string
	PackageDeploymentStatus string
	PackageDeploymentDetail string
	AgentPackageID          string
	ModulePackageID         string
	CanRollbackPackages     bool
	LastCommand             string
	LastCommandStatus       string
	Revoked                 bool
	LastHeartbeatAt         sql.NullTime
	CreatedAt               time.Time
}

type EventRecord struct {
	ID             uint64
	AgentID        string
	ServerName     string
	EnterpriseName string
	OccurredAt     time.Time
	Method         string
	URI            string
	RuleID         string
	Message        string
	Severity       string
	Blocked        bool
}

func (e EventRecord) SeverityLabel() string {
	labels := map[string]string{"0": "EMERGENCY", "1": "ALERT", "2": "CRITICAL", "3": "ERROR", "4": "WARNING", "5": "NOTICE", "6": "INFO", "7": "DEBUG"}
	if label := labels[e.Severity]; label != "" {
		return label
	}
	return e.Severity
}

type PolicyArtifact struct {
	RevisionID string
	Path       string
	SHA256     string
	Signature  string
}

func OpenStore(dsn string) (*Store, error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(32)
	db.SetMaxIdleConns(16)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(90 * time.Second)
	return &Store{db: db}, nil
}

func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Ping(ctx context.Context) error { return s.db.PingContext(ctx) }

func (s *Store) CreateEnrollmentToken(ctx context.Context, enterpriseID, label string, ttl time.Duration) (string, time.Time, error) {
	if enterpriseID == "" {
		return "", time.Time{}, errors.New("enterprise is required")
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	expires := time.Now().UTC().Add(ttl)
	_, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_tokens(id, enterprise_id, token_hash, label, expires_at) VALUES (?, ?, ?, ?, ?)`, randomID(), enterpriseID, tokenHash(token), label, expires)
	if err != nil {
		return "", time.Time{}, err
	}
	return token, expires, nil
}

func (s *Store) ValidateEnrollmentToken(ctx context.Context, token string) error {
	var used sql.NullTime
	var enterpriseID sql.NullString
	var expires time.Time
	err := s.db.QueryRowContext(ctx, `SELECT enterprise_id, expires_at, used_at FROM enrollment_tokens WHERE token_hash = ?`, tokenHash(token)).Scan(&enterpriseID, &expires, &used)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidEnrollmentToken
		}
		return err
	}
	if !enterpriseID.Valid || enterpriseID.String == "" || used.Valid || !expires.After(time.Now().UTC()) {
		return ErrInvalidEnrollmentToken
	}
	return nil
}

func (s *Store) AllowEnrollmentPackages(ctx context.Context, token string, packageIDs []string) error {
	raw, err := json.Marshal(packageIDs)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE enrollment_tokens SET allowed_packages_json = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP(6)`, raw, tokenHash(token))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrInvalidEnrollmentToken
	}
	return nil
}

func (s *Store) EnrollmentPackageAllowed(ctx context.Context, token, packageID string) (bool, error) {
	var raw sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT allowed_packages_json FROM enrollment_tokens WHERE token_hash = ? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP(6)`, tokenHash(token)).Scan(&raw)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrInvalidEnrollmentToken
		}
		return false, err
	}
	if !raw.Valid {
		return false, nil
	}
	var ids []string
	if err := json.Unmarshal([]byte(raw.String), &ids); err != nil {
		return false, err
	}
	for _, id := range ids {
		if id == packageID {
			return true, nil
		}
	}
	return false, nil
}

func (s *Store) ConsumeEnrollment(ctx context.Context, token, serverID, serverName, certSerial string, inventory model.Inventory) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var expires time.Time
	var used sql.NullTime
	var allowedJSON sql.NullString
	var enterpriseID sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT enterprise_id, expires_at, used_at, allowed_packages_json FROM enrollment_tokens WHERE token_hash = ? FOR UPDATE`, tokenHash(token)).Scan(&enterpriseID, &expires, &used, &allowedJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidEnrollmentToken
		}
		return err
	}
	if !enterpriseID.Valid || enterpriseID.String == "" || used.Valid || !expires.After(time.Now().UTC()) {
		return ErrInvalidEnrollmentToken
	}
	raw, err := json.Marshal(inventory)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO servers(id, enterprise_id, name, certificate_serial, inventory_json, agent_version, module_version) VALUES (?, ?, ?, ?, ?, ?, ?)`, serverID, enterpriseID.String, serverName, certSerial, raw, inventory.AgentVersion, inventory.ModuleVersion); err != nil {
		return err
	}
	if allowedJSON.Valid {
		var packageIDs []string
		if err := json.Unmarshal([]byte(allowedJSON.String), &packageIDs); err != nil {
			return err
		}
		if len(packageIDs) == 2 {
			if _, err := tx.ExecContext(ctx, `INSERT INTO desired_states(server_id, agent_package_id, module_package_id) VALUES (?, ?, ?)`, serverID, packageIDs[0], packageIDs[1]); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_at = UTC_TIMESTAMP(6) WHERE token_hash = ?`, tokenHash(token)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateHeartbeat(ctx context.Context, serverID string, heartbeat model.HeartbeatRequest) error {
	raw, err := json.Marshal(heartbeat.Inventory)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE servers SET inventory_json=?, agent_version=?, module_version=?, policy_revision=?, policy_hash=?, status=?, last_heartbeat_at=UTC_TIMESTAMP(6) WHERE id=?`, raw, heartbeat.Inventory.AgentVersion, heartbeat.Inventory.ModuleVersion, heartbeat.PolicyRevision, heartbeat.PolicyHash, heartbeat.Status, serverID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return sql.ErrNoRows
	}
	if heartbeat.PolicyRevision != "" {
		_, _ = s.db.ExecContext(ctx, `UPDATE policy_deployments SET status='APPLIED',detail='',updated_at=UTC_TIMESTAMP(6) WHERE server_id=? AND policy_revision_id=? AND status<>'APPLIED'`, serverID, heartbeat.PolicyRevision)
	}
	if heartbeat.LastCommandID != "" {
		_, _ = s.db.ExecContext(ctx, `UPDATE agent_commands SET status='COMPLETED',completed_at=UTC_TIMESTAMP(6),updated_at=UTC_TIMESTAMP(6) WHERE id=? AND server_id=? AND status='ACCEPTED'`, heartbeat.LastCommandID, serverID)
	}
	return nil
}

func (s *Store) DesiredState(ctx context.Context, serverID string) (model.DesiredState, error) {
	var state model.DesiredState
	var revision, artifactPath, hash, signature, mode, agentPackage, modulePackage, packageDeployment sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT pr.id, pr.artifact_path, pr.artifact_sha256, pr.artifact_signature, pr.mode, ds.agent_package_id, ds.module_package_id, ds.package_deployment_id
FROM servers s
LEFT JOIN desired_states ds ON ds.server_id=s.id
LEFT JOIN policy_revisions pr ON pr.id=ds.policy_revision_id
WHERE s.id=? AND s.revoked_at IS NULL`, serverID).Scan(&revision, &artifactPath, &hash, &signature, &mode, &agentPackage, &modulePackage, &packageDeployment)
	if err != nil {
		return state, err
	}
	state.RevisionID = revision.String
	state.ArtifactURL = artifactPath.String
	state.SHA256 = hash.String
	state.Signature = signature.String
	state.Mode = mode.String
	if state.Mode == "" {
		state.Mode = "DetectionOnly"
	}
	state.AgentPackageID = agentPackage.String
	state.ModulePackageID = modulePackage.String
	if packageDeployment.Valid {
		state.PackageDeployment = &model.PackageDeployment{ID: packageDeployment.String}
	}
	return state, nil
}

func (s *Store) PolicyArtifactForServer(ctx context.Context, serverID, revisionID string) (PolicyArtifact, error) {
	var artifact PolicyArtifact
	err := s.db.QueryRowContext(ctx, `SELECT pr.id, pr.artifact_path, pr.artifact_sha256, pr.artifact_signature
FROM desired_states ds JOIN policy_revisions pr ON pr.id=ds.policy_revision_id
WHERE ds.server_id=? AND pr.id=?`, serverID, revisionID).Scan(&artifact.RevisionID, &artifact.Path, &artifact.SHA256, &artifact.Signature)
	return artifact, err
}

func (s *Store) PackageAllowedForServer(ctx context.Context, serverID, packageID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM desired_states WHERE server_id=? AND (agent_package_id=? OR module_package_id=?)`, serverID, packageID, packageID).Scan(&count)
	return count == 1, err
}

func (s *Store) InsertEventBatch(ctx context.Context, serverID string, batch model.EventBatch) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT IGNORE INTO event_ingest_batches(agent_id, batch_id, event_count) VALUES (?, ?, ?)`, serverID, batch.BatchID, len(batch.Events))
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return true, nil
	}
	if len(batch.Events) != 0 {
		const columns = 14
		placeholders := make([]string, 0, len(batch.Events))
		args := make([]any, 0, len(batch.Events)*columns)
		for _, event := range batch.Events {
			placeholders = append(placeholders, "(?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
			args = append(args, serverID, batch.BatchID, event.EventID, event.OccurredAt.UTC(), event.TransactionID, event.Service, event.Method, event.URI, event.StatusCode, event.RuleID, event.Message, event.Severity, event.Blocked, event.PolicyRevision)
		}
		query := `INSERT INTO security_events(agent_id,batch_id,event_id,occurred_at,transaction_id,service,method,uri,status_code,rule_id,message,severity,blocked,policy_revision) VALUES ` + strings.Join(placeholders, ",")
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return false, nil
}

func (s *Store) PruneEvents(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 10000 {
		return 0, errors.New("prune limit must be between 1 and 10000")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM security_events WHERE occurred_at < ? ORDER BY occurred_at LIMIT ?`, before.UTC(), limit)
	if err != nil {
		return 0, err
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

func (s *Store) PruneEventBatches(ctx context.Context, before time.Time, limit int) (int64, error) {
	if limit < 1 || limit > 10000 {
		return 0, errors.New("prune limit must be between 1 and 10000")
	}
	result, err := s.db.ExecContext(ctx, `DELETE FROM event_ingest_batches WHERE committed_at < ? ORDER BY committed_at LIMIT ?`, before.UTC(), limit)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) SyncCatalog(ctx context.Context, catalog *packages.Catalog) error {
	manifest := catalog.Manifest()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT INTO package_bundles(bundle_version, source_commit, manifest_sha256, verified_at) VALUES (?, ?, ?, UTC_TIMESTAMP(6)) ON DUPLICATE KEY UPDATE source_commit=VALUES(source_commit), manifest_sha256=VALUES(manifest_sha256), verified_at=VALUES(verified_at)`, manifest.BundleVersion, manifest.SourceCommit, catalog.ManifestSHA256()); err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		targetFields := map[string]string{
			"os_id": artifact.OSID, "os_version": artifact.OSVersion, "architecture": artifact.Architecture,
			"web_server": artifact.WebServer, "web_server_version": artifact.WebServerVersion, "web_server_build_hash": artifact.WebServerBuild,
		}
		if artifact.Kind == "module" {
			targetFields["integration_mode"] = model.NormalizeIntegrationMode(artifact.IntegrationMode)
		}
		target, err := json.Marshal(targetFields)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO package_artifacts(id,bundle_version,kind,name,version,target_json,sha256,image_path,rollback_id) VALUES (?,?,?,?,?,?,?,?,NULLIF(?,'')) ON DUPLICATE KEY UPDATE bundle_version=VALUES(bundle_version), target_json=VALUES(target_json), sha256=VALUES(sha256), image_path=VALUES(image_path), rollback_id=VALUES(rollback_id)`, artifact.ID, manifest.BundleVersion, artifact.Kind, artifact.Name, artifact.Version, target, artifact.SHA256, artifact.Path, artifact.RollbackID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListServers(ctx context.Context, enterpriseID string, limit int) ([]ServerRecord, error) {
	query := `SELECT s.id,COALESCE(s.enterprise_id,''),COALESCE(e.name,'미지정'),s.name,s.status,s.inventory_json,s.policy_revision,
COALESCE(ds.policy_revision_id,''),COALESCE(pd.status,''),COALESCE(pd.detail,''),COALESCE(pkg.status,''),COALESCE(pkg.detail,''),
COALESCE(ds.agent_package_id,''),COALESCE(ds.module_package_id,''),COALESCE(cmd.command,''),COALESCE(cmd.status,''),s.revoked_at IS NOT NULL,s.last_heartbeat_at,s.created_at
FROM servers s
LEFT JOIN enterprises e ON e.id=s.enterprise_id
LEFT JOIN desired_states ds ON ds.server_id=s.id
LEFT JOIN policy_deployments pd ON pd.server_id=s.id AND pd.policy_revision_id=ds.policy_revision_id
LEFT JOIN package_deployments pkg ON pkg.id=ds.package_deployment_id
LEFT JOIN agent_commands cmd ON cmd.id=(SELECT ac.id FROM agent_commands ac WHERE ac.server_id=s.id ORDER BY ac.created_at DESC LIMIT 1)`
	args := make([]any, 0, 2)
	if enterpriseID != "" {
		query += ` WHERE s.enterprise_id=?`
		args = append(args, enterpriseID)
	}
	query += ` ORDER BY s.created_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]ServerRecord, 0)
	for rows.Next() {
		var item ServerRecord
		var inventory []byte
		if err := rows.Scan(&item.ID, &item.EnterpriseID, &item.EnterpriseName, &item.Name, &item.Status, &inventory, &item.PolicyRevision, &item.DesiredPolicyRevision, &item.PolicyDeploymentStatus, &item.PolicyDeploymentDetail, &item.PackageDeploymentStatus, &item.PackageDeploymentDetail, &item.AgentPackageID, &item.ModulePackageID, &item.LastCommand, &item.LastCommandStatus, &item.Revoked, &item.LastHeartbeatAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(inventory, &item.Inventory)
		markServerOffline(&item, time.Now().UTC())
		result = append(result, item)
	}
	return result, rows.Err()
}

func markServerOffline(item *ServerRecord, now time.Time) {
	if item == nil || item.Revoked || !item.LastHeartbeatAt.Valid {
		return
	}
	if now.Sub(item.LastHeartbeatAt.Time) > serverOfflineAfter {
		item.Status = "OFFLINE"
	}
}

type EventFilter struct {
	ServerID string
	Severity string
	Query    string
	Blocked  *bool
	Offset   int
}

func (s *Store) ListEvents(ctx context.Context, enterpriseID string, limit int) ([]EventRecord, error) {
	return s.ListEventsFiltered(ctx, enterpriseID, EventFilter{}, limit)
}

func (s *Store) ListEventsFiltered(ctx context.Context, enterpriseID string, filter EventFilter, limit int) ([]EventRecord, error) {
	query := `SELECT se.id,se.agent_id,s.name,COALESCE(e.name,'미지정'),se.occurred_at,se.method,se.uri,se.rule_id,se.message,se.severity,se.blocked
FROM security_events se JOIN servers s ON s.id=se.agent_id LEFT JOIN enterprises e ON e.id=s.enterprise_id`
	conditions := make([]string, 0, 5)
	args := make([]any, 0, 8)
	if enterpriseID != "" {
		conditions = append(conditions, `s.enterprise_id=?`)
		args = append(args, enterpriseID)
	}
	if filter.ServerID != "" {
		conditions = append(conditions, `se.agent_id=?`)
		args = append(args, filter.ServerID)
	}
	if filter.Severity != "" {
		conditions = append(conditions, `se.severity=?`)
		args = append(args, filter.Severity)
	}
	if filter.Blocked != nil {
		conditions = append(conditions, `se.blocked=?`)
		args = append(args, *filter.Blocked)
	}
	if filter.Query != "" {
		conditions = append(conditions, `(se.uri LIKE ? OR se.rule_id LIKE ? OR se.message LIKE ?)`)
		value := "%" + filter.Query + "%"
		args = append(args, value, value, value)
	}
	if len(conditions) != 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	query += ` ORDER BY se.occurred_at DESC LIMIT ? OFFSET ?`
	args = append(args, limit, max(filter.Offset, 0))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]EventRecord, 0)
	for rows.Next() {
		var item EventRecord
		if err := rows.Scan(&item.ID, &item.AgentID, &item.ServerName, &item.EnterpriseName, &item.OccurredAt, &item.Method, &item.URI, &item.RuleID, &item.Message, &item.Severity, &item.Blocked); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) Audit(ctx context.Context, requestID, actor, action, target, result, remote string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO admin_audit_logs(request_id,actor,action,target,result,remote_addr) VALUES (?,?,?,?,?,?)`, requestID, actor, action, target, result, remote)
	return err
}

func tokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func randomID() string {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	raw[6] = (raw[6] & 0x0f) | 0x40
	raw[8] = (raw[8] & 0x3f) | 0x80
	encoded := hex.EncodeToString(raw)
	return fmt.Sprintf("%s-%s-%s-%s-%s", encoded[0:8], encoded[8:12], encoded[12:16], encoded[16:20], encoded[20:32])
}
