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
	EnterprisePolicyID      string
	EnterprisePolicyName    string
	PolicyDeploymentStatus  string
	PolicyDeploymentDetail  string
	PackageDeploymentStatus string
	PackageDeploymentDetail string
	AgentPackageID          string
	ModulePackageID         string
	CanRollbackPackages     bool
	LastCommand             string
	LastCommandStatus       string
	PolicyRolloutActive     bool
	Revoked                 bool
	LastHeartbeatAt         sql.NullTime
	CreatedAt               time.Time
}

type EventRecord struct {
	ID              uint64    `json:"id"`
	IncidentID      uint64    `json:"incident_id,omitempty"`
	RequestID       string    `json:"request_id,omitempty"`
	AgentID         string    `json:"server_id"`
	ServerName      string    `json:"server_name"`
	EnterpriseID    string    `json:"enterprise_id,omitempty"`
	EnterpriseName  string    `json:"enterprise_name"`
	OccurredAt      time.Time `json:"occurred_at"`
	TransactionID   string    `json:"transaction_id,omitempty"`
	Service         string    `json:"service,omitempty"`
	Method          string    `json:"method"`
	URI             string    `json:"uri"`
	ClientIP        string    `json:"client_ip,omitempty"`
	CountryCode     string    `json:"country_code,omitempty"`
	StatusCode      uint16    `json:"status_code"`
	RuleID          string    `json:"rule_id"`
	Message         string    `json:"message"`
	MatchedVariable string    `json:"matched_variable,omitempty"`
	RuleTags        []string  `json:"rule_tags,omitempty"`
	Severity        string    `json:"severity"`
	Blocked         bool      `json:"blocked"`
	PolicyRevision  string    `json:"policy_revision,omitempty"`
	PolicyID        string    `json:"policy_id,omitempty"`
}

func (e EventRecord) SeverityLabel() string {
	labels := map[string]string{"0": "긴급 (EMERGENCY)", "1": "경보 (ALERT)", "2": "치명적 (CRITICAL)", "3": "오류 (ERROR)", "4": "주의 (WARNING)", "5": "알림 (NOTICE)", "6": "정보 (INFO)", "7": "디버그 (DEBUG)"}
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
	result, err := s.db.ExecContext(ctx, `INSERT INTO enrollment_tokens(id,enterprise_id,token_hash,label,expires_at)
SELECT ?,e.id,?,?,? FROM enterprises e WHERE e.id=? AND e.status='ACTIVE'`, randomID(), tokenHash(token), label, expires, enterpriseID)
	if err != nil {
		return "", time.Time{}, err
	}
	created, err := result.RowsAffected()
	if err != nil {
		return "", time.Time{}, err
	}
	if created != 1 {
		return "", time.Time{}, ErrEnterpriseNotActive
	}
	return token, expires, nil
}

func (s *Store) ValidateEnrollmentToken(ctx context.Context, token string) error {
	var used sql.NullTime
	var enterpriseID sql.NullString
	var expires time.Time
	var parentValid bool
	err := s.db.QueryRowContext(ctx, `SELECT et.enterprise_id,et.expires_at,et.used_at,
(et.install_token_id IS NULL OR (it.id IS NOT NULL AND it.revoked_at IS NULL AND (it.expires_at=? OR it.expires_at > UTC_TIMESTAMP(6))))
FROM enrollment_tokens et JOIN enterprises e ON e.id=et.enterprise_id
LEFT JOIN enterprise_install_tokens it ON it.id=et.install_token_id
WHERE et.token_hash=? AND e.status='ACTIVE'`, persistentInstallTokenExpiry, tokenHash(token)).Scan(&enterpriseID, &expires, &used, &parentValid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidEnrollmentToken
		}
		return err
	}
	if !enterpriseID.Valid || enterpriseID.String == "" || used.Valid || !expires.After(time.Now().UTC()) || !parentValid {
		return ErrInvalidEnrollmentToken
	}
	return nil
}

func (s *Store) AllowEnrollmentPackages(ctx context.Context, token string, packageIDs []string) error {
	raw, err := json.Marshal(packageIDs)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE enrollment_tokens SET allowed_packages_json=?
WHERE token_hash=? AND used_at IS NULL AND expires_at > UTC_TIMESTAMP(6)
AND (install_token_id IS NULL OR EXISTS (
  SELECT 1 FROM enterprise_install_tokens it
  WHERE it.id=enrollment_tokens.install_token_id AND it.revoked_at IS NULL AND (it.expires_at=? OR it.expires_at > UTC_TIMESTAMP(6))
)) AND EXISTS (
  SELECT 1 FROM enterprises e WHERE e.id=enrollment_tokens.enterprise_id AND e.status='ACTIVE'
)`, raw, tokenHash(token), persistentInstallTokenExpiry)
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
	err := s.db.QueryRowContext(ctx, `SELECT et.allowed_packages_json
FROM enrollment_tokens et JOIN enterprises e ON e.id=et.enterprise_id
LEFT JOIN enterprise_install_tokens it ON it.id=et.install_token_id
WHERE et.token_hash=? AND et.used_at IS NULL AND et.expires_at > UTC_TIMESTAMP(6)
AND e.status='ACTIVE' AND (et.install_token_id IS NULL OR (it.revoked_at IS NULL AND (it.expires_at=? OR it.expires_at > UTC_TIMESTAMP(6))))`, tokenHash(token), persistentInstallTokenExpiry).Scan(&raw)
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
	var installTokenID sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT enterprise_id,install_token_id,expires_at,used_at,allowed_packages_json
FROM enrollment_tokens WHERE token_hash=? FOR UPDATE`, tokenHash(token)).Scan(&enterpriseID, &installTokenID, &expires, &used, &allowedJSON); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrInvalidEnrollmentToken
		}
		return err
	}
	if !enterpriseID.Valid || enterpriseID.String == "" || used.Valid || !expires.After(time.Now().UTC()) {
		return ErrInvalidEnrollmentToken
	}
	if err := lockActiveEnterprise(ctx, tx, enterpriseID.String); err != nil {
		return ErrInvalidEnrollmentToken
	}
	if installTokenID.Valid {
		var installExpires time.Time
		var revoked sql.NullTime
		var maximum sql.NullInt64
		var enrollmentCount uint64
		if err := tx.QueryRowContext(ctx, `SELECT expires_at,revoked_at,max_enrollments,enrollment_count
FROM enterprise_install_tokens WHERE id=? FOR UPDATE`, installTokenID.String).Scan(&installExpires, &revoked, &maximum, &enrollmentCount); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrInvalidEnrollmentToken
			}
			return err
		}
		if !installTokenUsable(installExpires, revoked, maximum, enrollmentCount) {
			return ErrInvalidEnrollmentToken
		}
	}
	raw, err := json.Marshal(inventory)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO servers(id, enterprise_id, name, certificate_serial, inventory_json, agent_version, module_version) VALUES (?, ?, ?, ?, ?, ?, ?)`, serverID, enterpriseID.String, serverName, certSerial, raw, inventory.AgentVersion, inventory.ModuleVersion); err != nil {
		return err
	}
	desiredAgentID := ""
	desiredModuleID := ""
	if allowedJSON.Valid {
		var packageIDs []string
		if err := json.Unmarshal([]byte(allowedJSON.String), &packageIDs); err != nil {
			return err
		}
		if len(packageIDs) == 1 || len(packageIDs) == 2 {
			desiredAgentID = packageIDs[0]
			if len(packageIDs) == 2 {
				desiredModuleID = packageIDs[1]
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO desired_states(server_id, agent_package_id, module_package_id) VALUES (?, NULLIF(?,''), NULLIF(?,''))`, serverID, desiredAgentID, desiredModuleID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enrollment_tokens SET used_at = UTC_TIMESTAMP(6) WHERE token_hash = ?`, tokenHash(token)); err != nil {
		return err
	}
	if installTokenID.Valid {
		if _, err := tx.ExecContext(ctx, `UPDATE enterprise_install_tokens
SET enrollment_count=enrollment_count+1,last_used_at=UTC_TIMESTAMP(6) WHERE id=?`, installTokenID.String); err != nil {
			return err
		}
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
	var revision, artifactPath, hash, signature, mode, settingsJSON, agentPackage, modulePackage, packageDeployment, packageDeploymentDetail sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT pr.id, pr.artifact_path, pr.artifact_sha256, pr.artifact_signature, pr.mode, pr.settings_json, ds.agent_package_id, ds.module_package_id, ds.package_deployment_id, pkg.detail
FROM servers s
LEFT JOIN desired_states ds ON ds.server_id=s.id
LEFT JOIN policy_revisions pr ON pr.id=ds.policy_revision_id
LEFT JOIN package_deployments pkg ON pkg.id=ds.package_deployment_id
WHERE s.id=? AND s.revoked_at IS NULL`, serverID).Scan(&revision, &artifactPath, &hash, &signature, &mode, &settingsJSON, &agentPackage, &modulePackage, &packageDeployment, &packageDeploymentDetail)
	if err != nil {
		return state, err
	}
	state.RevisionID = revision.String
	state.ArtifactURL = artifactPath.String
	var settings PolicySettings
	if settingsJSON.Valid {
		_ = json.Unmarshal([]byte(settingsJSON.String), &settings)
	}
	if settings.ArtifactFormat != "" {
		state.ArtifactFormat = settings.ArtifactFormat
	} else if strings.HasSuffix(artifactPath.String, ".tar.gz") {
		state.ArtifactFormat = "policy-bundle-v2"
	} else if artifactPath.String != "" {
		state.ArtifactFormat = "conf-v1"
	}
	state.SHA256 = hash.String
	state.Signature = signature.String
	state.Mode = mode.String
	if state.Mode == "" {
		state.Mode = "DetectionOnly"
	}
	state.AgentPackageID = agentPackage.String
	state.ModulePackageID = modulePackage.String
	if packageDeployment.Valid {
		plan := decodePackageDeploymentPlan(packageDeploymentDetail.String)
		state.PackageDeployment = &model.PackageDeployment{ID: packageDeployment.String, WebServerControl: plan.WebServerControl}
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
	var enterpriseID string
	if err := tx.QueryRowContext(ctx, `SELECT enterprise_id FROM servers WHERE id=? AND revoked_at IS NULL`, serverID).Scan(&enterpriseID); err != nil {
		return false, err
	}
	incidentIDs := make(map[string]uint64)
	grouped := make(map[string][]model.SecurityEvent)
	groupOrder := make([]string, 0)
	for _, event := range batch.Events {
		key := incidentKey(event)
		if _, exists := grouped[key]; !exists {
			groupOrder = append(groupOrder, key)
		}
		grouped[key] = append(grouped[key], event)
	}
	for _, key := range groupOrder {
		id, err := insertIncidentTx(ctx, tx, enterpriseID, serverID, key, grouped[key])
		if err != nil {
			return false, err
		}
		incidentIDs[key] = id
	}
	if len(batch.Events) != 0 {
		const columns = 20
		placeholders := make([]string, 0, len(batch.Events))
		args := make([]any, 0, len(batch.Events)*columns)
		for _, event := range batch.Events {
			_, ip := canonicalEventIP(event.ClientIP)
			tags, err := json.Marshal(event.RuleTags)
			if err != nil {
				return false, err
			}
			placeholders = append(placeholders, "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)")
			args = append(args, incidentIDs[incidentKey(event)], serverID, batch.BatchID, event.EventID, event.RequestID, ip, event.OccurredAt.UTC(), event.TransactionID, event.Service, event.Method, event.URI, event.StatusCode, event.RuleID, event.Message, event.MatchedVariable, tags, event.Severity, event.Blocked, event.PolicyRevision, time.Now().UTC())
		}
		query := `INSERT INTO security_events(incident_id,agent_id,batch_id,event_id,request_id,client_ip,occurred_at,transaction_id,service,method,uri,status_code,rule_id,message,matched_variable,rule_tags_json,severity,blocked,policy_revision,created_at) VALUES ` + strings.Join(placeholders, ",")
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return false, err
		}
		for _, id := range incidentIDs {
			if _, err := tx.ExecContext(ctx, `UPDATE security_incidents SET primary_event_id=(SELECT se.id FROM security_events se WHERE se.incident_id=? ORDER BY CASE WHEN se.rule_id LIKE '949%' OR se.rule_id LIKE '959%' OR se.rule_id LIKE '980%' THEN 1 ELSE 0 END,se.id LIMIT 1) WHERE id=?`, id, id); err != nil {
				return false, err
			}
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
	for _, source := range manifest.PolicySources {
		target, err := json.Marshal(map[string]any{
			"source_id": source.ID, "provider": source.Provider, "repository": source.Repository,
			"channel": source.Channel, "crs_version": source.Version, "tag": source.Tag,
			"commit": source.Commit, "archive_sha256": source.ArchiveSHA256,
			"index_sha256": source.IndexSHA256, "compatible_package_ids": source.CompatiblePackageIDs,
		})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO package_artifacts(id,bundle_version,kind,name,version,target_json,sha256,image_path,rollback_id) VALUES (?,?,?,?,?,?,?,?,NULL) ON DUPLICATE KEY UPDATE bundle_version=VALUES(bundle_version), target_json=VALUES(target_json), sha256=VALUES(sha256), image_path=VALUES(image_path), rollback_id=NULL`, source.ID, manifest.BundleVersion, "policy-source", "OWASP Core Rule Set", source.Version, target, source.IndexSHA256, source.IndexPath); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListServers(ctx context.Context, enterpriseID string, limit int) ([]ServerRecord, error) {
	query := `SELECT s.id,COALESCE(s.enterprise_id,''),COALESCE(e.name,'미지정'),s.name,s.status,s.inventory_json,s.policy_revision,
COALESCE(ds.policy_revision_id,''),COALESCE(pd.status,''),COALESCE(pd.detail,''),COALESCE(pkg.status,''),COALESCE(pkg.detail,''),
COALESCE(ds.agent_package_id,''),COALESCE(ds.module_package_id,''),COALESCE(cmd.command,''),COALESCE(cmd.status,''),
EXISTS(SELECT 1 FROM policy_rollout_targets prt JOIN policy_rollouts pro ON pro.id=prt.rollout_id WHERE prt.server_id=s.id AND pro.status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED')),
COALESCE(eps.enterprise_policy_id,''),COALESCE(ep.name,''),s.revoked_at IS NOT NULL,s.last_heartbeat_at,s.created_at
FROM servers s
LEFT JOIN enterprises e ON e.id=s.enterprise_id
LEFT JOIN desired_states ds ON ds.server_id=s.id
LEFT JOIN enterprise_policy_servers eps ON eps.server_id=s.id
LEFT JOIN enterprise_policies ep ON ep.id=eps.enterprise_policy_id
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
		if err := rows.Scan(&item.ID, &item.EnterpriseID, &item.EnterpriseName, &item.Name, &item.Status, &inventory, &item.PolicyRevision, &item.DesiredPolicyRevision, &item.PolicyDeploymentStatus, &item.PolicyDeploymentDetail, &item.PackageDeploymentStatus, &item.PackageDeploymentDetail, &item.AgentPackageID, &item.ModulePackageID, &item.LastCommand, &item.LastCommandStatus, &item.PolicyRolloutActive, &item.EnterprisePolicyID, &item.EnterprisePolicyName, &item.Revoked, &item.LastHeartbeatAt, &item.CreatedAt); err != nil {
			return nil, err
		}
		item.PackageDeploymentDetail = packageDeploymentDisplayDetail(item.PackageDeploymentDetail)
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
	EnterpriseID    string
	PolicyID        string
	ServerID        string
	Severity        string
	RuleID          string
	Query           string
	Blocked         *bool
	Since           time.Time
	CursorAt        time.Time
	CursorID        uint64
	CursorDirection string
	Offset          int
}

func (s *Store) ListEvents(ctx context.Context, enterpriseID string, limit int) ([]EventRecord, error) {
	return s.ListEventsFiltered(ctx, enterpriseID, EventFilter{}, limit)
}

func (s *Store) ListEventsFiltered(ctx context.Context, enterpriseID string, filter EventFilter, limit int) ([]EventRecord, error) {
	query := `SELECT se.id,se.agent_id,s.name,COALESCE(s.enterprise_id,''),COALESCE(e.name,'미지정'),se.occurred_at,se.transaction_id,se.service,se.method,se.uri,se.status_code,se.rule_id,se.message,se.severity,se.blocked,se.policy_revision,COALESCE(pr.enterprise_policy_id,'')
FROM security_events se JOIN servers s ON s.id=se.agent_id LEFT JOIN enterprises e ON e.id=s.enterprise_id
LEFT JOIN policy_revisions pr ON pr.id=se.policy_revision`
	conditions := make([]string, 0, 9)
	args := make([]any, 0, 14)
	if enterpriseID != "" {
		conditions = append(conditions, `s.enterprise_id=?`)
		args = append(args, enterpriseID)
	} else if filter.EnterpriseID != "" {
		conditions = append(conditions, `s.enterprise_id=?`)
		args = append(args, filter.EnterpriseID)
	}
	if filter.PolicyID != "" {
		conditions = append(conditions, `pr.enterprise_policy_id=? AND EXISTS (SELECT 1 FROM enterprise_policies ep WHERE ep.id=pr.enterprise_policy_id AND ep.enterprise_id=s.enterprise_id)`)
		args = append(args, filter.PolicyID)
	}
	if filter.ServerID != "" {
		conditions = append(conditions, `se.agent_id=?`)
		args = append(args, filter.ServerID)
	}
	if filter.Severity != "" {
		conditions = append(conditions, `se.severity=?`)
		args = append(args, filter.Severity)
	}
	if filter.RuleID != "" {
		conditions = append(conditions, `se.rule_id=?`)
		args = append(args, filter.RuleID)
	}
	if !filter.Since.IsZero() {
		conditions = append(conditions, `se.occurred_at>=?`)
		args = append(args, filter.Since.UTC())
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
	if !filter.CursorAt.IsZero() && filter.CursorID != 0 {
		operator := "<"
		if filter.CursorDirection == eventCursorAfter {
			operator = ">"
		}
		conditions = append(conditions, `(se.occurred_at `+operator+` ? OR (se.occurred_at=? AND se.id `+operator+` ?))`)
		args = append(args, filter.CursorAt.UTC(), filter.CursorAt.UTC(), filter.CursorID)
		filter.Offset = 0
	}
	if len(conditions) != 0 {
		query += ` WHERE ` + strings.Join(conditions, ` AND `)
	}
	order := "DESC"
	if filter.CursorDirection == eventCursorAfter {
		order = "ASC"
	}
	query += ` ORDER BY se.occurred_at ` + order + `,se.id ` + order + ` LIMIT ? OFFSET ?`
	args = append(args, limit, max(filter.Offset, 0))
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]EventRecord, 0)
	for rows.Next() {
		var item EventRecord
		if err := rows.Scan(&item.ID, &item.AgentID, &item.ServerName, &item.EnterpriseID, &item.EnterpriseName, &item.OccurredAt, &item.TransactionID, &item.Service, &item.Method, &item.URI, &item.StatusCode, &item.RuleID, &item.Message, &item.Severity, &item.Blocked, &item.PolicyRevision, &item.PolicyID); err != nil {
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
