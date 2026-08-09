package manager

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

func (s *Store) ListSystemPolicyVersions(ctx context.Context) ([]SystemPolicyVersionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sp.id,sp.policy_key,sp.version,sp.schema_version,sp.name,sp.description,sp.crs_track,sp.crs_version,sp.status,sp.template_sha256,sp.source_commit,sp.hot_rule_set_version,sp.hot_rule_set_sha256,sp.defaults_json,sp.migration_notes_json,
COUNT(DISTINCT ep.enterprise_id),COUNT(DISTINCT ds.server_id),(SELECT COUNT(*) FROM policy_rollouts pr WHERE pr.target_system_policy_version_id=sp.id AND pr.status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED')),sp.created_at
FROM system_policy_versions sp
LEFT JOIN enterprise_policies ep ON ep.current_system_policy_version_id=sp.id
LEFT JOIN desired_states ds ON ds.policy_revision_id=ep.current_revision_id
GROUP BY sp.id,sp.policy_key,sp.version,sp.schema_version,sp.name,sp.description,sp.crs_track,sp.crs_version,sp.status,sp.template_sha256,sp.source_commit,sp.hot_rule_set_version,sp.hot_rule_set_sha256,sp.defaults_json,sp.migration_notes_json,sp.created_at
ORDER BY sp.policy_key,sp.created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]SystemPolicyVersionRecord, 0)
	for rows.Next() {
		var item SystemPolicyVersionRecord
		var defaults []byte
		var notes []byte
		if err := rows.Scan(&item.ID, &item.Key, &item.Version, &item.SchemaVersion, &item.Name, &item.Description, &item.CRSTrack, &item.CRSVersion, &item.Status, &item.TemplateSHA256, &item.SourceCommit, &item.HotRuleSetVersion, &item.HotRuleSetSHA256, &defaults, &notes, &item.EnterpriseCount, &item.ServerCount, &item.ActiveRolloutCount, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(defaults, &item.Defaults)
		_ = json.Unmarshal(notes, &item.MigrationNotes)
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range items {
		configuration, err := s.PolicyConfigurationBySystemPolicyID(ctx, items[index].ID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		template := systempolicy.Template{Defaults: items[index].Defaults}
		template = configuration.ApplyToSystemPolicyTemplate(template)
		items[index].Defaults = template.Defaults
	}
	return items, nil
}

func (s *Store) SystemPolicyTemplateByID(ctx context.Context, id string) (systempolicy.Template, error) {
	var item systempolicy.Template
	var defaults, notes []byte
	err := s.db.QueryRowContext(ctx, `SELECT schema_version,policy_key,version,name,description,crs_track,crs_version,status,template_sha256,defaults_json,migration_notes_json
FROM system_policy_versions WHERE id=?`, id).Scan(&item.SchemaVersion, &item.Key, &item.Version, &item.Name, &item.Description, &item.CRSTrack, &item.CRSVersion, &item.Status, &item.Digest, &defaults, &notes)
	if err != nil {
		return systempolicy.Template{}, err
	}
	if err := json.Unmarshal(defaults, &item.Defaults); err != nil {
		return systempolicy.Template{}, fmt.Errorf("decode system policy defaults: %w", err)
	}
	if len(notes) != 0 {
		_ = json.Unmarshal(notes, &item.MigrationNotes)
	}
	configuration, configurationErr := s.PolicyConfigurationBySystemPolicyID(ctx, id)
	if configurationErr == nil {
		item = configuration.ApplyToSystemPolicyTemplate(item)
	} else if !errors.Is(configurationErr, sql.ErrNoRows) {
		return systempolicy.Template{}, configurationErr
	}
	return item, nil
}

func (s *Store) LatestSystemPolicyTemplate(ctx context.Context, key string) (systempolicy.Template, error) {
	var id string
	err := s.db.QueryRowContext(ctx, `SELECT id FROM system_policy_versions WHERE policy_key=? AND status='PUBLISHED' ORDER BY created_at DESC LIMIT 1`, key).Scan(&id)
	if err != nil {
		return systempolicy.Template{}, err
	}
	return s.SystemPolicyTemplateByID(ctx, id)
}

func (s *Store) ListPublishedSystemPolicyTemplates(ctx context.Context) ([]systempolicy.Template, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM system_policy_versions WHERE status='PUBLISHED' ORDER BY policy_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	items := make([]systempolicy.Template, 0, len(ids))
	for _, id := range ids {
		item, err := s.SystemPolicyTemplateByID(ctx, id)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, nil
}

func (s *Store) NextSystemPolicyVersion(ctx context.Context) (string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT version FROM system_policy_versions WHERE policy_key=?`, systempolicy.DefaultTemplateKey)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	versions := make([]string, 0)
	for rows.Next() {
		var version string
		if err := rows.Scan(&version); err != nil {
			return "", err
		}
		versions = append(versions, version)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	return nextSystemPolicyVersionAfter(versions), nil
}

func (s *Store) PublishSystemPolicyVersion(ctx context.Context, item systempolicy.Template, sourceCommit, expectedCurrentID string) error {
	defaultsJSON, err := json.Marshal(item.Defaults)
	if err != nil {
		return err
	}
	notesJSON, err := json.Marshal(item.MigrationNotes)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_policy_versions WHERE id=?`, item.Reference()).Scan(&exists); err != nil {
		return err
	}
	if exists != 0 {
		return errors.New("system policy version already exists")
	}
	if item.Key != systempolicy.DefaultTemplateKey {
		return errors.New("Manager publishing is limited to the canonical crs-baseline policy")
	}
	type currentPolicy struct {
		id, key, version string
		schema           int
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,policy_key,version,schema_version FROM system_policy_versions
WHERE policy_key IN (?,?,?) AND status='PUBLISHED'
ORDER BY CASE policy_key WHEN ? THEN 0 WHEN ? THEN 1 ELSE 2 END,created_at DESC FOR UPDATE`,
		systempolicy.DefaultTemplateKey, systempolicy.DefaultOperatingTemplateKey, systempolicy.DefaultStableTemplateKey,
		systempolicy.DefaultTemplateKey, systempolicy.DefaultOperatingTemplateKey)
	if err != nil {
		return err
	}
	var current currentPolicy
	for rows.Next() {
		var candidate currentPolicy
		if err := rows.Scan(&candidate.id, &candidate.key, &candidate.version, &candidate.schema); err != nil {
			rows.Close()
			return err
		}
		if current.id == "" {
			current = candidate
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if current.id != expectedCurrentID {
		return errors.New("current system policy changed; validate the latest state again")
	}
	versionRows, err := tx.QueryContext(ctx, `SELECT version FROM system_policy_versions WHERE policy_key=? FOR UPDATE`, systempolicy.DefaultTemplateKey)
	if err != nil {
		return err
	}
	versions := make([]string, 0)
	for versionRows.Next() {
		var version string
		if err := versionRows.Scan(&version); err != nil {
			versionRows.Close()
			return err
		}
		versions = append(versions, version)
	}
	if err := versionRows.Err(); err != nil {
		versionRows.Close()
		return err
	}
	if err := versionRows.Close(); err != nil {
		return err
	}
	if item.Version != nextSystemPolicyVersionAfter(versions) {
		return errors.New("a canonical system policy must use the next unused patch version")
	}
	if current.id != "" && current.key == systempolicy.DefaultTemplateKey && item.SchemaVersion < current.schema {
		return errors.New("a canonical system policy cannot reduce its schema version")
	}
	if item.Defaults.CRSSource == nil || item.Defaults.CRSSource.Commit != sourceCommit {
		return errors.New("system policy source commit is not pinned")
	}
	var verifiedRelease int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM crs_releases WHERE id=? AND commit_sha=? AND status='VERIFIED' AND tag_signature_verified=TRUE`, item.Defaults.CRSSource.ID, sourceCommit).Scan(&verifiedRelease); err != nil {
		return err
	}
	if verifiedRelease != 1 {
		return errors.New("verified CRS release is unavailable")
	}
	if _, err := tx.ExecContext(ctx, `UPDATE system_policy_versions SET status='DEPRECATED' WHERE policy_key IN (?,?,?) AND status='PUBLISHED'`, systempolicy.DefaultTemplateKey, systempolicy.DefaultOperatingTemplateKey, systempolicy.DefaultStableTemplateKey); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO system_policy_versions(id,policy_key,version,schema_version,name,description,crs_track,crs_version,status,template_sha256,source_commit,hot_rule_set_version,hot_rule_set_sha256,defaults_json,migration_notes_json)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, item.Reference(), item.Key, item.Version, item.SchemaVersion, item.Name, item.Description, item.CRSTrack, item.CRSVersion, systempolicy.StatusPublished, item.Digest, sourceCommit, item.Defaults.HotRuleSetVersion, item.Defaults.HotRuleSetSHA256, defaultsJSON, notesJSON)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE enterprise_policies SET system_policy_key=? WHERE system_policy_key IN (?,?)`, systempolicy.DefaultTemplateKey, systempolicy.DefaultOperatingTemplateKey, systempolicy.DefaultStableTemplateKey); err != nil {
		return err
	}
	settings := PolicySettings{
		ParanoiaLevel: item.Defaults.ParanoiaLevel, ExecutingParanoiaLevel: item.Defaults.ExecutingParanoiaLevel,
		InboundScore: item.Defaults.InboundScore, OutboundScore: item.Defaults.OutboundScore,
		RequestBody: item.Defaults.RequestBody, ResponseBody: item.Defaults.ResponseBody,
		EarlyBlocking: item.Defaults.EarlyBlocking, SamplingPercentage: item.Defaults.SamplingPercentage,
	}
	configuration, legacy, err := structuredConfigurationFromPolicy(item.Reference(), "", item, item.Defaults.Mode, settings)
	if err != nil {
		return err
	}
	if err := insertPolicyConfigurationTx(ctx, tx, configuration); err != nil {
		return err
	}
	status := PolicyConfigMigrated
	detail := ""
	if legacy {
		status = PolicyConfigLegacyCompat
		detail = "legacy bypass or Rule ID range preserved"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE system_policy_versions SET config_storage_version=2,config_migration_status=?,config_migration_detail=? WHERE id=?`, status, detail, item.Reference()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) WithdrawSystemPolicyVersion(ctx context.Context, id string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE system_policy_versions SET status='WITHDRAWN'
WHERE id=? AND status IN ('PUBLISHED','DEPRECATED')
AND NOT EXISTS (SELECT 1 FROM enterprise_policies WHERE current_system_policy_version_id=system_policy_versions.id)
AND NOT EXISTS (SELECT 1 FROM policy_rollouts WHERE target_system_policy_version_id=system_policy_versions.id AND status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED'))`, id)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return errors.New("system policy version cannot be withdrawn")
	}
	return nil
}

type legacyPolicyRevision struct {
	ID           string
	EnterpriseID string
	Name         string
	Description  string
	Mode         string
	Settings     PolicySettings
	RequestedBy  string
	Active       bool
	CreatedAt    time.Time
}

func (s *Store) BackfillEnterprisePolicyDomains(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT pr.id,COALESCE(pr.enterprise_id,''),pr.revision_name,pr.description,pr.mode,pr.settings_json,
COALESCE((SELECT pd.requested_by FROM policy_deployments pd WHERE pd.policy_revision_id=pr.id AND pd.requested_by IS NOT NULL ORDER BY pd.created_at LIMIT 1),''),
EXISTS(SELECT 1 FROM desired_states ds WHERE ds.policy_revision_id=pr.id),pr.created_at
FROM policy_revisions pr WHERE pr.enterprise_policy_id IS NULL ORDER BY pr.created_at`)
	if err != nil {
		return err
	}
	items := make(map[string]legacyPolicyRevision)
	for rows.Next() {
		var item legacyPolicyRevision
		var raw sql.NullString
		if err := rows.Scan(&item.ID, &item.EnterpriseID, &item.Name, &item.Description, &item.Mode, &raw, &item.RequestedBy, &item.Active, &item.CreatedAt); err != nil {
			rows.Close()
			return err
		}
		if raw.Valid {
			_ = json.Unmarshal([]byte(raw.String), &item.Settings)
		}
		items[item.ID] = item
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(items) == 0 {
		return tx.Commit()
	}

	groups := make(map[string][]legacyPolicyRevision)
	for _, item := range items {
		root := item.ID
		seen := make(map[string]bool)
		for parent := item.Settings.MigratedFrom; parent != "" && !seen[parent]; {
			seen[parent] = true
			candidate, ok := items[parent]
			if !ok || candidate.EnterpriseID != item.EnterpriseID {
				break
			}
			root = candidate.ID
			parent = candidate.Settings.MigratedFrom
		}
		groups[root] = append(groups[root], item)
	}
	for _, revisions := range groups {
		sort.Slice(revisions, func(i, j int) bool { return revisions[i].CreatedAt.Before(revisions[j].CreatedAt) })
		current := revisions[len(revisions)-1]
		for _, revision := range revisions {
			if revision.Active && (!current.Active || revision.CreatedAt.After(current.CreatedAt)) {
				current = revision
			}
		}
		if current.EnterpriseID == "" {
			continue
		}
		status := EnterprisePolicyActive
		strategy := PolicyStrategyPinned
		systemVersionID := ""
		target := current.Settings.Target
		if target == "" {
			status = EnterprisePolicyLegacyLocked
			target = "legacy:" + current.ID
		}
		if current.Settings.TemplateKey == "" || current.Settings.TemplateVersion == "" {
			status = EnterprisePolicyLegacyLocked
		} else {
			systemVersionID = current.Settings.TemplateKey + "@" + current.Settings.TemplateVersion
			var exists int
			if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_policy_versions WHERE id=?`, systemVersionID).Scan(&exists); err != nil {
				return err
			}
			if exists != 1 {
				status = EnterprisePolicyLegacyLocked
				systemVersionID = ""
			}
			if current.Settings.PolicyOrigin == "system-seed" {
				strategy = PolicyStrategyManual
			} else if current.Settings.AutoUpdate {
				strategy = PolicyStrategyAutomatic
			}
		}
		policyID := randomID()
		previousRevisionID := current.Settings.MigratedFrom
		if _, exists := items[previousRevisionID]; !exists {
			previousRevisionID = ""
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO enterprise_policies(id,enterprise_id,name,description,target,system_policy_key,current_system_policy_version_id,update_strategy,status,current_revision_id,previous_revision_id,created_by)
VALUES (?,?,?,?,?,NULLIF(?,''),NULLIF(?,''),?,?,?,NULLIF(?,''),NULLIF(?,''))`, policyID, current.EnterpriseID, current.Name, current.Description, target, current.Settings.TemplateKey, systemVersionID, strategy, status, current.ID, previousRevisionID, current.RequestedBy)
		if err != nil {
			return err
		}
		for _, revision := range revisions {
			versionID := ""
			if revision.Settings.TemplateKey != "" && revision.Settings.TemplateVersion != "" {
				candidate := revision.Settings.TemplateKey + "@" + revision.Settings.TemplateVersion
				var exists int
				if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM system_policy_versions WHERE id=?`, candidate).Scan(&exists); err != nil {
					return err
				}
				if exists == 1 {
					versionID = candidate
				}
			}
			origin := revision.Settings.PolicyOrigin
			if origin == "" {
				origin = "LEGACY"
			}
			parentRevisionID := revision.Settings.MigratedFrom
			parent, exists := items[parentRevisionID]
			if !exists || parent.EnterpriseID != revision.EnterpriseID {
				parentRevisionID = ""
			}
			if _, err := tx.ExecContext(ctx, `UPDATE policy_revisions SET enterprise_policy_id=?,system_policy_version_id=NULLIF(?,''),parent_revision_id=NULLIF(?,''),policy_origin=? WHERE id=?`, policyID, versionID, parentRevisionID, origin, revision.ID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (s *Store) ListEnterprisePolicies(ctx context.Context, enterpriseID string, limit int) ([]EnterprisePolicyRecord, error) {
	query := `SELECT ep.id,ep.enterprise_id,e.name,ep.name,ep.description,ep.target,COALESCE(ep.system_policy_key,''),COALESCE(cur.name,latest.name,''),
COALESCE(ep.current_system_policy_version_id,''),COALESCE(cur.version,''),COALESCE(cur.crs_version,''),COALESCE(latest.id,''),COALESCE(latest.version,''),COALESCE(latest.crs_version,''),
ep.update_strategy,ep.status,COALESCE(ep.current_revision_id,''),COALESCE(ep.previous_revision_id,''),COALESCE(pr.mode,''),pr.settings_json,
COALESCE((SELECT r.id FROM policy_rollouts r WHERE r.enterprise_policy_id=ep.id ORDER BY r.created_at DESC LIMIT 1),''),
COALESCE((SELECT r.status FROM policy_rollouts r WHERE r.enterprise_policy_id=ep.id ORDER BY r.created_at DESC LIMIT 1),''),
EXISTS(SELECT 1 FROM policy_rollouts r WHERE r.enterprise_policy_id=ep.id AND r.status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED')),ep.created_at,ep.updated_at,
EXISTS(SELECT 1 FROM policy_migration_impacts mi WHERE mi.enterprise_policy_id=ep.id AND mi.target_system_policy_version_id=latest.id AND mi.status='MIGRATION_REQUIRED'),
COALESCE((SELECT mi.detail FROM policy_migration_impacts mi WHERE mi.enterprise_policy_id=ep.id AND mi.target_system_policy_version_id=latest.id LIMIT 1),'')
FROM enterprise_policies ep
JOIN enterprises e ON e.id=ep.enterprise_id
LEFT JOIN system_policy_versions cur ON cur.id=ep.current_system_policy_version_id
LEFT JOIN system_policy_versions latest ON latest.policy_key=ep.system_policy_key AND latest.status='PUBLISHED'
LEFT JOIN policy_revisions pr ON pr.id=ep.current_revision_id`
	args := make([]any, 0, 2)
	if enterpriseID != "" {
		query += ` WHERE ep.enterprise_id=?`
		args = append(args, enterpriseID)
	}
	query += ` ORDER BY e.name,ep.updated_at DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]EnterprisePolicyRecord, 0)
	for rows.Next() {
		var item EnterprisePolicyRecord
		var settings sql.NullString
		if err := rows.Scan(&item.ID, &item.EnterpriseID, &item.EnterpriseName, &item.Name, &item.Description, &item.Target, &item.SystemPolicyKey, &item.SystemPolicyName,
			&item.CurrentSystemPolicyID, &item.CurrentSystemPolicyVersion, &item.CurrentCRSVersion, &item.LatestSystemPolicyID, &item.LatestSystemPolicyVersion, &item.LatestCRSVersion,
			&item.UpdateStrategy, &item.Status, &item.CurrentRevisionID, &item.PreviousRevisionID, &item.CurrentMode, &settings, &item.LatestRolloutID, &item.LatestRolloutStatus, &item.HasActiveRollout, &item.CreatedAt, &item.UpdatedAt, &item.MigrationRequired, &item.MigrationDetail); err != nil {
			return nil, err
		}
		if settings.Valid {
			_ = json.Unmarshal([]byte(settings.String), &item.CurrentSettings)
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for index := range items {
		if items[index].CurrentRevisionID == "" {
			continue
		}
		configuration, err := s.PolicyConfigurationByRevisionID(ctx, items[index].CurrentRevisionID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, err
		}
		items[index].CurrentSettings = configuration.ApplyToSettings(items[index].CurrentSettings)
		items[index].CurrentConfiguration = &configuration
	}
	return items, nil
}

func (s *Store) EnterprisePolicyByID(ctx context.Context, scopeEnterpriseID, id string) (EnterprisePolicyRecord, error) {
	items, err := s.ListEnterprisePolicies(ctx, scopeEnterpriseID, 5000)
	if err != nil {
		return EnterprisePolicyRecord{}, err
	}
	for _, item := range items {
		if item.ID == id {
			return item, nil
		}
	}
	return EnterprisePolicyRecord{}, sql.ErrNoRows
}

func (s *Store) PolicyRevisionByID(ctx context.Context, enterprisePolicyID, revisionID string) (PolicyRevisionRecord, error) {
	var item PolicyRevisionRecord
	var settings sql.NullString
	err := s.db.QueryRowContext(ctx, `SELECT id,COALESCE(enterprise_policy_id,''),COALESCE(system_policy_version_id,''),COALESCE(parent_revision_id,''),revision_name,description,mode,settings_json,artifact_path,artifact_sha256,artifact_signature,policy_origin,created_at
FROM policy_revisions WHERE id=? AND enterprise_policy_id=?`, revisionID, enterprisePolicyID).Scan(&item.ID, &item.EnterprisePolicyID, &item.SystemPolicyVersionID, &item.ParentRevisionID, &item.Name, &item.Description, &item.Mode, &settings, &item.ArtifactPath, &item.ArtifactSHA256, &item.ArtifactSignature, &item.PolicyOrigin, &item.CreatedAt)
	if settings.Valid {
		_ = json.Unmarshal([]byte(settings.String), &item.Settings)
	}
	if err == nil {
		configuration, configurationErr := s.PolicyConfigurationByRevisionID(ctx, revisionID)
		if configurationErr == nil {
			item.Settings = configuration.ApplyToSettings(item.Settings)
		} else if !errors.Is(configurationErr, sql.ErrNoRows) {
			return PolicyRevisionRecord{}, configurationErr
		}
	}
	return item, err
}

func (s *Store) UpdateEnterprisePolicyStrategy(ctx context.Context, scopeEnterpriseID, policyID, expectedRevisionID, strategy, userID string) error {
	if strategy != PolicyStrategyManual && strategy != PolicyStrategyAutomatic && strategy != PolicyStrategyPinned {
		return errors.New("invalid enterprise policy update strategy")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var currentStrategy string
	if err := tx.QueryRowContext(ctx, `SELECT ep.update_strategy FROM enterprise_policies ep JOIN enterprises e ON e.id=ep.enterprise_id
WHERE ep.id=? AND ep.status='ACTIVE' AND e.status='ACTIVE' AND COALESCE(ep.current_revision_id,'')=? AND (?='' OR ep.enterprise_id=?) FOR UPDATE`, policyID, expectedRevisionID, scopeEnterpriseID, scopeEnterpriseID).Scan(&currentStrategy); err != nil {
		return err
	}
	if currentStrategy != strategy {
		if _, err := tx.ExecContext(ctx, `UPDATE enterprise_policies SET update_strategy=? WHERE id=?`, strategy, policyID); err != nil {
			return err
		}
	}
	if strategy == PolicyStrategyPinned {
		if _, err := tx.ExecContext(ctx, `UPDATE policy_rollouts SET status='CANCELLED',detail='기업 사용자가 버전 고정 전략으로 변경함',completed_at=UTC_TIMESTAMP(6) WHERE enterprise_policy_id=? AND status='AWAITING_APPROVAL'`, policyID); err != nil {
			return err
		}
	}
	if strategy == PolicyStrategyAutomatic {
		if _, err := tx.ExecContext(ctx, `UPDATE policy_rollouts SET status='QUEUED',approved_by=NULLIF(?,''),started_at=UTC_TIMESTAMP(6),detail='' WHERE enterprise_policy_id=? AND status='AWAITING_APPROVAL' AND expected_revision_id=?`, userID, policyID, expectedRevisionID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) CreateEnterprisePolicyWithRollout(ctx context.Context, enterpriseID, policyID, name, description, target, systemPolicyKey, strategy, userID string, revision PolicyRevisionInput, rolloutType, rolloutStatus string, serverIDs []string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err := lockActiveEnterprise(ctx, tx, enterpriseID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO enterprise_policies(id,enterprise_id,name,description,target,system_policy_key,update_strategy,status,created_by) VALUES (?,?,?,?,?,?,?,'ACTIVE',NULLIF(?,''))`, policyID, enterpriseID, name, description, target, systemPolicyKey, strategy, userID); err != nil {
		return "", err
	}
	if err := insertPolicyRevisionTx(ctx, tx, enterpriseID, policyID, revision); err != nil {
		return "", err
	}
	rolloutID := randomID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_rollouts(id,enterprise_policy_id,rollout_type,status,target_system_policy_version_id,target_revision_id,batch_size,requested_by,approved_by,detail) VALUES (?,?,?,?,?,?,25,NULLIF(?,''),NULLIF(?,''),'')`, rolloutID, policyID, rolloutType, rolloutStatus, revision.SystemPolicyVersionID, revision.ID, userID, userID); err != nil {
		return "", err
	}
	if err := insertRolloutTargetsTx(ctx, tx, rolloutID, revision.ID, serverIDs); err != nil {
		return "", err
	}
	return rolloutID, tx.Commit()
}

func (s *Store) ConvertLegacyEnterprisePolicy(ctx context.Context, policy EnterprisePolicyRecord, expectedRevisionID, systemPolicyKey, userID string, revision PolicyRevisionInput, serverIDs []string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE enterprise_policies SET status='ACTIVE',system_policy_key=?,update_strategy='MANUAL'
WHERE id=? AND enterprise_id=? AND status='LEGACY_LOCKED' AND COALESCE(current_revision_id,'')=?
AND EXISTS (SELECT 1 FROM enterprises e WHERE e.id=enterprise_policies.enterprise_id AND e.status='ACTIVE')`, systemPolicyKey, policy.ID, policy.EnterpriseID, expectedRevisionID)
	if err != nil {
		return "", err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return "", err
	}
	if changed != 1 {
		return "", errors.New("enterprise policy revision changed")
	}
	if err := insertPolicyRevisionTx(ctx, tx, policy.EnterpriseID, policy.ID, revision); err != nil {
		return "", err
	}
	rolloutID := randomID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_rollouts(id,enterprise_policy_id,rollout_type,status,from_revision_id,target_system_policy_version_id,target_revision_id,expected_revision_id,batch_size,requested_by,approved_by,detail,started_at) VALUES (?,?,'UPDATE','QUEUED',?,?,?,?,25,NULLIF(?,''),NULLIF(?,''),'',UTC_TIMESTAMP(6))`, rolloutID, policy.ID, expectedRevisionID, revision.SystemPolicyVersionID, revision.ID, expectedRevisionID, userID, userID); err != nil {
		return "", err
	}
	if err := insertRolloutTargetsTx(ctx, tx, rolloutID, revision.ID, serverIDs); err != nil {
		return "", err
	}
	return rolloutID, tx.Commit()
}

func (s *Store) CreatePolicyRollout(ctx context.Context, policy EnterprisePolicyRecord, expectedRevisionID, rolloutType, rolloutStatus, userID string, revision *PolicyRevisionInput, targetRevisionID, targetSystemVersionID string, serverIDs []string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err := lockActiveEnterprise(ctx, tx, policy.EnterpriseID); err != nil {
		return "", err
	}
	var currentRevisionID string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(current_revision_id,'') FROM enterprise_policies WHERE id=? AND enterprise_id=? FOR UPDATE`, policy.ID, policy.EnterpriseID).Scan(&currentRevisionID); err != nil {
		return "", err
	}
	if currentRevisionID != expectedRevisionID {
		return "", errors.New("enterprise policy revision changed")
	}
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_rollouts WHERE enterprise_policy_id=? AND status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED')`, policy.ID).Scan(&active); err != nil {
		return "", err
	}
	if active != 0 {
		return "", errors.New("enterprise policy already has an active rollout")
	}
	if revision != nil {
		if _, err := tx.ExecContext(ctx, `UPDATE enterprise_policies SET name=?,description=? WHERE id=? AND enterprise_id=?`, revision.Name, revision.Description, policy.ID, policy.EnterpriseID); err != nil {
			return "", err
		}
		if err := insertPolicyRevisionTx(ctx, tx, policy.EnterpriseID, policy.ID, *revision); err != nil {
			return "", err
		}
		targetRevisionID = revision.ID
	}
	rolloutID := randomID()
	approvedBy := ""
	if rolloutStatus != "AWAITING_APPROVAL" {
		approvedBy = userID
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_rollouts(id,enterprise_policy_id,rollout_type,status,from_revision_id,target_system_policy_version_id,target_revision_id,expected_revision_id,batch_size,requested_by,approved_by,detail) VALUES (?,?,?,?,?, ?,?,?,25,NULLIF(?,''),NULLIF(?,''),'')`, rolloutID, policy.ID, rolloutType, rolloutStatus, currentRevisionID, targetSystemVersionID, targetRevisionID, currentRevisionID, userID, approvedBy); err != nil {
		return "", err
	}
	if err := insertRolloutTargetsTx(ctx, tx, rolloutID, targetRevisionID, serverIDs); err != nil {
		return "", err
	}
	return rolloutID, tx.Commit()
}

func (s *Store) PolicyUpdateBlocked(ctx context.Context, policyID, targetSystemVersionID string) (bool, error) {
	var count int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_rollouts WHERE enterprise_policy_id=? AND (status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED') OR (rollout_type='UPDATE' AND target_system_policy_version_id=? AND status='FAILED'))`, policyID, targetSystemVersionID).Scan(&count)
	return count != 0, err
}

func insertPolicyRevisionTx(ctx context.Context, tx *sql.Tx, enterpriseID, enterprisePolicyID string, revision PolicyRevisionInput) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO policy_revisions(id,enterprise_id,enterprise_policy_id,system_policy_version_id,parent_revision_id,policy_origin,revision_name,description,mode,settings_json,artifact_path,artifact_sha256,artifact_signature)
VALUES (?,?,?,NULLIF(?,''),NULLIF(?,''),?,?,?,?,?,?,?,?)`, revision.ID, enterpriseID, enterprisePolicyID, revision.SystemPolicyVersionID, revision.ParentRevisionID, revision.PolicyOrigin, revision.Name, revision.Description, revision.Mode, revision.SettingsJSON, revision.ArtifactPath, revision.ArtifactSHA256, revision.ArtifactSignature)
	if err != nil || revision.Configuration == nil {
		return err
	}
	configuration := *revision.Configuration
	configuration.SystemPolicyVersionID = ""
	configuration.PolicyRevisionID = revision.ID
	if err := insertPolicyConfigurationTx(ctx, tx, configuration); err != nil {
		return err
	}
	status := PolicyConfigMigrated
	detail := ""
	for _, item := range configuration.Exclusions {
		if item.Legacy {
			status = PolicyConfigLegacyCompat
			detail = "legacy bypass preserved"
			break
		}
	}
	for _, item := range configuration.CustomRules {
		if item.LegacyIDRange {
			status = PolicyConfigLegacyCompat
			detail = "legacy Rule ID range preserved"
			break
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE policy_revisions SET config_storage_version=2,config_migration_status=?,config_migration_detail=? WHERE id=?`, status, detail, revision.ID)
	return err
}

func insertRolloutTargetsTx(ctx context.Context, tx *sql.Tx, rolloutID, finalRevisionID string, serverIDs []string) error {
	for index, serverID := range serverIDs {
		batchNo := 0
		if index > 0 {
			batchNo = 1 + (index-1)/25
		}
		var agentID, moduleID sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT agent_package_id,module_package_id FROM desired_states WHERE server_id=?`, serverID).Scan(&agentID, &moduleID); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_rollout_targets(rollout_id,server_id,batch_no,status,source_agent_package_id,source_module_package_id,final_revision_id,detail) VALUES (?,?,?,'PENDING',?,?,?,'')`, rolloutID, serverID, batchNo, agentID, moduleID, finalRevisionID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) ApprovePolicyRollout(ctx context.Context, scopeEnterpriseID, policyID, rolloutID, expectedRevisionID, userID string) error {
	result, err := s.db.ExecContext(ctx, `UPDATE policy_rollouts r JOIN enterprise_policies ep ON ep.id=r.enterprise_policy_id JOIN enterprises e ON e.id=ep.enterprise_id
SET r.status='QUEUED',r.approved_by=?,r.started_at=UTC_TIMESTAMP(6),r.detail=''
WHERE r.id=? AND r.enterprise_policy_id=? AND r.status='AWAITING_APPROVAL' AND e.status='ACTIVE' AND COALESCE(r.expected_revision_id,'')=? AND COALESCE(ep.current_revision_id,'')=? AND (?='' OR ep.enterprise_id=?)`, userID, rolloutID, policyID, expectedRevisionID, expectedRevisionID, scopeEnterpriseID, scopeEnterpriseID)
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

func (s *Store) RetryPolicyRollout(ctx context.Context, scopeEnterpriseID, policyID, rolloutID, expectedRevisionID, userID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var active int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_rollouts WHERE enterprise_policy_id=? AND id<>? AND status IN ('AWAITING_APPROVAL','QUEUED','CANARY','EXPANDING','PAUSED')`, policyID, rolloutID).Scan(&active); err != nil {
		return err
	}
	if active != 0 {
		return errors.New("enterprise policy already has an active rollout")
	}
	result, err := tx.ExecContext(ctx, `UPDATE policy_rollouts r JOIN enterprise_policies ep ON ep.id=r.enterprise_policy_id JOIN enterprises e ON e.id=ep.enterprise_id
SET r.status='QUEUED',r.approved_by=?,r.detail='',r.started_at=UTC_TIMESTAMP(6),r.completed_at=NULL
WHERE r.id=? AND r.enterprise_policy_id=? AND r.status IN ('PAUSED','FAILED') AND e.status='ACTIVE' AND COALESCE(r.expected_revision_id,'')=? AND COALESCE(ep.current_revision_id,'')=? AND (?='' OR ep.enterprise_id=?)`, userID, rolloutID, policyID, expectedRevisionID, expectedRevisionID, scopeEnterpriseID, scopeEnterpriseID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_rollout_targets SET status='PENDING',resume_status=NULL,detail='',stabilized_at=NULL WHERE rollout_id=?`, rolloutID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListPolicyRollouts(ctx context.Context, scopeEnterpriseID, policyID string, limit int) ([]PolicyRolloutRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id,r.enterprise_policy_id,ep.enterprise_id,ep.name,ep.target,r.rollout_type,r.status,COALESCE(r.from_revision_id,''),r.target_system_policy_version_id,COALESCE(r.target_revision_id,''),COALESCE(r.expected_revision_id,''),r.detail,
COALESCE(SUM(t.status IN ('PENDING','TRANSITION_PENDING','PACKAGE_PENDING','POLICY_PENDING','ROLLBACK_PENDING')),0),
COALESCE(SUM(t.status='DEFERRED'),0),COALESCE(SUM(t.status IN ('APPLIED','ROLLED_BACK')),0),COALESCE(SUM(t.status='FAILED'),0),r.created_at,r.updated_at
FROM policy_rollouts r
JOIN enterprise_policies ep ON ep.id=r.enterprise_policy_id
LEFT JOIN policy_rollout_targets t ON t.rollout_id=r.id
WHERE r.enterprise_policy_id=? AND (?='' OR ep.enterprise_id=?)
GROUP BY r.id,r.enterprise_policy_id,ep.enterprise_id,ep.name,ep.target,r.rollout_type,r.status,r.from_revision_id,r.target_system_policy_version_id,r.target_revision_id,r.expected_revision_id,r.detail,r.created_at,r.updated_at
ORDER BY r.created_at DESC LIMIT ?`, policyID, scopeEnterpriseID, scopeEnterpriseID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PolicyRolloutRecord, 0)
	for rows.Next() {
		var item PolicyRolloutRecord
		if err := rows.Scan(&item.ID, &item.EnterprisePolicyID, &item.EnterpriseID, &item.PolicyName, &item.Target, &item.Type, &item.Status, &item.FromRevisionID, &item.TargetSystemPolicyVersionID, &item.TargetRevisionID, &item.ExpectedRevisionID, &item.Detail, &item.PendingCount, &item.DeferredCount, &item.AppliedCount, &item.FailedCount, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListPolicyRevisions(ctx context.Context, scopeEnterpriseID, policyID string, limit int) ([]PolicyRevisionRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT pr.id,COALESCE(pr.enterprise_policy_id,''),COALESCE(pr.system_policy_version_id,''),COALESCE(pr.parent_revision_id,''),pr.revision_name,pr.description,pr.mode,pr.settings_json,pr.artifact_path,pr.artifact_sha256,pr.artifact_signature,pr.policy_origin,pr.created_at
FROM policy_revisions pr JOIN enterprise_policies ep ON ep.id=pr.enterprise_policy_id
WHERE pr.enterprise_policy_id=? AND (?='' OR ep.enterprise_id=?) ORDER BY pr.created_at DESC LIMIT ?`, policyID, scopeEnterpriseID, scopeEnterpriseID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PolicyRevisionRecord, 0)
	for rows.Next() {
		var item PolicyRevisionRecord
		var settings sql.NullString
		if err := rows.Scan(&item.ID, &item.EnterprisePolicyID, &item.SystemPolicyVersionID, &item.ParentRevisionID, &item.Name, &item.Description, &item.Mode, &settings, &item.ArtifactPath, &item.ArtifactSHA256, &item.ArtifactSignature, &item.PolicyOrigin, &item.CreatedAt); err != nil {
			return nil, err
		}
		if settings.Valid {
			_ = json.Unmarshal([]byte(settings.String), &item.Settings)
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListActivePolicyRollouts(ctx context.Context) ([]PolicyRolloutRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT r.id,r.enterprise_policy_id,ep.enterprise_id,ep.name,ep.target,r.rollout_type,r.status,COALESCE(r.from_revision_id,''),r.target_system_policy_version_id,COALESCE(r.target_revision_id,''),COALESCE(r.expected_revision_id,''),r.detail,r.created_at,r.updated_at
FROM policy_rollouts r JOIN enterprise_policies ep ON ep.id=r.enterprise_policy_id
JOIN enterprises e ON e.id=ep.enterprise_id
WHERE e.status='ACTIVE' AND r.status IN ('QUEUED','CANARY','EXPANDING') ORDER BY r.created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PolicyRolloutRecord, 0)
	for rows.Next() {
		var item PolicyRolloutRecord
		if err := rows.Scan(&item.ID, &item.EnterprisePolicyID, &item.EnterpriseID, &item.PolicyName, &item.Target, &item.Type, &item.Status, &item.FromRevisionID, &item.TargetSystemPolicyVersionID, &item.TargetRevisionID, &item.ExpectedRevisionID, &item.Detail, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) ListPolicyRolloutTargets(ctx context.Context, rolloutID string) ([]PolicyRolloutTargetRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT t.rollout_id,t.server_id,s.name,t.batch_no,t.status,COALESCE(t.resume_status,''),COALESCE(t.source_agent_package_id,''),COALESCE(t.source_module_package_id,''),COALESCE(t.target_agent_package_id,''),COALESCE(t.target_module_package_id,''),COALESCE(t.transition_revision_id,''),COALESCE(t.final_revision_id,''),COALESCE(t.package_deployment_id,''),t.detail,
s.status,(s.revoked_at IS NULL AND s.last_heartbeat_at >= UTC_TIMESTAMP(6) - INTERVAL 2 MINUTE),s.inventory_json,s.policy_revision,COALESCE(ds.policy_revision_id,''),COALESCE(pkg.status,''),COALESCE(pd.status,''),COALESCE(tpd.status,''),t.stabilized_at,t.updated_at
FROM policy_rollout_targets t JOIN servers s ON s.id=t.server_id
LEFT JOIN desired_states ds ON ds.server_id=s.id
LEFT JOIN package_deployments pkg ON pkg.id=t.package_deployment_id
LEFT JOIN policy_deployments pd ON pd.server_id=t.server_id AND pd.policy_revision_id=t.final_revision_id
LEFT JOIN policy_deployments tpd ON tpd.server_id=t.server_id AND tpd.policy_revision_id=t.transition_revision_id
WHERE t.rollout_id=? ORDER BY t.batch_no,s.name`, rolloutID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]PolicyRolloutTargetRecord, 0)
	for rows.Next() {
		var item PolicyRolloutTargetRecord
		var inventory []byte
		if err := rows.Scan(&item.RolloutID, &item.ServerID, &item.ServerName, &item.BatchNo, &item.Status, &item.ResumeStatus, &item.SourceAgentPackageID, &item.SourceModulePackageID, &item.TargetAgentPackageID, &item.TargetModulePackageID, &item.TransitionRevisionID, &item.FinalRevisionID, &item.PackageDeploymentID, &item.Detail,
			&item.ServerStatus, &item.Online, &inventory, &item.CurrentPolicyRevision, &item.DesiredPolicyRevision, &item.PackageStatus, &item.PolicyStatus, &item.TransitionPolicyStatus, &item.StabilizedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		var decoded struct {
			CRSVersion string `json:"crs_version"`
		}
		_ = json.Unmarshal(inventory, &decoded)
		item.InventoryCRSVersion = decoded.CRSVersion
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Store) UpdatePolicyRolloutStatus(ctx context.Context, rolloutID, status, detail string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE policy_rollouts SET status=?,detail=?,started_at=COALESCE(started_at,UTC_TIMESTAMP(6)),completed_at=IF(? IN ('APPLIED','FAILED','CANCELLED'),UTC_TIMESTAMP(6),completed_at) WHERE id=? AND status<>'CANCELLED'`, status, detail, status, rolloutID)
	return err
}

func (s *Store) UpdatePolicyRolloutTarget(ctx context.Context, rolloutID, serverID, status, detail string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE policy_rollout_targets SET status=?,resume_status=NULL,detail=?,stabilized_at=IF(?='APPLIED',UTC_TIMESTAMP(6),stabilized_at) WHERE rollout_id=? AND server_id=?`, status, detail, status, rolloutID, serverID)
	return err
}

func (s *Store) DeferPolicyRolloutTarget(ctx context.Context, rolloutID, serverID, resumeStatus string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE policy_rollout_targets SET status='DEFERRED',resume_status=?,detail='서버가 오프라인이므로 연결 후 재개합니다.' WHERE rollout_id=? AND server_id=? AND status=?`, resumeStatus, rolloutID, serverID, resumeStatus)
	return err
}

func (s *Store) ResumePolicyRolloutTarget(ctx context.Context, rolloutID, serverID, resumeStatus string) error {
	if resumeStatus == "" {
		resumeStatus = "PENDING"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE policy_rollout_targets SET status=?,resume_status=NULL,detail='' WHERE rollout_id=? AND server_id=? AND status='DEFERRED'`, resumeStatus, rolloutID, serverID)
	return err
}

func (s *Store) SwapPolicyRolloutCanary(ctx context.Context, rolloutID, deferredServerID, canaryServerID string, replacementBatch int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE policy_rollout_targets SET batch_no=? WHERE rollout_id=? AND server_id=? AND batch_no=0 AND status='DEFERRED'`, replacementBatch, rolloutID, deferredServerID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return errors.New("policy rollout canary changed")
	}
	result, err = tx.ExecContext(ctx, `UPDATE policy_rollout_targets SET batch_no=0 WHERE rollout_id=? AND server_id=? AND batch_no=? AND status='PENDING'`, rolloutID, canaryServerID, replacementBatch)
	if err != nil {
		return err
	}
	changed, err = result.RowsAffected()
	if err != nil || changed != 1 {
		if err != nil {
			return err
		}
		return errors.New("policy rollout canary changed")
	}
	return tx.Commit()
}

func (s *Store) InsertPolicyRevision(ctx context.Context, enterpriseID, enterprisePolicyID string, revision PolicyRevisionInput) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockActiveEnterprise(ctx, tx, enterpriseID); err != nil {
		return err
	}
	if err := insertPolicyRevisionTx(ctx, tx, enterpriseID, enterprisePolicyID, revision); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) AssignPolicyForRollout(ctx context.Context, rolloutID, enterpriseID, serverID, revisionID, userID, targetStatus string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockActiveEnterprise(ctx, tx, enterpriseID); err != nil {
		return err
	}
	var accessible int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM servers WHERE id=? AND enterprise_id=? AND revoked_at IS NULL`, serverID, enterpriseID).Scan(&accessible); err != nil {
		return err
	}
	if accessible != 1 {
		return sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_deployments SET status='SUPERSEDED',detail='정책 rollout으로 대체됨',updated_at=UTC_TIMESTAMP(6) WHERE server_id=? AND status='PENDING'`, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE desired_states SET policy_revision_id=? WHERE server_id=?`, revisionID, serverID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO policy_deployments(id,server_id,policy_revision_id,status,detail,requested_by,rollout_id) VALUES (?,?,?,'PENDING','',NULLIF(?,''),?)
ON DUPLICATE KEY UPDATE status='PENDING',detail='',requested_by=VALUES(requested_by),rollout_id=VALUES(rollout_id),updated_at=UTC_TIMESTAMP(6)`, randomID(), serverID, revisionID, userID, rolloutID); err != nil {
		return err
	}
	if targetStatus == "TRANSITION_PENDING" {
		if _, err := tx.ExecContext(ctx, `UPDATE policy_rollout_targets SET transition_revision_id=?,status='TRANSITION_PENDING',detail='' WHERE rollout_id=? AND server_id=?`, revisionID, rolloutID, serverID); err != nil {
			return err
		}
	} else if targetStatus == "POLICY_PENDING" {
		if _, err := tx.ExecContext(ctx, `UPDATE policy_rollout_targets SET status='POLICY_PENDING',detail='' WHERE rollout_id=? AND server_id=?`, rolloutID, serverID); err != nil {
			return err
		}
	} else {
		return errors.New("invalid rollout policy target status")
	}
	return tx.Commit()
}

func (s *Store) AssignPackagesForRollout(ctx context.Context, rolloutID, enterpriseID, serverID, agentID, moduleID, userID, targetStatus string) (string, error) {
	if targetStatus != "PACKAGE_PENDING" && targetStatus != "ROLLBACK_PENDING" {
		return "", errors.New("invalid rollout package target status")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if err := lockActiveEnterprise(ctx, tx, enterpriseID); err != nil {
		return "", err
	}
	var accessible int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM servers WHERE id=? AND enterprise_id=? AND revoked_at IS NULL`, serverID, enterpriseID).Scan(&accessible); err != nil {
		return "", err
	}
	if accessible != 1 {
		return "", sql.ErrNoRows
	}
	if _, err := tx.ExecContext(ctx, `UPDATE package_deployments SET status='SUPERSEDED',detail='정책 rollout으로 대체됨',updated_at=UTC_TIMESTAMP(6) WHERE server_id=? AND status='PENDING'`, serverID); err != nil {
		return "", err
	}
	deploymentID := randomID()
	if _, err := tx.ExecContext(ctx, `INSERT INTO package_deployments(id,server_id,agent_package_id,module_package_id,status,detail,requested_by,rollout_id) VALUES (?,?,?,?,'PENDING','',NULLIF(?,''),?)`, deploymentID, serverID, agentID, moduleID, userID, rolloutID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE desired_states SET agent_package_id=?,module_package_id=?,package_deployment_id=? WHERE server_id=?`, agentID, moduleID, deploymentID, serverID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_rollout_targets SET package_deployment_id=?,target_agent_package_id=?,target_module_package_id=?,status=?,detail='' WHERE rollout_id=? AND server_id=?`, deploymentID, agentID, moduleID, targetStatus, rolloutID, serverID); err != nil {
		return "", err
	}
	return deploymentID, tx.Commit()
}

func (s *Store) CompletePolicyRollout(ctx context.Context, rollout PolicyRolloutRecord) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var remaining int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_rollout_targets WHERE rollout_id=? AND status NOT IN ('APPLIED','ROLLED_BACK')`, rollout.ID).Scan(&remaining); err != nil {
		return err
	}
	if remaining != 0 {
		return errors.New("policy rollout still has unfinished targets")
	}
	var currentRevisionID string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(ep.current_revision_id,'')
FROM enterprise_policies ep JOIN enterprises e ON e.id=ep.enterprise_id
WHERE ep.id=? AND e.status='ACTIVE' FOR UPDATE`, rollout.EnterprisePolicyID).Scan(&currentRevisionID); err != nil {
		return err
	}
	if currentRevisionID != rollout.ExpectedRevisionID {
		return errors.New("enterprise policy revision changed")
	}
	if rollout.Type != "RECOVERY" {
		if _, err := tx.ExecContext(ctx, `UPDATE enterprise_policies SET previous_revision_id=current_revision_id,current_revision_id=?,current_system_policy_version_id=? WHERE id=?`, rollout.TargetRevisionID, rollout.TargetSystemPolicyVersionID, rollout.EnterprisePolicyID); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_rollouts SET status='APPLIED',detail='',completed_at=UTC_TIMESTAMP(6) WHERE id=?`, rollout.ID); err != nil {
		return err
	}
	return tx.Commit()
}
