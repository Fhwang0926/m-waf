package manager

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Fhwang0926/m-waf/internal/crsindex"
	"github.com/Fhwang0926/m-waf/internal/model"
	"github.com/Fhwang0926/m-waf/internal/systempolicy"
)

const structuredPolicyBackfillLock = "mwaf:policy-config-v2"

// UpsertCRSReleaseIndex registers a verified immutable source and its searchable
// metadata in one transaction. Existing tags are compared, never overwritten.
func (s *Store) UpsertCRSReleaseIndex(ctx context.Context, source model.PolicySourceArtifact, index crsindex.Index) error {
	if source.ID == "" || !source.TagSignatureVerified || source.TagObjectSHA == "" {
		return errors.New("CRS release requires a verified annotated tag")
	}
	if err := validateCRSReleaseIndex(source, index); err != nil {
		_ = s.recordRejectedCRSRelease(ctx, source)
		return err
	}
	channel := strings.ToUpper(source.Channel)
	if channel != "LTS" && channel != "STABLE" {
		return errors.New("CRS release channel must be LTS or STABLE")
	}
	archivePath := source.ArchivePath
	if archivePath == "" {
		archivePath = "bundle:" + source.ID + "/archive.tar.gz"
	}
	indexPath := source.IndexPath
	if indexPath == "" {
		indexPath = "bundle:" + source.ID + "/index.json"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var existingID, existingCommit, existingArchive, existingIndex string
	err = tx.QueryRowContext(ctx, `SELECT id,commit_sha,archive_sha256,index_sha256 FROM crs_releases WHERE repository=? AND tag=? FOR UPDATE`, source.Repository, source.Tag).Scan(&existingID, &existingCommit, &existingArchive, &existingIndex)
	if err == nil {
		if existingID != source.ID || existingCommit != source.Commit || !strings.EqualFold(existingArchive, source.ArchiveSHA256) || !strings.EqualFold(existingIndex, source.IndexSHA256) {
			return errors.New("CRS supply-chain mismatch: an existing tag resolves to different immutable content")
		}
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO crs_releases(id,provider,repository,channel,version,tag,commit_sha,tag_object_sha,tag_signature_verified,archive_path,archive_size,archive_sha256,index_path,index_size,index_sha256,status,verified_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'VERIFIED',UTC_TIMESTAMP(6))`, source.ID, source.Provider, source.Repository, channel, source.Version, source.Tag, source.Commit, source.TagObjectSHA, source.TagSignatureVerified, archivePath, source.ArchiveSize, source.ArchiveSHA256, indexPath, source.IndexSize, source.IndexSHA256)
	if err != nil {
		return err
	}
	for _, item := range index.Setup {
		optionsJSON, err := json.Marshal(item.Options)
		if err != nil {
			return err
		}
		valueType := item.Type
		if valueType == "number" {
			valueType = "integer"
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO crs_setup_definitions(release_id,setting_key,value_type,default_value,minimum_value,maximum_value,options_json,description) VALUES (?,?,?,?,?,?,?,?)`, source.ID, item.Key, valueType, item.Default, nullableSetupBound(item.Minimum), nullableSetupBound(item.Maximum), optionsJSON, item.Description); err != nil {
			return err
		}
	}
	for _, rule := range index.Rules {
		operatorName := crsRuleOperatorName(rule.Operator)
		if _, err := tx.ExecContext(ctx, `INSERT INTO crs_rules(release_id,rule_id,file_path,line_number,phase,paranoia_level,severity,message,operator_name,content_sha256,directive_text) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, source.ID, rule.ID, rule.File, rule.Line, rule.Phase, rule.ParanoiaLevel, rule.Severity, rule.Message, operatorName, rule.ContentHash, rule.Directive); err != nil {
			return err
		}
		for _, tag := range rule.Tags {
			if _, err := tx.ExecContext(ctx, `INSERT INTO crs_rule_tags(release_id,rule_id,tag) VALUES (?,?,?)`, source.ID, rule.ID, tag); err != nil {
				return err
			}
		}
		for _, variable := range rule.Variables {
			if _, err := tx.ExecContext(ctx, `INSERT INTO crs_rule_variables(release_id,rule_id,variable_name) VALUES (?,?,?)`, source.ID, rule.ID, variable); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func validateCRSReleaseIndex(source model.PolicySourceArtifact, index crsindex.Index) error {
	if index.Source.Commit != source.Commit || index.Source.ArchiveSHA256 != source.ArchiveSHA256 || index.Statistics.RuleCount != len(index.Rules) {
		return errors.New("CRS release metadata does not match its index")
	}
	setupKeys := make(map[string]bool, len(index.Setup))
	for _, item := range index.Setup {
		validType := item.Type == "integer" || item.Type == "number" || item.Type == "string" || item.Type == "boolean" || item.Type == "enum" || item.Type == "list"
		if item.Key == "" || item.Default == "" || !validType || setupKeys[item.Key] {
			return fmt.Errorf("CRS release contains an unsupported or duplicate Setup key %q", item.Key)
		}
		setupKeys[item.Key] = true
	}
	ruleIDs := make(map[int]bool, len(index.Rules))
	for _, item := range index.Rules {
		if item.ID <= 0 || item.Directive == "" || len(item.ContentHash) != 64 || len(crsRuleOperatorName(item.Operator)) > 255 || ruleIDs[item.ID] {
			return fmt.Errorf("CRS release contains an invalid or duplicate Rule ID %d", item.ID)
		}
		ruleIDs[item.ID] = true
	}
	return nil
}

// crsRuleOperatorName keeps the signed source index untouched while storing
// only the ModSecurity operator name in the searchable database column. A
// quoted value without an explicit @operator uses ModSecurity's default @rx.
func crsRuleOperatorName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	negated := strings.HasPrefix(value, "!")
	if negated {
		value = strings.TrimSpace(strings.TrimPrefix(value, "!"))
	}
	name := "@rx"
	if strings.HasPrefix(value, "@") {
		name = value
		if end := strings.IndexAny(name, " \t\r\n"); end >= 0 {
			name = name[:end]
		}
	}
	if negated {
		return "!" + name
	}
	return name
}

func (s *Store) recordRejectedCRSRelease(ctx context.Context, source model.PolicySourceArtifact) error {
	channel := strings.ToUpper(source.Channel)
	if channel != "LTS" && channel != "STABLE" || source.Repository == "" || source.Tag == "" {
		return nil
	}
	archivePath := source.ArchivePath
	if archivePath == "" {
		archivePath = "rejected:" + source.ID + "/archive.tar.gz"
	}
	indexPath := source.IndexPath
	if indexPath == "" {
		indexPath = "rejected:" + source.ID + "/index.json"
	}
	_, err := s.db.ExecContext(ctx, `INSERT IGNORE INTO crs_releases(id,provider,repository,channel,version,tag,commit_sha,tag_object_sha,tag_signature_verified,archive_path,archive_size,archive_sha256,index_path,index_size,index_sha256,status,verified_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'REJECTED',UTC_TIMESTAMP(6))`, source.ID, source.Provider, source.Repository, channel, source.Version, source.Tag, source.Commit, source.TagObjectSHA, source.TagSignatureVerified, archivePath, source.ArchiveSize, source.ArchiveSHA256, indexPath, source.IndexSize, source.IndexSHA256)
	return err
}

func nullableSetupBound(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func (s *Store) CRSReleaseIndexStatus(ctx context.Context, id string) (string, bool, error) {
	var status string
	var ruleCount int
	err := s.db.QueryRowContext(ctx, `SELECT r.status,COUNT(cr.rule_id) FROM crs_releases r LEFT JOIN crs_rules cr ON cr.release_id=r.id WHERE r.id=? GROUP BY r.id,r.status`, id).Scan(&status, &ruleCount)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return status, ruleCount > 0, err
}

func (s *Store) CRSReleaseVerifiedAt(ctx context.Context, id string) (time.Time, error) {
	var verifiedAt time.Time
	err := s.db.QueryRowContext(ctx, `SELECT verified_at FROM crs_releases WHERE id=? AND status='VERIFIED'`, id).Scan(&verifiedAt)
	return verifiedAt, err
}

func (s *Store) CRSReleaseIndex(ctx context.Context, id string) (crsindex.Index, error) {
	var result crsindex.Index
	result.SchemaVersion = crsindex.SchemaVersion
	result.GeneratedBy = "mwaf-crs-db-index"
	err := s.db.QueryRowContext(ctx, `SELECT provider,repository,LOWER(channel),version,tag,commit_sha,archive_sha256
FROM crs_releases WHERE id=? AND status='VERIFIED'`, id).Scan(
		&result.Source.Provider, &result.Source.Repository, &result.Source.Channel, &result.Source.Version,
		&result.Source.Tag, &result.Source.Commit, &result.Source.ArchiveSHA256,
	)
	if err != nil {
		return crsindex.Index{}, err
	}
	setupRows, err := s.db.QueryContext(ctx, `SELECT setting_key,value_type,default_value,minimum_value,maximum_value,options_json,description
FROM crs_setup_definitions WHERE release_id=? ORDER BY setting_key`, id)
	if err != nil {
		return crsindex.Index{}, err
	}
	setupLabels := make(map[string]string)
	for _, definition := range crsindex.SupportedSetup() {
		setupLabels[definition.Key] = definition.Label
	}
	for setupRows.Next() {
		var item crsindex.SetupField
		var minimum, maximum sql.NullInt64
		var options []byte
		if err := setupRows.Scan(&item.Key, &item.Type, &item.Default, &minimum, &maximum, &options, &item.Description); err != nil {
			setupRows.Close()
			return crsindex.Index{}, err
		}
		item.Minimum, item.Maximum = int(minimum.Int64), int(maximum.Int64)
		item.Label = setupLabels[item.Key]
		if item.Label == "" {
			item.Label = item.Key
		}
		if len(options) != 0 && string(options) != "null" {
			if err := json.Unmarshal(options, &item.Options); err != nil {
				setupRows.Close()
				return crsindex.Index{}, err
			}
		}
		result.Setup = append(result.Setup, item)
	}
	if err := setupRows.Close(); err != nil {
		return crsindex.Index{}, err
	}
	result.Setup = crsindex.NormalizeSupportedSetup(result.Setup)
	ruleRows, err := s.db.QueryContext(ctx, `SELECT rule_id,file_path,line_number,phase,paranoia_level,severity,message,operator_name,content_sha256,directive_text
FROM crs_rules WHERE release_id=? ORDER BY rule_id`, id)
	if err != nil {
		return crsindex.Index{}, err
	}
	rulePositions := make(map[int]int)
	files := make(map[string]bool)
	for ruleRows.Next() {
		var item crsindex.Rule
		if err := ruleRows.Scan(&item.ID, &item.File, &item.Line, &item.Phase, &item.ParanoiaLevel, &item.Severity, &item.Message, &item.Operator, &item.ContentHash, &item.Directive); err != nil {
			ruleRows.Close()
			return crsindex.Index{}, err
		}
		rulePositions[item.ID] = len(result.Rules)
		files[item.File] = true
		result.Rules = append(result.Rules, item)
	}
	if err := ruleRows.Close(); err != nil {
		return crsindex.Index{}, err
	}
	tagRows, err := s.db.QueryContext(ctx, `SELECT rule_id,tag FROM crs_rule_tags WHERE release_id=? ORDER BY rule_id,tag`, id)
	if err != nil {
		return crsindex.Index{}, err
	}
	for tagRows.Next() {
		var ruleID int
		var tag string
		if err := tagRows.Scan(&ruleID, &tag); err != nil {
			tagRows.Close()
			return crsindex.Index{}, err
		}
		if position, ok := rulePositions[ruleID]; ok {
			result.Rules[position].Tags = append(result.Rules[position].Tags, tag)
		}
	}
	if err := tagRows.Close(); err != nil {
		return crsindex.Index{}, err
	}
	variableRows, err := s.db.QueryContext(ctx, `SELECT rule_id,variable_name FROM crs_rule_variables WHERE release_id=? ORDER BY rule_id,variable_name`, id)
	if err != nil {
		return crsindex.Index{}, err
	}
	for variableRows.Next() {
		var ruleID int
		var variable string
		if err := variableRows.Scan(&ruleID, &variable); err != nil {
			variableRows.Close()
			return crsindex.Index{}, err
		}
		if position, ok := rulePositions[ruleID]; ok {
			result.Rules[position].Variables = append(result.Rules[position].Variables, variable)
		}
	}
	if err := variableRows.Close(); err != nil {
		return crsindex.Index{}, err
	}
	result.Statistics = crsindex.Statistics{RuleCount: len(result.Rules), FileCount: len(files), ByPhase: map[string]int{}, ByPL: map[string]int{}, ByTag: map[string]int{}}
	for _, rule := range result.Rules {
		result.Statistics.ByPhase[rule.Phase]++
		result.Statistics.ByPL[strconv.Itoa(rule.ParanoiaLevel)]++
		for _, tag := range rule.Tags {
			result.Statistics.ByTag[tag]++
		}
	}
	return result, nil
}

func (s *Store) SetPolicyMigrationImpact(ctx context.Context, policyID, targetSystemPolicyID, detail string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO policy_migration_impacts(enterprise_policy_id,target_system_policy_version_id,status,detail) VALUES (?,?,'MIGRATION_REQUIRED',?)
ON DUPLICATE KEY UPDATE status='MIGRATION_REQUIRED',detail=VALUES(detail)`, policyID, targetSystemPolicyID, truncate(detail, 2048))
	return err
}

func (s *Store) ClearPolicyMigrationImpact(ctx context.Context, policyID, targetSystemPolicyID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM policy_migration_impacts WHERE enterprise_policy_id=? AND target_system_policy_version_id=?`, policyID, targetSystemPolicyID)
	return err
}

func insertPolicyConfigurationTx(ctx context.Context, tx *sql.Tx, configuration PolicyConfiguration) error {
	configuration.Normalize()
	if err := configuration.UpdateDigest(); err != nil {
		return err
	}
	if err := configuration.ValidateAt(time.Now().UTC()); err != nil {
		return err
	}
	if configuration.ID == "" {
		configuration.ID = randomID()
	}
	releaseID := any(nil)
	if configuration.CRSReleaseID != "" {
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM crs_releases WHERE id=? AND status='VERIFIED'`, configuration.CRSReleaseID).Scan(&exists); err != nil {
			return err
		}
		if exists != 1 {
			return fmt.Errorf("verified CRS release %q is not indexed", configuration.CRSReleaseID)
		}
		releaseID = configuration.CRSReleaseID
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO policy_configurations(id,system_policy_version_id,policy_revision_id,crs_release_id,engine_mode,blocking_paranoia_level,executing_paranoia_level,inbound_anomaly_threshold,outbound_anomaly_threshold,request_body_access,response_body_access,early_blocking,sampling_percentage,rule_id_namespace_version,config_sha256)
VALUES (?,NULLIF(?,''),NULLIF(?,''),?,?,?,?,?,?,?,?,?,?,?,?)`, configuration.ID, configuration.SystemPolicyVersionID, configuration.PolicyRevisionID, releaseID, configuration.EngineMode, configuration.BlockingParanoiaLevel, configuration.ExecutingParanoiaLevel, configuration.InboundAnomalyThreshold, configuration.OutboundAnomalyThreshold, configuration.RequestBodyAccess, configuration.ResponseBodyAccess, configuration.EarlyBlocking, configuration.SamplingPercentage, configuration.RuleIDNamespaceVersion, configuration.ConfigSHA256)
	if err != nil {
		return err
	}
	for _, item := range configuration.Setup {
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_configuration_setup_values(configuration_id,setting_key,setting_value,source_scope) VALUES (?,?,?,?)`, configuration.ID, item.Key, item.Value, item.SourceScope); err != nil {
			return err
		}
	}
	for _, item := range configuration.Exclusions {
		if item.ID == "" {
			item.ID = randomID()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_configuration_exclusions(id,configuration_id,source_scope,exclusion_type,load_stage,rule_id,rule_tag,target,generated_rule_id,reason,expires_at,enabled,legacy,order_no)
VALUES (?,?,?,?,?,NULLIF(?,0),NULLIF(?,''),NULLIF(?,''),NULLIF(?,0),?,?,?,?,?)`, item.ID, configuration.ID, item.SourceScope, item.Type, item.LoadStage, item.RuleID, item.RuleTag, item.Target, item.GeneratedRuleID, item.Reason, item.ExpiresAt, item.Enabled, item.Legacy, item.Order); err != nil {
			return err
		}
		for _, condition := range item.Conditions {
			if _, err := tx.ExecContext(ctx, `INSERT INTO policy_configuration_exclusion_conditions(exclusion_id,order_no,field_name,operator_name,condition_value) VALUES (?,?,?,?,?)`, item.ID, condition.Order, condition.Field, condition.Operator, condition.Value); err != nil {
				return err
			}
		}
	}
	for _, item := range configuration.CustomRules {
		if item.ID == "" {
			item.ID = randomID()
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO policy_configuration_custom_rules(id,configuration_id,source_scope,rule_id,rule_name,phase,severity,canonical_sec_rule,content_sha256,enabled,legacy_id_range,order_no) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`, item.ID, configuration.ID, item.SourceScope, item.RuleID, item.Name, item.Phase, item.Severity, item.CanonicalSecRule, item.ContentSHA256, item.Enabled, item.LegacyIDRange, item.Order); err != nil {
			return err
		}
	}
	return nil
}

// BackfillStructuredPolicyConfigurations is deliberately artifact-neutral: it
// only records a normalized snapshot beside legacy JSON and never deploys it.
func (s *Store) BackfillStructuredPolicyConfigurations(ctx context.Context) error {
	connection, err := s.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	var locked int
	if err := connection.QueryRowContext(ctx, `SELECT GET_LOCK(?,0)`, structuredPolicyBackfillLock).Scan(&locked); err != nil {
		return err
	}
	if locked != 1 {
		return nil
	}
	defer connection.ExecContext(context.Background(), `SELECT RELEASE_LOCK(?)`, structuredPolicyBackfillLock)
	if err := s.backfillSystemPolicyConfigurations(ctx); err != nil {
		return err
	}
	return s.backfillRevisionConfigurations(ctx)
}

func (s *Store) backfillSystemPolicyConfigurations(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM system_policy_versions WHERE config_storage_version=1 AND config_migration_status='PENDING' ORDER BY created_at LIMIT 100`)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, id := range ids {
		item, err := s.SystemPolicyTemplateByID(ctx, id)
		if err != nil {
			return err
		}
		settings := PolicySettings{
			ParanoiaLevel: item.Defaults.ParanoiaLevel, ExecutingParanoiaLevel: item.Defaults.ExecutingParanoiaLevel,
			InboundScore: item.Defaults.InboundScore, OutboundScore: item.Defaults.OutboundScore,
			RequestBody: item.Defaults.RequestBody, ResponseBody: item.Defaults.ResponseBody,
			EarlyBlocking: item.Defaults.EarlyBlocking, SamplingPercentage: item.Defaults.SamplingPercentage,
		}
		configuration, legacy, buildErr := structuredConfigurationFromPolicy(id, "", item, item.Defaults.Mode, settings)
		if buildErr == nil {
			buildErr = s.validateBackfillCRSRelease(ctx, configuration)
		}
		if err := s.finishSystemPolicyBackfill(ctx, id, configuration, legacy, buildErr); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) finishSystemPolicyBackfill(ctx context.Context, id string, configuration PolicyConfiguration, legacy bool, buildErr error) error {
	if buildErr != nil {
		_, err := s.db.ExecContext(ctx, `UPDATE system_policy_versions SET config_migration_status='LEGACY_LOCKED',config_migration_detail=? WHERE id=? AND config_storage_version=1`, truncate(buildErr.Error(), 1024), id)
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var storageVersion int
	if err := tx.QueryRowContext(ctx, `SELECT config_storage_version FROM system_policy_versions WHERE id=? FOR UPDATE`, id).Scan(&storageVersion); err != nil {
		return err
	}
	if storageVersion != PolicyConfigStorageLegacy {
		return tx.Commit()
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_configurations WHERE system_policy_version_id=?`, id).Scan(&existing); err != nil {
		return err
	}
	if existing == 0 {
		if err := insertPolicyConfigurationTx(ctx, tx, configuration); err != nil {
			return err
		}
	}
	status := PolicyConfigMigrated
	detail := ""
	if legacy {
		status = PolicyConfigLegacyCompat
		detail = "legacy bypass or Rule ID range preserved"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE system_policy_versions SET config_storage_version=2,config_migration_status=?,config_migration_detail=? WHERE id=? AND config_storage_version=1`, status, detail, id); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) backfillRevisionConfigurations(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT id,COALESCE(system_policy_version_id,''),mode,settings_json FROM policy_revisions WHERE config_storage_version=1 AND config_migration_status='PENDING' ORDER BY created_at LIMIT 100`)
	if err != nil {
		return err
	}
	type candidate struct{ id, systemID, mode, settings string }
	var items []candidate
	for rows.Next() {
		var item candidate
		if err := rows.Scan(&item.id, &item.systemID, &item.mode, &item.settings); err != nil {
			rows.Close()
			return err
		}
		items = append(items, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range items {
		var settings PolicySettings
		buildErr := json.Unmarshal([]byte(item.settings), &settings)
		var configuration PolicyConfiguration
		legacy := false
		if buildErr == nil {
			var templateErr error
			var templateItem systempolicy.Template
			if item.systemID == "" {
				templateErr = errors.New("revision is not linked to a system policy version")
			} else {
				templateItem, templateErr = s.SystemPolicyTemplateByID(ctx, item.systemID)
			}
			if templateErr != nil {
				buildErr = templateErr
			} else {
				configuration, legacy, buildErr = structuredConfigurationFromPolicy("", item.id, templateItem, item.mode, settings)
				if buildErr == nil {
					buildErr = s.validateBackfillCRSRelease(ctx, configuration)
				}
			}
		}
		if err := s.finishRevisionBackfill(ctx, item.id, configuration, legacy, buildErr); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) validateBackfillCRSRelease(ctx context.Context, configuration PolicyConfiguration) error {
	if configuration.CRSReleaseID == "" {
		return nil
	}
	status, indexed, err := s.CRSReleaseIndexStatus(ctx, configuration.CRSReleaseID)
	if err != nil {
		return err
	}
	if status != "VERIFIED" || !indexed {
		return fmt.Errorf("verified CRS release %q is not indexed", configuration.CRSReleaseID)
	}
	return nil
}

func (s *Store) finishRevisionBackfill(ctx context.Context, id string, configuration PolicyConfiguration, legacy bool, buildErr error) error {
	if buildErr != nil {
		_, err := s.db.ExecContext(ctx, `UPDATE policy_revisions SET config_migration_status='LEGACY_LOCKED',config_migration_detail=? WHERE id=? AND config_storage_version=1`, truncate(buildErr.Error(), 1024), id)
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var storageVersion int
	if err := tx.QueryRowContext(ctx, `SELECT config_storage_version FROM policy_revisions WHERE id=? FOR UPDATE`, id).Scan(&storageVersion); err != nil {
		return err
	}
	if storageVersion != PolicyConfigStorageLegacy {
		return tx.Commit()
	}
	var existing int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM policy_configurations WHERE policy_revision_id=?`, id).Scan(&existing); err != nil {
		return err
	}
	if existing == 0 {
		if err := insertPolicyConfigurationTx(ctx, tx, configuration); err != nil {
			return err
		}
	}
	status := PolicyConfigMigrated
	detail := ""
	if legacy {
		status = PolicyConfigLegacyCompat
		detail = "legacy bypass or Rule ID range preserved"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE policy_revisions SET config_storage_version=2,config_migration_status=?,config_migration_detail=? WHERE id=? AND config_storage_version=1`, status, detail, id); err != nil {
		return err
	}
	return tx.Commit()
}

// PolicyConfigurationByRevisionID reconstructs the immutable structured
// snapshot. Legacy settings_json is only a fallback when no v2 row exists.
func (s *Store) PolicyConfigurationByRevisionID(ctx context.Context, revisionID string) (PolicyConfiguration, error) {
	return s.policyConfigurationByOwner(ctx, "policy_revision_id", revisionID)
}

func (s *Store) PolicyConfigurationBySystemPolicyID(ctx context.Context, systemPolicyID string) (PolicyConfiguration, error) {
	return s.policyConfigurationByOwner(ctx, "system_policy_version_id", systemPolicyID)
}

func (s *Store) policyConfigurationByOwner(ctx context.Context, ownerColumn, ownerID string) (PolicyConfiguration, error) {
	if ownerColumn != "policy_revision_id" && ownerColumn != "system_policy_version_id" {
		return PolicyConfiguration{}, errors.New("invalid policy configuration owner")
	}
	var item PolicyConfiguration
	query := fmt.Sprintf(`SELECT id,COALESCE(system_policy_version_id,''),COALESCE(policy_revision_id,''),COALESCE(crs_release_id,''),engine_mode,
blocking_paranoia_level,executing_paranoia_level,inbound_anomaly_threshold,outbound_anomaly_threshold,request_body_access,response_body_access,
early_blocking,sampling_percentage,rule_id_namespace_version,config_sha256
FROM policy_configurations WHERE %s=?`, ownerColumn)
	err := s.db.QueryRowContext(ctx, query, ownerID).Scan(
		&item.ID, &item.SystemPolicyVersionID, &item.PolicyRevisionID, &item.CRSReleaseID, &item.EngineMode,
		&item.BlockingParanoiaLevel, &item.ExecutingParanoiaLevel, &item.InboundAnomalyThreshold, &item.OutboundAnomalyThreshold,
		&item.RequestBodyAccess, &item.ResponseBodyAccess, &item.EarlyBlocking, &item.SamplingPercentage,
		&item.RuleIDNamespaceVersion, &item.ConfigSHA256,
	)
	if err != nil {
		return PolicyConfiguration{}, err
	}
	setupRows, err := s.db.QueryContext(ctx, `SELECT setting_key,setting_value,source_scope FROM policy_configuration_setup_values WHERE configuration_id=? ORDER BY setting_key`, item.ID)
	if err != nil {
		return PolicyConfiguration{}, err
	}
	for setupRows.Next() {
		var value CRSSetupValue
		if err := setupRows.Scan(&value.Key, &value.Value, &value.SourceScope); err != nil {
			setupRows.Close()
			return PolicyConfiguration{}, err
		}
		item.Setup = append(item.Setup, value)
	}
	if err := setupRows.Close(); err != nil {
		return PolicyConfiguration{}, err
	}

	exclusionRows, err := s.db.QueryContext(ctx, `SELECT id,source_scope,exclusion_type,load_stage,rule_id,rule_tag,target,generated_rule_id,reason,expires_at,enabled,legacy,order_no
FROM policy_configuration_exclusions WHERE configuration_id=? ORDER BY order_no,id`, item.ID)
	if err != nil {
		return PolicyConfiguration{}, err
	}
	for exclusionRows.Next() {
		var value PolicyExclusion
		var ruleID, generatedRuleID sql.NullInt64
		var ruleTag, target, reason sql.NullString
		var expiresAt sql.NullTime
		if err := exclusionRows.Scan(&value.ID, &value.SourceScope, &value.Type, &value.LoadStage, &ruleID, &ruleTag, &target, &generatedRuleID, &reason, &expiresAt, &value.Enabled, &value.Legacy, &value.Order); err != nil {
			exclusionRows.Close()
			return PolicyConfiguration{}, err
		}
		value.RuleID, value.GeneratedRuleID = int(ruleID.Int64), int(generatedRuleID.Int64)
		value.RuleTag, value.Target, value.Reason = ruleTag.String, target.String, reason.String
		if expiresAt.Valid {
			expires := expiresAt.Time
			value.ExpiresAt = &expires
		}
		item.Exclusions = append(item.Exclusions, value)
	}
	if err := exclusionRows.Close(); err != nil {
		return PolicyConfiguration{}, err
	}
	for index := range item.Exclusions {
		conditionRows, err := s.db.QueryContext(ctx, `SELECT field_name,operator_name,condition_value,order_no FROM policy_configuration_exclusion_conditions WHERE exclusion_id=? ORDER BY order_no`, item.Exclusions[index].ID)
		if err != nil {
			return PolicyConfiguration{}, err
		}
		for conditionRows.Next() {
			var condition PolicyExclusionCondition
			if err := conditionRows.Scan(&condition.Field, &condition.Operator, &condition.Value, &condition.Order); err != nil {
				conditionRows.Close()
				return PolicyConfiguration{}, err
			}
			item.Exclusions[index].Conditions = append(item.Exclusions[index].Conditions, condition)
		}
		if err := conditionRows.Close(); err != nil {
			return PolicyConfiguration{}, err
		}
	}

	ruleRows, err := s.db.QueryContext(ctx, `SELECT id,source_scope,rule_id,rule_name,phase,severity,canonical_sec_rule,content_sha256,enabled,legacy_id_range,order_no
FROM policy_configuration_custom_rules WHERE configuration_id=? ORDER BY order_no,id`, item.ID)
	if err != nil {
		return PolicyConfiguration{}, err
	}
	for ruleRows.Next() {
		var value PolicyCustomRule
		if err := ruleRows.Scan(&value.ID, &value.SourceScope, &value.RuleID, &value.Name, &value.Phase, &value.Severity, &value.CanonicalSecRule, &value.ContentSHA256, &value.Enabled, &value.LegacyIDRange, &value.Order); err != nil {
			ruleRows.Close()
			return PolicyConfiguration{}, err
		}
		item.CustomRules = append(item.CustomRules, value)
	}
	if err := ruleRows.Close(); err != nil {
		return PolicyConfiguration{}, err
	}
	storedDigest := item.ConfigSHA256
	if err := item.UpdateDigest(); err != nil {
		return PolicyConfiguration{}, err
	}
	if !strings.EqualFold(storedDigest, item.ConfigSHA256) {
		return PolicyConfiguration{}, errors.New("structured policy configuration digest mismatch")
	}
	return item, nil
}
